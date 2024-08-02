

// SPDX-License-Identifier: MIT
pragma solidity 0.8.21;

import {CrossChainTellerBase, BridgeData, ERC20} from "./CrossChainTellerBase.sol";
import { Auth } from "@solmate/auth/Auth.sol";
import {IBridge} from "@arbitrum/nitro-contracts/bridge/IBridge.sol";
import {IInbox} from "@arbitrum/nitro-contracts/bridge/IInbox.sol";
import {ArbSys} from "@arbitrum/nitro-contracts/precompiles/ArbSys.sol";
import {Outbox} from "@arbitrum/nitro-contracts/bridge/Outbox.sol";
import {AddressAliasHelper} from "@arbitrum/nitro-contracts/libraries/AddressAliasHelper.sol";

ArbSys constant ARBSYS = ArbSys(0x000000000000000000000000000000000000006E);

/**
 * @title CrossChainLayerZeroTellerWithMultiAssetSupport
 * @notice Arbitrum Bridge implementation of CrossChainTeller
 * Arbitrum is a bit unique as it has different logic for L1 -> L2 and L2 -> L1
 * So to best organize this we have made CrossChainARBTellerWithMultiAssetSupport abstract,
 * and create 2 children as L1 and L2 tellers to be deployed respectively
 */
abstract contract CrossChainARBTellerWithMultiAssetSupport is CrossChainTellerBase {

    address public peer;

    uint32 public maxMessageGas;
    uint32 public minMessageGas;

    error CrossChainARBTellerWithMultiAssetSupport_OnlyMessenger();
    error CrossChainARBTellerWithMultiAssetSupport_OnlyPeerAsSender();
    error CrossChainARBTellerWithMultiAssetSupport_NoFee();
    error CrossChainARBTellerWithMultiAssetSupport_GasOutOfBounds(uint32);

    constructor(address _owner, address _vault, address _accountant)
        CrossChainTellerBase(_owner, _vault, _accountant)
    {
        peer = address(this);
    }

    /**
     * Callable by OWNER_ROLE.
     * @param _peer new peer to set
     */
    function setPeer(address _peer) external requiresAuth{
        peer = _peer;
    }

    /**
     * @dev Callable by OWNER_ROLE.
     * @param newMinMessageGas the new minMessageGas bound
     * @param newMaxMessageGas the new maxMessageGas bound
     */
    function setGasBounds(uint32 newMinMessageGas, uint32 newMaxMessageGas) external requiresAuth {
        minMessageGas = newMinMessageGas;
        maxMessageGas = newMaxMessageGas;
    }

    /**
     * @notice Function for ARB Messenger to call to receive a message and mint the shares on this chain
     * @param receiver to receive the shares
     * @param shareMintAmount amount of shares to mint
     */
    function receiveBridgeMessage(address receiver, uint256 shareMintAmount) external virtual;

    /**
     * @notice before bridge hook to check gas bound
     * @param data bridge data
     */
    function _beforeBridge(BridgeData calldata data) internal override{
        uint32 messageGas = uint32(data.messageGas);
        if(messageGas > maxMessageGas || messageGas < minMessageGas){
            revert CrossChainARBTellerWithMultiAssetSupport_GasOutOfBounds(messageGas);
        }
    }

}

/**
 * @title CrossChainARBTellerWithMultiAssetSupportL1
 * @notice This is the version of the Arbitrum teller to be deployed on L1
 */
contract CrossChainARBTellerWithMultiAssetSupportL1 is CrossChainARBTellerWithMultiAssetSupport{
    IInbox public inbox;

    constructor(address _owner, address _vault, address _accountant, address _inbox)
    CrossChainARBTellerWithMultiAssetSupport(_owner, _vault, _accountant){
        inbox = IInbox(_inbox);
    }

    function receiveBridgeMessage(address receiver, uint256 shareMintAmount) external override {
        IBridge bridge = inbox.bridge();
        Outbox outbox = Outbox(bridge.activeOutbox());
        address l2Sender = outbox.l2ToL1Sender();

        // this prevents reentrancies on L2 to L1 txs
        if (msg.sender != address(bridge)){
            revert CrossChainARBTellerWithMultiAssetSupport_OnlyMessenger();
        }

        // message must come from peer
        if(l2Sender != peer){
            revert CrossChainARBTellerWithMultiAssetSupport_OnlyPeerAsSender();
        }

        vault.enter(address(0), ERC20(address(0)), 0, receiver, shareMintAmount);
    }

    /**
     * @notice taken from Arbitrum's Inbox.sol
     * This is the fee for the submission
     * @param dataLength length of data byte array
     * @param baseFee block basefee
     */
    function calculateRetryableSubmissionFee(uint256 dataLength, uint256 baseFee)
        public
        view
        returns (uint256)
    {
        // Use current block basefee if baseFee parameter is 0
        return (1400 + 6 * dataLength) * (baseFee == 0 ? block.basefee : baseFee);
    }

    /**
     * @notice the virtual function to override to get bridge fees
     * @param shareAmount to send
     * @param data bridge data
     */
    function _quote(uint256 shareAmount, BridgeData calldata data) internal view override returns(uint256){
        bytes memory ticketData = abi.encodeWithSelector(CrossChainARBTellerWithMultiAssetSupport.receiveBridgeMessage.selector, data.destinationChainReceiver, shareAmount);

        // Inbox.sol dictates:
        // msg.value >= (maxSubmissionCost + l2CallValue + gasLimit * maxFeePerGas)
        // and
        // maxSubmissionCost >= submissionFee
        // so we get this calculation:
        uint submissionFee = calculateRetryableSubmissionFee(ticketData.length, block.basefee);
        return (submissionFee + 0 + maxMessageGas * data.messageGas);
    }

    /**
     * @notice the virtual bridge function to execute Optimism messenger sendMessage()
     * @param data bridge data
     * @return msgNum
     */
    function _bridge(uint256 shareAmount, BridgeData calldata data) internal override returns(bytes32 msgNum){
        bytes memory ticketData = abi.encodeWithSelector(CrossChainARBTellerWithMultiAssetSupport.receiveBridgeMessage.selector, data.destinationChainReceiver, shareAmount);
        uint maxSubmissionCost = calculateRetryableSubmissionFee(ticketData.length, block.basefee);
        /*
        createRetryableTicket() parameters:
            address to,
            uint256 l2CallValue,
            uint256 maxSubmissionCost,
            address excessFeeRefundAddress,
            address callValueRefundAddress,
            uint256 gasLimit,
            uint256 maxFeePerGas,
            bytes calldata data
        */
        msgNum = bytes32(
        inbox.createRetryableTicket{value: msg.value}(
            peer, 
            0, 
            maxSubmissionCost, 
            msg.sender, 
            msg.sender, 
            maxMessageGas, 
            data.messageGas, 
            ticketData
            )
        );

    }
    
}

/**
 * @title CrossChainARBTellerWithMultiAssetSupportL2 
 * @notice This is the version of the Arbitrum teller to be deployed on L2 
 */
contract CrossChainARBTellerWithMultiAssetSupportL2 is CrossChainARBTellerWithMultiAssetSupport{

    constructor(address _owner, address _vault, address _accountant)
    CrossChainARBTellerWithMultiAssetSupport(_owner, _vault, _accountant){
    }

    function receiveBridgeMessage(address receiver, uint256 shareMintAmount) external override{
        if(msg.sender != AddressAliasHelper.applyL1ToL2Alias(peer)){
            revert CrossChainARBTellerWithMultiAssetSupport_OnlyPeerAsSender();
        }

        vault.enter(address(0), ERC20(address(0)), 0, receiver, shareMintAmount);
    }

    /**
     * @notice the virtual function to override to get bridge fees
     * @param shareAmount to send
     * @param data bridge data
     */
    function _quote(uint256 shareAmount, BridgeData calldata data) internal view override returns(uint256){
        return 0;
    }

    /**
     * @notice the virtual bridge function to execute Optimism messenger sendMessage()
     * @param data bridge data
     * @return messageId
     */
    function _bridge(uint256 shareAmount, BridgeData calldata data) internal override returns(bytes32){
        bytes memory call_data = abi.encodeWithSelector(CrossChainARBTellerWithMultiAssetSupport.receiveBridgeMessage.selector, data.destinationChainReceiver, shareAmount);
        ARBSYS.sendTxToL1(peer, call_data);
    }

}