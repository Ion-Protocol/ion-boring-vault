// SPDX-License-Identifier: MIT
pragma solidity 0.8.21;

import {DecoderCustomTypes} from "src/interfaces/DecoderCustomTypes.sol";
import {ERC20} from "@solmate/tokens/ERC20.sol";

contract BaseDecoderAndSanitizer {
    //============================== IMMUTABLES ===============================

    /**
     * @notice The BoringVault contract address.
     */
    address internal immutable boringVault;

    /**
     * @notice The 32 byte marker appeneded to the end of calldata to indicate
     *         strategist wants to use max available logic.
     */
    bytes32 public immutable MAX_AVAILABLE_MARKER;

    constructor(address _boringVault) {
        boringVault = _boringVault;
        MAX_AVAILABLE_MARKER = keccak256(abi.encode("Max Available Marker"));
    }

    function approve(address spender, uint256 amount)
        external
        view
        returns (bytes memory addressesFound, bytes memory targetData)
    {
        if (_checkForMarker(MAX_AVAILABLE_MARKER)) {
            uint256 sliceStart = msg.data.length - 52; // 52 = 32 + 20, 32 for marker and 20 for address
            amount = _maxAvailable(address(bytes20(msg.data[sliceStart:sliceStart + 20])), amount);
            targetData = abi.encodeWithSelector(this.approve.selector, spender, amount);
        } else {
            targetData = msg.data;
        }
        addressesFound = abi.encodePacked(spender);
    }

    // TODO could optimize with assembly.
    function _checkForMarker(bytes32 marker) internal pure returns (bool markerFound) {
        uint256 len = msg.data.length;
        if (len < 32) {
            return false;
        }
        return bytes32(msg.data[len - 32:]) == marker;
    }

    function _maxAvailable(address asset, uint256 amount) internal view returns (uint256) {
        if (amount == type(uint256).max) {
            return ERC20(asset).balanceOf(boringVault);
        }
        return amount;
    }
}
