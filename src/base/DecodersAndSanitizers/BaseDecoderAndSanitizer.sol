// SPDX-License-Identifier: MIT
pragma solidity 0.8.21;

import {DecoderCustomTypes} from "src/interfaces/DecoderCustomTypes.sol";
import {ERC20} from "@solmate/tokens/ERC20.sol";
import {console} from "@forge-std/Test.sol";

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

    /**
     * @dev To use maxAvailable logic, append
     *      abi.encodePacked(TOKEN, MAX_AVAILABLE_MARKER) to the end of calldata.
     */
    function approve(address spender, uint256 amount)
        external
        view
        returns (bytes memory addressesFound, bytes memory targetData)
    {
        if (_checkForMarker(MAX_AVAILABLE_MARKER)) {
            amount = _maxAvailableFromOffset(64, amount);
            targetData = abi.encodeWithSelector(this.approve.selector, spender, amount);
        } else {
            targetData = msg.data;
        }
        addressesFound = abi.encodePacked(spender);
    }

    function _checkForMarker(bytes32 marker) internal pure returns (bool markerFound) {
        // If msg.data length is less than 32, then it is not possible to have a marker
        // if msg.data length is equal to 32, it is also not possible to have a marker,
        // as msg.data will always have 4 byte function selector to start.
        // So the only case where we can possibly have a marker is when msg.data length
        // is greater than 32
        assembly {
            if gt(calldatasize(), 32) { markerFound := eq(calldataload(sub(calldatasize(), 32)), marker) }
        }
    }

    /**
     * @notice If amount if type(uint256).max, then extract asset from calldata and query boring vaults balance.
     */
    function _maxAvailableFromOffset(uint256 offset, uint256 amount) internal view returns (uint256) {
        if (amount == type(uint256).max) {
            ERC20 asset;
            assembly {
                // Extract address from calldata.
                asset := calldataload(sub(calldatasize(), offset))
            }
            return asset.balanceOf(boringVault);
        }
        return amount;
    }

    /**
     * @notice If amount if type(uint256).max, then query boring vaults balance.
     */
    function _maxAvailable(address asset, uint256 amount) internal view returns (uint256) {
        if (amount == type(uint256).max) {
            return ERC20(asset).balanceOf(boringVault);
        }
        return amount;
    }

    /**
     * @notice Extract address from calldata.
     */
    function _getAddressFromOffset(uint256 offset) internal pure returns (address addr) {
        assembly {
            addr := calldataload(sub(calldatasize(), offset))
        }
    }
}
