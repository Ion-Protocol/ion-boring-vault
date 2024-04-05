// SPDX-License-Identifier: MIT
pragma solidity 0.8.21;

import {BaseDecoderAndSanitizer, DecoderCustomTypes} from "src/base/DecodersAndSanitizers/BaseDecoderAndSanitizer.sol";
import {ERC4626} from "@solmate/tokens/ERC4626.sol";

abstract contract ERC4626DecoderAndSanitizer is BaseDecoderAndSanitizer {
    //============================== ERC4626 ===============================

    /**
     * @dev To use maxAvailable logic, append
     *      abi.encodePacked(TOKEN ADDRESS, MAX_AVAILABLE_MARKER) to the end of calldata.
     */
    function deposit(uint256 amount, address receiver)
        external
        view
        virtual
        returns (bytes memory addressesFound, bytes memory targetData)
    {
        if (_checkForMarker(MAX_AVAILABLE_MARKER)) {
            amount = _maxAvailableFromOffset(64, amount);
            targetData = abi.encodeWithSelector(this.deposit.selector, amount, receiver);
        } else {
            targetData = msg.data;
        }
        addressesFound = abi.encodePacked(receiver);
    }

    /**
     * @dev maxAvailable logic is not supported for mint.
     */
    function mint(uint256 shares, address receiver)
        external
        pure
        virtual
        returns (bytes memory addressesFound, bytes memory targetData)
    {
        targetData = msg.data;
        addressesFound = abi.encodePacked(receiver);
    }

    /**
     * @dev To use maxAvailable logic, append
     *      abi.encodePacked(ERC4626 ADDRESS, MAX_AVAILABLE_MARKER) to the end of calldata.
     */
    function withdraw(uint256 amount, address receiver, address owner)
        external
        view
        virtual
        returns (bytes memory addressesFound, bytes memory targetData)
    {
        if (_checkForMarker(MAX_AVAILABLE_MARKER)) {
            if (amount == type(uint256).max) {
                ERC4626 erc4626 = ERC4626(_getAddressFromOffset(64));
                amount = erc4626.maxWithdraw(boringVault);
            }
            targetData = abi.encodeWithSelector(this.withdraw.selector, amount, receiver, owner);
        } else {
            targetData = msg.data;
        }
        addressesFound = abi.encodePacked(receiver, owner);
    }

    /**
     * @dev To use maxAvailable logic, append
     *      abi.encodePacked(ERC4626 ADDRESS, MAX_AVAILABLE_MARKER) to the end of calldata.
     */
    function redeem(uint256 shares, address receiver, address owner)
        external
        view
        virtual
        returns (bytes memory addressesFound, bytes memory targetData)
    {
        if (_checkForMarker(MAX_AVAILABLE_MARKER)) {
            if (shares == type(uint256).max) {
                ERC4626 erc4626 = ERC4626(_getAddressFromOffset(64));
                shares = erc4626.maxRedeem(boringVault);
            }
            targetData = abi.encodeWithSelector(this.redeem.selector, shares, receiver, owner);
        } else {
            targetData = msg.data;
        }
        addressesFound = abi.encodePacked(receiver, owner);
    }
}
