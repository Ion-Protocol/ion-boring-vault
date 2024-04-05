// SPDX-License-Identifier: MIT
pragma solidity 0.8.21;

import {BaseDecoderAndSanitizer, DecoderCustomTypes} from "src/base/DecodersAndSanitizers/BaseDecoderAndSanitizer.sol";

abstract contract ConvexDecoderAndSanitizer is BaseDecoderAndSanitizer {
    //============================== CONVEX ===============================

    /**
     * @dev To use maxAvailable logic, append
     *      abi.encodePacked(LP TOKEN ADDRESS, MAX_AVAILABLE_MARKER) to the end of calldata.
     */
    function deposit(uint256 pid, uint256 amount, bool b)
        external
        view
        virtual
        returns (bytes memory, bytes memory targetData)
    {
        if (_checkForMarker(MAX_AVAILABLE_MARKER)) {
            amount = _maxAvailableFromOffset(64, amount);
            targetData = abi.encodeWithSelector(this.deposit.selector, pid, amount, b);
        } else {
            targetData = msg.data;
        }
    }

    /**
     * @dev To use maxAvailable logic, append
     *      abi.encodePacked(LP TOKEN ADDRESS, MAX_AVAILABLE_MARKER) to the end of calldata.
     */
    function withdrawAndUnwrap(uint256 amount, bool unwrap)
        external
        view
        virtual
        returns (bytes memory, bytes memory targetData)
    {
        if (_checkForMarker(MAX_AVAILABLE_MARKER)) {
            amount = _maxAvailableFromOffset(64, amount);
            targetData = abi.encodeWithSelector(this.withdrawAndUnwrap.selector, amount, unwrap);
        } else {
            targetData = msg.data;
        }
    }

    /**
     * @dev maxAvailable logic is not supported for this function.
     */
    function getReward(address _addr, bool)
        external
        pure
        virtual
        returns (bytes memory addressesFound, bytes memory targetData)
    {
        targetData = msg.data;
        addressesFound = abi.encodePacked(_addr);
    }
}
