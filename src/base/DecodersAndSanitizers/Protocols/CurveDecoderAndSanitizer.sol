// SPDX-License-Identifier: MIT
pragma solidity 0.8.21;

import {BaseDecoderAndSanitizer, DecoderCustomTypes} from "src/base/DecodersAndSanitizers/BaseDecoderAndSanitizer.sol";

abstract contract CurveDecoderAndSanitizer is BaseDecoderAndSanitizer {
    //============================== CURVE ===============================

    /**
     * @dev To use maxAvailable logic, append
     *      abi.encodePacked(TOKEN ADDRESS, MAX_AVAILABLE_MARKER) to the end of calldata.
     */
    function exchange(int128 i, int128 j, uint256 dx, uint256 min_dy)
        external
        view
        virtual
        returns (bytes memory, bytes memory targetData)
    {
        if (_checkForMarker(MAX_AVAILABLE_MARKER)) {
            dx = _maxAvailableFromOffset(64, dx);
            targetData = abi.encodeWithSelector(this.exchange.selector, i, j, dx, min_dy);
        } else {
            targetData = msg.data;
        }
    }

    /**
     * @dev To use maxAvailable logic, append
     *      abi.encodePacked(TOKEN ADDRESS 0,..., TOKEN ADDRESS N-1 , MAX_AVAILABLE_MARKER) to the end of calldata.
     *      Where N is the number of tokens in the pool.
     * @dev Tokens must be in reverse order of the pool.
     */
    function add_liquidity(uint256[] memory amounts, uint256 minOut)
        external
        view
        virtual
        returns (bytes memory, bytes memory targetData)
    {
        if (_checkForMarker(MAX_AVAILABLE_MARKER)) {
            for (uint256 i; i < amounts.length; ++i) {
                amounts[i] = _maxAvailableFromOffset(64 + (i * 20), amounts[i]);
            }
            targetData = abi.encodeWithSelector(this.add_liquidity.selector, amounts, minOut);
        } else {
            targetData = msg.data;
        }
    }

    /**
     * @dev To use maxAvailable logic, append
     *      abi.encodePacked(LP TOKEN ADDRESS, MAX_AVAILABLE_MARKER) to the end of calldata.
     */
    function remove_liquidity(uint256 amount, uint256[] calldata minAmountsOut)
        external
        view
        virtual
        returns (bytes memory, bytes memory targetData)
    {
        if (_checkForMarker(MAX_AVAILABLE_MARKER)) {
            amount = _maxAvailableFromOffset(64, amount);
            targetData = abi.encodeWithSelector(this.remove_liquidity.selector, amount, minAmountsOut);
        } else {
            targetData = msg.data;
        }
    }

    /**
     * @dev To use maxAvailable logic, append
     *      abi.encodePacked(LP TOKEN ADDRESS, MAX_AVAILABLE_MARKER) to the end of calldata.
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
     * @dev To use maxAvailable logic, append
     *      abi.encodePacked(LP TOKEN ADDRESS, MAX_AVAILABLE_MARKER) to the end of calldata.
     */
    function withdraw(uint256 amount)
        external
        view
        virtual
        returns (bytes memory addressesFound, bytes memory targetData)
    {
        if (_checkForMarker(MAX_AVAILABLE_MARKER)) {
            amount = _maxAvailableFromOffset(64, amount);
            targetData = abi.encodeWithSelector(this.withdraw.selector, amount);
        } else {
            targetData = msg.data;
        }
    }

    /**
     * @dev maxAvailable logic is not supported for this function.
     */
    function claim_rewards(address _addr)
        external
        pure
        virtual
        returns (bytes memory addressesFound, bytes memory targetData)
    {
        targetData = msg.data;
        addressesFound = abi.encodePacked(_addr);
    }
}
