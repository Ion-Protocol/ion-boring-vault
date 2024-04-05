// SPDX-License-Identifier: MIT
pragma solidity 0.8.21;

import {BaseDecoderAndSanitizer, DecoderCustomTypes} from "src/base/DecodersAndSanitizers/BaseDecoderAndSanitizer.sol";

abstract contract GearboxDecoderAndSanitizer is BaseDecoderAndSanitizer {
    //============================== GEARBOX ===============================

    function deposit(uint256) external pure virtual returns (bytes memory addressesFound, bytes memory targetData) {
        targetData = msg.data;
    }

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

    function claim() external pure virtual returns (bytes memory addressesFound, bytes memory targetData) {
        targetData = msg.data;
    }
}
