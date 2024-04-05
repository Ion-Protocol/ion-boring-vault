// SPDX-License-Identifier: MIT
pragma solidity 0.8.21;

import {BaseDecoderAndSanitizer, DecoderCustomTypes} from "src/base/DecodersAndSanitizers/BaseDecoderAndSanitizer.sol";

abstract contract NativeWrapperDecoderAndSanitizer is BaseDecoderAndSanitizer {
    //============================== ETHERFI ===============================

    function deposit() external pure virtual returns (bytes memory addressesFound, bytes memory targetData) {
        targetData = msg.data;
    }

    function withdraw(uint256) external pure virtual returns (bytes memory addressesFound, bytes memory targetData) {
        targetData = msg.data;
    }
}
