// SPDX-License-Identifier: MIT
pragma solidity 0.8.21;

import {BaseDecoderAndSanitizer, DecoderCustomTypes} from "src/base/DecodersAndSanitizers/BaseDecoderAndSanitizer.sol";

abstract contract RenzoDecoderAndSanitizer is BaseDecoderAndSanitizer {
    //============================== RENZO ===============================

    function depositETH() external pure virtual returns (bytes memory addressesFound, bytes memory targetData) {
        targetData = msg.data;
    }
}
