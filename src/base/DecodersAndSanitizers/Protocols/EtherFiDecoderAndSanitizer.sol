// SPDX-License-Identifier: MIT
pragma solidity 0.8.21;

import {BaseDecoderAndSanitizer, DecoderCustomTypes} from "src/base/DecodersAndSanitizers/BaseDecoderAndSanitizer.sol";

abstract contract EtherFiDecoderAndSanitizer is BaseDecoderAndSanitizer {
    //============================== ETHERFI ===============================

    function deposit() external pure virtual returns (bytes memory addressesFound, bytes memory targetData) {
        targetData = msg.data;
    }

    function wrap(uint256) external pure virtual returns (bytes memory addressesFound, bytes memory targetData) {
        targetData = msg.data;
    }

    function unwrap(uint256) external pure virtual returns (bytes memory addressesFound, bytes memory targetData) {
        targetData = msg.data;
    }

    function requestWithdraw(address _addr, uint256)
        external
        pure
        virtual
        returns (bytes memory addressesFound, bytes memory targetData)
    {
        targetData = msg.data;
        addressesFound = abi.encodePacked(_addr);
    }

    function claimWithdraw(uint256)
        external
        pure
        virtual
        returns (bytes memory addressesFound, bytes memory targetData)
    {
        targetData = msg.data;
    }
}
