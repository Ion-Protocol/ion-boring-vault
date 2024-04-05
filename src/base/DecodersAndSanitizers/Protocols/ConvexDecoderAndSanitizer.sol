// SPDX-License-Identifier: MIT
pragma solidity 0.8.21;

import {BaseDecoderAndSanitizer, DecoderCustomTypes} from "src/base/DecodersAndSanitizers/BaseDecoderAndSanitizer.sol";

abstract contract ConvexDecoderAndSanitizer is BaseDecoderAndSanitizer {
    //============================== CONVEX ===============================

    function deposit(uint256, uint256, bool)
        external
        view
        virtual
        returns (bytes memory addressesFound, bytes memory targetData)
    {
        targetData = msg.data;
    }

    function withdrawAndUnwrap(uint256, bool)
        external
        view
        virtual
        returns (bytes memory addressesFound, bytes memory targetData)
    {
        targetData = msg.data;
    }

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
