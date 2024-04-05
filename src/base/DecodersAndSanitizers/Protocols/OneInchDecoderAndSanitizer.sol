// SPDX-License-Identifier: MIT
pragma solidity 0.8.21;

import {BaseDecoderAndSanitizer, DecoderCustomTypes} from "src/base/DecodersAndSanitizers/BaseDecoderAndSanitizer.sol";

abstract contract OneInchDecoderAndSanitizer is BaseDecoderAndSanitizer {
    //============================== ERRORS ===============================

    error OneInchDecoderAndSanitizer__PermitNotSupported();

    //============================== ONEINCH ===============================

    function swap(
        address executor,
        DecoderCustomTypes.SwapDescription calldata desc,
        bytes calldata permit,
        bytes calldata
    ) external pure returns (bytes memory addressesFound, bytes memory targetData) {
        if (permit.length > 0) revert OneInchDecoderAndSanitizer__PermitNotSupported();
        targetData = msg.data;
        addressesFound = abi.encodePacked(executor, desc.srcToken, desc.dstToken, desc.srcReceiver, desc.dstReceiver);
    }

    function uniswapV3Swap(uint256, uint256, uint256[] calldata pools)
        external
        pure
        returns (bytes memory addressesFound, bytes memory targetData)
    {
        targetData = msg.data;
        for (uint256 i; i < pools.length; ++i) {
            addressesFound = abi.encodePacked(addressesFound, uint160(pools[i]));
        }
    }
}
