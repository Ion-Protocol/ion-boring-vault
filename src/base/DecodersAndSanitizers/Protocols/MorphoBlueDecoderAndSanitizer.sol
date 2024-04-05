// SPDX-License-Identifier: MIT
pragma solidity 0.8.21;

import {BaseDecoderAndSanitizer, DecoderCustomTypes} from "src/base/DecodersAndSanitizers/BaseDecoderAndSanitizer.sol";

abstract contract MorphoBlueDecoderAndSanitizer is BaseDecoderAndSanitizer {
    //============================== ERRORS ===============================

    error MorphoBlueDecoderAndSanitizer__CallbackNotSupported();

    //============================== MORPHO BLUE ===============================

    function supply(
        DecoderCustomTypes.MarketParams calldata params,
        uint256,
        uint256,
        address onBehalf,
        bytes calldata data
    ) external pure returns (bytes memory addressesFound, bytes memory targetData) {
        // Sanitize raw data
        if (data.length > 0) revert MorphoBlueDecoderAndSanitizer__CallbackNotSupported();
        targetData = msg.data;
        // Return addresses found
        addressesFound = abi.encodePacked(params.loanToken, params.collateralToken, params.oracle, params.irm, onBehalf);
    }

    function withdraw(
        DecoderCustomTypes.MarketParams calldata params,
        uint256,
        uint256,
        address onBehalf,
        address receiver
    ) external pure returns (bytes memory addressesFound, bytes memory targetData) {
        targetData = msg.data;
        // Return addresses found
        addressesFound =
            abi.encodePacked(params.loanToken, params.collateralToken, params.oracle, params.irm, onBehalf, receiver);
    }

    function borrow(
        DecoderCustomTypes.MarketParams calldata params,
        uint256,
        uint256,
        address onBehalf,
        address receiver
    ) external pure returns (bytes memory addressesFound, bytes memory targetData) {
        targetData = msg.data;
        addressesFound =
            abi.encodePacked(params.loanToken, params.collateralToken, params.oracle, params.irm, onBehalf, receiver);
    }

    function repay(
        DecoderCustomTypes.MarketParams calldata params,
        uint256,
        uint256,
        address onBehalf,
        bytes calldata data
    ) external pure returns (bytes memory addressesFound, bytes memory targetData) {
        // Sanitize raw data
        if (data.length > 0) revert MorphoBlueDecoderAndSanitizer__CallbackNotSupported();

        targetData = msg.data;
        // Return addresses found
        addressesFound = abi.encodePacked(params.loanToken, params.collateralToken, params.oracle, params.irm, onBehalf);
    }

    function supplyCollateral(
        DecoderCustomTypes.MarketParams calldata params,
        uint256,
        address onBehalf,
        bytes calldata data
    ) external pure returns (bytes memory addressesFound, bytes memory targetData) {
        // Sanitize raw data
        if (data.length > 0) revert MorphoBlueDecoderAndSanitizer__CallbackNotSupported();

        targetData = msg.data;
        // Return addresses found
        addressesFound = abi.encodePacked(params.loanToken, params.collateralToken, params.oracle, params.irm, onBehalf);
    }

    function withdrawCollateral(
        DecoderCustomTypes.MarketParams calldata params,
        uint256,
        address onBehalf,
        address receiver
    ) external pure returns (bytes memory addressesFound, bytes memory targetData) {
        targetData = msg.data;

        // Return addresses found
        addressesFound =
            abi.encodePacked(params.loanToken, params.collateralToken, params.oracle, params.irm, onBehalf, receiver);
    }
}
