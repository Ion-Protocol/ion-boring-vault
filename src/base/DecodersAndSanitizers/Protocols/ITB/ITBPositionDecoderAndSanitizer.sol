/* SPDX-License-Identifier: UNLICENSED */
pragma solidity ^0.8.0;

import "./common/BoringDecoderAndSanitizer.sol";
import "./eigen_layer/EigenLayerDecoderAndSanitizer.sol";

contract ITBPositionDecoderAndSanitizer is BoringDecoderAndSanitizer, EigenLayerDecoderAndSanitizer {
    constructor(address _boringVault) BoringDecoderAndSanitizer(_boringVault) {}

    function transfer(address _to, uint256) external pure returns (bytes memory addressesFound) {
        addressesFound = abi.encodePacked(_to);
    }
}
