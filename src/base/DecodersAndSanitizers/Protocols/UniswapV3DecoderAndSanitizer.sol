// SPDX-License-Identifier: MIT
pragma solidity 0.8.21;

import {INonFungiblePositionManager} from "src/interfaces/RawDataDecoderAndSanitizerInterfaces.sol";
import {BaseDecoderAndSanitizer, DecoderCustomTypes} from "src/base/DecodersAndSanitizers/BaseDecoderAndSanitizer.sol";

abstract contract UniswapV3DecoderAndSanitizer is BaseDecoderAndSanitizer {
    //============================== ERRORS ===============================

    error UniswapV3DecoderAndSanitizer__BadPathFormat();
    error UniswapV3DecoderAndSanitizer__BadTokenId();

    //============================== IMMUTABLES ===============================

    /**
     * @notice The networks uniswapV3 nonfungible position manager.
     */
    INonFungiblePositionManager internal immutable uniswapV3NonFungiblePositionManager;

    constructor(address _uniswapV3NonFungiblePositionManager) {
        uniswapV3NonFungiblePositionManager = INonFungiblePositionManager(_uniswapV3NonFungiblePositionManager);
    }

    //============================== UNISWAP V3 ===============================

    /**
     * @dev maxAvailable logic is not supported for exactInput.
     *      This would mean the params input needs to be memory instead of
     *      calldata, so that we can modify the params, but doing so makes the
     *      address extraction much more gas intensive.
     */
    function exactInput(DecoderCustomTypes.ExactInputParams calldata params)
        external
        pure
        virtual
        returns (bytes memory addressesFound, bytes memory targetData)
    {
        targetData = msg.data;
        // Return addresses found
        // Determine how many addresses are in params.path.
        uint256 chunkSize = 23; // 3 bytes for uint24 fee, and 20 bytes for address token
        uint256 pathLength = params.path.length;
        if (pathLength % chunkSize != 20) revert UniswapV3DecoderAndSanitizer__BadPathFormat();
        uint256 pathAddressLength = 1 + (pathLength / chunkSize);
        uint256 pathIndex;
        for (uint256 i; i < pathAddressLength; ++i) {
            addressesFound = abi.encodePacked(addressesFound, params.path[pathIndex:pathIndex + 20]);
            pathIndex += chunkSize;
        }
        addressesFound = abi.encodePacked(addressesFound, params.recipient);
    }

    /**
     * @dev To use maxAvailable logic, append
     *      abi.encodePacked(MAX_AVAILABLE_MARKER) to the end of calldata.
     */
    function mint(DecoderCustomTypes.MintParams memory params)
        external
        view
        virtual
        returns (bytes memory addressesFound, bytes memory targetData)
    {
        if (_checkForMarker(MAX_AVAILABLE_MARKER)) {
            params.amount0Desired = _maxAvailable(params.token0, params.amount0Desired);
            params.amount1Desired = _maxAvailable(params.token1, params.amount1Desired);
            targetData = abi.encodeWithSelector(this.mint.selector, params);
        } else {
            targetData = msg.data;
        }
        // Return addresses found
        addressesFound = abi.encodePacked(params.token0, params.token1, params.recipient);
    }

    /**
     * @dev To use maxAvailable logic, append
     *      abi.encodePacked(MAX_AVAILABLE_MARKER) to the end of calldata.
     */
    function increaseLiquidity(DecoderCustomTypes.IncreaseLiquidityParams memory params)
        external
        view
        virtual
        returns (bytes memory addressesFound, bytes memory targetData)
    {
        // Sanitize raw data
        if (uniswapV3NonFungiblePositionManager.ownerOf(params.tokenId) != boringVault) {
            revert UniswapV3DecoderAndSanitizer__BadTokenId();
        }

        // Extract addresses from uniswapV3NonFungiblePositionManager.positions(params.tokenId).
        (, address operator, address token0, address token1,,,,,,,,) =
            uniswapV3NonFungiblePositionManager.positions(params.tokenId);

        if (_checkForMarker(MAX_AVAILABLE_MARKER)) {
            params.amount0Desired = _maxAvailable(token0, params.amount0Desired);
            params.amount1Desired = _maxAvailable(token1, params.amount1Desired);
            targetData = abi.encodeWithSelector(this.increaseLiquidity.selector, params);
        } else {
            targetData = msg.data;
        }

        addressesFound = abi.encodePacked(operator, token0, token1);
    }

    /**
     * @dev To use maxAvailable logic, append
     *      abi.encodePacked(MAX_AVAILABLE_MARKER) to the end of calldata.
     * @dev Note liquidity should be uint128 max.
     */
    function decreaseLiquidity(DecoderCustomTypes.DecreaseLiquidityParams memory params)
        external
        view
        virtual
        returns (bytes memory addressesFound, bytes memory targetData)
    {
        // Sanitize raw data
        // NOTE ownerOf check is done in PositionManager contract as well, but it is added here
        // just for completeness.
        if (uniswapV3NonFungiblePositionManager.ownerOf(params.tokenId) != boringVault) {
            revert UniswapV3DecoderAndSanitizer__BadTokenId();
        }
        if (_checkForMarker(MAX_AVAILABLE_MARKER)) {
            if (params.liquidity == type(uint128).max) {
                (,,,,,,, params.liquidity,,,,) = uniswapV3NonFungiblePositionManager.positions(params.tokenId);
            }
            targetData = abi.encodeWithSelector(this.decreaseLiquidity.selector, params);
        } else {
            targetData = msg.data;
        }
    }

    /**
     * @dev maxAvailable logic is not supported for collect.
     */
    function collect(DecoderCustomTypes.CollectParams calldata params)
        external
        view
        virtual
        returns (bytes memory addressesFound, bytes memory targetData)
    {
        // Sanitize raw data
        // NOTE ownerOf check is done in PositionManager contract as well, but it is added here
        // just for completeness.
        if (uniswapV3NonFungiblePositionManager.ownerOf(params.tokenId) != boringVault) {
            revert UniswapV3DecoderAndSanitizer__BadTokenId();
        }
        targetData = msg.data;
        // Return addresses found
        addressesFound = abi.encodePacked(params.recipient);
    }
}
