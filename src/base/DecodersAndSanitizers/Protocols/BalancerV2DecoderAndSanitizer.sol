// SPDX-License-Identifier: MIT
pragma solidity 0.8.21;

import {
    BaseDecoderAndSanitizer,
    DecoderCustomTypes,
    ERC20
} from "src/base/DecodersAndSanitizers/BaseDecoderAndSanitizer.sol";

abstract contract BalancerV2DecoderAndSanitizer is BaseDecoderAndSanitizer {
    //============================== ERRORS ===============================

    error BalancerV2DecoderAndSanitizer__SingleSwapUserDataLengthNonZero();
    error BalancerV2DecoderAndSanitizer__InternalBalancesNotSupported();
    error BalancerV2DecoderAndSanitizer__ExitTypeMustBeProportional();

    //============================== BALANCER V2 ===============================

    function flashLoan(address recipient, address[] calldata tokens, uint256[] calldata, bytes calldata)
        external
        pure
        virtual
        returns (bytes memory addressesFound, bytes memory targetData)
    {
        targetData = msg.data;
        addressesFound = abi.encodePacked(recipient);
        for (uint256 i; i < tokens.length; ++i) {
            addressesFound = abi.encodePacked(addressesFound, tokens[i]);
        }
    }

    /**
     * @dev To use maxAvailable logic, append
     *      abi.encodePacked(MAX_AVAILABLE_MARKER) to the end of calldata.
     */
    function swap(
        DecoderCustomTypes.SingleSwap memory singleSwap,
        DecoderCustomTypes.FundManagement calldata funds,
        uint256 limit,
        uint256 deadline
    ) external view virtual returns (bytes memory addressesFound, bytes memory targetData) {
        // Sanitize raw data
        if (singleSwap.userData.length > 0) revert BalancerV2DecoderAndSanitizer__SingleSwapUserDataLengthNonZero();
        if (funds.fromInternalBalance) revert BalancerV2DecoderAndSanitizer__InternalBalancesNotSupported();
        if (funds.toInternalBalance) revert BalancerV2DecoderAndSanitizer__InternalBalancesNotSupported();

        if (_checkForMarker(MAX_AVAILABLE_MARKER)) {
            // This only works if singleSwap.kind == SwapKind.GIVEN_IN
            if (singleSwap.kind == DecoderCustomTypes.SwapKind.GIVEN_IN) {
                singleSwap.amount = _maxAvailable(singleSwap.assetIn, singleSwap.amount);
                targetData = abi.encodeWithSelector(this.swap.selector, singleSwap, funds, limit, deadline);
            }
            // TODO add explicit revert and test
        } else {
            targetData = msg.data;
        }

        // Return addresses found
        addressesFound = abi.encodePacked(
            _getPoolAddressFromPoolId(singleSwap.poolId),
            singleSwap.assetIn,
            singleSwap.assetOut,
            funds.sender,
            funds.recipient
        );
    }

    /**
     * @dev To use maxAvailable logic, append
     *      abi.encodePacked(MAX_AVAILABLE_MARKER) to the end of calldata.
     * @dev If maxAvailable is used, then maxAmountsIn will equal the max available amount for each asset.
     */
    function joinPool(bytes32 poolId, address sender, address recipient, DecoderCustomTypes.JoinPoolRequest memory req)
        external
        view
        virtual
        returns (bytes memory addressesFound, bytes memory targetData)
    {
        // Sanitize raw data
        if (req.fromInternalBalance) revert BalancerV2DecoderAndSanitizer__InternalBalancesNotSupported();

        if (_checkForMarker(MAX_AVAILABLE_MARKER)) {
            uint256 maxAmountsInLength = req.maxAmountsIn.length;
            for (uint256 i; i < maxAmountsInLength; ++i) {
                req.maxAmountsIn[i] = _maxAvailable(req.assets[i], req.maxAmountsIn[i]);
            }
            (uint8 kind,, uint256 minBPTOut) = abi.decode(req.userData, (uint8, uint256[], uint256));
            req.userData = abi.encode(kind, req.maxAmountsIn, minBPTOut);
            targetData = abi.encodeWithSelector(this.joinPool.selector, poolId, sender, recipient, req);
        } else {
            targetData = msg.data;
        }

        // Return addresses found
        addressesFound = abi.encodePacked(_getPoolAddressFromPoolId(poolId), sender, recipient);
        uint256 assetsLength = req.assets.length;
        for (uint256 i; i < assetsLength; ++i) {
            addressesFound = abi.encodePacked(addressesFound, req.assets[i]);
        }
    }

    // TODO add error checking revert test
    /**
     * @dev To use maxAvailable logic, append
     *      abi.encodePacked(MAX_AVAILABLE_MARKER) to the end of calldata.
     * @dev If maxAvailable is used, exit type must be proportional.
     */
    function exitPool(bytes32 poolId, address sender, address recipient, DecoderCustomTypes.ExitPoolRequest memory req)
        external
        view
        virtual
        returns (bytes memory addressesFound, bytes memory targetData)
    {
        // Sanitize raw data
        if (req.toInternalBalance) revert BalancerV2DecoderAndSanitizer__InternalBalancesNotSupported();
        address poolAddress = _getPoolAddressFromPoolId(poolId);

        if (_checkForMarker(MAX_AVAILABLE_MARKER)) {
            (uint8 kind, uint256 bptAmountIn) = abi.decode(req.userData, (uint8, uint256));
            if (kind != 1) revert BalancerV2DecoderAndSanitizer__ExitTypeMustBeProportional();
            bptAmountIn = _maxAvailable(poolAddress, bptAmountIn);
            req.userData = abi.encode(kind, bptAmountIn);
            targetData = abi.encodeWithSelector(this.exitPool.selector, poolId, sender, recipient, req);
        } else {
            targetData = msg.data;
        }

        // Return addresses found
        addressesFound = abi.encodePacked(poolAddress, sender, recipient);
        uint256 assetsLength = req.assets.length;
        for (uint256 i; i < assetsLength; ++i) {
            addressesFound = abi.encodePacked(addressesFound, req.assets[i]);
        }
    }

    /**
     * @dev To use maxAvailable logic, append
     *      abi.encodePacked(BPT ADDRESS, MAX_AVAILABLE_MARKER) to the end of calldata.
     */
    function deposit(uint256 amount, address recipient)
        external
        view
        virtual
        returns (bytes memory addressesFound, bytes memory targetData)
    {
        if (_checkForMarker(MAX_AVAILABLE_MARKER)) {
            amount = _maxAvailableFromOffset(64, amount);
            targetData = abi.encodeWithSelector(this.deposit.selector, amount, recipient);
        } else {
            targetData = msg.data;
        }
        addressesFound = abi.encodePacked(recipient);
    }

    /**
     * @dev To use maxAvailable logic, append
     *      abi.encodePacked(GAUGE ADDRESS, MAX_AVAILABLE_MARKER) to the end of calldata.
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

    function mint(address gauge) external pure virtual returns (bytes memory addressesFound, bytes memory targetData) {
        targetData = msg.data;
        addressesFound = abi.encodePacked(gauge);
    }

    // ========================================= INTERNAL HELPER FUNCTIONS =========================================

    /**
     * @notice Internal helper function that converts poolIds to pool addresses.
     */
    function _getPoolAddressFromPoolId(bytes32 poolId) internal pure returns (address) {
        return address(uint160(uint256(poolId >> 96)));
    }
}
