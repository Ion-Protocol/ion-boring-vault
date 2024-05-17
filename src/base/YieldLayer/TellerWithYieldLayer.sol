// SPDX-License-Identifier: MIT
pragma solidity 0.8.21;

import {TellerWithMultiAssetSupport, FixedPointMathLib} from "src/base/Roles/TellerWithMultiAssetSupport.sol";
import {RebasingBoringVaultWrapper} from "src/base/YieldLayer/RebasingBoringVaultWrapper.sol";

contract TellerWithYieldLayer is TellerWithMultiAssetSupport {
    using FixedPointMathLib for uint256;

    RebasingBoringVaultWrapper public immutable wrapper;

    constructor(address _owner, address _vault, address _accountant, address _weth, address _wrapper)
        TellerWithMultiAssetSupport(_owner, _vault, _accountant, _weth)
    {
        wrapper = RebasingBoringVaultWrapper(_wrapper);
    }

    function multicall(bytes[] calldata data) public returns (bytes[] memory results) {
        results = new bytes[](data.length);
        for (uint256 i = 0; i < data.length; i++) {
            (bool success, bytes memory result) = address(this).delegatecall(data[i]);

            if (!success) {
                // Next 5 lines from https://ethereum.stackexchange.com/a/83577
                if (result.length < 68) revert();
                assembly {
                    result := add(result, 0x04)
                }
                revert(abi.decode(result, (string)));
            }

            results[i] = result;
        }
    }

    /**
     * @notice Accepts BoringVault shares and wraps them into RebasingBoringVaultWrapper shares.
     */
    function wrap(uint256 amount) public {
        wrapper.enter(msg.sender, msg.sender, amount);
    }

    function wrapWithPermit(uint256 amount, uint256 deadline, uint8 v, bytes32 r, bytes32 s) public {
        try vault.permit(msg.sender, address(wrapper), amount, deadline, v, r, s) {}
        catch {
            if (vault.allowance(msg.sender, address(wrapper)) < amount) {
                revert("Sadness");
            }
        }
        wrapper.enter(msg.sender, msg.sender, amount);
    }

    function unwrap(uint256 amount) public {
        uint256 amountAdjusted = amount.mulDivDown(10 ** wrapper.decimals(), wrapper.getRate());
        wrapper.exit(msg.sender, msg.sender, amountAdjusted);
    }
    // TODO bridge
    // TODO bridgeWithPermit

    // TODO we will need some virtual internal functions to implement.
    // TODO one to send messages cross chain
    // TODO one to receive messages cross chain
    // They will need to call the BoringVault enter and exit functions, but specify ZERO for the asset amounts.

    // Deposit is already handled.
}
