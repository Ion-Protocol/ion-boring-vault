// SPDX-License-Identifier: MIT
pragma solidity 0.8.21;

import {RebasingERC20} from "src/base/YieldLayer/RebasingERC20.sol";
import {BoringVault} from "src/base/BoringVault.sol";
import {AccountantWithRateProviders} from "src/base/Roles/AccountantWithRateProviders.sol";
import {Auth, Authority} from "@solmate/auth/Auth.sol";
import {IRateProvider} from "src/interfaces/IRateProvider.sol";
import {SafeTransferLib} from "@solmate/utils/SafeTransferLib.sol";

contract RebasingBoringVaultWrapper is RebasingERC20, Auth {
    using SafeTransferLib for BoringVault;

    BoringVault public immutable boringVault;
    AccountantWithRateProviders public accountant;
    bool public useSafeRate;

    constructor(address _boringVault, address _owner) RebasingERC20("", "", 0) Auth(_owner, Authority(address(0))) {
        boringVault = BoringVault(payable(_boringVault));

        name = string.concat("Wrapped ", boringVault.name());
        symbol = string.concat("w", boringVault.symbol());
        decimals = boringVault.decimals();
    }

    function setAccountant(AccountantWithRateProviders _accountant) external requiresAuth {
        if (_accountant.decimals() != decimals) {
            revert("RebasingBoringVaultWrapper: mismatching decimals");
        }
        accountant = _accountant;
    }

    function toggleSafeRate() external requiresAuth {
        useSafeRate = !useSafeRate;
    }

    function _getRate() internal view override returns (uint256) {
        if (useSafeRate) {
            return accountant.getRateSafe();
        } else {
            return accountant.getRate();
        }
    }

    function getRate() external view returns (uint256) {
        return _getRate();
    }

    //============================== ENTER ===============================

    // TODO asset and assetAmount are BoringVault and BoringVAult shares.
    function enter(address from, address to, uint256 shareAmount) external requiresAuth {
        // Transfer assets in
        boringVault.safeTransferFrom(from, address(this), shareAmount);

        // Mint shares.
        _mint(to, shareAmount);

        // emit Enter(from, asset, assetAmount, to, shareAmount);
    }

    //============================== EXIT ===============================

    function exit(address to, address from, uint256 shareAmount) external requiresAuth {
        // Burn shares.
        _burn(from, shareAmount);

        // Transfer assets out.
        boringVault.safeTransfer(to, shareAmount);

        // emit Exit(to, asset, assetAmount, from, shareAmount);
    }
}
