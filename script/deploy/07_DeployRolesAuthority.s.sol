// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.21;

import {RolesAuthority} from "@solmate/auth/authorities/RolesAuthority.sol";
import {ManagerWithMerkleVerification} from "./../../src/base/Roles/ManagerWithMerkleVerification.sol";
import {BoringVault} from "./../../src/base/BoringVault.sol";
import {TellerWithMultiAssetSupport} from "./../../src/base/Roles/TellerWithMultiAssetSupport.sol";
import {AccountantWithRateProviders} from "./../../src/base/Roles/AccountantWithRateProviders.sol";
import {BaseScript} from "../Base.s.sol";
import {AtomicSolverV4} from "./../../src/atomic-queue/AtomicSolverV4.sol";

import {stdJson as StdJson} from "forge-std/StdJson.sol";

/**
 * NOTE Deploys with `Authority` set to zero bytes.
 */
contract DeployRolesAuthority is BaseScript {
    using StdJson for string;

    string path = "./deployment-config/07_DeployRolesAuthority.json";
    string config = vm.readFile(path);

    bytes32 rolesAuthoritySalt = config.readBytes32(".rolesAuthoritySalt");

    address boringVault = config.readAddress(".boringVault");
    address manager = config.readAddress(".manager");
    address teller = config.readAddress(".teller");
    address accountant = config.readAddress(".accountant");
    address strategist = config.readAddress(".strategist");
    address exchangeRateBot = config.readAddress(".exchangeRateBot");
    address solverBot = config.readAddress(".solverBot");
    address solver = config.readAddress(".solver");
    address queue = config.readAddress(".queue");

    uint8 public constant STRATEGIST_ROLE = 1;
    uint8 public constant MANAGER_ROLE = 2;
    uint8 public constant TELLER_ROLE = 3;
    uint8 public constant UPDATE_EXCHANGE_RATE_ROLE = 4;
    uint8 public constant SOLVER_ROLE = 5;
    uint8 public constant QUEUE_ROLE = 6;
    uint8 public constant SOLVER_CALLER_ROLE = 7;

    function run() public broadcast returns (RolesAuthority rolesAuthority) {
        require(boringVault.code.length != 0, "boringVault must have code");
        require(manager.code.length != 0, "manager must have code");
        require(teller.code.length != 0, "teller must have code");
        require(accountant.code.length != 0, "accountant must have code");
        require(solver.code.length != 0, "solver must have code");
        require(queue.code.length != 0, "queue must have code");
        
        require(boringVault != address(0), "boringVault");
        require(manager != address(0), "manager");
        require(teller != address(0), "teller");
        require(accountant != address(0), "accountant");
        require(strategist != address(0), "strategist");
        require(solver != address(0), "solver");
        require(queue != address(0), "queue");
        require(exchangeRateBot != address(0), "exchangeRateBot");
        require(solverBot != address(0), "solverBot");
        
        bytes memory creationCode = type(RolesAuthority).creationCode;

        rolesAuthority = RolesAuthority(
            CREATEX.deployCreate3(
                rolesAuthoritySalt,
                abi.encodePacked(
                    creationCode,
                    abi.encode(
                        broadcaster,
                        address(0) // `Authority`
                    )
                )
            )
        );

        // Setup initial roles configurations
        // --- Users ---
        // 1. VAULT_STRATEGIST (BOT EOA)
        // 2. MANAGER (CONTRACT)
        // 3. TELLER (CONTRACT)
        // --- Roles ---
        // 1. STRATEGIST_ROLE
        //     - manager.manageVaultWithMerkleVerification
        //     - assigned to VAULT_STRATEGIST
        // 2. MANAGER_ROLE
        //     - boringVault.manage()
        //     - assigned to MANAGER
        // 3. TELLER_ROLE
        //     - boringVault.enter()
        //     - boringVault.exit()
        //     - assigned to TELLER
        // 4. UPDATE_EXCHANGE_RATE_ROLE
        //     - accountant.updateExchangeRate
        //     - assigned to EXCHANGE_RATE_BOT
        // 5. SOLVER_ROLE
        //     - teller.bulkWithdraw
        //     - assigned to SOLVER
        // 6. QUEUE_ROLE
        //     - solver.finshSolve
        //     - assigned to QUEUE
        // 7. SOLVER_CALLER_ROLE
        //     - solver.p2pSolve
        //     - solver.redeemSolve
        //     - assigned to SOLVER_BOT
        // --- Public ---
        // 1. teller.deposit

        rolesAuthority.setRoleCapability(
            STRATEGIST_ROLE, manager, ManagerWithMerkleVerification.manageVaultWithMerkleVerification.selector, true
        );

        rolesAuthority.setRoleCapability(
            MANAGER_ROLE, boringVault, bytes4(keccak256(abi.encodePacked("manage(address,bytes,uint256)"))), true
        );

        rolesAuthority.setRoleCapability(
            MANAGER_ROLE, boringVault, bytes4(keccak256(abi.encodePacked("manage(address[],bytes[],uint256[])"))), true
        );

        rolesAuthority.setRoleCapability(TELLER_ROLE, boringVault, BoringVault.enter.selector, true);

        rolesAuthority.setRoleCapability(TELLER_ROLE, boringVault, BoringVault.exit.selector, true);

        rolesAuthority.setPublicCapability(teller, TellerWithMultiAssetSupport.deposit.selector, true);

        rolesAuthority.setRoleCapability(
            UPDATE_EXCHANGE_RATE_ROLE, accountant, AccountantWithRateProviders.updateExchangeRate.selector, true
        );

        rolesAuthority.setRoleCapability(
            SOLVER_ROLE, teller, TellerWithMultiAssetSupport.bulkWithdraw.selector, true
        );

        rolesAuthority.setRoleCapability(QUEUE_ROLE, solver, AtomicSolverV4.finishSolve.selector, true
        );

        rolesAuthority.setRoleCapability(
            SOLVER_CALLER_ROLE, solver, AtomicSolverV4.p2pSolve.selector, true
        );

        rolesAuthority.setRoleCapability(
            SOLVER_CALLER_ROLE, solver, AtomicSolverV4.redeemSolve.selector, true
        );

        // --- Assign roles to users ---

        rolesAuthority.setUserRole(strategist, STRATEGIST_ROLE, true);

        rolesAuthority.setUserRole(manager, MANAGER_ROLE, true);

        rolesAuthority.setUserRole(teller, TELLER_ROLE, true);

        rolesAuthority.setUserRole(exchangeRateBot, UPDATE_EXCHANGE_RATE_ROLE, true);

        rolesAuthority.setUserRole(solver, SOLVER_ROLE, true);
        
        rolesAuthority.setUserRole(queue, QUEUE_ROLE, true);
        
        rolesAuthority.setUserRole(solverBot, SOLVER_CALLER_ROLE, true);

        require(rolesAuthority.doesUserHaveRole(strategist, STRATEGIST_ROLE), "strategist should have STRATEGIST_ROLE");
        require(rolesAuthority.doesUserHaveRole(manager, MANAGER_ROLE), "manager should have MANAGER_ROLE");
        require(rolesAuthority.doesUserHaveRole(teller, TELLER_ROLE), "teller should have TELLER_ROLE");
        require(rolesAuthority.doesUserHaveRole(exchangeRateBot, UPDATE_EXCHANGE_RATE_ROLE), "exchangeRateBot should have UPDATE_EXCHANGE_RATE_ROLE");
        require(rolesAuthority.doesUserHaveRole(solver, SOLVER_ROLE), "solver should have SOLVER_ROLE");
        require(rolesAuthority.doesUserHaveRole(queue, QUEUE_ROLE), "queue should have QUEUE_ROLE");
        require(rolesAuthority.doesUserHaveRole(solverBot, SOLVER_CALLER_ROLE), "solverBot should have SOLVER_CALLER_ROLE");
        
        require(rolesAuthority.canCall(strategist, manager, ManagerWithMerkleVerification.manageVaultWithMerkleVerification.selector), "strategist should be able to call manageVaultWithMerkleVerification");
        require(rolesAuthority.canCall(manager, boringVault, bytes4(keccak256(abi.encodePacked("manage(address,bytes,uint256)")))), "manager should be able to call boringVault.manage");
        require(rolesAuthority.canCall(manager, boringVault, bytes4(keccak256(abi.encodePacked("manage(address[],bytes[],uint256[])")))), "manager should be able to call boringVault.manage");
        require(rolesAuthority.canCall(teller, boringVault, BoringVault.enter.selector), "teller should be able to call boringVault.enter");
        require(rolesAuthority.canCall(teller, boringVault, BoringVault.exit.selector), "teller should be able to call boringVault.exit");
        require(rolesAuthority.canCall(exchangeRateBot, accountant, AccountantWithRateProviders.updateExchangeRate.selector), "exchangeRateBot should be able to call accountant.updateExchangeRate");
        require(rolesAuthority.canCall(solver, teller, TellerWithMultiAssetSupport.bulkWithdraw.selector), "solver should be able to call teller.bulkWithdraw");
        require(rolesAuthority.canCall(queue, solver, AtomicSolverV4.finishSolve.selector), "queue should be able to call solver.finishSolve");
        require(rolesAuthority.canCall(solverBot, solver, AtomicSolverV4.p2pSolve.selector), "solverBot should be able to call solver.p2pSolve");
        require(rolesAuthority.canCall(solverBot, solver, AtomicSolverV4.redeemSolve.selector), "solverBot should be able to call solver.redeemSolve");

        require(rolesAuthority.canCall(address(1), teller, TellerWithMultiAssetSupport.deposit.selector), "anyone should be able to call teller.deposit");
    }
}
