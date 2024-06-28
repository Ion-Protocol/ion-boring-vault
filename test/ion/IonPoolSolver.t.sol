// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.21;

import {BoringVault} from "./../../src/base/BoringVault.sol";
import {EthPerWstEthRateProvider} from "./../../src/oracles/EthPerWstEthRateProvider.sol";
import {ETH_PER_STETH_CHAINLINK, WSTETH_ADDRESS} from "@ion-protocol/Constants.sol";
import {IonPoolSharedSetup} from "./IonPoolSharedSetup.sol";
import {ERC20} from "@solmate/tokens/ERC20.sol";
import {FixedPointMathLib} from "@solmate/utils/FixedPointMathLib.sol";
import {TellerWithMultiAssetSupport} from "./../../src/base/Roles/TellerWithMultiAssetSupport.sol";
import {AtomicSolverV4} from "./../../src/atomic-queue/AtomicSolverV4.sol";
import {AtomicQueueV2} from "./../../src/atomic-queue/AtomicQueueV2.sol";
import {RolesAuthority, Authority} from "@solmate/auth/authorities/RolesAuthority.sol";

import {console2} from "forge-std/console2.sol";

contract IonPoolSolverTest is IonPoolSharedSetup {
    using FixedPointMathLib for uint256;

    AtomicSolverV4 public atomicSolver;
    AtomicQueueV2 public atomicQueue;
    address immutable SOLVER_OWNER = makeAddr("AtomicSolverV4");
    uint8 public constant SOLVER_ROLE = 5;
    uint8 public constant QUEUE_ROLE = 6;
    uint8 public constant SOLVER_CALLER_ROLE = 7;
    

    EthPerWstEthRateProvider ethPerWstEthRateProvider;

    function setUp() public override {
        super.setUp();

        WETH.approve(address(boringVault), type(uint256).max);
        WSTETH.approve(address(boringVault), type(uint256).max);

        vm.startPrank(TELLER_OWNER);
        teller.addAsset(WETH);
        teller.addAsset(WSTETH);
        vm.stopPrank();

        // Setup accountant

        ethPerWstEthRateProvider =
            new EthPerWstEthRateProvider(address(ETH_PER_STETH_CHAINLINK), address(WSTETH_ADDRESS), 1 days);
        bool isPeggedToBase = false;

        atomicSolver = new AtomicSolverV4(SOLVER_OWNER, Authority(address(0)));

        atomicQueue = new AtomicQueueV2();

        rolesAuthority.setRoleCapability(
            SOLVER_ROLE,
            address(teller),
            TellerWithMultiAssetSupport.bulkWithdraw.selector,
            true
        );

        rolesAuthority.setRoleCapability(
            QUEUE_ROLE,
            address(atomicSolver),
            AtomicSolverV4.finishSolve.selector,
            true
        );

        rolesAuthority.setRoleCapability(
            SOLVER_CALLER_ROLE,
            address(atomicSolver),
            AtomicSolverV4.p2pSolve.selector,
            true
        );

        rolesAuthority.setRoleCapability(
            SOLVER_CALLER_ROLE,
            address(atomicSolver),
            AtomicSolverV4.redeemSolve.selector,
            true
        );

        rolesAuthority.setUserRole(address(atomicSolver), SOLVER_ROLE, true);
        rolesAuthority.setUserRole(address(atomicQueue), QUEUE_ROLE, true);
        rolesAuthority.setUserRole(SOLVER_OWNER, SOLVER_CALLER_ROLE, true);

        vm.prank(ACCOUNTANT_OWNER);
        accountant.setRateProviderData(
            ERC20(address(WSTETH_ADDRESS)), isPeggedToBase, address(ethPerWstEthRateProvider)
        );
    }

    function test_Deposit_MultipleUsers() public {
        uint256 depositAmt = 10 ether;
        uint256 minimumMint = 10 ether;

        // base / deposit asset
        uint256 basePerQuote = ethPerWstEthRateProvider.getRate(); // base / quote
        uint256 quotePerShare = accountant.getRateInQuoteSafe(WSTETH); // quote / share

        console2.log("base Per Quote", basePerQuote);

        uint256 basePerShare = accountant.getRate();
        uint256 expectedQuotePerShare = basePerShare * 1e18 / basePerQuote; // (base / share) / (base / quote) = quote / share

        uint256 shares = depositAmt.mulDivDown(1e18, quotePerShare);
        // mint amount = deposit amount * exchangeRate

        console2.log("shares", shares);

        deal(address(WSTETH), address(this), depositAmt);
        teller.deposit(WSTETH, depositAmt, minimumMint);
        address[] memory users = new address[](3);
        users[0] = makeAddr("user1");
        users[1] = makeAddr("user2");
        users[2] = makeAddr("user3");
        deal(address(WSTETH), users[0], depositAmt);
        deal(address(WSTETH), users[1], depositAmt);
        deal(address(WETH), users[2], depositAmt);
        vm.startPrank(users[0]);
        ERC20(WSTETH).approve(address(boringVault), type(uint256).max);
        teller.deposit(WSTETH, depositAmt, minimumMint);
        vm.stopPrank();
        vm.startPrank(users[1]);
        ERC20(WSTETH).approve(address(boringVault), type(uint256).max);
        teller.deposit(WSTETH, depositAmt, minimumMint);
        vm.stopPrank();
        vm.startPrank(users[2]);
        ERC20(WETH).approve(address(boringVault), type(uint256).max);
        teller.deposit(WETH, depositAmt, minimumMint);
        vm.stopPrank();

        assertEq(quotePerShare, expectedQuotePerShare, "exchange rate must read from price oracle");
        assertEq(boringVault.balanceOf(address(this)), shares, "shares minted");
        assertEq(WSTETH.balanceOf(address(this)), 0, "WSTETH transferred from user");
        assertEq(WSTETH.balanceOf(address(boringVault)), depositAmt * 3, "WSTETH transferred to vault");
        assertEq(WETH.balanceOf(address(boringVault)), depositAmt, "WETH transferred from user");


        // set atomic queue requests

        AtomicQueueV2.AtomicRequest memory request1 = AtomicQueueV2.AtomicRequest({
            deadline: 2**32,
            atomicPrice: 10**17,//0.1
            offerAmount: 10**18,//1 share
            inSolve: false
        });

        AtomicQueueV2.AtomicRequest memory request2 = AtomicQueueV2.AtomicRequest({
            deadline: 2**32,
            atomicPrice: 10**18,//1
            offerAmount: 10**18,//1 share
            inSolve: false
        });

        AtomicQueueV2.AtomicRequest memory request3 = AtomicQueueV2.AtomicRequest({
            deadline: 2**32,
            atomicPrice: 2 * 10**18,//2
            offerAmount: 10**18,//1 share
            inSolve: false
        });

        vm.prank(users[0]);
        atomicQueue.updateAtomicRequest(ERC20(boringVault), ERC20(WSTETH), request1);
        ERC20(boringVault).approve(address(atomicQueue), type(uint256).max);
        vm.stopPrank();
        vm.prank(users[1]);
        atomicQueue.updateAtomicRequest(ERC20(boringVault), ERC20(WSTETH), request2);
        ERC20(boringVault).approve(address(atomicQueue), type(uint256).max);
        vm.stopPrank();
        vm.prank(users[2]);
        atomicQueue.updateAtomicRequest(ERC20(boringVault), ERC20(WSTETH), request3);
        ERC20(boringVault).approve(address(atomicQueue), type(uint256).max);
        vm.stopPrank();

        AtomicQueueV2.AtomicRequest[] memory requests = new AtomicQueueV2.AtomicRequest[](3);
        requests[0] = atomicQueue.getUserAtomicRequest(users[0], ERC20(boringVault), ERC20(WSTETH));
        requests[1] = atomicQueue.getUserAtomicRequest(users[1], ERC20(boringVault), ERC20(WSTETH));
        requests[2] = atomicQueue.getUserAtomicRequest(users[2], ERC20(boringVault), ERC20(WSTETH));

        assertEq(requests[0].atomicPrice, 10**17, "request 1 atomic price");
        assertEq(requests[1].atomicPrice, 10**18, "request 2 atomic price");
        assertEq(requests[2].atomicPrice, 2 * 10**18, "request 3 atomic price");

        vm.startPrank(SOLVER_OWNER);
        vm.expectRevert(AtomicQueueV2__PriceTooHigh.selector, "AtomicQueueV2: PriceTooHigh");
        // queue, vault, want, users, min want asset (slippage param), maxAssets (cumsum of atomicPrice and offerAmounts), teller
        atomicSolver.redeemSolve(atomicQueue, ERC20(boringVault), ERC20(WSTETH), users, 10**18, 3*10**18, teller);
        vm.stopPrank();
    }

}