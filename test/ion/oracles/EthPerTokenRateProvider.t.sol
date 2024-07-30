// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.21;

import {IPriceFeed} from "../../../src/interfaces/IPriceFeed.sol";
import {EthPerTokenRateProvider} from "./../../../src/oracles/EthPerTokenRateProvider.sol";
import {
    ETH_PER_WEETH_CHAINLINK,
    ETH_PER_EZETH_CHAINLINK,
    ETH_PER_RSETH_CHAINLINK,
    ETH_PER_RSWETH_CHAINLINK,
    ETH_PER_PUFETH_CHAINLINK
} from "./../../../src/helper/Constants.sol";

import {Test} from "@forge-std/Test.sol";

abstract contract EthPerTokenRateProviderTest is Test {    
    uint256 MAX_TIME_FROM_LAST_UPDATE = 1 days;
    EthPerTokenRateProvider ethPerTokenRateProvider;

    uint256 expectedMinPrice;
    uint256 expectedMaxPrice;

    function setUp() public virtual {
        vm.createSelectFork(vm.envString("MAINNET_RPC_URL"));
    }

    function test_GetRateExpectedPrice() public {
        uint256 rate = ethPerTokenRateProvider.getRate();
        
        assertGe(rate, expectedMinPrice, "min price");
        assertLe(rate, expectedMaxPrice, "max price");
    }

    function test_Revert_MaxTimeFromLastUpdate() public {
        IPriceFeed underlyingPriceFeed = ethPerTokenRateProvider.PRICE_FEED();
        (,,, uint256 lastUpdatedAt,) = underlyingPriceFeed.latestRoundData(); // price of stETH denominated in ETH

        vm.warp(block.timestamp + 1 days);

        vm.expectRevert(
            abi.encodeWithSelector(
                EthPerTokenRateProvider.MaxTimeFromLastUpdatePassed.selector, block.timestamp, lastUpdatedAt
            )
        );
        ethPerTokenRateProvider.getRate();
    }

    function _setExpectedPriceRange(uint256 _expectedMinPrice, uint256 _expectedMaxPrice) public {
        expectedMinPrice = _expectedMinPrice;
        expectedMaxPrice = _expectedMaxPrice;
    }
}

contract WeEthRateProviderTest is EthPerTokenRateProviderTest {
    function setUp() public override {
        super.setUp();

        _setExpectedPriceRange(1e18, 1.2e18);

        ethPerTokenRateProvider = new EthPerTokenRateProvider(
            ETH_PER_WEETH_CHAINLINK, MAX_TIME_FROM_LAST_UPDATE, 18
        );
    } 
}

contract EzEthRateProviderTest is EthPerTokenRateProviderTest {
    function setUp() public override {
        super.setUp();

        _setExpectedPriceRange(0.98e18, 1.2e18);

        ethPerTokenRateProvider = new EthPerTokenRateProvider(
            ETH_PER_EZETH_CHAINLINK, MAX_TIME_FROM_LAST_UPDATE, 18
        );
    } 
}

contract RsEthRateProviderTest is EthPerTokenRateProviderTest {
    function setUp() public override {
        super.setUp();

        _setExpectedPriceRange(1e18, 1.2e18);

        ethPerTokenRateProvider = new EthPerTokenRateProvider(
            ETH_PER_RSETH_CHAINLINK, MAX_TIME_FROM_LAST_UPDATE, 18
        );
    } 
}

contract RswEthRateProviderTest is EthPerTokenRateProviderTest {
    function setUp() public override {
        super.setUp();

        _setExpectedPriceRange(1e18, 1.2e18);

        ethPerTokenRateProvider = new EthPerTokenRateProvider(
            ETH_PER_RSWETH_CHAINLINK, MAX_TIME_FROM_LAST_UPDATE, 18
        );
    } 
}

contract PufEthRateProviderTest is EthPerTokenRateProviderTest {
    function setUp() public override {
        super.setUp();

        _setExpectedPriceRange(0.99e18, 1.2e18);

        ethPerTokenRateProvider = new EthPerTokenRateProvider(
            ETH_PER_PUFETH_CHAINLINK, MAX_TIME_FROM_LAST_UPDATE, 18
        );
    } 
}
