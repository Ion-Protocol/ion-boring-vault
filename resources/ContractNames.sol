// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.21;

contract ContractNames {
    string public constant SevenSeasRolesAuthorityName = "Seven Seas RolesAuthority Version 0.0";
    string public constant ArcticArchitectureLensName = "Arctic Architecture Lens V0.0";
    string public constant AtomicQueueName = "Atomic Queue V0.0";
    string public constant AtomicSolverName = "Atomic Solver V3.0";

    // Migration
    string public constant CellarMigrationAdaptorName = "Cellar Migration Adaptor V0.1";
    string public constant CellarMigrationAdaptorName2 = "Cellar Migration Adaptor 2 V0.0";
    string public constant ParitySharePriceOracleName = "Parity Share Price Oracle V0.0";
    string public constant CellarMigratorWithSharePriceParityName = "Cellar Migrator With Share Price Parity V0.0";

    // Vaults
    string public constant EtherFiLiquidUsdRolesAuthorityName = "EtherFi Liquid USD RolesAuthority Version 0.0";
    string public constant EtherFiLiquidUsdName = "EtherFi Liquid USD V0.0";
    string public constant EtherFiLiquidUsdManagerName = "EtherFi Liquid USD Manager With Merkle Verification V0.0";
    string public constant EtherFiLiquidUsdAccountantName = "EtherFi Liquid USD Accountant With Rate Providers V0.0";
    string public constant EtherFiLiquidUsdTellerName = "EtherFi Liquid USD Teller With Multi Asset Support V0.0";
    string public constant EtherFiLiquidUsdDecoderAndSanitizerName = "EtherFi Liquid USD Decoder and Sanitizer V0.1";
    string public constant EtherFiLiquidUsdDelayedWithdrawer = "EtherFi Liquid USD Delayed Withdrawer V0.0";

    string public constant EtherFiLiquidEthRolesAuthorityName = "EtherFi Liquid ETH RolesAuthority Version 0.0";
    string public constant EtherFiLiquidEthName = "EtherFi Liquid ETH V0.1";
    string public constant EtherFiLiquidEthManagerName = "EtherFi Liquid ETH Manager With Merkle Verification V0.1";
    string public constant EtherFiLiquidEthAccountantName = "EtherFi Liquid ETH Accountant With Rate Providers V0.1";
    string public constant EtherFiLiquidEthTellerName = "EtherFi Liquid ETH Teller With Multi Asset Support V0.1";
    string public constant EtherFiLiquidEthDecoderAndSanitizerName = "EtherFi Liquid ETH Decoder and Sanitizer V0.0";
    string public constant EtherFiLiquidEthDelayedWithdrawer = "EtherFi Liquid ETH Delayed Withdrawer V0.0";

    string public constant TestVaultEthRolesAuthorityName = "Test ETH Vault RolesAuthority Version 0.0";
    string public constant TestVaultEthName = "Test ETH Vault V0.0";
    string public constant TestVaultEthManagerName = "Test ETH Vault Manager With Merkle Verification V0.0";
    string public constant TestVaultEthAccountantName = "Test ETH Vault Accountant With Rate Providers V0.0";
    string public constant TestVaultEthTellerName = "Test ETH Vault Teller With Multi Asset Support V0.0";
    string public constant TestVaultEthDecoderAndSanitizerName = "Test ETH Vault Decoder and Sanitizer V0.0";
    string public constant TestVaultEthDelayedWithdrawer = "Test ETH Vault Delayed Withdrawer V0.0";

    string public constant EtherFiLiquidBtcRolesAuthorityName = "EtherFi Liquid BTC RolesAuthority Version 0.0";
    string public constant EtherFiLiquidBtcName = "EtherFi Liquid BTC V0.0";
    string public constant EtherFiLiquidBtcManagerName = "EtherFi Liquid BTC Manager With Merkle Verification V0.0";
    string public constant EtherFiLiquidBtcAccountantName = "EtherFi Liquid BTC Accountant With Rate Providers V0.0";
    string public constant EtherFiLiquidBtcTellerName = "EtherFi Liquid BTC Teller With Multi Asset Support V0.0";
    string public constant EtherFiLiquidBtcDecoderAndSanitizerName = "EtherFi Liquid BTC Decoder and Sanitizer V0.0";
    string public constant EtherFiLiquidBtcDelayedWithdrawer = "EtherFi Liquid BTC Delayed Withdrawer V0.0";

    string public constant BridgingTestVaultEthRolesAuthorityName = "Bridging Test ETH Vault RolesAuthority Version 0.0";
    string public constant BridgingTestVaultEthName = "Bridging Test ETH Vault V0.0";
    string public constant BridgingTestVaultEthManagerName =
        "Bridging Test ETH Vault Manager With Merkle Verification V0.0";
    string public constant BridgingTestVaultEthAccountantName =
        "Bridging Test ETH Vault Accountant With Rate Providers V0.0";
    string public constant BridgingTestVaultEthTellerName =
        "Bridging Test ETH Vault Teller With Multi Asset Support V0.0";
    string public constant BridgingTestVaultEthDecoderAndSanitizerName =
        "Bridging Test ETH Vault Decoder and Sanitizer V0.0";
    string public constant BridgingTestVaultEthDelayedWithdrawer = "Bridging Test ETH Vault Delayed Withdrawer V0.0";

    string public constant ItbPositionDecoderAndSanitizerName = "ITB Position Decoder and Sanitizer V0.0";
    // gernic Rate Providers
    string public constant PendlePTweETHRateProviderName = "Pendle PT weETH Rate Provider V0.0";
    string public constant PendleYTweETHRateProviderName = "Pendle YT weETH Rate Provider V0.0";
    string public constant PendleLPweETHRateProviderName = "Pendle LP weETH Rate Provider V0.0";
    string public constant PendleZircuitPTweETHRateProviderName = "Pendle Zircuit PT weETH Rate Provider V0.0";
    string public constant PendleZircuitYTweETHRateProviderName = "Pendle Zircuit YT weETH Rate Provider V0.0";
    string public constant PendleZircuitLPweETHRateProviderName = "Pendle Zircuit LP weETH Rate Provider V0.0";
    string public constant AuraRETHWeETHBptRateProviderName = "Aura rETH weETH Bpt Rate Provider V0.0";
    string public constant WstETHRateProviderName = "wstETH Rate Provider V0.0";
    string public constant PendleWeETHMarketSeptemberRateProviderName =
        "Pendle weETH Market September 2024 Rate Provider V0.0";
    string public constant PendleEethPtSeptemberRateProviderName = "Pendle eETH PT September 2024 Rate Provider V0.0";
    string public constant PendleEethYtSeptemberRateProviderName = "Pendle eETH YT September 2024 Rate Provider V0.0";
    string public constant PendleWeETHMarketDecemberRateProviderName =
        "Pendle weETH Market December 2024 Rate Provider V0.0";
    string public constant PendleEethPtDecemberRateProviderName = "Pendle eETH PT December 2024 Rate Provider V0.0";
    string public constant PendleEethYtDecemberRateProviderName = "Pendle eETH YT December 2024 Rate Provider V0.0";
}
