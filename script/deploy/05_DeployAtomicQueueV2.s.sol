// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.21;

import {AtomicQueueV2} from "./../../src/atomic-queue/AtomicQueueV2.sol";
import {MainnetAddresses} from "./../../test/resources/MainnetAddresses.sol";
import {BaseScript} from "./../Base.s.sol";
import {stdJson as StdJson} from "forge-std/StdJson.sol";

contract DeployAtomicQueueV2 is BaseScript, MainnetAddresses {
    using StdJson for string;

    string path = "./deployment-config/05_DeployAtomicQueueV2.json";
    string config = vm.readFile(path);

    bytes32 queueSalt = config.readBytes32(".queueSalt");

    function run() public broadcast returns (AtomicQueueV2 queue) {        
        require(queueSalt != bytes32(0), "queueSalt");

        bytes memory creationCode = type(AtomicQueueV2).creationCode;

        queue = AtomicQueueV2(
            CREATEX.deployCreate3(
                queueSalt,
                abi.encodePacked(creationCode)
            )
        );
    }
}
