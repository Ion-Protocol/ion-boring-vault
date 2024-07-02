// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.21;

import {AtomicSolverV4} from "./../../src/atomic-queue/AtomicSolverV4.sol";
import {MainnetAddresses} from "./../../test/resources/MainnetAddresses.sol";
import {BaseScript} from "./../Base.s.sol";
import {stdJson as StdJson} from "forge-std/StdJson.sol";

contract DeployAtomicSolverV4 is BaseScript, MainnetAddresses {
    using StdJson for string;

    string path = "./deployment-config/06_AtomicSolverV4.json";
    string config = vm.readFile(path);

    bytes32 solverSalt = config.readBytes32(".solverSalt");

    function run() public broadcast returns (AtomicSolverV4 solver) {        
        require(solverSalt != bytes32(0), "solverSalt");

        bytes memory creationCode = type(AtomicSolverV4).creationCode;

        solver = AtomicSolverV4(
            CREATEX.deployCreate3(
                solverSalt,
                abi.encodePacked(creationCode, abi.encode(broadcaster))
            )
        );

        require(solver.owner() == address(broadcaster), "owner must be broadcaster");
    }
}
