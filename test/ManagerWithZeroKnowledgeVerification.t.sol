// SPDX-License-Identifier: Apache-2.0
pragma solidity 0.8.21;

import {MainnetAddresses} from "test/resources/MainnetAddresses.sol";
import {BoringVault} from "src/base/BoringVault.sol";
import {
    ManagerWithZeroKnowledgeVerification,
    ManageVerifier
} from "src/base/Roles/managers/ManagerWithZeroKnowledgeVerification.sol";
import {Pairing} from "src/zk-verifiers/ManageVerifier.sol";
import {SafeTransferLib} from "@solmate/utils/SafeTransferLib.sol";
import {FixedPointMathLib} from "@solmate/utils/FixedPointMathLib.sol";
import {ERC20} from "@solmate/tokens/ERC20.sol";
import {
    EtherFiLiquidDecoderAndSanitizer,
    MorphoBlueDecoderAndSanitizer,
    UniswapV3DecoderAndSanitizer,
    BalancerV2DecoderAndSanitizer,
    PendleRouterDecoderAndSanitizer
} from "src/base/DecodersAndSanitizers/EtherFiLiquidDecoderAndSanitizer.sol";
import {RenzoLiquidDecoderAndSanitizer} from "src/base/DecodersAndSanitizers/RenzoLiquidDecoderAndSanitizer.sol";
import {LidoLiquidDecoderAndSanitizer} from "src/base/DecodersAndSanitizers/LidoLiquidDecoderAndSanitizer.sol";
import {BalancerVault} from "src/interfaces/BalancerVault.sol";
import {IUniswapV3Router} from "src/interfaces/IUniswapV3Router.sol";
import {DecoderCustomTypes} from "src/interfaces/DecoderCustomTypes.sol";
import {RolesAuthority, Authority} from "@solmate/auth/authorities/RolesAuthority.sol";

import {Test, stdStorage, StdStorage, stdError, console} from "@forge-std/Test.sol";
import "@forge-std/StdJson.sol";

contract ManagerWithZeroKnowledgeVerificationTest is Test, MainnetAddresses {
    using SafeTransferLib for ERC20;
    using FixedPointMathLib for uint256;
    using stdStorage for StdStorage;
    using stdJson for string;

    ManagerWithZeroKnowledgeVerification public manager;
    BoringVault public boringVault;
    address public rawDataDecoderAndSanitizer;
    RolesAuthority public rolesAuthority;

    uint8 public constant MANAGER_ROLE = 1;
    uint8 public constant STRATEGIST_ROLE = 2;
    uint8 public constant MANGER_INTERNAL_ROLE = 3;
    uint8 public constant ADMIN_ROLE = 4;
    uint8 public constant BORING_VAULT_ROLE = 5;
    uint8 public constant BALANCER_VAULT_ROLE = 6;

    address public weEthOracle = 0x3fa58b74e9a8eA8768eb33c8453e9C2Ed089A40a;
    address public weEthIrm = 0x870aC11D48B15DB9a138Cf899d20F13F79Ba00BC;

    function setUp() external {
        // Setup forked environment.
        string memory rpcKey = "MAINNET_RPC_URL";
        uint256 blockNumber = 19369928;
        _startFork(rpcKey, blockNumber);

        boringVault = new BoringVault(address(this), "Boring Vault", "BV", 18);

        manager = new ManagerWithZeroKnowledgeVerification(address(this), address(boringVault), vault);

        rawDataDecoderAndSanitizer =
            address(new EtherFiLiquidDecoderAndSanitizer(address(boringVault), uniswapV3NonFungiblePositionManager));

        rolesAuthority = new RolesAuthority(address(this), Authority(address(0)));
        boringVault.setAuthority(rolesAuthority);
        manager.setAuthority(rolesAuthority);

        // Setup roles authority.
        rolesAuthority.setRoleCapability(
            MANAGER_ROLE,
            address(boringVault),
            bytes4(keccak256(abi.encodePacked("manage(address,bytes,uint256)"))),
            true
        );
        rolesAuthority.setRoleCapability(
            MANAGER_ROLE,
            address(boringVault),
            bytes4(keccak256(abi.encodePacked("manage(address[],bytes[],uint256[])"))),
            true
        );

        rolesAuthority.setRoleCapability(
            STRATEGIST_ROLE,
            address(manager),
            ManagerWithZeroKnowledgeVerification.manageVaultWithZeroKnowledgeVerification.selector,
            true
        );
        rolesAuthority.setRoleCapability(
            MANGER_INTERNAL_ROLE,
            address(manager),
            ManagerWithZeroKnowledgeVerification.manageVaultWithZeroKnowledgeVerification.selector,
            true
        );
        rolesAuthority.setRoleCapability(
            ADMIN_ROLE, address(manager), ManagerWithZeroKnowledgeVerification.setManageRoot.selector, true
        );
        // rolesAuthority.setRoleCapability(
        //     BORING_VAULT_ROLE, address(manager), ManagerWithZeroKnowledgeVerification.flashLoan.selector, true
        // );
        // rolesAuthority.setRoleCapability(
        //     BALANCER_VAULT_ROLE, address(manager), ManagerWithZeroKnowledgeVerification.receiveFlashLoan.selector, true
        // );

        // Grant roles
        rolesAuthority.setUserRole(address(this), STRATEGIST_ROLE, true);
        rolesAuthority.setUserRole(address(manager), MANGER_INTERNAL_ROLE, true);
        rolesAuthority.setUserRole(address(this), ADMIN_ROLE, true);
        rolesAuthority.setUserRole(address(manager), MANAGER_ROLE, true);
        rolesAuthority.setUserRole(address(boringVault), BORING_VAULT_ROLE, true);
        rolesAuthority.setUserRole(vault, BALANCER_VAULT_ROLE, true);

        // Allow the boring vault to receive ETH.
        rolesAuthority.setPublicCapability(address(boringVault), bytes4(0), true);
    }

    function testManagerMerkleVerificationHappyPath() external {
        // Allow the manager to call the USDC approve function to a specific address,
        // and the USDT transfer function to a specific address.
        address usdcSpender = vm.addr(0xDEAD);
        ManageLeaf[] memory leafs = new ManageLeaf[](1_024);
        leafs[0] = ManageLeaf(address(USDC), false, "approve(address,uint256)", new address[](1));
        leafs[0].argumentAddresses[0] = usdcSpender;

        bytes32[][] memory manageTree = _generateMerkleTree(leafs);

        bytes32 root = manageTree[manageTree.length - 1][0];
        manager.setManageRoot(address(this), root);

        address[] memory targets = new address[](1);
        targets[0] = address(USDC);

        bytes[] memory targetData = new bytes[](1);
        targetData[0] = abi.encodeWithSelector(ERC20.approve.selector, usdcSpender, 777);

        (bytes32[][] memory merkleProofs) = _getProofsUsingTree(leafs, manageTree);

        uint256[] memory values = new uint256[](1);

        deal(address(USDT), address(boringVault), 777);

        address[] memory decodersAndSanitizers = new address[](1);
        decodersAndSanitizers[0] = rawDataDecoderAndSanitizer;

        ManageVerifier.Proof[] memory manageProofs = new ManageVerifier.Proof[](1);
        {
            // Create first zk-proof.
            string[] memory inputs = new string[](37);
            inputs[0] = "zokrates";
            inputs[1] = "compute-witness";
            inputs[2] = "-a";
            inputs[3] = vm.toString(uint128(bytes16(manageTree[0][0])));
            inputs[4] = vm.toString(uint128(bytes16(manageTree[0][0] << 128)));
            inputs[5] = vm.toString(uint128(bytes16(root)));
            inputs[6] = vm.toString(uint128(bytes16(root << 128)));
            inputs[7] = vm.toString(uint256(0)); // nonce
            inputs[8] = vm.toString(block.timestamp); // timestamp
            inputs[9] = vm.toString(uint256(1)); // secret nonce
            inputs[10] = vm.toString(block.timestamp + 1); // deadline
            for (uint256 i; i < merkleProofs[0].length; ++i) {
                inputs[11 + 2 * i] = vm.toString(uint128(bytes16(merkleProofs[0][i])));
                inputs[11 + 2 * i + 1] = vm.toString(uint128(bytes16(merkleProofs[0][i] << 128)));
            }
            inputs[31] = "-s";
            inputs[32] = "zokrates/output/manage_verifier.json";
            inputs[33] = "-i";
            inputs[34] = "zokrates/output/manage_verifier";
            inputs[35] = "-o";
            inputs[36] = "zokrates/output/manage_verifier_witness";

            // Compute witness.
            vm.ffi(inputs);

            inputs = new string[](10);
            inputs[0] = "zokrates";
            inputs[1] = "generate-proof";
            inputs[2] = "-i";
            inputs[3] = "zokrates/output/manage_verifier";
            inputs[4] = "-j";
            inputs[5] = "zokrates/output/manage_verifier_proof.json";
            inputs[6] = "-p";
            inputs[7] = "zokrates/output/manage_verifier_proving.key";
            inputs[8] = "-w";
            inputs[9] = "zokrates/output/manage_verifier_witness";

            // Generate proof.
            vm.ffi(inputs);
        }

        // Extrac proof from json.
        string memory json = vm.readFile(string.concat(vm.projectRoot(), "/zokrates/output/manage_verifier_proof.json"));

        manageProofs[0] = ManageVerifier.Proof({
            a: Pairing.G1Point(
                abi.decode(json.parseRaw(".proof.a[0]"), (uint256)), abi.decode(json.parseRaw(".proof.a[1]"), (uint256))
                ),
            b: Pairing.G2Point(
                [
                    abi.decode(json.parseRaw(".proof.b[0][0]"), (uint256)),
                    abi.decode(json.parseRaw(".proof.b[0][1]"), (uint256))
                ],
                [
                    abi.decode(json.parseRaw(".proof.b[1][0]"), (uint256)),
                    abi.decode(json.parseRaw(".proof.b[1][1]"), (uint256))
                ]
                ),
            c: Pairing.G1Point(
                abi.decode(json.parseRaw(".proof.c[0]"), (uint256)), abi.decode(json.parseRaw(".proof.c[1]"), (uint256))
                )
        });

        manager.manageVaultWithZeroKnowledgeVerification(
            manageProofs, decodersAndSanitizers, targets, targetData, values
        );

        assertEq(USDC.allowance(address(boringVault), usdcSpender), 777, "USDC should have an allowance");
    }

    // ========================================= HELPER FUNCTIONS =========================================
    bool doNothing = true;

    // function flashLoan(address, address[] calldata tokens, uint256[] calldata amounts, bytes memory userData)
    //     external
    // {
    //     if (doNothing) {
    //         return;
    //     } else {
    //         // Edit userData.
    //         userData = hex"DEAD01";
    //         manager.receiveFlashLoan(tokens, amounts, amounts, userData);
    //     }
    // }

    bool iDidSomething = false;

    // Call this function approve, so that we can use the standard decoder.
    function approve(ERC20 token, uint256 amount) external {
        token.safeTransferFrom(msg.sender, address(this), amount);
        token.safeTransfer(msg.sender, amount);
        iDidSomething = true;
    }

    function _generateProof(bytes32 leaf, bytes32[][] memory tree) internal pure returns (bytes32[] memory proof) {
        // The length of each proof is the height of the tree - 1.
        uint256 tree_length = tree.length;
        proof = new bytes32[](tree_length - 1);

        // Build the proof
        for (uint256 i; i < tree_length - 1; ++i) {
            // For each layer we need to find the leaf.
            for (uint256 j; j < tree[i].length; ++j) {
                if (leaf == tree[i][j]) {
                    // We have found the leaf, so now figure out if the proof needs the next leaf or the previous one.
                    proof[i] = j % 2 == 0 ? tree[i][j + 1] : tree[i][j - 1];
                    leaf = _hashPair(leaf, proof[i]);
                    break;
                }
            }
        }
    }

    function _getProofsUsingTree(ManageLeaf[] memory manageLeafs, bytes32[][] memory tree)
        internal
        view
        returns (bytes32[][] memory proofs)
    {
        proofs = new bytes32[][](manageLeafs.length);
        for (uint256 i; i < manageLeafs.length; ++i) {
            // Generate manage proof.
            bytes4 selector = bytes4(keccak256(abi.encodePacked(manageLeafs[i].signature)));
            bytes memory rawDigest = abi.encodePacked(
                rawDataDecoderAndSanitizer, manageLeafs[i].target, manageLeafs[i].canSendValue, selector
            );
            uint256 argumentAddressesLength = manageLeafs[i].argumentAddresses.length;
            for (uint256 j; j < argumentAddressesLength; ++j) {
                rawDigest = abi.encodePacked(rawDigest, manageLeafs[i].argumentAddresses[j]);
            }
            bytes32 leaf = keccak256(rawDigest);
            proofs[i] = _generateProof(leaf, tree);
        }
    }

    function _buildTrees(bytes32[][] memory merkleTreeIn) internal pure returns (bytes32[][] memory merkleTreeOut) {
        // We are adding another row to the merkle tree, so make merkleTreeOut be 1 longer.
        uint256 merkleTreeIn_length = merkleTreeIn.length;
        merkleTreeOut = new bytes32[][](merkleTreeIn_length + 1);
        uint256 layer_length;
        // Iterate through merkleTreeIn to copy over data.
        for (uint256 i; i < merkleTreeIn_length; ++i) {
            layer_length = merkleTreeIn[i].length;
            merkleTreeOut[i] = new bytes32[](layer_length);
            for (uint256 j; j < layer_length; ++j) {
                merkleTreeOut[i][j] = merkleTreeIn[i][j];
            }
        }

        uint256 next_layer_length;
        if (layer_length % 2 != 0) {
            next_layer_length = (layer_length + 1) / 2;
        } else {
            next_layer_length = layer_length / 2;
        }
        merkleTreeOut[merkleTreeIn_length] = new bytes32[](next_layer_length);
        uint256 count;
        for (uint256 i; i < layer_length; i += 2) {
            merkleTreeOut[merkleTreeIn_length][count] =
                _hashPair(merkleTreeIn[merkleTreeIn_length - 1][i], merkleTreeIn[merkleTreeIn_length - 1][i + 1]);
            count++;
        }

        if (next_layer_length > 1) {
            // We need to process the next layer of leaves.
            merkleTreeOut = _buildTrees(merkleTreeOut);
        }
    }

    struct ManageLeaf {
        address target;
        bool canSendValue;
        string signature;
        address[] argumentAddresses;
    }

    function _generateMerkleTree(ManageLeaf[] memory manageLeafs) internal view returns (bytes32[][] memory tree) {
        uint256 leafsLength = manageLeafs.length;
        bytes32[][] memory leafs = new bytes32[][](1);
        leafs[0] = new bytes32[](leafsLength);
        for (uint256 i; i < leafsLength; ++i) {
            bytes4 selector = bytes4(keccak256(abi.encodePacked(manageLeafs[i].signature)));
            bytes memory rawDigest = abi.encodePacked(
                rawDataDecoderAndSanitizer, manageLeafs[i].target, manageLeafs[i].canSendValue, selector
            );
            uint256 argumentAddressesLength = manageLeafs[i].argumentAddresses.length;
            for (uint256 j; j < argumentAddressesLength; ++j) {
                rawDigest = abi.encodePacked(rawDigest, manageLeafs[i].argumentAddresses[j]);
            }
            leafs[0][i] = keccak256(rawDigest);
        }
        tree = _buildTrees(leafs);
    }

    function _hashPair(bytes32 a, bytes32 b) private pure returns (bytes32) {
        return a < b ? _efficientHash(a, b) : _efficientHash(b, a);
    }

    function _efficientHash(bytes32 a, bytes32 b) private pure returns (bytes32 value) {
        /// @solidity memory-safe-assembly
        assembly {
            mstore(0x00, a)
            mstore(0x20, b)
            value := keccak256(0x00, 0x40)
        }
    }

    function _startFork(string memory rpcKey, uint256 blockNumber) internal returns (uint256 forkId) {
        forkId = vm.createFork(vm.envString(rpcKey), blockNumber);
        vm.selectFork(forkId);
    }

    function _finalizeRequest(uint256 requestId, uint256 amount) internal {
        // Spoof unstEth contract into finalizing our request.
        IWithdrawRequestNft w = IWithdrawRequestNft(withdrawalRequestNft);
        address owner = w.owner();
        vm.startPrank(owner);
        w.updateAdmin(address(this), true);
        vm.stopPrank();

        ILiquidityPool lp = ILiquidityPool(EETH_LIQUIDITY_POOL);

        deal(address(this), amount);
        lp.deposit{value: amount}();
        address admin = lp.etherFiAdminContract();

        vm.startPrank(admin);
        lp.addEthAmountLockedForWithdrawal(uint128(amount));
        vm.stopPrank();

        w.finalizeRequests(requestId);
    }
}

interface IWithdrawRequestNft {
    struct WithdrawRequest {
        uint96 amountOfEEth;
        uint96 shareOfEEth;
        bool isValid;
        uint32 feeGwei;
    }

    function claimWithdraw(uint256 tokenId) external;

    function getRequest(uint256 requestId) external view returns (WithdrawRequest memory);

    function finalizeRequests(uint256 requestId) external;

    function owner() external view returns (address);

    function updateAdmin(address admin, bool isAdmin) external;
}

interface ILiquidityPool {
    function deposit() external payable returns (uint256);

    function requestWithdraw(address recipient, uint256 amount) external returns (uint256);

    function amountForShare(uint256 shares) external view returns (uint256);

    function etherFiAdminContract() external view returns (address);

    function addEthAmountLockedForWithdrawal(uint128 _amount) external;
}

interface IUNSTETH {
    function finalize(uint256 _lastRequestIdToBeFinalized, uint256 _maxShareRate) external payable;

    function getRoleMember(bytes32 role, uint256 index) external view returns (address);

    function FINALIZE_ROLE() external view returns (bytes32);

    function findCheckpointHints(uint256[] memory requestIds, uint256 firstIndex, uint256 lastIndex)
        external
        view
        returns (uint256[] memory);

    function getLastCheckpointIndex() external view returns (uint256);
}
