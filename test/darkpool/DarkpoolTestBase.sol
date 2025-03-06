// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { BN254 } from "solidity-bn254/BN254.sol";
import { ERC20Mock } from "oz-contracts/mocks/token/ERC20Mock.sol";
import { IPermit2 } from "permit2/interfaces/IPermit2.sol";
import { DeployPermit2 } from "permit2-test/utils/DeployPermit2.sol";
import { Test } from "forge-std/Test.sol";
import { TestUtils } from "../utils/TestUtils.sol";
import { CalldataUtils } from "../utils/CalldataUtils.sol";
import { HuffDeployer } from "foundry-huff/HuffDeployer.sol";
import { Vm } from "forge-std/Vm.sol";
import {
    ExternalTransfer, TransferType, TransferAuthorization, PublicRootKey
} from "renegade/libraries/darkpool/Types.sol";
import { TestVerifier } from "../test-contracts/TestVerifier.sol";
import { Darkpool } from "renegade/Darkpool.sol";
import { NullifierLib } from "renegade/libraries/darkpool/NullifierSet.sol";
import { WalletOperations } from "renegade/libraries/darkpool/WalletOperations.sol";
import { IHasher } from "renegade/libraries/poseidon2/IHasher.sol";
import { IVerifier } from "renegade/libraries/verifier/IVerifier.sol";
import { PlonkProof } from "renegade/libraries/verifier/Types.sol";

contract DarkpoolTestBase is CalldataUtils {
    using NullifierLib for NullifierLib.NullifierSet;

    Darkpool public darkpool;
    IHasher public hasher;
    NullifierLib.NullifierSet private testNullifierSet;
    IPermit2 public permit2;
    ERC20Mock public token1;
    ERC20Mock public token2;

    bytes constant INVALID_NULLIFIER_REVERT_STRING = "Nullifier already spent";
    bytes constant INVALID_ROOT_REVERT_STRING = "Merkle root not in history";
    bytes constant INVALID_SIGNATURE_REVERT_STRING = "Invalid signature";
    bytes constant INVALID_PROTOCOL_FEE_REVERT_STRING = "Invalid protocol fee rate";

    function setUp() public {
        // Deploy a Permit2 instance for testing
        DeployPermit2 permit2Deployer = new DeployPermit2();
        permit2 = IPermit2(permit2Deployer.deployPermit2());

        // Deploy mock tokens for testing
        token1 = new ERC20Mock();
        token2 = new ERC20Mock();

        // Deploy the darkpool implementation contracts
        hasher = IHasher(HuffDeployer.deploy("libraries/poseidon2/poseidonHasher"));
        IVerifier verifier = new TestVerifier();
        darkpool = new Darkpool(TEST_PROTOCOL_FEE, hasher, verifier, permit2);
    }

    // ---------------------------
    // | Library Primitive Tests |
    // ---------------------------

    /// @notice Test the nullifier set
    function test_nullifierSet() public {
        BN254.ScalarField nullifier = BN254.ScalarField.wrap(randomFelt());
        testNullifierSet.spend(nullifier); // Should succeed

        // Check that the nullifier is spent
        assertEq(testNullifierSet.isSpent(nullifier), true);

        // Should fail
        vm.expectRevert("Nullifier already spent");
        testNullifierSet.spend(nullifier);
    }
}
