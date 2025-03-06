// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { BN254 } from "solidity-bn254/BN254.sol";
import { ERC20Mock } from "openzeppelin-contracts/contracts/mocks/token/ERC20Mock.sol";
import { IPermit2 } from "permit2/interfaces/IPermit2.sol";
import { DeployPermit2 } from "permit2/../test/utils/DeployPermit2.sol";
import { Test } from "forge-std/Test.sol";
import { TestUtils } from "./utils/TestUtils.sol";
import { CalldataUtils } from "./utils/CalldataUtils.sol";
import { HuffDeployer } from "foundry-huff/HuffDeployer.sol";
import { console2 } from "forge-std/console2.sol";
import { Vm } from "forge-std/Vm.sol";
import { PlonkProof } from "../src/libraries/verifier/Types.sol";
import { ExternalTransfer, TransferType, TransferAuthorization } from "../src/libraries/darkpool/Types.sol";
import { Darkpool } from "../src/Darkpool.sol";
import { NullifierLib } from "../src/libraries/darkpool/NullifierSet.sol";
import { IHasher } from "../src/libraries/poseidon2/IHasher.sol";
import { IVerifier } from "../src/libraries/verifier/IVerifier.sol";
import { TestVerifier } from "./test-contracts/TestVerifier.sol";
import { ValidWalletCreateStatement, ValidWalletUpdateStatement } from "../src/libraries/darkpool/PublicInputs.sol";

contract DarkpoolTest is CalldataUtils {
    using NullifierLib for NullifierLib.NullifierSet;

    Darkpool public darkpool;
    IHasher public hasher;
    ERC20Mock public token1;
    ERC20Mock public token2;
    NullifierLib.NullifierSet private testNullifierSet;
    IPermit2 public permit2;

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
        darkpool = new Darkpool(hasher, verifier, permit2);
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

    // -------------------------
    // | Darkpool Method Tests |
    // -------------------------

    // --- Create Wallet --- //

    /// @notice Test creating a wallet
    function test_createWallet() public {
        (ValidWalletCreateStatement memory statement, PlonkProof memory proof) = createWalletCalldata();
        darkpool.createWallet(statement, proof);
    }

    // --- Update Wallet --- //

    /// @notice Test updating a wallet
    function test_updateWallet_validUpdate() public {
        // Setup calldata
        (
            bytes memory newSharesCommitmentSig,
            TransferAuthorization memory transferAuthorization,
            ValidWalletUpdateStatement memory statement,
            PlonkProof memory proof
        ) = updateWalletCalldata(hasher);

        // Modify the merkle root to be valid
        BN254.ScalarField currRoot = darkpool.getMerkleRoot();
        statement.merkleRoot = currRoot;

        // Update the wallet
        darkpool.updateWallet(newSharesCommitmentSig, transferAuthorization, statement, proof);
    }

    /// @notice Test updating a wallet with an invalid Merkle root
    function test_updateWallet_invalidMerkleRoot() public {
        // Setup calldata
        (
            bytes memory newSharesCommitmentSig,
            TransferAuthorization memory transferAuthorization,
            ValidWalletUpdateStatement memory statement,
            PlonkProof memory proof
        ) = updateWalletCalldata(hasher);

        // Modify the merkle root to be invalid
        statement.merkleRoot = randomScalar();

        // Should fail
        vm.expectRevert("Invalid Merkle root");
        darkpool.updateWallet(newSharesCommitmentSig, transferAuthorization, statement, proof);
    }

    /// @notice Test updating a wallet with a spent nullifier
    function test_updateWallet_spentNullifier() public {
        // Setup calldata
        (
            bytes memory newSharesCommitmentSig,
            TransferAuthorization memory transferAuthorization,
            ValidWalletUpdateStatement memory statement,
            PlonkProof memory proof
        ) = updateWalletCalldata(hasher);

        // Modify the merkle root to be valid
        BN254.ScalarField currRoot = darkpool.getMerkleRoot();
        statement.merkleRoot = currRoot;

        // First update should succeed
        darkpool.updateWallet(newSharesCommitmentSig, transferAuthorization, statement, proof);

        // Second update with same nullifier should fail
        vm.expectRevert("Nullifier already spent");
        darkpool.updateWallet(newSharesCommitmentSig, transferAuthorization, statement, proof);
    }

    /// @notice Test updating a wallet with an invalid signature
    function test_updateWallet_invalidSignature() public {
        // Setup calldata
        (
            bytes memory newSharesCommitmentSig,
            TransferAuthorization memory transferAuthorization,
            ValidWalletUpdateStatement memory statement,
            PlonkProof memory proof
        ) = updateWalletCalldata(hasher);

        // Use the current Merkle root to isolate the signature check directly
        BN254.ScalarField currRoot = darkpool.getMerkleRoot();
        statement.merkleRoot = currRoot;

        // Modify a random byte of the signature
        uint256 randIdx = randomUint(newSharesCommitmentSig.length);
        newSharesCommitmentSig[randIdx] = randomByte();

        // Should fail
        vm.expectRevert("Invalid signature");
        darkpool.updateWallet(newSharesCommitmentSig, transferAuthorization, statement, proof);
    }

    /// @notice Test updating a wallet with a deposit
    function test_updateWallet_deposit() public {
        Vm.Wallet memory userWallet = randomEthereumWallet();
        ExternalTransfer memory transfer = ExternalTransfer({
            account: userWallet.addr,
            mint: address(token1),
            amount: 100,
            transferType: TransferType.Deposit
        });

        // Setup calldata
        (
            bytes memory newSharesCommitmentSig,
            TransferAuthorization memory transferAuthorization,
            ValidWalletUpdateStatement memory statement,
            PlonkProof memory proof
        ) = updateWalletWithExternalTransferCalldata(hasher, transfer);
        statement.merkleRoot = darkpool.getMerkleRoot();

        // Update the wallet
        darkpool.updateWallet(newSharesCommitmentSig, transferAuthorization, statement, proof);

        // Check that the token balance has increased
        // TODO: Implement this
    }
}
