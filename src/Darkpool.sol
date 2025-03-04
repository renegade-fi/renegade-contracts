// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { console2 } from "forge-std/console2.sol";
import { PlonkProof, VerificationKey, NUM_SELECTORS, NUM_WIRE_TYPES } from "./libraries/verifier/Types.sol";
import { BN254 } from "solidity-bn254/BN254.sol";
import { VerifierCore } from "./libraries/verifier/VerifierCore.sol";
import { VerificationKeys } from "./libraries/darkpool/VerificationKeys.sol";
import { IHasher } from "./libraries/poseidon2/IHasher.sol";
import { IVerifier } from "./libraries/verifier/IVerifier.sol";
import {
    ValidWalletCreateStatement,
    ValidWalletUpdateStatement,
    StatementSerializer
} from "./libraries/darkpool/PublicInputs.sol";
import { WalletOperations } from "./libraries/darkpool/WalletOperations.sol";
import { MerkleTreeLib } from "./libraries/merkle/MerkleTree.sol";
import { NullifierLib } from "./libraries/darkpool/NullifierSet.sol";

using MerkleTreeLib for MerkleTreeLib.MerkleTree;
using NullifierLib for NullifierLib.NullifierSet;

contract Darkpool {
    /// @notice The hasher for the darkpool
    IHasher public hasher;
    /// @notice The verifier for the darkpool
    IVerifier public verifier;

    /// @notice The Merkle tree for wallet commitments
    MerkleTreeLib.MerkleTree private merkleTree;
    /// @notice The nullifier set for the darkpool
    /// @dev Each time a wallet is updated (placing an order, settling a match, depositing, etc) a nullifier is spent.
    /// @dev This ensures that a pre-update wallet cannot create two separate post-update wallets in the Merkle state
    /// @dev The nullifier is computed deterministically from the shares of the pre-update wallet
    NullifierLib.NullifierSet private nullifierSet;

    /// @notice The constructor for the darkpool
    /// @param hasher_ The hasher for the darkpool
    /// @param verifier_ The verifier for the darkpool
    constructor(IHasher hasher_, IVerifier verifier_) {
        hasher = hasher_;
        verifier = verifier_;
        merkleTree.initialize();
    }

    // --- State Getters --- //

    /// @notice Get the current Merkle root
    /// @return The current Merkle root
    function getMerkleRoot() public view returns (BN254.ScalarField) {
        return merkleTree.root;
    }

    /// @notice Check whether a root is in the Merkle root history
    /// @param root The root to check
    /// @return Whether the root is in the history
    function rootInHistory(BN254.ScalarField root) public view returns (bool) {
        return merkleTree.rootHistory[root];
    }

    /// @notice Check whether a nullifier has been spent
    /// @param nullifier The nullifier to check
    /// @return Whether the nullifier has been spent
    function nullifierSpent(BN254.ScalarField nullifier) public view returns (bool) {
        return nullifierSet.isSpent(nullifier);
    }

    // --- Core Wallet Methods --- //

    /// @notice Create a wallet in the darkpool
    /// @param statement The statement to verify
    /// @param proof The proof of `VALID WALLET CREATE`
    function createWallet(ValidWalletCreateStatement memory statement, PlonkProof memory proof) public {
        // 1. Verify the proof
        verifier.verifyValidWalletCreate(statement, proof);

        // 2. Compute a commitment to the wallet shares, and insert into the Merkle tree
        BN254.ScalarField walletCommitment =
            WalletOperations.computeWalletCommitment(statement.publicShares, statement.privateShareCommitment, hasher);
        merkleTree.insertLeaf(walletCommitment, hasher);
    }

    /// @notice Update a wallet in the darkpool
    /// @param newSharesCommitmentSig The signature of the new wallet shares commitment by the
    /// old wallet's root key
    /// @param statement The statement to verify
    /// @param proof The proof of `VALID WALLET UPDATE`
    function updateWallet(
        bytes calldata newSharesCommitmentSig,
        ValidWalletUpdateStatement memory statement,
        PlonkProof memory proof
    )
        public
    {
        // 1. Verify the Merkle root to which the pre-update wallet's inclusion proof opens,
        // and check that the nullifier has not been spent
        require(merkleTree.rootInHistory(statement.merkleRoot), "Invalid Merkle root");
        nullifierSet.spend(statement.previousNullifier);

        // 2. Verify the proof
        verifier.verifyValidWalletUpdate(statement, proof);

        // 2. Compute a commitment to the wallet shares, and insert into the Merkle tree
        BN254.ScalarField walletCommitment = WalletOperations.computeWalletCommitment(
            statement.newPublicShares, statement.newPrivateShareCommitment, hasher
        );
        merkleTree.insertLeaf(walletCommitment, hasher);

        // 3. Verify the signature of the new shares commitment by the root key
        bool validSig =
            WalletOperations.verifyWalletUpdateSignature(walletCommitment, newSharesCommitmentSig, statement.oldPkRoot);
        require(validSig, "Invalid signature");
    }
}
