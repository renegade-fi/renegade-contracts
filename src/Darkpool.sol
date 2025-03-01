// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { PlonkProof, VerificationKey, NUM_SELECTORS, NUM_WIRE_TYPES } from "./libraries/verifier/Types.sol";
import { BN254 } from "solidity-bn254/BN254.sol";
import { VerifierCore } from "./libraries/verifier/VerifierCore.sol";
import { VerificationKeys } from "./libraries/darkpool/VerificationKeys.sol";
import { IHasher } from "./libraries/poseidon2/IHasher.sol";
import { IVerifier } from "./libraries/verifier/IVerifier.sol";
import { ValidWalletCreateStatement, StatementSerializer } from "./libraries/darkpool/PublicInputs.sol";
import { MerkleTypes } from "./libraries/merkle/MerkleTypes.sol";
import { MerkleTreeLib } from "./libraries/merkle/MerkleTreeLib.sol";

// Use the StatementSerializer for all statements
using StatementSerializer for ValidWalletCreateStatement;
using MerkleTreeLib for MerkleTypes.MerkleTree;

contract Darkpool {
    /// @notice The hasher for the darkpool
    IHasher public hasher;
    /// @notice The verifier for the darkpool
    IVerifier public verifier;

    /// @notice The Merkle tree for wallet commitments
    MerkleTypes.MerkleTree public walletTree;

    /// @notice The constructor for the darkpool
    /// @param hasher_ The hasher for the darkpool
    /// @param verifier_ The verifier for the darkpool
    constructor(IHasher hasher_, IVerifier verifier_) {
        hasher = hasher_;
        verifier = verifier_;
    }

    /// @notice Create a wallet in the darkpool
    /// @param statement The statement to verify
    /// @param proof The proof of `VALID WALLET CREATE`
    function createWallet(ValidWalletCreateStatement memory statement, PlonkProof memory proof) public {
        // 1. Verify the proof
        verifier.verifyValidWalletCreate(statement, proof);

        // 2. Compute a commitment to the wallet shares
        uint256[] memory hashInputs = new uint256[](statement.publicShares.length + 1);
        hashInputs[0] = BN254.ScalarField.unwrap(statement.privateShareCommitment);
        for (uint256 i = 1; i <= statement.publicShares.length; i++) {
            hashInputs[i] = BN254.ScalarField.unwrap(statement.publicShares[i - 1]);
        }
        uint256 walletCommitment = hasher.spongeHash(hashInputs);

        // 3. Insert the wallet commitment into the Merkle tree
        require(walletTree.isInitialized, "Merkle tree not initialized");
        bytes32 leaf = bytes32(walletCommitment);
        walletTree.insertLeaf(hasher, leaf);
    }

    /// @notice Initialize the Merkle tree for wallet commitments
    /// @param depth The depth of the Merkle tree
    function initializeMerkleTree(uint8 depth) public {
        require(!walletTree.isInitialized, "Merkle tree already initialized");

        walletTree.depth = depth;
        walletTree.isInitialized = true;
        walletTree.nextLeafIndex = 0;
        walletTree.maxLeaves = 1 << depth; // 2^depth
        walletTree.rootHistorySize = 0;

        // Initialize the root to a default value (implementation-specific)
        // This would typically involve computing the root of an empty tree
        // based on your specific hashing implementation
        walletTree.root = bytes32(0);
    }
}
