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
import { MerkleTreeLib } from "./libraries/merkle/MerkleTree.sol";

// Use the StatementSerializer for all statements
using StatementSerializer for ValidWalletCreateStatement;
using MerkleTreeLib for MerkleTreeLib.MerkleTree;

contract Darkpool {
    /// @notice The hasher for the darkpool
    IHasher public hasher;
    /// @notice The verifier for the darkpool
    IVerifier public verifier;

    /// @notice The Merkle tree for wallet commitments
    MerkleTreeLib.MerkleTree public walletTree;

    /// @notice The constructor for the darkpool
    /// @param hasher_ The hasher for the darkpool
    /// @param verifier_ The verifier for the darkpool
    constructor(IHasher hasher_, IVerifier verifier_) {
        hasher = hasher_;
        verifier = verifier_;
        walletTree.initialize();
    }

    /// @notice Create a wallet in the darkpool
    /// @param statement The statement to verify
    /// @param proof The proof of `VALID WALLET CREATE`
    function createWallet(ValidWalletCreateStatement memory statement, PlonkProof memory proof) public {
        // 1. Verify the proof
        verifier.verifyValidWalletCreate(statement, proof);

        // 2. Compute a commitment to the wallet shares, and insert into the Merkle tree
        BN254.ScalarField walletCommitment =
            computeWalletCommitment(statement.publicShares, statement.privateShareCommitment);
        walletTree.insertLeaf(walletCommitment, hasher);
    }

    /// @notice Update a wallet in the darkpool
    /// @param statement The statement to verify
    /// @param proof The proof of `VALID WALLET UPDATE`
    function updateWallet(ValidWalletUpdateStatement memory statement, PlonkProof memory proof) public {
        // 1. Verify the proof
        verifier.verifyValidWalletUpdate(statement, proof);

        // 2. Compute a commitment to the wallet shares, and insert into the Merkle tree
        BN254.ScalarField walletCommitment =
            computeWalletCommitment(statement.newPublicShares, statement.newPrivateShareCommitment);
        walletTree.insertLeaf(walletCommitment, hasher);
    }

    /// @dev Compute a commitment to a wallet's shares
    function computeWalletCommitment(
        BN254.ScalarField[] memory publicShares,
        BN254.ScalarField privateShareCommitment
    )
        internal
        view
        returns (BN254.ScalarField)
    {
        uint256[] memory hashInputs = new uint256[](publicShares.length + 1);
        hashInputs[0] = BN254.ScalarField.unwrap(privateShareCommitment);
        for (uint256 i = 1; i <= publicShares.length; i++) {
            hashInputs[i] = BN254.ScalarField.unwrap(publicShares[i - 1]);
        }

        uint256 walletCommitment = hasher.spongeHash(hashInputs);
        return BN254.ScalarField.wrap(walletCommitment);
    }
}
