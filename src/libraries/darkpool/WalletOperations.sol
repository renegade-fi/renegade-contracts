// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import { BN254 } from "solidity-bn254/BN254.sol";
import { PublicRootKey } from "./Types.sol";
import { IHasher } from "../interfaces/IHasher.sol";
import { MerkleTreeLib } from "../merkle/MerkleTree.sol";
import { NullifierLib } from "./NullifierSet.sol";

// --- Helpers --- //

/// @dev Create a uint256 from a pair of BN254.ScalarField words, in little-endian order
function scalarWordsToUint(BN254.ScalarField low, BN254.ScalarField high) pure returns (uint256) {
    return BN254.ScalarField.unwrap(low) + (BN254.ScalarField.unwrap(high) * BN254.R_MOD);
}

/// @dev Split a uint256 into a pair of BN254.ScalarField words, in little-endian order
function uintToScalarWords(uint256 value) pure returns (BN254.ScalarField low, BN254.ScalarField high) {
    low = BN254.ScalarField.wrap(value % BN254.R_MOD);
    high = BN254.ScalarField.wrap(value / BN254.R_MOD);
}

// --- Library --- //

library WalletOperations {
    using NullifierLib for NullifierLib.NullifierSet;
    using MerkleTreeLib for MerkleTreeLib.MerkleTree;

    /// @notice Rotate a wallet's shares, nullifying the previous shares and inserting the new shares
    /// @param nullifier The nullifier of the previous wallet's shares
    /// @param historicalMerkleRoot The merkle root to which the previous wallet's share are committed
    /// @param newPrivateShareCommitment The commitment to the new private shares
    /// @param newPublicShares The new shares of the wallet to commit to
    /// @param nullifierSet The set of nullifiers for the darkpool
    /// @param merkleTree The merkle tree for the darkpool
    /// @param hasher The hasher for the darkpool
    function rotateWallet(
        BN254.ScalarField nullifier,
        BN254.ScalarField historicalMerkleRoot,
        BN254.ScalarField newPrivateShareCommitment,
        BN254.ScalarField[] calldata newPublicShares,
        NullifierLib.NullifierSet storage nullifierSet,
        MerkleTreeLib.MerkleTree storage merkleTree,
        IHasher hasher
    )
        internal
        returns (BN254.ScalarField newCommitment)
    {
        // 1. Nullify the previous wallet's shares
        nullifierSet.spend(nullifier);

        // 2. Check that the Merkle root is in the historical Merkle roots
        require(merkleTree.rootInHistory(historicalMerkleRoot), "Merkle root not in history");

        // 3. Insert the new shares into the Merkle tree
        newCommitment = insertWalletCommitment(newPrivateShareCommitment, newPublicShares, merkleTree, hasher);
    }

    /// @notice Insert a wallet's shares into the Merkle tree
    /// @param walletCommitment The commitment to the wallet's shares
    /// @param merkleTree The merkle tree for the darkpool
    /// @param hasher The hasher for the darkpool
    function insertWalletCommitment(
        BN254.ScalarField privateShareCommitment,
        BN254.ScalarField[] memory publicShares,
        MerkleTreeLib.MerkleTree storage merkleTree,
        IHasher hasher
    )
        internal
        returns (BN254.ScalarField walletCommitment)
    {
        walletCommitment = computeWalletCommitment(privateShareCommitment, publicShares, hasher);
        merkleTree.insertLeaf(walletCommitment, hasher);
    }

    /// @notice Compute a commitment to a wallet's shares
    /// @param publicShares The public shares of the wallet
    /// @param privateShareCommitment The commitment to the private shares
    /// @param hasher The hasher for the darkpool
    /// @return The commitment to the wallet's shares
    function computeWalletCommitment(
        BN254.ScalarField privateShareCommitment,
        BN254.ScalarField[] memory publicShares,
        IHasher hasher
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

    /// @notice Spend a note
    /// @dev This involves both checking the note's inclusion root and spending its nullifier
    /// @param noteNullifier The nullifier of the note
    /// @param noteRoot The root of the note
    /// @param nullifierSet The set of nullifiers for the darkpool
    /// @param merkleTree The merkle tree for the darkpool
    function spendNote(
        BN254.ScalarField noteNullifier,
        BN254.ScalarField noteRoot,
        NullifierLib.NullifierSet storage nullifierSet,
        MerkleTreeLib.MerkleTree storage merkleTree
    )
        internal
    {
        // 1. Check that the note is in the Merkle tree
        require(merkleTree.rootInHistory(noteRoot), "Note not in Merkle history");

        // 2. Spend the note
        nullifierSet.spend(noteNullifier);
    }

    /// @notice Verify a wallet update signature
    /// @dev The signature is expected in the following format:
    /// @dev r || s || v, for a total of 65 bytes where:
    /// @dev bytes [0:32] = r
    /// @dev bytes [32:64] = s
    /// @dev bytes [64] = v
    function verifyWalletUpdateSignature(
        BN254.ScalarField walletCommitment,
        bytes calldata newSharesCommitmentSig,
        PublicRootKey memory oldRootKey
    )
        internal
        pure
        returns (bool)
    {
        // 1. Hash the wallet commitment
        bytes32 commitmentHash = walletCommitmentDigest(walletCommitment);

        // 2. Verify the signature
        return verifyRootKeySignature(commitmentHash, newSharesCommitmentSig, oldRootKey);
    }

    /// @notice Verify the root key signature of a digest
    function verifyRootKeySignature(
        bytes32 digest,
        bytes calldata signature,
        PublicRootKey memory rootKey
    )
        internal
        pure
        returns (bool)
    {
        // Split the signature into r, s and v
        require(signature.length == 65, "Invalid signature length");
        bytes32 r = bytes32(signature[:32]);
        bytes32 s = bytes32(signature[32:64]);
        uint8 v = uint8(signature[64]);
        // Clients (notably ethers) sometimes use v = 0 or 1, the ecrecover precompile expects 27 or 28
        if (v == 0 || v == 1) {
            v += 27;
        }

        // Recover signer address using ecrecover
        address signer = ecrecover(digest, v, r, s);
        require(signer != address(0), "Invalid signature");

        // Convert oldRootKey to address and compare
        address rootKeyAddress = addressFromRootKey(rootKey);
        return signer == rootKeyAddress;
    }

    /// @notice Get the digest of a wallet commitment
    function walletCommitmentDigest(BN254.ScalarField walletCommitment) internal pure returns (bytes32) {
        bytes32 walletCommitmentBytes = bytes32(BN254.ScalarField.unwrap(walletCommitment));
        return keccak256(abi.encode(walletCommitmentBytes));
    }

    /// @notice Get an ethereum address from a public root key
    function addressFromRootKey(PublicRootKey memory rootKey) internal pure returns (address) {
        uint256 x = scalarWordsToUint(rootKey.x[0], rootKey.x[1]);
        uint256 y = scalarWordsToUint(rootKey.y[0], rootKey.y[1]);
        // Pack x and y into 64 bytes
        bytes memory packed = abi.encodePacked(x, y);

        // Hash and convert last 20 bytes to address
        bytes32 hash = keccak256(packed);
        return address(uint160(uint256(hash)));
    }
}
