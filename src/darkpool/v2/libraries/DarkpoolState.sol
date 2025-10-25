// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { BN254 } from "solidity-bn254/BN254.sol";
import { MerkleMountainLib } from "renegade-lib/merkle/MerkleMountain.sol";
import { NullifierLib } from "renegade-lib/NullifierSet.sol";

import { IHasher } from "renegade-lib/interfaces/IHasher.sol";

/// @title Darkpool State
/// @notice Storage struct bundling core darkpool state
/// @dev Used to pass storage references as a single parameter
struct DarkpoolState {
    /// @notice The mapping of open public intents
    /// @dev This maps the intent hash to the amount remaining.
    /// @dev An intent hash is a hash of the tuple (executor, intent),
    /// where executor is the address of the party allowed to fill the intent.
    mapping(bytes32 => uint256) openPublicIntents;
    /// @notice A store of spent signature nonces for user updates
    /// @dev This is used to prevent a relayer from submitting the same update twice
    mapping(uint256 => bool) spentNonces;
    /// @notice The Merkle mountain range for state element commitments
    MerkleMountainLib.MerkleMountainRange merkleMountainRange;
    /// @notice The nullifier set for the darkpool
    /// @dev Each time a state element is updated a nullifier is spent.
    /// @dev The nullifier set ensures that a pre-update state element cannot create two separate post-update state
    /// elements in the Merkle state
    /// @dev The nullifier is computed deterministically from the shares of the pre-update state element
    NullifierLib.NullifierSet nullifierSet;
}

/// @title DarkpoolState
/// @author Renegade Eng
/// @notice Library for the darkpool state
library DarkpoolStateLib {
    using MerkleMountainLib for MerkleMountainLib.MerkleMountainRange;
    using NullifierLib for NullifierLib.NullifierSet;

    // --- Errors --- //

    /// @notice Error thrown when a signature nonce has already been spent
    error NonceAlreadySpent();

    // --- Getters --- //

    /// @notice Get the amount remaining for an open public intent
    /// @param state The darkpool state
    /// @param intentHash The hash of the intent
    /// @return The amount remaining for the intent
    function getOpenIntentAmountRemaining(
        DarkpoolState storage state,
        bytes32 intentHash
    )
        internal
        view
        returns (uint256)
    {
        return state.openPublicIntents[intentHash];
    }

    /// @notice Check if a nullifier has been spent
    /// @param state The darkpool state
    /// @param nullifier The nullifier to check
    /// @return Whether the nullifier has been spent
    function nullifierSpent(DarkpoolState storage state, BN254.ScalarField nullifier) internal view returns (bool) {
        return state.nullifierSet.isSpent(nullifier);
    }

    /// @notice Check if a root is in the Merkle mountain range history
    /// @param state The darkpool state
    /// @param root The root to check
    /// @return Whether the root is in the history
    function rootInHistory(DarkpoolState storage state, BN254.ScalarField root) internal view returns (bool) {
        return state.merkleMountainRange.rootInHistory(root);
    }

    // --- Setters --- //

    /// @notice Set the amount remaining for an open public intent
    /// @param state The darkpool state
    /// @param intentHash The hash of the intent
    /// @param amount The amount remaining for the intent
    function setOpenIntentAmountRemaining(DarkpoolState storage state, bytes32 intentHash, uint256 amount) internal {
        state.openPublicIntents[intentHash] = amount;
    }

    /// @notice Decrement the amount remaining for an open public intent
    /// @param state The darkpool state
    /// @param intentHash The hash of the intent
    /// @param amount The amount to decrement the amount remaining by
    function decrementOpenIntentAmountRemaining(
        DarkpoolState storage state,
        bytes32 intentHash,
        uint256 amount
    )
        internal
    {
        state.openPublicIntents[intentHash] -= amount;
    }

    /// @notice Spend a signature nonce
    /// @param state The darkpool state
    /// @param nonce The nonce to spend
    function spendNonce(DarkpoolState storage state, uint256 nonce) internal {
        if (state.spentNonces[nonce]) revert NonceAlreadySpent();
        state.spentNonces[nonce] = true;
    }

    /// @notice Spend a nullifier
    /// @param state The darkpool state
    /// @param nullifier The nullifier to spend
    function spendNullifier(DarkpoolState storage state, BN254.ScalarField nullifier) internal {
        state.nullifierSet.spend(nullifier);
    }

    /// @notice Insert a leaf into the Merkle mountain range at the given depth
    /// @param state The darkpool state
    /// @param depth The depth at which to insert the leaf
    /// @param leaf The leaf to insert
    /// @param hasher The hasher to use for hashing
    function insertMerkleLeaf(
        DarkpoolState storage state,
        uint256 depth,
        BN254.ScalarField leaf,
        IHasher hasher
    )
        internal
    {
        state.merkleMountainRange.insertLeaf(depth, leaf, hasher);
    }
}
