// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { IPermit2 } from "permit2/interfaces/IPermit2.sol";
import { PlonkProof, VerificationKey, NUM_SELECTORS, NUM_WIRE_TYPES } from "./libraries/verifier/Types.sol";
import { BN254 } from "solidity-bn254/BN254.sol";
import { VerifierCore } from "./libraries/verifier/VerifierCore.sol";
import { VerificationKeys } from "./libraries/darkpool/VerificationKeys.sol";
import { IHasher } from "./libraries/poseidon2/IHasher.sol";
import { IVerifier } from "./libraries/verifier/IVerifier.sol";
import {
    ValidWalletCreateStatement,
    ValidWalletUpdateStatement,
    ValidCommitmentsStatement,
    ValidReblindStatement,
    ValidMatchSettleStatement,
    ValidMatchSettleAtomicStatement,
    StatementSerializer
} from "./libraries/darkpool/PublicInputs.sol";
import { WalletOperations } from "./libraries/darkpool/WalletOperations.sol";
import { TransferExecutor } from "./libraries/darkpool/ExternalTransfers.sol";
import {
    TransferAuthorization,
    isZero,
    PartyMatchPayload,
    MatchProofs,
    MatchLinkingProofs,
    indicesEqual,
    MatchAtomicProofs,
    MatchAtomicLinkingProofs,
    ExternalMatchResult,
    ExternalMatchDirection
} from "./libraries/darkpool/Types.sol";
import { DarkpoolConstants } from "./libraries/darkpool/Constants.sol";
import { MerkleTreeLib } from "./libraries/merkle/MerkleTree.sol";
import { NullifierLib } from "./libraries/darkpool/NullifierSet.sol";

using MerkleTreeLib for MerkleTreeLib.MerkleTree;
using NullifierLib for NullifierLib.NullifierSet;

contract Darkpool {
    /// @notice The protocol fee rate for the darkpool
    /// @dev This is the fixed point representation of a real number between 0 and 1.
    /// @dev To convert to its floating point representation, divide by the fixed point
    /// @dev precision, i.e. `fee = protocolFeeRate / FIXED_POINT_PRECISION`.
    /// @dev The current precision is `2 ** 63`.
    uint256 public protocolFeeRate;

    /// @notice The hasher for the darkpool
    IHasher public hasher;
    /// @notice The verifier for the darkpool
    IVerifier public verifier;
    /// @notice The Permit2 contract instance for handling deposits
    IPermit2 public permit2;

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
    /// @param permit2_ The Permit2 contract instance for handling deposits
    constructor(uint256 protocolFeeRate_, IHasher hasher_, IVerifier verifier_, IPermit2 permit2_) {
        protocolFeeRate = protocolFeeRate_;
        hasher = hasher_;
        verifier = verifier_;
        permit2 = permit2_;
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
    function createWallet(ValidWalletCreateStatement calldata statement, PlonkProof calldata proof) public {
        // 1. Verify the proof
        bool res = verifier.verifyValidWalletCreate(statement, proof);
        require(res, "Verification failed for wallet create");

        // 2. Insert the wallet shares into the Merkle tree
        WalletOperations.insertWalletCommitment(
            statement.privateShareCommitment, statement.publicShares, merkleTree, hasher
        );
    }

    /// @notice Update a wallet in the darkpool
    /// @param newSharesCommitmentSig The signature of the new wallet shares commitment by the
    /// old wallet's root key
    /// @param statement The statement to verify
    /// @param proof The proof of `VALID WALLET UPDATE`
    function updateWallet(
        bytes calldata newSharesCommitmentSig,
        TransferAuthorization calldata transferAuthorization,
        ValidWalletUpdateStatement calldata statement,
        PlonkProof calldata proof
    )
        public
    {
        // 1. Verify the proof
        bool res = verifier.verifyValidWalletUpdate(statement, proof);
        require(res, "Verification failed for wallet update");

        // 2. Rotate the wallet's shares into the Merkle tree
        BN254.ScalarField newCommitment = WalletOperations.rotateWallet(
            statement.previousNullifier,
            statement.merkleRoot,
            statement.newPrivateShareCommitment,
            statement.newPublicShares,
            nullifierSet,
            merkleTree,
            hasher
        );

        // 3. Verify the signature of the new shares commitment by the root key
        bool validSig =
            WalletOperations.verifyWalletUpdateSignature(newCommitment, newSharesCommitmentSig, statement.oldPkRoot);
        require(validSig, "Invalid signature");

        // 4. Execute the external transfer if it is non-zero
        if (!isZero(statement.externalTransfer)) {
            TransferExecutor.executeTransfer(
                statement.externalTransfer, statement.oldPkRoot, transferAuthorization, permit2
            );
        }
    }

    /// @notice Settle a match in the darkpool
    /// @param party0MatchPayload The validity proofs payload for the first party
    /// @param party1MatchPayload The validity proofs payload for the second party
    /// @param matchSettleStatement The statement of `VALID MATCH SETTLE`
    /// @param proofs The proofs for the match, including two sets of validity proofs and a settlement proof
    function processMatchSettle(
        PartyMatchPayload calldata party0MatchPayload,
        PartyMatchPayload calldata party1MatchPayload,
        ValidMatchSettleStatement calldata matchSettleStatement,
        MatchProofs calldata proofs,
        MatchLinkingProofs calldata linkingProofs
    )
        public
    {
        ValidCommitmentsStatement calldata commitmentsStatement0 = party0MatchPayload.validCommitmentsStatement;
        ValidCommitmentsStatement calldata commitmentsStatement1 = party1MatchPayload.validCommitmentsStatement;
        ValidReblindStatement calldata reblindStatement0 = party0MatchPayload.validReblindStatement;
        ValidReblindStatement calldata reblindStatement1 = party1MatchPayload.validReblindStatement;

        // 1. Verify the proofs
        bool res = verifier.verifyMatchBundle(
            party0MatchPayload, party1MatchPayload, matchSettleStatement, proofs, linkingProofs
        );
        require(res, "Verification failed for match bundle");

        // 2. Check statement consistency between the proofs for the two parties
        // I.e. public inputs used in multiple proofs should take the same values
        bool party0ValidIndices =
            indicesEqual(commitmentsStatement0.indices, matchSettleStatement.firstPartySettlementIndices);
        bool party1ValidIndices =
            indicesEqual(commitmentsStatement1.indices, matchSettleStatement.secondPartySettlementIndices);
        require(party0ValidIndices, "Invalid party 0 order settlement indices");
        require(party1ValidIndices, "Invalid party 1 order settlement indices");

        // 3. Validate the protocol fee rate used in the settlement
        require(matchSettleStatement.protocolFeeRate == protocolFeeRate, "Invalid protocol fee rate");

        // 4. Insert the new shares into the Merkle tree
        WalletOperations.rotateWallet(
            reblindStatement0.originalSharesNullifier,
            reblindStatement0.merkleRoot,
            reblindStatement0.newPrivateShareCommitment,
            matchSettleStatement.firstPartyPublicShares,
            nullifierSet,
            merkleTree,
            hasher
        );
        WalletOperations.rotateWallet(
            reblindStatement1.originalSharesNullifier,
            reblindStatement1.merkleRoot,
            reblindStatement1.newPrivateShareCommitment,
            matchSettleStatement.secondPartyPublicShares,
            nullifierSet,
            merkleTree,
            hasher
        );
    }

    /// @notice Process and atomic match settlement between two parties; one internal and one external
    /// @dev An internal party is one with state committed into the darkpool, while
    /// @dev an external party provides liquidity to the pool during the
    /// @dev transaction in which this method is called
    function processAtomicMatchSettle(
        PartyMatchPayload calldata internalPartyPayload,
        ValidMatchSettleAtomicStatement calldata matchSettleStatement,
        MatchAtomicProofs calldata proofs,
        MatchAtomicLinkingProofs calldata linkingProofs
    )
        public
        payable
    {
        ValidCommitmentsStatement calldata commitmentsStatement = internalPartyPayload.validCommitmentsStatement;
        ValidReblindStatement calldata reblindStatement = internalPartyPayload.validReblindStatement;

        // 1. Validate the transaction value
        // If the external party is selling native ETH, validate that they have provided the correct
        // amount in the transaction's value
        ExternalMatchResult memory matchResult = matchSettleStatement.matchResult;
        bool tradesNativeToken = DarkpoolConstants.isNativeEth(matchResult.baseMint);
        bool externalPartySells = matchResult.direction == ExternalMatchDirection.InternalPartyBuy;
        bool nativeEthSell = tradesNativeToken && externalPartySells;

        // The tx value should be zero unless the external party is selling native ETH
        if (!nativeEthSell && msg.value != 0) {
            revert("Invalid ETH value, should be zero unless selling native ETH");
        }

        // 2. Verify the proofs
        bool res = verifier.verifyAtomicMatchBundle(internalPartyPayload, matchSettleStatement, proofs, linkingProofs);
        require(res, "Verification failed for atomic match bundle");

        // 3. Check statement consistency for the internal party
        // I.e. public inputs used in multiple proofs should take the same values
        bool internalPartyValidIndices =
            indicesEqual(commitmentsStatement.indices, matchSettleStatement.internalPartySettlementIndices);
        require(internalPartyValidIndices, "Invalid internal party order settlement indices");

        // 4. Validate the protocol fee rate used in the settlement
        require(matchSettleStatement.protocolFeeRate == protocolFeeRate, "Invalid protocol fee rate");

        // 5. Insert the new shares into the Merkle tree
        WalletOperations.rotateWallet(
            reblindStatement.originalSharesNullifier,
            reblindStatement.merkleRoot,
            reblindStatement.newPrivateShareCommitment,
            matchSettleStatement.internalPartyModifiedShares,
            nullifierSet,
            merkleTree,
            hasher
        );

        // TODO: Execute external transfers to/from the external party
        require(false, "Not implemented");
    }
}
