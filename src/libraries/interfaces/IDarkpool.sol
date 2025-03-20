// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { IPermit2 } from "permit2/interfaces/IPermit2.sol";
import { PlonkProof, VerificationKey, NUM_SELECTORS, NUM_WIRE_TYPES } from "renegade-lib/verifier/Types.sol";
import { BN254 } from "solidity-bn254/BN254.sol";
import { IHasher } from "./IHasher.sol";
import { IVerifier } from "./IVerifier.sol";
import { IWETH9 } from "renegade-lib/interfaces/IWETH9.sol";
import {
    ValidWalletCreateStatement,
    ValidWalletUpdateStatement,
    ValidCommitmentsStatement,
    ValidReblindStatement,
    ValidMatchSettleStatement,
    ValidMatchSettleAtomicStatement,
    ValidMalleableMatchSettleAtomicStatement,
    ValidOfflineFeeSettlementStatement,
    ValidFeeRedemptionStatement
} from "renegade-lib/darkpool/PublicInputs.sol";
import { ExternalTransfer } from "renegade-lib/darkpool/types/Transfers.sol";
import {
    BoundedMatchResult,
    ExternalMatchResult,
    PartyMatchPayload,
    MatchProofs,
    MatchLinkingProofs,
    MatchAtomicProofs,
    MatchAtomicLinkingProofs,
    MalleableMatchAtomicProofs
} from "renegade-lib/darkpool/types/Settlement.sol";
import { TransferAuthorization } from "renegade-lib/darkpool/types/Transfers.sol";
import { FeeTake } from "renegade-lib/darkpool/types/Fees.sol";
import { EncryptionKey } from "renegade-lib/darkpool/types/Ciphertext.sol";

interface IDarkpool {
    // --- Events --- //

    /// @notice Emitted when a wallet update is performed
    /// @param wallet_blinder_share The public blinder share of the wallet, used for indexing
    event WalletUpdated(uint256 indexed wallet_blinder_share);
    /// @notice Emitted when an internal Merkle node is updated
    /// @param depth The depth at which the node is updated
    /// @param index The index of the node in the Merkle tree
    /// @param new_value The new value of the node
    event MerkleOpeningNode(uint8 indexed depth, uint128 indexed index, uint256 new_value);
    /// @notice Emitted when a Merkle leaf is inserted into the tree
    /// @param index The leaf index
    /// @param value The value of the leaf
    event MerkleInsertion(uint128 indexed index, uint256 indexed value);

    // --- State Getters --- //

    /// @notice Get the current Merkle root
    /// @return The current Merkle root
    function getMerkleRoot() external view returns (BN254.ScalarField);

    /// @notice Check whether a root is in the Merkle root history
    /// @param root The root to check
    /// @return Whether the root is in the history
    function rootInHistory(BN254.ScalarField root) external view returns (bool);

    /// @notice Check whether a nullifier has been spent
    /// @param nullifier The nullifier to check
    /// @return Whether the nullifier has been spent
    function nullifierSpent(BN254.ScalarField nullifier) external view returns (bool);

    /// @notice Get the public encryption key for the protocol's fees
    /// @return The public encryption key for the protocol's fees
    function getProtocolFeeKey() external view returns (EncryptionKey memory);

    /// @notice Get the protocol fee rate for a given asset
    /// @dev This fee only applies to external matches
    /// @param asset The asset to get the protocol fee rate for
    /// @return The protocol fee rate for the asset
    function getTokenExternalMatchFeeRate(address asset) external view returns (uint256);

    // --- State Variables --- //

    /// @notice The protocol fee rate for the darkpool
    function protocolFeeRate() external view returns (uint256);

    /// @notice The address at which external parties pay protocol fees
    function protocolFeeRecipient() external view returns (address);

    /// @notice The public encryption key for the protocol's fees
    function protocolFeeKey() external view returns (EncryptionKey memory);

    /// @notice A per-asset fee override for the darkpool
    function perTokenFeeOverrides(address) external view returns (uint256);

    /// @notice The hasher for the darkpool
    function hasher() external view returns (IHasher);

    /// @notice The verifier for the darkpool
    function verifier() external view returns (IVerifier);

    /// @notice The Permit2 contract instance for handling deposits
    function permit2() external view returns (IPermit2);

    /// @notice The WETH9 contract instance used for depositing/withdrawing native tokens
    function weth() external view returns (IWETH9);

    // --- State Setters --- //

    /// @notice Set the protocol fee rate for a given asset
    /// @param asset The asset to set the protocol fee rate for
    /// @param fee The protocol fee rate to set. This is a fixed point representation
    /// @dev of a real number between 0 and 1. To convert to its floating point representation,
    /// @dev divide by the fixed point precision, i.e. `fee = assetFeeRate / FIXED_POINT_PRECISION`.
    function setTokenExternalMatchFeeRate(address asset, uint256 fee) external;

    // --- Core Wallet Methods --- //

    /// @notice Create a wallet in the darkpool
    /// @param statement The statement to verify
    /// @param proof The proof of `VALID WALLET CREATE`
    function createWallet(ValidWalletCreateStatement calldata statement, PlonkProof calldata proof) external;

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
        external;

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
        external;

    /// @notice Process and atomic match settlement between two parties; one internal and one external
    /// @dev An internal party is one with state committed into the darkpool, while
    /// @dev an external party provides liquidity to the pool during the
    /// @dev transaction in which this method is called
    /// @dev The receiver of the match settlement is the sender of the transaction
    /// @param internalPartyPayload The validity proofs for the internal party
    /// @param matchSettleStatement The statement (public inputs) of `VALID MATCH SETTLE`
    /// @param proofs The proofs for the match
    /// @param linkingProofs The proof-linking arguments for the match
    function processAtomicMatchSettle(
        PartyMatchPayload calldata internalPartyPayload,
        ValidMatchSettleAtomicStatement calldata matchSettleStatement,
        MatchAtomicProofs calldata proofs,
        MatchAtomicLinkingProofs calldata linkingProofs
    )
        external
        payable;

    /// @notice Process an atomic match with a non-sender receiver specified
    /// @dev The receiver will receive the buy side token amount implied by the match
    /// @dev net of fees by the relayer and protocol
    /// @param receiver The address that will receive the buy side token amount implied by the match
    /// @param internalPartyPayload The validity proofs for the internal party
    /// @param matchSettleStatement The statement (public inputs) of `VALID MATCH SETTLE`
    /// @param proofs The proofs for the match
    /// @param linkingProofs The proof-linking arguments for the match
    function processAtomicMatchSettleWithReceiver(
        address receiver,
        PartyMatchPayload calldata internalPartyPayload,
        ValidMatchSettleAtomicStatement calldata matchSettleStatement,
        MatchAtomicProofs calldata proofs,
        MatchAtomicLinkingProofs calldata linkingProofs
    )
        external
        payable;

    /// @notice Process a malleable match settlement between two parties
    /// @dev This is a variant of `processAtomicMatchSettle` that allows the match amount to be determined
    /// @dev after the proof is generated. This is done by the prover constraining a valid range for the match
    /// @dev amount, allowing the tx sender to choose any value in this range.
    /// @dev The darkpool then uses the price specified in the statement to determine the quote amount and fees
    /// @dev for the match, then settles the obligations to both the internal and external parties
    /// @param baseAmount The base amount of the match, resolving in between the bounds
    /// @param receiver The address that will receive the buy side token amount for the external party
    /// @param internalPartyPayload The validity proofs for the internal party
    /// @param matchSettleStatement The statement (public inputs) of `VALID MATCH SETTLE`
    /// @param proofs The proofs for the match
    /// @param linkingProofs The proof-linking arguments for the match
    function processMalleableAtomicMatchSettle(
        uint256 baseAmount,
        address receiver,
        PartyMatchPayload calldata internalPartyPayload,
        ValidMalleableMatchSettleAtomicStatement calldata matchSettleStatement,
        MalleableMatchAtomicProofs calldata proofs,
        MatchAtomicLinkingProofs calldata linkingProofs
    )
        external
        payable;

    /// @notice Settle a fee due to the protocol or a relayer offline, i.e. without updating the recipient's wallet
    /// @dev Instead of updating the recipient's wallet, a `Note` is created that the recipient may later redeem
    /// @param statement The statement of `VALID OFFLINE FEE SETTLEMENT`
    /// @param proof The proof of `VALID OFFLINE FEE SETTLEMENT`
    function settleOfflineFee(
        ValidOfflineFeeSettlementStatement calldata statement,
        PlonkProof calldata proof
    )
        external
        payable;

    /// @notice Redeem a fee that has been paid offline into a wallet
    /// @param statement The statement of `VALID FEE REDEMPTION`
    /// @param proof The proof of `VALID FEE REDEMPTION`
    function redeemFee(
        bytes calldata recipientCommitmentSig,
        ValidFeeRedemptionStatement calldata statement,
        PlonkProof calldata proof
    )
        external;
}
