// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { IPermit2 } from "permit2/interfaces/IPermit2.sol";
import { PlonkProof, VerificationKey, NUM_SELECTORS, NUM_WIRE_TYPES } from "./libraries/verifier/Types.sol";
import { BN254 } from "solidity-bn254/BN254.sol";
import { VerifierCore } from "./libraries/verifier/VerifierCore.sol";
import { VerificationKeys } from "./libraries/darkpool/VerificationKeys.sol";
import { IHasher } from "./libraries/interfaces/IHasher.sol";
import { IVerifier } from "./libraries/interfaces/IVerifier.sol";
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
    ValidFeeRedemptionStatement,
    StatementSerializer
} from "renegade-lib/darkpool/PublicInputs.sol";
import { WalletOperations } from "renegade-lib/darkpool/WalletOperations.sol";
import { TransferExecutor } from "renegade-lib/darkpool/ExternalTransfers.sol";
import { TypesLib } from "renegade-lib/darkpool/types/TypesLib.sol";
import { ExternalTransfer } from "renegade-lib/darkpool/types/Transfers.sol";
import {
    BoundedMatchResult,
    ExternalMatchResult,
    ExternalMatchDirection,
    OrderSettlementIndices,
    PartyMatchPayload,
    MatchProofs,
    MatchLinkingProofs,
    MatchAtomicProofs,
    MatchAtomicLinkingProofs,
    MalleableMatchAtomicProofs
} from "renegade-lib/darkpool/types/Settlement.sol";
import { TransferAuthorization } from "renegade-lib/darkpool/types/Transfers.sol";
import { FeeTake, FeeTakeRate } from "renegade-lib/darkpool/types/Fees.sol";
import { EncryptionKey } from "renegade-lib/darkpool/types/Ciphertext.sol";
import { DarkpoolConstants } from "renegade-lib/darkpool/Constants.sol";
import { MerkleTreeLib } from "./libraries/merkle/MerkleTree.sol";
import { NullifierLib } from "./libraries/darkpool/NullifierSet.sol";

contract Darkpool {
    using MerkleTreeLib for MerkleTreeLib.MerkleTree;
    using NullifierLib for NullifierLib.NullifierSet;
    using TypesLib for ExternalTransfer;
    using TypesLib for ExternalMatchResult;
    using TypesLib for OrderSettlementIndices;
    using TypesLib for FeeTake;
    using TypesLib for EncryptionKey;

    /// @notice The protocol fee rate for the darkpool
    /// @dev This is the fixed point representation of a real number between 0 and 1.
    /// @dev To convert to its floating point representation, divide by the fixed point
    /// @dev precision, i.e. `fee = protocolFeeRate / FIXED_POINT_PRECISION`.
    /// @dev The current precision is `2 ** 63`.
    uint256 public protocolFeeRate;
    /// @notice The address at which external parties pay protocol fees
    /// @dev This is only used for external parties in atomic matches, fees for internal matches
    /// @dev and internal parties in atomic matches are paid via the `Note` mechanism.
    address public protocolFeeRecipient;
    /// @notice The public encryption key for the protocol's fees
    EncryptionKey public protocolFeeKey;
    /// @notice A per-asset fee override for the darkpool
    /// @dev This is used to set the protocol fee rate for atomic matches on a per-token basis
    /// @dev Only external match fees are overridden, internal match fees are always the protocol fee rate
    mapping(address => uint256) public perTokenFeeOverrides;

    /// @notice The hasher for the darkpool
    IHasher public hasher;
    /// @notice The verifier for the darkpool
    IVerifier public verifier;
    /// @notice The Permit2 contract instance for handling deposits
    IPermit2 public permit2;
    /// @notice The WETH9 contract instance used for depositing/withdrawing native tokens
    IWETH9 public weth;

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
    constructor(
        uint256 protocolFeeRate_,
        address protocolFeeRecipient_,
        EncryptionKey memory protocolFeeKey_,
        IWETH9 weth_,
        IHasher hasher_,
        IVerifier verifier_,
        IPermit2 permit2_
    ) {
        protocolFeeRate = protocolFeeRate_;
        protocolFeeRecipient = protocolFeeRecipient_;
        protocolFeeKey = protocolFeeKey_;
        hasher = hasher_;
        verifier = verifier_;
        permit2 = permit2_;
        weth = weth_;
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

    /// @notice Get the public encryption key for the protocol's fees
    /// @return The public encryption key for the protocol's fees
    function getProtocolFeeKey() public view returns (EncryptionKey memory) {
        return protocolFeeKey;
    }

    /// @notice Get the protocol fee rate for a given asset
    /// @dev This fee only applies to external matches
    /// @param asset The asset to get the protocol fee rate for
    /// @return The protocol fee rate for the asset
    function getTokenExternalMatchFeeRate(address asset) public view returns (uint256) {
        uint256 perTokenFee = perTokenFeeOverrides[asset];
        if (perTokenFee == 0) {
            return protocolFeeRate;
        }
        return perTokenFee;
    }

    // --- State Setters --- //

    /// @notice Set the protocol fee rate for a given asset
    /// @param asset The asset to set the protocol fee rate for
    /// @param fee The protocol fee rate to set. This is a fixed point representation
    /// @dev of a real number between 0 and 1. To convert to its floating point representation,
    /// @dev divide by the fixed point precision, i.e. `fee = assetFeeRate / FIXED_POINT_PRECISION`.
    function setTokenExternalMatchFeeRate(address asset, uint256 fee) public {
        // TODO: Add access control
        perTokenFeeOverrides[asset] = fee;
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
        if (!statement.externalTransfer.isZero()) {
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
            commitmentsStatement0.indices.indicesEqual(matchSettleStatement.firstPartySettlementIndices);
        bool party1ValidIndices =
            commitmentsStatement1.indices.indicesEqual(matchSettleStatement.secondPartySettlementIndices);
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
        public
        payable
    {
        address receiver = msg.sender;
        processAtomicMatchSettleWithReceiver(
            receiver, internalPartyPayload, matchSettleStatement, proofs, linkingProofs
        );
    }

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
        public
        payable
    {
        ValidCommitmentsStatement calldata commitmentsStatement = internalPartyPayload.validCommitmentsStatement;
        ValidReblindStatement calldata reblindStatement = internalPartyPayload.validReblindStatement;

        // 1. Validate the transaction value
        // If the external party is selling a native token, validate that they have provided the correct
        // amount in the transaction's value
        ExternalMatchResult memory matchResult = matchSettleStatement.matchResult;
        bool tradesNativeToken = DarkpoolConstants.isNativeToken(matchResult.baseMint);
        bool externalPartySells = matchResult.direction == ExternalMatchDirection.InternalPartyBuy;
        bool nativeTokenSell = tradesNativeToken && externalPartySells;

        // The tx value should be zero unless the external party is selling native token
        if (!nativeTokenSell && msg.value != 0) {
            revert("Invalid ETH value, should be zero unless selling native token");
        }

        // 2. Verify the proofs
        bool res = verifier.verifyAtomicMatchBundle(internalPartyPayload, matchSettleStatement, proofs, linkingProofs);
        require(res, "Verification failed for atomic match bundle");

        // 3. Check statement consistency for the internal party
        // I.e. public inputs used in multiple proofs should take the same values
        bool internalPartyValidIndices =
            commitmentsStatement.indices.indicesEqual(matchSettleStatement.internalPartySettlementIndices);
        require(internalPartyValidIndices, "Invalid internal party order settlement indices");

        // 4. Validate the protocol fee rate used in the settlement
        uint256 protocolFee = getTokenExternalMatchFeeRate(matchResult.baseMint);
        require(matchSettleStatement.protocolFeeRate == protocolFee, "Invalid protocol fee rate");

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

        // 6. Execute external transfers to/from the external party
        ValidMatchSettleAtomicStatement calldata statement = matchSettleStatement;
        TransferExecutor.SimpleTransfer[] memory transfers = buildAtomicMatchTransfers(
            receiver, statement.relayerFeeAddress, statement.matchResult, statement.externalPartyFees
        );
        TransferExecutor.executeTransferBatch(transfers, weth);
    }

    /// @notice Process a malleable match settlement between two parties
    /// @dev This is a variant of `processAtomicMatchSettle` that allows the match amount to be determined
    /// @dev after the proof is generated. This is done by the prover constraining a valid range for the match
    /// @dev amount, allowing the tx sender to choose any value in this range.
    /// @dev The darkpool then uses the price specified in the statement to determine the quote amount and fees
    /// @dev for the match, then settles the obligations to both the internal and external parties
    /// @param baseAmount The base amount of the match, resolving in between the bounds
    /// @param internalPartyPayload The validity proofs for the internal party
    /// @param matchSettleStatement The statement (public inputs) of `VALID MATCH SETTLE`
    /// @param proofs The proofs for the match
    /// @param linkingProofs The proof-linking arguments for the match
    function processMalleableAtomicMatchSettle(
        uint256 baseAmount,
        PartyMatchPayload calldata internalPartyPayload,
        ValidMalleableMatchSettleAtomicStatement calldata matchSettleStatement,
        MalleableMatchAtomicProofs calldata proofs,
        MatchAtomicLinkingProofs calldata linkingProofs
    )
        public
        payable
    {
        // 1. Validate the transaction value
        // If the external party is selling a native token, validate that they have provided the correct
        // amount in the transaction's value
        BoundedMatchResult memory boundedMatchResult = matchSettleStatement.matchResult;
        bool tradesNativeToken = DarkpoolConstants.isNativeToken(boundedMatchResult.baseMint);
        bool externalPartySells = boundedMatchResult.direction == ExternalMatchDirection.InternalPartyBuy;
        bool nativeTokenSell = tradesNativeToken && externalPartySells;

        // The tx value should be zero unless the external party is selling native token
        if (!nativeTokenSell && msg.value != 0) {
            revert("Invalid ETH value, should be zero unless selling native token");
        }

        // 2. Verify the proofs
        bool res =
            verifier.verifyMalleableMatchBundle(internalPartyPayload, matchSettleStatement, proofs, linkingProofs);
        require(res, "Verification failed for malleable match bundle");

        // 3. Verify the protocol fee rates used in settlement
        uint256 protocolFee = getTokenExternalMatchFeeRate(boundedMatchResult.baseMint);
        FeeTakeRate memory internalPartyFees = matchSettleStatement.internalFeeRates;
        FeeTakeRate memory externalPartyFees = matchSettleStatement.externalFeeRates;
        require(internalPartyFees.protocolFeeRate.repr == protocolFee, "Invalid internal party protocol fee rate");
        require(externalPartyFees.protocolFeeRate.repr == protocolFee, "Invalid external party protocol fee rate");

        // 4. Build an external match result from the bounded match result
        ExternalMatchResult memory matchResult = TypesLib.buildExternalMatchResult(baseAmount, boundedMatchResult);

        // 5. Compute the fees due on the match
        (address internalPartyReceiveMint, uint256 internalPartyReceiveAmount) =
            matchResult.externalPartySellMintAmount();
        (address externalPartyReceiveMint, uint256 externalPartyReceiveAmount) =
            matchResult.externalPartyBuyMintAmount();
        FeeTake memory internalPartyFeeTake = TypesLib.computeFeeTake(internalPartyFees, internalPartyReceiveAmount);
        FeeTake memory externalPartyFeeTake = TypesLib.computeFeeTake(externalPartyFees, externalPartyReceiveAmount);

        require(false, "Not implemented");
    }

    /// @notice Settle a fee due to the protocol or a relayer offline, i.e. without updating the recipient's wallet
    /// @dev Instead of updating the recipient's wallet, a `Note` is created that the recipient may later redeem
    /// @param statement The statement of `VALID OFFLINE FEE SETTLEMENT`
    /// @param proof The proof of `VALID OFFLINE FEE SETTLEMENT`
    function settleOfflineFee(
        ValidOfflineFeeSettlementStatement calldata statement,
        PlonkProof calldata proof
    )
        public
        payable
    {
        // 1. Check that the statement uses the correct protocol fee encryption key
        bool correctKey = statement.protocolKey.encryptionKeyEqual(protocolFeeKey);
        require(correctKey, "Invalid protocol fee encryption key");

        // 2. Verify the proof of `VALID OFFLINE FEE SETTLEMENT`
        bool res = verifier.verifyValidOfflineFeeSettlement(statement, proof);
        require(res, "Verification failed for offline fee settlement");

        // 3. Rotate the fee payer's wallet
        WalletOperations.rotateWallet(
            statement.walletNullifier,
            statement.merkleRoot,
            statement.updatedWalletCommitment,
            statement.updatedWalletPublicShares,
            nullifierSet,
            merkleTree,
            hasher
        );

        // 4. Commit the note into the merkle tree
        merkleTree.insertLeaf(statement.noteCommitment, hasher);
    }

    /// @notice Redeem a fee that has been paid offline into a wallet
    /// @param statement The statement of `VALID FEE REDEMPTION`
    /// @param proof The proof of `VALID FEE REDEMPTION`
    function redeemFee(
        bytes calldata recipientCommitmentSig,
        ValidFeeRedemptionStatement calldata statement,
        PlonkProof calldata proof
    )
        public
    {
        // 1. Verify the proof
        bool res = verifier.verifyValidFeeRedemption(statement, proof);
        require(res, "Verification failed for fee redemption");

        // 2. Rotate the wallet
        BN254.ScalarField newCommitment = WalletOperations.rotateWallet(
            statement.walletNullifier,
            statement.walletRoot,
            statement.newWalletCommitment,
            statement.newWalletPublicShares,
            nullifierSet,
            merkleTree,
            hasher
        );

        // 3. Verify the signature of the new shares commitment by the root key
        bool validSig =
            WalletOperations.verifyWalletUpdateSignature(newCommitment, recipientCommitmentSig, statement.walletRootKey);
        require(validSig, "Invalid signature");

        // 4. Spend the note
        WalletOperations.spendNote(statement.noteNullifier, statement.noteRoot, nullifierSet, merkleTree);
    }

    // --- Helpers --- //

    /// @notice Build a list of simple transfers to settle an atomic match
    function buildAtomicMatchTransfers(
        address externalParty,
        address relayerFeeAddr,
        ExternalMatchResult memory matchResult,
        FeeTake memory feeTake
    )
        internal
        view
        returns (TransferExecutor.SimpleTransfer[] memory transfers)
    {
        (address sellMint, uint256 sellAmount) = matchResult.externalPartySellMintAmount();
        (address buyMint, uint256 buyAmount) = matchResult.externalPartyBuyMintAmount();

        // Build the transfers
        transfers = new TransferExecutor.SimpleTransfer[](4);

        // 1. Deposit the sell amount
        transfers[0] = TransferExecutor.SimpleTransfer({
            account: msg.sender,
            mint: sellMint,
            amount: sellAmount,
            transferType: TransferExecutor.SimpleTransferType.Deposit
        });

        // 2. Withdraw the buy amount net of fees
        // Tx will revert if the buy amount is less than the total fees
        uint256 totalFees = feeTake.total();
        uint256 traderTake = buyAmount - totalFees;
        transfers[1] = TransferExecutor.SimpleTransfer({
            account: externalParty,
            mint: buyMint,
            amount: traderTake,
            transferType: TransferExecutor.SimpleTransferType.Withdrawal
        });

        // 3. Withdraw the relayer's fee on the external party to the relayer
        transfers[2] = TransferExecutor.SimpleTransfer({
            account: relayerFeeAddr,
            mint: buyMint,
            amount: feeTake.relayerFee,
            transferType: TransferExecutor.SimpleTransferType.Withdrawal
        });

        // 4. Withdraw the protocol's fee on the external party to the protocol
        transfers[3] = TransferExecutor.SimpleTransfer({
            account: protocolFeeRecipient,
            mint: buyMint,
            amount: feeTake.protocolFee,
            transferType: TransferExecutor.SimpleTransferType.Withdrawal
        });
    }
}
