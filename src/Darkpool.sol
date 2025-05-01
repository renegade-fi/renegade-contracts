// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { IPermit2 } from "permit2/interfaces/IPermit2.sol";
import { PlonkProof, VerificationKey, NUM_SELECTORS, NUM_WIRE_TYPES } from "renegade-lib/verifier/Types.sol";
import { BN254 } from "solidity-bn254/BN254.sol";
import { VerifierCore } from "./libraries/verifier/VerifierCore.sol";
import { VerificationKeys } from "./libraries/darkpool/VerificationKeys.sol";
import { IHasher } from "./libraries/interfaces/IHasher.sol";
import { IVerifier } from "./libraries/interfaces/IVerifier.sol";
import { IWETH9 } from "renegade-lib/interfaces/IWETH9.sol";
import { Ownable } from "openzeppelin-contracts/contracts/access/Ownable.sol";
import { Pausable } from "openzeppelin-contracts/contracts/utils/Pausable.sol";
import { TransferExecutor } from "./TransferExecutor.sol";
import {
    ValidWalletCreateStatement,
    ValidWalletUpdateStatement,
    ValidCommitmentsStatement,
    ValidReblindStatement,
    ValidMatchSettleStatement,
    ValidMatchSettleWithCommitmentsStatement,
    ValidMatchSettleAtomicStatement,
    ValidMatchSettleAtomicWithCommitmentsStatement,
    ValidMalleableMatchSettleAtomicStatement,
    ValidOfflineFeeSettlementStatement,
    ValidFeeRedemptionStatement,
    StatementSerializer
} from "renegade-lib/darkpool/PublicInputs.sol";
import { WalletOperations } from "renegade-lib/darkpool/WalletOperations.sol";
import { ExternalTransferLib } from "renegade-lib/darkpool/ExternalTransfers.sol";
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
import { BabyJubJubPoint } from "./libraries/darkpool/types/Ciphertext.sol";

contract Darkpool is Ownable, Pausable {
    using MerkleTreeLib for MerkleTreeLib.MerkleTree;
    using NullifierLib for NullifierLib.NullifierSet;
    using TypesLib for ExternalTransfer;
    using TypesLib for ExternalMatchResult;
    using TypesLib for OrderSettlementIndices;
    using TypesLib for FeeTake;
    using TypesLib for EncryptionKey;

    // Events
    event FeeChanged(uint256 newFee);
    event ExternalMatchFeeChanged(address indexed asset, uint256 newFee);
    event PubkeyRotated(uint256 newPubkeyX, uint256 newPubkeyY);
    event ExternalFeeCollectionAddressChanged(address indexed newAddress);

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
    /// @notice The TransferExecutor contract for handling external transfers
    address public transferExecutor;

    /// @notice The Merkle tree for wallet commitments
    MerkleTreeLib.MerkleTree private merkleTree;
    /// @notice The nullifier set for the darkpool
    /// @dev Each time a wallet is updated (placing an order, settling a match, depositing, etc) a nullifier is spent.
    /// @dev This ensures that a pre-update wallet cannot create two separate post-update wallets in the Merkle state
    /// @dev The nullifier is computed deterministically from the shares of the pre-update wallet
    NullifierLib.NullifierSet private nullifierSet;
    /// @notice The set of public blinder shares that have been inserted into the darkpool
    /// @dev We track this to prevent duplicate blinders that may affect the ability of indexers to uniquely
    /// @dev recover a wallet
    NullifierLib.NullifierSet private publicBlinderSet;

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
        IPermit2 permit2_,
        address transferExecutor_
    )
        Ownable(msg.sender)
    {
        protocolFeeRate = protocolFeeRate_;
        protocolFeeRecipient = protocolFeeRecipient_;
        protocolFeeKey = protocolFeeKey_;
        hasher = hasher_;
        verifier = verifier_;
        permit2 = permit2_;
        weth = weth_;
        transferExecutor = transferExecutor_;
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

    /// @notice Check whether a public blinder has been used
    /// @param publicBlinder The public blinder to check
    /// @return Whether the public blinder has been used
    function publicBlinderUsed(BN254.ScalarField publicBlinder) public view returns (bool) {
        return publicBlinderSet.isSpent(publicBlinder);
    }

    /// @notice Get the protocol fee rate
    /// @return The protocol fee rate
    function getProtocolFee() public view returns (uint256) {
        return protocolFeeRate;
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

    /// @notice Get the protocol fee recipient address
    /// @notice This is the address to which external match fees are sent for the protocol
    /// @return The protocol fee recipient address
    function getProtocolFeeRecipient() public view returns (address) {
        return protocolFeeRecipient;
    }

    // --- State Setters --- //

    /// @notice Set the protocol fee rate
    /// @param newFee The new protocol fee rate to set
    function setProtocolFeeRate(uint256 newFee) public onlyOwner whenNotPaused {
        require(newFee != 0, "Fee cannot be zero");
        protocolFeeRate = newFee;
        emit FeeChanged(newFee);
    }

    /// @notice Set the protocol fee rate for a given asset
    /// @param asset The asset to set the protocol fee rate for
    /// @param fee The protocol fee rate to set. This is a fixed point representation
    /// @dev of a real number between 0 and 1. To convert to its floating point representation,
    /// @dev divide by the fixed point precision, i.e. `fee = assetFeeRate / FIXED_POINT_PRECISION`.
    function setTokenExternalMatchFeeRate(address asset, uint256 fee) public onlyOwner whenNotPaused {
        require(fee != 0, "Fee cannot be zero");
        perTokenFeeOverrides[asset] = fee;
        emit ExternalMatchFeeChanged(asset, fee);
    }

    /// @notice Remove the fee override for an asset
    /// @param asset The asset to remove the fee override for
    function removeTokenExternalMatchFeeRate(address asset) public onlyOwner whenNotPaused {
        delete perTokenFeeOverrides[asset];
        emit ExternalMatchFeeChanged(asset, protocolFeeRate);
    }

    /// @notice Set the protocol public encryption key
    /// @param newPubkeyX The new X coordinate of the public key
    /// @param newPubkeyY The new Y coordinate of the public key
    function setProtocolFeeKey(uint256 newPubkeyX, uint256 newPubkeyY) public onlyOwner whenNotPaused {
        protocolFeeKey = EncryptionKey({
            point: BabyJubJubPoint({ x: BN254.ScalarField.wrap(newPubkeyX), y: BN254.ScalarField.wrap(newPubkeyY) })
        });
        emit PubkeyRotated(newPubkeyX, newPubkeyY);
    }

    /// @notice Set the protocol external fee collection address
    /// @param newAddress The new address to collect external fees
    function setProtocolFeeRecipient(address newAddress) public onlyOwner whenNotPaused {
        require(newAddress != address(0), "Address cannot be zero");
        protocolFeeRecipient = newAddress;
        emit ExternalFeeCollectionAddressChanged(newAddress);
    }

    /// @notice Set the address of the TransferExecutor contract
    /// @param newTransferExecutor The new address of the TransferExecutor contract
    function setTransferExecutor(address newTransferExecutor) public onlyOwner whenNotPaused {
        require(newTransferExecutor != address(0), "Address cannot be zero");
        transferExecutor = newTransferExecutor;
    }

    /// @notice Pause the darkpool
    function pause() public onlyOwner {
        _pause();
    }

    /// @notice Unpause the darkpool
    function unpause() public onlyOwner {
        _unpause();
    }

    // --- Core Wallet Methods --- //

    /// @notice Create a wallet in the darkpool
    /// @param statement The statement to verify
    /// @param proof The proof of `VALID WALLET CREATE`
    function createWallet(
        ValidWalletCreateStatement calldata statement,
        PlonkProof calldata proof
    )
        public
        whenNotPaused
    {
        // 1. Verify the proof
        bool res = verifier.verifyValidWalletCreate(statement, proof);
        require(res, "Verification failed for wallet create");

        // 2. Mark the public blinder share as spent
        // Assumes that the public blinder share is the last share in the array
        BN254.ScalarField publicBlinder = statement.publicShares[statement.publicShares.length - 1];
        WalletOperations.markPublicBlinderAsUsed(publicBlinder, publicBlinderSet);

        // 3. Insert the wallet shares into the Merkle tree
        merkleTree.insertLeaf(statement.walletShareCommitment, hasher);
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
        whenNotPaused
    {
        // 1. Verify the proof
        bool res = verifier.verifyValidWalletUpdate(statement, proof);
        require(res, "Verification failed for wallet update");

        // 2. Rotate the wallet's shares into the Merkle tree
        BN254.ScalarField newCommitment = statement.newWalletCommitment;
        WalletOperations.rotateWalletWithCommitment(
            statement.previousNullifier,
            statement.merkleRoot,
            newCommitment,
            statement.newPublicShares,
            nullifierSet,
            publicBlinderSet,
            merkleTree,
            hasher
        );

        // 3. Verify the signature of the new shares commitment by the root key
        bool validSig =
            WalletOperations.verifyWalletUpdateSignature(newCommitment, newSharesCommitmentSig, statement.oldPkRoot);
        require(validSig, "Invalid signature");

        // 4. Execute the external transfer if it is non-zero
        if (!statement.externalTransfer.isZero()) {
            // delegatecall to TransferExecutor
            (bool success, bytes memory returnData) = transferExecutor.delegatecall(
                abi.encodeWithSelector(
                    TransferExecutor.executeTransfer.selector,
                    statement.externalTransfer,
                    statement.oldPkRoot,
                    transferAuthorization,
                    permit2
                )
            );
            _handleDelegateCallResult(success, returnData);
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
        whenNotPaused
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
            publicBlinderSet,
            merkleTree,
            hasher
        );
        WalletOperations.rotateWallet(
            reblindStatement1.originalSharesNullifier,
            reblindStatement1.merkleRoot,
            reblindStatement1.newPrivateShareCommitment,
            matchSettleStatement.secondPartyPublicShares,
            nullifierSet,
            publicBlinderSet,
            merkleTree,
            hasher
        );
    }

    /// @notice Settle a match in the darkpool with wallet commitments pre-computed in-circuit
    /// @dev This is a variant of `processMatchSettle` that allows the prover to pre-compute the wallet
    /// @dev commitments for the two parties, then pass them into the function as part of the statement
    /// @param party0MatchPayload The validity proofs for the first party
    /// @param party1MatchPayload The validity proofs for the second party
    /// @param matchSettleStatement The statement of `VALID MATCH SETTLE WITH COMMITMENTS`
    /// @param proofs The proofs for the match
    /// @param linkingProofs The proof-linking arguments for the match
    function processMatchSettleWithCommitments(
        PartyMatchPayload calldata party0MatchPayload,
        PartyMatchPayload calldata party1MatchPayload,
        ValidMatchSettleWithCommitmentsStatement calldata matchSettleStatement,
        MatchProofs calldata proofs,
        MatchLinkingProofs calldata linkingProofs
    )
        public
        whenNotPaused
    {
        ValidCommitmentsStatement calldata commitmentsStatement0 = party0MatchPayload.validCommitmentsStatement;
        ValidCommitmentsStatement calldata commitmentsStatement1 = party1MatchPayload.validCommitmentsStatement;
        ValidReblindStatement calldata reblindStatement0 = party0MatchPayload.validReblindStatement;
        ValidReblindStatement calldata reblindStatement1 = party1MatchPayload.validReblindStatement;

        // 1. Verify the proofs
        bool res = verifier.verifyMatchBundleWithCommitments(
            party0MatchPayload, party1MatchPayload, matchSettleStatement, proofs, linkingProofs
        );
        require(res, "Verification failed for match bundle with commitments");

        // 2. Check statement consistency between the proofs for the two parties
        // I.e. public inputs used in multiple proofs should take the same values
        bool party0ValidIndices =
            commitmentsStatement0.indices.indicesEqual(matchSettleStatement.firstPartySettlementIndices);
        bool party1ValidIndices =
            commitmentsStatement1.indices.indicesEqual(matchSettleStatement.secondPartySettlementIndices);
        require(party0ValidIndices, "Invalid party 0 order settlement indices");
        require(party1ValidIndices, "Invalid party 1 order settlement indices");

        uint256 reblindComm0 = BN254.ScalarField.unwrap(reblindStatement0.newPrivateShareCommitment);
        uint256 reblindComm1 = BN254.ScalarField.unwrap(reblindStatement1.newPrivateShareCommitment);
        uint256 newShareComm0 = BN254.ScalarField.unwrap(matchSettleStatement.privateShareCommitment0);
        uint256 newShareComm1 = BN254.ScalarField.unwrap(matchSettleStatement.privateShareCommitment1);
        bool party0ValidCommitment = reblindComm0 == newShareComm0;
        bool party1ValidCommitment = reblindComm1 == newShareComm1;
        require(party0ValidCommitment, "Invalid party 0 private share commitment");
        require(party1ValidCommitment, "Invalid party 1 private share commitment");

        // 3. Validate the protocol fee rate used in the settlement
        require(matchSettleStatement.protocolFeeRate == protocolFeeRate, "Invalid protocol fee rate");

        // 4. Insert the new shares into the Merkle tree
        WalletOperations.rotateWalletWithCommitment(
            reblindStatement0.originalSharesNullifier,
            reblindStatement0.merkleRoot,
            matchSettleStatement.newShareCommitment0,
            matchSettleStatement.firstPartyPublicShares,
            nullifierSet,
            publicBlinderSet,
            merkleTree,
            hasher
        );
        WalletOperations.rotateWalletWithCommitment(
            reblindStatement1.originalSharesNullifier,
            reblindStatement1.merkleRoot,
            matchSettleStatement.newShareCommitment1,
            matchSettleStatement.secondPartyPublicShares,
            nullifierSet,
            publicBlinderSet,
            merkleTree,
            hasher
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
    function processAtomicMatchSettle(
        address receiver,
        PartyMatchPayload calldata internalPartyPayload,
        ValidMatchSettleAtomicStatement calldata matchSettleStatement,
        MatchAtomicProofs calldata proofs,
        MatchAtomicLinkingProofs calldata linkingProofs
    )
        public
        payable
        whenNotPaused
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
        // If trading the native token, we need to convert the base mint to use WETH so that its pair
        // matches the internal party's pair
        ValidMatchSettleAtomicStatement memory statement = matchSettleStatement;
        if (tradesNativeToken) {
            statement.matchResult.baseMint = address(weth);
        }
        bool res = verifier.verifyAtomicMatchBundle(internalPartyPayload, statement, proofs, linkingProofs);
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
            publicBlinderSet,
            merkleTree,
            hasher
        );

        // 6. Execute external transfers to/from the external party using TransferExecutor
        (bool success, bytes memory returnData) = transferExecutor.delegatecall(
            abi.encodeWithSelector(
                TransferExecutor.executeAtomicMatchTransfers.selector,
                receiver,
                matchSettleStatement.relayerFeeAddress,
                protocolFeeRecipient,
                matchResult,
                matchSettleStatement.externalPartyFees,
                weth
            )
        );
        _handleDelegateCallResult(success, returnData);
    }

    /// @notice Process an atomic match settlement between two parties with commitments; one internal and one external
    /// @dev An internal party is one with state committed into the darkpool, while
    /// @dev an external party provides liquidity to the pool during the
    /// @dev transaction in which this method is called
    /// @dev The receiver of the match settlement is the sender of the transaction
    /// @dev This variant allows the receiver to be specified as a parameter
    /// @param receiver The address that will receive the buy side token amount for the external party
    /// @param internalPartyPayload The validity proofs for the internal party
    /// @param matchSettleStatement The statement (public inputs) of `VALID MATCH SETTLE WITH COMMITMENTS`
    /// @param proofs The proofs for the match
    /// @param linkingProofs The proof-linking arguments for the match
    function processAtomicMatchSettleWithCommitments(
        address receiver,
        PartyMatchPayload calldata internalPartyPayload,
        ValidMatchSettleAtomicWithCommitmentsStatement calldata matchSettleStatement,
        MatchAtomicProofs calldata proofs,
        MatchAtomicLinkingProofs calldata linkingProofs
    )
        public
        payable
        whenNotPaused
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
        // If trading the native token, we need to convert the base mint to use WETH so that its pair
        // matches the internal party's pair
        ValidMatchSettleAtomicWithCommitmentsStatement memory statement = matchSettleStatement;
        if (tradesNativeToken) {
            statement.matchResult.baseMint = address(weth);
        }
        bool res =
            verifier.verifyAtomicMatchBundleWithCommitments(internalPartyPayload, statement, proofs, linkingProofs);
        require(res, "Verification failed for atomic match bundle with commitments");

        // 3. Check statement consistency for the internal party
        // I.e. public inputs used in multiple proofs should take the same values
        bool internalPartyValidIndices =
            commitmentsStatement.indices.indicesEqual(matchSettleStatement.internalPartySettlementIndices);
        require(internalPartyValidIndices, "Invalid internal party order settlement indices");

        uint256 reblindComm = BN254.ScalarField.unwrap(reblindStatement.newPrivateShareCommitment);
        uint256 newShareComm = BN254.ScalarField.unwrap(matchSettleStatement.privateShareCommitment);
        bool internalPartyValidCommitment = reblindComm == newShareComm;
        require(internalPartyValidCommitment, "Invalid internal party private share commitment");

        // 4. Validate the protocol fee rate used in the settlement
        uint256 protocolFee = getTokenExternalMatchFeeRate(matchResult.baseMint);
        require(matchSettleStatement.protocolFeeRate == protocolFee, "Invalid protocol fee rate");

        // 5. Insert the new shares into the Merkle tree
        WalletOperations.rotateWalletWithCommitment(
            reblindStatement.originalSharesNullifier,
            reblindStatement.merkleRoot,
            matchSettleStatement.newShareCommitment,
            matchSettleStatement.internalPartyModifiedShares,
            nullifierSet,
            publicBlinderSet,
            merkleTree,
            hasher
        );

        // 6. Execute external transfers to/from the external party using TransferExecutor
        (bool success, bytes memory returnData) = transferExecutor.delegatecall(
            abi.encodeWithSelector(
                TransferExecutor.executeAtomicMatchTransfers.selector,
                receiver,
                matchSettleStatement.relayerFeeAddress,
                protocolFeeRecipient,
                matchResult,
                matchSettleStatement.externalPartyFees,
                weth
            )
        );
        _handleDelegateCallResult(success, returnData);
    }

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
        public
        payable
        whenNotPaused
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
        // If trading the native token, we need to convert the base mint to use WETH so that its pair
        // matches the internal party's pair
        ValidMalleableMatchSettleAtomicStatement memory statement = matchSettleStatement;
        if (tradesNativeToken) {
            statement.matchResult.baseMint = address(weth);
        }
        bool res = verifier.verifyMalleableMatchBundle(internalPartyPayload, statement, proofs, linkingProofs);
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
        (, uint256 externalPartyReceiveAmount) = matchResult.externalPartyBuyMintAmount();
        FeeTake memory externalPartyFeeTake = TypesLib.computeFeeTake(externalPartyFees, externalPartyReceiveAmount);

        // 6. Apply the match to the internal party's public shares
        ValidReblindStatement calldata reblindStatement = internalPartyPayload.validReblindStatement;
        ValidCommitmentsStatement calldata commitmentsStatement = internalPartyPayload.validCommitmentsStatement;
        BN254.ScalarField[] memory newShares = WalletOperations.applyExternalMatchToShares(
            matchSettleStatement.internalPartyPublicShares, internalPartyFees, matchResult, commitmentsStatement.indices
        );

        // 7. Insert the new shares into the Merkle tree
        WalletOperations.rotateWallet(
            reblindStatement.originalSharesNullifier,
            reblindStatement.merkleRoot,
            reblindStatement.newPrivateShareCommitment,
            newShares,
            nullifierSet,
            publicBlinderSet,
            merkleTree,
            hasher
        );

        // 8. Execute external transfers to/from the external party using TransferExecutor
        (bool success, bytes memory returnData) = transferExecutor.delegatecall(
            abi.encodeWithSelector(
                TransferExecutor.executeAtomicMatchTransfers.selector,
                receiver,
                matchSettleStatement.relayerFeeAddress,
                protocolFeeRecipient,
                matchResult,
                externalPartyFeeTake,
                weth
            )
        );
        _handleDelegateCallResult(success, returnData);
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
        whenNotPaused
    {
        // 1. Check that the statement uses the correct protocol fee encryption key
        bool correctKey = statement.protocolKey.encryptionKeyEqual(protocolFeeKey);
        require(correctKey, "Invalid protocol fee encryption key");

        // 2. Verify the proof of `VALID OFFLINE FEE SETTLEMENT`
        bool res = verifier.verifyValidOfflineFeeSettlement(statement, proof);
        require(res, "Verification failed for offline fee settlement");

        // 3. Rotate the fee payer's wallet
        WalletOperations.rotateWalletWithCommitment(
            statement.walletNullifier,
            statement.merkleRoot,
            statement.newWalletCommitment,
            statement.updatedWalletPublicShares,
            nullifierSet,
            publicBlinderSet,
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
        whenNotPaused
    {
        // 1. Verify the proof
        bool res = verifier.verifyValidFeeRedemption(statement, proof);
        require(res, "Verification failed for fee redemption");

        // 2. Rotate the wallet
        BN254.ScalarField newCommitment = statement.newSharesCommitment;
        WalletOperations.rotateWalletWithCommitment(
            statement.walletNullifier,
            statement.walletRoot,
            newCommitment,
            statement.newWalletPublicShares,
            nullifierSet,
            publicBlinderSet,
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

    // --- Helper Functions --- //

    /// @notice Helper function to forward revert reasons from delegatecalls
    /// @param success Whether the delegatecall was successful
    /// @param returnData The data returned from the delegatecall
    function _handleDelegateCallResult(bool success, bytes memory returnData) private pure {
        if (!success) {
            // Forward the revert reason
            assembly {
                let returnDataSize := mload(returnData)
                revert(add(32, returnData), returnDataSize)
            }
        }
    }
}
