// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Initializable } from "oz-contracts/proxy/utils/Initializable.sol";
import { Ownable } from "oz-contracts/access/Ownable.sol";
import { Ownable2Step } from "oz-contracts/access/Ownable2Step.sol";
import { Pausable } from "oz-contracts/utils/Pausable.sol";
import { IPermit2 } from "permit2-lib/interfaces/IPermit2.sol";

import { IHasher } from "renegade-lib/interfaces/IHasher.sol";
import { IDarkpoolV2 } from "darkpoolv2-interfaces/IDarkpoolV2.sol";
import { IVerifier } from "darkpoolv2-interfaces/IVerifier.sol";
import { IVkeys } from "darkpoolv2-interfaces/IVkeys.sol";
import { IWETH9 } from "renegade-lib/interfaces/IWETH9.sol";

import { BN254 } from "solidity-bn254/BN254.sol";

import { MerkleMountainLib } from "renegade-lib/merkle/MerkleMountain.sol";
import { NullifierLib } from "renegade-lib/NullifierSet.sol";

import { EncryptionKey, BabyJubJubPoint } from "renegade-lib/Ciphertext.sol";
import { FixedPoint, FixedPointLib } from "renegade-lib/FixedPoint.sol";
import { DarkpoolConstants } from "darkpoolv2-lib/Constants.sol";

import { BoundedMatchResult } from "darkpoolv2-types/BoundedMatchResult.sol";
import { ObligationBundle } from "darkpoolv2-types/settlement/ObligationBundle.sol";
import { SettlementBundle } from "darkpoolv2-types/settlement/SettlementBundle.sol";
import {
    DepositProofBundle,
    NewBalanceDepositProofBundle,
    OrderCancellationProofBundle,
    WithdrawalProofBundle,
    PublicProtocolFeePaymentProofBundle,
    PublicRelayerFeePaymentProofBundle,
    PrivateProtocolFeePaymentProofBundle,
    PrivateRelayerFeePaymentProofBundle,
    NoteRedemptionProofBundle
} from "darkpoolv2-types/ProofBundles.sol";
import { DepositAuth } from "darkpoolv2-types/transfers/Deposit.sol";
import { WithdrawalAuth } from "darkpoolv2-types/transfers/Withdrawal.sol";
import { OrderCancellationAuth } from "darkpoolv2-types/OrderCancellation.sol";
import { SignatureWithNonce } from "darkpoolv2-types/settlement/SignatureWithNonce.sol";
import { PublicIntentPermit } from "darkpoolv2-types/settlement/IntentBundle.sol";
import { SettlementLib } from "darkpoolv2-lib/settlement/SettlementLib.sol";
import { ExternalSettlementLib } from "darkpoolv2-lib/settlement/ExternalSettlementLib.sol";
import { DarkpoolState, DarkpoolStateLib } from "darkpoolv2-lib/DarkpoolState.sol";
import { StateUpdatesLib } from "darkpoolv2-lib/StateUpdatesLib.sol";

/// @notice Contract references needed for darkpool operations
/// @dev Used for settlement, fee payments, and other operations requiring contract instances
struct DarkpoolContracts {
    IHasher hasher;
    IVerifier verifier;
    IWETH9 weth;
    IPermit2 permit2;
    IVkeys vkeys;
}

/// @title DarkpoolV2
/// @author Renegade Eng
/// @notice V2 of the Renegade darkpool contract for private trading
contract DarkpoolV2 is Initializable, Ownable2Step, Pausable, IDarkpoolV2 {
    using MerkleMountainLib for MerkleMountainLib.MerkleMountainRange;
    using NullifierLib for NullifierLib.NullifierSet;
    using DarkpoolStateLib for DarkpoolState;

    // -----------
    // | Storage |
    // -----------

    // --- Delegate Addresses --- //

    /// @notice The hasher for the darkpool
    IHasher public hasher;
    /// @notice The verification keys contract
    IVkeys public vkeys;
    /// @notice The verifier for the darkpool
    IVerifier public verifier;
    /// @notice The Permit2 contract instance for handling deposits
    IPermit2 public permit2;
    /// @notice The WETH9 contract instance used for depositing/withdrawing native tokens
    IWETH9 public weth;

    // --- Protocol Level State Storage --- //

    /// @notice Bundled core darkpool state
    /// @dev We bundle the state here to pass it as a single parameter to verification methods.
    /// @dev Contains: openPublicIntents mapping, spentNonces mapping, perPairFeeOverrides mapping, merkleTree,
    /// nullifierSet, protocolFeeKey, protocolFeeRecipient, and defaultProtocolFeeRate
    DarkpoolState private _state;

    // ---------------------------------
    // | Constructors and Initializers |
    // ---------------------------------

    /// @notice Constructor that disables initializers for the implementation contract
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() Ownable(msg.sender) {
        _disableInitializers();
    }

    /// @inheritdoc IDarkpoolV2
    function initialize(
        address initialOwner,
        uint256 defaultProtocolFeeRateRepr,
        address protocolFeeRecipient_,
        EncryptionKey memory protocolFeeKey_,
        IWETH9 weth_,
        IHasher hasher_,
        IVkeys vkeys_,
        IVerifier verifier_,
        IPermit2 permit2_
    )
        public
        initializer
    {
        _transferOwnership(initialOwner);

        _state.defaultProtocolFeeRate = FixedPointLib.wrap(defaultProtocolFeeRateRepr);
        _state.protocolFeeRecipient = protocolFeeRecipient_;
        _state.protocolFeeKey = protocolFeeKey_;
        _state.merkleMountainRange.initialize(DarkpoolConstants.DEFAULT_MERKLE_DEPTH);
        hasher = hasher_;
        vkeys = vkeys_;
        verifier = verifier_;
        permit2 = permit2_;
        weth = weth_;
    }

    // -----------------
    // | State Getters |
    // -----------------

    /// @inheritdoc IDarkpoolV2
    function openPublicIntents(bytes32 intentHash) public view returns (uint256) {
        return _state.getOpenIntentAmountRemaining(intentHash);
    }

    /// @inheritdoc IDarkpoolV2
    function nullifierSpent(BN254.ScalarField nullifier) public view returns (bool) {
        return _state.nullifierSpent(nullifier);
    }

    /// @inheritdoc IDarkpoolV2
    function getMerkleRoot(uint256 depth) public view returns (BN254.ScalarField) {
        return _state.getMerkleRoot(depth);
    }

    /// @inheritdoc IDarkpoolV2
    function rootInHistory(BN254.ScalarField root) public view returns (bool) {
        return _state.rootInHistory(root);
    }

    /// @inheritdoc IDarkpoolV2
    function getProtocolFee(address asset0, address asset1) public view returns (FixedPoint memory) {
        return _state.getProtocolFeeRate(asset0, asset1).rate;
    }

    /// @inheritdoc IDarkpoolV2
    function getDefaultProtocolFee() public view returns (FixedPoint memory) {
        return _state.getDefaultProtocolFeeRate();
    }

    /// @inheritdoc IDarkpoolV2
    function getProtocolFeeRecipient() public view returns (address) {
        return _state.getProtocolFeeRecipient();
    }

    /// @notice Get the public encryption key for the protocol's fees
    /// @return The public encryption key for the protocol's fees
    function getProtocolFeeKey() public view returns (EncryptionKey memory) {
        return _state.getProtocolFeeKey();
    }

    /// @notice Check if a token is whitelisted
    /// @param token The token address to check
    /// @return Whether the token is whitelisted
    function isTokenWhitelisted(address token) public view returns (bool) {
        return _state.isTokenWhitelisted(token);
    }

    // -----------------
    // | State Updates |
    // -----------------

    // --- Order Cancellation --- //

    /// @inheritdoc IDarkpoolV2
    function cancelPrivateOrder(
        OrderCancellationAuth memory auth,
        OrderCancellationProofBundle calldata orderCancellationProofBundle
    )
        public
        whenNotPaused
    {
        StateUpdatesLib.cancelPrivateOrder(_state, verifier, auth, orderCancellationProofBundle);
    }

    /// @inheritdoc IDarkpoolV2
    function cancelPublicOrder(
        OrderCancellationAuth memory auth,
        PublicIntentPermit calldata permit,
        SignatureWithNonce calldata intentSignature
    )
        public
    {
        StateUpdatesLib.cancelPublicOrder(_state, auth, permit, intentSignature);
    }

    /// @inheritdoc IDarkpoolV2
    function revokeNonce(
        address owner,
        uint256 nonceToRevoke,
        SignatureWithNonce memory signature
    )
        public
        whenNotPaused
    {
        StateUpdatesLib.revokeNonce(_state, owner, nonceToRevoke, signature);
    }

    // --- Deposit --- //

    /// @inheritdoc IDarkpoolV2
    function deposit(DepositAuth calldata auth, DepositProofBundle calldata depositProofBundle) public whenNotPaused {
        StateUpdatesLib.deposit(_state, verifier, hasher, permit2, auth, depositProofBundle);
    }

    /// @inheritdoc IDarkpoolV2
    function depositNewBalance(
        DepositAuth calldata auth,
        NewBalanceDepositProofBundle calldata newBalanceProofBundle
    )
        public
        whenNotPaused
    {
        StateUpdatesLib.depositNewBalance(_state, verifier, hasher, permit2, auth, newBalanceProofBundle);
    }

    // --- Withdrawal --- //

    /// @inheritdoc IDarkpoolV2
    function withdraw(
        WithdrawalAuth calldata auth,
        WithdrawalProofBundle calldata withdrawalProofBundle
    )
        public
        whenNotPaused
    {
        StateUpdatesLib.withdraw(_state, verifier, hasher, auth, withdrawalProofBundle);
    }

    // --- Fees --- //

    /// @inheritdoc IDarkpoolV2
    function payPublicProtocolFee(PublicProtocolFeePaymentProofBundle calldata proofBundle) public whenNotPaused {
        DarkpoolContracts memory contracts = _getDarkpoolContracts();
        StateUpdatesLib.payPublicProtocolFee(proofBundle, contracts, _state);
    }

    /// @inheritdoc IDarkpoolV2
    function payPublicRelayerFee(PublicRelayerFeePaymentProofBundle calldata proofBundle) public whenNotPaused {
        DarkpoolContracts memory contracts = _getDarkpoolContracts();
        StateUpdatesLib.payPublicRelayerFee(proofBundle, contracts, _state);
    }

    /// @inheritdoc IDarkpoolV2
    function payPrivateProtocolFee(PrivateProtocolFeePaymentProofBundle calldata proofBundle) public whenNotPaused {
        DarkpoolContracts memory contracts = _getDarkpoolContracts();
        StateUpdatesLib.payPrivateProtocolFee(proofBundle, contracts, _state);
    }

    /// @inheritdoc IDarkpoolV2
    function payPrivateRelayerFee(PrivateRelayerFeePaymentProofBundle calldata proofBundle) public whenNotPaused {
        DarkpoolContracts memory contracts = _getDarkpoolContracts();
        StateUpdatesLib.payPrivateRelayerFee(proofBundle, contracts, _state);
    }

    /// @inheritdoc IDarkpoolV2
    function redeemNote(NoteRedemptionProofBundle calldata proofBundle) public whenNotPaused {
        DarkpoolContracts memory contracts = _getDarkpoolContracts();
        StateUpdatesLib.redeemNote(proofBundle, contracts, _state);
    }

    // --------------
    // | Settlement |
    // --------------

    /// @inheritdoc IDarkpoolV2
    function settleMatch(
        ObligationBundle calldata obligationBundle,
        SettlementBundle calldata party0SettlementBundle,
        SettlementBundle calldata party1SettlementBundle
    )
        public
        whenNotPaused
    {
        DarkpoolContracts memory contracts = _getDarkpoolContracts();
        SettlementLib.settleMatch(_state, contracts, obligationBundle, party0SettlementBundle, party1SettlementBundle);
    }

    /// @inheritdoc IDarkpoolV2
    function settleExternalMatch(
        uint256 externalPartyAmountIn,
        address recipient,
        BoundedMatchResult calldata matchResult,
        SettlementBundle calldata internalPartySettlementBundle
    )
        public
        whenNotPaused
        returns (uint256 receivedAmount)
    {
        DarkpoolContracts memory contracts = _getDarkpoolContracts();
        receivedAmount = ExternalSettlementLib.settleExternalMatch(
            _state, contracts, externalPartyAmountIn, recipient, matchResult, internalPartySettlementBundle
        );
    }

    // -----------------
    // | Admin Setters |
    // -----------------

    /// @notice Set the default protocol fee rate
    /// @param newFeeRateRepr The new fee rate as FixedPoint repr (must be non-zero)
    function setDefaultProtocolFeeRate(uint256 newFeeRateRepr) external onlyOwner {
        if (newFeeRateRepr == 0) revert IDarkpoolV2.FeeCannotBeZero();
        FixedPoint memory newFeeRate = FixedPointLib.wrap(newFeeRateRepr);
        _state.defaultProtocolFeeRate = newFeeRate;
        emit FeeChanged(newFeeRateRepr);
    }

    /// @notice Set per-pair fee override (or remove if feeRateRepr is 0)
    /// @dev Order of asset0/asset1 doesn't matter - keys are canonicalized
    /// @param asset0 The first asset in the trading pair
    /// @param asset1 The second asset in the trading pair
    /// @param feeRateRepr The fee rate repr (0 to remove override)
    function setExternalMatchFeeOverride(address asset0, address asset1, uint256 feeRateRepr) external onlyOwner {
        FixedPoint memory feeRate = FixedPointLib.wrap(feeRateRepr);
        _state.setPerPairFeeOverride(asset0, asset1, feeRate);
        emit ExternalMatchFeeChanged(asset0, asset1, feeRateRepr);
    }

    /// @notice Set the protocol fee recipient address
    /// @param newRecipient The new protocol fee recipient address
    function setProtocolFeeRecipient(address newRecipient) external onlyOwner {
        if (newRecipient == address(0)) revert IDarkpoolV2.AddressCannotBeZero();
        _state.protocolFeeRecipient = newRecipient;
        emit ExternalFeeCollectionAddressChanged(newRecipient);
    }

    /// @notice Set the protocol fee encryption key
    /// @param newPubkeyX The new X coordinate of the public key
    /// @param newPubkeyY The new Y coordinate of the public key
    function setProtocolFeeKey(uint256 newPubkeyX, uint256 newPubkeyY) external onlyOwner {
        _state.protocolFeeKey = EncryptionKey({
            point: BabyJubJubPoint({ x: BN254.ScalarField.wrap(newPubkeyX), y: BN254.ScalarField.wrap(newPubkeyY) })
        });
        emit PubkeyRotated(newPubkeyX, newPubkeyY);
    }

    /// @notice Set the verifier contract
    /// @param newVerifier The new verifier contract
    function setVerifier(IVerifier newVerifier) external onlyOwner {
        if (address(newVerifier) == address(0)) revert IDarkpoolV2.AddressCannotBeZero();
        verifier = newVerifier;
    }

    /// @notice Set the hasher contract
    /// @param newHasher The new hasher contract
    function setHasher(IHasher newHasher) external onlyOwner {
        if (address(newHasher) == address(0)) revert IDarkpoolV2.AddressCannotBeZero();
        hasher = newHasher;
    }

    /// @notice Set the whitelist status for a token
    /// @param token The token address to set whitelist status for
    /// @param whitelisted Whether the token should be whitelisted
    function setTokenWhitelist(address token, bool whitelisted) external onlyOwner {
        _state.setTokenWhitelist(token, whitelisted);
    }

    /// @notice Whitelist multiple tokens in a single transaction
    /// @param tokens The token addresses to whitelist
    function whitelistTokensBatch(address[] calldata tokens) external onlyOwner {
        for (uint256 i = 0; i < tokens.length; ++i) {
            _state.setTokenWhitelist(tokens[i], true);
        }
    }

    /// @notice Pause the darkpool
    function pause() external onlyOwner {
        _pause();
    }

    /// @notice Unpause the darkpool
    function unpause() external onlyOwner {
        _unpause();
    }

    // --------------------
    // | Helper Functions |
    // --------------------

    /// @notice Create a DarkpoolContracts struct from the contract's stored contract instances
    /// @return contracts The DarkpoolContracts struct containing all contract references
    function _getDarkpoolContracts() internal view returns (DarkpoolContracts memory contracts) {
        contracts =
            DarkpoolContracts({ hasher: hasher, verifier: verifier, weth: weth, permit2: permit2, vkeys: vkeys });
    }
}
