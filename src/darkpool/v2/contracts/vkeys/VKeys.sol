// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { VerificationKey, ProofLinkingVK } from "renegade-lib/verifier/Types.sol";
import { IVkeys } from "darkpoolv2-interfaces/IVkeys.sol";
import { WalletUpdateVKeys } from "./WalletUpdateVKeys.sol";
import { SettlementVKeys } from "./SettlementVKeys.sol";
import { ProofLinkingVKeys } from "./ProofLinkingVKeys.sol";

/// @title VKeys
/// @author Renegade Eng
/// @notice Implementation of the verification keys in the darkpool v2
/// @dev Deploys sub-contracts in constructor to stay under contract size limits
contract VKeys is IVkeys {
    /// @notice Sub-contract containing wallet update verification keys
    WalletUpdateVKeys public immutable WALLET_UPDATE_VKEYS;
    /// @notice Sub-contract containing settlement verification keys
    SettlementVKeys public immutable SETTLEMENT_VKEYS;
    /// @notice Sub-contract containing proof linking verification keys (placeholder)
    ProofLinkingVKeys public immutable PROOF_LINKING_VKEYS;

    constructor() {
        WALLET_UPDATE_VKEYS = new WalletUpdateVKeys();
        SETTLEMENT_VKEYS = new SettlementVKeys();
        PROOF_LINKING_VKEYS = new ProofLinkingVKeys();
    }

    // ----------------------
    // | Wallet Update Keys |
    // ----------------------

    /// @notice Get the verification key for `VALID BALANCE CREATE`
    /// @return The verification key for `VALID BALANCE CREATE`
    function balanceCreateKeys() external view override returns (VerificationKey memory) {
        return WALLET_UPDATE_VKEYS.balanceCreateKeys();
    }

    /// @notice Get the verification key for `VALID DEPOSIT`
    /// @return The verification key for `VALID DEPOSIT`
    function depositKeys() external view override returns (VerificationKey memory) {
        return WALLET_UPDATE_VKEYS.depositKeys();
    }

    /// @notice Get the verification key for `VALID WITHDRAWAL`
    /// @return The verification key for `VALID WITHDRAWAL`
    function withdrawalKeys() external view override returns (VerificationKey memory) {
        return WALLET_UPDATE_VKEYS.withdrawalKeys();
    }

    /// @notice Get the verification key for `VALID ORDER CANCELLATION`
    /// @return The verification key for `VALID ORDER CANCELLATION`
    function orderCancellationKeys() external view override returns (VerificationKey memory) {
        return WALLET_UPDATE_VKEYS.orderCancellationKeys();
    }

    /// @notice Get the verification key for `VALID NOTE REDEMPTION`
    /// @return The verification key for `VALID NOTE REDEMPTION`
    function noteRedemptionKeys() external view override returns (VerificationKey memory) {
        return WALLET_UPDATE_VKEYS.noteRedemptionKeys();
    }

    /// @notice Get the verification key for `VALID PRIVATE PROTOCOL FEE PAYMENT`
    /// @return The verification key for `VALID PRIVATE PROTOCOL FEE PAYMENT`
    function privateProtocolFeePaymentKeys() external view override returns (VerificationKey memory) {
        return WALLET_UPDATE_VKEYS.privateProtocolFeePaymentKeys();
    }

    /// @notice Get the verification key for `VALID PRIVATE RELAYER FEE PAYMENT`
    /// @return The verification key for `VALID PRIVATE RELAYER FEE PAYMENT`
    function privateRelayerFeePaymentKeys() external view override returns (VerificationKey memory) {
        return WALLET_UPDATE_VKEYS.privateRelayerFeePaymentKeys();
    }

    /// @notice Get the verification key for `VALID PUBLIC PROTOCOL FEE PAYMENT`
    /// @return The verification key for `VALID PUBLIC PROTOCOL FEE PAYMENT`
    function publicProtocolFeePaymentKeys() external view override returns (VerificationKey memory) {
        return WALLET_UPDATE_VKEYS.publicProtocolFeePaymentKeys();
    }

    /// @notice Get the verification key for `VALID PUBLIC RELAYER FEE PAYMENT`
    /// @return The verification key for `VALID PUBLIC RELAYER FEE PAYMENT`
    function publicRelayerFeePaymentKeys() external view override returns (VerificationKey memory) {
        return WALLET_UPDATE_VKEYS.publicRelayerFeePaymentKeys();
    }

    // -------------------
    // | Settlement Keys |
    // -------------------

    /// @notice Get the verification key for `INTENT ONLY FIRST FILL VALIDITY`
    /// @return The verification key for `INTENT ONLY FIRST FILL VALIDITY`
    function intentOnlyFirstFillValidityKeys() external view override returns (VerificationKey memory) {
        return SETTLEMENT_VKEYS.intentOnlyFirstFillValidityKeys();
    }

    /// @notice Get the verification key for `INTENT ONLY VALIDITY`
    /// @return The verification key for `INTENT ONLY VALIDITY`
    function intentOnlyValidityKeys() external view override returns (VerificationKey memory) {
        return SETTLEMENT_VKEYS.intentOnlyValidityKeys();
    }

    /// @notice Get the verification key for `INTENT AND BALANCE FIRST FILL VALIDITY`
    /// @return The verification key for `INTENT AND BALANCE FIRST FILL VALIDITY`
    function intentAndBalanceFirstFillValidityKeys() external view override returns (VerificationKey memory) {
        return SETTLEMENT_VKEYS.intentAndBalanceFirstFillValidityKeys();
    }

    /// @notice Get the verification key for `INTENT AND BALANCE VALIDITY`
    /// @return The verification key for `INTENT AND BALANCE VALIDITY`
    function intentAndBalanceValidityKeys() external view override returns (VerificationKey memory) {
        return SETTLEMENT_VKEYS.intentAndBalanceValidityKeys();
    }

    /// @notice Get the verification key for `INTENT ONLY PUBLIC SETTLEMENT`
    /// @return The verification key for `INTENT ONLY PUBLIC SETTLEMENT`
    function intentOnlyPublicSettlementKeys() external view override returns (VerificationKey memory) {
        return SETTLEMENT_VKEYS.intentOnlyPublicSettlementKeys();
    }

    /// @notice Get the verification key for `INTENT ONLY BOUNDED SETTLEMENT`
    /// @return The verification key for `INTENT ONLY BOUNDED SETTLEMENT`
    function intentOnlyBoundedSettlementKeys() external view override returns (VerificationKey memory) {
        return SETTLEMENT_VKEYS.intentOnlyBoundedSettlementKeys();
    }

    /// @notice Get the verification key for `INTENT AND BALANCE PUBLIC SETTLEMENT`
    /// @return The verification key for `INTENT AND BALANCE PUBLIC SETTLEMENT`
    function intentAndBalancePublicSettlementKeys() external view override returns (VerificationKey memory) {
        return SETTLEMENT_VKEYS.intentAndBalancePublicSettlementKeys();
    }

    /// @notice Get the verification key for `INTENT AND BALANCE PRIVATE SETTLEMENT`
    /// @return The verification key for `INTENT AND BALANCE PRIVATE SETTLEMENT`
    function intentAndBalancePrivateSettlementKeys() external view override returns (VerificationKey memory) {
        return SETTLEMENT_VKEYS.intentAndBalancePrivateSettlementKeys();
    }

    /// @notice Get the verification key for `INTENT AND BALANCE BOUNDED SETTLEMENT`
    /// @return The verification key for `INTENT AND BALANCE BOUNDED SETTLEMENT`
    function intentAndBalanceBoundedSettlementKeys() external view override returns (VerificationKey memory) {
        return SETTLEMENT_VKEYS.intentAndBalanceBoundedSettlementKeys();
    }

    /// @notice Get the verification key for `OUTPUT BALANCE VALIDITY`
    /// @return The verification key for `OUTPUT BALANCE VALIDITY`
    function outputBalanceValidityKeys() external view override returns (VerificationKey memory) {
        return SETTLEMENT_VKEYS.outputBalanceValidityKeys();
    }

    /// @notice Get the verification key for `NEW OUTPUT BALANCE VALIDITY`
    /// @return The verification key for `NEW OUTPUT BALANCE VALIDITY`
    function newOutputBalanceValidityKeys() external view override returns (VerificationKey memory) {
        return SETTLEMENT_VKEYS.newOutputBalanceValidityKeys();
    }

    // -----------------------
    // | Proof Linking Keys |
    // -----------------------

    /// @notice Get the verification key for `INTENT ONLY SETTLEMENT`
    /// @return The verification key for `INTENT ONLY SETTLEMENT`
    function intentOnlySettlementLinkingKey() external view override returns (ProofLinkingVK memory) {
        return PROOF_LINKING_VKEYS.intentOnlySettlementLinkingKey();
    }

    /// @notice Get the verification key for `INTENT AND BALANCE SETTLEMENT 0`
    /// @return The verification key for `INTENT AND BALANCE SETTLEMENT 0`
    function intentAndBalanceSettlement0LinkingKey() external view override returns (ProofLinkingVK memory) {
        return PROOF_LINKING_VKEYS.intentAndBalanceSettlement0LinkingKey();
    }

    /// @notice Get the verification key for `INTENT AND BALANCE SETTLEMENT 1`
    /// @return The verification key for `INTENT AND BALANCE SETTLEMENT 1`
    function intentAndBalanceSettlement1LinkingKey() external view override returns (ProofLinkingVK memory) {
        return PROOF_LINKING_VKEYS.intentAndBalanceSettlement1LinkingKey();
    }

    /// @notice Get the verification key for `OUTPUT BALANCE SETTLEMENT 0`
    /// @return The verification key for `OUTPUT BALANCE SETTLEMENT 0`
    function outputBalanceSettlement0LinkingKey() external view override returns (ProofLinkingVK memory) {
        return PROOF_LINKING_VKEYS.outputBalanceSettlement0LinkingKey();
    }

    /// @notice Get the verification key for `OUTPUT BALANCE SETTLEMENT 1`
    /// @return The verification key for `OUTPUT BALANCE SETTLEMENT 1`
    function outputBalanceSettlement1LinkingKey() external view override returns (ProofLinkingVK memory) {
        return PROOF_LINKING_VKEYS.outputBalanceSettlement1LinkingKey();
    }
}
