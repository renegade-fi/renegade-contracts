//! Calldata bundle implementations for the V2 ABI
use alloy::primitives::{Address, U256};
use alloy::sol_types::SolValue;

use super::IDarkpoolV2::*;

/// The public obligation bundle type
pub const PUBLIC_OBLIGATION_BUNDLE_TYPE: u8 = 0;
/// The private obligation bundle type
pub const PRIVATE_OBLIGATION_BUNDLE_TYPE: u8 = 1;

/// The bundle type for a natively-settled public intent
pub const NATIVE_SETTLED_PUBLIC_INTENT_BUNDLE_TYPE: u8 = 0;
/// The bundle type for a natively-settled private intent
pub const NATIVE_SETTLED_PRIVATE_INTENT_BUNDLE_TYPE: u8 = 1;
/// The bundle type for a natively-settled renegade private intent
pub const NATIVE_SETTLED_RENEGADE_PRIVATE_INTENT_BUNDLE_TYPE: u8 = 2;
/// The bundle type for a Renegade settled private fill
pub const RENEGADE_SETTLED_PRIVATE_FILL_BUNDLE_TYPE: u8 = 3;

/// The type of the bundle for an existing output balance
pub const EXISTING_OUTPUT_BALANCE_BUNDLE_TYPE: u8 = 0;
/// The type of the bundle for a new output balance
pub const NEW_OUTPUT_BALANCE_BUNDLE_TYPE: u8 = 1;

impl ObligationBundle {
    /// Create a new public obligation bundle
    pub fn new_public(
        obligation0: SettlementObligation,
        obligation1: SettlementObligation,
    ) -> Self {
        let data = (obligation0, obligation1).abi_encode();
        Self {
            obligationType: PUBLIC_OBLIGATION_BUNDLE_TYPE,
            data: data.into(),
        }
    }

    /// Create a new private obligation bundle
    pub fn new_private(
        statement: IntentAndBalancePrivateSettlementStatement,
        proof: PlonkProof,
    ) -> Self {
        let inner = PrivateObligationBundle { statement, proof };
        let data = inner.abi_encode();

        Self {
            obligationType: PRIVATE_OBLIGATION_BUNDLE_TYPE,
            data: data.into(),
        }
    }
}

impl SettlementBundle {
    /// Build a public intent settlement bundle
    pub fn public_intent_settlement(
        auth: PublicIntentAuthBundle,
        relayer_fee_rate: FeeRate,
    ) -> Self {
        let inner = PublicIntentPublicBalanceBundle {
            auth,
            relayerFeeRate: relayer_fee_rate,
        };
        let data = inner.abi_encode();

        Self {
            isFirstFill: false,
            bundleType: NATIVE_SETTLED_PUBLIC_INTENT_BUNDLE_TYPE,
            data: data.into(),
        }
    }

    /// Build a private intent, public balance settlement bundle for a first fill
    pub fn private_intent_public_balance_first_fill(
        auth: PrivateIntentAuthBundleFirstFill,
        settlement_statement: IntentOnlyPublicSettlementStatement,
        settlement_proof: PlonkProof,
        linking_proof: LinkingProof,
    ) -> Self {
        let inner = PrivateIntentPublicBalanceFirstFillBundle {
            auth,
            settlementStatement: settlement_statement,
            settlementProof: settlement_proof,
            authSettlementLinkingProof: linking_proof,
        };
        let data = inner.abi_encode();

        Self {
            isFirstFill: true,
            bundleType: NATIVE_SETTLED_PRIVATE_INTENT_BUNDLE_TYPE,
            data: data.into(),
        }
    }

    /// Build a private intent, public balance settlement bundle for a bounded first fill
    pub fn private_intent_public_balance_bounded_first_fill(
        auth: PrivateIntentAuthBundleFirstFill,
        settlement_statement: IntentOnlyBoundedSettlementStatement,
        settlement_proof: PlonkProof,
        linking_proof: LinkingProof,
    ) -> Self {
        let inner = PrivateIntentPublicBalanceBoundedFirstFillBundle {
            auth,
            settlementStatement: settlement_statement,
            settlementProof: settlement_proof,
            authSettlementLinkingProof: linking_proof,
        };
        let data = inner.abi_encode();

        Self {
            isFirstFill: true,
            bundleType: NATIVE_SETTLED_PRIVATE_INTENT_BUNDLE_TYPE,
            data: data.into(),
        }
    }

    /// Build a private intent, public balance settlement bundle for a bounded subsequent fill
    pub fn private_intent_public_balance_bounded(
        auth: PrivateIntentAuthBundle,
        settlement_statement: IntentOnlyBoundedSettlementStatement,
        settlement_proof: PlonkProof,
        linking_proof: LinkingProof,
    ) -> Self {
        let inner = PrivateIntentPublicBalanceBoundedBundle {
            auth,
            settlementStatement: settlement_statement,
            settlementProof: settlement_proof,
            authSettlementLinkingProof: linking_proof,
        };
        let data = inner.abi_encode();

        Self {
            isFirstFill: false,
            bundleType: NATIVE_SETTLED_PRIVATE_INTENT_BUNDLE_TYPE,
            data: data.into(),
        }
    }

    /// Build a private intent, public balance settlement bundle for a subsequent fill
    pub fn private_intent_public_balance(
        auth: PrivateIntentAuthBundle,
        settlement_statement: IntentOnlyPublicSettlementStatement,
        settlement_proof: PlonkProof,
        linking_proof: LinkingProof,
    ) -> Self {
        let inner = PrivateIntentPublicBalanceBundle {
            auth,
            settlementStatement: settlement_statement,
            settlementProof: settlement_proof,
            authSettlementLinkingProof: linking_proof,
        };
        let data = inner.abi_encode();

        Self {
            isFirstFill: false,
            bundleType: NATIVE_SETTLED_PRIVATE_INTENT_BUNDLE_TYPE,
            data: data.into(),
        }
    }

    /// Build a renegade settled private intent first fill bundle
    pub fn renegade_settled_private_intent_first_fill(
        auth: RenegadeSettledIntentAuthBundleFirstFill,
        output_balance_bundle: OutputBalanceBundle,
        settlement_statement: IntentAndBalancePublicSettlementStatement,
        settlement_proof: PlonkProof,
        linking_proof: LinkingProof,
    ) -> Self {
        let inner = RenegadeSettledIntentFirstFillBundle {
            auth,
            outputBalanceBundle: output_balance_bundle,
            settlementStatement: settlement_statement,
            settlementProof: settlement_proof,
            authSettlementLinkingProof: linking_proof,
        };
        let data = inner.abi_encode();

        Self {
            isFirstFill: true,
            bundleType: NATIVE_SETTLED_RENEGADE_PRIVATE_INTENT_BUNDLE_TYPE,
            data: data.into(),
        }
    }

    /// Build a renegade settled private intent subsequent fill bundle
    pub fn renegade_settled_private_intent(
        auth: RenegadeSettledIntentAuthBundle,
        output_balance_bundle: OutputBalanceBundle,
        settlement_statement: IntentAndBalancePublicSettlementStatement,
        settlement_proof: PlonkProof,
        linking_proof: LinkingProof,
    ) -> Self {
        let inner = RenegadeSettledIntentBundle {
            auth,
            outputBalanceBundle: output_balance_bundle,
            settlementStatement: settlement_statement,
            settlementProof: settlement_proof,
            authSettlementLinkingProof: linking_proof,
        };
        let data = inner.abi_encode();

        Self {
            isFirstFill: false,
            bundleType: NATIVE_SETTLED_RENEGADE_PRIVATE_INTENT_BUNDLE_TYPE,
            data: data.into(),
        }
    }

    /// Build a Renegade settled private fill bundle for a first fill
    pub fn renegade_settled_private_first_fill(
        auth: RenegadeSettledIntentAuthBundleFirstFill,
        output_balance_bundle: OutputBalanceBundle,
        linking_proof: LinkingProof,
    ) -> Self {
        let inner = RenegadeSettledPrivateFirstFillBundle {
            auth,
            outputBalanceBundle: output_balance_bundle,
            authSettlementLinkingProof: linking_proof,
        };
        let data = inner.abi_encode();

        Self {
            isFirstFill: true,
            bundleType: RENEGADE_SETTLED_PRIVATE_FILL_BUNDLE_TYPE,
            data: data.into(),
        }
    }

    /// Build a Renegade settled private fill bundle for a subsequent fill
    pub fn renegade_settled_private_fill(
        auth: RenegadeSettledIntentAuthBundle,
        output_balance_bundle: OutputBalanceBundle,
        linking_proof: LinkingProof,
    ) -> Self {
        let inner = RenegadeSettledPrivateFillBundle {
            auth,
            outputBalanceBundle: output_balance_bundle,
            authSettlementLinkingProof: linking_proof,
        };
        let data = inner.abi_encode();

        Self {
            isFirstFill: false,
            bundleType: RENEGADE_SETTLED_PRIVATE_FILL_BUNDLE_TYPE,
            data: data.into(),
        }
    }

    /// Build a renegade settled private intent bounded first fill bundle
    pub fn renegade_settled_private_intent_bounded_first_fill(
        auth: RenegadeSettledIntentAuthBundleFirstFill,
        output_balance_bundle: OutputBalanceBundle,
        settlement_statement: IntentAndBalanceBoundedSettlementStatement,
        settlement_proof: PlonkProof,
        linking_proof: LinkingProof,
    ) -> Self {
        let inner = RenegadeSettledIntentBoundedFirstFillBundle {
            auth,
            outputBalanceBundle: output_balance_bundle,
            settlementStatement: settlement_statement,
            settlementProof: settlement_proof,
            authSettlementLinkingProof: linking_proof,
        };
        let data = inner.abi_encode();

        Self {
            isFirstFill: true,
            bundleType: NATIVE_SETTLED_RENEGADE_PRIVATE_INTENT_BUNDLE_TYPE,
            data: data.into(),
        }
    }

    /// Build a renegade settled private intent bounded subsequent fill bundle
    pub fn renegade_settled_private_intent_bounded(
        auth: RenegadeSettledIntentAuthBundle,
        output_balance_bundle: OutputBalanceBundle,
        settlement_statement: IntentAndBalanceBoundedSettlementStatement,
        settlement_proof: PlonkProof,
        linking_proof: LinkingProof,
    ) -> Self {
        let inner = RenegadeSettledIntentBoundedBundle {
            auth,
            outputBalanceBundle: output_balance_bundle,
            settlementStatement: settlement_statement,
            settlementProof: settlement_proof,
            authSettlementLinkingProof: linking_proof,
        };
        let data = inner.abi_encode();

        Self {
            isFirstFill: false,
            bundleType: NATIVE_SETTLED_RENEGADE_PRIVATE_INTENT_BUNDLE_TYPE,
            data: data.into(),
        }
    }
}

impl OutputBalanceBundle {
    /// Build a new output balance bundle
    pub fn new_output_balance(
        merkle_depth: U256,
        statement: NewOutputBalanceValidityStatement,
        proof: PlonkProof,
        linking_proof: LinkingProof,
    ) -> Self {
        let inner = NewBalanceBundle { statement };
        let data = inner.abi_encode();
        OutputBalanceBundle {
            merkleDepth: merkle_depth,
            bundleType: NEW_OUTPUT_BALANCE_BUNDLE_TYPE,
            data: data.into(),
            proof,
            settlementLinkingProof: linking_proof,
        }
    }

    /// Build an existing output balance bundle
    pub fn existing_output_balance(
        merkle_depth: U256,
        statement: OutputBalanceValidityStatement,
        proof: PlonkProof,
        linking_proof: LinkingProof,
    ) -> Self {
        let inner = ExistingBalanceBundle { statement };
        let data = inner.abi_encode();

        OutputBalanceBundle {
            merkleDepth: merkle_depth,
            bundleType: EXISTING_OUTPUT_BALANCE_BUNDLE_TYPE,
            data: data.into(),
            proof,
            settlementLinkingProof: linking_proof,
        }
    }
}

impl BoundedMatchResult {
    /// Build a bounded match result bundle
    pub fn new(
        internal_party_input_token: Address,
        internal_party_output_token: Address,
        price: FixedPoint,
        min_internal_party_amt_in: U256,
        max_internal_party_amt_in: U256,
        block_deadline: U256,
    ) -> Self {
        Self {
            internalPartyInputToken: internal_party_input_token,
            internalPartyOutputToken: internal_party_output_token,
            price: price,
            minInternalPartyAmountIn: min_internal_party_amt_in,
            maxInternalPartyAmountIn: max_internal_party_amt_in,
            blockDeadline: block_deadline,
        }
    }
}
