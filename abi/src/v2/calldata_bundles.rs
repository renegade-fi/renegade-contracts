//! Calldata bundle implementations for the V2 ABI
use alloy::sol_types::SolValue;

use super::IDarkpoolV2::*;
use super::*;

/// The public obligation bundle type
pub const PUBLIC_OBLIGATION_BUNDLE_TYPE: u8 = 0;
/// The private obligation bundle type
pub const PRIVATE_OBLIGATION_BUNDLE_TYPE: u8 = 1;

/// The type of the bundle for a natively-settled private intent
pub const NATIVE_SETTLED_PRIVATE_INTENT_BUNDLE_TYPE: u8 = 1;

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
}

impl SettlementBundle {
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
}
