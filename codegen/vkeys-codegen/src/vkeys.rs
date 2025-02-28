//! Code for generating verification keys for the Renegade circuits

use std::fmt::{self, Display};

use reference_impl_common::abi_types::VerificationKey;
use renegade_circuit_types::traits::SingleProverCircuit;
use renegade_circuits::zk_circuits::{
    valid_commitments::SizedValidCommitments, valid_fee_redemption::SizedValidFeeRedemption,
    valid_malleable_match_settle_atomic::SizedValidMalleableMatchSettleAtomic,
    valid_match_settle::SizedValidMatchSettle,
    valid_match_settle_atomic::SizedValidMatchSettleAtomic,
    valid_offline_fee_settlement::SizedValidOfflineFeeSettlement, valid_reblind::SizedValidReblind,
    valid_wallet_create::SizedValidWalletCreate, valid_wallet_update::SizedValidWalletUpdate,
};

/// The circuit to generate a verification key for
#[derive(Debug, Clone, Copy)]
#[allow(clippy::enum_variant_names)]
pub(super) enum Circuit {
    /// The `VALID WALLET CREATE` circuit
    ValidWalletCreate,
    /// The `VALID WALLET UPDATE` circuit
    ValidWalletUpdate,
    /// The `VALID REBLIND` circuit
    ValidReblind,
    /// The `VALID COMMITMENTS` circuit
    ValidCommitments,
    /// The `VALID MATCH SETTLE` circuit
    ValidMatchSettle,
    /// The `VALID MATCH SETTLE ATOMIC` circuit
    ValidMatchSettleAtomic,
    /// The `VALID MALLEABLE MATCH SETTLE ATOMIC` circuit
    ValidMalleableMatchSettleAtomic,
    /// The `VALID OFFLINE FEE SETTLEMENT` circuit
    ValidOfflineFeeSettlement,
    /// The `VALID FEE REDEMPTION` circuit
    ValidFeeRedemption,
}
impl Display for Circuit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl Circuit {
    /// Generate the verification key for the circuit
    ///
    /// `SingleProverCircuit` cannot be a trait object, so we must handle each
    /// circuit explicitly
    pub fn vkey(&self) -> VerificationKey {
        match self {
            Self::ValidWalletCreate => generate_vkey_for_circuit::<SizedValidWalletCreate>(),
            Self::ValidWalletUpdate => generate_vkey_for_circuit::<SizedValidWalletUpdate>(),
            Self::ValidReblind => generate_vkey_for_circuit::<SizedValidReblind>(),
            Self::ValidCommitments => generate_vkey_for_circuit::<SizedValidCommitments>(),
            Self::ValidMatchSettle => generate_vkey_for_circuit::<SizedValidMatchSettle>(),
            Self::ValidMatchSettleAtomic => {
                generate_vkey_for_circuit::<SizedValidMatchSettleAtomic>()
            }
            Self::ValidMalleableMatchSettleAtomic => {
                generate_vkey_for_circuit::<SizedValidMalleableMatchSettleAtomic>()
            }
            Self::ValidOfflineFeeSettlement => {
                generate_vkey_for_circuit::<SizedValidOfflineFeeSettlement>()
            }
            Self::ValidFeeRedemption => generate_vkey_for_circuit::<SizedValidFeeRedemption>(),
        }
    }

    /// Get the name of the circuit for the purpose of generating a Solidity constant
    pub fn name(&self) -> &'static str {
        match self {
            Self::ValidWalletCreate => "VALID_WALLET_CREATE",
            Self::ValidWalletUpdate => "VALID_WALLET_UPDATE",
            Self::ValidReblind => "VALID_REBLIND",
            Self::ValidCommitments => "VALID_COMMITMENTS",
            Self::ValidMatchSettle => "VALID_MATCH_SETTLE",
            Self::ValidMatchSettleAtomic => "VALID_MATCH_SETTLE_ATOMIC",
            Self::ValidMalleableMatchSettleAtomic => "VALID_MALLEABLE_MATCH_SETTLE_ATOMIC",
            Self::ValidOfflineFeeSettlement => "VALID_OFFLINE_FEE_SETTLEMENT",
            Self::ValidFeeRedemption => "VALID_FEE_REDEMPTION",
        }
    }

    /// Get all circuits
    pub fn all() -> Vec<Self> {
        vec![
            Self::ValidWalletCreate,
            Self::ValidWalletUpdate,
            Self::ValidReblind,
            Self::ValidCommitments,
            Self::ValidMatchSettle,
            Self::ValidMatchSettleAtomic,
            Self::ValidMalleableMatchSettleAtomic,
            Self::ValidOfflineFeeSettlement,
            Self::ValidFeeRedemption,
        ]
    }
}

/// Generate the verification keys for all circuits
///
/// Returns a map from the circuit name to the verification key
fn generate_vkey_for_circuit<T: SingleProverCircuit>() -> VerificationKey {
    let vk = T::verifying_key();
    let vkey = VerificationKey::from(vk.as_ref().clone());
    vkey
}
