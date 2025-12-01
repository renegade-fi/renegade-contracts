//! Code for generating verification keys for the Renegade circuits (v2)

use renegade_circuit_types_v2::traits::SingleProverCircuit;
use renegade_circuits_v2::zk_circuits::fees::valid_note_redemption::SizedValidNoteRedemption;
use renegade_circuits_v2::zk_circuits::fees::valid_private_protocol_fee_payment::SizedValidPrivateProtocolFeePayment;
use renegade_circuits_v2::zk_circuits::fees::valid_private_relayer_fee_payment::SizedValidPrivateRelayerFeePayment;
use renegade_circuits_v2::zk_circuits::fees::valid_public_protocol_fee_payment::SizedValidPublicProtocolFeePayment;
use renegade_circuits_v2::zk_circuits::fees::valid_public_relayer_fee_payment::SizedValidPublicRelayerFeePayment;
use renegade_circuits_v2::zk_circuits::settlement::{
    intent_and_balance_private_settlement::IntentAndBalancePrivateSettlementCircuit,
    intent_and_balance_public_settlement::IntentAndBalancePublicSettlementCircuit,
    intent_only_public_settlement::SizedIntentOnlyPublicSettlementCircuit,
};
use renegade_circuits_v2::zk_circuits::valid_order_cancellation::SizedValidOrderCancellationCircuit;
use renegade_circuits_v2::zk_circuits::valid_withdrawal::SizedValidWithdrawal;
use renegade_circuits_v2::zk_circuits::validity_proofs::{
    intent_and_balance::SizedIntentAndBalanceValidityCircuit,
    intent_and_balance_first_fill::SizedIntentAndBalanceFirstFillValidityCircuit,
    intent_only::IntentOnlyValidityCircuit,
    intent_only_first_fill::IntentOnlyFirstFillValidityCircuit,
};
use renegade_circuits_v2::zk_circuits::{
    valid_balance_create::ValidBalanceCreate, valid_deposit::SizedValidDeposit,
};
use renegade_constants_v2::MERKLE_HEIGHT;
use std::fmt::{self, Display};

use crate::{NamedLinkingVkey, NamedVkey};
use reference_impl_common::abi_types::{ProofLinkingVK, VerificationKey};

/// The circuit to generate a verification key for
#[derive(Debug, Clone, Copy)]
#[allow(clippy::enum_variant_names)]
enum V2Circuit {
    // --- State Updates --- //
    ValidBalanceCreate,
    ValidDeposit,
    ValidWithdrawal,
    ValidOrderCancellation,
    // --- Fee Payments --- //
    ValidPrivateProtocolFeePayment,
    ValidPrivateRelayerFeePayment,
    ValidPublicProtocolFeePayment,
    ValidPublicRelayerFeePayment,
    ValidNoteRedemption,
    // --- Validity Proofs ---//
    IntentOnlyFirstFillValidity,
    IntentOnlyValidity,
    IntentAndBalanceFirstFillValidity,
    IntentAndBalanceValidity,
    // --- Settlement Circuits --- //
    IntentOnlyPublicSettlement,
    IntentAndBalancePublicSettlement,
    IntentAndBalancePrivateSettlement,
}

impl Display for V2Circuit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl V2Circuit {
    /// Generate the verification key for the circuit
    pub fn vkey(&self) -> VerificationKey {
        match self {
            Self::ValidBalanceCreate => generate_vkey_for_circuit::<ValidBalanceCreate>(),
            Self::ValidDeposit => generate_vkey_for_circuit::<SizedValidDeposit>(),
            Self::ValidWithdrawal => generate_vkey_for_circuit::<SizedValidWithdrawal>(),
            Self::ValidOrderCancellation => {
                generate_vkey_for_circuit::<SizedValidOrderCancellationCircuit>()
            }
            Self::ValidNoteRedemption => generate_vkey_for_circuit::<SizedValidNoteRedemption>(),
            Self::ValidPrivateProtocolFeePayment => {
                generate_vkey_for_circuit::<SizedValidPrivateProtocolFeePayment>()
            }
            Self::ValidPrivateRelayerFeePayment => {
                generate_vkey_for_circuit::<SizedValidPrivateRelayerFeePayment>()
            }
            Self::ValidPublicProtocolFeePayment => {
                generate_vkey_for_circuit::<SizedValidPublicProtocolFeePayment>()
            }
            Self::ValidPublicRelayerFeePayment => {
                generate_vkey_for_circuit::<SizedValidPublicRelayerFeePayment>()
            }
            Self::IntentOnlyFirstFillValidity => {
                generate_vkey_for_circuit::<IntentOnlyFirstFillValidityCircuit>()
            }
            Self::IntentOnlyValidity => {
                generate_vkey_for_circuit::<IntentOnlyValidityCircuit<MERKLE_HEIGHT>>()
            }
            Self::IntentAndBalanceFirstFillValidity => {
                generate_vkey_for_circuit::<SizedIntentAndBalanceFirstFillValidityCircuit>()
            }
            Self::IntentAndBalanceValidity => {
                generate_vkey_for_circuit::<SizedIntentAndBalanceValidityCircuit>()
            }
            Self::IntentOnlyPublicSettlement => {
                generate_vkey_for_circuit::<SizedIntentOnlyPublicSettlementCircuit>()
            }
            Self::IntentAndBalancePublicSettlement => {
                generate_vkey_for_circuit::<IntentAndBalancePublicSettlementCircuit>()
            }
            Self::IntentAndBalancePrivateSettlement => {
                generate_vkey_for_circuit::<IntentAndBalancePrivateSettlementCircuit>()
            }
        }
    }

    /// Get the name of the circuit for the purpose of generating a Solidity constant
    pub fn name(&self) -> &'static str {
        match self {
            Self::ValidBalanceCreate => "VALID_BALANCE_CREATE",
            Self::ValidDeposit => "VALID_DEPOSIT",
            Self::ValidWithdrawal => "VALID_WITHDRAWAL",
            Self::ValidOrderCancellation => "VALID_ORDER_CANCELLATION",
            Self::ValidNoteRedemption => "VALID_NOTE_REDEMPTION",
            Self::ValidPrivateProtocolFeePayment => "VALID_PRIVATE_PROTOCOL_FEE_PAYMENT",
            Self::ValidPrivateRelayerFeePayment => "VALID_PRIVATE_RELAYER_FEE_PAYMENT",
            Self::ValidPublicProtocolFeePayment => "VALID_PUBLIC_PROTOCOL_FEE_PAYMENT",
            Self::ValidPublicRelayerFeePayment => "VALID_PUBLIC_RELAYER_FEE_PAYMENT",
            Self::IntentOnlyFirstFillValidity => "INTENT_ONLY_FIRST_FILL_VALIDITY",
            Self::IntentOnlyValidity => "INTENT_ONLY_VALIDITY",
            Self::IntentAndBalanceFirstFillValidity => "INTENT_AND_BALANCE_FIRST_FILL_VALIDITY",
            Self::IntentAndBalanceValidity => "INTENT_AND_BALANCE_VALIDITY",
            Self::IntentOnlyPublicSettlement => "INTENT_ONLY_PUBLIC_SETTLEMENT",
            Self::IntentAndBalancePublicSettlement => "INTENT_AND_BALANCE_PUBLIC_SETTLEMENT",
            Self::IntentAndBalancePrivateSettlement => "INTENT_AND_BALANCE_PRIVATE_SETTLEMENT",
        }
    }

    /// Get all circuits
    pub fn all() -> Vec<Self> {
        vec![
            Self::ValidBalanceCreate,
            Self::ValidDeposit,
            Self::ValidWithdrawal,
            Self::ValidOrderCancellation,
            Self::ValidNoteRedemption,
            Self::ValidPrivateProtocolFeePayment,
            Self::ValidPrivateRelayerFeePayment,
            Self::ValidPublicProtocolFeePayment,
            Self::ValidPublicRelayerFeePayment,
            Self::IntentOnlyFirstFillValidity,
            Self::IntentOnlyValidity,
            Self::IntentAndBalanceFirstFillValidity,
            Self::IntentAndBalanceValidity,
            Self::IntentOnlyPublicSettlement,
            Self::IntentAndBalancePublicSettlement,
            Self::IntentAndBalancePrivateSettlement,
        ]
    }
}

/// Represents all the linking instances in the Renegade circuits
#[derive(Debug, Clone, Copy)]
pub enum V2LinkingInstance {
    // TODO: Add v2 linking instance variants
}

impl V2LinkingInstance {
    /// Generate a verification key for the linking instance
    pub fn vkey(&self) -> ProofLinkingVK {
        match self {
            // TODO: Implement vkey generation for v2 linking instances
            _ => todo!("Add linking instances"),
        }
    }

    /// Get the name of the linking instance
    pub fn name(&self) -> &'static str {
        match self {
            // TODO: Implement name for v2 linking instances
            _ => todo!("Add linking instance names"),
        }
    }

    /// Get all linking instances
    pub fn all() -> Vec<Self> {
        vec![
            // TODO: Fill in v2 linking instances
        ]
    }
}

// --- Helpers --- //

/// Generate all verification keys and linking instances for v2
pub fn gen_all_vkeys() -> (Vec<NamedVkey>, Vec<NamedLinkingVkey>) {
    let circuits: Vec<NamedVkey> = V2Circuit::all()
        .into_iter()
        .map(|circuit| NamedVkey {
            name: circuit.name().to_string(),
            vkey: circuit.vkey(),
        })
        .collect();

    let linking_instances: Vec<NamedLinkingVkey> = V2LinkingInstance::all()
        .into_iter()
        .map(|instance| NamedLinkingVkey {
            name: instance.name().to_string(),
            vkey: instance.vkey(),
        })
        .collect();

    (circuits, linking_instances)
}

// --- Helpers --- //

/// Generate the verification keys for all circuits
///
/// Returns a map from the circuit name to the verification key
fn generate_vkey_for_circuit<T: SingleProverCircuit>() -> VerificationKey {
    let vk = T::verifying_key();
    let vkey = VerificationKey::from(vk.as_ref().clone());
    vkey
}
