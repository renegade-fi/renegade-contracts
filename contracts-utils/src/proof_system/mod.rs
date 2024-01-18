//! Proof system utilities

use std::{
    error::Error,
    fmt::{self, Display, Formatter},
};

use arbitrum_client::errors::ConversionError;
use circuit_types::{errors::ProverError, traits::SingleProverCircuit};
use circuits::zk_circuits::{
    VALID_COMMITMENTS_MATCH_SETTLE_LINK0, VALID_COMMITMENTS_MATCH_SETTLE_LINK1,
    VALID_REBLIND_COMMITMENTS_LINK,
};
use contracts_common::types::{MatchLinkingVkeys, MatchVkeys};
use mpc_relation::proof_linking::GroupLayout;

use crate::conversion::{to_contract_vkey, to_linking_vkey};

pub mod dummy_renegade_circuits;
pub mod test_data;

// ------------------------
// | HIGH-LEVEL UTILITIES |
// ------------------------

/// Generate the verification keys for the circuits involved in settling a matched trade.
///
/// Defined generically over the `VALID COMMITMENTS`, `VALID REBLIND`, and `VALID MATCH SETTLE`
/// circuits, so that this can be used in both testing and production setings.
pub fn gen_match_vkeys<C, R, M>() -> Result<MatchVkeys, ProofSystemError>
where
    C: SingleProverCircuit,
    R: SingleProverCircuit,
    M: SingleProverCircuit,
{
    let valid_commitments_vkey = to_contract_vkey((*C::verifying_key()).clone())?;
    let valid_reblind_vkey = to_contract_vkey((*R::verifying_key()).clone())?;
    let valid_match_settle_vkey = to_contract_vkey((*M::verifying_key()).clone())?;

    Ok(MatchVkeys {
        valid_commitments_vkey,
        valid_reblind_vkey,
        valid_match_settle_vkey,
    })
}

/// The link group layouts involved in settling a matched trade
pub struct MatchGroupLayouts {
    /// The `VALID REBLIND` <-> `VALID COMMITMENTS` link group layout
    pub valid_reblind_commitments: GroupLayout,
    /// The first party's `VALID COMMITMENTS` <-> `VALID MATCH SETTLE` link group layout
    pub valid_commitments_match_settle_0: GroupLayout,
    /// The second party's `VALID COMMITMENTS` <-> `VALID MATCH SETTLE` link group layout
    pub valid_commitments_match_settle_1: GroupLayout,
}

/// Generates the group layouts for the linked circuits involved in settling a matched trade.
///
/// Defined generically over the `VALID COMMITMENTS` circuit, so that this can be used in both
/// the testing and production setting.
pub fn gen_match_layouts<C: SingleProverCircuit>() -> Result<MatchGroupLayouts, ProofSystemError> {
    let valid_commitments_layout = C::get_circuit_layout()
        .map_err(|e| ProofSystemError::ProverError(ProverError::Plonk(e)))?;

    let valid_reblind_commitments =
        valid_commitments_layout.get_group_layout(VALID_REBLIND_COMMITMENTS_LINK);

    let valid_commitments_match_settle_0 =
        valid_commitments_layout.get_group_layout(VALID_COMMITMENTS_MATCH_SETTLE_LINK0);

    let valid_commitments_match_settle_1 =
        valid_commitments_layout.get_group_layout(VALID_COMMITMENTS_MATCH_SETTLE_LINK1);

    Ok(MatchGroupLayouts {
        valid_reblind_commitments,
        valid_commitments_match_settle_0,
        valid_commitments_match_settle_1,
    })
}

/// Generates the linking verification keys for the linked circuits involved in settling a matched trade.
///
/// Defined generically over the `VALID COMMITMENTS` circuit, so that this can be used in both
/// the testing and production setting.
pub fn gen_match_linking_vkeys<C: SingleProverCircuit>(
) -> Result<MatchLinkingVkeys, ProofSystemError> {
    let MatchGroupLayouts {
        valid_reblind_commitments,
        valid_commitments_match_settle_0,
        valid_commitments_match_settle_1,
    } = gen_match_layouts::<C>()?;

    Ok(MatchLinkingVkeys {
        valid_reblind_commitments: to_linking_vkey(&valid_reblind_commitments),
        valid_commitments_match_settle_0: to_linking_vkey(&valid_commitments_match_settle_0),
        valid_commitments_match_settle_1: to_linking_vkey(&valid_commitments_match_settle_1),
    })
}

// --------------
// | ERROR TYPE |
// --------------

/// An error that occured when interacting with the proof system
#[derive(Debug)]
pub enum ProofSystemError {
    /// An error that occurred when converting between prover and contract types
    ConversionError(ConversionError),
    /// An error that occurred when computing a proof
    ProverError(ProverError),
}

impl Display for ProofSystemError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ProofSystemError::ConversionError(e) => write!(f, "ConversionError: {}", e),
            ProofSystemError::ProverError(e) => write!(f, "ProverError: {}", e),
        }
    }
}

impl Error for ProofSystemError {}

impl From<ConversionError> for ProofSystemError {
    fn from(e: ConversionError) -> Self {
        ProofSystemError::ConversionError(e)
    }
}

impl From<ProverError> for ProofSystemError {
    fn from(e: ProverError) -> Self {
        ProofSystemError::ProverError(e)
    }
}
