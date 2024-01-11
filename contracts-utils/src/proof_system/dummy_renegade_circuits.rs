//! Defines a mock circuit that is generic over the same statements as the Renegade
//! protocol circuits, but is trivially satisfiable

use core::marker::PhantomData;

use circuit_types::{
    traits::{CircuitBaseType, SingleProverCircuit},
    PlonkCircuit,
};
use circuits::zk_circuits::{
    valid_commitments::ValidCommitmentsStatement,
    valid_match_settle::SizedValidMatchSettleStatement, valid_reblind::ValidReblindStatement,
    valid_wallet_create::SizedValidWalletCreateStatement,
    valid_wallet_update::SizedValidWalletUpdateStatement,
};

use eyre::Result;

use mpc_plonk::errors::PlonkError;

/// A simple circuit that is trivially satisfiable in that it applies no constraints.
///
/// Defined generically over an application-level statement type.
pub struct DummyCircuit<S: CircuitBaseType> {
    #[doc(hidden)]
    _phantom: PhantomData<S>,
}

impl<S: CircuitBaseType> SingleProverCircuit for DummyCircuit<S> {
    type Statement = S;
    type Witness = ();

    fn name() -> String {
        "Dummy Circuit".to_string()
    }

    fn apply_constraints(
        _witness_var: (),
        _statement_var: <S as CircuitBaseType>::VarType,
        _cs: &mut PlonkCircuit,
    ) -> Result<(), PlonkError> {
        Ok(())
    }
}

/// The dummy version of the `VALID WALLET CREATE` circuit
pub type DummyValidWalletCreate = DummyCircuit<SizedValidWalletCreateStatement>;

/// The dummy version of the `VALID WALLET UPDATE` circuit
pub type DummyValidWalletUpdate = DummyCircuit<SizedValidWalletUpdateStatement>;

/// The dummy version of the `VALID REBLIND` circuit
pub type DummyValidReblind = DummyCircuit<ValidReblindStatement>;

/// The dummy version of the `VALID COMMITMENTS` circuit
pub type DummyValidCommitments = DummyCircuit<ValidCommitmentsStatement>;

/// The dummy version of the `VALID MATCH SETTLE` circuit
pub type DummyValidMatchSettle = DummyCircuit<SizedValidMatchSettleStatement>;
