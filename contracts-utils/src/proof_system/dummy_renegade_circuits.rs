//! Defines mock versions of the Renegade protocol circuits that expect the same
//! statements & link groups, but expect no witness, abd have trivially satisfiable
//! dummy constraints.

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

pub struct DummyCircuit<S: CircuitBaseType> {
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

// -----------------------
// | VALID WALLET CREATE |
// -----------------------

pub type DummyValidWalletCreate = DummyCircuit<SizedValidWalletCreateStatement>;

// -----------------------
// | VALID WALLET UPDATE |
// -----------------------

pub type DummyValidWalletUpdate = DummyCircuit<SizedValidWalletUpdateStatement>;

// -----------------
// | VALID REBLIND |
// -----------------

pub type DummyValidReblind = DummyCircuit<ValidReblindStatement>;

// ---------------------
// | VALID COMMITMENTS |
// ---------------------

pub type DummyValidCommitments = DummyCircuit<ValidCommitmentsStatement>;

// ----------------------
// | VALID MATCH SETTLE |
// ----------------------

pub type DummyValidMatchSettle = DummyCircuit<SizedValidMatchSettleStatement>;
