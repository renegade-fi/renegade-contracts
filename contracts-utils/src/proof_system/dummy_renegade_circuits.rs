//! Defines mock circuits that expect the same statements & linking relationships
//! as the Renegade protocol circuits, but are trivially satisfiable

#![allow(missing_docs, clippy::missing_docs_in_private_items)]

use circuit_macros::circuit_type;
use circuit_types::{
    traits::{BaseType, CircuitBaseType, CircuitVarType, SingleProverCircuit},
    PlonkCircuit,
};
use circuits::zk_circuits::{
    valid_commitments::ValidCommitmentsStatement,
    valid_fee_redemption::SizedValidFeeRedemptionStatement,
    valid_match_settle::SizedValidMatchSettleStatement,
    valid_offline_fee_settlement::SizedValidOfflineFeeSettlementStatement,
    valid_reblind::ValidReblindStatement,
    valid_relayer_fee_settlement::SizedValidRelayerFeeSettlementStatement,
    valid_wallet_create::SizedValidWalletCreateStatement,
    valid_wallet_update::SizedValidWalletUpdateStatement, VALID_COMMITMENTS_MATCH_SETTLE_LINK0,
    VALID_COMMITMENTS_MATCH_SETTLE_LINK1, VALID_REBLIND_COMMITMENTS_LINK,
};

use constants::Scalar;
use contracts_common::types::ScalarField;
use eyre::Result;
use mpc_plonk::errors::PlonkError;
use mpc_relation::{
    proof_linking::{GroupLayout, LinkableCircuit},
    traits::Circuit,
    Variable,
};

/// The dummy version of the `VALID WALLET CREATE` circuit
pub struct DummyValidWalletCreate;

impl SingleProverCircuit for DummyValidWalletCreate {
    type Statement = SizedValidWalletCreateStatement;
    type Witness = ();

    fn name() -> String {
        "Dummy Valid Wallet Create".to_string()
    }

    fn apply_constraints(
        _witness_var: (),
        _statement_var: <SizedValidWalletCreateStatement as CircuitBaseType>::VarType,
        _cs: &mut PlonkCircuit,
    ) -> Result<(), PlonkError> {
        Ok(())
    }
}

/// The dummy version of the `VALID WALLET UPDATE` circuit
pub struct DummyValidWalletUpdate;

impl SingleProverCircuit for DummyValidWalletUpdate {
    type Statement = SizedValidWalletUpdateStatement;
    type Witness = ();

    fn name() -> String {
        "Dummy Valid Wallet Update".to_string()
    }

    fn apply_constraints(
        _witness_var: (),
        _statement_var: <SizedValidWalletUpdateStatement as CircuitBaseType>::VarType,
        _cs: &mut PlonkCircuit,
    ) -> Result<(), PlonkError> {
        Ok(())
    }
}

/// The dummy version of the `VALID REBLIND` witness,
/// which defines a single element to be linked with the dummy
/// `VALID COMMITMENTS` circuit
#[circuit_type(singleprover_circuit)]
#[derive(Clone)]
pub struct DummyValidReblindWitness {
    /// The element to be linked with `VALID COMMITMENTS`
    #[link_groups = "valid_reblind_commitments"]
    pub valid_reblind_commitments: Scalar,
}

/// The dummy version of the `VALID REBLIND` circuit
pub struct DummyValidReblind;

impl SingleProverCircuit for DummyValidReblind {
    type Statement = ValidReblindStatement;
    type Witness = DummyValidReblindWitness;

    fn name() -> String {
        "Dummy Valid Reblind".to_string()
    }

    fn apply_constraints(
        _witness_var: <DummyValidReblindWitness as CircuitBaseType>::VarType,
        _statement_var: <ValidReblindStatement as CircuitBaseType>::VarType,
        _cs: &mut PlonkCircuit,
    ) -> Result<(), PlonkError> {
        Ok(())
    }

    fn proof_linking_groups() -> Result<Vec<(String, Option<GroupLayout>)>, PlonkError> {
        Ok(vec![(VALID_REBLIND_COMMITMENTS_LINK.to_string(), None)])
    }
}

/// The dummy version of the `VALID COMMITMENTS` witness,
/// which defines a single element to be linked with the dummy
/// `VALID REBLIND` circuit, and two elements to be linked with the dummy
/// `VALID MATCH SETTLE` circuit depending on which party is settling
#[circuit_type(singleprover_circuit)]
#[derive(Clone)]
pub struct DummyValidCommitmentsWitness {
    /// The element to be linked with `VALID REBLIND`
    #[link_groups = "valid_reblind_commitments"]
    pub valid_reblind_commitments: Scalar,
    /// The first element to be linked with `VALID MATCH SETTLE`
    #[link_groups = "valid_commitments_match_settle0"]
    pub valid_commitments_match_settle0: Scalar,
    /// The second element to be linked with `VALID MATCH SETTLE`
    #[link_groups = "valid_commitments_match_settle1"]
    pub valid_commitments_match_settle1: Scalar,
}

/// The dummy version of the `VALID COMMITMENTS` circuit
pub struct DummyValidCommitments;

impl SingleProverCircuit for DummyValidCommitments {
    type Statement = ValidCommitmentsStatement;
    type Witness = DummyValidCommitmentsWitness;

    fn name() -> String {
        "Dummy Valid Commitments".to_string()
    }

    fn apply_constraints(
        _witness_var: <DummyValidCommitmentsWitness as CircuitBaseType>::VarType,
        _statement_var: <ValidCommitmentsStatement as CircuitBaseType>::VarType,
        _cs: &mut PlonkCircuit,
    ) -> Result<(), PlonkError> {
        Ok(())
    }

    fn proof_linking_groups() -> Result<Vec<(String, Option<GroupLayout>)>, PlonkError> {
        let reblind_layout = DummyValidReblind::get_circuit_layout()?;
        let layout1 = reblind_layout.get_group_layout(VALID_REBLIND_COMMITMENTS_LINK);

        let match_settle_layout = DummyValidMatchSettle::get_circuit_layout()?;
        let layout2 = match_settle_layout.get_group_layout(VALID_COMMITMENTS_MATCH_SETTLE_LINK0);
        let layout3 = match_settle_layout.get_group_layout(VALID_COMMITMENTS_MATCH_SETTLE_LINK1);

        Ok(vec![
            (VALID_REBLIND_COMMITMENTS_LINK.to_string(), Some(layout1)),
            (
                VALID_COMMITMENTS_MATCH_SETTLE_LINK0.to_string(),
                Some(layout2),
            ),
            (
                VALID_COMMITMENTS_MATCH_SETTLE_LINK1.to_string(),
                Some(layout3),
            ),
        ])
    }
}

/// The dummy version of the `VALID MATCH SETTLE` witness,
/// which defines two elements to be linked with the dummy
/// `VALID COMMITMENTS` circuit depending on which party is settling
#[circuit_type(singleprover_circuit)]
#[derive(Clone)]
pub struct DummyValidMatchSettleWitness {
    /// The first element to be linked with `VALID COMMITMENTS`
    #[link_groups = "valid_commitments_match_settle0"]
    pub valid_commitments_match_settle0: Scalar,
    /// The second element to be linked with `VALID COMMITMENTS`
    #[link_groups = "valid_commitments_match_settle1"]
    pub valid_commitments_match_settle1: Scalar,
}

/// The dummy version of the `VALID MATCH SETTLE` circuit
pub struct DummyValidMatchSettle;

impl SingleProverCircuit for DummyValidMatchSettle {
    type Statement = SizedValidMatchSettleStatement;
    type Witness = DummyValidMatchSettleWitness;

    fn name() -> String {
        "Dummy Valid Match Settle".to_string()
    }

    fn apply_constraints(
        _witness_var: <DummyValidMatchSettleWitness as CircuitBaseType>::VarType,
        _statement_var: <SizedValidMatchSettleStatement as CircuitBaseType>::VarType,
        _cs: &mut PlonkCircuit,
    ) -> Result<(), PlonkError> {
        Ok(())
    }

    fn proof_linking_groups() -> Result<Vec<(String, Option<GroupLayout>)>, PlonkError> {
        Ok(vec![
            (VALID_COMMITMENTS_MATCH_SETTLE_LINK0.to_string(), None),
            (VALID_COMMITMENTS_MATCH_SETTLE_LINK1.to_string(), None),
        ])
    }
}

/// The dummy version of the `VALID RELAYER FEE SETTLEMENT` circuit
pub struct DummyValidRelayerFeeSettlement;

impl SingleProverCircuit for DummyValidRelayerFeeSettlement {
    type Statement = SizedValidRelayerFeeSettlementStatement;
    type Witness = ();

    fn name() -> String {
        "Dummy Valid Relayer Fee Settlement".to_string()
    }

    fn apply_constraints(
        _witness_var: (),
        _statement_var: <SizedValidRelayerFeeSettlementStatement as CircuitBaseType>::VarType,
        _cs: &mut PlonkCircuit,
    ) -> Result<(), PlonkError> {
        Ok(())
    }
}

/// The dummy version of the `VALID OFFLINE FEE SETTLEMENT` circuit
pub struct DummyValidOfflineFeeSettlement;

impl SingleProverCircuit for DummyValidOfflineFeeSettlement {
    type Statement = SizedValidOfflineFeeSettlementStatement;
    type Witness = ();

    fn name() -> String {
        "Dummy Valid Offline Fee Settlement".to_string()
    }

    fn apply_constraints(
        _witness_var: (),
        _statement_var: <SizedValidOfflineFeeSettlementStatement as CircuitBaseType>::VarType,
        _cs: &mut PlonkCircuit,
    ) -> Result<(), PlonkError> {
        Ok(())
    }
}

/// The dummy version of the `VALID FEE REDEMPTION` circuit
pub struct DummyValidFeeRedemption;

impl SingleProverCircuit for DummyValidFeeRedemption {
    type Statement = SizedValidFeeRedemptionStatement;
    type Witness = ();

    fn name() -> String {
        "Dummy Valid Fee Redemption".to_string()
    }

    fn apply_constraints(
        _witness_var: (),
        _statement_var: <SizedValidFeeRedemptionStatement as CircuitBaseType>::VarType,
        _cs: &mut PlonkCircuit,
    ) -> Result<(), PlonkError> {
        Ok(())
    }
}
