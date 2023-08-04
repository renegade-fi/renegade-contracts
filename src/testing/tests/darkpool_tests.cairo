use clone::Clone;
use option::OptionTrait;
use result::ResultTrait;
use traits::{TryInto, Into};
use box::BoxTrait;
use array::ArrayTrait;
use zeroable::Zeroable;
use starknet::{
    ContractAddress, contract_address_try_from_felt252, deploy_syscall, get_tx_info,
    testing::set_contract_address, contract_address::ContractAddressZeroable,
};

use renegade_contracts::{
    darkpool::{
        Darkpool, Darkpool::ContractState, IDarkpool, IDarkpoolDispatcher, IDarkpoolDispatcherTrait,
        types::{ExternalTransfer, MatchPayload}
    },
    merkle::Merkle, nullifier_set::NullifierSet, verifier::{scalar::Scalar, types::Proof},
};

use super::{merkle_tests::TEST_MERKLE_HEIGHT, super::test_utils::get_dummy_proof};

use debug::PrintTrait;


const TEST_CALLER: felt252 = 0x0123456789abcdef;

#[test]
#[available_gas(1000000000)] // 10x
fn test_new_wallet_last_modified() {
    let mut darkpool = setup_darkpool();

    let (
        wallet_blinder_share,
        wallet_share_commitment,
        public_wallet_shares,
        proof,
        witness_commitments
    ) =
        get_dummy_new_wallet_args();

    darkpool
        .new_wallet(
            wallet_blinder_share,
            wallet_share_commitment,
            public_wallet_shares,
            proof,
            witness_commitments
        );
    let last_modified = darkpool.get_wallet_blinder_transaction(wallet_blinder_share);

    let tx_info = get_tx_info().unbox();
    assert(last_modified == tx_info.transaction_hash, 'incorrect last modified tx hash');
}

#[test]
#[available_gas(1000000000)] // 10x
fn test_update_wallet_last_modified() {
    let mut darkpool = setup_darkpool();

    let (
        wallet_blinder_share,
        wallet_share_commitment,
        old_shares_nullifier,
        public_wallet_shares,
        external_transfers,
        proof,
        witness_commitments
    ) =
        get_dummy_update_wallet_args();

    darkpool
        .update_wallet(
            wallet_blinder_share,
            wallet_share_commitment,
            old_shares_nullifier,
            public_wallet_shares,
            external_transfers,
            proof,
            witness_commitments
        );

    let last_modified = darkpool.get_wallet_blinder_transaction(wallet_blinder_share);

    let tx_info = get_tx_info().unbox();
    assert(last_modified == tx_info.transaction_hash, 'incorrect last modified tx hash');
}

#[test]
#[available_gas(1000000000)] // 10x
fn test_process_match_last_modified() {
    let mut darkpool = setup_darkpool();

    let (
        party_0_match_payload,
        party_1_match_payload,
        match_proof,
        match_witness_commitments,
        settle_proof,
        settle_witness_commitments
    ) =
        get_dummy_process_match_args();

    darkpool
        .process_match(
            party_0_match_payload.clone(),
            party_1_match_payload.clone(),
            match_proof,
            match_witness_commitments,
            settle_proof,
            settle_witness_commitments
        );

    let last_modified = darkpool
        .get_wallet_blinder_transaction(party_0_match_payload.wallet_blinder_share);
    let tx_info = get_tx_info().unbox();

    assert(last_modified == tx_info.transaction_hash, 'incorrect last modified tx hash');

    let last_modified = darkpool
        .get_wallet_blinder_transaction(party_1_match_payload.wallet_blinder_share);
    assert(last_modified == tx_info.transaction_hash, 'incorrect last modified tx hash');
}

#[test]
#[available_gas(1000000000)] // 10x
fn test_update_wallet_nullifiers() {
    let mut darkpool = setup_darkpool();

    let (
        wallet_blinder_share,
        wallet_share_commitment,
        old_shares_nullifier,
        public_wallet_shares,
        external_transfers,
        proof,
        witness_commitments
    ) =
        get_dummy_update_wallet_args();

    assert(!darkpool.is_nullifier_used(old_shares_nullifier), 'nullifier should not be used');

    darkpool
        .update_wallet(
            wallet_blinder_share,
            wallet_share_commitment,
            old_shares_nullifier,
            public_wallet_shares,
            external_transfers,
            proof,
            witness_commitments
        );

    assert(darkpool.is_nullifier_used(old_shares_nullifier), 'nullifier should be used');
}

#[test]
#[available_gas(1000000000)] // 10x
fn test_process_match_nullifiers() {
    let mut darkpool = setup_darkpool();

    let (
        party_0_match_payload,
        party_1_match_payload,
        match_proof,
        match_witness_commitments,
        settle_proof,
        settle_witness_commitments
    ) =
        get_dummy_process_match_args();

    assert(
        !darkpool.is_nullifier_used(party_0_match_payload.old_shares_nullifier),
        'nullifier should not be used'
    );
    assert(
        !darkpool.is_nullifier_used(party_1_match_payload.old_shares_nullifier),
        'nullifier should not be used'
    );

    darkpool
        .process_match(
            party_0_match_payload.clone(),
            party_1_match_payload.clone(),
            match_proof,
            match_witness_commitments,
            settle_proof,
            settle_witness_commitments
        );

    assert(
        darkpool.is_nullifier_used(party_0_match_payload.old_shares_nullifier),
        'nullifier should be used'
    );
    assert(
        darkpool.is_nullifier_used(party_1_match_payload.old_shares_nullifier),
        'nullifier should be used'
    );
}

// -----------
// | HELPERS |
// -----------

fn setup_darkpool() -> IDarkpoolDispatcher {
    let test_caller = contract_address_try_from_felt252(TEST_CALLER).unwrap();
    set_contract_address(test_caller);
    let mut calldata = ArrayTrait::new();
    calldata.append(TEST_CALLER);

    let (darkpool_address, _) = deploy_syscall(
        Darkpool::TEST_CLASS_HASH.try_into().unwrap(), 0, calldata.span(), false, 
    )
        .unwrap();

    let mut darkpool = IDarkpoolDispatcher { contract_address: darkpool_address };
    darkpool
        .initialize(
            Merkle::TEST_CLASS_HASH.try_into().unwrap(),
            NullifierSet::TEST_CLASS_HASH.try_into().unwrap(),
            TEST_MERKLE_HEIGHT
        );

    darkpool
}

fn get_dummy_new_wallet_args() -> (Scalar, Scalar, Array<Scalar>, Proof, Array<EcPoint>) {
    (0.into(), 0.into(), ArrayTrait::new(), get_dummy_proof(), ArrayTrait::new())
}

fn get_dummy_update_wallet_args() -> (
    Scalar, Scalar, Scalar, Array<Scalar>, Array<ExternalTransfer>, Proof, Array<EcPoint>
) {
    (
        0.into(),
        0.into(),
        0.into(),
        ArrayTrait::new(),
        ArrayTrait::new(),
        get_dummy_proof(),
        ArrayTrait::new(),
    )
}

fn get_dummy_match_payload(blinder: Scalar, nullifier: Scalar) -> MatchPayload {
    MatchPayload {
        wallet_blinder_share: blinder,
        wallet_share_commitment: 0.into(),
        old_shares_nullifier: nullifier,
        public_wallet_shares: ArrayTrait::new(),
        valid_commitments_proof: get_dummy_proof(),
        valid_commitments_witness_commitments: ArrayTrait::new(),
        valid_reblind_proof: get_dummy_proof(),
        valid_reblind_witness_commitments: ArrayTrait::new(),
    }
}

fn get_dummy_process_match_args() -> (
    MatchPayload, MatchPayload, Proof, Array<EcPoint>, Proof, Array<EcPoint>
) {
    (
        get_dummy_match_payload(0.into(), 0.into()),
        get_dummy_match_payload(1.into(), 1.into()),
        get_dummy_proof(),
        ArrayTrait::new(),
        get_dummy_proof(),
        ArrayTrait::new(),
    )
}
