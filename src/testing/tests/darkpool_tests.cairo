use clone::Clone;
use option::OptionTrait;
use result::ResultTrait;
use traits::{TryInto, Into};
use box::BoxTrait;
use array::ArrayTrait;
use zeroable::Zeroable;
use starknet::{
    ContractAddress, contract_address_try_from_felt252, contract_address_to_felt252, deploy_syscall,
    get_tx_info, testing::set_contract_address, contract_address::ContractAddressZeroable,
};

use renegade_contracts::{
    darkpool::{
        Darkpool, Darkpool::ContractState, IDarkpool, IDarkpoolDispatcher, IDarkpoolDispatcherTrait,
        types::{ExternalTransfer, MatchPayload}
    },
    merkle::Merkle, nullifier_set::NullifierSet, verifier::{scalar::Scalar, types::Proof},
    oz::erc20::{IERC20Dispatcher, IERC20DispatcherTrait}
};

use super::{
    merkle_tests::TEST_MERKLE_HEIGHT,
    super::{
        test_utils::{get_dummy_proof, DUMMY_ROOT_INNER, DUMMY_WALLET_BLINDER_TX},
        test_contracts::{dummy_erc20::DummyERC20, dummy_upgrade_target::DummyUpgradeTarget}
    }
};

use debug::PrintTrait;


const TEST_CALLER: felt252 = 'TEST_CALLER';
const DUMMY_CALLER: felt252 = 'DUMMY_CALLER';

const INIT_BALANCE: u256 = 1000;
const TRANSFER_AMOUNT: u256 = 100;

// ---------
// | TESTS |
// ---------

// ------------------------------
// | WALLET LAST MODIFIED TESTS |
// ------------------------------

#[test]
#[available_gas(10000000000)] // 100x
fn test_new_wallet_last_modified() {
    let test_caller = contract_address_try_from_felt252(TEST_CALLER).unwrap();
    set_contract_address(test_caller);
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
#[available_gas(10000000000)] // 100x
fn test_update_wallet_last_modified() {
    let test_caller = contract_address_try_from_felt252(TEST_CALLER).unwrap();
    set_contract_address(test_caller);
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
#[available_gas(10000000000)] // 100x
fn test_process_match_last_modified() {
    let test_caller = contract_address_try_from_felt252(TEST_CALLER).unwrap();
    set_contract_address(test_caller);
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

// ---------------------------
// | IS NULLIFIER USED TESTS |
// ---------------------------

#[test]
#[available_gas(10000000000)] // 100x
fn test_update_wallet_nullifiers() {
    let test_caller = contract_address_try_from_felt252(TEST_CALLER).unwrap();
    set_contract_address(test_caller);
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
#[available_gas(10000000000)] // 100x
fn test_process_match_nullifiers() {
    let test_caller = contract_address_try_from_felt252(TEST_CALLER).unwrap();
    set_contract_address(test_caller);
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

// ------------------
// | TRANSFER TESTS |
// ------------------

#[test]
#[available_gas(10000000000)] // 100x
fn test_update_wallet_deposit() {
    let test_caller = contract_address_try_from_felt252(TEST_CALLER).unwrap();
    set_contract_address(test_caller);
    let mut darkpool = setup_darkpool();
    let dummy_erc20 = setup_dummy_erc20(darkpool.contract_address);

    let (
        wallet_blinder_share,
        wallet_share_commitment,
        old_shares_nullifier,
        public_wallet_shares,
        _,
        proof,
        witness_commitments
    ) =
        get_dummy_update_wallet_args();

    let mut external_transfers = ArrayTrait::new();
    external_transfers.append(get_dummy_deposit(dummy_erc20.contract_address));

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

    let test_caller = contract_address_try_from_felt252(TEST_CALLER).unwrap();
    let caller_balance = dummy_erc20.balance_of(test_caller);
    let darkpool_balance = dummy_erc20.balance_of(darkpool.contract_address);

    assert(caller_balance == INIT_BALANCE - TRANSFER_AMOUNT, 'incorrect caller balance');
    assert(darkpool_balance == INIT_BALANCE + TRANSFER_AMOUNT, 'incorrect darkpool balance');
}

#[test]
#[available_gas(10000000000)] // 100x
fn test_update_wallet_withdrawal() {
    let test_caller = contract_address_try_from_felt252(TEST_CALLER).unwrap();
    set_contract_address(test_caller);
    let mut darkpool = setup_darkpool();
    let dummy_erc20 = setup_dummy_erc20(darkpool.contract_address);

    let (
        wallet_blinder_share,
        wallet_share_commitment,
        old_shares_nullifier,
        public_wallet_shares,
        _,
        proof,
        witness_commitments
    ) =
        get_dummy_update_wallet_args();

    let mut external_transfers = ArrayTrait::new();
    external_transfers.append(get_dummy_withdrawal(dummy_erc20.contract_address));

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

    let test_caller = contract_address_try_from_felt252(TEST_CALLER).unwrap();

    let caller_balance = dummy_erc20.balance_of(test_caller);
    let darkpool_balance = dummy_erc20.balance_of(darkpool.contract_address);

    assert(caller_balance == INIT_BALANCE + TRANSFER_AMOUNT, 'incorrect caller balance');
    assert(darkpool_balance == INIT_BALANCE - TRANSFER_AMOUNT, 'incorrect darkpool balance');
}

// -----------------
// | UPGRADE TESTS |
// -----------------

#[test]
#[available_gas(1000000000)] // 10x
fn test_upgrade_darkpool() {
    let test_caller = contract_address_try_from_felt252(TEST_CALLER).unwrap();
    set_contract_address(test_caller);
    let mut darkpool = setup_darkpool();

    darkpool.upgrade(DummyUpgradeTarget::TEST_CLASS_HASH.try_into().unwrap());
    // The dummy upgrade target has a hardcoded response for the `get_wallet_blinder_transaction`
    // method, which we assert here.
    assert(
        darkpool.get_wallet_blinder_transaction(0.into()) == DUMMY_WALLET_BLINDER_TX,
        'upgrade target wrong result'
    );

    darkpool.upgrade(Darkpool::TEST_CLASS_HASH.try_into().unwrap());
    assert(darkpool.get_wallet_blinder_transaction(0.into()) == 0, 'original target wrong result');
}

#[test]
#[available_gas(10000000000)] // 100x
fn test_upgrade_darkpool_storage() {
    let test_caller = contract_address_try_from_felt252(TEST_CALLER).unwrap();
    set_contract_address(test_caller);
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

    let original_root = darkpool.get_root();

    darkpool.upgrade(DummyUpgradeTarget::TEST_CLASS_HASH.try_into().unwrap());
    darkpool.upgrade(Darkpool::TEST_CLASS_HASH.try_into().unwrap());

    assert(darkpool.get_root() == original_root, 'root not preserved');
    assert(darkpool.is_nullifier_used(old_shares_nullifier), 'nullifier not preserved');
}

#[test]
#[available_gas(1000000000)] // 10x
fn test_upgrade_merkle() {
    let test_caller = contract_address_try_from_felt252(TEST_CALLER).unwrap();
    set_contract_address(test_caller);
    let mut darkpool = setup_darkpool();

    let original_root = darkpool.get_root();

    darkpool.upgrade_merkle(DummyUpgradeTarget::TEST_CLASS_HASH.try_into().unwrap());
    assert(darkpool.get_root() == DUMMY_ROOT_INNER.into(), 'upgrade target wrong result');

    darkpool.upgrade_merkle(Merkle::TEST_CLASS_HASH.try_into().unwrap());
    assert(darkpool.get_root() == original_root, 'original target wrong result');
}

#[test]
#[available_gas(1000000000)] // 10x
fn test_upgrade_nullifier_set() {
    let test_caller = contract_address_try_from_felt252(TEST_CALLER).unwrap();
    set_contract_address(test_caller);
    let mut darkpool = setup_darkpool();

    darkpool.upgrade_nullifier_set(DummyUpgradeTarget::TEST_CLASS_HASH.try_into().unwrap());
    assert(darkpool.is_nullifier_used(0.into()), 'upgrade target wrong result');

    darkpool.upgrade_nullifier_set(NullifierSet::TEST_CLASS_HASH.try_into().unwrap());
    assert(!darkpool.is_nullifier_used(0.into()), 'original target wrong result');
}

// ----------------------------
// | OWNERSHIP TRANSFER TESTS |
// ----------------------------

#[test]
#[available_gas(1000000000)] // 10x
fn test_transfer_ownership() {
    let test_caller = contract_address_try_from_felt252(TEST_CALLER).unwrap();
    set_contract_address(test_caller);
    let mut darkpool = setup_darkpool();

    let dummy_caller = contract_address_try_from_felt252(DUMMY_CALLER).unwrap();
    darkpool.transfer_ownership(dummy_caller);

    assert(darkpool.owner() == dummy_caller, 'ownership transfer failed');
}

// ------------------------
// | ACCESS CONTROL TESTS |
// ------------------------

#[test]
#[should_panic]
#[available_gas(1000000000)] // 10x
fn test_initialize_access() {
    let dummy_caller = contract_address_try_from_felt252(DUMMY_CALLER).unwrap();
    set_contract_address(dummy_caller);
    setup_darkpool();
}

#[test]
#[should_panic]
#[available_gas(1000000000)] // 10x
fn test_upgrade_darkpool_access() {
    let test_caller = contract_address_try_from_felt252(TEST_CALLER).unwrap();
    set_contract_address(test_caller);
    let mut darkpool = setup_darkpool();

    let dummy_caller = contract_address_try_from_felt252(DUMMY_CALLER).unwrap();
    set_contract_address(dummy_caller);

    darkpool.upgrade(DummyUpgradeTarget::TEST_CLASS_HASH.try_into().unwrap());
}

#[test]
#[should_panic]
#[available_gas(1000000000)] // 10x
fn test_upgrade_merkle_access() {
    let test_caller = contract_address_try_from_felt252(TEST_CALLER).unwrap();
    set_contract_address(test_caller);
    let mut darkpool = setup_darkpool();

    let dummy_caller = contract_address_try_from_felt252(DUMMY_CALLER).unwrap();
    set_contract_address(dummy_caller);

    darkpool.upgrade_merkle(DummyUpgradeTarget::TEST_CLASS_HASH.try_into().unwrap());
}

#[test]
#[should_panic]
#[available_gas(1000000000)] // 10x
fn test_upgrade_nullifier_set_access() {
    let test_caller = contract_address_try_from_felt252(TEST_CALLER).unwrap();
    set_contract_address(test_caller);
    let mut darkpool = setup_darkpool();

    let dummy_caller = contract_address_try_from_felt252(DUMMY_CALLER).unwrap();
    set_contract_address(dummy_caller);

    darkpool.upgrade_nullifier_set(DummyUpgradeTarget::TEST_CLASS_HASH.try_into().unwrap());
}

#[test]
#[should_panic]
#[available_gas(1000000000)] // 10x
fn test_transfer_ownership_access() {
    let test_caller = contract_address_try_from_felt252(TEST_CALLER).unwrap();
    set_contract_address(test_caller);
    let mut darkpool = setup_darkpool();

    let dummy_caller = contract_address_try_from_felt252(DUMMY_CALLER).unwrap();
    set_contract_address(dummy_caller);
    darkpool.transfer_ownership(dummy_caller);
}

// ------------------------
// | INITIALIZATION TESTS |
// ------------------------

#[test]
#[should_panic]
#[available_gas(1000000000)] // 10x
fn test_initialize_twice() {
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
        .initialize(
            Merkle::TEST_CLASS_HASH.try_into().unwrap(),
            NullifierSet::TEST_CLASS_HASH.try_into().unwrap(),
            TEST_MERKLE_HEIGHT
        );
}

// -----------
// | HELPERS |
// -----------

fn setup_darkpool() -> IDarkpoolDispatcher {
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

fn setup_dummy_erc20(darkpool_contract_address: ContractAddress) -> IERC20Dispatcher {
    let mut calldata = ArrayTrait::new();
    calldata.append('DummyToken');
    calldata.append('DUMMY');
    calldata.append(INIT_BALANCE.low.into());
    calldata.append(INIT_BALANCE.high.into());
    calldata.append(2);
    calldata.append(TEST_CALLER);
    calldata.append(contract_address_to_felt252(darkpool_contract_address));

    let (dummy_erc20_address, _) = deploy_syscall(
        DummyERC20::TEST_CLASS_HASH.try_into().unwrap(), 0, calldata.span(), false, 
    )
        .unwrap();

    let mut dummy_erc20 = IERC20Dispatcher { contract_address: dummy_erc20_address };
    dummy_erc20.approve(darkpool_contract_address, INIT_BALANCE);

    dummy_erc20
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

fn get_dummy_deposit(dummy_erc20_address: ContractAddress) -> ExternalTransfer {
    ExternalTransfer {
        account_addr: contract_address_try_from_felt252(TEST_CALLER).unwrap(),
        mint: dummy_erc20_address,
        amount: TRANSFER_AMOUNT,
        is_withdrawal: false,
    }
}

fn get_dummy_withdrawal(dummy_erc20_address: ContractAddress) -> ExternalTransfer {
    ExternalTransfer {
        account_addr: contract_address_try_from_felt252(TEST_CALLER).unwrap(),
        mint: dummy_erc20_address,
        amount: TRANSFER_AMOUNT,
        is_withdrawal: true,
    }
}
