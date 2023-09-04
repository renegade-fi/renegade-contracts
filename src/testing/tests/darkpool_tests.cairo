use option::OptionTrait;
use result::ResultTrait;
use traits::{TryInto, Into};
use array::ArrayTrait;
use starknet::{
    ContractAddress, contract_address_try_from_felt252, deploy_syscall,
    testing::set_contract_address,
};

use renegade_contracts::{
    darkpool::{
        Darkpool, IDarkpoolDispatcher, IDarkpoolDispatcherTrait, types::{Circuit, FeatureFlags}
    },
    merkle::Merkle, nullifier_set::NullifierSet,
    verifier::{MultiVerifier, IMultiVerifierDispatcher, IMultiVerifierDispatcherTrait},
    utils::eq::OptionTPartialEq,
};

use super::{
    merkle_tests::TEST_MERKLE_HEIGHT,
    super::{
        test_utils::{
            get_dummy_circuit_params, get_dummy_proof, get_dummy_witness_commitments,
            DUMMY_ROOT_INNER, DUMMY_WALLET_BLINDER_TX
        },
        test_contracts::{dummy_upgrade_target::DummyUpgradeTarget}
    }
};


const TEST_CALLER: felt252 = 'TEST_CALLER';
const DUMMY_CALLER: felt252 = 'DUMMY_CALLER';

// ---------
// | TESTS |
// ---------

// -----------------
// | UPGRADE TESTS |
// -----------------

#[test]
#[available_gas(10000000000)] // 100x
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
#[available_gas(10000000000)] // 100x
fn test_upgrade_nullifier_set() {
    let test_caller = contract_address_try_from_felt252(TEST_CALLER).unwrap();
    set_contract_address(test_caller);
    let mut darkpool = setup_darkpool();

    darkpool.upgrade_nullifier_set(DummyUpgradeTarget::TEST_CLASS_HASH.try_into().unwrap());
    assert(!darkpool.is_nullifier_available(0.into()), 'upgrade target wrong result');

    darkpool.upgrade_nullifier_set(NullifierSet::TEST_CLASS_HASH.try_into().unwrap());
    assert(darkpool.is_nullifier_available(0.into()), 'original target wrong result');
}

#[test]
#[should_panic(
    expected: ('failed to read from storage', 'ENTRYPOINT_FAILED', 'ENTRYPOINT_FAILED', )
)]
#[available_gas(10000000000)] // 100x
fn test_upgrade_verifier() {
    let test_caller = contract_address_try_from_felt252(TEST_CALLER).unwrap();
    set_contract_address(test_caller);
    let mut darkpool = setup_darkpool_with_flags(
        FeatureFlags { use_base_field_poseidon: true, disable_verification: false }
    );

    darkpool.upgrade_verifier(DummyUpgradeTarget::TEST_CLASS_HASH.try_into().unwrap());
    assert(
        darkpool.check_verification_job_status(0) == Option::Some(true),
        'upgrade target wrong result'
    );

    darkpool.upgrade_verifier(MultiVerifier::TEST_CLASS_HASH.try_into().unwrap());
    assert(
        darkpool.check_verification_job_status(0) == Option::None(()), 'upgrade target wrong result'
    );
}

// ----------------------------
// | OWNERSHIP TRANSFER TESTS |
// ----------------------------

#[test]
#[available_gas(10000000000)] // 100x
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
#[should_panic(expected: ('Caller is not the owner', 'ENTRYPOINT_FAILED', ))]
#[available_gas(10000000000)] // 100x
fn test_initialize_access() {
    let dummy_caller = contract_address_try_from_felt252(DUMMY_CALLER).unwrap();
    set_contract_address(dummy_caller);
    setup_darkpool();
}

#[test]
#[should_panic(expected: ('Caller is not the owner', 'ENTRYPOINT_FAILED', ))]
#[available_gas(10000000000)] // 100x
fn test_upgrade_darkpool_access() {
    let test_caller = contract_address_try_from_felt252(TEST_CALLER).unwrap();
    set_contract_address(test_caller);
    let mut darkpool = setup_darkpool();

    let dummy_caller = contract_address_try_from_felt252(DUMMY_CALLER).unwrap();
    set_contract_address(dummy_caller);

    darkpool.upgrade(DummyUpgradeTarget::TEST_CLASS_HASH.try_into().unwrap());
}

#[test]
#[should_panic(expected: ('Caller is not the owner', 'ENTRYPOINT_FAILED', ))]
#[available_gas(10000000000)] // 100x
fn test_upgrade_merkle_access() {
    let test_caller = contract_address_try_from_felt252(TEST_CALLER).unwrap();
    set_contract_address(test_caller);
    let mut darkpool = setup_darkpool();

    let dummy_caller = contract_address_try_from_felt252(DUMMY_CALLER).unwrap();
    set_contract_address(dummy_caller);

    darkpool.upgrade_merkle(DummyUpgradeTarget::TEST_CLASS_HASH.try_into().unwrap());
}

#[test]
#[should_panic(expected: ('Caller is not the owner', 'ENTRYPOINT_FAILED', ))]
#[available_gas(10000000000)] // 100x
fn test_upgrade_nullifier_set_access() {
    let test_caller = contract_address_try_from_felt252(TEST_CALLER).unwrap();
    set_contract_address(test_caller);
    let mut darkpool = setup_darkpool();

    let dummy_caller = contract_address_try_from_felt252(DUMMY_CALLER).unwrap();
    set_contract_address(dummy_caller);

    darkpool.upgrade_nullifier_set(DummyUpgradeTarget::TEST_CLASS_HASH.try_into().unwrap());
}

#[test]
#[should_panic(expected: ('Caller is not the owner', 'ENTRYPOINT_FAILED', ))]
#[available_gas(10000000000)] // 100x
fn test_upgrade_verifier_access() {
    let test_caller = contract_address_try_from_felt252(TEST_CALLER).unwrap();
    set_contract_address(test_caller);
    let mut darkpool = setup_darkpool_with_flags(
        FeatureFlags { use_base_field_poseidon: true, disable_verification: false }
    );

    let dummy_caller = contract_address_try_from_felt252(DUMMY_CALLER).unwrap();
    set_contract_address(dummy_caller);

    darkpool.upgrade_verifier(DummyUpgradeTarget::TEST_CLASS_HASH.try_into().unwrap());
}

#[test]
#[should_panic(expected: ('Caller is not the owner', 'ENTRYPOINT_FAILED', ))]
#[available_gas(10000000000)] // 100x
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
#[should_panic(expected: ('Initializable: is initialized', 'ENTRYPOINT_FAILED', ))]
#[available_gas(10000000000)] // 100x
fn test_initialize_twice() {
    let test_caller = contract_address_try_from_felt252(TEST_CALLER).unwrap();
    set_contract_address(test_caller);

    let mut calldata = ArrayTrait::new();
    calldata.append(TEST_CALLER);
    Serde::<FeatureFlags>::serialize(
        @FeatureFlags { use_base_field_poseidon: false, disable_verification: false }, ref calldata
    );

    let (darkpool_address, _) = deploy_syscall(
        Darkpool::TEST_CLASS_HASH.try_into().unwrap(), 0, calldata.span(), false, 
    )
        .unwrap();

    let mut darkpool = IDarkpoolDispatcher { contract_address: darkpool_address };

    initialize_darkpool(ref darkpool);
    initialize_darkpool(ref darkpool);
}

// -----------
// | HELPERS |
// -----------

fn setup_darkpool() -> IDarkpoolDispatcher {
    // Default feature flags used disable the scalar field poseidon hash and the verifier, as these
    // are generally not what is being tested here and disabling them speeds up tests.
    setup_darkpool_with_flags(
        FeatureFlags { use_base_field_poseidon: true, disable_verification: true }
    )
}

fn setup_darkpool_with_flags(feature_flags: FeatureFlags) -> IDarkpoolDispatcher {
    let mut calldata = ArrayTrait::new();
    calldata.append(TEST_CALLER);
    Serde::<FeatureFlags>::serialize(@feature_flags, ref calldata);

    let (darkpool_address, _) = deploy_syscall(
        Darkpool::TEST_CLASS_HASH.try_into().unwrap(), 0, calldata.span(), false, 
    )
        .unwrap();

    let mut darkpool = IDarkpoolDispatcher { contract_address: darkpool_address };
    initialize_darkpool(ref darkpool);

    darkpool
}

fn initialize_darkpool(ref darkpool: IDarkpoolDispatcher) {
    darkpool
        .initialize(
            Merkle::TEST_CLASS_HASH.try_into().unwrap(),
            NullifierSet::TEST_CLASS_HASH.try_into().unwrap(),
            MultiVerifier::TEST_CLASS_HASH.try_into().unwrap(),
            TEST_MERKLE_HEIGHT,
        );

    darkpool.parameterize_circuit(Circuit::ValidWalletCreate(()), get_dummy_circuit_params());
    darkpool.parameterize_circuit(Circuit::ValidWalletUpdate(()), get_dummy_circuit_params());
    darkpool.parameterize_circuit(Circuit::ValidCommitments(()), get_dummy_circuit_params());
    darkpool.parameterize_circuit(Circuit::ValidReblind(()), get_dummy_circuit_params());
    darkpool.parameterize_circuit(Circuit::ValidMatchMpc(()), get_dummy_circuit_params());
    darkpool.parameterize_circuit(Circuit::ValidSettle(()), get_dummy_circuit_params());
}

fn assert_not_verified(ref darkpool: IDarkpoolDispatcher, verification_job_id: felt252) {
    assert(
        darkpool.check_verification_job_status(verification_job_id) == Option::None(()),
        'circuit verified'
    );
}
