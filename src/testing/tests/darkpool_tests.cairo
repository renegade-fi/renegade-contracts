use option::OptionTrait;
use result::ResultTrait;
use traits::{TryInto, Into};
use array::ArrayTrait;
use starknet::{
    ContractAddress, contract_address_try_from_felt252, deploy_syscall,
    testing::set_contract_address,
};

use renegade_contracts::{
    darkpool::{Darkpool, IDarkpoolDispatcher, IDarkpoolDispatcherTrait, types::Circuit},
    merkle::Merkle, nullifier_set::NullifierSet,
    verifier::{Verifier, IVerifierDispatcher, IVerifierDispatcherTrait},
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
    let (mut darkpool, _) = setup_darkpool();

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
    let (mut darkpool, _) = setup_darkpool();

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
    let (mut darkpool, _) = setup_darkpool();

    darkpool.upgrade_nullifier_set(DummyUpgradeTarget::TEST_CLASS_HASH.try_into().unwrap());
    assert(!darkpool.is_nullifier_available(0.into()), 'upgrade target wrong result');

    darkpool.upgrade_nullifier_set(NullifierSet::TEST_CLASS_HASH.try_into().unwrap());
    assert(darkpool.is_nullifier_available(0.into()), 'original target wrong result');
}

#[test]
#[available_gas(10000000000)] // 100x
fn test_upgrade_verifier() {
    set_contract_address(contract_address_try_from_felt252(TEST_CALLER).unwrap());
    let (mut darkpool, verifier_addresses) = setup_darkpool();

    let (upgrade_target_address, _) = deploy_syscall(
        DummyUpgradeTarget::TEST_CLASS_HASH.try_into().unwrap(), 0, ArrayTrait::new().span(), false, 
    )
        .unwrap();

    // For each circuit, queue a dummy verification job, check that the verifier has not verified it,
    // upgrade the verifier, check that it (and it alone) has verified the dummy job,
    // and then upgrade it back to the original verifier contract.

    let valid_wallet_create_verifier_address = *verifier_addresses[0];
    let valid_wallet_update_verifier_address = *verifier_addresses[1];
    let valid_commitments_verifier_address = *verifier_addresses[2];
    let valid_reblind_verifier_address = *verifier_addresses[3];
    let valid_match_mpc_verifier_address = *verifier_addresses[4];
    let valid_settle_verifier_address = *verifier_addresses[5];

    // Only the darkpool address can call external functions on the verifier
    set_contract_address(darkpool.contract_address);

    queue_job_direct(valid_wallet_create_verifier_address, 0);
    queue_job_direct(valid_wallet_update_verifier_address, 0);
    queue_job_direct(valid_commitments_verifier_address, 0);
    queue_job_direct(valid_reblind_verifier_address, 0);
    queue_job_direct(valid_match_mpc_verifier_address, 0);
    queue_job_direct(valid_settle_verifier_address, 0);

    set_contract_address(contract_address_try_from_felt252(TEST_CALLER).unwrap());

    // VALID WALLET CREATE
    assert_not_verified(ref darkpool, Circuit::ValidWalletCreate(()), 0);
    darkpool.upgrade_verifier(Circuit::ValidWalletCreate(()), upgrade_target_address);
    assert_only_upgraded_circuit_verified(ref darkpool, Circuit::ValidWalletCreate(()), 0);
    darkpool.upgrade_verifier(Circuit::ValidWalletCreate(()), valid_wallet_create_verifier_address);

    // VALID WALLET UPDATE
    assert_not_verified(ref darkpool, Circuit::ValidWalletUpdate(()), 0);
    darkpool.upgrade_verifier(Circuit::ValidWalletUpdate(()), upgrade_target_address);
    assert_only_upgraded_circuit_verified(ref darkpool, Circuit::ValidWalletUpdate(()), 0);
    darkpool.upgrade_verifier(Circuit::ValidWalletUpdate(()), valid_wallet_update_verifier_address);

    // VALID COMMITMENTS
    assert_not_verified(ref darkpool, Circuit::ValidCommitments(()), 0);
    darkpool.upgrade_verifier(Circuit::ValidCommitments(()), upgrade_target_address);
    assert_only_upgraded_circuit_verified(ref darkpool, Circuit::ValidCommitments(()), 0);
    darkpool.upgrade_verifier(Circuit::ValidCommitments(()), valid_commitments_verifier_address);

    // VALID REBLIND
    assert_not_verified(ref darkpool, Circuit::ValidReblind(()), 0);
    darkpool.upgrade_verifier(Circuit::ValidReblind(()), upgrade_target_address);
    assert_only_upgraded_circuit_verified(ref darkpool, Circuit::ValidReblind(()), 0);
    darkpool.upgrade_verifier(Circuit::ValidReblind(()), valid_reblind_verifier_address);

    // VALID MATCH MPC
    assert_not_verified(ref darkpool, Circuit::ValidMatchMpc(()), 0);
    darkpool.upgrade_verifier(Circuit::ValidMatchMpc(()), upgrade_target_address);
    assert_only_upgraded_circuit_verified(ref darkpool, Circuit::ValidMatchMpc(()), 0);
    darkpool.upgrade_verifier(Circuit::ValidMatchMpc(()), valid_match_mpc_verifier_address);

    // VALID SETTLE
    assert_not_verified(ref darkpool, Circuit::ValidSettle(()), 0);
    darkpool.upgrade_verifier(Circuit::ValidSettle(()), upgrade_target_address);
    assert_only_upgraded_circuit_verified(ref darkpool, Circuit::ValidSettle(()), 0);
    darkpool.upgrade_verifier(Circuit::ValidSettle(()), valid_settle_verifier_address);
}

// ----------------------------
// | OWNERSHIP TRANSFER TESTS |
// ----------------------------

#[test]
#[available_gas(10000000000)] // 100x
fn test_transfer_ownership() {
    let test_caller = contract_address_try_from_felt252(TEST_CALLER).unwrap();
    set_contract_address(test_caller);
    let (mut darkpool, _) = setup_darkpool();

    let dummy_caller = contract_address_try_from_felt252(DUMMY_CALLER).unwrap();
    darkpool.transfer_ownership(dummy_caller);

    assert(darkpool.owner() == dummy_caller, 'ownership transfer failed');
}

// ------------------------
// | ACCESS CONTROL TESTS |
// ------------------------

#[test]
#[should_panic(expected: ('Caller is not the owner', 'ENTRYPOINT_FAILED'))]
#[available_gas(10000000000)] // 100x
fn test_initialize_access() {
    let dummy_caller = contract_address_try_from_felt252(DUMMY_CALLER).unwrap();
    set_contract_address(dummy_caller);
    setup_darkpool();
}

#[test]
#[should_panic(expected: ('Caller is not the owner', 'ENTRYPOINT_FAILED'))]
#[available_gas(10000000000)] // 100x
fn test_upgrade_darkpool_access() {
    let test_caller = contract_address_try_from_felt252(TEST_CALLER).unwrap();
    set_contract_address(test_caller);
    let (mut darkpool, _) = setup_darkpool();

    let dummy_caller = contract_address_try_from_felt252(DUMMY_CALLER).unwrap();
    set_contract_address(dummy_caller);

    darkpool.upgrade(DummyUpgradeTarget::TEST_CLASS_HASH.try_into().unwrap());
}

#[test]
#[should_panic(expected: ('Caller is not the owner', 'ENTRYPOINT_FAILED'))]
#[available_gas(10000000000)] // 100x
fn test_upgrade_merkle_access() {
    let test_caller = contract_address_try_from_felt252(TEST_CALLER).unwrap();
    set_contract_address(test_caller);
    let (mut darkpool, _) = setup_darkpool();

    let dummy_caller = contract_address_try_from_felt252(DUMMY_CALLER).unwrap();
    set_contract_address(dummy_caller);

    darkpool.upgrade_merkle(DummyUpgradeTarget::TEST_CLASS_HASH.try_into().unwrap());
}

#[test]
#[should_panic(expected: ('Caller is not the owner', 'ENTRYPOINT_FAILED'))]
#[available_gas(10000000000)] // 100x
fn test_upgrade_nullifier_set_access() {
    let test_caller = contract_address_try_from_felt252(TEST_CALLER).unwrap();
    set_contract_address(test_caller);
    let (mut darkpool, _) = setup_darkpool();

    let dummy_caller = contract_address_try_from_felt252(DUMMY_CALLER).unwrap();
    set_contract_address(dummy_caller);

    darkpool.upgrade_nullifier_set(DummyUpgradeTarget::TEST_CLASS_HASH.try_into().unwrap());
}

#[test]
#[should_panic(expected: ('Caller is not the owner', 'ENTRYPOINT_FAILED'))]
#[available_gas(10000000000)] // 100x
fn test_upgrade_verifier_access() {
    let test_caller = contract_address_try_from_felt252(TEST_CALLER).unwrap();
    set_contract_address(test_caller);
    let (mut darkpool, _) = setup_darkpool();

    let dummy_caller = contract_address_try_from_felt252(DUMMY_CALLER).unwrap();
    set_contract_address(dummy_caller);

    // Testing w/ multiple `Circuit` enum variants is irrelevant as the access control is
    // checked before ever referencing the `Circuit` argument
    darkpool
        .upgrade_verifier(
            Circuit::ValidWalletCreate(()), DummyUpgradeTarget::TEST_CLASS_HASH.try_into().unwrap()
        );
}

#[test]
#[should_panic(expected: ('Caller is not the owner', 'ENTRYPOINT_FAILED'))]
#[available_gas(10000000000)] // 100x
fn test_transfer_ownership_access() {
    let test_caller = contract_address_try_from_felt252(TEST_CALLER).unwrap();
    set_contract_address(test_caller);
    let (mut darkpool, _) = setup_darkpool();

    let dummy_caller = contract_address_try_from_felt252(DUMMY_CALLER).unwrap();
    set_contract_address(dummy_caller);
    darkpool.transfer_ownership(dummy_caller);
}

// ------------------------
// | INITIALIZATION TESTS |
// ------------------------

#[test]
#[should_panic(expected: ('Initializable: is initialized', 'ENTRYPOINT_FAILED'))]
#[available_gas(10000000000)] // 100x
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

    initialize_darkpool(ref darkpool);
    initialize_darkpool(ref darkpool);
}

// -----------
// | HELPERS |
// -----------

fn setup_darkpool() -> (IDarkpoolDispatcher, Array<ContractAddress>) {
    let mut calldata = ArrayTrait::new();
    calldata.append(TEST_CALLER);

    let (darkpool_address, _) = deploy_syscall(
        Darkpool::TEST_CLASS_HASH.try_into().unwrap(), 0, calldata.span(), false, 
    )
        .unwrap();

    let mut darkpool = IDarkpoolDispatcher { contract_address: darkpool_address };
    let verifier_addresses = initialize_darkpool(ref darkpool);

    (darkpool, verifier_addresses)
}

fn initialize_darkpool(ref darkpool: IDarkpoolDispatcher) -> Array<ContractAddress> {
    let verifier_addresses = darkpool
        .initialize(
            Merkle::TEST_CLASS_HASH.try_into().unwrap(),
            NullifierSet::TEST_CLASS_HASH.try_into().unwrap(),
            Verifier::TEST_CLASS_HASH.try_into().unwrap(),
            TEST_MERKLE_HEIGHT,
        );

    darkpool.initialize_verifier(Circuit::ValidWalletCreate(()), get_dummy_circuit_params());
    darkpool.initialize_verifier(Circuit::ValidWalletUpdate(()), get_dummy_circuit_params());
    darkpool.initialize_verifier(Circuit::ValidCommitments(()), get_dummy_circuit_params());
    darkpool.initialize_verifier(Circuit::ValidReblind(()), get_dummy_circuit_params());
    darkpool.initialize_verifier(Circuit::ValidMatchMpc(()), get_dummy_circuit_params());
    darkpool.initialize_verifier(Circuit::ValidSettle(()), get_dummy_circuit_params());

    verifier_addresses
}

fn assert_only_upgraded_circuit_verified(
    ref darkpool: IDarkpoolDispatcher, upgraded_circuit: Circuit, verification_job_id: felt252
) {
    let mut circuits = ArrayTrait::new();
    circuits.append(Circuit::ValidWalletCreate(()));
    circuits.append(Circuit::ValidWalletUpdate(()));
    circuits.append(Circuit::ValidCommitments(()));
    circuits.append(Circuit::ValidReblind(()));
    circuits.append(Circuit::ValidMatchMpc(()));
    circuits.append(Circuit::ValidSettle(()));

    loop {
        match circuits.pop_front() {
            Option::Some(circuit) => {
                if circuit == upgraded_circuit {
                    assert(
                        darkpool
                            .check_verification_job_status(
                                circuit, verification_job_id
                            ) == Option::Some(true),
                        'upgraded circuit not verified'
                    );
                } else {
                    assert_not_verified(ref darkpool, circuit, verification_job_id);
                }
            },
            Option::None(()) => {
                break;
            }
        };
    };
}

fn assert_not_verified(
    ref darkpool: IDarkpoolDispatcher, circuit: Circuit, verification_job_id: felt252
) {
    assert(
        darkpool.check_verification_job_status(circuit, verification_job_id) == Option::None(()),
        'circuit verified'
    );
}

fn queue_job_direct(verifier_address: ContractAddress, verification_job_id: felt252) {
    let mut verifier = IVerifierDispatcher { contract_address: verifier_address };
    let proof = get_dummy_proof();
    let witness_commitments = get_dummy_witness_commitments();
    verifier.queue_verification_job(proof, witness_commitments, verification_job_id);
}
