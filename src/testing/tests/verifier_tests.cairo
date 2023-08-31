use traits::TryInto;
use option::OptionTrait;
use result::ResultTrait;
use array::ArrayTrait;
use starknet::{deploy_syscall, contract_address_try_from_felt252, testing::set_contract_address};

use renegade_contracts::verifier::{Verifier, IVerifierDispatcher, IVerifierDispatcherTrait};

use super::super::test_utils::{
    get_dummy_circuit_params, get_dummy_proof, get_dummy_witness_commitments
};


const TEST_CALLER: felt252 = 'TEST_CALLER';
const DUMMY_CALLER: felt252 = 'DUMMY_CALLER';

// ---------
// | TESTS |
// ---------

// ------------------------
// | ACCESS CONTROL TESTS |
// ------------------------

#[test]
#[should_panic(expected: ('Caller is not the owner', 'ENTRYPOINT_FAILED'))]
#[available_gas(10000000000)] // 100x
fn test_initialize_access() {
    let dummy_caller = contract_address_try_from_felt252(DUMMY_CALLER).unwrap();
    set_contract_address(dummy_caller);
    setup_verifier();
}

#[test]
#[should_panic(expected: ('Caller is not the owner', 'ENTRYPOINT_FAILED'))]
#[available_gas(10000000000)] // 100x
fn test_queue_verification_job_access() {
    let test_caller = contract_address_try_from_felt252(TEST_CALLER).unwrap();
    set_contract_address(test_caller);
    let mut verifier = setup_verifier();

    let proof = get_dummy_proof();
    let witness_commitments = get_dummy_witness_commitments();

    let dummy_caller = contract_address_try_from_felt252(DUMMY_CALLER).unwrap();
    set_contract_address(dummy_caller);
    verifier.queue_verification_job(proof, witness_commitments, 42);
}

#[test]
#[should_panic(expected: ('Caller is not the owner', 'ENTRYPOINT_FAILED'))]
#[available_gas(10000000000)] // 100x
fn test_step_verification_access() {
    let test_caller = contract_address_try_from_felt252(TEST_CALLER).unwrap();
    set_contract_address(test_caller);
    let mut verifier = setup_verifier();

    let proof = get_dummy_proof();
    let witness_commitments = get_dummy_witness_commitments();

    let dummy_caller = contract_address_try_from_felt252(DUMMY_CALLER).unwrap();
    set_contract_address(dummy_caller);
    verifier.step_verification(42);
}

// -----------
// | HELPERS |
// -----------

fn setup_verifier() -> IVerifierDispatcher {
    let mut calldata = ArrayTrait::new();
    calldata.append(TEST_CALLER);

    let (verifier_address, _) = deploy_syscall(
        Verifier::TEST_CLASS_HASH.try_into().unwrap(), 0, calldata.span(), false
    )
        .unwrap();

    let mut verifier = IVerifierDispatcher { contract_address: verifier_address };
    verifier.initialize(get_dummy_circuit_params());

    verifier
}
