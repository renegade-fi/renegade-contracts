// A generic interface for the nullifier set contract, used to
// enable library calls from the main contract
%lang starknet

@contract_interface
namespace INullifierSet {
    func is_nullifier_used(nullifier: felt) -> (res: felt) {
    }

    func mark_nullifier_used(nullifier: felt) {
    }
}
