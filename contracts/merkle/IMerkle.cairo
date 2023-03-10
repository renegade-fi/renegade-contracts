// A generic interface for the Merkle tree contract, used to
// enable library calls from the main contract
%lang starknet

@contract_interface
namespace IMerkle {
    func initializer(height: felt) {
    }

    func get_root(index: felt) -> (root: felt) {
    }

    func insert(value: felt) -> (new_root: felt) {
    }
}
