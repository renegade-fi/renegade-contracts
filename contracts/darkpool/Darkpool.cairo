// Declare this file as a StarkNet contract.
%lang starknet

from openzeppelin.upgrades.library import Proxy

from starkware.cairo.common.cairo_builtins import HashBuiltin

from contracts.darkpool.library import Darkpool, ExternalTransfer

//
// Initializer
//

// @notice initializes the contract state and sets up the proxy
// @param proxy_admin the admin account for the proxy, controls upgrades
// @param merkle_class the declared contract class of the Merkle tree implementation
// @param nullifier_class the declare contract class of the nullifier set implementation
@external
func initializer{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    proxy_admin: felt, merkle_class: felt, nullifier_class: felt
) {
    Darkpool.initialize(
        proxy_admin=proxy_admin, merkle_class=merkle_class, nullifier_class=nullifier_class
    );
    return ();
}

//
// Upgrades
//

// @notice upgrades the implementation class hash in the proxy contract, only
// callable by the proxy admin
// @param implementation_hash the class hash of the declared implementation
@external
func upgrade{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    implementation_hash: felt
) {
    Proxy.assert_only_admin();
    Proxy._set_implementation_hash(implementation_hash);
    return ();
}

//
// Getters
//

// @dev returns the most recent root of the Merkle state tree
// @return the root at the zero'th index in the root history
@view
func get_root{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (root: felt) {
    // Get the implementation class
    let (root) = Darkpool.get_root();
    return (root=root);
}

// @dev returns whether a given nullifier has already been used
// @return a boolean encoded as a felt -- 1 for true, 0 for false
@view
func is_nullifier_used{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    nullifier: felt
) -> (res: felt) {
    let (res) = Darkpool.nullifier_used(nullifier=nullifier);
    return (res=res);
}

//
// Setters
//

// @dev adds a new wallet to the commitment tree
// @param commitment the commitment to the new wallet
// @return the new root after the wallet is inserted into the tree
@external
func new_wallet{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    commitment: felt
) -> (new_root: felt) {
    let (new_root) = Darkpool.new_wallet(commitment=commitment);
    return (new_root=new_root);
}

// @notice update a wallet in the commitment tree
// @param commitment the commitment to the updated wallet
// @param match_nullifier the wallet match nullifier for the wallet before it was updated
// @param spend_nullifier the wallet spend nullifier for the wallet before it was updated
// @return the root of the state tree after the new commitment is inserted
@external
func update_wallet{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    commitment: felt,
    match_nullifier: felt,
    spend_nullifier: felt,
    external_transfers_len: felt,
    external_transfers: ExternalTransfer*,
) -> (new_root: felt) {
    let (new_root) = Darkpool.update_wallet(
        commitment=commitment,
        match_nullifier=match_nullifier,
        spend_nullifier=spend_nullifier,
        external_transfers_len=external_transfers_len,
        external_transfers=external_transfers,
    );
    return (new_root=new_root);
}
