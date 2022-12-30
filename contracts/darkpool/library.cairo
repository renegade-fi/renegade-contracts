// Groups library methods for the darkpool implementation
%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin

from openzeppelin.upgrades.library import Proxy

from contracts.merkle.IMerkle import IMerkle
from contracts.nullifier.INullifierSet import INullifierSet

//
// Constants
//

// The height of the Merkle tree used for state proofs
const MERKLE_TREE_HEIGHT = 32;

//
// Structs
//

// Represents an external transfer of an ERC20 token
struct ExternalTransfer {
    // The mint (contract address) of the token being transferred
    mint: felt,
    // The amount of the token transferred
    amount: felt,
    // The direction of transfer -- 0 is deposit, 1 is withdraw
    direction: felt,
}

//
// Storage
//

// Stores the implementation class hash for the Merkle tree interface
@storage_var
func Renegade_merkle_class() -> (res: felt) {
}

// Stores the implementation class hash for the Nullifier set interface
@storage_var
func Renegade_nullifier_class() -> (res: felt) {
}

namespace Darkpool {
    // @dev initializes the contract state and sets up the proxy
    // @param proxy_admin the admin account for the proxy, controls upgrades
    // @param merkle_class the declared contract class of the Merkle tree implementation
    // @param nullifier_class the declare contract class of the nullifier set implementation
    func initialize{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
        proxy_admin: felt, merkle_class: felt, nullifier_class: felt
    ) {
        // Setup the UUPS proxy
        Proxy.initializer(proxy_admin);

        // Setup the merkle tree and nullifier set
        IMerkle.library_call_initializer(class_hash=merkle_class, height=MERKLE_TREE_HEIGHT);

        // Write the implementation class hashes to storage
        Renegade_merkle_class.write(value=merkle_class);
        Renegade_nullifier_class.write(value=nullifier_class);

        return ();
    }

    //
    // Getters
    //

    // @dev returns the most recent root of the Merkle state tree
    // @return the root at the zero'th index in the root history
    func get_root{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (
        root: felt
    ) {
        // Get the implementation class
        let (merkle_class) = Renegade_merkle_class.read();
        let (root) = IMerkle.library_call_get_root(class_hash=merkle_class, index=0);
        return (root=root);
    }

    // @dev returns whether a given nullifier has already been used
    // @return a boolean encoded as a felt -- 1 for true, 0 for false
    func nullifier_used{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
        nullifier: felt
    ) -> (res: felt) {
        // Get the implementation class
        let (nullifier_class) = Renegade_nullifier_class.read();
        let (res) = INullifierSet.library_call_is_nullifier_used(
            class_hash=nullifier_class, nullifier=nullifier
        );

        return (res=res);
    }

    //
    // Setters
    //

    // @dev adds a new wallet to the commitment tree
    // @param commitment the commitment to the new wallet
    // @return the new root after the wallet is inserted into the tree
    func new_wallet{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
        commitment: felt
    ) -> (new_root: felt) {
        // TODO: Add verification of VALID WALLET CREATE
        // Insert the new wallet's commitment into the state tree
        let (merkle_class) = Renegade_merkle_class.read();
        let (new_root) = IMerkle.library_call_insert(class_hash=merkle_class, value=commitment);

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
        // TODO: Add verification of VALID WALLET UPDATE
        // Insert the updated commitment into the state tree
        let (merkle_class) = Renegade_merkle_class.read();
        let (new_root) = IMerkle.library_call_insert(class_hash=merkle_class, value=commitment);

        // Add both the match and spend nullifiers to the spent nullifier set
        let (nullifier_class) = Renegade_nullifier_class.read();
        INullifierSet.library_call_mark_nullifier_used(
            class_hash=nullifier_class, nullifier=match_nullifier
        );
        INullifierSet.library_call_mark_nullifier_used(
            class_hash=nullifier_class, nullifier=spend_nullifier
        );

        return (new_root=new_root);
    }
}
