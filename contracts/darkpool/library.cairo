// Groups library methods for the darkpool implementation
%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.uint256 import Uint256
from starkware.starknet.common.syscalls import get_caller_address, get_contract_address

from openzeppelin.upgrades.library import Proxy
from openzeppelin.token.erc20.IERC20 import IERC20

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
    amount: Uint256,
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

//
// Events
//

// An event representing a deposit from an external account to the darkpool
@event
func Renegade_deposit(sender: felt, mint: felt, amount: Uint256) {
}

// An event representing a withdraw from the darkpool to an external account
@event
func Renegade_withdraw(recipient: felt, mint: felt, amount: Uint256) {
}

//
// Library methods
//

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

    // @dev update a wallet in the commitment tree
    // @param commitment the commitment to the updated wallet
    // @param match_nullifier the wallet match nullifier for the wallet before it was updated
    // @param spend_nullifier the wallet spend nullifier for the wallet before it was updated
    // @param external_transfers_len the number of external transfers in the update
    // @param external_transfers the transfers to execute outside of the darkpool
    // @return the root of the state tree after the new commitment is inserted
    func update_wallet{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
        commitment: felt,
        match_nullifier: felt,
        spend_nullifier: felt,
        external_transfers_len: felt,
        external_transfers: ExternalTransfer*,
    ) -> (new_root: felt) {
        alloc_locals;

        // TODO: Add verification of VALID WALLET UPDATE
        // Insert the updated commitment into the state tree
        let (merkle_class) = Renegade_merkle_class.read();
        let (local new_root) = IMerkle.library_call_insert(
            class_hash=merkle_class, value=commitment
        );

        // Add both the match and spend nullifiers to the spent nullifier set
        let (nullifier_class) = Renegade_nullifier_class.read();
        INullifierSet.library_call_mark_nullifier_used(
            class_hash=nullifier_class, nullifier=match_nullifier
        );
        INullifierSet.library_call_mark_nullifier_used(
            class_hash=nullifier_class, nullifier=spend_nullifier
        );

        // Process the external transfers
        let (contract_address) = get_contract_address();
        let (caller_address) = get_caller_address();
        _execute_transfers(
            contract_address=contract_address,
            external_address=caller_address,
            transfers_len=external_transfers_len,
            transfers=external_transfers,
        );

        return (new_root=new_root);
    }

    // @dev executes a set of external ERC20 transfers
    // @param contract_address the address of the current contract
    // @param external_address the external address to withdraw to/deposit from
    // @param transfers_len the number of external transfers to execute
    // @param transfers the external transfers to execute
    func _execute_transfers{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
        contract_address: felt,
        external_address: felt,
        transfers_len: felt,
        transfers: ExternalTransfer*,
    ) {
        // Base case
        if (transfers_len == 0) {
            return ();
        }

        // Execute the first transfer in the list
        let next_transfer = transfers[0];

        // Assert that the direction is set as zero or one
        with_attr error_message("direction must be 0 or 1, got {next_transfer.direction}") {
            assert next_transfer.direction * (1 - next_transfer.direction) = 0;
        }

        if (next_transfer.direction == 0) {
            // Deposit
            IERC20.transferFrom(
                contract_address=next_transfer.mint,
                sender=external_address,
                recipient=contract_address,
                amount=next_transfer.amount,
            );

            // Emit an event
            Renegade_deposit.emit(
                sender=external_address, mint=next_transfer.mint, amount=next_transfer.amount
            );
        } else {
            // Withdraw
            IERC20.transfer(
                contract_address=next_transfer.mint,
                recipient=external_address,
                amount=next_transfer.amount,
            );

            // Emit an event
            Renegade_withdraw.emit(
                recipient=external_address, mint=next_transfer.mint, amount=next_transfer.amount
            );
        }

        // Recurse
        _execute_transfers(
            contract_address=contract_address,
            external_address=external_address,
            transfers_len=transfers_len - 1,
            transfers=&transfers[1],
        );
        return ();
    }
}
