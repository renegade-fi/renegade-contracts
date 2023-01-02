// Groups library methods for the darkpool implementation
%lang starknet

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.hash_chain import hash_chain
from starkware.cairo.common.memcpy import memcpy
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
func Darkpool_merkle_class() -> (res: felt) {
}

// Stores the implementation class hash for the Nullifier set interface
@storage_var
func Darkpool_nullifier_class() -> (res: felt) {
}

//
// Events
//

// An event representing a deposit from an external account to the darkpool
@event
func Darkpool_deposit(sender: felt, mint: felt, amount: Uint256) {
}

// An event representing a withdraw from the darkpool to an external account
@event
func Darkpool_withdraw(recipient: felt, mint: felt, amount: Uint256) {
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
        Darkpool_merkle_class.write(value=merkle_class);
        Darkpool_nullifier_class.write(value=nullifier_class);

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
        let (merkle_class) = Darkpool_merkle_class.read();
        let (root) = IMerkle.library_call_get_root(class_hash=merkle_class, index=0);
        return (root=root);
    }

    // @dev returns whether a given nullifier has already been used
    // @return a boolean encoded as a felt -- 1 for true, 0 for false
    func nullifier_used{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
        nullifier: felt
    ) -> (res: felt) {
        // Get the implementation class
        let (nullifier_class) = Darkpool_nullifier_class.read();
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
        let (merkle_class) = Darkpool_merkle_class.read();
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
        internal_transfer_ciphertext_len: felt,
        internal_transfer_ciphertext: felt*,
        external_transfers_len: felt,
        external_transfers: ExternalTransfer*,
    ) -> (new_root: felt) {
        alloc_locals;

        // TODO: Add verification of VALID WALLET UPDATE
        // Insert the updated commitment into the state tree
        let (merkle_class) = Darkpool_merkle_class.read();
        let (local new_root) = IMerkle.library_call_insert(
            class_hash=merkle_class, value=commitment
        );

        // Add both the match and spend nullifiers to the spent nullifier set
        let (nullifier_class) = Darkpool_nullifier_class.read();
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

        // Process the internal transfer if one exists
        if (internal_transfer_ciphertext_len == 0) {
            return (new_root=new_root);
        }

        let (transfer_commitment) = _hash_array(
            internal_transfer_ciphertext_len, internal_transfer_ciphertext
        );
        let (new_root) = IMerkle.library_call_insert(
            class_hash=merkle_class, value=transfer_commitment
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
            Darkpool_deposit.emit(
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
            Darkpool_withdraw.emit(
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

    // @dev encumber two wallets that have matched
    // @param match_nullifier1 the wallet match nullifier of the first wallet
    // @param match_nullifier2 the wallet match nullifier of the second wallet
    // @param note1_ciphertext_len the number of felts in the first encrypted note
    // @param note1_ciphertext the first note, encrypted under the first party's key
    // @param note2_ciphertext_len the number of felts in the second encrypted note
    // @param note2_ciphertext the second note, encrypted under the second party's key
    // @return the new root after inserting the notes into the commitment tree
    func process_match{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
        match_nullifier1: felt,
        match_nullifier2: felt,
        note1_ciphertext_len: felt,
        note1_ciphertext: felt*,
        note2_ciphertext_len: felt,
        note2_ciphertext: felt*,
    ) -> (new_root: felt) {
        alloc_locals;

        // Insert the nullifiers into the nullifier set
        let (nullifier_class) = Darkpool_nullifier_class.read();
        INullifierSet.library_call_mark_nullifier_used(
            class_hash=nullifier_class, nullifier=match_nullifier1
        );
        INullifierSet.library_call_mark_nullifier_used(
            class_hash=nullifier_class, nullifier=match_nullifier2
        );

        // Hash the note ciphertexts and add them to the commitment tree
        let (local merkle_class) = Darkpool_merkle_class.read();
        let (hash_note1) = _hash_array(note1_ciphertext_len, note1_ciphertext);
        IMerkle.library_call_insert(class_hash=merkle_class, value=hash_note1);

        let (hash_note2) = _hash_array(note2_ciphertext_len, note2_ciphertext);
        let (new_root) = IMerkle.library_call_insert(class_hash=merkle_class, value=hash_note2);

        return (new_root=new_root);
    }

    // @dev helper to hash an array of values
    // @param data_len the number of felts to hash
    // @param data a pointer to the data being hashed
    // @return the hash of the data computed as per:
    // https://docs.starknet.io/documentation/architecture_and_concepts/Hashing/hash-functions/#array_hashing
    func _hash_array{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
        data_len: felt, data: felt*
    ) -> (hash: felt) {
        alloc_locals;

        // Allocate a segment for the payload to be hashed from
        let (local hash_payload: felt*) = alloc();
        hash_payload[0] = data_len;

        memcpy(&hash_payload[1], data, data_len);

        // Hash the payload with a chained pedersen hash
        let (hash) = hash_chain{hash_ptr=pedersen_ptr}(hash_payload);
        return (hash=hash);
    }

    // @dev process a settlement, this involves updating the balance of a wallet by nullifying a note
    // @param from_internal_transfer whether or not the note was generated by an internal transfer
    // @param wallet_commitment a commitment to the new wallet
    // @param match_nullifier the match nullifier of the old wallet
    // @param spend_nullifier the spend nullifier of the old wallet
    // @param note_redeem_nullifier a nullifier for the note being redeemed into the wallet
    // @return the merkle root after update
    func process_settle{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
        from_internal_transfer: felt,
        wallet_commitment: felt,
        match_nullifier: felt,
        spend_nullifier: felt,
        note_redeem_nullifier: felt,
    ) -> (new_root: felt) {
        // Assert that the value is boolean
        assert from_internal_transfer * (1 - from_internal_transfer) = 0;

        // Insert the nullifiers into the set
        let (nullifier_class) = Darkpool_nullifier_class.read();
        INullifierSet.library_call_mark_nullifier_used(
            class_hash=nullifier_class, nullifier=spend_nullifier
        );
        INullifierSet.library_call_mark_nullifier_used(
            class_hash=nullifier_class, nullifier=note_redeem_nullifier
        );

        // If the redeemed note came from an internal transfer; no call to `match` was made
        // to nullify the match_nullifier, do so now
        if (from_internal_transfer == 1) {
            INullifierSet.library_call_mark_nullifier_used(
                class_hash=nullifier_class, nullifier=match_nullifier
            );

            // Rebind implicit args
            tempvar syscall_ptr = syscall_ptr;
            tempvar pedersen_ptr = pedersen_ptr;
            tempvar range_check_ptr = range_check_ptr;
        } else {
            tempvar syscall_ptr = syscall_ptr;
            tempvar pedersen_ptr = pedersen_ptr;
            tempvar range_check_ptr = range_check_ptr;
        }

        // Insert the new commitment into the merkle tree
        let (merkle_class) = Darkpool_merkle_class.read();
        let (new_root) = IMerkle.library_call_insert(
            class_hash=merkle_class, value=wallet_commitment
        );

        return (new_root=new_root);
    }
}
