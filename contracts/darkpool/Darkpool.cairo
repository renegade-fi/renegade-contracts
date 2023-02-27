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

// @notice upgrades the implementation class hash of the Merkle tree in the contract
// @param implementation_hash the class hash of the Merkle tree implementation
@external
func upgrade_merkle{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    implementation_hash: felt
) {
    // Only an admin may update the Merkle implementation
    Proxy.assert_only_admin();

    Darkpool.set_merkle_class(class_hash=implementation_hash);
    return ();
}

// @notice upgrades the implementation class hash of the nullifier set in the contract
// @param implementation_hash the class hash of the nullifier set implementation
@external
func upgrade_nullifier{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    implementation_hash: felt
) {
    // Only an admin may update the nullifier set implementation
    Proxy.assert_only_admin();

    Darkpool.set_nullifier_class(class_hash=implementation_hash);
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
    internal_transfer_ciphertext_len: felt,
    internal_transfer_ciphertext: felt*,
    external_transfers_len: felt,
    external_transfers: ExternalTransfer*,
) -> (new_root: felt) {
    let (new_root) = Darkpool.update_wallet(
        commitment=commitment,
        match_nullifier=match_nullifier,
        spend_nullifier=spend_nullifier,
        internal_transfer_ciphertext_len=internal_transfer_ciphertext_len,
        internal_transfer_ciphertext=internal_transfer_ciphertext,
        external_transfers_len=external_transfers_len,
        external_transfers=external_transfers,
    );
    return (new_root=new_root);
}

// @notice encumber two wallets by submitting a successfully completed match to the contract
// @param match_nullifier1 the wallet match nullifier of the first wallet
// @param match_nullifier2 the wallet match nullifier of the second wallet
// @param note1_ciphertext_len the number of felts in the first encrypted note
// @param note1_ciphertext the first note, encrypted under the first party's key
// @param note2_ciphertext_len the number of felts in the second encrypted note
// @param note2_ciphertext the second note, encrypted under the second party's key
// @return the new root after inserting the notes into the commitment tree
@external
func match{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    match_nullifier1: felt,
    match_nullifier2: felt,
    note1_ciphertext_len: felt,
    note1_ciphertext: felt*,
    note2_ciphertext_len: felt,
    note2_ciphertext: felt*,
) -> (new_root: felt) {
    let (new_root) = Darkpool.process_match(
        match_nullifier1=match_nullifier1,
        match_nullifier2=match_nullifier2,
        note1_ciphertext_len=note1_ciphertext_len,
        note1_ciphertext=note1_ciphertext,
        note2_ciphertext_len=note2_ciphertext_len,
        note2_ciphertext=note2_ciphertext,
    );

    return (new_root=new_root);
}

// @dev process a settlement, this involves updating the balance of a wallet by nullifying a note
// @param from_internal_transfer whether or not the note was generated by an internal transfer
// @param wallet_commitment a commitment to the new wallet
// @param match_nullifier the match nullifier of the old wallet
// @param spend_nullifier the spend nullifier of the old wallet
// @param note_redeem_nullifier a nullifier for the note being redeemed into the wallet
// @return the merkle root after update
@external
func settle{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    from_internal_transfer: felt,
    wallet_commitment: felt,
    match_nullifier: felt,
    spend_nullifier: felt,
    note_redeem_nullifier: felt,
) -> (new_root: felt) {
    let (new_root) = Darkpool.process_settle(
        from_internal_transfer=from_internal_transfer,
        wallet_commitment=wallet_commitment,
        match_nullifier=match_nullifier,
        spend_nullifier=spend_nullifier,
        note_redeem_nullifier=note_redeem_nullifier,
    );

    return (new_root=new_root);
}
