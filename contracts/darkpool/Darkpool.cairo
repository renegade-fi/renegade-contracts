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

// @notice returns the hash of the most recent transaction to update a given wallet
// as identified by pk_view
// @return the tx hash
@view
func get_wallet_update{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    pk_view: felt
) -> (tx_hash: felt) {
    let (tx_hash) = Darkpool.get_wallet_update(pk_view=pk_view);
    return (tx_hash=tx_hash);
}

// @notice returns the most recent root of the Merkle state tree
// @return the root at the zero'th index in the root history
@view
func get_root{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (root: felt) {
    // Get the implementation class
    let (root) = Darkpool.get_root();
    return (root=root);
}

// @notice returns whether the given root is in the history
// @param the root to check the history for
// @return 1 if the root is in the history, 0 if it is not
@view
func root_in_history{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    root: felt
) -> (res: felt) {
    let (res) = Darkpool.root_in_history(root=root);
    return (res=res);
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
// @param pk_view the public view key of the wallet, used for indexing
// @param commitment the commitment to the new wallet
// @param encryption_blob the wallet's ciphertext blob
// @param proof_blob the proof of `VALID NEW WALLET`
// @return the new root after the wallet is inserted into the tree
@external
func new_wallet{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    pk_view: felt,
    commitment: felt,
    encryption_blob_len: felt,
    encryption_blob: felt*,
    proof_blob_len: felt,
    proof_blob: felt*,
) -> (new_root: felt) {
    let (new_root) = Darkpool.new_wallet(commitment=commitment);

    Darkpool.mark_wallet_updated(pk_view=pk_view);
    return (new_root=new_root);
}

// @notice update a wallet in the commitment tree
// @param pk_view the public view key of the wallet, used for indexing
// @param commitment the commitment to the updated wallet
// @param match_nullifier the wallet match nullifier for the wallet before it was updated
// @param spend_nullifier the wallet spend nullifier for the wallet before it was updated
// @param internal_transfer_ciphertext the encryption of an internal transfer if present
// @param external_transfers the external transfers (ERC20 deposit/withdrawl)
// @param encryption_blob the encryption of the updated wallet
// @param proof_blob the proof of `VALID WALLET UPDATE`
// @return the root of the state tree after the new commitment is inserted
@external
func update_wallet{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    pk_view: felt,
    commitment: felt,
    match_nullifier: felt,
    spend_nullifier: felt,
    internal_transfer_ciphertext_len: felt,
    internal_transfer_ciphertext: felt*,
    external_transfers_len: felt,
    external_transfers: ExternalTransfer*,
    encryption_blob_len: felt,
    encryption_blob: felt*,
    proof_blob_len: felt,
    proof_blob: felt*,
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

    Darkpool.mark_wallet_updated(pk_view=pk_view);
    return (new_root=new_root);
}

// @notice encumber two wallets by submitting a successfully completed match to the contract
// @dev for now the arguments are overly verbose, considering that we'll be rewriting this all
// in Cairo 1.0 soon, it's not worth cleaning this up for now.
@external
func match{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    match_nullifier1: felt,
    match_nullifier2: felt,
    party0_note_commit: felt,
    party0_note_ciphertext_len: felt,
    party0_note_ciphertext: felt*,
    party1_note_commit: felt,
    party1_note_ciphertext_len: felt,
    party1_note_ciphertext: felt*,
    relayer0_note_commit: felt,
    relayer0_note_ciphertext_len: felt,
    relayer0_note_ciphertext: felt*,
    relayer1_note_commit: felt,
    relayer1_note_ciphertext_len: felt,
    relayer1_note_ciphertext: felt*,
    protocol_note_commit: felt,
    protocol_note_ciphertext_len: felt,
    protocol_note_ciphertext: felt*,
    proof_blob_len: felt,
    proof_blob: felt*,
) -> (new_root: felt) {
    let (new_root) = Darkpool.process_match(
        match_nullifier1=match_nullifier1,
        match_nullifier2=match_nullifier2,
        party0_note_commit=party0_note_commit,
        party1_note_commit=party1_note_commit,
        relayer0_note_commit=relayer0_note_commit,
        relayer1_note_commit=relayer1_note_commit,
        protocol_note_commit=protocol_note_commit,
    );

    return (new_root=new_root);
}

// @dev process a settlement, this involves updating the balance of a wallet by nullifying a note
// @param pk_view the public view key of the wallet being updated, used for indexing
// @param from_internal_transfer whether or not the note was generated by an internal transfer
// @param wallet_commitment a commitment to the new wallet
// @param match_nullifier the match nullifier of the old wallet
// @param spend_nullifier the spend nullifier of the old wallet
// @param note_redeem_nullifier a nullifier for the note being redeemed into the wallet
// @return the merkle root after update
@external
func settle{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    pk_view: felt,
    from_internal_transfer: felt,
    wallet_commitment: felt,
    match_nullifier: felt,
    spend_nullifier: felt,
    note_redeem_nullifier: felt,
    wallet_ciphertext_len: felt,
    wallet_ciphertext: felt*,
    proof_blob_len: felt,
    proof_blob: felt*,
) -> (new_root: felt) {
    let (new_root) = Darkpool.process_settle(
        from_internal_transfer=from_internal_transfer,
        wallet_commitment=wallet_commitment,
        match_nullifier=match_nullifier,
        spend_nullifier=spend_nullifier,
        note_redeem_nullifier=note_redeem_nullifier,
    );

    Darkpool.mark_wallet_updated(pk_view=pk_view);
    return (new_root=new_root);
}
