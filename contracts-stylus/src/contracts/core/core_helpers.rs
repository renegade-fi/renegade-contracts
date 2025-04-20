//! Helpers for core contracts, mostly around interacting with core state
use core::borrow::{Borrow, BorrowMut};

use crate::{
    assert_result, if_verifying,
    utils::{
        constants::{
            CALL_RETDATA_DECODING_ERROR_MESSAGE, INVALID_ARR_LEN_ERROR_MESSAGE,
            NULLIFIER_SPENT_ERROR_MESSAGE, PUBLIC_BLINDER_USED_ERROR_MESSAGE,
            ROOT_NOT_IN_HISTORY_ERROR_MESSAGE,
        },
        helpers::{
            delegate_call_helper, get_public_blinder_from_shares, postcard_serialize,
            static_call_helper,
        },
        solidity::{
            executeExternalTransferCall, executeTransferBatchCall, insertCommitmentCall,
            insertSharesCommitmentCall, insertSharesWithSigCall, rootInHistoryCall, verifyCall,
            NotePosted, NullifierSpent, WalletUpdated,
        },
    },
    TRANSFER_ARITHMETIC_OVERFLOW_ERROR_MESSAGE, VKEYS_FETCH_ERROR_MESSAGE,
};
use alloc::{vec, vec::Vec};
use alloy_sol_types::{SolCall, SolType};
use contracts_common::{
    custom_serde::{pk_to_u256s, scalar_to_u256},
    types::{
        u256_to_scalar, ExternalMatchResult, ExternalTransfer, FeeTake, PublicEncryptionKey,
        PublicSigningKey, ScalarField, SimpleErc20Transfer,
    },
};
use stylus_sdk::{
    abi::Bytes,
    alloy_primitives::{Address, U256},
    prelude::*,
};

use super::CoreContractStorage;

// -----------------------
// | CORE GETTER HELPERS |
// -----------------------

/// Gets the protocol public encryption key
pub fn get_protocol_public_encryption_key<
    C: CoreContractStorage,
    S: TopLevelStorage + Borrow<C>,
>(
    s: &S,
) -> Result<PublicEncryptionKey, Vec<u8>> {
    let storage = s.borrow();
    let protocol_pubkey_x = storage.protocol_public_encryption_key().get(0).unwrap();
    let protocol_pubkey_y = storage.protocol_public_encryption_key().get(1).unwrap();

    Ok(PublicEncryptionKey {
        x: u256_to_scalar(protocol_pubkey_x)?,
        y: u256_to_scalar(protocol_pubkey_y)?,
    })
}

/// Checks that the given Merkle root is in the root history
pub fn check_root_in_history<C: CoreContractStorage, S: TopLevelStorage + BorrowMut<C>>(
    s: &mut S,
    root: ScalarField,
) -> Result<(), Vec<u8>> {
    let root = scalar_to_u256(root);
    let merkle_address = s.borrow_mut().merkle_address();
    let (res,) = delegate_call_helper::<rootInHistoryCall>(s, merkle_address, (root,))?.into();

    assert_result!(res, ROOT_NOT_IN_HISTORY_ERROR_MESSAGE)
}

/// Fetches the verification keys by their associated method selector on the
/// vkeys contract. This assumes that the vkeys contract method takes no
/// arguments and returns a single `bytes` value.
pub fn fetch_vkeys<C: CoreContractStorage, S: TopLevelStorage + HostAccess + Borrow<C>>(
    s: &S,
    selector: &[u8],
) -> Result<Vec<u8>, Vec<u8>> {
    let storage = s.borrow();
    let vkeys_address = storage.vkeys_address();
    let res =
        s.vm().static_call(&s, vkeys_address, selector).map_err(|_| VKEYS_FETCH_ERROR_MESSAGE)?;

    let vkey_bytes = Bytes::abi_decode(&res, false /* validate */)
        .map_err(|_| CALL_RETDATA_DECODING_ERROR_MESSAGE.to_vec())?
        .0;

    Ok(vkey_bytes.to_vec())
}

/// Calls the verifier contract with the given selector.
///
/// Assumes that the argument type is a single `bytes` value and the return type
/// is a single `bool`.
pub fn call_verifier<Core, S, C>(
    storage: &S,
    args: <C::Parameters<'_> as SolType>::RustType,
) -> Result<C::Return, Vec<u8>>
where
    Core: CoreContractStorage,
    S: TopLevelStorage + Borrow<Core>,
    C: SolCall,
{
    let verifier_address = storage.borrow().verifier_core_address();
    static_call_helper::<C>(storage, verifier_address, args)
}

/// Calls the settlement verifier contract with the given arguments
pub fn call_settlement_verifier<Core, S, C>(
    storage: &S,
    args: <C::Parameters<'_> as SolType>::RustType,
) -> Result<C::Return, Vec<u8>>
where
    Core: CoreContractStorage,
    S: TopLevelStorage + Borrow<Core>,
    C: SolCall,
{
    let verifier_address = storage.borrow().verifier_settlement_address();
    static_call_helper::<C>(storage, verifier_address, args)
}

// -----------------------
// | CORE SETTER HELPERS |
// -----------------------

// --- Nullifier and Blinder Sets --- //

/// Marks the given nullifier as spent
pub fn mark_nullifier_spent<
    C: CoreContractStorage,
    S: TopLevelStorage + HostAccess + BorrowMut<C>,
>(
    s: &mut S,
    nullifier: ScalarField,
) -> Result<(), Vec<u8>> {
    let this = s.borrow_mut();

    let nullifier = scalar_to_u256(nullifier);

    if_verifying!(assert_result!(
        !this.nullifier_set().get(nullifier),
        NULLIFIER_SPENT_ERROR_MESSAGE
    )?);

    this.nullifier_set_mut().insert(nullifier, true);
    log(s.vm(), NullifierSpent { nullifier });
    Ok(())
}

/// Marks the given public blinder as used
pub fn mark_public_blinder_used<C: CoreContractStorage, S: TopLevelStorage + BorrowMut<C>>(
    s: &mut S,
    blinder: ScalarField,
) -> Result<(), Vec<u8>> {
    // First check that the blinder hasn't been used
    let this = s.borrow_mut();
    let blinder = scalar_to_u256(blinder);
    assert_result!(!this.public_blinder_set().get(blinder), PUBLIC_BLINDER_USED_ERROR_MESSAGE)?;

    // Mark the blinder as used
    this.public_blinder_set_mut().insert(blinder, true);
    Ok(())
}

// --- Merkle Tree --- //

/// Inserts a wallet commitment directly into the Merkle tree, without hashing
/// shares to generate the commitment
///
/// This method is used for wallet rotations in which the full wallet commitment
/// is computed in-circuit
pub fn insert_commitment_into_tree<C: CoreContractStorage, S: TopLevelStorage + BorrowMut<C>>(
    s: &mut S,
    commitment: ScalarField,
) -> Result<(), Vec<u8>> {
    let storage = s.borrow_mut();
    let merkle_address = storage.merkle_address();
    let commitment_u256 = scalar_to_u256(commitment);
    delegate_call_helper::<insertCommitmentCall>(s, merkle_address, (commitment_u256,))?;

    Ok(())
}

/// Prepares the wallet shares for insertion into the Merkle tree by converting
/// them to a vector of [`U256`]
pub fn prepare_wallet_shares_for_insertion(
    private_shares_commitment: ScalarField,
    public_wallet_shares: &[ScalarField],
) -> Vec<U256> {
    let mut total_wallet_shares = vec![scalar_to_u256(private_shares_commitment)];
    for share in public_wallet_shares {
        total_wallet_shares.push(scalar_to_u256(*share));
    }
    total_wallet_shares
}

/// Prepares the private shares commitment & public wallet shares for insertion
/// into the Merkle tree and delegate-calls the appropriate method on the Merkle
/// contract
pub fn insert_wallet_shares_into_tree<C: CoreContractStorage, S: TopLevelStorage + BorrowMut<C>>(
    s: &mut S,
    private_shares_commitment: ScalarField,
    public_wallet_shares: &[ScalarField],
) -> Result<(), Vec<u8>> {
    let total_wallet_shares =
        prepare_wallet_shares_for_insertion(private_shares_commitment, public_wallet_shares);

    let storage = s.borrow_mut();
    let merkle_address = storage.merkle_address();
    delegate_call_helper::<insertSharesCommitmentCall>(s, merkle_address, (total_wallet_shares,))
        .map(|_| ())
}

/// Prepares the private shares commitment & public wallet shares for insertion
/// into the Merkle tree, as well as the signature & pubkey for verification,
/// and delegate-calls the appropriate method on the Merkle contract
pub fn insert_signed_shares_into_tree<C: CoreContractStorage, S: TopLevelStorage + BorrowMut<C>>(
    s: &mut S,
    private_shares_commitment: ScalarField,
    public_wallet_shares: &[ScalarField],
    wallet_commitment_signature: Vec<u8>,
    old_pk_root: &PublicSigningKey,
) -> Result<(), Vec<u8>> {
    let total_wallet_shares =
        prepare_wallet_shares_for_insertion(private_shares_commitment, public_wallet_shares);

    let merkle_address = s.borrow_mut().merkle_address();

    let old_pk_root_u256s =
        pk_to_u256s(old_pk_root).map_err(|_| INVALID_ARR_LEN_ERROR_MESSAGE.to_vec())?;

    delegate_call_helper::<insertSharesWithSigCall>(
        s,
        merkle_address,
        (total_wallet_shares, wallet_commitment_signature.to_vec().into(), old_pk_root_u256s),
    )
    .map(|_| ())
}

/// Verifies the given proof using the given public inputs
/// & verification key.
pub fn verify<C: CoreContractStorage, S: TopLevelStorage + BorrowMut<C>>(
    s: &mut S,
    vkey_ser: Vec<u8>,
    proof_ser: Vec<u8>,
    public_inputs_ser: Vec<u8>,
) -> Result<bool, Vec<u8>> {
    let verification_bundle_ser = [vkey_ser, proof_ser, public_inputs_ser].concat();
    let result = call_verifier::<_, _, verifyCall>(s, (verification_bundle_ser.into(),))?;

    Ok(result._0)
}

// --------------------
// | Transfer Helpers |
// --------------------

/// Execute the transfers to/from the external party in an atomic match
/// settlement.
///
/// Returns the amount received by the external party, less of fees
#[cfg(any(feature = "core-atomic-match-settle", feature = "core-malleable-match-settle"))]
pub fn execute_atomic_match_transfers<
    C: CoreContractStorage,
    S: TopLevelStorage + HostAccess + BorrowMut<C>,
>(
    storage: &mut S,
    receiver: Address,
    fees: FeeTake,
    match_result: ExternalMatchResult,
    relayer_fee_address: Address,
) -> Result<U256, Vec<u8>> {
    /// The number of transfers to execute in an atomic match settlement
    const N_TRANSFERS: usize = 4;
    let tx_sender = storage.vm().msg_sender();

    let mut transfers_batch = Vec::with_capacity(N_TRANSFERS);
    let (send_mint, send_amount) = match_result.external_party_sell_mint_amount();
    let (receive_mint, receive_amount) = match_result.external_party_buy_mint_amount();

    // The fee charged by the relayer to the external party
    transfers_batch.push(SimpleErc20Transfer::new_withdraw(
        relayer_fee_address,
        receive_mint,
        fees.relayer_fee,
    ));

    // The fee charged by the protocol to the external party
    let protocol_fee_address = storage.borrow_mut().protocol_external_fee_collection_address();
    transfers_batch.push(SimpleErc20Transfer::new_withdraw(
        protocol_fee_address,
        receive_mint,
        fees.protocol_fee,
    ));

    // The amount received by the external party after deducting the fees
    let trader_take = receive_amount
        .checked_sub(fees.total())
        .ok_or(TRANSFER_ARITHMETIC_OVERFLOW_ERROR_MESSAGE)?;

    transfers_batch.push(SimpleErc20Transfer::new_withdraw(receiver, receive_mint, trader_take));

    // The amount sent by the external party to the darkpool
    transfers_batch.push(SimpleErc20Transfer::new_deposit(tx_sender, send_mint, send_amount));

    execute_simple_transfers(storage, transfers_batch)?;

    Ok(trader_take)
}

/// Executes a list of simple ERC20 transfers
#[cfg(any(feature = "core-atomic-match-settle", feature = "core-malleable-match-settle"))]
pub fn execute_simple_transfers<C: CoreContractStorage, S: TopLevelStorage + BorrowMut<C>>(
    storage: &mut S,
    transfers: Vec<SimpleErc20Transfer>,
) -> Result<(), Vec<u8>> {
    let transfer_executor_address = storage.borrow_mut().transfer_executor_address();
    let calldata = postcard_serialize(&transfers)?;
    delegate_call_helper::<executeTransferBatchCall>(
        storage,
        transfer_executor_address,
        (calldata.into(),),
    )
    .map(|_| ())
}

/// Executes the given external transfer (withdrawal / deposit)
pub fn execute_external_transfer<C: CoreContractStorage, S: TopLevelStorage + BorrowMut<C>>(
    s: &mut S,
    old_pk_root: PublicSigningKey,
    transfer: ExternalTransfer,
    transfer_aux_data_bytes: Bytes,
) -> Result<(), Vec<u8>> {
    let transfer_executor_address = s.borrow_mut().transfer_executor_address();
    let old_pk_root_bytes = postcard_serialize(&old_pk_root)?;
    let transfer_bytes = postcard_serialize(&transfer)?;

    delegate_call_helper::<executeExternalTransferCall>(
        s,
        transfer_executor_address,
        (
            old_pk_root_bytes.to_vec().into(),
            transfer_bytes.to_vec().into(),
            transfer_aux_data_bytes.0.to_vec().into(),
        ),
    )?;

    Ok(())
}

// -------------------
// | Wallet Rotation |
// -------------------

/// Nullifies the old wallet and commits to the new wallet
pub fn rotate_wallet<C: CoreContractStorage, S: TopLevelStorage + HostAccess + BorrowMut<C>>(
    s: &mut S,
    old_wallet_nullifier: ScalarField,
    merkle_root: ScalarField,
    new_wallet_private_shares_commitment: ScalarField,
    new_wallet_public_shares: &[ScalarField],
) -> Result<(), Vec<u8>> {
    check_wallet_rotation(s, old_wallet_nullifier, merkle_root, new_wallet_public_shares)?;
    insert_wallet_shares_into_tree(
        s,
        new_wallet_private_shares_commitment,
        new_wallet_public_shares,
    )
}

/// Nullifies the old wallet and commits to the new wallet,
/// verifying a signature over the commitment to the new wallet
pub fn rotate_wallet_with_signature<
    C: CoreContractStorage,
    S: TopLevelStorage + HostAccess + BorrowMut<C>,
>(
    s: &mut S,
    old_wallet_nullifier: ScalarField,
    merkle_root: ScalarField,
    new_wallet_private_shares_commitment: ScalarField,
    new_wallet_public_shares: &[ScalarField],
    new_wallet_commitment_signature: Vec<u8>,
    old_pk_root: PublicSigningKey,
) -> Result<(), Vec<u8>> {
    check_wallet_rotation(s, old_wallet_nullifier, merkle_root, new_wallet_public_shares)?;
    insert_signed_shares_into_tree(
        s,
        new_wallet_private_shares_commitment,
        new_wallet_public_shares,
        new_wallet_commitment_signature,
        &old_pk_root,
    )
}

/// Attempts to nullify the old wallet, ensures that the given Merkle
/// root is a valid historical root, and marks the public blinder as used.
/// Logs the wallet update if successful.
pub fn check_wallet_rotation<
    C: CoreContractStorage,
    S: TopLevelStorage + HostAccess + BorrowMut<C>,
>(
    s: &mut S,
    old_wallet_nullifier: ScalarField,
    merkle_root: ScalarField,
    new_wallet_public_shares: &[ScalarField],
) -> Result<(), Vec<u8>> {
    check_root_and_nullify(s, old_wallet_nullifier, merkle_root)?;
    log_blinder_used(s, new_wallet_public_shares)?;

    Ok(())
}

/// Checks that the given Merkle root is a valid historical root,
/// and marks the nullifier as spent.
pub fn check_root_and_nullify<
    C: CoreContractStorage,
    S: TopLevelStorage + HostAccess + BorrowMut<C>,
>(
    s: &mut S,
    nullifier: ScalarField,
    merkle_root: ScalarField,
) -> Result<(), Vec<u8>> {
    if_verifying!({
        check_root_in_history(s, merkle_root)?;
    });

    mark_nullifier_spent(s, nullifier)
}

/// Commits the given note commitment in the Merkle tree
pub fn commit_note<C: CoreContractStorage, S: TopLevelStorage + HostAccess + BorrowMut<C>>(
    s: &mut S,
    note_commitment: ScalarField,
) -> Result<(), Vec<u8>> {
    let note_commitment_u256 = scalar_to_u256(note_commitment);
    let merkle_address = s.borrow_mut().merkle_address();
    delegate_call_helper::<insertCommitmentCall>(s, merkle_address, (note_commitment_u256,))?;

    log(s.vm(), NotePosted { note_commitment: note_commitment_u256 });

    Ok(())
}

// -----------
// | LOGGING |
// -----------

/// Emits a `WalletUpdated` event with the wallet's public blinder share
pub fn log_blinder_used<C: CoreContractStorage, S: TopLevelStorage + HostAccess + BorrowMut<C>>(
    s: &mut S,
    public_wallet_shares: &[ScalarField],
) -> Result<(), Vec<u8>> {
    // Mark the public blinder as used
    let wallet_blinder_share = get_public_blinder_from_shares(public_wallet_shares);
    mark_public_blinder_used(s, wallet_blinder_share)?;

    // Log the wallet update
    let blinder_u256 = scalar_to_u256(wallet_blinder_share);
    log(s.vm(), WalletUpdated { wallet_blinder_share: blinder_u256 });

    Ok(())
}
