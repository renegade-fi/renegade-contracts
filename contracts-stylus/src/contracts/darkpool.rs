//! The darkpool smart contract, responsible for maintaining the set of nullified wallets,
//! verifying the various proofs of the Renegade protocol, and handling deposits / withdrawals.

use alloc::{vec, vec::Vec};
use core::borrow::{Borrow, BorrowMut};
use stylus_sdk::{
    abi::Bytes,
    alloy_primitives::{Address, U256, U64},
    evm, msg,
    prelude::*,
    storage::{StorageAddress, StorageArray, StorageBool, StorageMap, StorageU256, StorageU64},
};

use crate::{
    assert_result,
    utils::{
        constants::{
            INVALID_VERSION_ERROR_MESSAGE, MERKLE_STORAGE_GAP_SIZE, NOT_OWNER_ERROR_MESSAGE,
            PAUSED_ERROR_MESSAGE, TRANSFER_EXECUTOR_STORAGE_GAP_SIZE, UNPAUSED_ERROR_MESSAGE,
            ZERO_ADDRESS_ERROR_MESSAGE, ZERO_FEE_ERROR_MESSAGE,
        },
        helpers::delegate_call_helper,
        solidity::{
            init_0Call as initMerkleCall, init_1Call as initTransferExecutorCall, newWalletCall,
            processMatchSettleCall, redeemFeeCall, rootCall, rootInHistoryCall,
            settleOfflineFeeCall, settleOnlineRelayerFeeCall, updateWalletCall,
            DarkpoolCoreAddressChanged, FeeChanged, MerkleAddressChanged, OwnershipTransferred,
            Paused, PubkeyRotated, TransferExecutorAddressChanged, Unpaused,
            VerifierAddressChanged, VkeysAddressChanged,
        },
    },
};

/// The darkpool contract's storage layout
#[solidity_storage]
#[cfg_attr(feature = "darkpool", entrypoint)]
pub struct DarkpoolContract {
    /// Storage gap to prevent collisions with the Merkle contract
    __merkle_gap: StorageArray<StorageU256, MERKLE_STORAGE_GAP_SIZE>,

    /// Storage gap to prevent collisions with the transfer executor contract
    __transfer_executor_gap: StorageArray<StorageU256, TRANSFER_EXECUTOR_STORAGE_GAP_SIZE>,

    /// The owner of the darkpool contract
    owner: StorageAddress,

    /// Whether or not the darkpool has been initialized
    initialized: StorageU64,

    /// Whether or not the darkpool is paused
    paused: StorageBool,

    /// The address of the darkpool core contract
    pub(crate) darkpool_core_address: StorageAddress,

    /// The address of the verifier contract
    pub(crate) verifier_address: StorageAddress,

    /// The address of the vkeys contract
    pub(crate) vkeys_address: StorageAddress,

    /// The address of the Merkle contract
    pub(crate) merkle_address: StorageAddress,

    /// The address of the transfer executor contract
    pub(crate) transfer_executor_address: StorageAddress,

    /// The set of wallet nullifiers, representing a mapping from a nullifier
    /// (which is a Bn254 scalar field element serialized into 32 bytes) to a
    /// boolean indicating whether or not the nullifier is spent
    nullifier_set: StorageMap<U256, StorageBool>,

    /// The set of public blinder shares used by wallets committed into the darkpool
    ///
    /// We disallow re-use of public blinder shares to prevent clients indexing the
    /// pool from seeing conflicting wallet shares
    public_blinder_set: StorageMap<U256, StorageBool>,

    /// The protocol fee, representing a percentage of the trade volume
    /// as a fixed-point number shifted by 32 bits.
    ///
    /// I.e., the fee is `protocol_fee / 2^32`
    protocol_fee: StorageU256,

    /// The BabyJubJub EC-ElGamal public encryption key for the protocol
    protocol_public_encryption_key: StorageArray<StorageU256, 2>,
}

#[external]
impl DarkpoolContract {
    // -----------------
    // | INITIALIZABLE |
    // -----------------

    /// Initializes the Darkpool
    #[allow(clippy::too_many_arguments)]
    pub fn initialize<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        darkpool_core_address: Address,
        verifier_address: Address,
        vkeys_address: Address,
        merkle_address: Address,
        transfer_executor_address: Address,
        permit2_address: Address,
        protocol_fee: U256,
        protocol_public_encryption_key: [U256; 2],
    ) -> Result<(), Vec<u8>> {
        // Initialize the Merkle tree
        delegate_call_helper::<initMerkleCall>(storage, merkle_address, ())?;

        // Initialize the transfer executor
        delegate_call_helper::<initTransferExecutorCall>(
            storage,
            transfer_executor_address,
            (permit2_address,),
        )?;

        // Set the stored addresses
        DarkpoolContract::_transfer_ownership(storage, msg::sender());
        DarkpoolContract::set_darkpool_core_address(storage, darkpool_core_address)?;
        DarkpoolContract::set_verifier_address(storage, verifier_address)?;
        DarkpoolContract::set_vkeys_address(storage, vkeys_address)?;
        DarkpoolContract::set_merkle_address(storage, merkle_address)?;
        DarkpoolContract::set_transfer_executor_address(storage, transfer_executor_address)?;

        // Set the protocol fee
        DarkpoolContract::set_fee(storage, protocol_fee)?;

        // Set the protocol public encryption key
        DarkpoolContract::set_public_encryption_key(storage, protocol_public_encryption_key)?;

        // Mark the darkpool as initialized
        DarkpoolContract::_initialize(storage, 1)?;

        Ok(())
    }

    // -----------
    // | OWNABLE |
    // -----------

    /// Returns the current owner of the darkpool
    pub fn owner<S: TopLevelStorage + Borrow<Self>>(storage: &S) -> Result<Address, Vec<u8>> {
        Ok(storage.borrow().owner.get())
    }

    /// Transfers ownership of the darkpool to the provided address
    pub fn transfer_ownership<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        new_owner: Address,
    ) -> Result<(), Vec<u8>> {
        DarkpoolContract::_check_owner(storage)?;

        DarkpoolContract::check_address_not_zero(new_owner)?;
        DarkpoolContract::_transfer_ownership(storage, new_owner);

        Ok(())
    }

    // ------------
    // | PAUSABLE |
    // ------------

    /// Returns whether or not the darkpool is paused
    pub fn paused<S: TopLevelStorage + Borrow<Self>>(storage: &S) -> Result<bool, Vec<u8>> {
        Ok(storage.borrow().paused.get())
    }

    /// Pauses the darkpool
    pub fn pause<S: TopLevelStorage + BorrowMut<Self>>(storage: &mut S) -> Result<(), Vec<u8>> {
        DarkpoolContract::_check_owner(storage)?;
        DarkpoolContract::_check_not_paused(storage)?;
        storage.borrow_mut().paused.set(true);
        evm::log(Paused {});
        Ok(())
    }

    /// Unpauses the darkpool
    pub fn unpause<S: TopLevelStorage + BorrowMut<Self>>(storage: &mut S) -> Result<(), Vec<u8>> {
        DarkpoolContract::_check_owner(storage)?;
        DarkpoolContract::_check_paused(storage)?;
        storage.borrow_mut().paused.set(false);
        evm::log(Unpaused {});
        Ok(())
    }

    // -----------
    // | GETTERS |
    // -----------

    /// Checks whether the given nullifier is spent
    pub fn is_nullifier_spent<S: TopLevelStorage + Borrow<Self>>(
        storage: &S,
        nullifier: U256,
    ) -> Result<bool, Vec<u8>> {
        let this = storage.borrow();
        Ok(this.nullifier_set.get(nullifier))
    }

    /// Checks whether the given public blinder share has been used
    pub fn is_public_blinder_used<S: TopLevelStorage + Borrow<Self>>(
        storage: &S,
        blinder: U256,
    ) -> Result<bool, Vec<u8>> {
        let this = storage.borrow();
        Ok(this.public_blinder_set.get(blinder))
    }

    /// Returns the current root of the Merkle tree
    pub fn get_root<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
    ) -> Result<U256, Vec<u8>> {
        let merkle_address = storage.borrow_mut().merkle_address.get();
        let (res,) = delegate_call_helper::<rootCall>(storage, merkle_address, ())?.into();
        Ok(res)
    }

    /// Returns whether or not the given root is a valid historical Merkle root
    pub fn root_in_history<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        root: U256,
    ) -> Result<bool, Vec<u8>> {
        let merkle_address = storage.borrow_mut().merkle_address.get();
        let (res,) =
            delegate_call_helper::<rootInHistoryCall>(storage, merkle_address, (root,))?.into();

        Ok(res)
    }

    /// Returns the protocol fee
    pub fn get_fee<S: TopLevelStorage + Borrow<Self>>(storage: &S) -> Result<U256, Vec<u8>> {
        Ok(storage.borrow().protocol_fee.get())
    }

    /// Returns the protocol public encryption key
    pub fn get_pubkey<S: TopLevelStorage + Borrow<Self>>(
        storage: &S,
    ) -> Result<[U256; 2], Vec<u8>> {
        Ok(DarkpoolContract::_get_protocol_pubkey_coords(storage))
    }

    // -----------
    // | SETTERS |
    // -----------

    /// Set the protocol fee
    pub fn set_fee<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        new_fee: U256,
    ) -> Result<(), Vec<u8>> {
        DarkpoolContract::_check_owner(storage)?;
        assert_result!(new_fee != U256::ZERO, ZERO_FEE_ERROR_MESSAGE)?;
        storage.borrow_mut().protocol_fee.set(new_fee);
        evm::log(FeeChanged { new_fee });
        Ok(())
    }

    /// Set the protocol public encryption key
    pub fn set_public_encryption_key<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        new_public_encryption_key: [U256; 2],
    ) -> Result<(), Vec<u8>> {
        DarkpoolContract::_check_owner(storage)?;
        let mut pubkey_x = storage
            .borrow_mut()
            .protocol_public_encryption_key
            .setter(0)
            .unwrap();
        pubkey_x.set(new_public_encryption_key[0]);

        let mut pubkey_y = storage
            .borrow_mut()
            .protocol_public_encryption_key
            .setter(1)
            .unwrap();
        pubkey_y.set(new_public_encryption_key[1]);

        evm::log(PubkeyRotated {
            new_pubkey_x: new_public_encryption_key[0],
            new_pubkey_y: new_public_encryption_key[1],
        });

        Ok(())
    }

    /// Sets the darkpool core address
    pub fn set_darkpool_core_address<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        darkpool_core_address: Address,
    ) -> Result<(), Vec<u8>> {
        DarkpoolContract::_check_owner(storage)?;

        DarkpoolContract::check_address_not_zero(darkpool_core_address)?;
        storage
            .borrow_mut()
            .darkpool_core_address
            .set(darkpool_core_address);

        evm::log(DarkpoolCoreAddressChanged {
            new_address: darkpool_core_address,
        });

        Ok(())
    }

    /// Sets the verifier address
    pub fn set_verifier_address<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        verifier_address: Address,
    ) -> Result<(), Vec<u8>> {
        DarkpoolContract::_check_owner(storage)?;
        DarkpoolContract::check_address_not_zero(verifier_address)?;
        storage.borrow_mut().verifier_address.set(verifier_address);
        evm::log(VerifierAddressChanged {
            new_address: verifier_address,
        });
        Ok(())
    }

    /// Sets the vkeys address
    pub fn set_vkeys_address<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        vkeys_address: Address,
    ) -> Result<(), Vec<u8>> {
        DarkpoolContract::_check_owner(storage)?;
        DarkpoolContract::check_address_not_zero(vkeys_address)?;
        storage.borrow_mut().vkeys_address.set(vkeys_address);
        evm::log(VkeysAddressChanged {
            new_address: vkeys_address,
        });
        Ok(())
    }

    /// Sets the Merkle address
    pub fn set_merkle_address<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        merkle_address: Address,
    ) -> Result<(), Vec<u8>> {
        DarkpoolContract::_check_owner(storage)?;
        DarkpoolContract::check_address_not_zero(merkle_address)?;
        storage.borrow_mut().merkle_address.set(merkle_address);
        evm::log(MerkleAddressChanged {
            new_address: merkle_address,
        });
        Ok(())
    }

    /// Sets the transfer executor address
    pub fn set_transfer_executor_address<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        transfer_executor_address: Address,
    ) -> Result<(), Vec<u8>> {
        DarkpoolContract::_check_owner(storage)?;
        DarkpoolContract::check_address_not_zero(transfer_executor_address)?;

        storage
            .borrow_mut()
            .transfer_executor_address
            .set(transfer_executor_address);

        evm::log(TransferExecutorAddressChanged {
            new_address: transfer_executor_address,
        });
        Ok(())
    }

    // ----------------
    // | CORE METHODS |
    // ----------------

    /// Adds a new wallet to the commitment tree
    pub fn new_wallet<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        proof: Bytes,
        valid_wallet_create_statement_bytes: Bytes,
    ) -> Result<(), Vec<u8>> {
        DarkpoolContract::_check_not_paused(storage)?;

        let darkpool_core_address = storage.borrow_mut().darkpool_core_address.get();
        delegate_call_helper::<newWalletCall>(
            storage,
            darkpool_core_address,
            (proof.into(), valid_wallet_create_statement_bytes.into()),
        )
        .map(|_| ())
    }

    /// Update a wallet in the commitment tree
    pub fn update_wallet<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        proof: Bytes,
        valid_wallet_update_statement_bytes: Bytes,
        wallet_commitment_signature: Bytes,
        transfer_aux_data_bytes: Bytes,
    ) -> Result<(), Vec<u8>> {
        DarkpoolContract::_check_not_paused(storage)?;

        let darkpool_core_address = storage.borrow_mut().darkpool_core_address.get();
        delegate_call_helper::<updateWalletCall>(
            storage,
            darkpool_core_address,
            (
                proof.into(),
                valid_wallet_update_statement_bytes.into(),
                wallet_commitment_signature.into(),
                transfer_aux_data_bytes.into(),
            ),
        )
        .map(|_| ())
    }

    /// Settles a matched order between two parties,
    /// inserting the updated wallets into the commitment tree.
    ///
    /// The `match_proofs` argument is the serialization of the [`contracts_common::types::MatchProofs`]
    /// struct, and the `match_linking_proofs` argument is the serialization of the
    /// [`contracts_common::types::MatchLinkingProofs`] struct
    pub fn process_match_settle<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        party_0_match_payload: Bytes,
        party_1_match_payload: Bytes,
        valid_match_settle_statement: Bytes,
        match_proofs: Bytes,
        match_linking_proofs: Bytes,
    ) -> Result<(), Vec<u8>> {
        DarkpoolContract::_check_not_paused(storage)?;

        let darkpool_core_address = storage.borrow_mut().darkpool_core_address.get();
        delegate_call_helper::<processMatchSettleCall>(
            storage,
            darkpool_core_address,
            (
                party_0_match_payload.into(),
                party_1_match_payload.into(),
                valid_match_settle_statement.into(),
                match_proofs.into(),
                match_linking_proofs.into(),
            ),
        )
        .map(|_| ())
    }

    /// Settles the fee accumulated by a relayer for a given balance in a managed wallet
    /// into the relayer's wallet
    pub fn settle_online_relayer_fee<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        proof: Bytes,
        valid_relayer_fee_settlement_statement: Bytes,
        relayer_wallet_commitment_signature: Bytes,
    ) -> Result<(), Vec<u8>> {
        DarkpoolContract::_check_not_paused(storage)?;

        let darkpool_core_address = storage.borrow_mut().darkpool_core_address.get();
        delegate_call_helper::<settleOnlineRelayerFeeCall>(
            storage,
            darkpool_core_address,
            (
                proof.into(),
                valid_relayer_fee_settlement_statement.into(),
                relayer_wallet_commitment_signature.into(),
            ),
        )
        .map(|_| ())
    }

    /// Settles the fee accumulated either by a relayer or the protocol
    /// into an encrypted note which is committed to the Merkle tree
    pub fn settle_offline_fee<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        proof: Bytes,
        valid_offline_fee_settlement_statement: Bytes,
    ) -> Result<(), Vec<u8>> {
        DarkpoolContract::_check_not_paused(storage)?;

        let darkpool_core_address = storage.borrow_mut().darkpool_core_address.get();
        delegate_call_helper::<settleOfflineFeeCall>(
            storage,
            darkpool_core_address,
            (proof.into(), valid_offline_fee_settlement_statement.into()),
        )
        .map(|_| ())
    }

    /// Redeems a fee note into the recipient's wallet, nullifying the note
    pub fn redeem_fee<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        proof: Bytes,
        valid_fee_redemption_statement: Bytes,
        recipient_wallet_commitment_signature: Bytes,
    ) -> Result<(), Vec<u8>> {
        DarkpoolContract::_check_not_paused(storage)?;

        let darkpool_core_address = storage.borrow_mut().darkpool_core_address.get();
        delegate_call_helper::<redeemFeeCall>(
            storage,
            darkpool_core_address,
            (
                proof.into(),
                valid_fee_redemption_statement.into(),
                recipient_wallet_commitment_signature.into(),
            ),
        )
        .map(|_| ())
    }
}

/// Internal helper methods
impl DarkpoolContract {
    // -----------------
    // | INITIALIZABLE |
    // -----------------

    /// Initializes this contract with the given version.
    pub fn _initialize<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        version: u64,
    ) -> Result<(), Vec<u8>> {
        let version_uint64 = U64::from_limbs([version]);
        let this = storage.borrow_mut();
        assert_result!(
            this.initialized.get() < version_uint64,
            INVALID_VERSION_ERROR_MESSAGE
        )?;
        this.initialized.set(version_uint64);
        Ok(())
    }

    // -----------
    // | OWNABLE |
    // -----------

    /// Updates the stored owner address to `new_owner`
    pub fn _transfer_ownership<S: TopLevelStorage + BorrowMut<Self>>(
        storage: &mut S,
        new_owner: Address,
    ) {
        storage.borrow_mut().owner.set(new_owner);
        evm::log(OwnershipTransferred { new_owner })
    }

    /// Checks that the sender is the owner
    pub fn _check_owner<S: TopLevelStorage + Borrow<Self>>(storage: &S) -> Result<(), Vec<u8>> {
        assert_result!(
            storage.borrow().owner.get() == msg::sender(),
            NOT_OWNER_ERROR_MESSAGE
        )
    }

    // ------------
    // | PAUSABLE |
    // ------------

    /// Checks that the darkpool is paused
    pub fn _check_paused<S: TopLevelStorage + Borrow<Self>>(storage: &S) -> Result<(), Vec<u8>> {
        assert_result!(storage.borrow().paused.get(), PAUSED_ERROR_MESSAGE)
    }

    /// Checks that the darkpool is not paused
    pub fn _check_not_paused<S: TopLevelStorage + Borrow<Self>>(
        storage: &S,
    ) -> Result<(), Vec<u8>> {
        assert_result!(!storage.borrow().paused.get(), UNPAUSED_ERROR_MESSAGE)
    }

    // ----------------
    // | CORE HELPERS |
    // ----------------

    /// Checks that the given address is not the zero address
    pub fn check_address_not_zero(address: Address) -> Result<(), Vec<u8>> {
        assert_result!(address != Address::ZERO, ZERO_ADDRESS_ERROR_MESSAGE)
    }

    /// Gets the affine coordinates of the protocol public encryption key
    /// as U256s
    pub fn _get_protocol_pubkey_coords<S: TopLevelStorage + Borrow<Self>>(
        storage: &S,
    ) -> [U256; 2] {
        let protocol_pubkey_x = storage
            .borrow()
            .protocol_public_encryption_key
            .get(0)
            .unwrap();

        let protocol_pubkey_y = storage
            .borrow()
            .protocol_public_encryption_key
            .get(1)
            .unwrap();

        [protocol_pubkey_x, protocol_pubkey_y]
    }
}
