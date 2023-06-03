#[contract]
mod DarkpoolLib {
    use starknet::ClassHash;
    use starknet::ContractAddress;
    use starknet::info;
    use box::BoxTrait;
    use array::ArrayTrait;
    use option::OptionTrait;
    use serde::Serde;

    use quaireaux_utils::check_gas;

    use renegade_contracts::nullifier_set::interface::INullifierSetDispatcherTrait;
    use renegade_contracts::nullifier_set::interface::INullifierSetLibraryDispatcher;
    use renegade_contracts::merkle::interface::IMerkleDispatcherTrait;
    use renegade_contracts::merkle::interface::IMerkleLibraryDispatcher;
    use renegade_contracts::oz::erc20::interface::IERC20DispatcherTrait;
    use renegade_contracts::oz::erc20::interface::IERC20Dispatcher;

    // -----------
    // | STRUCTS |
    // -----------

    /// Represents an external transfer of an ERC20 token
    #[derive(Copy, Drop)]
    struct ExternalTransfer {
        /// The address of the account contract to deposit from or withdraw to
        account_addr: ContractAddress,
        /// The mint (contract address) of the token being transferred
        mint: ContractAddress,
        /// The amount of the token transferred
        amount: u256,
        /// Whether or not the transfer is a deposit (otherwise a withdrawal)
        is_deposit: bool,
    }

    impl ExternalTransferSerde of Serde::<ExternalTransfer> {
        fn serialize(ref serialized: Array::<felt252>, input: ExternalTransfer) {
            Serde::<ContractAddress>::serialize(ref serialized, input.account_addr);
            Serde::<ContractAddress>::serialize(ref serialized, input.mint);
            Serde::<u256>::serialize(ref serialized, input.amount);
            Serde::<bool>::serialize(ref serialized, input.is_deposit);
        }
        fn deserialize(ref serialized: Span::<felt252>) -> Option<ExternalTransfer> {
            Option::Some(
                ExternalTransfer {
                    account_addr: Serde::<ContractAddress>::deserialize(ref serialized)?,
                    mint: Serde::<ContractAddress>::deserialize(ref serialized)?,
                    amount: Serde::<u256>::deserialize(ref serialized)?,
                    is_deposit: Serde::<bool>::deserialize(ref serialized)?,
                }
            )
        }
    }

    /// Represents the artifacts produced by one of the parties in a match
    #[derive(Drop)]
    struct MatchPayload {
        wallet_blinder_share: felt252,
        old_shares_nullifier: felt252,
        wallet_share_commitment: felt252,
        public_wallet_shares: Array::<felt252>,
        valid_commitments_proof_blob: Array::<felt252>,
        valid_reblind_proof_blob: Array::<felt252>,
    }

    impl MatchPayloadSerde of Serde::<MatchPayload> {
        fn serialize(ref serialized: Array<felt252>, input: MatchPayload) {
            Serde::<felt252>::serialize(ref serialized, input.wallet_blinder_share);
            Serde::<felt252>::serialize(ref serialized, input.old_shares_nullifier);
            Serde::<felt252>::serialize(ref serialized, input.wallet_share_commitment);
            Serde::<Array::<felt252>>::serialize(ref serialized, input.public_wallet_shares);
            Serde::<Array::<felt252>>::serialize(
                ref serialized, input.valid_commitments_proof_blob
            );
            Serde::<Array::<felt252>>::serialize(ref serialized, input.valid_reblind_proof_blob);
        }
        fn deserialize(ref serialized: Span<felt252>) -> Option<MatchPayload> {
            Option::Some(
                MatchPayload {
                    wallet_blinder_share: Serde::<felt252>::deserialize(ref serialized)?,
                    old_shares_nullifier: Serde::<felt252>::deserialize(ref serialized)?,
                    wallet_share_commitment: Serde::<felt252>::deserialize(ref serialized)?,
                    public_wallet_shares: Serde::<Array::<felt252>>::deserialize(ref serialized)?,
                    valid_commitments_proof_blob: Serde::<Array::<felt252>>::deserialize(
                        ref serialized
                    )?,
                    valid_reblind_proof_blob: Serde::<Array::<felt252>>::deserialize(
                        ref serialized
                    )?,
                }
            )
        }
    }

    // -----------
    // | STORAGE |
    // -----------

    struct Storage {
        /// Stores the implementation class hash for the Merkle tree interface
        merkle_class_hash: ClassHash,
        /// Stores the implementation class hash for the nullifier set interface
        nullifier_set_class_hash: ClassHash,
        /// Stores a mapping from the wallet identity to the hash of the last transaction
        /// in which it was changed
        wallet_last_modified: LegacyMap<felt252, felt252>
    }

    // ----------
    // | EVENTS |
    // ----------

    /// Emitted when there's an update to the encrypted wallet identified by `wallet_blinder_share`
    #[event]
    fn Darkpool_wallet_update(wallet_blinder_share: felt252) {}

    /// Emitted when there's a deposit from an external account to the darkpool
    #[event]
    fn Darkpool_deposit(sender: ContractAddress, mint: ContractAddress, amount: u256) {}

    /// Emitted when there's a withdrawal from the darkpool to an external account
    #[event]
    fn Darkpool_withdraw(recipient: ContractAddress, mint: ContractAddress, amount: u256) {}

    /// Emitted when there's a change to the Merkle tree implementation class
    #[event]
    fn Darkpool_merkle_class_hash_changed(old_class: ClassHash, new_class: ClassHash) {}

    /// Emitted when there's a change to the nullifier set implementation class
    #[event]
    fn Darkpool_nullifier_set_class_hash_changed(old_class: ClassHash, new_class: ClassHash) {}

    // -----------
    // | LIBRARY |
    // -----------

    // ---------
    // | PROXY |
    // ---------

    /// Initializes the contract state
    /// Parameters:
    /// - `merkle_class`: The declared contract class of the Merkle tree implementation
    /// - `nullifier_class`: The declared contract class of the nullifier set implementation
    fn initializer(
        _merkle_class_hash: ClassHash, _nullifier_set_class_hash: ClassHash, _height: u8
    ) {
        // Save Merkle tree & nullifier set class hashes to storage
        merkle_class_hash::write(_merkle_class_hash);
        nullifier_set_class_hash::write(_nullifier_set_class_hash);

        // Initialize the Merkle tree
        _get_merkle_tree().initializer(_height);
    }

    /// Upgrades the Merkle implementation class
    /// Parameters:
    /// - `class_hash`: The hash of the implementation class used for Merkle operations
    fn set_merkle_class(class_hash: ClassHash) {
        // Get existing class hash to emit event
        let old_class_hash = merkle_class_hash::read();
        merkle_class_hash::write(class_hash);
        // Emit event
        Darkpool_merkle_class_hash_changed(old_class_hash, class_hash);
    }

    /// Upgrades the nullifier set implementation class
    /// Parameters:
    /// - `class_hash`: The hash of the implementation class used for nullifier set operations
    fn set_nullifier_set_class(class_hash: ClassHash) {
        // Get existing class hash to emit event
        let old_class_hash = nullifier_set_class_hash::read();
        nullifier_set_class_hash::write(class_hash);
        // Emit event
        Darkpool_nullifier_set_class_hash_changed(old_class_hash, class_hash);
    }

    // -----------
    // | GETTERS |
    // -----------

    /// Returns the hash of the most recent transaction to update a given wallet
    /// as indexed by the public share of the wallet blinder
    /// Parameters:
    /// - `wallet_blinder_share`: The identifier of the wallet
    /// Returns:
    /// - The tx hash
    fn get_wallet_blinder_transaction(wallet_blinder_share: felt252) -> felt252 {
        wallet_last_modified::read(wallet_blinder_share)
    }

    /// Returns the most recent root of the Merkle state tree
    /// Returns:
    /// - The current root
    fn get_root() -> felt252 {
        _get_merkle_tree().get_root()
    }

    /// Returns whether the given root is in the history
    /// Parameters:
    /// - `root`: The root to check history for
    /// Returns:
    /// - A boolean indicating whether or not the root is in the history
    fn root_in_history(root: felt252) -> bool {
        _get_merkle_tree().root_in_history(root)
    }

    /// Returns whether a given nullifier has already been used
    /// Parameters:
    /// - `nullifier`: The nullifier to check the set for
    /// Returns:
    /// - A boolean indicating whether or not the nullifier is used
    fn is_nullifier_used(nullifier: felt252) -> bool {
        _get_nullifier_set().is_nullifier_used(nullifier)
    }

    // -----------
    // | SETTERS |
    // -----------

    /// Sets the wallet update storage variable to the current transaction hash,
    /// indicating that the wallet has been modified at this transaction
    /// Parameters:
    /// - `wallet_blinder_share`: The identifier of the wallet
    fn mark_wallet_updated(wallet_blinder_share: felt252) {
        // Check that wallet blinder share isn't already indexed
        assert(wallet_last_modified::read(wallet_blinder_share) == 0, 'wallet already indexed');
        // Get the current tx hash
        let tx_hash = info::get_tx_info().unbox().transaction_hash;
        // Update storage mapping
        wallet_last_modified::write(wallet_blinder_share, tx_hash);
        // Emit event
        Darkpool_wallet_update(wallet_blinder_share);
    }

    /// Adds a new wallet to the commitment tree
    /// Parameters:
    /// - `wallet_blinder_share`: The public share of the wallet blinder, used for indexing
    /// - `wallet_share_commitment`: The commitment to the new wallet's shares
    /// - `public_wallet_shares`: The public shares of the new wallet
    /// - `proof_blob`: The proof of `VALID_WALLET_CREATE`
    /// Returns:
    /// - The new root after the wallet is inserted into the tree
    fn new_wallet(
        wallet_blinder_share: felt252,
        wallet_share_commitment: felt252,
        public_wallet_shares: Array::<felt252>,
        proof_blob: Array::<felt252>,
    ) -> felt252 {
        // TODO: Add verification of `VALID_WALLET_CREATE`

        // Insert the new wallet's commitment into the Merkle tree
        let merkle_tree = _get_merkle_tree();
        let new_root = merkle_tree.insert(wallet_share_commitment);

        // Mark wallet as updated
        mark_wallet_updated(wallet_blinder_share);

        new_root
    }

    /// Update a wallet in the commitment tree
    /// Parameters:
    /// - `wallet_blinder_share`: The public share of the wallet blinder, used for indexing
    /// - `wallet_share_commitment`: The commitment to the updated wallet's shares
    /// - `old_shares_nullifier`: The nullifier for the public shares of the wallet before it was updated
    /// - `public_wallet_shares`: The public shares of the wallet after it was updated
    /// - `external_transfers`: The external transfers (ERC20 deposit/withdrawal)
    /// - `proof_blob`: The proof of `VALID_WALLET_UPDATE`
    /// Returns:
    /// - The root of the tree after the new commitment is inserted
    fn update_wallet(
        wallet_blinder_share: felt252,
        wallet_share_commitment: felt252,
        old_shares_nullifier: felt252,
        public_wallet_shares: Array::<felt252>,
        mut external_transfers: Array::<ExternalTransfer>,
        proof_blob: Array::<felt252>,
    ) -> felt252 {
        // TODO: Add verification of `VALID_WALLET_UPDATE`

        // Insert the updated wallet's commitment into the Merkle tree
        let merkle_tree = _get_merkle_tree();
        let new_root = merkle_tree.insert(wallet_share_commitment);

        // Add the old shares nullifier to the spent nullifier set
        let nullifier_set = _get_nullifier_set();
        nullifier_set.mark_nullifier_used(old_shares_nullifier);

        // Process the external transfers
        let contract_address = info::get_contract_address();
        let caller_address = info::get_caller_address();
        _execute_external_transfers(contract_address, caller_address, external_transfers);

        // Mark wallet as updated
        mark_wallet_updated(wallet_blinder_share);

        new_root
    }

    /// Encumber two wallets by submitting a successfully completed match to the contract.
    /// Parameters:
    /// - `party_0_payload`: The first party's match payload
    /// - `party_1_payload`: The second party's match payload
    /// - `match_proof_blob`: The proof of `VALID_MATCH_MPC`
    /// - `settle_proof_blob`: The proof of `VALID_SETTLE`
    fn process_match(
        party_0_payload: MatchPayload,
        party_1_payload: MatchPayload,
        match_proof_blob: Array::<felt252>,
        settle_proof_blob: Array::<felt252>,
    ) -> felt252 {
        let nullifier_set = _get_nullifier_set();
        nullifier_set.mark_nullifier_used(party_0_payload.old_shares_nullifier);
        nullifier_set.mark_nullifier_used(party_1_payload.old_shares_nullifier);

        let merkle_tree = _get_merkle_tree();
        merkle_tree.insert(party_0_payload.wallet_share_commitment);
        let new_root = merkle_tree.insert(party_1_payload.wallet_share_commitment);

        // Mark wallet as updated
        mark_wallet_updated(party_0_payload.wallet_blinder_share);
        mark_wallet_updated(party_1_payload.wallet_blinder_share);

        new_root
    }

    // -----------
    // | HELPERS |
    // -----------

    /// Returns the library dispatcher struct for the Merkle interface,
    /// using the currently stored Merkle class hash
    /// Returns:
    /// - Library dispatcher instance
    fn _get_merkle_tree() -> IMerkleLibraryDispatcher {
        IMerkleLibraryDispatcher { class_hash: merkle_class_hash::read() }
    }

    /// Returns the library dispatcher struct for the nullifier set interface,
    /// using the currently stored nullifier set class hash
    /// Returns:
    /// - Library dispatcher instance
    fn _get_nullifier_set() -> INullifierSetLibraryDispatcher {
        INullifierSetLibraryDispatcher { class_hash: nullifier_set_class_hash::read() }
    }

    /// Returns the contract dispatcher struct for the ERC20 interface,
    /// using the passed in contract address
    /// Parameters:
    /// - `contract_address`: The contract address of the ERC20 contract to use
    /// Returns:
    /// - Contract dispatcher instance
    fn _get_erc20(contract_address: ContractAddress) -> IERC20Dispatcher {
        IERC20Dispatcher { contract_address }
    }

    /// Executes a set of external ERC20 transfers
    /// Parameters:
    /// - `contract_address`: The address of the current contract // TODO: Should we just get this inside the body of this function?
    /// - `caller_address`: The address triggering the withdrawal / deposit // TODO: Should we just get this inside the body of this function?
    /// - `transfers`: The external transfers to execute
    fn _execute_external_transfers(
        contract_address: ContractAddress,
        caller_address: ContractAddress,
        mut transfers: Array<ExternalTransfer>
    ) {
        check_gas();

        if !transfers.is_empty() {
            // Get the first transfer in the list
            // It's safe to unwrap here since we only enter this branch if
            // the list is not empty
            let next_transfer = transfers.pop_front().unwrap();

            // Get contract dispatcher instance for transfer mint
            let erc20 = _get_erc20(next_transfer.mint);

            // Execute the transfer
            if next_transfer.is_deposit {
                // Deposit
                erc20.transfer_from(
                    next_transfer.account_addr, contract_address, next_transfer.amount
                );

                // Emit event
                Darkpool_deposit(caller_address, next_transfer.mint, next_transfer.amount);
            } else {
                // Withdraw
                erc20.transfer(next_transfer.account_addr, next_transfer.amount);

                // Emit event
                Darkpool_withdraw(caller_address, next_transfer.mint, next_transfer.amount);
            }

            // Recurse
            _execute_external_transfers(contract_address, caller_address, transfers);
        }
    }
}
