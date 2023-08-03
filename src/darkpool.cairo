mod types;

// TODO: Fit to the contract extensibility framework once it is implemented

// -------------
// | INTERFACE |
// -------------

use starknet::ClassHash;

use renegade_contracts::{verifier::{scalar::Scalar, types::Proof}, utils::serde::EcPointSerde};

use types::{ExternalTransfer, MatchPayload};


#[starknet::interface]
trait IDarkpool<TContractState> {
    // GETTERS
    fn get_wallet_blinder_transaction(
        self: @TContractState, wallet_blinder_share: Scalar
    ) -> felt252;
    fn get_root(self: @TContractState) -> Scalar;
    fn root_in_history(self: @TContractState, root: Scalar) -> bool;
    fn is_nullifier_used(self: @TContractState, nullifier: Scalar) -> bool;
    // SETTERS
    fn new_wallet(
        ref self: TContractState,
        wallet_blinder_share: Scalar,
        wallet_share_commitment: Scalar,
        public_wallet_shares: Array<Scalar>,
        proof: Proof,
        witness_commitments: Array<EcPoint>,
    ) -> Scalar;
    fn update_wallet(
        ref self: TContractState,
        wallet_blinder_share: Scalar,
        wallet_share_commitment: Scalar,
        old_shares_nullifier: Scalar,
        public_wallet_shares: Array<Scalar>,
        external_transfers: Array<ExternalTransfer>,
        proof: Proof,
        witness_commitments: Array<EcPoint>,
    ) -> Scalar;
    fn process_match(
        ref self: TContractState,
        party_0_payload: MatchPayload,
        party_1_payload: MatchPayload,
        match_proof: Proof,
        match_witness_commitments: Array<EcPoint>,
        settle_proof: Proof,
        settle_witness_commitments: Array<EcPoint>,
    ) -> Scalar;
}

#[starknet::contract]
mod Darkpool {
    use option::OptionTrait;
    use array::ArrayTrait;
    use box::BoxTrait;
    use zeroable::Zeroable;
    use starknet::{
        ClassHash, get_caller_address, get_contract_address, get_tx_info, ContractAddress,
        replace_class_syscall, contract_address::ContractAddressZeroable,
    };

    use renegade_contracts::{
        verifier::{scalar::Scalar, types::Proof},
        merkle::{IMerkleLibraryDispatcher, IMerkleDispatcherTrait},
        nullifier_set::{INullifierSetLibraryDispatcher, INullifierSetDispatcherTrait},
        utils::serde::EcPointSerde, oz::erc20::{IERC20DispatcherTrait, IERC20Dispatcher},
    };

    use super::types::{ExternalTransfer, MatchPayload};

    // -----------
    // | STORAGE |
    // -----------

    #[storage]
    struct Storage {
        // OWNABLE
        /// Stores the owner of the contract
        _owner: ContractAddress,
        // INITIALIZEABLE
        /// Stores whether or not the contract has been initialized
        _initialized: bool,
        // CORE
        /// Stores the implementation class hash for the Merkle tree interface
        merkle_class_hash: ClassHash,
        /// Stores the implementation class hash for the nullifier set interface
        nullifier_set_class_hash: ClassHash,
        /// Stores a mapping from the wallet identity to the hash of the last transaction
        /// in which it was changed
        wallet_last_modified: LegacyMap<Scalar, felt252>
    }

    // ----------
    // | EVENTS |
    // ----------

    /// Emitted when ownership of the Darkpool contract is transferred
    #[derive(Drop, PartialEq, starknet::Event)]
    struct OwnershipTransfer {
        previous_owner: ContractAddress,
        new_owner: ContractAddress,
    }

    /// Emitted when there's a change to the Darkpool implementation class
    #[derive(Drop, PartialEq, starknet::Event)]
    struct DarkpoolUpgrade {
        new_class: ClassHash, 
    }

    /// Emitted when there's a change to the Merkle tree implementation class
    #[derive(Drop, PartialEq, starknet::Event)]
    struct MerkleUpgrade {
        old_class: ClassHash,
        new_class: ClassHash,
    }

    /// Emitted when there's a change to the nullifier set implementation class
    #[derive(Drop, PartialEq, starknet::Event)]
    struct NullifierSetUpgrade {
        old_class: ClassHash,
        new_class: ClassHash,
    }

    /// Emitted when there's an update to the encrypted wallet identified by `wallet_blinder_share`
    #[derive(Drop, PartialEq, starknet::Event)]
    struct WalletUpdate {
        wallet_blinder_share: Scalar, 
    }

    /// Emitted when there's a deposit from an external account to the darkpool
    #[derive(Drop, PartialEq, starknet::Event)]
    struct Deposit {
        sender: ContractAddress,
        mint: ContractAddress,
        amount: u256,
    }

    /// Emitted when there's a withdrawal from the darkpool to an external account
    #[derive(Drop, PartialEq, starknet::Event)]
    struct Withdrawal {
        recipient: ContractAddress,
        mint: ContractAddress,
        amount: u256,
    }

    #[event]
    #[derive(Drop, PartialEq, starknet::Event)]
    enum Event {
        OwnershipTransfer: OwnershipTransfer,
        DarkpoolUpgrade: DarkpoolUpgrade,
        MerkleUpgrade: MerkleUpgrade,
        NullifierSetUpgrade: NullifierSetUpgrade,
        WalletUpdate: WalletUpdate,
        Deposit: Deposit,
        Withdrawal: Withdrawal,
    }

    // ---------------
    // | CONSTRUCTOR |
    // ---------------

    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress) {
        _ownable_initialize(ref self, owner);
    }

    // -----------
    // | UPGRADE |
    // -----------

    /// Upgrades the Darkpool implementation class
    /// Parameters:
    /// - `darkpool_class_hash`: The hash of the new implementation class
    #[external(v0)]
    fn upgrade(ref self: ContractState, darkpool_class_hash: ClassHash) {
        ownable__assert_only_owner(@self);
        upgradeable__upgrade(ref self, darkpool_class_hash);
    }

    // ---------
    // | PROXY |
    // ---------

    /// Initializes the contract state
    /// Parameters:
    /// - `merkle_class`: The declared contract class of the Merkle tree implementation
    /// - `nullifier_class`: The declared contract class of the nullifier set implementation
    #[external(v0)]
    fn initializer(
        ref self: ContractState,
        merkle_class_hash: ClassHash,
        nullifier_set_class_hash: ClassHash,
        height: u8
    ) {
        ownable__assert_only_owner(@self);
        initializable__initialize(ref self);

        // Save Merkle tree & nullifier set class hashes to storage
        self.merkle_class_hash.write(merkle_class_hash);
        self.nullifier_set_class_hash.write(nullifier_set_class_hash);

        // Initialize the Merkle tree
        _get_merkle_tree(@self).initialize(height);
    }

    /// Upgrades the Merkle implementation class
    /// Parameters:
    /// - `merkle_class_hash`: The hash of the implementation class used for Merkle operations
    #[external(v0)]
    fn upgrade_merkle(ref self: ContractState, merkle_class_hash: ClassHash) {
        ownable__assert_only_owner(@self);

        // Get existing class hash to emit event
        let old_class_hash = self.merkle_class_hash.read();
        self.merkle_class_hash.write(merkle_class_hash);
        // Emit event
        self
            .emit(
                Event::MerkleUpgrade(
                    MerkleUpgrade { old_class: old_class_hash, new_class: merkle_class_hash }
                )
            );
    }

    /// Upgrades the nullifier set implementation class
    /// Parameters:
    /// - `nullifier_set_class_hash`: The hash of the implementation class used for nullifier set operations
    #[external(v0)]
    fn upgrade_nullifier_set(ref self: ContractState, nullifier_set_class_hash: ClassHash) {
        ownable__assert_only_owner(@self);

        // Get existing class hash to emit event
        let old_class_hash = self.nullifier_set_class_hash.read();
        self.nullifier_set_class_hash.write(nullifier_set_class_hash);
        // Emit event
        self
            .emit(
                Event::NullifierSetUpgrade(
                    NullifierSetUpgrade {
                        old_class: old_class_hash, new_class: nullifier_set_class_hash
                    }
                )
            );
    }

    // -------------
    // | INTERFACE |
    // -------------

    #[external(v0)]
    impl IDarkpoolImpl of super::IDarkpool<ContractState> {
        // -----------
        // | GETTERS |
        // -----------

        /// Returns the hash of the most recent transaction to update a given wallet
        /// as indexed by the public share of the wallet blinder
        /// Parameters:
        /// - `wallet_blinder_share`: The identifier of the wallet
        /// Returns:
        /// - The tx hash
        fn get_wallet_blinder_transaction(
            self: @ContractState, wallet_blinder_share: Scalar
        ) -> felt252 {
            self.wallet_last_modified.read(wallet_blinder_share)
        }

        /// Returns the most recent root of the Merkle state tree
        /// Returns:
        /// - The current root
        fn get_root(self: @ContractState) -> Scalar {
            _get_merkle_tree(self).get_root()
        }

        /// Returns whether the given root is in the history
        /// Parameters:
        /// - `root`: The root to check history for
        /// Returns:
        /// - A boolean indicating whether or not the root is in the history
        fn root_in_history(self: @ContractState, root: Scalar) -> bool {
            _get_merkle_tree(self).root_in_history(root)
        }

        /// Returns whether a given nullifier has already been used
        /// Parameters:
        /// - `nullifier`: The nullifier to check the set for
        /// Returns:
        /// - A boolean indicating whether or not the nullifier is used
        fn is_nullifier_used(self: @ContractState, nullifier: Scalar) -> bool {
            _get_nullifier_set(self).is_nullifier_used(nullifier)
        }

        // -----------
        // | SETTERS |
        // -----------

        /// Adds a new wallet to the commitment tree
        /// Parameters:
        /// - `wallet_blinder_share`: The public share of the wallet blinder, used for indexing
        /// - `wallet_share_commitment`: The commitment to the new wallet's shares
        /// - `public_wallet_shares`: The public shares of the new wallet
        /// - `proof`: The proof of `VALID_WALLET_CREATE`
        /// - `witness_commitments`: The Pedersen commitments to the witness elements
        /// Returns:
        /// - The new root after the wallet is inserted into the tree
        fn new_wallet(
            ref self: ContractState,
            wallet_blinder_share: Scalar,
            wallet_share_commitment: Scalar,
            public_wallet_shares: Array<Scalar>,
            proof: Proof,
            witness_commitments: Array<EcPoint>,
        ) -> Scalar {
            // TODO: Add verification of `VALID_WALLET_CREATE`

            // Insert the new wallet's commitment into the Merkle tree
            let merkle_tree = _get_merkle_tree(@self);
            let new_root = merkle_tree.insert(wallet_share_commitment);

            // Mark wallet as updated
            _mark_wallet_updated(ref self, wallet_blinder_share);

            new_root
        }

        /// Update a wallet in the commitment tree
        /// Parameters:
        /// - `wallet_blinder_share`: The public share of the wallet blinder, used for indexing
        /// - `wallet_share_commitment`: The commitment to the updated wallet's shares
        /// - `old_shares_nullifier`: The nullifier for the public shares of the wallet before it was updated
        /// - `public_wallet_shares`: The public shares of the wallet after it was updated
        /// - `external_transfers`: The external transfers (ERC20 deposit/withdrawal)
        /// - `proof`: The proof of `VALID_WALLET_UPDATE`
        /// - `witness_commitments`: The Pedersen commitments to the witness elements
        /// Returns:
        /// - The root of the tree after the new commitment is inserted
        fn update_wallet(
            ref self: ContractState,
            wallet_blinder_share: Scalar,
            wallet_share_commitment: Scalar,
            old_shares_nullifier: Scalar,
            public_wallet_shares: Array<Scalar>,
            mut external_transfers: Array<ExternalTransfer>,
            proof: Proof,
            witness_commitments: Array<EcPoint>,
        ) -> Scalar {
            // TODO: Add verification of `VALID_WALLET_UPDATE`

            // Insert the updated wallet's commitment into the Merkle tree
            let merkle_tree = _get_merkle_tree(@self);
            let new_root = merkle_tree.insert(wallet_share_commitment);

            // Add the old shares nullifier to the spent nullifier set
            let nullifier_set = _get_nullifier_set(@self);
            nullifier_set.mark_nullifier_used(old_shares_nullifier);

            // Process the external transfers
            _execute_external_transfers(ref self, external_transfers);

            // Mark wallet as updated
            _mark_wallet_updated(ref self, wallet_blinder_share);

            new_root
        }

        /// Settles a matched order between two parties
        /// Parameters:
        /// - `party_0_payload`: The first party's match payload
        /// - `party_1_payload`: The second party's match payload
        /// - `match_proof`: The proof of `VALID_MATCH_MPC`
        /// - `match_witness_commitments`: The Pedersen commitments to the match proof witness elements
        /// - `settle_proof`: The proof of `VALID_SETTLE`
        /// - `settle_witness_commitments`: The Pedersen commitments to the settle proof witness elements
        fn process_match(
            ref self: ContractState,
            party_0_payload: MatchPayload,
            party_1_payload: MatchPayload,
            match_proof: Proof,
            match_witness_commitments: Array<EcPoint>,
            settle_proof: Proof,
            settle_witness_commitments: Array<EcPoint>,
        ) -> Scalar {
            // TODO: Add verification of `VALID_MATCH_MPC` and `VALID_SETTLE`

            let nullifier_set = _get_nullifier_set(@self);
            nullifier_set.mark_nullifier_used(party_0_payload.old_shares_nullifier);
            nullifier_set.mark_nullifier_used(party_1_payload.old_shares_nullifier);

            let merkle_tree = _get_merkle_tree(@self);
            merkle_tree.insert(party_0_payload.wallet_share_commitment);
            let new_root = merkle_tree.insert(party_1_payload.wallet_share_commitment);

            // Mark wallet as updated
            _mark_wallet_updated(ref self, party_0_payload.wallet_blinder_share);
            _mark_wallet_updated(ref self, party_1_payload.wallet_blinder_share);

            new_root
        }
    }

    // -----------
    // | HELPERS |
    // -----------

    // -----------
    // | GETTERS |
    // -----------

    /// Returns the library dispatcher struct for the Merkle interface,
    /// using the currently stored Merkle class hash
    /// Returns:
    /// - Library dispatcher instance
    fn _get_merkle_tree(self: @ContractState) -> IMerkleLibraryDispatcher {
        IMerkleLibraryDispatcher { class_hash: self.merkle_class_hash.read() }
    }

    /// Returns the library dispatcher struct for the nullifier set interface,
    /// using the currently stored nullifier set class hash
    /// Returns:
    /// - Library dispatcher instance
    fn _get_nullifier_set(self: @ContractState) -> INullifierSetLibraryDispatcher {
        INullifierSetLibraryDispatcher { class_hash: self.nullifier_set_class_hash.read() }
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

    // -----------
    // | SETTERS |
    // -----------

    /// Sets the wallet update storage variable to the current transaction hash,
    /// indicating that the wallet has been modified at this transaction
    /// Parameters:
    /// - `wallet_blinder_share`: The identifier of the wallet
    fn _mark_wallet_updated(ref self: ContractState, wallet_blinder_share: Scalar) {
        // Check that wallet blinder share isn't already indexed
        assert(self.wallet_last_modified.read(wallet_blinder_share) == 0, 'wallet already indexed');
        // Get the current tx hash
        let tx_hash = get_tx_info().unbox().transaction_hash;
        // Update storage mapping
        self.wallet_last_modified.write(wallet_blinder_share, tx_hash);
        // Emit event
        self.emit(Event::WalletUpdate(WalletUpdate { wallet_blinder_share }));
    }

    /// Executes a set of external ERC20 transfers
    /// Parameters:
    /// - `transfers`: The external transfers to execute
    fn _execute_external_transfers(
        ref self: ContractState, mut transfers: Array<ExternalTransfer>
    ) {
        let contract_address = get_contract_address();
        loop {
            if transfers.is_empty() {
                break;
            };

            // Get the first transfer in the list
            // It's safe to unwrap here since we only enter this branch if
            // the list is not empty
            let next_transfer = transfers.pop_front().unwrap();

            // Get contract dispatcher instance for transfer mint
            let erc20 = _get_erc20(next_transfer.mint);

            // Execute the transfer
            if !next_transfer.is_withdrawal {
                // Deposit
                erc20
                    .transfer_from(
                        next_transfer.account_addr, contract_address, next_transfer.amount
                    );

                // Emit event
                self
                    .emit(
                        Event::Deposit(
                            Deposit {
                                sender: next_transfer.account_addr,
                                mint: next_transfer.mint,
                                amount: next_transfer.amount
                            }
                        )
                    );
            } else {
                // Withdraw
                erc20.transfer(next_transfer.account_addr, next_transfer.amount);

                // Emit event
                self
                    .emit(
                        Event::Withdrawal(
                            Withdrawal {
                                recipient: next_transfer.account_addr,
                                mint: next_transfer.mint,
                                amount: next_transfer.amount
                            }
                        )
                    );
            };
        };
    }

    // -----------
    // | OWNABLE |
    // -----------
    // Adapted from OpenZeppelin's `Ownable` contract

    /// Asserts that the caller is the owner of the contract
    #[external(v0)]
    fn ownable__assert_only_owner(self: @ContractState) {
        let owner = self._owner.read();
        let caller = get_caller_address();
        assert(!caller.is_zero(), 'Caller is the zero address');
        assert(caller == owner, 'Caller is not the owner');
    }

    /// Returns the owner of the contract
    #[external(v0)]
    fn ownable__owner(self: @ContractState) -> ContractAddress {
        self._owner.read()
    }

    /// Transfers ownership of the contract to a new address
    #[external(v0)]
    fn ownable__transfer_ownership(ref self: ContractState, new_owner: ContractAddress) {
        assert(!new_owner.is_zero(), 'New owner is the zero address');
        ownable__assert_only_owner(@self);
        _ownable__transfer_ownership(ref self, new_owner);
    }

    /// Initializes the contract with an owner
    fn _ownable_initialize(ref self: ContractState, owner: ContractAddress) {
        _ownable__transfer_ownership(ref self, owner)
    }

    /// Internal function to transfer ownership of the contract to a new address
    fn _ownable__transfer_ownership(ref self: ContractState, new_owner: ContractAddress) {
        let previous_owner: ContractAddress = self._owner.read();
        self._owner.write(new_owner);
        self.emit(Event::OwnershipTransfer(OwnershipTransfer { previous_owner, new_owner }));
    }

    // -----------------
    // | INITIALIZABLE |
    // -----------------
    // Adapted from OpenZeppelin's `Initializable` contract

    /// Returns whether the contract has been initialized
    #[external(v0)]
    fn initializable__is_initialized(self: @ContractState) -> bool {
        self._initialized.read()
    }

    /// Marks the contract as initialized
    /// Caller function must handle access control.
    fn initializable__initialize(ref self: ContractState) {
        assert(!initializable__is_initialized(@self), 'Initializable: is initialized');
        self._initialized.write(true);
    }

    // ---------------
    // | UPGRADEABLE |
    // ---------------
    // Adapted from OpenZeppelin's `Upgradeable` contract

    /// Upgrades the contract to a new implementation class.
    /// Caller function must handle access control.
    fn upgradeable__upgrade(ref self: ContractState, class_hash: ClassHash) {
        replace_class_syscall(class_hash).unwrap_syscall();
        self.emit(Event::DarkpoolUpgrade(DarkpoolUpgrade { new_class: class_hash }));
    }
}
