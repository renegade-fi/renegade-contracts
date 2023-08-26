mod types;
mod statements;

// TODO: Fit to the contract extensibility framework once it is implemented

// -------------
// | INTERFACE |
// -------------

use starknet::{ClassHash, ContractAddress};

use renegade_contracts::{
    verifier::{scalar::Scalar, types::{Proof, CircuitParams}}, utils::serde::EcPointSerde,
};

use types::{
    ExternalTransfer, MatchPayload, NewWalletCallbackElems, UpdateWalletCallbackElems,
    ProcessMatchCallbackElems, Circuit,
};
use statements::{ValidWalletCreateStatement, ValidWalletUpdateStatement, ValidSettleStatement};


#[starknet::interface]
trait IDarkpool<TContractState> {
    // OWNERSHIP
    fn transfer_ownership(ref self: TContractState, new_owner: ContractAddress);
    fn owner(self: @TContractState) -> ContractAddress;
    // INITIALIZATION
    fn initialize(
        ref self: TContractState,
        merkle_class_hash: ClassHash,
        nullifier_set_class_hash: ClassHash,
        height: u8,
    );
    fn initialize_verifier(
        ref self: TContractState,
        circuit: Circuit,
        verifier_contract_address: ContractAddress,
        circuit_params: CircuitParams,
    );
    // OZ
    fn upgrade(ref self: TContractState, darkpool_class_hash: ClassHash);
    fn upgrade_merkle(ref self: TContractState, merkle_class_hash: ClassHash);
    fn upgrade_nullifier_set(ref self: TContractState, nullifier_set_class_hash: ClassHash);
    fn upgrade_verifier(
        ref self: TContractState, circuit: Circuit, verifier_contract_address: ContractAddress
    );
    // GETTERS
    fn get_wallet_blinder_transaction(
        self: @TContractState, wallet_blinder_share: Scalar
    ) -> felt252;
    fn get_root(self: @TContractState) -> Scalar;
    fn root_in_history(self: @TContractState, root: Scalar) -> bool;
    fn is_nullifier_available(self: @TContractState, nullifier: Scalar) -> bool;
    fn check_verification_job_status(
        self: @TContractState, circuit: Circuit, verification_job_id: felt252
    ) -> Option<bool>;
    // SETTERS
    fn new_wallet(
        ref self: TContractState,
        wallet_blinder_share: Scalar,
        statement: ValidWalletCreateStatement,
        witness_commitments: Array<EcPoint>,
        proof: Proof,
        verification_job_id: felt252,
    );
    fn poll_new_wallet(
        ref self: TContractState, verification_job_id: felt252, 
    ) -> Option<Result<Scalar, felt252>>;
    fn update_wallet(
        ref self: TContractState,
        wallet_blinder_share: Scalar,
        statement: ValidWalletUpdateStatement,
        statement_signature: (Scalar, Scalar),
        witness_commitments: Array<EcPoint>,
        proof: Proof,
        verification_job_id: felt252,
    );
    fn poll_update_wallet(
        ref self: TContractState, verification_job_id: felt252, 
    ) -> Option<Result<Scalar, felt252>>;
    fn process_match(
        ref self: TContractState,
        party_0_payload: MatchPayload,
        party_1_payload: MatchPayload,
        valid_match_mpc_witness_commitments: Array<EcPoint>,
        valid_match_mpc_proof: Proof,
        valid_settle_statement: ValidSettleStatement,
        valid_settle_witness_commitments: Array<EcPoint>,
        valid_settle_proof: Proof,
        verification_job_ids: Array<felt252>,
    );
    fn poll_process_match(
        ref self: TContractState, verification_job_ids: Array<felt252>, 
    ) -> Option<Result<Scalar, felt252>>;
}

#[starknet::contract]
mod Darkpool {
    use option::OptionTrait;
    use traits::Into;
    use clone::Clone;
    use array::{ArrayTrait, SpanTrait};
    use box::BoxTrait;
    use zeroable::Zeroable;
    use ecdsa::check_ecdsa_signature;
    use starknet::{
        ClassHash, get_caller_address, get_contract_address, get_tx_info, ContractAddress,
        replace_class_syscall, contract_address::ContractAddressZeroable,
    };

    use alexandria_data_structures::array_ext::ArrayTraitExt;

    use renegade_contracts::{
        verifier::{
            scalar::Scalar, types::{Proof, CircuitParams}, IVerifierDispatcher,
            IVerifierDispatcherTrait
        },
        merkle::{poseidon::poseidon_hash, IMerkleLibraryDispatcher, IMerkleDispatcherTrait},
        nullifier_set::{INullifierSetLibraryDispatcher, INullifierSetDispatcherTrait},
        utils::{
            serde::EcPointSerde, storage::StoreSerdeWrapper,
            crypto::{append_statement_commitments, hash_statement}
        },
        oz::erc20::{IERC20DispatcherTrait, IERC20Dispatcher},
    };

    use super::{
        types::{
            ExternalTransfer, MatchPayload, NewWalletCallbackElems, UpdateWalletCallbackElems,
            ProcessMatchCallbackElems, Circuit, PublicSigningKeyTrait,
        },
        statements::{ValidWalletCreateStatement, ValidWalletUpdateStatement, ValidSettleStatement}
    };

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
        /// Stores the contract address of the deployed verifier for the VALID WALLET CREATE circuit
        valid_wallet_create_verifier_address: ContractAddress,
        /// Stores the contract address of the deployed verifier for the VALID WALLET UPDATE circuit
        valid_wallet_update_verifier_address: ContractAddress,
        /// Stores the contract address of the deployed verifier for the VALID COMMITMENTS circuit
        valid_commitments_verifier_address: ContractAddress,
        /// Stores the contract address of the deployed verifier for the VALID REBLIND circuit
        valid_reblind_verifier_address: ContractAddress,
        /// Stores the contract address of the deployed verifier for the VALID MATCH MPC circuit
        valid_match_mpc_verifier_address: ContractAddress,
        /// Stores the contract address of the deployed verifier for the VALID SETTLE circuit
        valid_settle_verifier_address: ContractAddress,
        /// Mapping of elements to be used in the post-polling merkle & nullifier set
        /// callback logic for in-progress `new_wallet` verification jobs
        new_wallet_callback_elems: LegacyMap<felt252, StoreSerdeWrapper<NewWalletCallbackElems>>,
        /// Mapping of elements to be used in the post-polling merkle & nullifier set
        /// callback logic for in-progress `update_wallet` verification jobs
        update_wallet_callback_elems: LegacyMap<felt252,
        StoreSerdeWrapper<UpdateWalletCallbackElems>>,
        /// Mapping of elements to be used in the post-polling merkle & nullifier set
        /// callback logic for in-progress `process_match` verification jobs.
        /// Uses the first verification job id in the list of ids for the process_match proofs
        /// as the mapping key.
        process_match_callback_elems: LegacyMap<felt252,
        StoreSerdeWrapper<ProcessMatchCallbackElems>>,
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

    /// Emitted when there's a change to the verifier contract address
    #[derive(Drop, PartialEq, starknet::Event)]
    struct VerifierUpgrade {
        circuit: Circuit,
        old_address: ContractAddress,
        new_address: ContractAddress,
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
        VerifierUpgrade: VerifierUpgrade,
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

    // -------------
    // | INTERFACE |
    // -------------

    #[external(v0)]
    impl IDarkpoolImpl of super::IDarkpool<ContractState> {
        // -------------
        // | OWNERSHIP |
        // -------------

        /// Transfers ownership of the contract to a new address
        fn transfer_ownership(ref self: ContractState, new_owner: ContractAddress) {
            assert(!new_owner.is_zero(), 'New owner is the zero address');
            ownable__assert_only_owner(@self);
            _ownable__transfer_ownership(ref self, new_owner);
        }

        /// Returns the owner of the contract
        fn owner(self: @ContractState) -> ContractAddress {
            self._owner.read()
        }

        // ------------------
        // | INITIALIZATION |
        // ------------------

        /// Initializes the contract state
        /// Parameters:
        /// - `merkle_class_hash`: The declared contract class hash of the Merkle tree implementation
        /// - `nullifier_class_hash`: The declared contract class hash of the nullifier set implementation
        /// - `height`: The height of the Merkle tree
        fn initialize(
            ref self: ContractState,
            merkle_class_hash: ClassHash,
            nullifier_set_class_hash: ClassHash,
            height: u8,
        ) {
            ownable__assert_only_owner(@self);
            initializable__initialize(ref self);

            // Save Merkle tree & nullifier set class hashes to storage
            self.merkle_class_hash.write(merkle_class_hash);
            self.nullifier_set_class_hash.write(nullifier_set_class_hash);

            // Initialize the Merkle tree & verifier
            _get_merkle_tree(@self).initialize(height);
        }

        /// Initializes a verifier contract
        /// Parameters:
        /// - `verifier_contract_address`: The address of the deployed verifier contract
        /// - `circuit`: The circuit for which to initialize the verifier contract
        /// - `circuit_params`: The parameters of the circuit
        fn initialize_verifier(
            ref self: ContractState,
            circuit: Circuit,
            verifier_contract_address: ContractAddress,
            circuit_params: CircuitParams
        ) {
            ownable__assert_only_owner(@self);

            // Save verifier contract address to storage
            _write_verifier_address(ref self, circuit, verifier_contract_address);
            // Initialize the verifier
            _get_verifier(@self, circuit).initialize(circuit_params);
        }

        // -----------
        // | UPGRADE |
        // -----------

        /// Upgrades the Darkpool implementation class
        /// Parameters:
        /// - `darkpool_class_hash`: The hash of the new implementation class
        fn upgrade(ref self: ContractState, darkpool_class_hash: ClassHash) {
            ownable__assert_only_owner(@self);
            upgradeable__upgrade(ref self, darkpool_class_hash);
        }

        /// Upgrades the Merkle implementation class
        /// Parameters:
        /// - `merkle_class_hash`: The hash of the implementation class used for Merkle operations
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

        /// Upgrades the verifier contract address
        /// Parameters:
        /// - `verifier_contract_address`: The address of the deployed verifier contract
        /// - `circuit`: The circuit for which to upgrade the verifier
        fn upgrade_verifier(
            ref self: ContractState, circuit: Circuit, verifier_contract_address: ContractAddress
        ) {
            ownable__assert_only_owner(@self);

            // Get existing contract_address to emit event
            let old_address = _read_verifier_address(@self, circuit);
            _write_verifier_address(ref self, circuit, verifier_contract_address);

            // Emit event
            self
                .emit(
                    Event::VerifierUpgrade(
                        VerifierUpgrade {
                            circuit, old_address, new_address: verifier_contract_address
                        }
                    )
                );
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

        /// Returns whether a given nullifier has already been spent or is in use
        /// Parameters:
        /// - `nullifier`: The nullifier to check the set for
        /// Returns:
        /// - `true` if the nullifier is neither spent, nor in use, `false` otherwise`
        fn is_nullifier_available(self: @ContractState, nullifier: Scalar) -> bool {
            let nullifier_set = _get_nullifier_set(self);
            !(nullifier_set.is_nullifier_spent(nullifier)
                || nullifier_set.is_nullifier_in_use(nullifier))
        }

        /// Returns the status of the given verification job
        /// Parameters:
        /// - `verification_job_id`: The ID of the verification job to check
        /// Returns:
        /// - An optional boolean, which, if is `None`, means the job is still in progress,
        ///   and otherwise indicates whether or not the verification succeeded
        fn check_verification_job_status(
            self: @ContractState, circuit: Circuit, verification_job_id: felt252
        ) -> Option<bool> {
            _get_verifier(self, circuit).check_verification_job_status(verification_job_id)
        }

        // -----------
        // | SETTERS |
        // -----------

        /// Adds a new wallet to the commitment tree
        /// Parameters:
        /// - `wallet_blinder_share`: The public share of the wallet blinder, used for indexing
        /// - `statement`: Public inputs to the `VALID_WALLET_CREATE` circuit
        /// - `proof`: The proof of `VALID_WALLET_CREATE`
        /// - `witness_commitments`: The Pedersen commitments to the witness elements
        /// - `verification_job_id`: The ID of the verification job to enqueue
        fn new_wallet(
            ref self: ContractState,
            wallet_blinder_share: Scalar,
            statement: ValidWalletCreateStatement,
            mut witness_commitments: Array<EcPoint>,
            proof: Proof,
            verification_job_id: felt252,
        ) {
            let verifier = _get_verifier(@self, Circuit::ValidWalletCreate(()));

            // Inject witness
            let (B, B_blind) = verifier.get_pc_gens();
            append_statement_commitments(B, B_blind, @statement, ref witness_commitments);

            // Queue verification
            verifier.queue_verification_job(proof, witness_commitments, verification_job_id);

            // Store callback elements
            let callback_elems = NewWalletCallbackElems {
                wallet_blinder_share,
                public_wallet_shares: statement.public_wallet_shares,
                private_shares_commitment: statement.private_shares_commitment,
                tx_hash: get_tx_info().unbox().transaction_hash
            };
            self
                .new_wallet_callback_elems
                .write(verification_job_id, StoreSerdeWrapper { inner: callback_elems });
        }

        /// Poll the new wallet verification job, and if it verifies, insert the new wallet into the
        /// merkle tree
        /// Parameters:
        /// - `verification_job_id`: The ID of the verification job to step through
        /// Returns:
        /// - The new root after the wallet is inserted into the tree, if the proof verifies
        fn poll_new_wallet(
            ref self: ContractState, verification_job_id: felt252, 
        ) -> Option<Result<Scalar, felt252>> {
            let verifier = _get_verifier(@self, Circuit::ValidWalletCreate(()));

            assert(
                verifier.check_verification_job_status(verification_job_id).is_none(),
                'polling already complete'
            );

            let verified = verifier.step_verification(verification_job_id);

            match verified {
                Option::Some(success) => {
                    if success {
                        // Callback logic
                        let mut callback_elems = self
                            .new_wallet_callback_elems
                            .read(verification_job_id)
                            .inner;

                        // Insert the new wallet's commitment into the Merkle tree
                        let mut hash_input = ArrayTrait::new();
                        hash_input.append(callback_elems.private_shares_commitment);
                        hash_input.append_all(ref callback_elems.public_wallet_shares);
                        let total_shares_commitment = *poseidon_hash(
                            hash_input.span(), 1 // num_elements
                        )[0];

                        let merkle_tree = _get_merkle_tree(@self);
                        let new_root = merkle_tree.insert(total_shares_commitment);

                        // Mark wallet as updated
                        _mark_wallet_updated(
                            ref self, callback_elems.wallet_blinder_share, callback_elems.tx_hash
                        );

                        Option::Some(Result::Ok(new_root))
                    } else {
                        // Verification failed
                        Option::Some(Result::Err('verification failed'))
                    }
                },
                Option::None(()) => Option::None(())
            }
        }

        /// Update a wallet in the commitment tree
        /// Parameters:
        /// - `wallet_blinder_share`: The public share of the wallet blinder, used for indexing
        /// - `statement`: Public inputs to the `VALID_WALLET_UPDATE` circuit
        /// - `proof`: The proof of `VALID_WALLET_UPDATE`
        /// - `witness_commitments`: The Pedersen commitments to the witness elements
        /// - `verification_job_id`: The ID of the verification job to enqueue
        fn update_wallet(
            ref self: ContractState,
            wallet_blinder_share: Scalar,
            statement: ValidWalletUpdateStatement,
            statement_signature: (Scalar, Scalar),
            mut witness_commitments: Array<EcPoint>,
            proof: Proof,
            verification_job_id: felt252,
        ) {
            // Assert that the merkle root for which inclusion is proven in `VALID WALLET UPDATE`
            // is a valid historical root
            assert(
                _get_merkle_tree(@self).root_in_history(statement.merkle_root),
                'invalid statement merkle root'
            );

            // Assert that statement signature is valid
            let statement_hash = hash_statement(@statement);
            let (r, s) = statement_signature;
            assert(
                check_ecdsa_signature(
                    statement_hash.into(), statement.old_pk_root.get_x(), r.into(), s.into()
                ),
                'invalid statement signature'
            );

            // Mark the `old_shares_nullifier` as in use
            _get_nullifier_set(@self).mark_nullifier_in_use(statement.old_shares_nullifier);

            let verifier = _get_verifier(@self, Circuit::ValidWalletUpdate(()));

            // Inject witness
            let (B, B_blind) = verifier.get_pc_gens();
            append_statement_commitments(B, B_blind, @statement, ref witness_commitments);

            // Queue verification
            verifier.queue_verification_job(proof, witness_commitments, verification_job_id);

            // Store callback elements
            let external_transfer = if statement.external_transfer == Default::default() {
                Option::None(())
            } else {
                Option::Some(statement.external_transfer)
            };

            let callback_elems = UpdateWalletCallbackElems {
                wallet_blinder_share,
                old_shares_nullifier: statement.old_shares_nullifier,
                new_public_shares: statement.new_public_shares,
                new_private_shares_commitment: statement.new_private_shares_commitment,
                external_transfer,
                tx_hash: get_tx_info().unbox().transaction_hash
            };
            self
                .update_wallet_callback_elems
                .write(verification_job_id, StoreSerdeWrapper { inner: callback_elems.clone() });
        }

        /// Poll the update wallet verification job, and if it verifies, insert the updated wallet into the
        /// merkle tree
        /// Parameters:
        /// - `verification_job_id`: The ID of the verification job to step through
        /// Returns:
        /// - The root of the tree after the new commitment is inserted, if the proof verifies
        fn poll_update_wallet(
            ref self: ContractState, verification_job_id: felt252, 
        ) -> Option<Result<Scalar, felt252>> {
            let verifier = _get_verifier(@self, Circuit::ValidWalletUpdate(()));

            assert(
                verifier.check_verification_job_status(verification_job_id).is_none(),
                'polling already complete'
            );

            let verified = verifier.step_verification(verification_job_id);

            match verified {
                Option::Some(success) => {
                    let nullifier_set = _get_nullifier_set(@self);
                    let mut callback_elems = self
                        .update_wallet_callback_elems
                        .read(verification_job_id)
                        .inner;

                    if success {
                        // Callback logic

                        // Insert the updated wallet's commitment into the Merkle tree
                        let mut hash_input = ArrayTrait::new();
                        hash_input.append(callback_elems.new_private_shares_commitment);
                        hash_input.append_all(ref callback_elems.new_public_shares);
                        let total_shares_commitment = *poseidon_hash(
                            hash_input.span(), 1 // num_elements
                        )[0];

                        let merkle_tree = _get_merkle_tree(@self);
                        let new_root = merkle_tree.insert(total_shares_commitment);

                        // Add the old shares nullifier to the spent nullifier set
                        nullifier_set.mark_nullifier_spent(callback_elems.old_shares_nullifier);

                        // Process the external transfer
                        match callback_elems.external_transfer {
                            Option::Some(transfer) => _execute_external_transfer(
                                ref self, transfer
                            ),
                            Option::None(()) => {}
                        };

                        // Mark wallet as updated
                        _mark_wallet_updated(
                            ref self, callback_elems.wallet_blinder_share, callback_elems.tx_hash
                        );

                        Option::Some(Result::Ok(new_root))
                    } else {
                        // Verification failed
                        nullifier_set.mark_nullifier_unused(callback_elems.old_shares_nullifier);
                        Option::Some(Result::Err('verification failed'))
                    }
                },
                Option::None(()) => Option::None(())
            }
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
            mut party_0_payload: MatchPayload,
            mut party_1_payload: MatchPayload,
            valid_match_mpc_witness_commitments: Array<EcPoint>,
            valid_match_mpc_proof: Proof,
            valid_settle_statement: ValidSettleStatement,
            mut valid_settle_witness_commitments: Array<EcPoint>,
            valid_settle_proof: Proof,
            verification_job_ids: Array<felt252>,
        ) {
            // Assert that the merkle roots for which inclusion is proven in `VALID REBLIND`
            // are valid historical roots
            let merkle_tree = _get_merkle_tree(@self);
            assert(
                merkle_tree.root_in_history(party_0_payload.valid_reblind_statement.merkle_root),
                'invalid statement merkle root'
            );
            assert(
                merkle_tree.root_in_history(party_1_payload.valid_reblind_statement.merkle_root),
                'invalid statement merkle root'
            );

            // Mark the `original_shares_nullifier`s as in use
            let nullifier_set = _get_nullifier_set(@self);
            nullifier_set
                .mark_nullifier_in_use(
                    party_0_payload.valid_reblind_statement.original_shares_nullifier
                );
            nullifier_set
                .mark_nullifier_in_use(
                    party_1_payload.valid_reblind_statement.original_shares_nullifier
                );

            // Inject witnesses & queue verifications
            // TODO: This probably won't fit in a transaction... think about how to handle this

            // Party 0 VALID COMMITMENTS
            let valid_commitments_verifier = _get_verifier(@self, Circuit::ValidCommitments(()));
            let (valid_commitments_B, valid_commitments_B_blind) = valid_commitments_verifier
                .get_pc_gens();
            append_statement_commitments(
                valid_commitments_B,
                valid_commitments_B_blind,
                @party_0_payload.valid_commitments_statement,
                ref party_0_payload.valid_commitments_witness_commitments
            );
            valid_commitments_verifier
                .queue_verification_job(
                    party_0_payload.valid_commitments_proof,
                    party_0_payload.valid_commitments_witness_commitments,
                    *verification_job_ids[0]
                );

            // Party 0 VALID REBLIND
            let valid_reblind_verifier = _get_verifier(@self, Circuit::ValidReblind(()));
            let (valid_reblind_B, valid_reblind_B_blind) = valid_reblind_verifier.get_pc_gens();
            append_statement_commitments(
                valid_reblind_B,
                valid_reblind_B_blind,
                @party_0_payload.valid_reblind_statement,
                ref party_0_payload.valid_reblind_witness_commitments
            );
            valid_reblind_verifier
                .queue_verification_job(
                    party_0_payload.valid_reblind_proof,
                    party_0_payload.valid_reblind_witness_commitments,
                    *verification_job_ids[1]
                );

            // Party 1 VALID COMMITMENTS
            append_statement_commitments(
                valid_commitments_B,
                valid_commitments_B_blind,
                @party_1_payload.valid_commitments_statement,
                ref party_1_payload.valid_commitments_witness_commitments
            );
            valid_commitments_verifier
                .queue_verification_job(
                    party_1_payload.valid_commitments_proof,
                    party_1_payload.valid_commitments_witness_commitments,
                    *verification_job_ids[2]
                );

            // Party 1 VALID REBLIND
            append_statement_commitments(
                valid_reblind_B,
                valid_reblind_B_blind,
                @party_1_payload.valid_reblind_statement,
                ref party_1_payload.valid_reblind_witness_commitments
            );
            valid_reblind_verifier
                .queue_verification_job(
                    party_1_payload.valid_reblind_proof,
                    party_1_payload.valid_reblind_witness_commitments,
                    *verification_job_ids[3]
                );

            // VALID MATCH MPC
            // No statement to inject into witness
            let valid_match_mpc_verifier = _get_verifier(@self, Circuit::ValidMatchMpc(()));
            valid_match_mpc_verifier
                .queue_verification_job(
                    valid_match_mpc_proof,
                    valid_match_mpc_witness_commitments,
                    *verification_job_ids[4]
                );

            // VALID SETTLE
            let valid_settle_verifier = _get_verifier(@self, Circuit::ValidSettle(()));
            let (valid_settle_B, valid_settle_B_blind) = valid_settle_verifier.get_pc_gens();
            append_statement_commitments(
                valid_settle_B,
                valid_settle_B_blind,
                @valid_settle_statement,
                ref valid_settle_witness_commitments
            );
            valid_settle_verifier
                .queue_verification_job(
                    valid_settle_proof, valid_settle_witness_commitments, *verification_job_ids[5]
                );

            // Store callback elements
            let callback_elems = ProcessMatchCallbackElems {
                party_0_wallet_blinder_share: party_0_payload.wallet_blinder_share,
                party_0_reblinded_private_shares_commitment: party_0_payload
                    .valid_reblind_statement
                    .reblinded_private_shares_commitment,
                party_0_modified_shares: valid_settle_statement.party0_modified_shares,
                party_0_original_shares_nullifier: party_0_payload
                    .valid_reblind_statement
                    .original_shares_nullifier,
                party_1_wallet_blinder_share: party_1_payload.wallet_blinder_share,
                party_1_reblinded_private_shares_commitment: party_1_payload
                    .valid_reblind_statement
                    .reblinded_private_shares_commitment,
                party_1_modified_shares: valid_settle_statement.party1_modified_shares,
                party_1_original_shares_nullifier: party_1_payload
                    .valid_reblind_statement
                    .original_shares_nullifier,
                tx_hash: get_tx_info().unbox().transaction_hash
            };
            self
                .process_match_callback_elems
                .write( // Use the first verification job id as the mapping key for the callback elements
                    *verification_job_ids[0], StoreSerdeWrapper { inner: callback_elems }
                );
        }

        /// Poll the process match verification job, and if it verifies, insert the updated wallet into the
        /// merkle tree
        /// Parameters:
        /// - `verification_job_id`: The ID of the verification job to step through
        /// Returns:
        /// - The root of the tree after the new commitment is inserted, if the proof verifies
        fn poll_process_match(
            ref self: ContractState, verification_job_ids: Array<felt252>, 
        ) -> Option<Result<Scalar, felt252>> {
            let valid_commitments_verifier = _get_verifier(@self, Circuit::ValidCommitments(()));
            let valid_reblind_verifier = _get_verifier(@self, Circuit::ValidReblind(()));
            let valid_match_mpc_verifier = _get_verifier(@self, Circuit::ValidMatchMpc(()));
            let valid_settle_verifier = _get_verifier(@self, Circuit::ValidSettle(()));

            let verifiers = array![
                valid_commitments_verifier,
                valid_reblind_verifier,
                valid_commitments_verifier,
                valid_reblind_verifier,
                valid_match_mpc_verifier,
                valid_settle_verifier,
            ]
                .span();
            let verification_job_ids = verification_job_ids.span();

            assert(
                verifiers.len() == verification_job_ids.len(), 'wrong # of verification job ids'
            );

            // Assert that no verification jobs have failed, and that not all are complete
            let mut i = 0;
            let mut should_poll = false;
            loop {
                if i == verification_job_ids.len() {
                    break;
                }

                let verified = (*verifiers[i])
                    .check_verification_job_status(*verification_job_ids[i]);

                match verified {
                    Option::Some(success) => {
                        if !success {
                            break;
                        }
                    },
                    Option::None(()) => {
                        should_poll = true;
                        break;
                    },
                };

                i += 1;
            };
            assert(should_poll, 'polling already complete');

            let mut all_verified = Option::None(());
            loop {
                if i == verification_job_ids.len() {
                    all_verified = Option::Some(true);
                    break;
                };

                let verified = (*verifiers[i]).step_verification(*verification_job_ids[i]);

                match verified {
                    Option::Some(success) => {
                        if !success {
                            all_verified = Option::Some(false);
                            break;
                        };

                        i += 1;
                    },
                    Option::None(()) => {
                        break;
                    },
                };
            };

            match all_verified {
                Option::Some(success) => {
                    let nullifier_set = _get_nullifier_set(@self);
                    let mut callback_elems = self
                        .process_match_callback_elems
                        .read(*verification_job_ids[0])
                        .inner;

                    if success {
                        // Callback logic

                        // Insert both parties' old shares nullifiers to the spent nullifier set
                        nullifier_set
                            .mark_nullifier_spent(callback_elems.party_0_original_shares_nullifier);
                        nullifier_set
                            .mark_nullifier_spent(callback_elems.party_1_original_shares_nullifier);

                        // Insert both partes' updated wallet commitments to the merkle tree
                        let mut party_0_hash_input = ArrayTrait::new();
                        party_0_hash_input
                            .append(callback_elems.party_0_reblinded_private_shares_commitment);
                        party_0_hash_input.append_all(ref callback_elems.party_0_modified_shares);
                        let party_0_total_shares_commitment = *poseidon_hash(
                            party_0_hash_input.span(), 1 // num_elements
                        )[0];
                        let mut party_1_hash_input = ArrayTrait::new();
                        party_1_hash_input
                            .append(callback_elems.party_1_reblinded_private_shares_commitment);
                        party_1_hash_input.append_all(ref callback_elems.party_1_modified_shares);
                        let party_1_total_shares_commitment = *poseidon_hash(
                            party_1_hash_input.span(), 1 // num_elements
                        )[0];

                        let merkle_tree = _get_merkle_tree(@self);
                        merkle_tree.insert(party_0_total_shares_commitment);
                        let new_root = merkle_tree.insert(party_1_total_shares_commitment);

                        // Mark wallet as updated
                        _mark_wallet_updated(
                            ref self,
                            callback_elems.party_0_wallet_blinder_share,
                            callback_elems.tx_hash
                        );
                        _mark_wallet_updated(
                            ref self,
                            callback_elems.party_1_wallet_blinder_share,
                            callback_elems.tx_hash
                        );

                        Option::Some(Result::Ok(new_root))
                    } else {
                        // Verification failed
                        nullifier_set
                            .mark_nullifier_unused(
                                callback_elems.party_0_original_shares_nullifier
                            );
                        nullifier_set
                            .mark_nullifier_unused(
                                callback_elems.party_1_original_shares_nullifier
                            );
                        Option::Some(Result::Err('verification failed'))
                    }
                },
                Option::None(()) => Option::None(()),
            }
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

    /// Returns the contract dispatcher struct for the verifier interface,
    /// using the currently stored verifier contract address for the given circuit
    /// Parameters:
    /// - `circuit`: The circuit for which to get the verifier contract
    /// Returns:
    /// - Contract dispatcher instance
    fn _get_verifier(self: @ContractState, circuit: Circuit) -> IVerifierDispatcher {
        let contract_address = _read_verifier_address(self, circuit);

        IVerifierDispatcher { contract_address }
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

    /// Returns the currently stored contract address of the verifier contract for the given circuit
    /// Parameters:
    /// - `circuit`: The circuit for which to get the verifier contract address
    fn _read_verifier_address(self: @ContractState, circuit: Circuit) -> ContractAddress {
        match circuit {
            Circuit::ValidWalletCreate(()) => self.valid_wallet_create_verifier_address.read(),
            Circuit::ValidWalletUpdate(()) => self.valid_wallet_update_verifier_address.read(),
            Circuit::ValidCommitments(()) => self.valid_commitments_verifier_address.read(),
            Circuit::ValidReblind(()) => self.valid_reblind_verifier_address.read(),
            Circuit::ValidMatchMpc(()) => self.valid_match_mpc_verifier_address.read(),
            Circuit::ValidSettle(()) => self.valid_settle_verifier_address.read(),
        }
    }

    // -----------
    // | SETTERS |
    // -----------

    /// Stores a new verifier contract address for the given circuit
    /// Parameters:
    /// - `circuit`: The circuit for which to store the verifier contract address
    /// - `verifier_contract_address`: The address of the deployed verifier contract
    fn _write_verifier_address(
        ref self: ContractState, circuit: Circuit, verifier_contract_address: ContractAddress
    ) {
        match circuit {
            Circuit::ValidWalletCreate(()) => self
                .valid_wallet_create_verifier_address
                .write(verifier_contract_address),
            Circuit::ValidWalletUpdate(()) => self
                .valid_wallet_update_verifier_address
                .write(verifier_contract_address),
            Circuit::ValidCommitments(()) => self
                .valid_commitments_verifier_address
                .write(verifier_contract_address),
            Circuit::ValidReblind(()) => self
                .valid_reblind_verifier_address
                .write(verifier_contract_address),
            Circuit::ValidMatchMpc(()) => self
                .valid_match_mpc_verifier_address
                .write(verifier_contract_address),
            Circuit::ValidSettle(()) => self
                .valid_settle_verifier_address
                .write(verifier_contract_address),
        }
    }

    /// Sets the wallet update storage variable to the current transaction hash,
    /// indicating that the wallet has been modified at this transaction
    /// Parameters:
    /// - `wallet_blinder_share`: The identifier of the wallet
    fn _mark_wallet_updated(
        ref self: ContractState, wallet_blinder_share: Scalar, tx_hash: felt252
    ) {
        // Check that wallet blinder share isn't already indexed
        assert(self.wallet_last_modified.read(wallet_blinder_share) == 0, 'wallet already indexed');
        // Update storage mapping
        self.wallet_last_modified.write(wallet_blinder_share, tx_hash);
        // Emit event
        self.emit(Event::WalletUpdate(WalletUpdate { wallet_blinder_share }));
    }

    /// Executes an external ERC20 transfer
    /// Parameters:
    /// - `transfer`: The external transfer to execute
    fn _execute_external_transfer(ref self: ContractState, mut transfer: ExternalTransfer) {
        let contract_address = get_contract_address();

        // Get contract dispatcher instance for transfer mint
        let erc20 = _get_erc20(transfer.mint);

        // Execute the transfer
        if transfer.is_withdrawal {
            // Withdraw
            erc20.transfer(transfer.account_addr, transfer.amount);

            // Emit event
            self
                .emit(
                    Event::Withdrawal(
                        Withdrawal {
                            recipient: transfer.account_addr,
                            mint: transfer.mint,
                            amount: transfer.amount
                        }
                    )
                );
        } else {
            // Deposit
            erc20.transferFrom(transfer.account_addr, contract_address, transfer.amount);

            // Emit event
            self
                .emit(
                    Event::Deposit(
                        Deposit {
                            sender: transfer.account_addr,
                            mint: transfer.mint,
                            amount: transfer.amount
                        }
                    )
                );
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
