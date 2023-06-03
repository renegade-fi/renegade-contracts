mod library;

#[contract]
mod Darkpool {
    use starknet::ClassHash;
    use starknet::ContractAddress;
    use array::ArrayTrait;

    use renegade_contracts::oz::initializable::library::InitializableLib;
    use renegade_contracts::oz::ownable::library::OwnableLib;
    use renegade_contracts::oz::upgradeable::library::UpgradeableLib;
    use super::library::DarkpoolLib;

    // ---------------
    // | CONSTRUCTOR |
    // ---------------

    #[constructor]
    fn constructor(owner: ContractAddress) {
        OwnableLib::initializer(owner)
    }

    // -----------
    // | UPGRADE |
    // -----------

    #[external]
    fn upgrade(impl_hash: ClassHash) {
        OwnableLib::assert_only_owner();
        UpgradeableLib::upgrade(impl_hash)
    }

    // ---------
    // | PROXY |
    // ---------

    #[external]
    fn initializer(merkle_class_hash: ClassHash, nullifier_set_class_hash: ClassHash, height: u8) {
        OwnableLib::assert_only_owner();
        InitializableLib::initialize();
        DarkpoolLib::initializer(merkle_class_hash, nullifier_set_class_hash, height)
    }

    #[external]
    fn upgrade_merkle(merkle_class_hash: ClassHash) {
        OwnableLib::assert_only_owner();
        DarkpoolLib::set_merkle_class(merkle_class_hash)
    }

    #[external]
    fn upgrade_nullifier_set(nullifier_set_class_hash: ClassHash) {
        OwnableLib::assert_only_owner();
        DarkpoolLib::set_nullifier_set_class(nullifier_set_class_hash)
    }

    // -------------
    // | INTERFACE |
    // -------------

    #[view]
    fn get_wallet_blinder_transaction(public_blinder_share: felt252) -> felt252 {
        DarkpoolLib::get_wallet_blinder_transaction(public_blinder_share)
    }

    #[view]
    fn get_root() -> felt252 {
        DarkpoolLib::get_root()
    }

    #[view]
    fn root_in_history(root: felt252) -> bool {
        DarkpoolLib::root_in_history(root)
    }

    #[view]
    fn is_nullifier_used(nullifier: felt252) -> bool {
        DarkpoolLib::is_nullifier_used(nullifier)
    }

    #[external]
    fn new_wallet(
        wallet_blinder_share: felt252,
        wallet_share_commitment: felt252,
        public_wallet_shares: Array::<felt252>,
        proof_blob: Array::<felt252>,
    ) -> felt252 {
        DarkpoolLib::new_wallet(
            wallet_blinder_share, wallet_share_commitment, public_wallet_shares, proof_blob, 
        )
    }

    #[external]
    fn update_wallet(
        wallet_blinder_share: felt252,
        wallet_share_commitment: felt252,
        old_shares_nullifier: felt252,
        public_wallet_shares: Array::<felt252>,
        mut external_transfers: Array::<DarkpoolLib::ExternalTransfer>,
        proof_blob: Array::<felt252>,
    ) -> felt252 {
        DarkpoolLib::update_wallet(
            wallet_blinder_share,
            wallet_share_commitment,
            old_shares_nullifier,
            public_wallet_shares,
            external_transfers,
            proof_blob,
        )
    }

    #[external]
    fn process_match(
        party_0_payload: DarkpoolLib::MatchPayload,
        party_1_payload: DarkpoolLib::MatchPayload,
        match_proof_blob: Array::<felt252>,
        settle_proof_blob: Array::<felt252>,
    ) -> felt252 {
        DarkpoolLib::process_match(
            party_0_payload, party_1_payload, match_proof_blob, settle_proof_blob, 
        )
    }
}
