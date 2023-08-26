use traits::Into;
use clone::Clone;
use array::ArrayTrait;

use alexandria_data_structures::array_ext::ArrayTraitExt;
use renegade_contracts::{
    verifier::scalar::{Scalar, ScalarSerializable}, utils::eq::ArrayTPartialEq
};

use super::types::{ExternalTransfer, PublicSigningKey};

// -------------------
// | STATEMENT TYPES |
// -------------------
/// All statement types are assumed to have the same serialization
/// to/from Scalars as the relayer-side implementation.

/// Statement for the VALID_WALLET_CREATE proof
#[derive(Drop, Serde, Clone, PartialEq)]
struct ValidWalletCreateStatement {
    /// The commitment to the private secret shares of the wallet
    private_shares_commitment: Scalar,
    /// The public secret shares of the wallet
    public_wallet_shares: Array<Scalar>,
}

impl ValidWalletCreateStatementToScalarsImpl of ScalarSerializable<ValidWalletCreateStatement> {
    fn to_scalars(self: @ValidWalletCreateStatement) -> Array<Scalar> {
        let mut scalars = ArrayTrait::new();
        // TODO: Consider forking ArrayTraitExt impl to be able to avoid this clone
        let mut public_wallet_shares = self.public_wallet_shares.clone();

        scalars.append(*self.private_shares_commitment);
        scalars.append_all(ref public_wallet_shares);

        scalars
    }
}

/// Statement for the VALID_WALLET_UPDATE proof
#[derive(Drop, Serde, Clone, PartialEq)]
struct ValidWalletUpdateStatement {
    /// The nullifier of the old wallet's secret shares
    old_shares_nullifier: Scalar,
    /// A commitment to the new wallet's private secret shares
    new_private_shares_commitment: Scalar,
    /// The public secret shares of the new wallet
    new_public_shares: Array<Scalar>,
    /// A historic merkle root for which we prove inclusion of
    /// the commitment to the old wallet's private secret shares
    merkle_root: Scalar,
    /// The external transfer associated with this update
    external_transfer: ExternalTransfer,
    /// The public root key of the old wallet, rotated out after this update
    old_pk_root: PublicSigningKey,
    /// The timestamp this update was applied at
    timestamp: u64,
}

impl ValidWalletUpdateStatementToScalarsImpl of ScalarSerializable<ValidWalletUpdateStatement> {
    fn to_scalars(self: @ValidWalletUpdateStatement) -> Array<Scalar> {
        let mut scalars = ArrayTrait::new();
        let mut new_public_shares = self.new_public_shares.clone();
        let mut old_pk_root = self.old_pk_root.clone();
        let mut external_transfer_scalars = self.external_transfer.to_scalars();

        scalars.append(*self.old_shares_nullifier);
        scalars.append(*self.new_private_shares_commitment);
        scalars.append_all(ref new_public_shares);
        scalars.append(*self.merkle_root);
        scalars.append_all(ref external_transfer_scalars);
        scalars.append_all(ref old_pk_root.x);
        scalars.append_all(ref old_pk_root.y);
        scalars.append((*self.timestamp).into());

        scalars
    }
}

/// Statement for the VALID_REBLIND proof
#[derive(Drop, Serde, Copy, PartialEq)]
struct ValidReblindStatement {
    /// The nullifier of the original wallet's secret shares
    original_shares_nullifier: Scalar,
    /// A commitment to the private secret shares of the reblinded wallet
    reblinded_private_shares_commitment: Scalar,
    /// A historic merkle root for which we prove inclusion of
    /// the commitment to the original wallet's private secret shares
    merkle_root: Scalar,
}

impl ValidReblindStatementToScalarsImpl of ScalarSerializable<ValidReblindStatement> {
    fn to_scalars(self: @ValidReblindStatement) -> Array<Scalar> {
        let mut scalars = ArrayTrait::new();

        scalars.append(*self.original_shares_nullifier);
        scalars.append(*self.reblinded_private_shares_commitment);
        scalars.append(*self.merkle_root);

        scalars
    }
}

/// Statememt for the VALID_COMMITMENTS proof
#[derive(Drop, Serde, Copy, PartialEq)]
struct ValidCommitmentsStatement {
    /// The index of the balance sent by the party if a successful match occurs
    balance_send_index: u64,
    /// The index of the balance received by the party if a successful match occurs
    balance_receive_index: u64,
    /// The index of the order being matched
    order_index: u64,
}

impl ValidCommitmentsStatementToScalarsImpl of ScalarSerializable<ValidCommitmentsStatement> {
    fn to_scalars(self: @ValidCommitmentsStatement) -> Array<Scalar> {
        let mut scalars = ArrayTrait::new();

        scalars.append((*self.balance_send_index).into());
        scalars.append((*self.balance_receive_index).into());
        scalars.append((*self.order_index).into());

        scalars
    }
}

/// Statement for the VALID_SETTLE proof
#[derive(Drop, Serde, Clone, PartialEq)]
struct ValidSettleStatement {
    /// The modified public secret shares of the first party
    party0_modified_shares: Array<Scalar>,
    /// The modified public secret shares of the second party
    party1_modified_shares: Array<Scalar>,
    /// The index of the balance sent by the first party in the settlement
    party0_send_balance_index: u64,
    /// The index of the balance received by the first party in the settlement
    party0_receive_balance_index: u64,
    /// The index of the first party's matched order
    party0_order_index: u64,
    /// The index of the balance sent by the second party in the settlement
    party1_send_balance_index: u64,
    /// The index of the balance received by the second party in the settlement
    party1_receive_balance_index: u64,
    /// The index of the second party's matched order
    party1_order_index: u64,
}

impl ValidSettleStatementToScalarsImpl of ScalarSerializable<ValidSettleStatement> {
    fn to_scalars(self: @ValidSettleStatement) -> Array<Scalar> {
        let mut scalars = ArrayTrait::new();
        let mut party0_modified_shares = self.party0_modified_shares.clone();
        let mut party1_modified_shares = self.party1_modified_shares.clone();

        scalars.append_all(ref party0_modified_shares);
        scalars.append_all(ref party1_modified_shares);
        scalars.append((*self.party0_send_balance_index).into());
        scalars.append((*self.party0_receive_balance_index).into());
        scalars.append((*self.party0_order_index).into());
        scalars.append((*self.party1_send_balance_index).into());
        scalars.append((*self.party1_receive_balance_index).into());
        scalars.append((*self.party1_order_index).into());

        scalars
    }
}
