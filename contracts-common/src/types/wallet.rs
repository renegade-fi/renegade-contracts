//! Types related to darkpool wallets

use super::{
    u256_to_scalar, ExternalMatchResult, FeeRates, FixedPoint, OrderSettlementIndices,
    PublicEncryptionKey, PublicKeychain, ScalarField,
};
use crate::types::{BabyJubJubPoint, PublicIdentificationKey, PublicRootKey};
use alloc::vec::Vec;

/// Error message for when a vector cannot be sized into an array
pub const VEC_SIZE_ERROR: &[u8] = b"Vector length does not match array size";

/// The maximum number of balances in a wallet
pub const MAX_BALANCES: usize = 10;
/// The maximum number of orders in a wallet
pub const MAX_ORDERS: usize = 4;
/// The number of scalars in a serialized wallet share
pub const NUM_WALLET_SCALARS: usize = 70;

/// Helper function to size a vector into an array
pub fn size_vec<T, const N: usize>(vec: Vec<T>) -> Result<[T; N], Vec<u8>> {
    vec.try_into().map_err(|_| VEC_SIZE_ERROR.to_vec())
}

/// A secret share of a darkpool wallet
#[cfg(feature = "core-settlement")]
pub struct WalletShare {
    /// The list of balances in the wallet
    pub balances: [BalanceShare; MAX_BALANCES],
    /// The list of orders in the wallet
    pub orders: [OrderShare; MAX_ORDERS],
    /// The keychain of the wallet
    pub keychain: PublicKeychain,
    /// The maximum match fee that the user is willing to pay for a match
    pub max_match_fee: FixedPoint,
    /// The public key of the cluster that the wallet has authorized to collect
    /// match fees
    pub managing_cluster: PublicEncryptionKey,
    /// The public share of the wallet's blinder
    pub blinder: ScalarField,
}

#[cfg(feature = "core-settlement")]
impl WalletShare {
    /// Apply an external match to a wallet's shares
    ///
    /// SAFETY: It is assumed that all balance increment/decrements have been
    /// checked for overflow elsewhere, e.g. in-circuit
    pub fn apply_external_match_to_shares(
        &mut self,
        internal_party_fee_rate: FeeRates,
        match_result: &ExternalMatchResult,
        indices: OrderSettlementIndices,
    ) {
        // Deduct the matched amount from the order's volume
        let base_amt_scalar = u256_to_scalar(match_result.base_amount).unwrap();
        self.orders[indices.order as usize].amount -= base_amt_scalar;

        // Compute the fees owed by the internal party
        let (_, recv_amount) = match_result.external_party_sell_mint_amount();
        let (_, send_amount) = match_result.external_party_buy_mint_amount();
        let internal_party_fees = internal_party_fee_rate.get_fee_take(recv_amount);

        // Add the receive amount to the wallet's balances
        let net_receive_amount = recv_amount - internal_party_fees.total();
        let recv_bal = &mut self.balances[indices.balance_receive as usize];

        recv_bal.amount += u256_to_scalar(net_receive_amount).unwrap();
        recv_bal.relayer_fee_balance += u256_to_scalar(internal_party_fees.relayer_fee).unwrap();
        recv_bal.protocol_fee_balance += u256_to_scalar(internal_party_fees.protocol_fee).unwrap();

        // Deduct the send amount from the wallet's balances
        let send_bal = &mut self.balances[indices.balance_send as usize];
        send_bal.amount -= u256_to_scalar(send_amount).unwrap();
    }

    /// Serialize a wallet share into a list of scalars
    pub fn scalar_serialize(&self) -> [ScalarField; NUM_WALLET_SCALARS] {
        let mut scalars = [ScalarField::default(); NUM_WALLET_SCALARS];
        let mut offset = 0;

        // Serialize the balances
        for balance in &self.balances {
            scalars[offset] = balance.token;
            scalars[offset + 1] = balance.amount;
            scalars[offset + 2] = balance.relayer_fee_balance;
            scalars[offset + 3] = balance.protocol_fee_balance;
            offset += 4;
        }

        // Serialize the orders
        for order in &self.orders {
            scalars[offset] = order.quote_mint;
            scalars[offset + 1] = order.base_mint;
            scalars[offset + 2] = order.side;
            scalars[offset + 3] = order.amount;
            scalars[offset + 4] = order.worst_case_price;
            offset += 5;
        }

        // Serialize the keychain
        scalars[offset] = self.keychain.pk_root.x[0];
        scalars[offset + 1] = self.keychain.pk_root.x[1];
        scalars[offset + 2] = self.keychain.pk_root.y[0];
        scalars[offset + 3] = self.keychain.pk_root.y[1];
        scalars[offset + 4] = self.keychain.pk_match.key;
        scalars[offset + 5] = self.keychain.nonce;
        offset += 6;

        // Serialize the max match fee
        scalars[offset] = self.max_match_fee.repr;
        offset += 1;

        // Serialize the managing cluster
        scalars[offset] = self.managing_cluster.x;
        scalars[offset + 1] = self.managing_cluster.y;
        offset += 2;

        // Serialize the blinder
        scalars[offset] = self.blinder;

        scalars
    }

    /// Deserialize a wallet share from a list of scalars
    pub fn scalar_deserialize(scalars: &[ScalarField]) -> Self {
        assert_eq!(scalars.len(), NUM_WALLET_SCALARS, "Scalar length does not match expected size");
        let mut offset = 0;

        // Deserialize the balances
        let mut balances_vec = Vec::with_capacity(MAX_BALANCES);
        for _ in 0..MAX_BALANCES {
            balances_vec.push(BalanceShare {
                token: scalars[offset],
                amount: scalars[offset + 1],
                relayer_fee_balance: scalars[offset + 2],
                protocol_fee_balance: scalars[offset + 3],
            });
            offset += 4;
        }
        let balances = size_vec(balances_vec).unwrap();

        // Deserialize the orders
        let mut orders_vec = Vec::with_capacity(MAX_ORDERS);
        for _ in 0..MAX_ORDERS {
            orders_vec.push(OrderShare {
                quote_mint: scalars[offset],
                base_mint: scalars[offset + 1],
                side: scalars[offset + 2],
                amount: scalars[offset + 3],
                worst_case_price: scalars[offset + 4],
            });
            offset += 5;
        }
        let orders = size_vec(orders_vec).unwrap();

        // Deserialize the keychain
        let keychain = PublicKeychain {
            pk_root: PublicRootKey {
                x: [scalars[offset], scalars[offset + 1]],
                y: [scalars[offset + 2], scalars[offset + 3]],
            },
            pk_match: PublicIdentificationKey { key: scalars[offset + 4] },
            nonce: scalars[offset + 5],
        };
        offset += 6;

        // Deserialize the max match fee
        let max_match_fee = FixedPoint { repr: scalars[offset] };
        offset += 1;

        // Deserialize the managing cluster
        let managing_cluster = BabyJubJubPoint { x: scalars[offset], y: scalars[offset + 1] };
        offset += 2;

        // Deserialize the blinder
        let blinder = scalars[offset];
        Self { balances, orders, keychain, max_match_fee, managing_cluster, blinder }
    }
}

/// A secret share of a balance in a darkpool wallet
#[derive(Copy, Clone, Debug)]
pub struct BalanceShare {
    /// The address of the token
    pub token: ScalarField,
    /// The amount of the balance
    pub amount: ScalarField,
    /// The amount of the balance owed to the managing relayer cluster
    pub relayer_fee_balance: ScalarField,
    /// The amount of the balance owed to the protocol
    pub protocol_fee_balance: ScalarField,
}

/// A secret share of an order in a darkpool wallet
#[derive(Clone, Copy, Debug)]
pub struct OrderShare {
    /// The address of the quote token
    pub quote_mint: ScalarField,
    /// The address of the base token
    pub base_mint: ScalarField,
    /// The direction of the order (buy/sell)
    pub side: ScalarField,
    /// The amount of the order
    pub amount: ScalarField,
    /// The worst case price that the user is willing to accept on this order.
    /// For buy orders, this is the maximum price willing to pay.
    /// For sell orders, this is the minimum price willing to accept.
    pub worst_case_price: ScalarField,
}

#[cfg(test)]
mod tests {
    use ark_ff::UniformRand;
    use rand::thread_rng;

    use super::*;

    #[test]
    fn test_scalar_serialize_deserialize() {
        // Generate random scalars
        let mut rng = thread_rng();
        let mut scalars = Vec::new();
        for _ in 0..NUM_WALLET_SCALARS {
            scalars.push(ScalarField::rand(&mut rng));
        }

        // Deserialize then serialize the wallet
        let sized_scalars = size_vec(scalars).unwrap();
        let wallet = WalletShare::scalar_deserialize(&sized_scalars);
        let serialized = wallet.scalar_serialize();
        assert_eq!(sized_scalars, serialized);
    }
}
