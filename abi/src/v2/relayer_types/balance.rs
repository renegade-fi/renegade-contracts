//! Balance type conversions

use renegade_circuit_types_v2::balance::PostMatchBalanceShare;
use renegade_crypto_v2::fields::scalar_to_u256;

use crate::v2::{relayer_types::u256_to_scalar, IDarkpoolV2};

impl From<PostMatchBalanceShare> for IDarkpoolV2::PostMatchBalanceShare {
    fn from(share: PostMatchBalanceShare) -> Self {
        Self {
            relayerFeeBalance: scalar_to_u256(&share.relayer_fee_balance),
            protocolFeeBalance: scalar_to_u256(&share.protocol_fee_balance),
            amount: scalar_to_u256(&share.amount),
        }
    }
}

impl From<IDarkpoolV2::PostMatchBalanceShare> for PostMatchBalanceShare {
    fn from(share: IDarkpoolV2::PostMatchBalanceShare) -> Self {
        Self {
            relayer_fee_balance: u256_to_scalar(share.relayerFeeBalance),
            protocol_fee_balance: u256_to_scalar(share.protocolFeeBalance),
            amount: u256_to_scalar(share.amount),
        }
    }
}
