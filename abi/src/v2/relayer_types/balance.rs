//! Balance type conversions

use renegade_circuit_types_v2::{
    balance::{BalanceShare, PostMatchBalanceShare, PreMatchBalanceShare},
    elgamal::BabyJubJubPointShare,
    schnorr::SchnorrPublicKeyShare,
};
use renegade_crypto_v2::fields::scalar_to_u256;

use crate::v2::{
    relayer_types::u256_to_scalar,
    IDarkpoolV2::{self},
};

impl From<BalanceShare> for IDarkpoolV2::BalanceShare {
    fn from(share: BalanceShare) -> Self {
        Self {
            mint: scalar_to_u256(&share.mint),
            owner: scalar_to_u256(&share.owner),
            relayerFeeRecipient: scalar_to_u256(&share.relayer_fee_recipient),
            signingAuthority: IDarkpoolV2::BabyJubJubPoint {
                x: scalar_to_u256(&share.authority.point.x),
                y: scalar_to_u256(&share.authority.point.y),
            },
            relayerFeeBalance: scalar_to_u256(&share.relayer_fee_balance),
            protocolFeeBalance: scalar_to_u256(&share.protocol_fee_balance),
            amount: scalar_to_u256(&share.amount),
        }
    }
}

impl From<IDarkpoolV2::BalanceShare> for BalanceShare {
    fn from(share: IDarkpoolV2::BalanceShare) -> Self {
        Self {
            mint: u256_to_scalar(share.mint),
            owner: u256_to_scalar(share.owner),
            relayer_fee_recipient: u256_to_scalar(share.relayerFeeRecipient),
            authority: SchnorrPublicKeyShare {
                point: BabyJubJubPointShare {
                    x: u256_to_scalar(share.signingAuthority.x),
                    y: u256_to_scalar(share.signingAuthority.y),
                },
            },
            relayer_fee_balance: u256_to_scalar(share.relayerFeeBalance),
            protocol_fee_balance: u256_to_scalar(share.protocolFeeBalance),
            amount: u256_to_scalar(share.amount),
        }
    }
}

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

impl From<PreMatchBalanceShare> for IDarkpoolV2::PreMatchBalanceShare {
    fn from(share: PreMatchBalanceShare) -> Self {
        Self {
            mint: scalar_to_u256(&share.mint),
            owner: scalar_to_u256(&share.owner),
            relayerFeeRecipient: scalar_to_u256(&share.relayer_fee_recipient),
            signingAuthority: IDarkpoolV2::BabyJubJubPoint {
                x: scalar_to_u256(&share.authority.point.x),
                y: scalar_to_u256(&share.authority.point.y),
            },
        }
    }
}

impl From<IDarkpoolV2::PreMatchBalanceShare> for PreMatchBalanceShare {
    fn from(share: IDarkpoolV2::PreMatchBalanceShare) -> Self {
        Self {
            mint: u256_to_scalar(share.mint),
            owner: u256_to_scalar(share.owner),
            relayer_fee_recipient: u256_to_scalar(share.relayerFeeRecipient),
            authority: SchnorrPublicKeyShare {
                point: BabyJubJubPointShare {
                    x: u256_to_scalar(share.signingAuthority.x),
                    y: u256_to_scalar(share.signingAuthority.y),
                },
            },
        }
    }
}
