//! Conversion for intent types

use super::u256_to_scalar;
#[cfg(feature = "v2-auth-helpers")]
use crate::v2::IDarkpoolV2::SignatureWithNonce;
use crate::v2::{
    relayer_types::{u128_to_u256, u256_to_u128},
    IDarkpoolV2,
};
use darkpool_types::intent::{Intent as CircuitIntent, IntentShare, PreMatchIntentShare};
use renegade_circuit_types_v2::fixed_point::FixedPointShare;
use renegade_crypto_v2::fields::scalar_to_u256;
#[cfg(feature = "v2-auth-helpers")]
use {
    crate::v2::IDarkpoolV2::PublicIntentPermit,
    alloy::{
        primitives::{keccak256, Address, B256, U256},
        signers::{local::PrivateKeySigner, Error as SignerError},
        sol_types::SolValue,
    },
};

impl From<IDarkpoolV2::Intent> for CircuitIntent {
    fn from(intent: IDarkpoolV2::Intent) -> Self {
        Self {
            in_token: intent.inToken,
            out_token: intent.outToken,
            owner: intent.owner,
            min_price: intent.minPrice.into(),
            amount_in: u256_to_u128(intent.amountIn),
        }
    }
}

impl From<CircuitIntent> for IDarkpoolV2::Intent {
    fn from(intent: CircuitIntent) -> Self {
        Self {
            inToken: intent.in_token,
            outToken: intent.out_token,
            owner: intent.owner,
            minPrice: intent.min_price.into(),
            amountIn: u128_to_u256(intent.amount_in),
        }
    }
}

impl From<IntentShare> for IDarkpoolV2::IntentPublicShare {
    fn from(share: IntentShare) -> Self {
        Self {
            inToken: scalar_to_u256(&share.in_token),
            outToken: scalar_to_u256(&share.out_token),
            owner: scalar_to_u256(&share.owner),
            minPrice: scalar_to_u256(&share.min_price.repr),
            amountIn: scalar_to_u256(&share.amount_in),
        }
    }
}

impl From<IDarkpoolV2::IntentPublicShare> for IntentShare {
    fn from(share: IDarkpoolV2::IntentPublicShare) -> Self {
        Self {
            in_token: u256_to_scalar(share.inToken),
            out_token: u256_to_scalar(share.outToken),
            owner: u256_to_scalar(share.owner),
            min_price: FixedPointShare {
                repr: u256_to_scalar(share.minPrice),
            },
            amount_in: u256_to_scalar(share.amountIn),
        }
    }
}

impl From<PreMatchIntentShare> for IDarkpoolV2::IntentPreMatchShare {
    fn from(share: PreMatchIntentShare) -> Self {
        Self {
            inToken: scalar_to_u256(&share.in_token),
            outToken: scalar_to_u256(&share.out_token),
            owner: scalar_to_u256(&share.owner),
            minPrice: scalar_to_u256(&share.min_price.repr),
        }
    }
}

impl From<IDarkpoolV2::IntentPreMatchShare> for PreMatchIntentShare {
    fn from(share: IDarkpoolV2::IntentPreMatchShare) -> Self {
        Self {
            in_token: u256_to_scalar(share.inToken),
            out_token: u256_to_scalar(share.outToken),
            owner: u256_to_scalar(share.owner),
            min_price: FixedPointShare {
                repr: u256_to_scalar(share.minPrice),
            },
        }
    }
}

#[cfg(feature = "v2-auth-helpers")]
impl PublicIntentPermit {
    /// Create a signature for a public intent permit
    pub fn sign(
        &self,
        chain_id: u64,
        signer: &PrivateKeySigner,
    ) -> Result<SignatureWithNonce, SignerError> {
        let payload = self.abi_encode();
        SignatureWithNonce::sign(&payload, chain_id, signer)
    }

    /// Validate a signature for a public intent permit against a known address
    pub fn validate(
        &self,
        chain_id: u64,
        signature_with_nonce: &SignatureWithNonce,
        expected_address: Address,
    ) -> Result<bool, SignerError> {
        signature_with_nonce.validate(self.abi_encode().as_slice(), chain_id, expected_address)
    }

    /// Compute the hash of a public intent permit
    ///
    /// This is the keccak256 hash of the ABI-encoded permit, matching
    /// the Solidity `EfficientHashLib.hash(abi.encode(permit))`.
    pub fn compute_hash(&self) -> B256 {
        keccak256(self.abi_encode())
    }

    /// Compute the nullifier for a public intent permit
    ///
    /// The nullifier uniquely identifies an intent + signature combination:
    /// `H(intentHash || nonce)` where `||` is abi.encodePacked concatenation.
    ///
    /// The nonce here is the nonce originally used to sign the intent.
    pub fn compute_nullifier(&self, intent_signature_nonce: U256) -> U256 {
        let intent_hash = self.compute_hash();
        let nonce_bytes = intent_signature_nonce.to_be_bytes::<{ U256::BYTES }>();
        let packed = [intent_hash.as_slice(), nonce_bytes.as_slice()].concat();
        let hash = keccak256(&packed);

        U256::from_be_bytes(hash.0)
    }
}
