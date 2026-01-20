//! Authorization helpers for the V2 ABI

use alloy::{
    primitives::{keccak256, Address, B256, U256},
    signers::{local::PrivateKeySigner, Error as SignerError, Signature, SignerSync},
};

use crate::v2::IDarkpoolV2::SignatureWithNonce;

/// Compute the digest for signing with nonce
///
/// This computes H(H(payload) || nonce || chainId)
fn compute_digest_with_nonce(payload: &[u8], nonce: U256, chain_id: u64) -> B256 {
    // Pre-hash the payload
    let payload_digest = keccak256(payload);

    // Hash the payload with the nonce and chain ID
    let nonce_bytes = nonce.to_be_bytes::<{ U256::BYTES }>();
    let chain_id_bytes = U256::from(chain_id).to_be_bytes::<{ U256::BYTES }>();
    let full_payload = [
        payload_digest.as_slice(),
        nonce_bytes.as_slice(),
        chain_id_bytes.as_slice(),
    ]
    .concat();
    keccak256(&full_payload)
}

impl SignatureWithNonce {
    /// Generate a signature with a nonce for a given message
    ///
    /// This is H(H(payload) || nonce || chainId)
    pub fn sign(
        payload: &[u8],
        chain_id: u64,
        signer: &PrivateKeySigner,
    ) -> Result<Self, SignerError> {
        let nonce = U256::random();
        let digest = compute_digest_with_nonce(payload, nonce, chain_id);

        let signature = signer.sign_hash_sync(&digest)?;
        let sig_bytes = signature.as_bytes().to_vec();
        Ok(Self {
            nonce,
            signature: sig_bytes.into(),
        })
    }

    /// Validate this signature against a known address
    ///
    /// This reconstructs the digest H(H(payload) || nonce || chainId) and recovers
    /// the signer address from the signature, then compares it to the expected address.
    pub fn validate(
        &self,
        payload: &[u8],
        chain_id: u64,
        expected_address: Address,
    ) -> Result<bool, SignerError> {
        let digest = compute_digest_with_nonce(payload, self.nonce, chain_id);

        // Parse the signature bytes (65 bytes: r, s, v)
        let sig_bytes: &[u8] = self.signature.as_ref();
        if sig_bytes.len() != 65 {
            return Err(SignerError::message("Invalid signature length"));
        }

        // Extract recovery ID (v) from last byte and convert to parity bool
        // v is 27 or 28 for legacy, or 0/1 for EIP-155. We normalize to 0/1.
        let v = sig_bytes[64];
        let parity = match v {
            27 | 0 => false,
            28 | 1 => true,
            _ => return Err(SignerError::message("Invalid recovery ID")),
        };
        let signature = Signature::from_bytes_and_parity(&sig_bytes[..64], parity);

        // Recover the signer address
        let recovered_address = signature.recover_address_from_prehash(&digest)?;
        Ok(recovered_address == expected_address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::Address;

    #[test]
    fn test_sign_and_validate_compatibility() {
        // Create a test signer
        let signer = PrivateKeySigner::random();
        let signer_address = signer.address();

        // Test payload and chain ID
        let payload = b"test message";
        let chain_id = 1u64;

        // Sign the payload
        let signature_with_nonce =
            SignatureWithNonce::sign(payload, chain_id, &signer).expect("Failed to sign");

        // Validate the signature
        let is_valid = signature_with_nonce
            .validate(payload, chain_id, signer_address)
            .expect("Failed to validate signature");

        assert!(
            is_valid,
            "Signature validation should succeed for correct signer"
        );
    }

    #[test]
    fn test_validate_signature_invalid_address() {
        // Create a test signer
        let signer = PrivateKeySigner::random();

        // Test payload and chain ID
        let payload = b"test message";
        let chain_id = 1u64;

        // Sign the payload
        let signature_with_nonce =
            SignatureWithNonce::sign(payload, chain_id, &signer).expect("Failed to sign");

        // Test with wrong address
        let wrong_address = Address::ZERO;
        let is_valid = signature_with_nonce
            .validate(payload, chain_id, wrong_address)
            .expect("Failed to validate signature");

        assert!(
            !is_valid,
            "Signature validation should fail for wrong address"
        );
    }

    #[test]
    fn test_validate_signature_invalid_payload() {
        // Create a test signer
        let signer = PrivateKeySigner::random();
        let signer_address = signer.address();

        // Test payload and chain ID
        let payload = b"test message";
        let chain_id = 1u64;

        // Sign the payload
        let signature_with_nonce =
            SignatureWithNonce::sign(payload, chain_id, &signer).expect("Failed to sign");

        // Test with wrong payload
        let wrong_payload = b"wrong message";
        let is_valid = signature_with_nonce
            .validate(wrong_payload, chain_id, signer_address)
            .expect("Failed to validate signature");

        assert!(
            !is_valid,
            "Signature validation should fail for wrong payload"
        );
    }

    #[test]
    fn test_validate_signature_invalid_chain_id() {
        // Create a test signer
        let signer = PrivateKeySigner::random();
        let signer_address = signer.address();

        // Test payload and chain ID
        let payload = b"test message";
        let chain_id = 1u64;

        // Sign the payload
        let signature_with_nonce =
            SignatureWithNonce::sign(payload, chain_id, &signer).expect("Failed to sign");

        // Test with wrong chain ID
        let wrong_chain_id = 2u64;
        let is_valid = signature_with_nonce
            .validate(payload, wrong_chain_id, signer_address)
            .expect("Failed to validate signature");

        assert!(
            !is_valid,
            "Signature validation should fail for wrong chain ID"
        );
    }
}
