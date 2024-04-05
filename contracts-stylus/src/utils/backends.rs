//! Common utilities used throughout the smart contracts, including testing contracts.

use ark_ff::One;
use contracts_common::{
    backends::{EcRecoverBackend, EcdsaError, G1ArithmeticBackend, G1ArithmeticError, HashBackend},
    constants::{
        HASH_OUTPUT_SIZE, NUM_BYTES_ADDRESS, NUM_BYTES_FELT, NUM_BYTES_SIGNATURE, NUM_BYTES_U256,
    },
    custom_serde::{BytesDeserializable, BytesSerializable},
    types::{G1Affine, G2Affine, ScalarField},
};
use stylus_sdk::{alloy_primitives::Address, call::RawCall, crypto::keccak};

use crate::utils::constants::{
    EC_ADD_ADDRESS_LAST_BYTE, EC_MUL_ADDRESS_LAST_BYTE, EC_PAIRING_ADDRESS_LAST_BYTE,
    EC_RECOVER_ADDRESS_LAST_BYTE, PAIRING_CHECK_RESULT_LAST_BYTE_INDEX,
};

use super::constants::EC_RECOVER_INPUT_LEN;

/// The hashing backend used in the Stylus VM,
/// which uses the VM-accelerated Keccak-256 implementation
pub struct StylusHasher;
impl HashBackend for StylusHasher {
    fn hash(input: &[u8]) -> [u8; HASH_OUTPUT_SIZE] {
        keccak(input).into()
    }
}

/// The G1 arithmetic backend used in the Stylus VM,
/// which calls out to the EC arithmetic EVM precompiles
#[cfg_attr(not(feature = "verifier"), allow(dead_code))]
pub struct PrecompileG1ArithmeticBackend;

impl G1ArithmeticBackend for PrecompileG1ArithmeticBackend {
    /// Calls the `ecAdd` precompile with the given points, handling de/serialization
    fn ec_add(a: G1Affine, b: G1Affine) -> Result<G1Affine, G1ArithmeticError> {
        if a == G1Affine::identity() {
            return Ok(b);
        } else if b == G1Affine::identity() {
            return Ok(a);
        }

        // Serialize the points
        let mut calldata = [0_u8; NUM_BYTES_FELT * 4];
        calldata[..NUM_BYTES_FELT * 2].copy_from_slice(&a.serialize_to_bytes());
        calldata[NUM_BYTES_FELT * 2..].copy_from_slice(&b.serialize_to_bytes());

        // Call the `ecAdd` precompile
        let res_xy_bytes = RawCall::new_static()
            .call(Address::with_last_byte(EC_ADD_ADDRESS_LAST_BYTE), &calldata)
            .map_err(|_| G1ArithmeticError)?;

        // Deserialize the affine coordinates returned from the precompile
        G1Affine::deserialize_from_bytes(&res_xy_bytes).map_err(|_| G1ArithmeticError)
    }

    /// Calls the `ecMul` precompile with the given scalar and point, handling de/serialization
    fn ec_scalar_mul(a: ScalarField, b: G1Affine) -> Result<G1Affine, G1ArithmeticError> {
        if a == ScalarField::one() {
            return Ok(b);
        }

        // Serialize the point and scalar
        let mut calldata = [0_u8; NUM_BYTES_FELT * 3];
        calldata[..NUM_BYTES_FELT * 2].copy_from_slice(&b.serialize_to_bytes());
        calldata[NUM_BYTES_FELT * 2..].copy_from_slice(&a.serialize_to_bytes());

        // Call the `ecMul` precompile
        let res_xy_bytes = RawCall::new_static()
            .call(Address::with_last_byte(EC_MUL_ADDRESS_LAST_BYTE), &calldata)
            .map_err(|_| G1ArithmeticError)?;

        // Deserialize the affine coordinates returned from the precompile
        G1Affine::deserialize_from_bytes(&res_xy_bytes).map_err(|_| G1ArithmeticError)
    }

    /// Calls the `ecPairing` precompile with the given points, handling de/serialization
    fn ec_pairing_check(
        a_1: G1Affine,
        b_1: G2Affine,
        a_2: G1Affine,
        b_2: G2Affine,
    ) -> Result<bool, G1ArithmeticError> {
        // Serialize the points
        let mut calldata = [0_u8; NUM_BYTES_FELT * 12];
        calldata[..NUM_BYTES_FELT * 2].copy_from_slice(&a_1.serialize_to_bytes());
        calldata[NUM_BYTES_FELT * 2..NUM_BYTES_FELT * 6].copy_from_slice(&b_1.serialize_to_bytes());
        calldata[NUM_BYTES_FELT * 6..NUM_BYTES_FELT * 8].copy_from_slice(&a_2.serialize_to_bytes());
        calldata[NUM_BYTES_FELT * 8..].copy_from_slice(&b_2.serialize_to_bytes());

        // Call the `ecPairing` precompile
        let res = RawCall::new_static()
            // Only get the last byte of the 32-byte return data,
            // containing the boolean result
            .limit_return_data(
                PAIRING_CHECK_RESULT_LAST_BYTE_INDEX, /* offset */
                1,                                    /* size */
            )
            .call(
                Address::with_last_byte(EC_PAIRING_ADDRESS_LAST_BYTE),
                &calldata,
            )
            .map_err(|_| G1ArithmeticError)?;

        // Return the result of the pairing check, which is either a 0 or 1.
        Ok(res[0] == 1)
    }
}

/// The ECDSA recovery backend used in the Stylus VM,
/// which calls out to the `ecRecover` EVM precompile
pub struct PrecompileEcRecoverBackend;

impl EcRecoverBackend for PrecompileEcRecoverBackend {
    /// Calls out to the `ecRecover` precompile.
    ///
    /// This method expects the following format for the signature:
    /// ```
    /// signature[0..32] = r (big-endian)
    /// signature[32..64] = s (big-endian)
    /// signature[64] = v (0 or 1)
    /// ```
    fn ec_recover(
        message_hash: &[u8; HASH_OUTPUT_SIZE],
        signature: &[u8; NUM_BYTES_SIGNATURE],
    ) -> Result<[u8; NUM_BYTES_ADDRESS], EcdsaError> {
        // Prepare the input data for the `ecRecover` precompile, namely:
        // input[0..32] = message_hash
        // input[32..64] = v (big-endian)
        // input[64..96] = r (big-endian)
        // input[96..128] = s (big-endian)
        let mut input = [0_u8; EC_RECOVER_INPUT_LEN];
        // Add message hash to input
        input[..NUM_BYTES_U256].copy_from_slice(message_hash);
        // Left-pad `v` with zero-bytes & add to input
        input[NUM_BYTES_U256..2 * NUM_BYTES_U256 - 1].copy_from_slice(&[0_u8; NUM_BYTES_U256 - 1]);
        // We expect `v` to be either 0 or 1, but the `ecRecover`
        // precompile expects either 27 or 28
        input[2 * NUM_BYTES_U256 - 1] = signature[64] + 27;
        // Add `r` & `s` to input
        input[2 * NUM_BYTES_U256..].copy_from_slice(&signature[0..2 * NUM_BYTES_U256]);

        // Call the `ecRecover` precompile
        let res = RawCall::new_static()
            // Only get the last 20 bytes of the 32-byte return data
            .limit_return_data(NUM_BYTES_U256 - NUM_BYTES_ADDRESS, NUM_BYTES_ADDRESS)
            .call(
                Address::with_last_byte(EC_RECOVER_ADDRESS_LAST_BYTE),
                &input,
            )
            .map_err(|_| EcdsaError)?;

        res.try_into().map_err(|_| EcdsaError)
    }
}
