//! Common utilities used throughout the smart contracts, including testing contracts.

use contracts_core::{
    types::{G1Affine, G2Affine, ScalarField},
    utils::{PrecompileG1, PrecompileG2, PrecompileSerializable, PrecompileSerializationError},
    verifier::errors::VerifierError,
};
use stylus_sdk::{
    alloy_primitives::Address,
    call::{static_call, Call},
    storage::TopLevelStorage,
};

use crate::constants::{
    EC_ADD_ADDRESS_LAST_BYTE, EC_MUL_ADDRESS_LAST_BYTE, EC_PAIRING_ADDRESS_LAST_BYTE,
    PAIRING_CHECK_RESULT_LAST_BYTE_INDEX,
};

// TODO: Perhaps remove error structure, and results broadly, in favor of `unwrap`s
// in the Stylus code? It doesn't seem that error types are logged at all in the VM,
// it just reverts the transaction.

#[derive(Debug)]
pub enum BackendError {
    /// An error that occurred while de/serializing data for a precompile
    PrecompileSerialization(PrecompileSerializationError),
    /// An error that occurred while calling a precompile
    PrecompileInvocation,
}

impl From<PrecompileSerializationError> for BackendError {
    fn from(value: PrecompileSerializationError) -> Self {
        BackendError::PrecompileSerialization(value)
    }
}

impl From<BackendError> for VerifierError {
    fn from(_value: BackendError) -> Self {
        VerifierError::BackendError
    }
}

/// Calls the `ecAdd` precompile with the given points, handling de/serialization
pub fn ec_add_impl<S: TopLevelStorage>(
    contract: &mut S,
    a: G1Affine,
    b: G1Affine,
) -> Result<G1Affine, BackendError> {
    // Serialize the points
    let a_data = PrecompileG1(a).serialize_for_precompile();
    let b_data = PrecompileG1(b).serialize_for_precompile();

    // Call the `ecAdd` precompile
    let res_xy_bytes = static_call(
        Call::new_in(contract),
        Address::with_last_byte(EC_ADD_ADDRESS_LAST_BYTE),
        &[a_data, b_data].concat(),
    )
    .map_err(|_| BackendError::PrecompileInvocation)?;

    // Deserialize the affine coordinates returned from the precompile
    Ok(PrecompileG1::deserialize_from_precompile(&res_xy_bytes)?.0)
}

/// Calls the `ecMul` precompile with the given scalar and point, handling de/serialization
pub fn ec_scalar_mul_impl<S: TopLevelStorage>(
    contract: &mut S,
    a: ScalarField,
    b: G1Affine,
) -> Result<G1Affine, BackendError> {
    // Serialize the point and scalar
    let a_data = a.serialize_for_precompile();
    let b_data = PrecompileG1(b).serialize_for_precompile();

    // Call the `ecMul` precompile
    let res_xy_bytes = static_call(
        Call::new_in(contract),
        Address::with_last_byte(EC_MUL_ADDRESS_LAST_BYTE),
        &[b_data, a_data].concat(),
    )
    .map_err(|_| BackendError::PrecompileInvocation)?;

    // Deserialize the affine coordinates returned from the precompile
    Ok(PrecompileG1::deserialize_from_precompile(&res_xy_bytes)?.0)
}

/// Calls the `ecPairing` precompile with the given points, handling de/serialization
pub fn ec_pairing_check_impl<S: TopLevelStorage>(
    contract: &mut S,
    a_1: G1Affine,
    b_1: G2Affine,
    a_2: G1Affine,
    b_2: G2Affine,
) -> Result<bool, BackendError> {
    // Serialize the points
    let a_1_data = PrecompileG1(a_1).serialize_for_precompile();
    let b_1_data = PrecompileG2(b_1).serialize_for_precompile();
    let a_2_data = PrecompileG1(a_2).serialize_for_precompile();
    let b_2_data = PrecompileG2(b_2).serialize_for_precompile();

    // Call the `ecPairing` precompile
    let res = static_call(
        Call::new_in(contract),
        Address::with_last_byte(EC_PAIRING_ADDRESS_LAST_BYTE),
        &[a_1_data, b_1_data, a_2_data, b_2_data].concat(),
    )
    .map_err(|_| BackendError::PrecompileInvocation)?;

    // Return the result of the pairing check, which is either a 0 or 1.
    // However, the precompile always returns a 32-byte output
    Ok(res[PAIRING_CHECK_RESULT_LAST_BYTE_INDEX] == 1)
}
