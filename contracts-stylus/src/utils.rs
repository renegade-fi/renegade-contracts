//! Common utilities used throughout the smart contracts, including testing contracts.

use contracts_core::{
    serde::{
        Deserializable, PrecompileG1, PrecompileG2, PrecompileScalar,
        Serializable,
    },
    types::{G1Affine, G2Affine, ScalarField},
    verifier::{errors::VerifierError, G1ArithmeticBackend},
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

pub struct EvmPrecompileBackend<S> {
    pub contract: S,
}

impl<'a, S: TopLevelStorage + 'a> G1ArithmeticBackend for EvmPrecompileBackend<&'a mut S> {
    /// Calls the `ecAdd` precompile with the given points, handling de/serialization
    fn ec_add(&mut self, a: G1Affine, b: G1Affine) -> Result<G1Affine, VerifierError> {
        // Serialize the points
        let a_data = PrecompileG1(a).serialize();
        let b_data = PrecompileG1(b).serialize();

        // Call the `ecAdd` precompile
        let res_xy_bytes = static_call(
            Call::new_in(self.contract),
            Address::with_last_byte(EC_ADD_ADDRESS_LAST_BYTE),
            &[a_data, b_data].concat(),
        )
        .map_err(|_| VerifierError::ArithmeticBackend)?;

        // Deserialize the affine coordinates returned from the precompile
        Ok(PrecompileG1::deserialize(&res_xy_bytes).0)
    }

    /// Calls the `ecMul` precompile with the given scalar and point, handling de/serialization
    fn ec_scalar_mul(&mut self, a: ScalarField, b: G1Affine) -> Result<G1Affine, VerifierError> {
        // Serialize the point and scalar
        let a_data = PrecompileScalar(a).serialize();
        let b_data = PrecompileG1(b).serialize();

        // Call the `ecMul` precompile
        let res_xy_bytes = static_call(
            Call::new_in(self.contract),
            Address::with_last_byte(EC_MUL_ADDRESS_LAST_BYTE),
            &[b_data, a_data].concat(),
        )
        .map_err(|_| VerifierError::ArithmeticBackend)?;

        // Deserialize the affine coordinates returned from the precompile
        Ok(PrecompileG1::deserialize(&res_xy_bytes).0)
    }

    /// Calls the `ecPairing` precompile with the given points, handling de/serialization
    fn ec_pairing_check(
        &mut self,
        a_1: G1Affine,
        b_1: G2Affine,
        a_2: G1Affine,
        b_2: G2Affine,
    ) -> Result<bool, VerifierError> {
        // Serialize the points
        let a_1_data = PrecompileG1(a_1).serialize();
        let b_1_data = PrecompileG2(b_1).serialize();
        let a_2_data = PrecompileG1(a_2).serialize();
        let b_2_data = PrecompileG2(b_2).serialize();

        // Call the `ecPairing` precompile
        let res = static_call(
            Call::new_in(self.contract),
            Address::with_last_byte(EC_PAIRING_ADDRESS_LAST_BYTE),
            &[a_1_data, b_1_data, a_2_data, b_2_data].concat(),
        )
        .map_err(|_| VerifierError::ArithmeticBackend)?;

        // Return the result of the pairing check, which is either a 0 or 1.
        // However, the precompile always returns a 32-byte output
        Ok(res[PAIRING_CHECK_RESULT_LAST_BYTE_INDEX] == 1)
    }
}
