//! Testing contract which wraps EVM precompile functionality for testing
//! purposes. This contract is intended to be used in conjunction with a local
//! devnet, along with testing scripts in the `integration` crate

use alloc::vec::Vec;
use contracts_common::{
    backends::{EcRecoverBackend, G1ArithmeticBackend},
    serde_def_types::{SerdeG1Affine, SerdeG2Affine, SerdeScalarField},
};
use stylus_sdk::{abi::Bytes, prelude::*};

use crate::utils::backends::{PrecompileEcRecoverBackend, PrecompileG1ArithmeticBackend};

/// The precompile testing contract, which itself is stateless
#[storage]
#[entrypoint]
struct PrecompileTestContract;

#[public]
impl PrecompileTestContract {
    /// Invokes the `ecAdd` precompile on the given inputs
    pub fn test_ec_add(&self, a_bytes: Bytes, b_bytes: Bytes) -> Result<Bytes, Vec<u8>> {
        let a: SerdeG1Affine = postcard::from_bytes(a_bytes.as_slice()).unwrap();
        let b: SerdeG1Affine = postcard::from_bytes(b_bytes.as_slice()).unwrap();
        let c = PrecompileG1ArithmeticBackend::ec_add(a.0, b.0).unwrap();
        let c_bytes = postcard::to_allocvec(&SerdeG1Affine(c)).unwrap();
        Ok(c_bytes.into())
    }

    /// Invokes the `ecMul` precompile on the given inputs
    pub fn test_ec_mul(&self, a_bytes: Bytes, b_bytes: Bytes) -> Result<Bytes, Vec<u8>> {
        let a: SerdeScalarField = postcard::from_bytes(a_bytes.as_slice()).unwrap();
        let b: SerdeG1Affine = postcard::from_bytes(b_bytes.as_slice()).unwrap();
        let c = PrecompileG1ArithmeticBackend::ec_scalar_mul(a.0, b.0).unwrap();
        Ok(postcard::to_allocvec(&SerdeG1Affine(c)).unwrap().into())
    }

    /// Invokes the `ecPairing` precompile on the given inputs
    pub fn test_ec_pairing(&self, a_bytes: Bytes, b_bytes: Bytes) -> Result<bool, Vec<u8>> {
        let a: SerdeG1Affine = postcard::from_bytes(a_bytes.as_slice()).unwrap();
        let b: SerdeG2Affine = postcard::from_bytes(b_bytes.as_slice()).unwrap();

        Ok(PrecompileG1ArithmeticBackend::ec_pairing_check(a.0, b.0, -a.0, b.0).unwrap())
    }

    /// Invokes the `ecRecover` precompile on the given inputs
    pub fn test_ec_recover(&self, msg_hash: Bytes, signature: Bytes) -> Result<Bytes, Vec<u8>> {
        let res = PrecompileEcRecoverBackend::ec_recover(
            msg_hash.as_slice().try_into().unwrap(),
            signature.as_slice().try_into().unwrap(),
        )
        .unwrap();
        Ok(res.to_vec().into())
    }
}
