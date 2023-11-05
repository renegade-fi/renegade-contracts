//! Testing contract which wraps precompile functionality for testing purposes.
//! This contract is intended to be used in conjunction with a local devnet, along with testing scripts
//! in the `integration` crate

use alloc::vec::Vec;
use common::serde_def_types::{SerdeG1Affine, SerdeG2Affine, SerdeScalarField};
use contracts_core::verifier::G1ArithmeticBackend;
use stylus_sdk::{abi::Bytes, prelude::*};

use crate::utils::PrecompileG1ArithmeticBackend;

#[solidity_storage]
#[entrypoint]
struct PrecompileTestContract;

#[external]
impl PrecompileTestContract {
    pub fn test_ec_add(&self, a_bytes: Bytes, b_bytes: Bytes) -> Result<Bytes, Vec<u8>> {
        let a: SerdeG1Affine = postcard::from_bytes(a_bytes.as_slice()).unwrap();
        let b: SerdeG1Affine = postcard::from_bytes(b_bytes.as_slice()).unwrap();
        let c = PrecompileG1ArithmeticBackend::ec_add(a.0, b.0).unwrap();
        Ok(postcard::to_allocvec(&SerdeG1Affine(c)).unwrap().into())
    }

    pub fn test_ec_mul(&self, a_bytes: Bytes, b_bytes: Bytes) -> Result<Bytes, Vec<u8>> {
        let a: SerdeScalarField = postcard::from_bytes(a_bytes.as_slice()).unwrap();
        let b: SerdeG1Affine = postcard::from_bytes(b_bytes.as_slice()).unwrap();
        let c = PrecompileG1ArithmeticBackend::ec_scalar_mul(a.0, b.0).unwrap();
        Ok(postcard::to_allocvec(&SerdeG1Affine(c)).unwrap().into())
    }

    pub fn test_ec_pairing(&self, a_bytes: Bytes, b_bytes: Bytes) -> Result<bool, Vec<u8>> {
        let a: SerdeG1Affine = postcard::from_bytes(a_bytes.as_slice()).unwrap();
        let b: SerdeG2Affine = postcard::from_bytes(b_bytes.as_slice()).unwrap();

        Ok(PrecompileG1ArithmeticBackend::ec_pairing_check(a.0, b.0, -a.0, b.0).unwrap())
    }
}
