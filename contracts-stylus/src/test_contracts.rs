//! Dummy contracts which wrap VM-specific functionality (e.g., precompiles) for testing purposes.
//! These contracts are intended to be used in conjunction with a local devnet, along with testing scripts
//! in the `integration` crate

use alloc::vec::Vec;
use ark_ec::{AffineRepr, CurveGroup};
use contracts_core::{
    types::{G1Affine, G2Affine, ScalarField},
    verifier::{errors::VerifierError, G1ArithmeticBackend},
};
use stylus_sdk::prelude::*;

use crate::utils::{ec_add_impl, ec_pairing_check_impl, ec_scalar_mul_impl};

#[solidity_storage]
#[entrypoint]
struct TestContract;

impl G1ArithmeticBackend for TestContract {
    fn ec_add(&mut self, a: G1Affine, b: G1Affine) -> Result<G1Affine, VerifierError> {
        Ok(ec_add_impl(self, a, b)?)
    }

    fn ec_scalar_mul(&mut self, a: ScalarField, b: G1Affine) -> Result<G1Affine, VerifierError> {
        Ok(ec_scalar_mul_impl(self, a, b)?)
    }

    fn ec_pairing_check(
        &mut self,
        a_1: G1Affine,
        b_1: G2Affine,
        a_2: G1Affine,
        b_2: G2Affine,
    ) -> Result<bool, VerifierError> {
        Ok(ec_pairing_check_impl(self, a_1, b_1, a_2, b_2)?)
    }
}

#[external]
impl TestContract {
    pub fn test_add(&mut self) -> Result<(), Vec<u8>> {
        let a = G1Affine::generator();
        let b = G1Affine::generator();
        let c = self.ec_add(a, b).unwrap();
        assert_eq!(c, a + b);

        Ok(())
    }

    pub fn test_mul(&mut self) -> Result<(), Vec<u8>> {
        let a = ScalarField::from(2_u8);
        let b = G1Affine::generator();
        let c = self.ec_scalar_mul(a, b).unwrap();
        let mut expected = b.into_group();
        expected *= a;
        assert_eq!(c, expected.into_affine());

        Ok(())
    }

    pub fn test_pairing(&mut self) -> Result<(), Vec<u8>> {
        let a_1 = G1Affine::generator();
        let b_1 = G2Affine::generator();

        let a_2 = G1Affine::generator();
        let b_2 = G2Affine::generator();

        let res = self.ec_pairing_check(a_1, b_1, -a_2, b_2).unwrap();

        assert!(res);

        Ok(())
    }
}
