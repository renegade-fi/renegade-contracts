//! Dummy contracts which wrap VM-specific functionality (e.g., precompiles) for testing purposes.
//! These contracts are intended to be used in conjunction with a local devnet, along with testing scripts
//! in the `integration` crate

use alloc::vec::Vec;
use ark_ec::{AffineRepr, CurveGroup};
use ark_std::UniformRand;
use contracts_core::{
    types::{G1Affine, G2Affine, ScalarField},
    verifier::G1ArithmeticBackend,
};
use stylus_sdk::prelude::*;

use crate::utils::EvmPrecompileBackend;

#[solidity_storage]
#[entrypoint]
struct TestContract;

#[external]
impl TestContract {
    pub fn test_add(&mut self) -> Result<(), Vec<u8>> {
        let mut backend = EvmPrecompileBackend { contract: self };

        let mut rng = ark_std::test_rng();
        let a = G1Affine::rand(&mut rng);
        let b = G1Affine::rand(&mut rng);
        let c = backend.ec_add(a, b).unwrap();
        assert_eq!(c, a + b);

        Ok(())
    }

    pub fn test_mul(&mut self) -> Result<(), Vec<u8>> {
        let mut backend = EvmPrecompileBackend { contract: self };

        let mut rng = ark_std::test_rng();
        let a = ScalarField::rand(&mut rng);
        let b = G1Affine::rand(&mut rng);
        let c = backend.ec_scalar_mul(a, b).unwrap();
        let mut expected = b.into_group();
        expected *= a;
        assert_eq!(c, expected.into_affine());

        Ok(())
    }

    pub fn test_pairing(&mut self) -> Result<(), Vec<u8>> {
        let mut backend = EvmPrecompileBackend { contract: self };

        let mut rng = ark_std::test_rng();
        let a_1 = G1Affine::rand(&mut rng);
        let b_1 = G2Affine::rand(&mut rng);

        let res = backend.ec_pairing_check(a_1, b_1, -a_1, b_1).unwrap();

        assert!(res);

        Ok(())
    }
}
