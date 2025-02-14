//! Types for the verifier solidity interface

use ark_bn254::{Bn254, Fq, Fq2, Fr};
use ark_ec::pairing::Pairing;
use itertools::Itertools;
use renegade_constants::SystemCurve;

// Constants matching those in Types.sol
const NUM_WIRE_TYPES: usize = 5;
const NUM_SELECTORS: usize = 13;

// --- Type Aliases --- //
pub type VerifyingKey = mpc_plonk::proof_system::structs::VerifyingKey<SystemCurve>;

// Struct definitions matching Solidity types
#[derive(Debug, Clone, Copy)]
pub struct G1Point {
    pub(crate) x: Fq,
    pub(crate) y: Fq,
}

impl G1Point {
    pub fn from_affine(point: <Bn254 as Pairing>::G1Affine) -> Self {
        Self {
            x: point.x,
            y: point.y,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct G2Point {
    pub(crate) x: Fq2,
    pub(crate) y: Fq2,
}

impl G2Point {
    pub fn from_affine(point: <Bn254 as Pairing>::G2Affine) -> Self {
        Self {
            x: point.x,
            y: point.y,
        }
    }
}
#[derive(Debug)]
pub struct PlonkProof {
    pub(crate) wire_comms: [G1Point; NUM_WIRE_TYPES],
    pub(crate) z_comm: G1Point,
    pub(crate) quotient_comms: [G1Point; NUM_WIRE_TYPES],
    pub(crate) w_zeta: G1Point,
    pub(crate) w_zeta_omega: G1Point,
    pub(crate) wire_evals: [Fr; NUM_WIRE_TYPES],
    pub(crate) sigma_evals: [Fr; NUM_WIRE_TYPES - 1],
    pub(crate) z_bar: Fr,
}

impl From<mpc_plonk::proof_system::structs::Proof<SystemCurve>> for PlonkProof {
    fn from(proof: mpc_plonk::proof_system::structs::Proof<SystemCurve>) -> Self {
        PlonkProof {
            wire_comms: proof
                .wires_poly_comms
                .iter()
                .map(|c| G1Point::from_affine(c.0))
                .collect_vec()
                .try_into()
                .unwrap(),
            z_comm: G1Point::from_affine(proof.prod_perm_poly_comm.0),
            quotient_comms: proof
                .split_quot_poly_comms
                .iter()
                .map(|c| G1Point::from_affine(c.0))
                .collect_vec()
                .try_into()
                .unwrap(),
            w_zeta: G1Point::from_affine(proof.opening_proof.0),
            w_zeta_omega: G1Point::from_affine(proof.shifted_opening_proof.0),
            wire_evals: proof.poly_evals.wires_evals.clone().try_into().unwrap(),
            sigma_evals: proof
                .poly_evals
                .wire_sigma_evals
                .clone()
                .try_into()
                .unwrap(),
            z_bar: proof.poly_evals.perm_next_eval,
        }
    }
}

#[derive(Debug)]
pub struct VerificationKey {
    pub(crate) n: u32,
    pub(crate) l: u32,
    pub(crate) k: [Fr; NUM_WIRE_TYPES],
    pub(crate) q_comms: [G1Point; NUM_SELECTORS],
    pub(crate) sigma_comms: [G1Point; NUM_WIRE_TYPES],
    pub(crate) g: G1Point,
    pub(crate) h: G2Point,
    pub(crate) x_h: G2Point,
}

impl From<&VerifyingKey> for VerificationKey {
    fn from(vk: &VerifyingKey) -> Self {
        Self {
            n: vk.domain_size as u32,
            l: vk.num_inputs as u32,
            k: vk.k.clone().try_into().unwrap(),
            g: G1Point::from_affine(vk.open_key.g),
            h: G2Point::from_affine(vk.open_key.h),
            x_h: G2Point::from_affine(vk.open_key.beta_h),
            q_comms: vk
                .selector_comms
                .iter()
                .map(|c| G1Point::from_affine(c.0))
                .collect_vec()
                .try_into()
                .unwrap(),
            sigma_comms: vk
                .sigma_comms
                .iter()
                .map(|c| G1Point::from_affine(c.0))
                .collect_vec()
                .try_into()
                .unwrap(),
        }
    }
}
