//! Types for the verifier solidity interface

use alloy::sol_types::sol;
use renegade_constants::SystemCurve;

// Constants matching those in Types.sol
const NUM_WIRE_TYPES: usize = 5;
const NUM_SELECTORS: usize = 13;

// -------------
// | ABI Types |
// -------------

sol! {
    /// @dev The number of wire types in the arithmetization
    uint256 constant NUM_WIRE_TYPES = 5;
    /// @dev The number of selectors in the arithmetization
    uint256 constant NUM_SELECTORS = 13;
    /// @notice type alias for BN254::ScalarField
    type ScalarField is uint256;
    /// @notice type alias for BN254::BaseField
    type BaseField is uint256;

    // @dev G1 group element, a point on the BN254 curve
    struct G1Point {
        BaseField x;
        BaseField y;
    }

    // @dev G2 group element where x \in Fp2 = c0 + c1 * X
    struct G2Point {
        BaseField x0;
        BaseField x1;
        BaseField y0;
        BaseField y1;
    }

    /// @title A Plonk proof
    /// @notice This matches the Rust implementation from mpc-jellyfish
    struct PlonkProof {
        /// @dev The commitments to the wire polynomials
        G1Point[NUM_WIRE_TYPES] wire_comms;
        /// @dev The commitment to the grand product polynomial encoding the permutation argument
        G1Point z_comm;
        /// @dev The commitments to the split quotient polynomials
        G1Point[NUM_WIRE_TYPES] quotient_comms;
        /// @dev The opening proof of evaluations at challenge point `zeta`
        G1Point w_zeta;
        /// @dev The opening proof of evaluations at challenge point `zeta * omega`
        G1Point w_zeta_omega;
        /// @dev The evaluations of the wire polynomials at the challenge point `zeta`
        ScalarField[NUM_WIRE_TYPES] wire_evals;
        /// @dev The evaluations of the permutation polynomials at the challenge point `zeta`
        ScalarField[NUM_WIRE_TYPES - 1] sigma_evals;
        /// @dev The evaluation of the grand product polynomial at the challenge point `zeta * omega`
        ScalarField z_bar;
    }

    /// @title A Plonk verification key
    struct VerificationKey {
        /// The number of gates in the circuit
        uint64 n;
        /// The number of public inputs to the circuit
        uint64 l;
        /// The constants used to generate the cosets of the evaluation domain
        ScalarField[NUM_WIRE_TYPES] k;
        /// The commitments to the selector polynomials
        G1Point[NUM_SELECTORS] q_comms;
        /// The commitments to the permutation polynomials
        G1Point[NUM_WIRE_TYPES] sigma_comms;
        /// The generator of G1
        G1Point g;
        /// The generator of G2
        G2Point h;
        /// The secret evaluation point multiplied by the generator of G2
        G2Point x_h;
    }
}

// ---------------
// | Conversions |
// ---------------

type SystemVkey = mpc_plonk::proof_system::structs::VerifyingKey<SystemCurve>;
type SystemProof = mpc_plonk::proof_system::structs::Proof<SystemCurve>;

impl From<SystemVkey> for VerificationKey {
    fn from(vkey: SystemVkey) -> Self {
        todo!()
    }
}

impl From<SystemProof> for PlonkProof {
    fn from(proof: SystemProof) -> Self {
        todo!()
    }
}
