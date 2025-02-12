// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

import {BN254} from "solidity-bn254/BN254.sol";

/// @dev The number of wire types in the arithmetization
uint256 constant NUM_WIRE_TYPES = 5;
/// @dev The number of selectors in the arithmetization
uint256 constant NUM_SELECTORS = 13;

/// @title A Plonk proof
/// @notice This matches the Rust implementation from mpc-jellyfish
struct PlonkProof {
    /// @dev The commitments to the wire polynomials
    BN254.G1Point[NUM_WIRE_TYPES] wire_comms;
    /// @dev The commitment to the grand product polynomial encoding the permutation argument
    BN254.G1Point z_comm;
    /// @dev The commitments to the split quotient polynomials
    BN254.G1Point[NUM_WIRE_TYPES] quotient_comms;
    /// @dev The opening proof of evaluations at challenge point `zeta`
    BN254.G1Point w_zeta;
    /// @dev The opening proof of evaluations at challenge point `zeta * omega`
    BN254.G1Point w_zeta_omega;
    /// @dev The evaluations of the wire polynomials at the challenge point `zeta`
    BN254.ScalarField[NUM_WIRE_TYPES] wire_evals;
    /// @dev The evaluations of the permutation polynomials at the challenge point `zeta`
    BN254.ScalarField[NUM_WIRE_TYPES - 1] sigma_evals;
    /// @dev The evaluation of the grand product polynomial at the challenge point `zeta * omega`
    BN254.ScalarField z_bar;
}

/// @title A Plonk verification key
struct VerificationKey {
    /// The number of gates in the circuit
    uint256 n;
    /// The number of public inputs to the circuit
    uint256 l;
    /// The constants used to generate the cosets of the evaluation domain
    BN254.ScalarField[NUM_WIRE_TYPES] k;
    /// The commitments to the selector polynomials
    BN254.G1Point[NUM_SELECTORS] q_comms;
    /// The commitments to the permutation polynomials
    BN254.G1Point[NUM_WIRE_TYPES] sigma_comms;
    /// The generator of G1
    BN254.G1Point g;
    /// The generator of G2
    BN254.G2Point h;
    /// The secret evaluation point multiplied by the generator of G2
    BN254.G2Point x_h;
}
