// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

import {Transcript} from "./Transcript.sol";
import {PlonkProof, NUM_WIRE_TYPES} from "./Types.sol";

import {BN254} from "solidity-bn254/BN254.sol";
import {console2} from "forge-std/console2.sol";

/// @title A verifier for Plonk proofs
/// @notice This implementation currently follows that outlined in the paper closely:
/// https://eprint.iacr.org/2019/953.pdf
contract Verifier {
    /// @notice Verify a batch of Plonk proofs using the arithmetization defined in `mpc-jellyfish`:
    /// https://github.com/renegade-fi/mpc-jellyfish
    /// @param proof The proof to verify
    /// @return True if the proof is valid, false otherwise
    function verify(PlonkProof memory proof) public view returns (bool) {
        plonkStep1And2(proof);
    }

    /// @notice Step 1 of the plonk verification algorithm
    /// @notice Verify that the G_1 points are on the curve
    function plonkStep1And2(PlonkProof memory proof) internal pure {
        // Check that the commitments to the wire polynomials are on the curve
        for (uint256 i = 0; i < proof.wire_comms.length; i++) {
            BN254.validateG1Point(proof.wire_comms[i]);
        }

        // Check the commitment to the grand product polynomial is on the curve
        BN254.validateG1Point(proof.z_comm);

        // Check the commitments to the quotient polynomials are on the curve
        for (uint256 i = 0; i < proof.quotient_comms.length; i++) {
            BN254.validateG1Point(proof.quotient_comms[i]);
        }

        // Check that the opening proofs are on the curve
        BN254.validateG1Point(proof.w_zeta);
        BN254.validateG1Point(proof.w_zeta_omega);

        // Check that each of the evaluations of wire polynomials are in the scalar field
        for (uint256 i = 0; i < proof.wire_evals.length; i++) {
            BN254.validateScalarField(proof.wire_evals[i]);
        }

        // Check that each of the evaluations of the permutation polynomials are in the scalar field
        for (uint256 i = 0; i < proof.sigma_evals.length; i++) {
            BN254.validateScalarField(proof.sigma_evals[i]);
        }

        // Check that the evaluation of the grand product polynomial is in the scalar field
        BN254.validateScalarField(proof.z_bar);
    }
}
