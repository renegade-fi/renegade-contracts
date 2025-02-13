// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

import {Transcript} from "./Transcript.sol";
import {PlonkProof, VerificationKey, Challenges, NUM_WIRE_TYPES} from "./Types.sol";
import {TranscriptLib} from "./Transcript.sol";
import {BN254} from "solidity-bn254/BN254.sol";
import {BN254Helpers} from "./BN254Helpers.sol";
import {console2} from "forge-std/console2.sol";

// -------------
// | Constants |
// -------------

/// @dev The bytes representation of the number of bits in the scalar field (little-endian)
/// @dev Shifted to give a little endian representation
bytes4 constant SCALAR_FIELD_N_BITS = bytes4(uint32(254) << 24);

// ------------
// | Verifier |
// ------------

/// @title A verifier for Plonk proofs
/// @notice This implementation currently follows that outlined in the paper closely:
/// https://eprint.iacr.org/2019/953.pdf
contract Verifier {
    /// @notice Verify a batch of Plonk proofs using the arithmetization defined in `mpc-jellyfish`:
    /// https://github.com/renegade-fi/mpc-jellyfish
    /// @param proof The proof to verify
    /// @param publicInputs The public inputs to the proof
    /// @param vk The verification key for the circuit
    /// @return True if the proof is valid, false otherwise
    function verify(PlonkProof memory proof, BN254.ScalarField[] memory publicInputs, VerificationKey memory vk)
        public
        view
        returns (bool)
    {
        plonkStep1And2(proof);
        plonkStep3(publicInputs);
        Challenges memory challenges = plonkStep4(proof, publicInputs, vk);

        // Get the base root of unity for the circuit's evaluation domain
        BN254.ScalarField omega = BN254Helpers.rootOfUnity(vk.n);
        (BN254.ScalarField zeroPolyEval, BN254.ScalarField lagrangeEval) = plonkStep5And6(omega, challenges, vk);

        // TODO: Check the proof
        return true;
    }

    /// @notice Step 1 and 2 of the plonk verification algorithm
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

    /// @notice Step 3 of the plonk verification algorithm
    /// @notice Verify that the public inputs to the proof are all in the scalar field
    function plonkStep3(BN254.ScalarField[] memory publicInputs) internal pure {
        // Check that the public inputs are all in the scalar field
        for (uint256 i = 0; i < publicInputs.length; i++) {
            BN254.validateScalarField(publicInputs[i]);
        }
    }

    /// @notice Step 4 of the plonk verification algorithm
    /// @notice Compute the challenges from a Fiat-Shamir transcript
    /// @dev matches the transcript implementation from `mpc-jellyfish`
    function plonkStep4(PlonkProof memory proof, BN254.ScalarField[] memory publicInputs, VerificationKey memory vk)
        internal
        pure
        returns (Challenges memory challenges)
    {
        // Create a new transcript
        Transcript memory transcript = TranscriptLib.new_transcript();

        // Append the verification key metadata and public inputs
        bytes memory nBitsBytes = abi.encodePacked(SCALAR_FIELD_N_BITS);
        bytes memory nBytes = abi.encodePacked(vk.n);
        bytes memory lBytes = abi.encodePacked(vk.l);
        TranscriptLib.appendMessage(transcript, nBitsBytes);
        TranscriptLib.appendMessage(transcript, nBytes);
        TranscriptLib.appendMessage(transcript, lBytes);
        TranscriptLib.appendScalars(transcript, vk.k);
        TranscriptLib.appendPoints(transcript, vk.q_comms);
        TranscriptLib.appendPoints(transcript, vk.sigma_comms);
        TranscriptLib.appendScalars(transcript, publicInputs);

        // Round 1: Append the wire commitments and squeeze the permutation challenges
        TranscriptLib.appendPoints(transcript, proof.wire_comms);

        // Squeeze an unused challenge tau for consistency with the Plookup-enabled prover
        TranscriptLib.getChallenge(transcript);
        BN254.ScalarField beta = TranscriptLib.getChallenge(transcript);
        BN254.ScalarField gamma = TranscriptLib.getChallenge(transcript);

        // Round 2: Append the quotient permutation polynomial commitment and squeeze the quotient challenge
        TranscriptLib.appendPoint(transcript, proof.z_comm);
        BN254.ScalarField alpha = TranscriptLib.getChallenge(transcript);

        // Round 3: Append the quotient polynomial commitments and squeeze the evaluation challenge
        TranscriptLib.appendPoints(transcript, proof.quotient_comms);
        BN254.ScalarField zeta = TranscriptLib.getChallenge(transcript);

        // Round 4: Append the wire, permutation, and grand product evals and squeeze the v opening challenge
        TranscriptLib.appendScalars(transcript, proof.wire_evals);
        TranscriptLib.appendScalars(transcript, proof.sigma_evals);
        TranscriptLib.appendScalar(transcript, proof.z_bar);
        BN254.ScalarField v = TranscriptLib.getChallenge(transcript);

        // Round 5: Append the two opening proof commitments and squeeze the multipoint evaluation challenge
        TranscriptLib.appendPoint(transcript, proof.w_zeta);
        TranscriptLib.appendPoint(transcript, proof.w_zeta_omega);
        BN254.ScalarField u = TranscriptLib.getChallenge(transcript);

        return Challenges({beta: beta, gamma: gamma, alpha: alpha, zeta: zeta, v: v, u: u});
    }

    /// @notice Plonk step 5 and 6
    /// @dev Step 5: Compute the zero polynomial evaluation
    /// @dev This is (for eval point zeta) zeta^n - 1
    /// @dev Step 6: Compute the first Lagrange basis polynomial evaluated at zeta
    /// @param omega The base root of unity for the evaluation domain
    /// @param challenges The challenges from the transcript
    /// @param vk The verification key
    /// @return The evaluation of the zero polynomial and the first Lagrange basis polynomial at zeta
    function plonkStep5And6(BN254.ScalarField omega, Challenges memory challenges, VerificationKey memory vk)
        internal
        view
        returns (BN254.ScalarField, BN254.ScalarField)
    {
        // Step 5: Compute the zero polynomial evaluation
        uint256 zetaUint = BN254.ScalarField.unwrap(challenges.zeta);
        BN254.ScalarField zetaPow = BN254.ScalarField.wrap(BN254.powSmall(zetaUint, vk.n, BN254.R_MOD));
        BN254.ScalarField zeroPolyEval = BN254.add(zetaPow, BN254Helpers.NEG_ONE);

        // Step 6: Compute the first Lagrange basis polynomial evaluated at zeta
        BN254.ScalarField nScalar = BN254.ScalarField.wrap(uint256(vk.n));
        BN254.ScalarField lagrangeDenom = BN254.add(challenges.zeta, BN254.negate(omega));
        lagrangeDenom = BN254.invert(BN254.mul(nScalar, lagrangeDenom));
        BN254.ScalarField lagrangeNum = BN254.mul(zeroPolyEval, omega);
        BN254.ScalarField lagrangeEval = BN254.mul(lagrangeNum, lagrangeDenom);

        return (zeroPolyEval, lagrangeEval);
    }
}
