// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

import { Transcript } from "./Transcript.sol";
import { PlonkProof, VerificationKey, Challenges, NUM_WIRE_TYPES, NUM_SELECTORS } from "./Types.sol";
import { TranscriptLib } from "./Transcript.sol";
import { BN254 } from "solidity-bn254/BN254.sol";
import { BN254Helpers } from "./BN254Helpers.sol";
import { Utils } from "solidity-bn254/Utils.sol";

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
    using TranscriptLib for Transcript;

    /// @notice Verify a single plonk proof
    /// @notice Verify a single plonk proof
    /// @param proof The proof to verify
    /// @param publicInputs The public inputs to the proof
    /// @param vk The verification key for the circuit
    /// @return True if the proof is valid, false otherwise
    function verify(
        PlonkProof memory proof,
        BN254.ScalarField[] memory publicInputs,
        VerificationKey memory vk
    )
        public
        view
        returns (bool)
    {
        PlonkProof[] memory proofArray = new PlonkProof[](1);
        proofArray[0] = proof;

        BN254.ScalarField[][] memory publicInputsArray = new BN254.ScalarField[][](1);
        publicInputsArray[0] = publicInputs;

        VerificationKey[] memory vkArray = new VerificationKey[](1);
        vkArray[0] = vk;

        return batchVerify(proofArray, publicInputsArray, vkArray);
    }

    /// @notice Verify a batch of Plonk proofs using the arithmetization defined in `mpc-jellyfish`:
    /// https://github.com/renegade-fi/mpc-jellyfish
    /// @param proofs The proofs to verify
    /// @param publicInputs The public inputs to the proofs
    /// @param vks The verification keys for the circuit
    /// @return True if the proofs are valid, false otherwise
    function batchVerify(
        PlonkProof[] memory proofs,
        BN254.ScalarField[][] memory publicInputs,
        VerificationKey[] memory vks
    )
        public
        view
        returns (bool)
    {
        plonkStep1And2(proofs);
        plonkStep3(publicInputs);
        Challenges[] memory batchChallenges = plonkStep4(proofs, publicInputs, vks);

        // Get the base root of unity for the circuit's evaluation domain
        BN254.ScalarField[] memory lastChallenges = new BN254.ScalarField[](proofs.length);
        BN254.G1Point[] memory lhsTerms = new BN254.G1Point[](proofs.length);
        BN254.G1Point[] memory rhsTerms = new BN254.G1Point[](proofs.length);
        for (uint256 i = 0; i < proofs.length; i++) {
            PlonkProof memory proof = proofs[i];
            VerificationKey memory vk = vks[i];
            Challenges memory challenges = batchChallenges[i];
            BN254.ScalarField[] memory publicInput = publicInputs[i];

            // Setup the public input polynomial
            BN254.ScalarField omega = BN254Helpers.rootOfUnity(vk.n);
            (BN254.ScalarField vanishingEval, BN254.ScalarField lagrangeEval) = plonkStep5And6(vk.n, challenges.zeta);
            BN254.ScalarField publicInputPolyEval = plonkStep7(vk.n, challenges.zeta, omega, vanishingEval, publicInput);

            // Compute the reduction to a pairing check
            BN254.ScalarField linearizationConstTerm = plonkStep8(
                publicInputPolyEval,
                lagrangeEval,
                challenges.alpha,
                challenges.beta,
                challenges.gamma,
                proof.wire_evals,
                proof.sigma_evals,
                proof.z_bar
            );
            BN254.G1Point memory committedPoly = plonkStep9(lagrangeEval, vanishingEval, challenges, proof, vk);
            BN254.G1Point memory batchCommitment = plonkStep10(committedPoly, challenges, proof, vk);
            BN254.G1Point memory batchEval = plonkStep11(linearizationConstTerm, challenges, proof, vk);

            // Step 12: Batch validate the evaluations
            // LHS of the pairing check: e(w_zeta + w_zeta_omega * u, x_h)
            BN254.G1Point memory lhsTerm = BN254.add(proof.w_zeta, BN254.scalarMul(proof.w_zeta_omega, challenges.u));

            // RHS of the pairing check: e(zeta * w_zeta + u * zeta * omega * w_zeta_omega + batchCommitment -
            // batchEval, x_h)
            BN254.G1Point memory rhsTerm = BN254.add(
                BN254.scalarMul(proof.w_zeta, challenges.zeta),
                BN254.scalarMul(proof.w_zeta_omega, BN254.mul(challenges.u, BN254.mul(challenges.zeta, omega)))
            );
            rhsTerm = BN254.add(rhsTerm, BN254.add(batchCommitment, BN254.negate(batchEval)));

            lhsTerms[i] = lhsTerm;
            rhsTerms[i] = BN254.negate(rhsTerm);
            lastChallenges[i] = challenges.u;
        }

        return verifyBatchOpening(vks[0].h, vks[0].x_h, lhsTerms, rhsTerms, lastChallenges);
    }

    /// Verify a batch opening of proofs
    function verifyBatchOpening(
        BN254.G2Point memory h,
        BN254.G2Point memory x_h,
        BN254.G1Point[] memory lhsG1Terms,
        BN254.G1Point[] memory rhsG1Terms,
        BN254.ScalarField[] memory lastChallenges
    )
        public
        view
        returns (bool)
    {
        uint256 numProofs = lhsG1Terms.length;

        // Sample a random scalar to parameterize the random linear combination
        // If only one proof is supplied, no randomization is needed
        BN254.ScalarField r = BN254Helpers.ONE;
        if (numProofs > 1) {
            Transcript memory transcript = TranscriptLib.new_transcript();
            transcript.appendScalars(lastChallenges);
            r = transcript.getChallenge();
        }

        BN254.ScalarField rCurr = r;
        BN254.G1Point memory lhsTerm = lhsG1Terms[0];
        BN254.G1Point memory rhsTerm = rhsG1Terms[0];
        for (uint256 i = 1; i < numProofs; i++) {
            lhsTerm = BN254.add(lhsTerm, BN254.scalarMul(lhsG1Terms[i], rCurr));
            rhsTerm = BN254.add(rhsTerm, BN254.scalarMul(rhsG1Terms[i], rCurr));
            rCurr = BN254.mul(rCurr, r);
        }

        return BN254.pairingProd2(lhsTerm, x_h, rhsTerm, h);
    }

    /// @notice Step 1 and 2 of the plonk verification algorithm
    /// @notice Verify that the G_1 points are on the curve
    function plonkStep1And2(PlonkProof[] memory proofs) internal pure {
        // Check that the commitments to the wire polynomials are on the curve
        for (uint256 i = 0; i < proofs.length; i++) {
            PlonkProof memory proof = proofs[i];
            for (uint256 j = 0; j < proof.wire_comms.length; j++) {
                BN254.validateG1Point(proof.wire_comms[j]);
            }

            // Check the commitment to the grand product polynomial is on the curve
            BN254.validateG1Point(proof.z_comm);

            // Check the commitments to the quotient polynomials are on the curve
            for (uint256 j = 0; j < proof.quotient_comms.length; j++) {
                BN254.validateG1Point(proof.quotient_comms[j]);
            }

            // Check that the opening proofs are on the curve
            BN254.validateG1Point(proof.w_zeta);
            BN254.validateG1Point(proof.w_zeta_omega);

            // Check that each of the evaluations of wire polynomials are in the scalar field
            for (uint256 j = 0; j < proof.wire_evals.length; j++) {
                BN254.validateScalarField(proof.wire_evals[j]);
            }

            // Check that each of the evaluations of the permutation polynomials are in the scalar field
            for (uint256 j = 0; j < proof.sigma_evals.length; j++) {
                BN254.validateScalarField(proof.sigma_evals[j]);
            }

            // Check that the evaluation of the grand product polynomial is in the scalar field
            BN254.validateScalarField(proof.z_bar);
        }
    }

    /// @notice Step 3 of the plonk verification algorithm
    /// @notice Verify that the public inputs to the proof are all in the scalar field
    function plonkStep3(BN254.ScalarField[][] memory publicInputs) internal pure {
        // Check that the public inputs are all in the scalar field
        for (uint256 i = 0; i < publicInputs.length; i++) {
            for (uint256 j = 0; j < publicInputs[i].length; j++) {
                BN254.validateScalarField(publicInputs[i][j]);
            }
        }
    }

    /// @notice Step 4 of the plonk verification algorithm
    /// @notice Compute the challenges from a Fiat-Shamir transcript
    /// @dev matches the transcript implementation from `mpc-jellyfish`
    function plonkStep4(
        PlonkProof[] memory proofs,
        BN254.ScalarField[][] memory publicInputs,
        VerificationKey[] memory vks
    )
        internal
        pure
        returns (Challenges[] memory)
    {
        Challenges[] memory challengesArray = new Challenges[](proofs.length);

        for (uint256 i = 0; i < proofs.length; i++) {
            // Create a new transcript
            Transcript memory transcript = TranscriptLib.new_transcript();

            // Append the verification key metadata and public inputs
            bytes memory nBitsBytes = abi.encodePacked(SCALAR_FIELD_N_BITS);
            transcript.appendMessage(nBitsBytes);
            transcript.appendU64(vks[i].n);
            transcript.appendU64(vks[i].l);

            transcript.appendScalars(vks[i].k);
            transcript.appendPoints(vks[i].q_comms);
            transcript.appendPoints(vks[i].sigma_comms);
            transcript.appendScalars(publicInputs[i]);

            // Round 1: Append the wire commitments and squeeze the permutation challenges
            transcript.appendPoints(proofs[i].wire_comms);

            // Squeeze an unused challenge tau for consistency with the Plookup-enabled prover
            transcript.getChallenge();
            BN254.ScalarField beta = transcript.getChallenge();
            BN254.ScalarField gamma = transcript.getChallenge();

            // Round 2: Append the quotient permutation polynomial commitment and squeeze the quotient challenge
            transcript.appendPoint(proofs[i].z_comm);
            BN254.ScalarField alpha = transcript.getChallenge();

            // Round 3: Append the quotient polynomial commitments and squeeze the evaluation challenge
            transcript.appendPoints(proofs[i].quotient_comms);
            BN254.ScalarField zeta = transcript.getChallenge();

            // Round 4: Append the wire, permutation, and grand product evals and squeeze the v opening challenge
            transcript.appendScalars(proofs[i].wire_evals);
            transcript.appendScalars(proofs[i].sigma_evals);
            transcript.appendScalar(proofs[i].z_bar);
            BN254.ScalarField v = transcript.getChallenge();

            // Round 5: Append the two opening proof commitments and squeeze the multipoint evaluation challenge
            transcript.appendPoint(proofs[i].w_zeta);
            transcript.appendPoint(proofs[i].w_zeta_omega);
            BN254.ScalarField u = transcript.getChallenge();

            challengesArray[i] = Challenges({ beta: beta, gamma: gamma, alpha: alpha, zeta: zeta, v: v, u: u });
        }

        return challengesArray;
    }

    /// @notice Plonk step 5 and 6
    /// @dev Step 5: Compute the zero polynomial evaluation
    /// @dev This is (for eval point zeta) zeta^n - 1
    /// @dev Step 6: Compute the first Lagrange basis polynomial evaluated at zeta
    /// @param n The number of gates in the circuit
    /// @param zeta The evaluation challenge from the transcript
    /// @return The evaluation of the zero polynomial and the first Lagrange basis polynomial at zeta
    function plonkStep5And6(
        uint256 n,
        BN254.ScalarField zeta
    )
        internal
        view
        returns (BN254.ScalarField, BN254.ScalarField)
    {
        // Step 5: Compute the zero polynomial evaluation
        uint256 zetaUint = BN254.ScalarField.unwrap(zeta);
        BN254.ScalarField zetaPow = BN254.ScalarField.wrap(BN254.powSmall(zetaUint, n, BN254.R_MOD));
        BN254.ScalarField vanishingEval = BN254.add(zetaPow, BN254Helpers.NEG_ONE);

        // Step 6: Compute the first Lagrange basis polynomial evaluated at zeta
        BN254.ScalarField nScalar = BN254.ScalarField.wrap(uint256(n));
        BN254.ScalarField lagrangeDenom = BN254.add(zeta, BN254Helpers.NEG_ONE);
        lagrangeDenom = BN254.invert(BN254.mul(nScalar, lagrangeDenom));
        BN254.ScalarField lagrangeNum = vanishingEval;
        BN254.ScalarField lagrangeEval = BN254.mul(lagrangeNum, lagrangeDenom);

        return (vanishingEval, lagrangeEval);
    }

    /// @notice Step 7 of the plonk verification algorithm with full struct
    /// @dev Compute the evaluation of the public input polynomial
    /// @dev Over the multiplicative subgroup, each Lagrange basis polynomial L_i(x) takes the form:
    /// @dev L_i(x) = (zeta^n - 1) / n * (zeta - omega^i)
    function plonkStep7(
        uint256 n,
        BN254.ScalarField zeta,
        BN254.ScalarField omega,
        BN254.ScalarField vanishingEval,
        BN254.ScalarField[] memory publicInputs
    )
        internal
        view
        returns (BN254.ScalarField)
    {
        BN254.ScalarField nInv = BN254.invert(BN254.ScalarField.wrap(n));
        BN254.ScalarField vanishingDivN = BN254.mul(vanishingEval, nInv);

        BN254.ScalarField result = BN254.ScalarField.wrap(0);
        BN254.ScalarField currOmegaPow = BN254Helpers.ONE;
        for (uint256 i = 0; i < publicInputs.length; i++) {
            BN254.ScalarField lagrangeNum = BN254.mul(vanishingDivN, currOmegaPow);
            BN254.ScalarField lagrangeDenom = BN254.add(zeta, BN254.negate(currOmegaPow));
            BN254.ScalarField lagrangeEval = BN254.mul(lagrangeNum, BN254.invert(lagrangeDenom));
            currOmegaPow = BN254.mul(currOmegaPow, omega);

            BN254.ScalarField currTerm = BN254.mul(publicInputs[i], lagrangeEval);
            result = BN254.add(result, currTerm);
        }

        return result;
    }

    /// @notice Step 8 of the plonk verification algorithm
    /// @dev Compute the constant term of the linearization polynomial
    function plonkStep8(
        BN254.ScalarField publicInputPolyEval,
        BN254.ScalarField lagrange1Eval,
        BN254.ScalarField alpha,
        BN254.ScalarField beta,
        BN254.ScalarField gamma,
        BN254.ScalarField[NUM_WIRE_TYPES] memory wireEvals,
        BN254.ScalarField[NUM_WIRE_TYPES - 1] memory sigmaEvals,
        BN254.ScalarField zEval
    )
        internal
        pure
        returns (BN254.ScalarField)
    {
        // Term 1: PI(\zeta)
        BN254.ScalarField res = publicInputPolyEval;

        // Term 2: -L_1(\zeta) * \alpha^2
        BN254.ScalarField term2 = BN254.mul(lagrange1Eval, BN254.mul(alpha, alpha));
        res = BN254.add(res, BN254.negate(term2));

        // Add the terms from the permutation argument
        BN254.ScalarField term3 = BN254.mul(alpha, zEval);
        for (uint256 i = 0; i < wireEvals.length - 1; i++) {
            BN254.ScalarField wireEval = wireEvals[i];
            BN254.ScalarField sigmaEval = sigmaEvals[i];

            BN254.ScalarField wirePermTerm = BN254.add(wireEval, BN254.mul(beta, sigmaEval));
            wirePermTerm = BN254.add(wirePermTerm, gamma);

            term3 = BN254.mul(term3, wirePermTerm);
        }

        // Add in the final term without the sigma eval
        BN254.ScalarField lastPermTerm = BN254.add(wireEvals[wireEvals.length - 1], gamma);
        term3 = BN254.mul(term3, lastPermTerm);
        res = BN254.add(res, BN254.negate(term3));

        return res;
    }

    /// @notice Step 9 of the plonk verification algorithm
    /// @dev Compute a linearized commitment to the combined polynomial relation
    function plonkStep9(
        BN254.ScalarField lagrange1Eval,
        BN254.ScalarField vanishingEval,
        Challenges memory challenges,
        PlonkProof memory proof,
        VerificationKey memory vk
    )
        internal
        view
        returns (BN254.G1Point memory)
    {
        // Add in the gate constraints
        BN254.G1Point memory res = plonkStep9GateTerm(proof, vk);

        // Add in the permutation argument contribution
        BN254.G1Point memory permTerm = plonkStep9PermutationTerm(lagrange1Eval, challenges, proof, vk);
        res = BN254.add(res, permTerm);

        // Add in the quotient polynomial contribution
        BN254.G1Point memory quotientTerm = plonkStep9QuotientTerm(challenges.zeta, vanishingEval, proof);
        res = BN254.add(res, quotientTerm);
        return res;
    }

    /// @notice Compute the gate constraints contribution to the linearized polynomial relation
    /// @dev The selectors are:
    /// @dev q_lc[0:3], q_mul[0:1], q_hash[0:3], q_out, q_const, q_prod
    function plonkStep9GateTerm(
        PlonkProof memory proof,
        VerificationKey memory vk
    )
        internal
        view
        returns (BN254.G1Point memory)
    {
        BN254.G1Point memory res = BN254.infinity();

        // The first four terms are linear combination gates
        res = BN254.add(res, BN254.scalarMul(vk.q_comms[0], proof.wire_evals[0]));
        res = BN254.add(res, BN254.scalarMul(vk.q_comms[1], proof.wire_evals[1]));
        res = BN254.add(res, BN254.scalarMul(vk.q_comms[2], proof.wire_evals[2]));
        res = BN254.add(res, BN254.scalarMul(vk.q_comms[3], proof.wire_evals[3]));

        // The next two terms are multiplication gates
        BN254.ScalarField mul1 = BN254.mul(proof.wire_evals[0], proof.wire_evals[1]);
        BN254.ScalarField mul2 = BN254.mul(proof.wire_evals[2], proof.wire_evals[3]);
        res = BN254.add(res, BN254.scalarMul(vk.q_comms[4], mul1));
        res = BN254.add(res, BN254.scalarMul(vk.q_comms[5], mul2));

        // The next four terms are hash gates
        BN254.ScalarField hash1 = BN254Helpers.fifthPower(proof.wire_evals[0]);
        BN254.ScalarField hash2 = BN254Helpers.fifthPower(proof.wire_evals[1]);
        BN254.ScalarField hash3 = BN254Helpers.fifthPower(proof.wire_evals[2]);
        BN254.ScalarField hash4 = BN254Helpers.fifthPower(proof.wire_evals[3]);
        res = BN254.add(res, BN254.scalarMul(vk.q_comms[6], hash1));
        res = BN254.add(res, BN254.scalarMul(vk.q_comms[7], hash2));
        res = BN254.add(res, BN254.scalarMul(vk.q_comms[8], hash3));
        res = BN254.add(res, BN254.scalarMul(vk.q_comms[9], hash4));

        // The next two gates are the output gate and the constant gate (1)
        BN254.ScalarField negOutput = BN254.negate(proof.wire_evals[4]);
        res = BN254.add(res, BN254.scalarMul(vk.q_comms[10], negOutput));
        res = BN254.add(res, vk.q_comms[11]); // Omit scalar mul by 1

        // Last we have the elliptic curve gate, the product of all wires
        BN254.ScalarField wireProd = BN254.mul(mul1, mul2);
        wireProd = BN254.mul(wireProd, proof.wire_evals[4]);
        res = BN254.add(res, BN254.scalarMul(vk.q_comms[12], wireProd));

        return res;
    }

    /// @notice Compute the permutation argument contribution to the linearized polynomial relation
    function plonkStep9PermutationTerm(
        BN254.ScalarField lagrange1Eval,
        Challenges memory challenges,
        PlonkProof memory proof,
        VerificationKey memory vk
    )
        internal
        view
        returns (BN254.G1Point memory)
    {
        // The first permutation term, multiplied by the commitment [z]
        BN254.ScalarField betaZeta = BN254.mul(challenges.beta, challenges.zeta);
        BN254.ScalarField coeff = challenges.alpha;
        for (uint256 i = 0; i < NUM_WIRE_TYPES; i++) {
            BN254.ScalarField betaTerm = BN254.mul(betaZeta, vk.k[i]);
            BN254.ScalarField term = BN254.add(proof.wire_evals[i], betaTerm);
            BN254.ScalarField coeffTerm = BN254.add(term, challenges.gamma);
            coeff = BN254.mul(coeff, coeffTerm);
        }

        BN254.ScalarField lagrangeTerm = BN254.mul(lagrange1Eval, BN254.mul(challenges.alpha, challenges.alpha));
        coeff = BN254.add(coeff, BN254.add(lagrangeTerm, challenges.u));
        BN254.G1Point memory res = BN254.scalarMul(proof.z_comm, coeff);

        // The second permutation term, multiplied by the last permutation polynomial's commitment
        BN254.ScalarField coeff2 = BN254.mul(challenges.alpha, BN254.mul(challenges.beta, proof.z_bar));
        for (uint256 i = 0; i < NUM_WIRE_TYPES - 1; i++) {
            BN254.ScalarField term = proof.wire_evals[i];
            term = BN254.add(term, BN254.mul(challenges.beta, proof.sigma_evals[i]));
            term = BN254.add(term, challenges.gamma);
            coeff2 = BN254.mul(coeff2, term);
        }

        coeff2 = BN254.negate(coeff2);
        BN254.G1Point memory permTerm2 = BN254.scalarMul(vk.sigma_comms[NUM_WIRE_TYPES - 1], coeff2);
        return BN254.add(res, permTerm2);
    }

    /// @notice Compute the quotient polynomial contribution to the linearized polynomial relation
    function plonkStep9QuotientTerm(
        BN254.ScalarField zeta,
        BN254.ScalarField vanishingEval,
        PlonkProof memory proof
    )
        internal
        view
        returns (BN254.G1Point memory)
    {
        // Unlike the plonk paper, Jellyfish uses zeta^(n+2) instead of zeta^n, see:
        // https://github.com/EspressoSystems/jellyfish/blob/main/plonk/src/proof_system/prover.rs#L893
        BN254.ScalarField zetaToNPlus2 = BN254.mul(BN254.add(vanishingEval, BN254Helpers.ONE), BN254.mul(zeta, zeta));

        BN254.ScalarField coeff = BN254.negate(vanishingEval);
        BN254.G1Point memory res = BN254.infinity();
        for (uint256 i = 0; i < NUM_WIRE_TYPES; i++) {
            res = BN254.add(res, BN254.scalarMul(proof.quotient_comms[i], coeff));
            coeff = BN254.mul(coeff, zetaToNPlus2);
        }

        return res;
    }

    /// @notice Step 10 of the plonk verification algorithm
    /// @dev Compute the full polynomial relation
    function plonkStep10(
        BN254.G1Point memory aggregatePolyComm,
        Challenges memory challenges,
        PlonkProof memory proof,
        VerificationKey memory vk
    )
        internal
        view
        returns (BN254.G1Point memory)
    {
        BN254.G1Point memory res = aggregatePolyComm;

        // Add in the wire commitments
        BN254.ScalarField coeff = challenges.v;
        for (uint256 i = 0; i < NUM_WIRE_TYPES; i++) {
            BN254.G1Point memory term = BN254.scalarMul(proof.wire_comms[i], coeff);
            res = BN254.add(res, term);
            coeff = BN254.mul(coeff, challenges.v);
        }

        // Add in the permutation commitments, except the last
        for (uint256 i = 0; i < NUM_WIRE_TYPES - 1; i++) {
            BN254.G1Point memory term = BN254.scalarMul(vk.sigma_comms[i], coeff);
            res = BN254.add(res, term);
            coeff = BN254.mul(coeff, challenges.v);
        }

        return res;
    }

    /// @notice Step 11 of the plonk verification algorithm
    /// @dev Compute the batch evaluation to compare against the claimed openings
    function plonkStep11(
        BN254.ScalarField linearizationConstTerm,
        Challenges memory challenges,
        PlonkProof memory proof,
        VerificationKey memory vk
    )
        internal
        view
        returns (BN254.G1Point memory)
    {
        BN254.ScalarField resCoeff = BN254.negate(linearizationConstTerm);
        BN254.ScalarField termCoeff = challenges.v;
        for (uint256 i = 0; i < NUM_WIRE_TYPES; i++) {
            BN254.ScalarField term = BN254.mul(proof.wire_evals[i], termCoeff);
            resCoeff = BN254.add(resCoeff, term);
            termCoeff = BN254.mul(termCoeff, challenges.v);
        }

        for (uint256 i = 0; i < NUM_WIRE_TYPES - 1; i++) {
            BN254.ScalarField term = BN254.mul(proof.sigma_evals[i], termCoeff);
            resCoeff = BN254.add(resCoeff, term);
            termCoeff = BN254.mul(termCoeff, challenges.v);
        }

        BN254.ScalarField lastTerm = BN254.mul(proof.z_bar, challenges.u);
        resCoeff = BN254.add(resCoeff, lastTerm);

        BN254.G1Point memory res = BN254.scalarMul(vk.g, resCoeff);
        return res;
    }
}
