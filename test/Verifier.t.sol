// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

import { TestUtils } from "./utils/TestUtils.sol";
import { VerifierTestUtils } from "./utils/VerifierTestUtils.sol";
import { Verifier } from "../src/verifier/Verifier.sol";
import {
    PlonkProof,
    NUM_WIRE_TYPES,
    NUM_SELECTORS,
    VerificationKey,
    OpeningElements,
    emptyOpeningElements
} from "../src/verifier/Types.sol";

import { BN254 } from "solidity-bn254/BN254.sol";
import { console2 } from "forge-std/console2.sol";

contract VerifierTest is VerifierTestUtils {
    Verifier public verifier;
    TestUtils public testUtils;

    bytes constant INVALID_G1_POINT = "Bn254: invalid G1 point";
    bytes constant INVALID_SCALAR = "Bn254: invalid scalar field";

    function setUp() public {
        verifier = new Verifier();
    }

    // --- Invalid Test Cases --- //

    /// @notice Test that the verifier properly validates all proof components in step 1 of Plonk verification
    function testMalformedProof() public {
        // Create a valid scalar and EC point to use as a base
        BN254.G1Point memory validPoint = BN254.P1();
        BN254.G1Point memory invalidPoint = BN254.G1Point({ x: BN254.BaseField.wrap(42), y: BN254.BaseField.wrap(0) });
        BN254.ScalarField validScalar = BN254.ScalarField.wrap(1);
        BN254.ScalarField invalidScalar = BN254.ScalarField.wrap(BN254.R_MOD);

        // Create fixed-size arrays
        BN254.G1Point[NUM_WIRE_TYPES] memory wire_comms;
        BN254.G1Point[NUM_WIRE_TYPES] memory quotient_comms;
        BN254.ScalarField[NUM_WIRE_TYPES] memory wire_evals;
        BN254.ScalarField[NUM_WIRE_TYPES - 1] memory sigma_evals;

        // Fill arrays with valid values
        for (uint256 i = 0; i < NUM_WIRE_TYPES; i++) {
            wire_comms[i] = validPoint;
            quotient_comms[i] = validPoint;
            wire_evals[i] = validScalar;
            if (i < NUM_WIRE_TYPES - 1) {
                sigma_evals[i] = validScalar;
            }
        }

        // Create a valid proof
        BN254.ScalarField[] memory publicInputs = new BN254.ScalarField[](1);
        publicInputs[0] = validScalar;
        PlonkProof memory proof = PlonkProof({
            wire_comms: wire_comms,
            z_comm: validPoint,
            quotient_comms: quotient_comms,
            w_zeta: validPoint,
            w_zeta_omega: validPoint,
            wire_evals: wire_evals,
            sigma_evals: sigma_evals,
            z_bar: validScalar
        });

        // Create a mock verification key
        VerificationKey memory vk = createMockVerificationKey();

        // Test Case 1: Invalid wire commitment
        uint256 invalidIdx = randomUint(NUM_WIRE_TYPES);
        proof.wire_comms[invalidIdx] = invalidPoint;
        vm.expectRevert(INVALID_G1_POINT);
        verifier.verify(proof, publicInputs, vk);
        proof.wire_comms[invalidIdx] = validPoint; // Reset

        // Test Case 2: Invalid z commitment
        invalidIdx = randomUint(NUM_WIRE_TYPES);
        proof.z_comm = invalidPoint;
        vm.expectRevert(INVALID_G1_POINT);
        verifier.verify(proof, publicInputs, vk);
        proof.z_comm = validPoint; // Reset

        // Test Case 3: Invalid quotient commitment
        invalidIdx = randomUint(NUM_WIRE_TYPES);
        proof.quotient_comms[invalidIdx] = invalidPoint;
        vm.expectRevert(INVALID_G1_POINT);
        verifier.verify(proof, publicInputs, vk);
        proof.quotient_comms[invalidIdx] = validPoint; // Reset

        // Test Case 4: Invalid w_zeta
        invalidIdx = randomUint(NUM_WIRE_TYPES);
        proof.w_zeta = invalidPoint;
        vm.expectRevert(INVALID_G1_POINT);
        verifier.verify(proof, publicInputs, vk);
        proof.w_zeta = validPoint; // Reset

        // Test Case 5: Invalid w_zeta_omega
        invalidIdx = randomUint(NUM_WIRE_TYPES);
        proof.w_zeta_omega = invalidPoint;
        vm.expectRevert(INVALID_G1_POINT);
        verifier.verify(proof, publicInputs, vk);
        proof.w_zeta_omega = validPoint; // Reset

        // Test Case 6: Invalid wire evaluation
        invalidIdx = randomUint(NUM_WIRE_TYPES);
        proof.wire_evals[invalidIdx] = invalidScalar;
        vm.expectRevert(INVALID_SCALAR);
        verifier.verify(proof, publicInputs, vk);
        proof.wire_evals[invalidIdx] = validScalar; // Reset

        // Test Case 7: Invalid sigma evaluation
        invalidIdx = randomUint(NUM_WIRE_TYPES - 1);
        proof.sigma_evals[invalidIdx] = invalidScalar;
        vm.expectRevert(INVALID_SCALAR);
        verifier.verify(proof, publicInputs, vk);
        proof.sigma_evals[invalidIdx] = validScalar; // Reset

        // Test Case 8: Invalid z_bar
        invalidIdx = randomUint(NUM_WIRE_TYPES);
        proof.z_bar = invalidScalar;
        vm.expectRevert(INVALID_SCALAR);
        verifier.verify(proof, publicInputs, vk);
        proof.z_bar = validScalar; // Reset
    }

    /// @notice Test that the verifier properly validates public inputs in step 3 of Plonk verification
    function testInvalidPublicInputs() public {
        uint256 NUM_PUBLIC_INPUTS = 3;

        // Create a valid scalar and EC point to use as a base
        BN254.G1Point memory validPoint = BN254.P1();
        BN254.ScalarField validScalar = BN254.ScalarField.wrap(1);
        BN254.ScalarField invalidScalar = BN254.ScalarField.wrap(BN254.R_MOD);

        // Create fixed-size arrays for a valid proof
        BN254.G1Point[NUM_WIRE_TYPES] memory wire_comms;
        BN254.G1Point[NUM_WIRE_TYPES] memory quotient_comms;
        BN254.ScalarField[NUM_WIRE_TYPES] memory wire_evals;
        BN254.ScalarField[NUM_WIRE_TYPES - 1] memory sigma_evals;

        // Fill arrays with valid values
        for (uint256 i = 0; i < NUM_WIRE_TYPES; i++) {
            wire_comms[i] = validPoint;
            quotient_comms[i] = validPoint;
            wire_evals[i] = validScalar;
            if (i < NUM_WIRE_TYPES - 1) {
                sigma_evals[i] = validScalar;
            }
        }

        // Create a valid proof
        PlonkProof memory proof = PlonkProof({
            wire_comms: wire_comms,
            z_comm: validPoint,
            quotient_comms: quotient_comms,
            w_zeta: validPoint,
            w_zeta_omega: validPoint,
            wire_evals: wire_evals,
            sigma_evals: sigma_evals,
            z_bar: validScalar
        });

        // Create a mock verification key
        VerificationKey memory vk = createMockVerificationKey();

        // Test Case: Invalid public input
        BN254.ScalarField[] memory publicInputs = new BN254.ScalarField[](NUM_PUBLIC_INPUTS);
        for (uint256 i = 0; i < NUM_PUBLIC_INPUTS; i++) {
            publicInputs[i] = validScalar;
        }

        // Try a random position with an invalid scalar
        uint256 invalidIdx = randomUint(NUM_PUBLIC_INPUTS);
        publicInputs[invalidIdx] = invalidScalar;
        vm.expectRevert(INVALID_SCALAR);
        verifier.verify(proof, publicInputs, vk);
    }

    /// @notice Test that a valid proof passes steps 1-3 of Plonk verification
    function testDummyProof() public view {
        // Create a valid scalar and EC point to use as a base
        BN254.G1Point memory validPoint = BN254.P1();
        BN254.ScalarField validScalar = BN254.ScalarField.wrap(1);

        // Create fixed-size arrays for a valid proof
        BN254.G1Point[NUM_WIRE_TYPES] memory wire_comms;
        BN254.G1Point[NUM_WIRE_TYPES] memory quotient_comms;
        BN254.ScalarField[NUM_WIRE_TYPES] memory wire_evals;
        BN254.ScalarField[NUM_WIRE_TYPES - 1] memory sigma_evals;

        // Fill arrays with valid values
        for (uint256 i = 0; i < NUM_WIRE_TYPES; i++) {
            wire_comms[i] = validPoint;
            quotient_comms[i] = validPoint;
            wire_evals[i] = validScalar;
            if (i < NUM_WIRE_TYPES - 1) {
                sigma_evals[i] = validScalar;
            }
        }

        // Create a valid proof
        PlonkProof memory proof = PlonkProof({
            wire_comms: wire_comms,
            z_comm: validPoint,
            quotient_comms: quotient_comms,
            w_zeta: validPoint,
            w_zeta_omega: validPoint,
            wire_evals: wire_evals,
            sigma_evals: sigma_evals,
            z_bar: validScalar
        });

        // Create a mock verification key
        VerificationKey memory vk = createMockVerificationKey();

        // Create a valid public input
        BN254.ScalarField[] memory publicInputs = new BN254.ScalarField[](1);
        publicInputs[0] = validScalar;

        // This should not revert since we're using valid inputs
        bool res = verifier.verify(proof, publicInputs, vk);
        require(!res, "Proof verification should have failed");
    }

    /// @notice Test a modified proof that should fail verification
    function testModifiedProof() public {
        // First generate the verification key for the circuit
        compileRustBinary("test/rust-reference-impls/verifier/Cargo.toml");
        VerificationKey memory vkey = getMulTwoVkey();

        // Create a proof for the mul-two circuit
        uint256 a = randomFelt();
        uint256 b = randomFelt();
        (uint256 c, PlonkProof memory originalProof) = getMulTwoProof(a, b);

        // Create the public inputs array once
        BN254.ScalarField[] memory publicInputs = new BN254.ScalarField[](1);
        publicInputs[0] = BN254.ScalarField.wrap(c);

        BN254.G1Point memory dummyG1Point = BN254.P1();
        BN254.ScalarField dummyScalar = BN254.ScalarField.wrap(1);

        bool res;

        // Test Case 1: Modify a wire commitment
        {
            uint256 randomIdx = randomUint(NUM_WIRE_TYPES);
            PlonkProof memory proof = clonePlonkProof(originalProof);
            proof.wire_comms[randomIdx] = dummyG1Point;
            res = verifier.verify(proof, publicInputs, vkey);
            require(!res, "Proof verification should have failed");
        }

        // Test Case 2: Modify z_comm
        {
            PlonkProof memory proof = clonePlonkProof(originalProof);
            proof.z_comm = dummyG1Point;
            res = verifier.verify(proof, publicInputs, vkey);
            require(!res, "Proof verification should have failed");
        }

        // Test Case 3: Modify a quotient commitment
        {
            uint256 randomIdx = randomUint(NUM_WIRE_TYPES);
            PlonkProof memory proof = clonePlonkProof(originalProof);
            proof.quotient_comms[randomIdx] = dummyG1Point;
            res = verifier.verify(proof, publicInputs, vkey);
            require(!res, "Proof verification should have failed");
        }

        // Test Case 4: Modify w_zeta
        {
            PlonkProof memory proof = clonePlonkProof(originalProof);
            proof.w_zeta = dummyG1Point;
            res = verifier.verify(proof, publicInputs, vkey);
            require(!res, "Proof verification should have failed");
        }

        // Test Case 5: Modify w_zeta_omega
        {
            PlonkProof memory proof = clonePlonkProof(originalProof);
            proof.w_zeta_omega = dummyG1Point;
            res = verifier.verify(proof, publicInputs, vkey);
            require(!res, "Proof verification should have failed");
        }

        // Test Case 6: Modify a wire evaluation
        {
            uint256 randomIdx = randomUint(NUM_WIRE_TYPES);
            PlonkProof memory proof = clonePlonkProof(originalProof);
            proof.wire_evals[randomIdx] = dummyScalar;
            res = verifier.verify(proof, publicInputs, vkey);
            require(!res, "Proof verification should have failed");
        }

        // Test Case 7: Modify a sigma evaluation
        {
            uint256 randomIdx = randomUint(NUM_WIRE_TYPES - 1);
            PlonkProof memory proof = clonePlonkProof(originalProof);
            proof.sigma_evals[randomIdx] = dummyScalar;
            res = verifier.verify(proof, publicInputs, vkey);
            require(!res, "Proof verification should have failed");
        }

        // Test Case 8: Modify z_bar
        {
            PlonkProof memory proof = clonePlonkProof(originalProof);
            proof.z_bar = dummyScalar;
            res = verifier.verify(proof, publicInputs, vkey);
            require(!res, "Proof verification should have failed");
        }

        // Verify the original proof still works
        res = verifier.verify(originalProof, publicInputs, vkey);
        require(res, "Original proof verification should have succeeded");
    }

    /// @notice Test that batch verification fails if any proof in the batch is invalid
    function testInvalidBatchVerification() public {
        // First generate the verification keys for the circuits
        compileRustBinary("test/rust-reference-impls/verifier/Cargo.toml");

        // Generate batch test data
        (PlonkProof[] memory proofs, BN254.ScalarField[][] memory publicInputs, VerificationKey[] memory vks) =
            generateBatchProofData();

        // Randomly select a proof to modify
        uint256 proofToModify = randomUint(proofs.length);
        PlonkProof memory invalidProof = clonePlonkProof(proofs[proofToModify]);

        // Randomly select which part of the proof to modify
        uint256 modType = randomUint(8);
        BN254.G1Point memory dummyG1Point = BN254.P1();
        BN254.ScalarField dummyScalar = BN254.ScalarField.wrap(1);

        if (modType == 0) {
            // Modify a wire commitment
            uint256 randomIdx = randomUint(NUM_WIRE_TYPES);
            invalidProof.wire_comms[randomIdx] = dummyG1Point;
        } else if (modType == 1) {
            // Modify z_comm
            invalidProof.z_comm = dummyG1Point;
        } else if (modType == 2) {
            // Modify a quotient commitment
            uint256 randomIdx = randomUint(NUM_WIRE_TYPES);
            invalidProof.quotient_comms[randomIdx] = dummyG1Point;
        } else if (modType == 3) {
            // Modify w_zeta
            invalidProof.w_zeta = dummyG1Point;
        } else if (modType == 4) {
            // Modify w_zeta_omega
            invalidProof.w_zeta_omega = dummyG1Point;
        } else if (modType == 5) {
            // Modify a wire evaluation
            uint256 randomIdx = randomUint(NUM_WIRE_TYPES);
            invalidProof.wire_evals[randomIdx] = dummyScalar;
        } else if (modType == 6) {
            // Modify a sigma evaluation
            uint256 randomIdx = randomUint(NUM_WIRE_TYPES - 1);
            invalidProof.sigma_evals[randomIdx] = dummyScalar;
        } else {
            // Modify z_bar
            invalidProof.z_bar = dummyScalar;
        }

        // Replace the selected proof with the invalid one
        proofs[proofToModify] = invalidProof;

        // Verify the batch - should fail
        OpeningElements memory extraOpeningElements = emptyOpeningElements();
        bool res = verifier.batchVerify(proofs, publicInputs, vks, extraOpeningElements);
        require(!res, "Proof verification should have failed");
    }

    /// @notice Test the case in which a public input is modified
    function testModifiedPublicInput() public {
        // First generate the verification keys for the circuits
        compileRustBinary("test/rust-reference-impls/verifier/Cargo.toml");
        VerificationKey memory vkey = getPermutationVkey();

        // Generate data for the permutation circuit
        uint256 randomChallenge = randomFelt();
        uint256[5] memory statement;
        uint256[5] memory witness;
        for (uint256 i = 0; i < 5; i++) {
            statement[i] = randomFelt();
            witness[5 - i - 1] = statement[i];
        }

        // Get the proof and public input
        PlonkProof memory proof = getPermutationProof(randomChallenge, statement, witness);

        // Verify the proof
        BN254.ScalarField[] memory publicInputs = new BN254.ScalarField[](6);
        publicInputs[0] = BN254.ScalarField.wrap(randomChallenge);
        for (uint256 i = 0; i < 5; i++) {
            publicInputs[i + 1] = BN254.ScalarField.wrap(statement[i]);
        }

        // Modify the public input
        uint256 randomIdx = randomUint(publicInputs.length);
        publicInputs[randomIdx] = BN254.ScalarField.wrap(randomFelt());

        // Verify the proof
        bool res = verifier.verify(proof, publicInputs, vkey);
        require(!res, "Proof verification should have failed");
    }

    // --- Valid Test Cases --- //

    /// @notice Test the verifier against a reference implementation on the mul-two circuit
    function testVerifierMulTwo() public {
        // First generate the verification key for the circuit
        compileRustBinary("test/rust-reference-impls/verifier/Cargo.toml");
        VerificationKey memory vkey = getMulTwoVkey();

        // Generate two random inputs and prove their product
        uint256 a = randomFelt();
        uint256 b = randomFelt();
        (uint256 c, PlonkProof memory proof) = getMulTwoProof(a, b);

        // Verify the proof
        BN254.ScalarField[] memory publicInputs = new BN254.ScalarField[](1);
        publicInputs[0] = BN254.ScalarField.wrap(c);
        bool res = verifier.verify(proof, publicInputs, vkey);
        require(res, "Proof verification should have succeeded");
    }

    /// @notice Test the verifier against a reference implementation on the sum-pow circuit
    function testVerifierSumPow() public {
        uint256 NUM_INPUTS = 10;

        // First generate the verification key for the circuit
        compileRustBinary("test/rust-reference-impls/verifier/Cargo.toml");
        VerificationKey memory vkey = getSumPowVkey();

        // Generate ten random inputs
        uint256[10] memory inputs;
        for (uint256 i = 0; i < NUM_INPUTS; i++) {
            inputs[i] = randomFelt();
        }

        // Get the proof and public input
        (BN254.ScalarField sumPow, PlonkProof memory proof) = getSumPowProof(inputs);

        // Verify the proof
        BN254.ScalarField[] memory publicInputs = new BN254.ScalarField[](1);
        publicInputs[0] = sumPow;
        bool res = verifier.verify(proof, publicInputs, vkey);
        require(res, "Proof verification should have succeeded");
    }

    /// @notice Test the verifier against a reference implementation on the permutation circuit
    function testVerifierPermutation() public {
        uint256 N = 5;
        // First generate the verification key for the circuit
        compileRustBinary("test/rust-reference-impls/verifier/Cargo.toml");
        VerificationKey memory vkey = getPermutationVkey();

        // Generate a random statement and witness
        uint256[5] memory statement;
        uint256[5] memory witness;
        for (uint256 i = 0; i < N; i++) {
            uint256 val = randomFelt();
            statement[i] = val;
            witness[N - i - 1] = val; // A simple reverse permutation
        }

        // Get the proof
        uint256 randomChallenge = randomFelt();
        PlonkProof memory proof = getPermutationProof(randomChallenge, statement, witness);

        // Verify the proof
        BN254.ScalarField[] memory publicInputs = new BN254.ScalarField[](N + 1);
        publicInputs[0] = BN254.ScalarField.wrap(randomChallenge);
        for (uint256 i = 0; i < N; i++) {
            publicInputs[i + 1] = BN254.ScalarField.wrap(statement[i]);
        }

        bool res = verifier.verify(proof, publicInputs, vkey);
        require(res, "Proof verification should have succeeded");
    }

    /// @notice Test batch verification against all three circuits
    function testBatchVerification() public {
        // First generate the verification keys for the circuits
        compileRustBinary("test/rust-reference-impls/verifier/Cargo.toml");

        // Generate batch test data
        (PlonkProof[] memory proofs, BN254.ScalarField[][] memory publicInputs, VerificationKey[] memory vks) =
            generateBatchProofData();

        // Verify the batch
        OpeningElements memory extraOpeningElements = emptyOpeningElements();
        bool res = verifier.batchVerify(proofs, publicInputs, vks, extraOpeningElements);
        require(res, "Proof verification should have succeeded");
    }
}
