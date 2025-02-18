// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.0;

import { TestUtils } from "./utils/TestUtils.sol";
import { VerifierTestUtils } from "./utils/VerifierTestUtils.sol";
import { Verifier } from "../src/verifier/Verifier.sol";
import { PlonkProof, NUM_WIRE_TYPES, NUM_SELECTORS, VerificationKey } from "../src/verifier/Types.sol";

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

    /// @notice Test the verifier against a reference implementation
    function testVerifierMulTwo() public {
        // First generate the verification key for the circuit
        compileRustBinary("test/rust-reference-impls/verifier/Cargo.toml");
        VerificationKey memory vkey = getMulTwoVkey();

        // Generate two random inputs and prove their product
        uint256 a = randomFelt();
        uint256 b = randomFelt();
        uint256 c = mulmod(a, b, PRIME);
        PlonkProof memory proof = getMulTwoProof(a, b);

        // Verify the proof
        BN254.ScalarField[] memory publicInputs = new BN254.ScalarField[](1);
        publicInputs[0] = BN254.ScalarField.wrap(c);
        bool res = verifier.verify(proof, publicInputs, vkey);
        require(res, "Proof verification should have succeeded");
    }
}
