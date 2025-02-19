// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { Test } from "forge-std/Test.sol";
import { TestUtils } from "./TestUtils.sol";
import { VerificationKey, NUM_SELECTORS, NUM_WIRE_TYPES, PlonkProof } from "../../src/verifier/Types.sol";
import { BN254 } from "solidity-bn254/BN254.sol";
import { BN254Helpers } from "../../src/verifier/BN254Helpers.sol";
import { Strings } from "openzeppelin-contracts/contracts/utils/Strings.sol";

contract VerifierTestUtils is TestUtils {
    // ---------
    // | Mocks |
    // ---------

    /// @dev Creates a mock verification key for testing
    function createMockVerificationKey() internal pure returns (VerificationKey memory) {
        BN254.G1Point memory validPoint = BN254.P1();
        BN254.ScalarField validScalar = BN254.ScalarField.wrap(1);

        // Create arrays for the verification key
        BN254.G1Point[NUM_SELECTORS] memory q_comms;
        BN254.G1Point[NUM_WIRE_TYPES] memory sigma_comms;
        BN254.ScalarField[NUM_WIRE_TYPES] memory k;

        // Fill arrays with valid values
        for (uint256 i = 0; i < NUM_SELECTORS; i++) {
            q_comms[i] = validPoint;
        }
        for (uint256 i = 0; i < NUM_WIRE_TYPES; i++) {
            sigma_comms[i] = validPoint;
            k[i] = validScalar;
        }

        return VerificationKey({
            n: 8, // Small power of 2 for testing
            l: 1, // Single public input
            k: k,
            q_comms: q_comms,
            sigma_comms: sigma_comms,
            g: validPoint,
            h: BN254.P2(),
            x_h: BN254.P2()
        });
    }

    // -----------------------------
    // | Reference Implementations |
    // -----------------------------

    /// @dev Run the reference implementation to generate a vkey for the mulTwo circuit
    function getMulTwoVkey() internal returns (VerificationKey memory) {
        string[] memory args = new string[](3);
        args[0] = "./test/rust-reference-impls/target/debug/verifier";
        args[1] = "mul-two";
        args[2] = "print-vkey";

        string memory response = runBinaryGetResponse(args);
        return abi.decode(vm.parseBytes(response), (VerificationKey));
    }

    /// @dev Run the reference implementation to generate a proof for the mulTwo circuit
    function getMulTwoProof(uint256 a, uint256 b) internal returns (uint256, PlonkProof memory) {
        uint256 c = mulmod(a, b, PRIME);
        string[] memory args = new string[](6);
        args[0] = "./test/rust-reference-impls/target/debug/verifier";
        args[1] = "mul-two";
        args[2] = "prove";
        args[3] = Strings.toString(a);
        args[4] = Strings.toString(b);
        args[5] = Strings.toString(c);

        string memory response = runBinaryGetResponse(args);
        return (c, abi.decode(vm.parseBytes(response), (PlonkProof)));
    }

    /// @dev Run the reference implementation to generate a vkey for the sumPow circuit
    function getSumPowVkey() internal returns (VerificationKey memory) {
        string[] memory args = new string[](3);
        args[0] = "./test/rust-reference-impls/target/debug/verifier";
        args[1] = "sum-pow";
        args[2] = "print-vkey";

        string memory response = runBinaryGetResponse(args);
        return abi.decode(vm.parseBytes(response), (VerificationKey));
    }

    /// @dev Run the reference implementation to generate a proof for the sumPow circuit
    function getSumPowProof(uint256[10] memory witness) internal returns (BN254.ScalarField, PlonkProof memory) {
        BN254.ScalarField sum = BN254.ScalarField.wrap(0);
        for (uint256 i = 0; i < witness.length; i++) {
            sum = BN254.add(sum, BN254.ScalarField.wrap(witness[i]));
        }
        BN254.ScalarField expected = BN254Helpers.fifthPower(sum);

        string[] memory args = new string[](14);
        args[0] = "./test/rust-reference-impls/target/debug/verifier";
        args[1] = "sum-pow";
        args[2] = "prove";
        for (uint256 i = 0; i < witness.length; i++) {
            args[3 + i] = Strings.toString(witness[i]);
        }
        args[13] = Strings.toString(BN254.ScalarField.unwrap(expected));

        string memory response = runBinaryGetResponse(args);
        return (expected, abi.decode(vm.parseBytes(response), (PlonkProof)));
    }

    /// @dev Run the reference implementation to generate a vkey for the permutation circuit
    function getPermutationVkey() internal returns (VerificationKey memory) {
        string[] memory args = new string[](3);
        args[0] = "./test/rust-reference-impls/target/debug/verifier";
        args[1] = "permutation";
        args[2] = "print-vkey";

        string memory response = runBinaryGetResponse(args);
        return abi.decode(vm.parseBytes(response), (VerificationKey));
    }

    /// @dev Run the reference implementation to generate a proof for the permutation circuit
    function getPermutationProof(
        uint256 randomChallenge,
        uint256[5] memory statement,
        uint256[5] memory witness
    )
        internal
        returns (PlonkProof memory)
    {
        string[] memory args = new string[](17);
        args[0] = "./test/rust-reference-impls/target/debug/verifier";
        args[1] = "permutation";
        args[2] = "prove";
        args[3] = "--random-challenge";
        args[4] = Strings.toString(randomChallenge);

        // Encode statement elements
        args[5] = "--values";
        for (uint256 i = 0; i < statement.length; i++) {
            args[6 + i] = Strings.toString(statement[i]);
        }

        // Encode witness elements
        args[11] = "--permuted-values";
        for (uint256 i = 0; i < witness.length; i++) {
            args[12 + i] = Strings.toString(witness[i]);
        }

        string memory response = runBinaryGetResponse(args);
        return abi.decode(vm.parseBytes(response), (PlonkProof));
    }
}
