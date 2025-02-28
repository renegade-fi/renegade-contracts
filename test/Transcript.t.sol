// SPDX-License-Identifier: Apache
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {BN254} from "solidity-bn254/BN254.sol";
import {BN254Helpers} from "../src/libraries/verifier/BN254Helpers.sol";
import {Transcript, TranscriptLib} from "../src/libraries/verifier/Transcript.sol";
import {TestUtils} from "./utils/TestUtils.sol";
import {console2} from "forge-std/console2.sol";

/// @title Transcript Test Contract
/// @notice Test contract for verifying the functionality of the Fiat-Shamir transcript
/// @dev Tests the creation, message appending, and challenge generation of the Transcript struct
contract TranscriptTest is TestUtils {
    using TranscriptLib for Transcript;

    /// @notice Test the basic flow of transcript operations with a single input
    function testTranscriptBasic() public {
        uint256 TEST_DATA_BYTES = 1024;

        // Create a new transcript
        Transcript memory transcript = TranscriptLib.newTranscript();

        // Generate random test data
        bytes memory testData = vm.randomBytes(TEST_DATA_BYTES);
        transcript.appendMessage(testData);

        // Get a challenge from our implementation
        BN254.ScalarField challenge = transcript.getChallenge();

        // Get challenge from reference implementation
        bytes[] memory inputs = new bytes[](1);
        inputs[0] = testData;
        uint256[] memory expectedChallenges = runReferenceImpl(inputs);

        // Compare results
        assertEq(
            BN254.ScalarField.unwrap(challenge),
            expectedChallenges[0],
            "Challenge mismatch between Solidity and reference implementation"
        );
    }

    /// @notice Test the basic flow of transcript operations with multiple inputs
    function testTranscriptMultiple() public {
        uint256 TEST_DATA_BYTES = 1024;
        uint256 NUM_TEST_INPUTS = 5;

        // Create a new transcript
        Transcript memory transcript = TranscriptLib.newTranscript();

        // Generate multiple random test inputs
        bytes[] memory testInputs = new bytes[](NUM_TEST_INPUTS);
        for (uint256 i = 0; i < NUM_TEST_INPUTS; i++) {
            testInputs[i] = vm.randomBytes(TEST_DATA_BYTES);
        }

        // Get challenges from our implementation
        BN254.ScalarField[] memory challenges = new BN254.ScalarField[](NUM_TEST_INPUTS);
        for (uint256 i = 0; i < NUM_TEST_INPUTS; i++) {
            transcript.appendMessage(testInputs[i]);
            challenges[i] = transcript.getChallenge();
        }

        // Get challenges from reference implementation
        uint256[] memory expectedChallenges = runReferenceImpl(testInputs);

        // Compare results
        for (uint256 i = 0; i < NUM_TEST_INPUTS; i++) {
            assertEq(
                BN254.ScalarField.unwrap(challenges[i]),
                expectedChallenges[i],
                string(abi.encodePacked("Challenge mismatch at index ", vm.toString(i)))
            );
        }
    }

    /// @notice Test the methods for appending a set of scalars to the transcript
    function testTranscriptAppendScalars() public {
        uint256 NUM_SCALARS = 10;
        BN254.ScalarField[] memory scalars = new BN254.ScalarField[](NUM_SCALARS);
        for (uint256 i = 0; i < NUM_SCALARS; i++) {
            scalars[i] = BN254.ScalarField.wrap(randomFelt());
        }

        // Run the reference implementation
        bytes memory fullInput = "";
        for (uint256 i = 0; i < NUM_SCALARS; i++) {
            fullInput = abi.encodePacked(fullInput, BN254Helpers.scalarToLeBytes(scalars[i]));
        }
        bytes[] memory inputs = new bytes[](1);
        inputs[0] = fullInput;
        uint256[] memory expectedChallenges = runReferenceImpl(inputs);

        // Create a new transcript
        Transcript memory transcript = TranscriptLib.newTranscript();

        // Append the scalars
        transcript.appendScalars(scalars);
        BN254.ScalarField challenge = transcript.getChallenge();

        // Compare results
        assertEq(
            BN254.ScalarField.unwrap(challenge),
            expectedChallenges[0],
            "Challenge mismatch between Solidity and reference implementation"
        );
    }

    /// @notice Test the methods for appending a set of points to the transcript
    function testTranscriptAppendPoints() public {
        uint256 NUM_POINTS = 10;
        BN254.G1Point[] memory points = new BN254.G1Point[](NUM_POINTS);
        for (uint256 i = 0; i < NUM_POINTS; i++) {
            points[i] = randomG1Point();
        }

        // Run the reference implementation
        bytes memory fullInput = "";
        for (uint256 i = 0; i < NUM_POINTS; i++) {
            fullInput = abi.encodePacked(fullInput, BN254.g1Serialize(points[i]));
        }
        bytes[] memory inputs = new bytes[](1);
        inputs[0] = fullInput;
        uint256[] memory expectedChallenges = runReferenceImpl(inputs);

        // Create a new transcript
        Transcript memory transcript = TranscriptLib.newTranscript();

        // Append the points
        transcript.appendPoints(points);
        BN254.ScalarField challenge = transcript.getChallenge();

        // Compare results
        assertEq(
            BN254.ScalarField.unwrap(challenge),
            expectedChallenges[0],
            "Challenge mismatch between Solidity and reference implementation"
        );
    }

    // -----------
    // | Helpers |
    // -----------

    /// @dev Helper to run the reference implementation
    function runReferenceImpl(bytes[] memory inputs) internal returns (uint256[] memory) {
        // First compile the binary
        compileRustBinary("test/rust-reference-impls/transcript/Cargo.toml");

        // Prepare arguments for the Rust binary
        string[] memory args = new string[](inputs.length + 1);
        args[0] = "./test/rust-reference-impls/target/debug/transcript";

        // Convert each input to hex string and add as argument
        for (uint256 i = 0; i < inputs.length; i++) {
            args[i + 1] = string(abi.encodePacked("0x", bytesToHexString(inputs[i])));
        }

        // Run the reference implementation and parse space-separated array output
        return runBinaryGetArray(args, " ");
    }
}
