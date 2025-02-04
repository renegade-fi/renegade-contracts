// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {BN254} from "solidity-bn254/BN254.sol";
import {Transcript, TranscriptLib} from "../src/verifier/Transcript.sol";
import {TestUtils} from "./utils/TestUtils.sol";
import {console2} from "forge-std/console2.sol";

/// @title Transcript Test Contract
/// @notice Test contract for verifying the functionality of the Fiat-Shamir transcript
/// @dev Tests the creation, message appending, and challenge generation of the Transcript struct
contract TranscriptTest is TestUtils {
    using TranscriptLib for Transcript;

    /// @dev Number of random bytes to generate for test data
    uint256 constant TEST_DATA_BYTES = 1024;

    /// @notice Test the basic flow of transcript operations
    function testTranscriptBasic() public {
        // Create a new transcript
        Transcript memory transcript = TranscriptLib.new_transcript();

        // Generate random test data
        bytes memory testData = vm.randomBytes(TEST_DATA_BYTES);
        transcript.appendMessage(testData);

        // Get a challenge from our implementation
        BN254.ScalarField challenge = transcript.getChallenge();
        uint256 expectedChallenge = runReferenceImpl(testData);

        // Compare results
        assertEq(
            BN254.ScalarField.unwrap(challenge),
            expectedChallenge,
            "Challenge mismatch between Solidity and reference implementation"
        );
    }

    /// @dev Helper to run the reference implementation
    function runReferenceImpl(bytes memory data) internal returns (uint256) {
        // First compile the binary
        compileRustBinary("test/rust-reference-impls/transcript/Cargo.toml");

        // Convert input bytes to hex string without 0x prefix
        string memory hexData = bytesToHexString(data);

        // Prepare arguments for the Rust binary
        string[] memory args = new string[](2);
        args[0] = "./test/rust-reference-impls/target/debug/transcript";
        args[1] = string(abi.encodePacked("0x", hexData));

        // Run the reference implementation and parse result
        return vm.parseUint(runBinaryGetResponse(args));
    }
}
