// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {Test} from "forge-std/Test.sol";
import {BN254} from "solidity-bn254/BN254.sol";
import {Transcript, TranscriptLib} from "../src/verifier/Transcript.sol";

/// @title Transcript Test Contract
/// @notice Test contract for verifying the functionality of the Fiat-Shamir transcript
/// @dev Tests the creation, message appending, and challenge generation of the Transcript struct
contract TranscriptTest is Test {
    using TranscriptLib for Transcript;

    /// @notice Test the basic flow of transcript operations
    /// @dev Verifies:
    ///      1. Transcript creation
    ///      2. Message appending
    ///      3. Challenge generation and non-zero value
    function testTranscriptBasic() public pure {
        // Create a new transcript
        Transcript memory transcript = TranscriptLib.new_transcript();

        // Append some test data
        bytes memory testData = hex"deadbeef";
        transcript.appendMessage(testData);

        // Get a challenge and verify it's not zero
        BN254.ScalarField challenge = transcript.getChallenge();
        require(BN254.ScalarField.unwrap(challenge) != 0, "Challenge should not be zero");
    }
}
