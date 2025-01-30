// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {BN254} from "solidity-bn254/BN254.sol";

// --- Hash & Transcript Constants --- //

/// @dev The size of the hash state in bytes
uint256 constant HASH_STATE_SIZE = 64;
/// @dev The maximum number of elements that can be appended to the transcript
uint256 constant MAX_TRANSCRIPT_ELEMENTS = 1024;

// --- Challenge Generation Constants --- //

/// @dev The number of bytes to use in the low bytes of the challenge
uint256 constant CHALLENGE_LOW_BYTES = 31;
/// @dev The number of bytes to use in the high bytes of the challenge
uint256 constant CHALLENGE_HIGH_BYTES = 17;

// --- Bit Manipulation Constants --- //

/// @dev Bit shift for the low bytes mask (31 bytes * 8)
uint256 constant LOW_BYTES_SHIFT = CHALLENGE_LOW_BYTES * 8;
/// @dev Bit shift for the high bytes mask (17 bytes * 8)
uint256 constant HIGH_BYTES_SHIFT = CHALLENGE_HIGH_BYTES * 8;
/// @dev Mask for the low bytes
uint256 constant LOW_BYTES_MASK = (1 << 248) - 1;
/// @dev Mask for the high bytes
uint256 constant HIGH_BYTES_MASK = (1 << 136) - 1;
/// @dev The shift value for the high bytes of the challenge: 2^(CHALLENGE_LOW_BYTES * 8)
BN254.ScalarField constant CHALLENGE_HIGH_SHIFT = BN254.ScalarField.wrap(2 ** (CHALLENGE_LOW_BYTES * 8));

// --- Memory Layout Constants --- //

/// @dev Offset for struct header in memory (32 bytes)
uint256 constant STRUCT_HEADER_OFFSET = 0x20;
/// @dev Offset for array length in memory (32 bytes)
uint256 constant ARRAY_LENGTH_OFFSET = 0x20;
/// @dev Offset for second 32-byte chunk in memory
uint256 constant SECOND_CHUNK_OFFSET = 0x20;

// --- Transcript Type --- //

/// @title The Fiat-Shamir transcript used by the verifier
/// @dev The underlying hash function is keccak256
struct Transcript {
    /// @dev The hash state of the transcript as a fixed-size byte array
    bytes hashState;
    /// @dev The concatenated bytes of all elements
    bytes elements;
}

// --- Implementation Library --- //

/// @title The Fiat-Shamir transcript used by the verifier
library TranscriptLib {
    /// @dev Creates a new transcript in memory
    function new_transcript() internal pure returns (Transcript memory t) {
        t.hashState = new bytes(HASH_STATE_SIZE);
        t.elements = new bytes(0);
        return t;
    }

    /// @dev Appends a message to the transcript
    /// @param self The transcript
    /// @param element The message to append
    function appendMessage(Transcript memory self, bytes memory element) internal pure {
        self.elements = abi.encodePacked(self.elements, element);
    }

    /// @dev Gets the current challenge from the transcript
    /// @param self The transcript
    /// @return Challenge The Fiat-Shamir challenge
    function getChallenge(Transcript memory self) internal pure returns (BN254.ScalarField) {
        // Concatenate state, transcript elements, and 0/1 bytes
        bytes memory input0 = abi.encodePacked(self.hashState, self.elements, uint8(0));
        bytes memory input1 = abi.encodePacked(self.hashState, self.elements, uint8(1));

        // Hash inputs and store in low/high bits of state
        bytes32 low = keccak256(input0);
        bytes32 high = keccak256(input1);

        // Variables to store the extracted bytes
        uint256 lowBytes;
        uint256 highBytes;

        // Copy the hash outputs into the state bytes array and extract challenge bytes
        assembly {
            // Store the low and high bytes in the hash state
            let hashStateBase := mload(add(self, STRUCT_HEADER_OFFSET))
            let statePtr := add(hashStateBase, ARRAY_LENGTH_OFFSET)
            mstore(statePtr, low) // Store low 32 bytes
            mstore(add(statePtr, SECOND_CHUNK_OFFSET), high) // Store high 32 bytes

            // Read challenge bytes directly from memory
            // Load first CHALLENGE_LOW_BYTES (31) bytes for low part
            lowBytes := and(mload(statePtr), LOW_BYTES_MASK)

            // Load next CHALLENGE_HIGH_BYTES (17) bytes for high part
            let highValue := mload(add(statePtr, CHALLENGE_LOW_BYTES))
            highBytes := and(highValue, HIGH_BYTES_MASK)
        }

        // Convert to scalar field elements and combine
        BN254.ScalarField lowPart = BN254.ScalarField.wrap(lowBytes);
        BN254.ScalarField highPart = BN254.ScalarField.wrap(highBytes);

        BN254.ScalarField shiftedHigh = BN254.mul(highPart, CHALLENGE_HIGH_SHIFT);
        return BN254.add(lowPart, shiftedHigh);
    }
}
