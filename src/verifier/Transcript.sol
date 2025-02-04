// SPDX-License-Identifier: Apache
pragma solidity ^0.8.0;

import {BN254} from "solidity-bn254/BN254.sol";
import {console2} from "forge-std/console2.sol";

// --- Hash & Transcript Constants --- //

/// @dev The size of the hash state in bytes
uint256 constant HASH_STATE_SIZE = 64;

// --- Bit Manipulation Constants --- //

/// @dev The number of bytes to use in the low bytes of the challenge
uint256 constant CHALLENGE_LOW_BYTES = 31;

/// @dev Mask for the low bytes
uint256 constant LOW_BYTES_MASK = ((1 << 248) - 1) << 8; // Selects the low 31 bytes
/// @dev Mask for the high bytes
uint256 constant HIGH_BYTES_MASK = ((1 << 136) - 1) << 120; // Selects the low 17 bytes
/// @dev The shift value for the high bytes of the challenge: 2^(CHALLENGE_LOW_BYTES * 8)
uint256 constant CHALLENGE_HIGH_SHIFT = 2 ** (CHALLENGE_LOW_BYTES * 8);

// --- Transcript Type --- //

/// @title The Fiat-Shamir transcript used by the verifier
/// @dev The underlying hash function is keccak256
struct Transcript {
    /// @dev The low 32 bytes of the hash state
    uint256 hashStateLow;
    /// @dev The high 32 bytes of the hash state
    uint256 hashStateHigh;
    /// @dev The concatenated bytes of all elements
    bytes elements;
}

// --- Implementation Library --- //

/// @title The Fiat-Shamir transcript used by the verifier
library TranscriptLib {
    /// @dev Creates a new transcript in memory
    function new_transcript() internal pure returns (Transcript memory t) {
        t.hashStateLow = 0;
        t.hashStateHigh = 0;
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
        bytes memory input0 = abi.encodePacked(self.hashStateLow, self.hashStateHigh, self.elements, uint8(0));
        bytes memory input1 = abi.encodePacked(self.hashStateLow, self.hashStateHigh, self.elements, uint8(1));

        // Hash inputs and update the hash state
        bytes32 low = keccak256(input0);
        bytes32 high = keccak256(input1);
        self.hashStateLow = uint256(low);
        self.hashStateHigh = uint256(high);

        // Extract challenge bytes, we wish to interpret keccak output in little-endian order,
        // so we need to reverse the bytes when converting to the scalar type
        bytes32 lowBytes;
        bytes32 highBytes;
        assembly {
            // Get the data pointer for the bytes arrays
            let lowBytesStatePtr := self
            let highBytesStatePtr := add(lowBytesStatePtr, CHALLENGE_LOW_BYTES)

            // Mask and store the values
            lowBytes := and(mload(lowBytesStatePtr), LOW_BYTES_MASK)
            highBytes := and(mload(highBytesStatePtr), HIGH_BYTES_MASK)
        }

        // Convert from bytes
        BN254.ScalarField lowScalar = scalarFromLeBytes(lowBytes);
        BN254.ScalarField highScalar = scalarFromLeBytes(highBytes);

        BN254.ScalarField shiftedHigh = BN254.mul(highScalar, BN254.ScalarField.wrap(CHALLENGE_HIGH_SHIFT));
        return BN254.add(lowScalar, shiftedHigh);
    }

    /// @dev Converts a little-endian bytes array to a uint256
    function scalarFromLeBytes(bytes32 buf) internal pure returns (BN254.ScalarField) {
        // Reverse the byte order
        bytes32 reversedBuf;
        assembly {
            for { let i := 0 } lt(i, 32) { i := add(i, 1) } {
                // Copy the next byte into the reversed buffer
                let shift := mul(sub(31, i), 8)
                reversedBuf := or(shl(shift, and(buf, 0xff)), reversedBuf)
                buf := shr(8, buf)
            }
        }

        // Convert to uint256, reduce via the modulus, and return
        uint256 reduced = uint256(reversedBuf) % BN254.R_MOD;
        return BN254.ScalarField.wrap(reduced);
    }
}
