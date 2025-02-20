// SPDX-License-Identifier: Apache
pragma solidity ^0.8.0;

import { BN254 } from "solidity-bn254/BN254.sol";
import { Utils } from "solidity-bn254/Utils.sol";
import { console2 } from "forge-std/console2.sol";
import { NUM_WIRE_TYPES, NUM_SELECTORS } from "./Types.sol";

// --- Hash & Transcript Constants --- //

/// @dev The size of the hash state in bytes
uint256 constant HASH_STATE_SIZE = 64;
/// @dev The number of bytes in a scalar serialized for the transcript
uint256 constant SCALAR_BYTES = 32;

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

    /// @dev Append a u64 value to the transcript
    /// @param self The transcript
    /// @param element The u64 value to append
    function appendU64(Transcript memory self, uint64 element) internal pure {
        bytes memory leBytes = u64ToLeBytes(element);
        appendMessage(self, leBytes);
    }

    /// @dev Appends a scalar value to the transcript
    /// @param self The transcript
    /// @param element The scalar to append
    function appendScalar(Transcript memory self, BN254.ScalarField element) internal pure {
        // Convert scalar to little-endian bytes
        bytes32 leBytes = scalarToLeBytes(element);
        appendMessage(self, abi.encodePacked(leBytes));
    }

    /// @dev Append a list of scalars to the transcript
    /// @param self The transcript
    /// @param dataPtr Pointer to the start of scalar data in memory
    /// @param len Length of the array
    function appendScalarsHelper(Transcript memory self, uint256 dataPtr, uint256 len) internal pure {
        bytes memory scalarsSerialized = new bytes(len * SCALAR_BYTES);
        for (uint256 i = 0; i < len; i++) {
            // Load the scalar from memory
            bytes32 scalarBytes;
            assembly {
                let ptr := add(dataPtr, mul(i, SCALAR_BYTES))
                scalarBytes := mload(ptr)
            }

            // Convert to little-endian bytes and store
            scalarBytes = scalarToLeBytes(BN254.ScalarField.wrap(uint256(scalarBytes)));
            assembly {
                let destPtr := add(scalarsSerialized, 32)
                let currDestPtr := add(destPtr, mul(i, SCALAR_BYTES))
                mstore(currDestPtr, scalarBytes)
            }
        }

        appendMessage(self, scalarsSerialized);
    }

    /// @dev Append a list of scalars to the transcript (dynamic array version)
    /// @param self The transcript
    /// @param elements The scalars to append
    function appendScalars(Transcript memory self, BN254.ScalarField[] memory elements) internal pure {
        uint256 dataPtr;
        uint256 len;
        assembly {
            len := mload(elements)
            dataPtr := add(elements, 0x20) // skip length word
        }
        appendScalarsHelper(self, dataPtr, len);
    }

    /// @dev Append a fixed-size list of scalars to the transcript
    /// @param self The transcript
    /// @param elements The scalars to append
    function appendScalars(Transcript memory self, BN254.ScalarField[NUM_WIRE_TYPES] memory elements) internal pure {
        uint256 dataPtr;
        assembly {
            dataPtr := elements
        }
        appendScalarsHelper(self, dataPtr, NUM_WIRE_TYPES);
    }

    /// @dev Append a fixed-size list of scalars to the transcript
    /// @param self The transcript
    /// @param elements The scalars to append
    function appendScalars(
        Transcript memory self,
        BN254.ScalarField[NUM_WIRE_TYPES - 1] memory elements
    )
        internal
        pure
    {
        uint256 dataPtr;
        assembly {
            dataPtr := elements
        }
        appendScalarsHelper(self, dataPtr, NUM_WIRE_TYPES - 1);
    }

    /// @dev Append a point to the transcript
    /// @param self The transcript
    /// @param point The point to append
    function appendPoint(Transcript memory self, BN254.G1Point memory point) internal pure {
        appendMessage(self, BN254.g1Serialize(point));
    }

    /// @dev Append a list of points to the transcript
    /// @param self The transcript
    /// @param points The points to append
    function appendPoints(Transcript memory self, BN254.G1Point[] memory points) internal pure {
        // Handle both dynamic and fixed-size arrays using assembly
        uint256 length;
        assembly {
            length := mload(points)
        }
        for (uint256 i = 0; i < length; i++) {
            appendPoint(self, points[i]);
        }
    }

    /// @dev Append a fixed-size list of points to the transcript
    /// @param self The transcript
    /// @param points The points to append
    function appendPoints(Transcript memory self, BN254.G1Point[NUM_WIRE_TYPES] memory points) internal pure {
        for (uint256 i = 0; i < NUM_WIRE_TYPES; i++) {
            appendPoint(self, points[i]);
        }
    }

    /// @dev Append a fixed-size list of points to the transcript
    /// @param self The transcript
    /// @param points The points to append
    function appendPoints(Transcript memory self, BN254.G1Point[NUM_SELECTORS] memory points) internal pure {
        for (uint256 i = 0; i < NUM_SELECTORS; i++) {
            appendPoint(self, points[i]);
        }
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
        uint256 scalarBytes = Utils.reverseEndianness(uint256(buf));
        return BN254.ScalarField.wrap(scalarBytes % BN254.R_MOD);
    }

    /// @dev Converts a scalar value to little-endian bytes
    function scalarToLeBytes(BN254.ScalarField scalar) internal returns (bytes32) {
        uint256 scalarBytes = Utils.reverseEndianness(BN254.ScalarField.unwrap(scalar));
        return bytes32(scalarBytes);
    }

    /// @dev Converts a u64 value to little-endian bytes
    function u64ToLeBytes(uint64 value) internal pure returns (bytes memory) {
        bytes memory leBytes = new bytes(8);
        assembly {
            // Get the pointer to the bytes array data (skip the length prefix)
            let dataPtr := add(leBytes, 0x20)

            for { let i := 0 } lt(i, 8) { i := add(i, 1) } {
                // Get the next byte from the value and store it
                mstore8(add(dataPtr, i), and(value, 0xff))
                // Shift the value right by 8 bits
                value := shr(8, value)
            }
        }
        return leBytes;
    }
}
