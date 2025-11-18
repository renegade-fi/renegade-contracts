// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { BN254 } from "solidity-bn254/BN254.sol";

// This file contains types for the ciphertext in the darkpool

// --------------
// | Ciphertext |
// --------------

/// @title ElGamalCiphertext
/// @notice A ciphertext of an ElGamal hybrid encryption
/// @dev The ciphertext consists of an asymmetric ephemeral key -- a random point on an elliptic curve (see below) --
/// @dev and a series of field elements in the base field of the curve.
/// @dev The encryption of the plaintext multiplies the public key with a random scalar, generating the ephemeral key.
/// @dev The ephemeral key's x and y coordinates seed a cipher which is used to encrypt the plaintext in a symmetric
/// stream.
/// @dev The ciphertext thus consists of:
///     - the random scalar multiplied with the curve basepoint, so that the decryption may recover the ephemeral key
///     - the stream-encrypted plaintext
/// @dev For our system, we encrypt over the Baby JubJub curve, which has a base field isomorphic to the scalar
/// @dev field of the BN254 elliptic curve, over which we construct our proofs. This gives a particularly efficient
/// @dev cipher, using proof-system-native arithmetic.
struct ElGamalCiphertext {
    /// @dev The ephemeral key
    BabyJubJubPoint ephemeralKey;
    /// @dev The ciphertext
    BN254.ScalarField[] ciphertext;
}

/// @title BabyJubJubPoint
/// @notice A point on the Baby JubJub curve
struct BabyJubJubPoint {
    /// @dev The x coordinate of the point
    BN254.ScalarField x;
    /// @dev The y coordinate of the point
    BN254.ScalarField y;
}

/// @title EncryptionKey
/// @notice A public key for the above ElGamal hybrid cryptosystem
struct EncryptionKey {
    /// @dev The underlying point on the Baby JubJub curve
    BabyJubJubPoint point;
}
