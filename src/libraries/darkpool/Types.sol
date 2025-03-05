// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

// This file contains the types used in the darkpool

import { BN254 } from "solidity-bn254/BN254.sol";

/// @dev The type hash for the DepositWitness struct
bytes32 constant DEPOSIT_WITNESS_TYPEHASH = keccak256("DepositWitness(uint256[4] pkRoot)");
/// @dev The type string for the DepositWitness struct
string constant DEPOSIT_WITNESS_TYPE_STRING =
    "DepositWitness witness)DepositWitness(uint256[4] pkRoot)TokenPermissions(address token,uint256 amount)";

// ---------------------
// | External Transfer |
// ---------------------

/// @notice An external transfer representing a deposit or withdrawal into/from the darkpool
struct ExternalTransfer {
    /// @dev The account address of the sender/recipient
    address account;
    /// @dev The mint (erc20 address) of the token
    address mint;
    /// @dev The amount of the transfer
    uint256 amount;
    /// @dev Indicates if it's a deposit or withdrawal
    TransferType transferType;
}

/// @notice The type of transfer
enum TransferType {
    Deposit,
    Withdrawal
}

/// @notice Auxiliary data authorizing a transfer
/// @dev This struct is effectively a union of the auth required for
/// @dev a deposit (permit2) and that required for a withdrawal (a simple signature)
/// @dev The external transfer implementation will use the appropriate authorization
/// @dev based on the transfer type
struct TransferAuthorization {
    /// @dev The nonce of the permit
    uint256 permit2Nonce;
    /// @dev The deadline of the permit
    uint256 permit2Deadline;
    /// @dev The signature of the permit
    bytes permit2Signature;
    /// @dev The signature of the external transfer
    bytes externalTransferSignature;
}

/// @notice The permit2 witness for a deposit
/// @dev The Permit2 witness type used in a deposit
struct DepositWitness {
    /// @dev The limb-serialization of the public key of the old wallet
    uint256[4] pkRoot;
}

/// @notice Computes the EIP-712 hash of a DepositWitness
/// @param witness The DepositWitness to hash
/// @return The EIP-712 hash of the DepositWitness
function hashDepositWitness(DepositWitness memory witness) pure returns (bytes32) {
    // Hash the struct data according to EIP-712
    bytes32 pkRootHash = keccak256(abi.encode(witness.pkRoot));
    return keccak256(abi.encode(DEPOSIT_WITNESS_TYPEHASH, pkRootHash));
}

// ------------
// | Keychain |
// ------------

/// @notice A public root key, essentially a `Scalar` representation of a k256 public key
/// @dev The `x` and `y` coordinates are elements of the base field of the k256 curve, which
/// @dev each require 254 bits to represent
struct PublicRootKey {
    /// @dev The x coordinate of the public key
    BN254.ScalarField[2] x;
    /// @dev The y coordinate of the public key
    BN254.ScalarField[2] y;
}

/// @notice Serialize the public root key into a list of uint256s
function publicKeyToUints(PublicRootKey memory pk) pure returns (uint256[4] memory scalars) {
    scalars[0] = BN254.ScalarField.unwrap(pk.x[0]);
    scalars[1] = BN254.ScalarField.unwrap(pk.x[1]);
    scalars[2] = BN254.ScalarField.unwrap(pk.y[0]);
    scalars[3] = BN254.ScalarField.unwrap(pk.y[1]);
}
