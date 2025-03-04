// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { BN254 } from "solidity-bn254/BN254.sol";
import { ExternalTransfer, PublicRootKey } from "./Types.sol";

// This file represents the public inputs (statements) for various proofs used by the darkpool

// -------------------
// | Statement Types |
// -------------------

/// @title ValidWalletCreateStatement the statement type for the `VALID WALLET CREATE` proof
struct ValidWalletCreateStatement {
    /// @dev The commitment to the wallet's private shares
    BN254.ScalarField privateShareCommitment;
    /// @dev The public wallet shares of the wallet
    BN254.ScalarField[] publicShares;
}

/// @title ValidWalletUpdateStatement the statement type for the `VALID WALLET UPDATE` proof
struct ValidWalletUpdateStatement {
    /// @dev The nullifier of the previous wallet
    BN254.ScalarField previousNullifier;
    /// @dev A commitment to the new wallet's private shares
    BN254.ScalarField newPrivateShareCommitment;
    /// @dev The new public shares of the wallet
    BN254.ScalarField[] newPublicShares;
    /// @dev The global Merkle root that the old wallet shares open into
    BN254.ScalarField merkleRoot;
    /// @dev The external transfer in the update, zeroed out if there is no transfer
    ExternalTransfer externalTransfer;
    /// @dev The old public root key of the keychain
    PublicRootKey oldPkRoot;
}

// ------------------------
// | Scalar Serialization |
// ------------------------

/// @title StatementSerializer Library for serializing statement types to scalar arrays
library StatementSerializer {
    using StatementSerializer for ValidWalletCreateStatement;
    using StatementSerializer for ValidWalletUpdateStatement;
    using StatementSerializer for ExternalTransfer;
    using StatementSerializer for PublicRootKey;

    // --- Valid Wallet Create --- //

    /// @notice Serializes a ValidWalletCreateStatement into an array of scalar field elements
    /// @param self The statement to serialize
    /// @return serialized The serialized statement as an array of scalar field elements
    function scalarSerialize(ValidWalletCreateStatement memory self)
        internal
        pure
        returns (BN254.ScalarField[] memory)
    {
        // Create array with size = 1 (for privateShareCommitment) + publicShares.length
        BN254.ScalarField[] memory serialized = new BN254.ScalarField[](1 + self.publicShares.length);

        // Add the wallet commitment
        serialized[0] = self.privateShareCommitment;

        // Add all public shares
        for (uint256 i = 0; i < self.publicShares.length; i++) {
            serialized[i + 1] = self.publicShares[i];
        }

        return serialized;
    }

    // --- Valid Wallet Update --- //

    /// @notice Serializes a ValidWalletUpdateStatement into an array of scalar field elements
    /// @param self The statement to serialize
    /// @return serialized The serialized statement as an array of scalar field elements
    function scalarSerialize(ValidWalletUpdateStatement memory self)
        internal
        pure
        returns (BN254.ScalarField[] memory)
    {
        BN254.ScalarField[] memory serialized = new BN254.ScalarField[](1 + 1 + self.newPublicShares.length);
        serialized[0] = self.previousNullifier;
        serialized[1] = self.newPrivateShareCommitment;

        // Copy the public shares
        uint256 n = self.newPublicShares.length;
        for (uint256 i = 0; i < n; i++) {
            serialized[i + 2] = self.newPublicShares[i];
        }

        serialized[n + 2] = self.merkleRoot;
        BN254.ScalarField[] memory externalTransferSerialized = self.externalTransfer.scalarSerialize();
        for (uint256 i = 0; i < externalTransferSerialized.length; i++) {
            serialized[n + 3 + i] = externalTransferSerialized[i];
        }

        BN254.ScalarField[] memory oldPkRootSerialized = self.oldPkRoot.scalarSerialize();
        for (uint256 i = 0; i < oldPkRootSerialized.length; i++) {
            serialized[n + 3 + externalTransferSerialized.length + i] = oldPkRootSerialized[i];
        }

        return serialized;
    }

    // --- Types --- //

    /// @notice Serializes an ExternalTransfer into an array of scalar field elements
    /// @param self The transfer to serialize
    /// @return serialized The serialized transfer as an array of scalar field elements
    function scalarSerialize(ExternalTransfer memory self) internal pure returns (BN254.ScalarField[] memory) {
        BN254.ScalarField[] memory serialized = new BN254.ScalarField[](4);

        serialized[0] = BN254.ScalarField.wrap(uint256(uint160(self.account)));
        serialized[1] = BN254.ScalarField.wrap(uint256(uint160(self.mint)));
        serialized[2] = BN254.ScalarField.wrap(self.amount);
        serialized[3] = BN254.ScalarField.wrap(self.timestamp);

        return serialized;
    }

    /// @notice Serializes a PublicRootKey into an array of scalar field elements
    /// @param self The key to serialize
    /// @return serialized The serialized key as an array of scalar field elements
    function scalarSerialize(PublicRootKey memory self) internal pure returns (BN254.ScalarField[] memory) {
        BN254.ScalarField[] memory serialized = new BN254.ScalarField[](4);

        serialized[0] = self.x[0];
        serialized[1] = self.x[1];
        serialized[2] = self.y[0];
        serialized[3] = self.y[1];

        return serialized;
    }
}

// Enable the library for the statement type
using StatementSerializer for ValidWalletCreateStatement;
