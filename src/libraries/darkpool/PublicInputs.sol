// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { BN254 } from "solidity-bn254/BN254.sol";

// This file represents the public inputs (statements) for various proofs used by the darkpool

/// @dev The number of public shares in a wallet
uint256 constant N_WALLET_SHARES = 70;

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

// ------------------------
// | Scalar Serialization |
// ------------------------

/// @title StatementSerializer Library for serializing statement types to scalar arrays
library StatementSerializer {
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

    /// @notice Deserializes an array of scalar field elements into a ValidWalletCreateStatement
    /// @param serialized The serialized statement as an array of scalar field elements
    /// @return statement The deserialized ValidWalletCreateStatement
    function scalarDeserialize(BN254.ScalarField[] memory serialized)
        internal
        pure
        returns (ValidWalletCreateStatement memory statement)
    {
        require(serialized.length >= 1, "Invalid serialized statement length");

        // Extract the private share commitment
        statement.privateShareCommitment = serialized[0];

        // Extract the public shares
        statement.publicShares = new BN254.ScalarField[](serialized.length - 1);
        for (uint256 i = 0; i < serialized.length - 1; i++) {
            statement.publicShares[i] = serialized[i + 1];
        }

        return statement;
    }
}

// Enable the library for the statement type
using StatementSerializer for ValidWalletCreateStatement;
