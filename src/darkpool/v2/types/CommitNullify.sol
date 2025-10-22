// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { BN254 } from "solidity-bn254/BN254.sol";
import { IHasher } from "renegade-lib/interfaces/IHasher.sol";

/// @title CommitmentNullifierLib
/// @author Renegade Eng
/// @notice Library for computing and operating on commitments and nullifiers
library CommitmentNullifierLib {
    /// @notice Compute the full commitment to a state element from a partial commitment
    /// @param partialCommitment The partial commitment to the state element
    /// @param remainingShares The remaining shares to hash into the commitment
    /// @param hasher The hasher to use for hashing
    /// @return The full commitment to the state element
    /// @dev We assume the commitment is computed as :
    ///     H(partialCommitment || share0 || share1 || ... || shareN)
    function computeFullCommitment(
        BN254.ScalarField partialCommitment,
        BN254.ScalarField[] memory remainingShares,
        IHasher hasher
    )
        internal
        view
        returns (BN254.ScalarField)
    {
        // Build inputs and hash
        uint256[] memory hashInputs = new uint256[](remainingShares.length + 1);
        hashInputs[0] = BN254.ScalarField.unwrap(partialCommitment);
        for (uint256 i = 1; i < remainingShares.length + 1; ++i) {
            hashInputs[i] = BN254.ScalarField.unwrap(remainingShares[i - 1]);
        }

        return BN254.ScalarField.wrap(hasher.spongeHash(hashInputs));
    }
}
