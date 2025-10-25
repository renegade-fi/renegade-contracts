// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { BN254 } from "solidity-bn254/BN254.sol";
import { PlonkProof, VerificationKey, OpeningElements } from "renegade-lib/verifier/Types.sol";

/// @title IVerifier
/// @author Renegade Eng
/// @notice Interface for verifying zero-knowledge proofs
interface IVerifier {
    /// @notice Verify a batch of proofs
    /// @param proofs The proofs to verify
    /// @param publicInputs The public inputs to the proofs
    /// @param vks The verification keys for the proofs
    /// @param extraOpeningElements The extra opening elements to use in the batch verification
    /// @return True if the proofs are valid, false otherwise
    /// @dev We use this method for settlements which don't have a _specific_ list of proofs to verify
    /// and instead prefer to pass proofs as a batch.
    function batchVerify(
        PlonkProof[] memory proofs,
        BN254.ScalarField[][] memory publicInputs,
        VerificationKey[] memory vks,
        OpeningElements memory extraOpeningElements
    )
        external
        view
        returns (bool);
}
