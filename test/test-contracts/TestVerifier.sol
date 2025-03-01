// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { PlonkProof } from "../../src/libraries/verifier/Types.sol";
import { IVerifier } from "../../src/libraries/verifier/IVerifier.sol";
import { ValidWalletCreateStatement } from "../../src/libraries/darkpool/PublicInputs.sol";

/// @title Test Verifier Implementation
/// @notice This is a test implementation of the `IVerifier` interface that always returns true
contract TestVerifier is IVerifier {
    /// @notice Verify a proof of `VALID WALLET CREATE`
    /// @param statement The public inputs to the proof
    /// @param proof The proof to verify
    /// @return True always, regardless of the proof
    function verifyValidWalletCreate(
        ValidWalletCreateStatement memory statement,
        PlonkProof memory proof
    )
        external
        view
        returns (bool)
    {
        // Always return true for testing purposes
        return true;
    }
}
