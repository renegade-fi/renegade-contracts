// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { PlonkProof, VerificationKey } from "../../src/libraries/verifier/Types.sol";
import { ValidWalletCreateStatement, StatementSerializer } from "../../src/libraries/darkpool/PublicInputs.sol";
import { VerificationKeys } from "../../src/libraries/darkpool/VerificationKeys.sol";
import { IVerifier } from "../../src/libraries/verifier/IVerifier.sol";
import { VerifierCore } from "../../src/libraries/verifier/VerifierCore.sol";
import { BN254 } from "solidity-bn254/BN254.sol";

using StatementSerializer for ValidWalletCreateStatement;

/// @title Test Verifier Implementation
/// @notice This is a test implementation of the `IVerifier` interface that always returns true
/// @notice even if verification fails
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
        VerificationKey memory vk = abi.decode(VerificationKeys.VALID_WALLET_CREATE_VKEY, (VerificationKey));
        BN254.ScalarField[] memory publicInputs = statement.scalarSerialize();
        VerifierCore.verify(proof, publicInputs, vk);
        return true;
    }
}
