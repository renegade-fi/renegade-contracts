// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IVerifier } from "darkpoolv2-interfaces/IVerifier.sol";

import { BN254 } from "solidity-bn254/BN254.sol";
import { PlonkProof, VerificationKey, OpeningElements } from "renegade-lib/verifier/Types.sol";
import { VerifierCore } from "renegade-lib/verifier/VerifierCore.sol";

import { DepositProofBundle } from "darkpoolv2-types/ProofBundles.sol";
import { ExistingBalanceDepositValidityStatement, PublicInputsLib } from "darkpoolv2-lib/PublicInputs.sol";

/// @title Verifier
/// @author Renegade Eng
/// @notice Implementation of the IVerifier interface for the DarkpoolV2 contract
contract Verifier is IVerifier {
    using PublicInputsLib for ExistingBalanceDepositValidityStatement;

    /// @inheritdoc IVerifier
    function verifyExistingBalanceDepositValidity(DepositProofBundle calldata depositProofBundle)
        external
        view
        returns (bool)
    {
        VerificationKey memory vk = PublicInputsLib.dummyVkey();
        BN254.ScalarField[] memory publicInputs = depositProofBundle.statement.statementSerialize();
        return VerifierCore.verify(depositProofBundle.proof, publicInputs, vk);
    }

    /// @inheritdoc IVerifier
    function batchVerify(
        PlonkProof[] calldata proofs,
        BN254.ScalarField[][] calldata publicInputs,
        VerificationKey[] calldata vks,
        OpeningElements calldata extraOpeningElements
    )
        external
        view
        returns (bool)
    {
        return VerifierCore.batchVerify(proofs, publicInputs, vks, extraOpeningElements);
    }
}
