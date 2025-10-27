// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IVerifier } from "darkpoolv2-interfaces/IVerifier.sol";

import { BN254 } from "solidity-bn254/BN254.sol";
import { PlonkProof, VerificationKey, OpeningElements } from "renegade-lib/verifier/Types.sol";
import {
    DepositProofBundle, NewBalanceDepositProofBundle, WithdrawalProofBundle
} from "darkpoolv2-types/ProofBundles.sol";

/// @title Test Verifier Implementation
/// @notice This is a test implementation of the `IVerifier` interface that always returns true
/// @notice even if verification fails
contract TestVerifierV2 is IVerifier {
    /// @inheritdoc IVerifier
    function verifyExistingBalanceDepositValidity(DepositProofBundle calldata) external pure returns (bool) {
        return true;
    }

    /// @inheritdoc IVerifier
    function verifyNewBalanceDepositValidity(NewBalanceDepositProofBundle calldata) external pure returns (bool) {
        return true;
    }

    /// @inheritdoc IVerifier
    function verifyWithdrawalValidity(WithdrawalProofBundle calldata) external pure returns (bool) {
        return true;
    }

    /// @inheritdoc IVerifier
    function batchVerify(
        PlonkProof[] memory,
        BN254.ScalarField[][] memory,
        VerificationKey[] memory,
        OpeningElements memory
    )
        external
        pure
        returns (bool)
    {
        return true;
    }
}
