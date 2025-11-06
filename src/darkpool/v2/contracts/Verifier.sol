// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { IVerifier } from "darkpoolv2-interfaces/IVerifier.sol";
import { IVkeys } from "darkpoolv2-interfaces/IVkeys.sol";

import { BN254 } from "solidity-bn254/BN254.sol";
import { PlonkProof, VerificationKey, OpeningElements } from "renegade-lib/verifier/Types.sol";
import { VerifierCore } from "renegade-lib/verifier/VerifierCore.sol";

import {
    DepositProofBundle,
    NewBalanceDepositProofBundle,
    WithdrawalProofBundle,
    FeePaymentProofBundle
} from "darkpoolv2-types/ProofBundles.sol";
import {
    ValidDepositStatement,
    ValidBalanceCreateStatement,
    WithdrawalValidityStatement,
    FeePaymentValidityStatement,
    PublicInputsLib
} from "darkpoolv2-lib/PublicInputs.sol";

/// @title Verifier
/// @author Renegade Eng
/// @notice Implementation of the IVerifier interface for the DarkpoolV2 contract
contract Verifier is IVerifier {
    using PublicInputsLib for ValidDepositStatement;
    using PublicInputsLib for ValidBalanceCreateStatement;
    using PublicInputsLib for WithdrawalValidityStatement;
    using PublicInputsLib for FeePaymentValidityStatement;

    /// @notice The verification keys contract
    IVkeys public immutable VKEYS;

    /// @notice Constructor that sets the verification keys contract
    /// @param _vkeys The verification keys contract address
    constructor(IVkeys _vkeys) {
        VKEYS = _vkeys;
    }

    /// @inheritdoc IVerifier
    function verifyExistingBalanceDepositValidity(DepositProofBundle calldata depositProofBundle)
        external
        view
        returns (bool)
    {
        VerificationKey memory vk = VKEYS.depositKeys();
        BN254.ScalarField[] memory publicInputs = depositProofBundle.statement.statementSerialize();
        return VerifierCore.verify(depositProofBundle.proof, publicInputs, vk);
    }

    /// @inheritdoc IVerifier
    function verifyNewBalanceDepositValidity(NewBalanceDepositProofBundle calldata newBalanceProofBundle)
        external
        view
        returns (bool)
    {
        VerificationKey memory vk = VKEYS.balanceCreateKeys();
        BN254.ScalarField[] memory publicInputs = newBalanceProofBundle.statement.statementSerialize();
        return VerifierCore.verify(newBalanceProofBundle.proof, publicInputs, vk);
    }

    /// @inheritdoc IVerifier
    function verifyWithdrawalValidity(WithdrawalProofBundle calldata withdrawalProofBundle)
        external
        view
        returns (bool)
    {
        VerificationKey memory vk = VKEYS.withdrawalKeys();
        BN254.ScalarField[] memory publicInputs = withdrawalProofBundle.statement.statementSerialize();
        return VerifierCore.verify(withdrawalProofBundle.proof, publicInputs, vk);
    }

    /// @inheritdoc IVerifier
    function verifyFeePaymentValidity(FeePaymentProofBundle calldata feePaymentProofBundle)
        external
        view
        returns (bool)
    {
        VerificationKey memory vk = VKEYS.noteRedemptionKeys();
        BN254.ScalarField[] memory publicInputs = feePaymentProofBundle.statement.statementSerialize();
        return VerifierCore.verify(feePaymentProofBundle.proof, publicInputs, vk);
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
