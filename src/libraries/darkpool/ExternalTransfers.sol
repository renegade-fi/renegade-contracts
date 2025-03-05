// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {
    ExternalTransfer,
    TransferType,
    TransferAuthorization,
    PublicRootKey,
    publicKeyToUints,
    DepositWitness,
    hashDepositWitness,
    DEPOSIT_WITNESS_TYPE_STRING
} from "../darkpool/Types.sol";
import { IPermit2 } from "permit2/interfaces/IPermit2.sol";
import { ISignatureTransfer } from "permit2/interfaces/ISignatureTransfer.sol";

// @title TransferExecutor
// @notice This library implements the logic for executing external transfers
// @notice External transfers are either deposits or withdrawals into/from the darkpool
library TransferExecutor {
    /// @notice Executes an external transfer (deposit or withdrawal) for the darkpool
    /// @param transfer The external transfer details including account, mint, amount and type
    /// @param oldPkRoot The public root key of the sender's Renegade wallet
    /// @param authorization The authorization data for the transfer (permit2 or withdrawal signature)
    /// @param permit2 The Permit2 contract instance for handling deposits
    function executeTransfer(
        ExternalTransfer calldata transfer,
        PublicRootKey calldata oldPkRoot,
        TransferAuthorization calldata authorization,
        IPermit2 permit2
    )
        internal
    {
        bool isDeposit = transfer.transferType == TransferType.Deposit;
        if (isDeposit) {
            executeDeposit(oldPkRoot, transfer, authorization, permit2);
        } else {
            executeWithdrawal(transfer);
        }
    }

    // --- Deposit --- //

    /// @notice Executes a deposit of shares into the darkpool
    /// @dev Deposits flow through the permit2 contract, which allows us to attach the public root
    /// @dev key to the deposit's witness. This provides a link between the on-chain wallet and the
    /// @dev Renegade wallet, ensuring that only one Renegade wallet may redeem the permit.
    /// @param transfer The transfer to execute
    /// @param authorization The authorization for the deposit
    /// @param permit2 The permit2 contract
    function executeDeposit(
        PublicRootKey calldata oldPkRoot,
        ExternalTransfer calldata transfer,
        TransferAuthorization calldata authorization,
        IPermit2 permit2
    )
        internal
    {
        // Build the permit
        ISignatureTransfer.TokenPermissions memory tokenPermissions =
            ISignatureTransfer.TokenPermissions({ token: transfer.mint, amount: transfer.amount });
        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: tokenPermissions,
            nonce: authorization.permit2Nonce,
            deadline: authorization.permit2Deadline
        });
        ISignatureTransfer.SignatureTransferDetails memory signatureTransferDetails =
            ISignatureTransfer.SignatureTransferDetails({ to: address(this), requestedAmount: transfer.amount });
        DepositWitness memory depositWitness = DepositWitness({ pkRoot: publicKeyToUints(oldPkRoot) });
        bytes32 depositWitnessHash = hashDepositWitness(depositWitness);

        address owner = transfer.account;
        permit2.permitWitnessTransferFrom(
            permit,
            signatureTransferDetails,
            owner,
            depositWitnessHash,
            DEPOSIT_WITNESS_TYPE_STRING,
            authorization.permit2Signature
        );
    }

    /// @notice Builds the deposit witness hash from the public root key
    /// @param oldPkRoot The public root key of the sender's Renegade wallet
    /// @return The deposit witness hash
    function buildDepositWitnessHash(PublicRootKey calldata oldPkRoot) internal pure returns (bytes32) {
        return keccak256(abi.encode(oldPkRoot));
    }

    // --- Withdrawal --- //

    /// @notice Executes a withdrawal of shares from the darkpool
    /// @param transfer The transfer to execute
    function executeWithdrawal(ExternalTransfer calldata transfer) internal {
        // TODO: Implement withdrawal logic
    }
}
