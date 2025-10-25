// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { BN254 } from "solidity-bn254/BN254.sol";
import { PlonkProof, VerificationKey } from "renegade-lib/verifier/Types.sol";
import { SimpleTransfer } from "darkpoolv2-types/transfers/SimpleTransfer.sol";
import { SettlementTransfers, SettlementTransfersLib } from "darkpoolv2-types/transfers/TransfersList.sol";
import { VerificationList, VerificationListLib } from "darkpoolv2-types/VerificationList.sol";

/// @title Settlement Context
/// @author Renegade Eng
/// @notice A context for a settlement
struct SettlementContext {
    /// @dev The transfers to settle
    SettlementTransfers transfers;
    /// @dev The verifications to perform on the settlement
    VerificationList verifications;
}

/// @title Settlement Context Library
/// @author Renegade Eng
/// @notice A library for managing settlement contexts
library SettlementContextLib {
    using SettlementTransfersLib for SettlementTransfers;
    using VerificationListLib for VerificationList;

    /// @notice Create a new settlement context
    /// @param transferCapacity The capacity of the transfers list
    /// @param verificationCapacity The capacity of the verifications list
    /// @return The new settlement context
    function newContext(
        uint256 transferCapacity,
        uint256 verificationCapacity
    )
        internal
        pure
        returns (SettlementContext memory)
    {
        return SettlementContext({
            transfers: SettlementTransfersLib.newList(transferCapacity),
            verifications: VerificationListLib.newList(verificationCapacity)
        });
    }

    // --- Getters --- //

    /// @notice Get the length of the deposits list
    /// @param context The context to get the length of
    /// @return The length of the transfers list
    function numDeposits(SettlementContext memory context) internal pure returns (uint256) {
        return context.transfers.numDeposits();
    }

    /// @notice Get the length of the withdrawals list
    /// @param context The context to get the length of
    /// @return The length of the withdrawals list
    function numWithdrawals(SettlementContext memory context) internal pure returns (uint256) {
        return context.transfers.numWithdrawals();
    }

    /// @notice Get the length of the verifications list
    /// @param context The context to get the length of
    /// @return The length of the verifications list
    function numProofs(SettlementContext memory context) internal pure returns (uint256) {
        return context.verifications.length();
    }

    // --- Setters --- //

    /// @notice Push a deposit to the transfers list
    /// @param context The context to push to
    /// @param deposit The deposit to push
    function pushDeposit(SettlementContext memory context, SimpleTransfer memory deposit) internal pure {
        context.transfers.pushDeposit(deposit);
    }

    /// @notice Push a withdrawal to the transfers list
    /// @param context The context to push to
    /// @param withdrawal The withdrawal to push
    function pushWithdrawal(SettlementContext memory context, SimpleTransfer memory withdrawal) internal pure {
        context.transfers.pushWithdrawal(withdrawal);
    }

    /// @notice Push a proof to the verifications list
    /// @param context The context to push to
    /// @param publicInputs The public inputs to the proof
    /// @param proof The proof to push
    /// @param vk The verification key to use
    function pushProof(
        SettlementContext memory context,
        BN254.ScalarField[] memory publicInputs,
        PlonkProof memory proof,
        VerificationKey memory vk
    )
        internal
        pure
    {
        context.verifications.push(publicInputs, proof, vk);
    }
}
