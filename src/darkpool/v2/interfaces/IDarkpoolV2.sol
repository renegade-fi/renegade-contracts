// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { BN254 } from "solidity-bn254/BN254.sol";
import { ObligationBundle } from "darkpoolv2-types/settlement/ObligationBundle.sol";
import { SettlementBundle } from "darkpoolv2-types/settlement/SettlementBundle.sol";
import {
    DepositProofBundle,
    NewBalanceDepositProofBundle,
    WithdrawalProofBundle,
    FeePaymentProofBundle
} from "darkpoolv2-types/ProofBundles.sol";
import { DepositAuth } from "darkpoolv2-types/transfers/Deposit.sol";
import { WithdrawalAuth } from "darkpoolv2-types/transfers/Withdrawal.sol";
import { EncryptionKey } from "darkpoolv1-types/Ciphertext.sol";
import { IHasher } from "renegade-lib/interfaces/IHasher.sol";
import { IVerifier } from "darkpoolv2-interfaces/IVerifier.sol";
import { IPermit2 } from "permit2-lib/interfaces/IPermit2.sol";
import { IWETH9 } from "renegade-lib/interfaces/IWETH9.sol";

/// @title IDarkpoolV2
/// @author Renegade Eng
/// @notice Interface for the DarkpoolV2 contract
interface IDarkpoolV2 {
    // --- Events --- //

    /// @notice Emitted when an internal Merkle node is updated
    /// @param depth The depth at which the node is updated
    /// @param index The index of the node in the Merkle tree
    /// @param new_value The new value of the node
    /// forge-lint: disable-next-line(mixed-case-variable)
    event MerkleOpeningNode(uint8 indexed depth, uint128 indexed index, uint256 new_value);
    /// @notice Emitted when a Merkle leaf is inserted into the tree
    /// @param index The leaf index
    /// @param value The value of the leaf
    /// forge-lint: disable-next-line(mixed-case-variable)
    event MerkleInsertion(uint128 indexed index, uint256 indexed value);
    /// @notice Emitted when a nullifier is spent
    /// @param nullifier The nullifier that was spent
    event NullifierSpent(BN254.ScalarField nullifier);
    /// @notice Emitted when a new recovery ID is registered on-chain
    /// @param recoveryId The recovery ID that was registered
    event RecoveryIdRegistered(BN254.ScalarField indexed recoveryId);

    /// @notice Initialize the darkpool contract
    /// @param initialOwner The initial owner of the contract
    /// @param protocolFeeRate_ The protocol fee rate
    /// @param protocolFeeRecipient_ The address to receive protocol fees
    /// @param protocolFeeKey_ The encryption key for protocol fees
    /// @param weth_ The WETH9 contract instance
    /// @param hasher_ The hasher for the darkpool
    /// @param verifier_ The verifier for the darkpool
    /// @param permit2_ The Permit2 contract instance
    /// @param transferExecutor_ The TransferExecutor contract address
    function initialize(
        address initialOwner,
        uint256 protocolFeeRate_,
        address protocolFeeRecipient_,
        EncryptionKey memory protocolFeeKey_,
        IWETH9 weth_,
        IHasher hasher_,
        IVerifier verifier_,
        IPermit2 permit2_,
        address transferExecutor_
    )
        external;

    /// @notice Check if a nullifier has been spent
    /// @param nullifier The nullifier to check
    /// @return True if the nullifier has been spent, false otherwise
    function nullifierSpent(BN254.ScalarField nullifier) external view returns (bool);

    /// @notice Check if a root is in the Merkle mountain range history
    /// @param root The root to check
    /// @return True if the root is in the history, false otherwise
    function rootInHistory(BN254.ScalarField root) external view returns (bool);

    /// @notice Get the amount remaining for an open public intent
    /// @param intentHash The hash of the intent
    /// @return The amount remaining for the intent
    function openPublicIntents(bytes32 intentHash) external view returns (uint256);

    /// @notice Deposit into an existing balance in the darkpool
    /// @param auth The authorization for the deposit
    /// @param depositProofBundle The proof bundle for the deposit
    function deposit(DepositAuth memory auth, DepositProofBundle calldata depositProofBundle) external;

    /// @notice Deposit a new balance into the darkpool
    /// @param auth The authorization for the deposit
    /// @param newBalanceProofBundle The proof bundle for the new balance deposit
    function depositNewBalance(
        DepositAuth memory auth,
        NewBalanceDepositProofBundle calldata newBalanceProofBundle
    )
        external;

    /// @notice Withdraw from a balance in the darkpool
    /// @param auth The authorization for the withdrawal
    /// @param withdrawalProofBundle The proof bundle for the withdrawal
    function withdraw(WithdrawalAuth memory auth, WithdrawalProofBundle calldata withdrawalProofBundle) external;

    /// @notice Pay fees on a balance
    /// @param feePaymentProofBundle The proof bundle for the fee payment
    function payFees(FeePaymentProofBundle calldata feePaymentProofBundle) external;

    /// @notice Settle a trade
    /// @param obligationBundle The obligation bundle for the trade. This type encodes the result of the trade.
    /// In the case of a public trade, this value encodes the settlement obligations for each party in the trade.
    /// If the trade is private, this bundle holds a proof attesting to the validity of the settlement.
    /// @param party0SettlementBundle The settlement bundle for the first party. This type validates the first user's
    /// state elements which are input to the trade.
    /// @param party1SettlementBundle The settlement bundle for the second party. This type validates the second user's
    /// state elements which are input to the trade.
    function settleMatch(
        ObligationBundle calldata obligationBundle,
        SettlementBundle calldata party0SettlementBundle,
        SettlementBundle calldata party1SettlementBundle
    )
        external;
}
