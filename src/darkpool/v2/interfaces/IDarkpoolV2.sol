// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { BN254 } from "solidity-bn254/BN254.sol";
import { ObligationBundle } from "darkpoolv2-types/settlement/ObligationBundle.sol";
import { SettlementBundle } from "darkpoolv2-types/settlement/SettlementBundle.sol";
import { DepositProofBundle } from "darkpoolv2-types/ProofBundles.sol";
import { EncryptionKey } from "darkpoolv1-types/Ciphertext.sol";
import { IHasher } from "renegade-lib/interfaces/IHasher.sol";
import { IVerifier } from "darkpoolv2-interfaces/IVerifier.sol";
import { IPermit2 } from "permit2-lib/interfaces/IPermit2.sol";
import { IWETH9 } from "renegade-lib/interfaces/IWETH9.sol";

/// @title IDarkpoolV2
/// @author Renegade Eng
/// @notice Interface for the DarkpoolV2 contract
interface IDarkpoolV2 {
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
    /// @param depositProofBundle The proof bundle for the deposit
    function deposit(DepositProofBundle calldata depositProofBundle) external;

    /// @notice Deposit a new balance into the darkpool
    /// @param token The token to deposit
    /// @param amount The amount to deposit
    /// @param from The address from which to deposit
    function depositNewBalance(address token, uint256 amount, address from) external;

    /// @notice Withdraw from a balance in the darkpool
    /// @param token The token to withdraw
    /// @param amount The amount to withdraw
    /// @param to The address to which to withdraw
    function withdraw(address token, uint256 amount, address to) external;

    /// @notice Pay fees on a balance
    /// @param token The token to pay fees on
    /// @param amount The amount to pay fees on
    /// @param from The address from which to pay fees
    function payFees(address token, uint256 amount, address from) external;

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
