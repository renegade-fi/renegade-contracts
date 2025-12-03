// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { BN254 } from "solidity-bn254/BN254.sol";
import { ObligationBundle } from "darkpoolv2-types/settlement/ObligationBundle.sol";
import { SettlementBundle } from "darkpoolv2-types/settlement/SettlementBundle.sol";
import {
    DepositProofBundle,
    NewBalanceDepositProofBundle,
    OrderCancellationProofBundle,
    WithdrawalProofBundle,
    PublicProtocolFeePaymentProofBundle,
    PublicRelayerFeePaymentProofBundle,
    PrivateProtocolFeePaymentProofBundle,
    PrivateRelayerFeePaymentProofBundle
} from "darkpoolv2-types/ProofBundles.sol";
import { BoundedMatchResultBundle } from "darkpoolv2-types/settlement/BoundedMatchResultBundle.sol";
import { DepositAuth } from "darkpoolv2-types/transfers/Deposit.sol";
import { WithdrawalAuth } from "darkpoolv2-types/transfers/Withdrawal.sol";
import { OrderCancellationAuth } from "darkpoolv2-types/OrderCancellation.sol";
import { EncryptionKey } from "renegade-lib/Ciphertext.sol";
import { FixedPoint } from "renegade-lib/FixedPoint.sol";
import { IHasher } from "renegade-lib/interfaces/IHasher.sol";
import { IVerifier } from "darkpoolv2-interfaces/IVerifier.sol";
import { IVkeys } from "darkpoolv2-interfaces/IVkeys.sol";
import { IPermit2 } from "permit2-lib/interfaces/IPermit2.sol";
import { IWETH9 } from "renegade-lib/interfaces/IWETH9.sol";

/// @title IDarkpoolV2
/// @author Renegade Eng
/// @notice Interface for the DarkpoolV2 contract
interface IDarkpoolV2 {
    // --- Error Messages --- //
    /// @notice Thrown when proof verification fails
    error ProofVerificationFailed();
    /// @notice Thrown when a deposit verification fails
    error DepositVerificationFailed();
    /// @notice Thrown when a withdrawal verification fails
    error WithdrawalVerificationFailed();
    /// @notice Thrown when a fee payment verification fails
    error FeePaymentVerificationFailed();
    /// @notice Thrown when an order cancellation verification fails
    error OrderCancellationVerificationFailed();
    /// @notice Thrown when the order cancellation signature is invalid
    error InvalidOrderCancellationSignature();
    /// @notice Thrown when the obligation types are not compatible
    error IncompatibleObligationTypes();
    /// @notice Thrown when the obligation tokens are not compatible
    error IncompatiblePairs();
    /// @notice Thrown when the obligation amounts are not compatible
    error IncompatibleAmounts();
    /// @notice Thrown when an obligation is invalid
    error InvalidObligation();
    /// @notice Thrown when the settlement bundle type is invalid
    error InvalidSettlementBundleType();
    /// @notice Thrown when verification fails for a settlement
    error SettlementVerificationFailed();
    /// @notice Thrown when an intent commitment signature is invalid
    error InvalidIntentCommitmentSignature();
    /// @notice Thrown when the public input length is invalid
    error InvalidPublicInputLength();
    /// @notice Thrown when an amount is too large
    error AmountTooLarge(uint256 amount);
    /// @notice Thrown when a price is too large
    error PriceTooLarge(uint256 price);
    /// @notice Thrown when a fee rate is too large
    error FeeRateTooLarge(uint256 feeRate);
    /// @notice Thrown when a bounded match amount is out of bounds
    error BoundedMatchAmountOutOfBounds(uint256 amount, uint256 minAmount, uint256 maxAmount);
    /// @notice Thrown when the bounds of a bounded match result are invalid
    error InvalidBoundedMatchBounds();
    /// @notice Thrown when a bounded match has expired
    error BoundedMatchExpired();
    /// @notice Thrown when a bounded match amount is zero
    error BoundedMatchZeroAmount();

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
    /// @param defaultProtocolFeeRateRepr The default protocol fee rate for the darkpool (as uint256 repr)
    /// We take the repr rather than the `FixedPoint` because the Solidity compiler fails with Yul stack too deep
    /// errors otherwise.
    /// @param protocolFeeRecipient_ The address to receive protocol fees
    /// @param protocolFeeKey_ The encryption key for protocol fees
    /// @param weth_ The WETH9 contract instance
    /// @param hasher_ The hasher for the darkpool
    /// @param vkeys_ The verification keys for the darkpool
    /// @param verifier_ The verifier for the darkpool
    /// @param permit2_ The Permit2 contract instance
    /// @param transferExecutor_ The TransferExecutor contract address
    function initialize(
        address initialOwner,
        uint256 defaultProtocolFeeRateRepr,
        address protocolFeeRecipient_,
        EncryptionKey memory protocolFeeKey_,
        IWETH9 weth_,
        IHasher hasher_,
        IVkeys vkeys_,
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

    /// @notice Get the protocol fee for an asset pair
    /// @param asset0 The first asset in the trading pair
    /// @param asset1 The second asset in the trading pair
    /// @return The protocol fee rate for the asset pair
    function getProtocolFee(address asset0, address asset1) external view returns (FixedPoint memory);

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

    /// @notice Cancel an order in the darkpool
    /// @param auth The authorization for the order cancellation
    /// @param orderCancellationProofBundle The proof bundle for the order cancellation
    function cancelOrder(
        OrderCancellationAuth memory auth,
        OrderCancellationProofBundle calldata orderCancellationProofBundle
    )
        external;

    /// @notice Pay protocol fees publicly on a balance
    /// @param proofBundle The proof bundle for the public protocol fee payment
    function payPublicProtocolFee(PublicProtocolFeePaymentProofBundle calldata proofBundle) external;

    /// @notice Pay relayer fees publicly on a balance
    /// @param proofBundle The proof bundle for the public relayer fee payment
    function payPublicRelayerFee(PublicRelayerFeePaymentProofBundle calldata proofBundle) external;

    /// @notice Pay protocol fees privately on a balance
    /// @param proofBundle The proof bundle for the private protocol fee payment
    function payPrivateProtocolFee(PrivateProtocolFeePaymentProofBundle calldata proofBundle) external;

    /// @notice Pay relayer fees privately on a balance
    /// @param proofBundle The proof bundle for the private relayer fee payment
    function payPrivateRelayerFee(PrivateRelayerFeePaymentProofBundle calldata proofBundle) external;

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

    /// @notice Settle a trade with an external party who decides the trade size
    /// @param externalPartyAmountIn The input amount for the trade
    /// @param recipient The recipient of
    /// @param matchBundle The bounded match result bundle
    /// @param internalPartySettlementBundle The settlement bundle for the internal party. This type validates
    /// the internal user's state elements which are input to the trade.
    function settleExternalMatch(
        uint256 externalPartyAmountIn,
        address recipient,
        BoundedMatchResultBundle calldata matchBundle,
        SettlementBundle calldata internalPartySettlementBundle
    )
        external;
}
