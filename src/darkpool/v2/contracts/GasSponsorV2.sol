// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Initializable } from "oz-contracts/proxy/utils/Initializable.sol";
import { Ownable } from "oz-contracts/access/Ownable.sol";
import { Ownable2Step } from "oz-contracts/access/Ownable2Step.sol";
import { Pausable } from "oz-contracts/utils/Pausable.sol";

import { ECDSA } from "oz-contracts/utils/cryptography/ECDSA.sol";
import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";

import { IDarkpoolV2 } from "darkpoolv2-interfaces/IDarkpoolV2.sol";
import { IGasSponsorV2 } from "darkpoolv2-interfaces/IGasSponsorV2.sol";
import { DarkpoolConstants } from "darkpoolv2-lib/Constants.sol";
import { BoundedMatchResult } from "darkpoolv2-types/BoundedMatchResult.sol";
import { SettlementBundle } from "darkpoolv2-types/settlement/SettlementBundle.sol";

import { IERC20 } from "oz-contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "oz-contracts/token/ERC20/utils/SafeERC20.sol";
import { SafeTransferLib } from "solmate/src/utils/SafeTransferLib.sol";

/**
 * @title GasSponsorV2
 * @author Renegade Eng
 * @notice A contract used to sponsor gas costs of external matches in DarkpoolV2
 */
contract GasSponsorV2 is Initializable, Ownable2Step, Pausable, IGasSponsorV2 {
    // -----------
    // | STORAGE |
    // -----------

    /// @notice The address of the DarkpoolV2 proxy contract
    address public darkpoolAddress;
    /// @notice The public key used to authenticate gas sponsorship, stored as an address
    address public authAddress;
    /// @notice The set of used nonces for sponsored matches
    mapping(uint256 => bool) public usedNonces;

    // ---------------
    // | CONSTRUCTOR |
    // ---------------

    /// @notice Constructor that disables initializers for the implementation contract
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() Ownable(msg.sender) {
        _disableInitializers();
    }

    // ----------------------
    // | EXTERNAL FUNCTIONS |
    // ----------------------

    // --- Initialization --- //

    /**
     * @notice Initializes the gas sponsor contract with the given darkpool address and auth pubkey
     * @param initialOwner The initial owner of the gas sponsor contract
     * @param _darkpoolAddress The address of the DarkpoolV2 proxy contract
     * @param _authAddress The public key used to authenticate gas sponsorship
     */
    function initialize(address initialOwner, address _darkpoolAddress, address _authAddress) public initializer {
        _transferOwnership(initialOwner);
        darkpoolAddress = _darkpoolAddress;
        authAddress = _authAddress;
    }

    // --- Key Rotation --- //

    /**
     * @notice Rotates the auth address to the given new address
     * @param newAuthAddress The new auth address
     */
    function rotateAuthAddress(address newAuthAddress) external onlyOwner {
        authAddress = newAuthAddress;
        emit AuthAddressRotated(newAuthAddress);
    }

    // --- Pause Control --- //

    /**
     * @notice Pauses the gas sponsor contract
     */
    function pause() external onlyOwner {
        _pause();
    }

    /**
     * @notice Unpauses the gas sponsor contract
     */
    function unpause() external onlyOwner {
        _unpause();
    }

    // --- Funding --- //

    /**
     * @notice Receives ETH from the caller
     */
    receive() external payable { }

    /**
     * @notice Withdraws ETH from the gas sponsor contract to the given receiver
     * @param receiver The address to receive the ETH
     * @param amount The amount of ETH to withdraw
     */
    function withdrawEth(address receiver, uint256 amount) external onlyOwner {
        SafeTransferLib.safeTransferETH(receiver, amount);
    }

    /**
     * @notice Withdraws ERC20 tokens from the gas sponsor contract to the given receiver
     * @param receiver The address to receive the tokens
     * @param token The token address
     * @param amount The amount of tokens to withdraw
     */
    function withdrawTokens(address receiver, address token, uint256 amount) external onlyOwner {
        IERC20 tokenContract = IERC20(token);
        SafeERC20.safeTransfer(tokenContract, receiver, amount);
    }

    // --- Gas Sponsorship --- //

    /**
     * @notice Sponsor the gas costs of an external match settlement on DarkpoolV2
     * @param externalPartyAmountIn The input amount for the trade from the external party
     * @param receiver The address to receive the output tokens (0 = msg.sender)
     * @param matchResult The bounded match result parameters
     * @param internalPartySettlementBundle The settlement bundle for the internal party
     * @param refundAddress The address to refund gas costs to
     * @param refundNativeEth Whether to refund gas costs in native ETH
     * @param refundAmount The amount to refund
     * @param nonce A unique nonce for this sponsorship
     * @param signature The signature authorizing the sponsorship
     * @return The amount received by the external party
     */
    function sponsorExternalMatchSettle(
        uint256 externalPartyAmountIn,
        address receiver,
        BoundedMatchResult calldata matchResult,
        SettlementBundle calldata internalPartySettlementBundle,
        address refundAddress,
        bool refundNativeEth,
        uint256 refundAmount,
        uint256 nonce,
        bytes calldata signature
    )
        external
        payable
        returns (uint256)
    {
        // Resolve the receiver and verify the sponsorship signature
        address resolvedReceiver = receiver == address(0) ? msg.sender : receiver;
        _verifySigSpendNonce(nonce, refundAddress, refundAmount, signature);

        // Execute the external match
        (address outputTokenAddr, uint256 receivedInMatch) =
            _doExternalMatch(externalPartyAmountIn, resolvedReceiver, matchResult, internalPartySettlementBundle);

        // If gas sponsorship is paused or refund amount is 0, return early
        if (paused() || refundAmount == 0) {
            emit GasSponsorshipSkipped(nonce);
            emit SponsoredExternalMatchOutput(receivedInMatch, nonce);
            return receivedInMatch;
        }

        // Refund the gas costs
        uint256 receivedAmount = _refundGasCost(
            refundNativeEth, refundAddress, outputTokenAddr, refundAmount, receivedInMatch, resolvedReceiver, nonce
        );

        emit SponsoredExternalMatchOutput(receivedAmount, nonce);
        return receivedAmount;
    }

    // ----------------------
    // | INTERNAL FUNCTIONS |
    // ----------------------

    // --- Authorization --- //

    /**
     * @notice Verify the sponsorship signature and mark its nonce as used
     * @param nonce The nonce to verify and mark as used
     * @param refundAddress The refund address
     * @param refundAmount The refund amount
     * @param signature The signature to verify
     */
    function _verifySigSpendNonce(
        uint256 nonce,
        address refundAddress,
        uint256 refundAmount,
        bytes calldata signature
    )
        internal
    {
        _assertSponsorshipSignature(nonce, refundAddress, refundAmount, signature);
        _markNonceUsed(nonce);
    }

    /**
     * @notice Verify the signature over the nonce, refund address, and refund amount
     * @param nonce The nonce to verify
     * @param refundAddress The refund address
     * @param refundAmount The refund amount
     * @param signature The signature to verify
     */
    function _assertSponsorshipSignature(
        uint256 nonce,
        address refundAddress,
        uint256 refundAmount,
        bytes calldata signature
    )
        internal
        view
    {
        // Create message hash directly from encoded tuple
        bytes32 messageHash = EfficientHashLib.hash(abi.encode(nonce, refundAddress, refundAmount));

        // Split the signature into r, s and v
        if (signature.length != 65) revert InvalidSignatureLength();
        bytes32 r = bytes32(signature[:32]);
        bytes32 s = bytes32(signature[32:64]);
        uint8 v = uint8(signature[64]);

        // Clients sometimes use v = 0 or 1, the ecrecover precompile expects 27 or 28
        if (v < 27) {
            v += 27;
        }

        address recoveredAddress = ECDSA.recover(messageHash, v, r, s);
        if (recoveredAddress != authAddress) revert InvalidSignature();
    }

    /**
     * @notice Marks the given nonce as used
     * @param nonce The nonce to mark as used
     */
    function _markNonceUsed(uint256 nonce) internal {
        if (usedNonces[nonce]) revert NonceAlreadyUsed();
        usedNonces[nonce] = true;
        emit NonceUsed(nonce);
    }

    // --- External Match Helpers --- //

    /**
     * @notice Executes an external match on the darkpool
     * @param externalPartyAmountIn The amount the external party is providing
     * @param receiver The address to receive tokens
     * @param matchResult The bounded match result parameters
     * @param internalPartySettlementBundle The settlement bundle for the internal party
     * @return outputTokenAddr The token address received by the external party
     * @return receivedInMatch The amount received by the external party in the match, net of fees
     */
    function _doExternalMatch(
        uint256 externalPartyAmountIn,
        address receiver,
        BoundedMatchResult calldata matchResult,
        SettlementBundle calldata internalPartySettlementBundle
    )
        internal
        returns (address, uint256)
    {
        // Process tokens based on external match parameters
        _custodySendTokens(matchResult, externalPartyAmountIn);

        // Call the darkpool contract and get the net receive amount
        IDarkpoolV2 darkpool = IDarkpoolV2(darkpoolAddress);
        uint256 receivedInMatch =
            darkpool.settleExternalMatch(externalPartyAmountIn, receiver, matchResult, internalPartySettlementBundle);

        // The output token is the internal party's input token
        address outputTokenAddr = matchResult.internalPartyInputToken;

        return (outputTokenAddr, receivedInMatch);
    }

    // --- Transfer Helpers --- //

    /**
     * @notice Takes custody of the trader's tokens to proxy the match
     * @param matchResult The bounded match result containing token and price details
     * @param externalPartyAmountIn The amount the external party is providing
     */
    function _custodySendTokens(BoundedMatchResult calldata matchResult, uint256 externalPartyAmountIn) internal {
        address sender = msg.sender;
        address sponsor = address(this);

        // The external party's input token is the internal party's output token
        address inputToken = matchResult.internalPartyOutputToken;

        // Only execute ERC20 transfer if not native ETH
        if (!DarkpoolConstants.isNativeToken(inputToken)) {
            IERC20 token = IERC20(inputToken);
            SafeERC20.safeIncreaseAllowance(token, darkpoolAddress, externalPartyAmountIn);
            SafeERC20.safeTransferFrom(token, sender, sponsor, externalPartyAmountIn);
        }
    }

    // --- Refund Helpers --- //

    /**
     * @notice Resolves the refund address to use
     * @param refundNativeEth Whether to refund in native ETH
     * @param refundAddress The explicitly specified refund address
     * @param receiver The receiver of the match output
     * @return The resolved refund address
     */
    function _resolveRefundAddress(
        bool refundNativeEth,
        address refundAddress,
        address receiver
    )
        internal
        view
        returns (address)
    {
        // If the refund address is explicitly set, use it
        if (refundAddress != address(0)) {
            return refundAddress;
        } else if (refundNativeEth) {
            // If refunding through native ETH, default to tx.origin
            // solhint-disable-next-line avoid-tx-origin
            return tx.origin;
        } else {
            // Otherwise default to the receiver
            return receiver;
        }
    }

    /**
     * @notice Refunds gas costs through native ETH
     * @param refundAddress The address to receive the refund
     * @param refundAmount The amount to refund in native ETH
     * @param nonce The nonce of the sponsorship
     * @return The amount actually refunded (0 if balance insufficient)
     */
    function _refundThroughNativeEth(
        address refundAddress,
        uint256 refundAmount,
        uint256 nonce
    )
        internal
        returns (uint256)
    {
        // Check balance, do not revert if insufficient
        if (address(this).balance < refundAmount) {
            emit InsufficientSponsorBalance(nonce);
            return 0;
        }

        // Transfer ETH
        SafeTransferLib.safeTransferETH(refundAddress, refundAmount);
        emit SponsoredExternalMatch(refundAmount, address(0), nonce);
        return refundAmount;
    }

    /**
     * @notice Refunds gas costs through the output token
     * @param refundAddress The address to receive the refund
     * @param outputTokenAddr The token address to use for refund
     * @param refundAmount The amount to refund in the output token
     * @param nonce The nonce of the sponsorship
     * @return The amount actually refunded (0 if balance insufficient)
     */
    function _refundThroughOutputToken(
        address refundAddress,
        address outputTokenAddr,
        uint256 refundAmount,
        uint256 nonce
    )
        internal
        returns (uint256)
    {
        // Check balance, do not revert if insufficient
        IERC20 outputToken = IERC20(outputTokenAddr);
        if (outputToken.balanceOf(address(this)) < refundAmount) {
            emit InsufficientSponsorBalance(nonce);
            return 0;
        }

        // Transfer tokens
        SafeERC20.safeTransfer(outputToken, refundAddress, refundAmount);
        emit SponsoredExternalMatch(refundAmount, outputTokenAddr, nonce);
        return refundAmount;
    }

    /**
     * @notice Refunds the user's gas costs
     * @param refundNativeEth Whether to refund in native ETH
     * @param refundAddress The address to receive the refund
     * @param outputTokenAddr The output token address from the match
     * @param refundAmount The amount to refund
     * @param receivedInMatch The amount received from the match
     * @param receiver The receiver of the match output
     * @param nonce The nonce of the sponsorship
     * @return The total amount received including refund
     */
    function _refundGasCost(
        bool refundNativeEth,
        address refundAddress,
        address outputTokenAddr,
        uint256 refundAmount,
        uint256 receivedInMatch,
        address receiver,
        uint256 nonce
    )
        internal
        returns (uint256)
    {
        address resolvedRefundAddress = _resolveRefundAddress(refundNativeEth, refundAddress, receiver);
        bool isNativeEthOutput = DarkpoolConstants.isNativeToken(outputTokenAddr);

        // Refund through appropriate method
        uint256 refundedAmount;
        if (refundNativeEth || isNativeEthOutput) {
            refundedAmount = _refundThroughNativeEth(resolvedRefundAddress, refundAmount, nonce);
        } else {
            refundedAmount = _refundThroughOutputToken(resolvedRefundAddress, outputTokenAddr, refundAmount, nonce);
        }

        // Calculate total received amount
        uint256 receivedAmount;
        if (isNativeEthOutput || !refundNativeEth) {
            // If output token is ETH or refunding in-kind, include refund in total
            receivedAmount = receivedInMatch + refundedAmount;
        } else {
            receivedAmount = receivedInMatch;
        }

        return receivedAmount;
    }
}
