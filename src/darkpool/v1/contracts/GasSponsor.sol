// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { Initializable } from "oz-contracts/proxy/utils/Initializable.sol";
import { Ownable } from "oz-contracts/access/Ownable.sol";
import { Ownable2Step } from "oz-contracts/access/Ownable2Step.sol";
import { Pausable } from "oz-contracts/utils/Pausable.sol";
import { IDarkpool } from "darkpoolv1-lib/interfaces/IDarkpool.sol";
import { ECDSA } from "oz-contracts/utils/cryptography/ECDSA.sol";
import { DarkpoolConstants } from "darkpoolv1-lib/Constants.sol";
import { TypesLib } from "darkpoolv1-types/TypesLib.sol";

import { IERC20 } from "oz-contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "oz-contracts/token/ERC20/utils/SafeERC20.sol";
import { SafeTransferLib } from "solmate/src/utils/SafeTransferLib.sol";

import {
    ValidMatchSettleAtomicStatement, ValidMalleableMatchSettleAtomicStatement
} from "darkpoolv1-lib/PublicInputs.sol";

import {
    ExternalMatchResult,
    PartyMatchPayload,
    MatchAtomicProofs,
    MalleableMatchAtomicProofs,
    MatchAtomicLinkingProofs
} from "darkpoolv1-types/Settlement.sol";

/**
 * @title GasSponsor
 * @notice A contract used to sponsor gas costs of external (atomic) matches
 */
contract GasSponsor is Initializable, Ownable2Step, Pausable {
    using TypesLib for ExternalMatchResult;

    // ------------------
    // | ERROR MESSAGES |
    // ------------------

    error NonceAlreadyUsed();
    error InsufficientBalance();
    error InvalidVersion();
    error NotOwner();
    error InvalidSignature();
    error AddressZero();

    // ----------
    // | EVENTS |
    // ----------

    event OwnershipTransferred(address indexed newOwner);
    event NonceUsed(uint256 indexed nonce);
    event AuthAddressRotated(address indexed newAuthAddress);
    event InsufficientSponsorBalance(uint256 indexed nonce);
    event SponsoredExternalMatch(uint256 refundAmount, address token, uint256 indexed nonce);
    event SponsoredExternalMatchOutput(uint256 receivedAmount, uint256 indexed nonce);
    event GasSponsorshipSkipped(uint256 indexed nonce);

    // -----------
    // | STORAGE |
    // -----------

    /// @notice The address of the darkpool proxy contract
    address public darkpoolAddress;
    /// @notice The public key used to authenticate gas sponsorship, stored as an address
    address public authAddress;
    /// @notice The set of used nonces for sponsored matches
    mapping(uint256 => bool) public usedNonces;

    // ---------------
    // | CONSTRUCTOR |
    // ---------------

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
     * @param _darkpoolAddress The address of the darkpool proxy contract
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
     * @notice Sponsor the gas costs of an atomic match settlement
     * @param receiver The address to receive the tokens
     * @param internalPartyMatchPayload The internal party match payload
     * @param validMatchSettleAtomicStatement The valid match settle atomic statement
     * @param matchProofs The match proofs
     * @param matchLinkingProofs The match linking proofs
     * @param refundAddress The address to refund gas costs to
     * @param refundNativeEth Whether to refund gas costs in native ETH
     * @param refundAmount The amount to refund
     * @param nonce A unique nonce for this sponsorship
     * @param signature The signature authorizing the sponsorship
     * @return The amount received by the external party
     */
    function sponsorAtomicMatchSettle(
        address receiver,
        PartyMatchPayload calldata internalPartyMatchPayload,
        ValidMatchSettleAtomicStatement calldata validMatchSettleAtomicStatement,
        MatchAtomicProofs calldata matchProofs,
        MatchAtomicLinkingProofs calldata matchLinkingProofs,
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

        // Execute the atomic match
        (ExternalMatchResult memory matchRes, uint256 receivedInMatch) = _doAtomicMatch(
            resolvedReceiver,
            internalPartyMatchPayload,
            validMatchSettleAtomicStatement,
            matchProofs,
            matchLinkingProofs
        );

        // If gas sponsorship is paused or refund amount is 0, return early
        if (paused() || refundAmount == 0) {
            emit GasSponsorshipSkipped(nonce);
            emit SponsoredExternalMatchOutput(receivedInMatch, nonce);
            return receivedInMatch;
        }

        // Refund the gas costs
        (address buyTokenAddr,) = matchRes.externalPartyBuyMintAmount();
        uint256 receivedAmount = _refundGasCost(
            refundNativeEth, refundAddress, buyTokenAddr, refundAmount, receivedInMatch, resolvedReceiver, nonce
        );

        emit SponsoredExternalMatchOutput(receivedAmount, nonce);
        return receivedAmount;
    }

    /**
     * @notice Sponsors a malleable atomic match settlement
     * @param quoteAmount The quote amount for the malleable match
     * @param baseAmount The base amount for the malleable match
     * @param receiver The address to receive the tokens
     * @param internalPartyMatchPayload The internal party match payload
     * @param malleableMatchSettleStatement The malleable match settle statement
     * @param matchProofs The match proofs
     * @param matchLinkingProofs The match linking proofs
     * @param refundAddress The address to refund gas costs to
     * @param refundNativeEth Whether to refund gas costs in native ETH
     * @param refundAmount The amount to refund
     * @param nonce A unique nonce for this sponsorship
     * @param signature The signature authorizing the sponsorship
     * @return The amount received by the external party
     */
    function sponsorMalleableAtomicMatchSettle(
        uint256 quoteAmount,
        uint256 baseAmount,
        address receiver,
        PartyMatchPayload calldata internalPartyMatchPayload,
        ValidMalleableMatchSettleAtomicStatement calldata malleableMatchSettleStatement,
        MalleableMatchAtomicProofs calldata matchProofs,
        MatchAtomicLinkingProofs calldata matchLinkingProofs,
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

        // Execute the malleable match
        (ExternalMatchResult memory matchRes, uint256 receivedInMatch) = _doMalleableMatch(
            quoteAmount,
            baseAmount,
            resolvedReceiver,
            internalPartyMatchPayload,
            malleableMatchSettleStatement,
            matchProofs,
            matchLinkingProofs
        );

        // If gas sponsorship is paused or refund amount is 0, return early
        if (paused() || refundAmount == 0) {
            emit GasSponsorshipSkipped(nonce);
            emit SponsoredExternalMatchOutput(receivedInMatch, nonce);
            return receivedInMatch;
        }

        // Refund the gas costs
        (address buyTokenAddr,) = matchRes.externalPartyBuyMintAmount();
        uint256 receivedAmount = _refundGasCost(
            refundNativeEth, refundAddress, buyTokenAddr, refundAmount, receivedInMatch, resolvedReceiver, nonce
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
        bytes32 messageHash = keccak256(abi.encode(nonce, refundAddress, refundAmount));

        // Split the signature into r, s and v
        require(signature.length == 65, "Invalid signature length");
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

    // --- Atomic Match Helpers --- //

    /**
     * @notice Executes an atomic match on the darkpool
     * @param receiver The address to receive tokens
     * @param internalPartyMatchPayload The match payload for the internal party
     * @param validMatchSettleAtomicStatement The match settle statement
     * @param matchProofs The match proofs
     * @param matchLinkingProofs The match linking proofs
     * @return The match result and amount received in the match
     */
    function _doAtomicMatch(
        address receiver,
        PartyMatchPayload calldata internalPartyMatchPayload,
        ValidMatchSettleAtomicStatement calldata validMatchSettleAtomicStatement,
        MatchAtomicProofs calldata matchProofs,
        MatchAtomicLinkingProofs calldata matchLinkingProofs
    )
        internal
        returns (ExternalMatchResult memory, uint256)
    {
        // Process tokens based on external match parameters
        ExternalMatchResult memory matchResult = validMatchSettleAtomicStatement.matchResult;
        _custodySendTokens(matchResult);

        // Call the darkpool contract
        IDarkpool darkpool = IDarkpool(darkpoolAddress);
        uint256 receivedInMatch = darkpool.processAtomicMatchSettle{ value: msg.value }(
            receiver, internalPartyMatchPayload, validMatchSettleAtomicStatement, matchProofs, matchLinkingProofs
        );

        return (matchResult, receivedInMatch);
    }

    /**
     * @notice Executes a malleable match on the darkpool
     */
    function _doMalleableMatch(
        uint256 quoteAmount,
        uint256 baseAmount,
        address receiver,
        PartyMatchPayload calldata internalPartyMatchPayload,
        ValidMalleableMatchSettleAtomicStatement calldata malleableMatchSettleStatement,
        MalleableMatchAtomicProofs calldata matchProofs,
        MatchAtomicLinkingProofs calldata matchLinkingProofs
    )
        internal
        returns (ExternalMatchResult memory, uint256)
    {
        // Convert malleable match to external match result using base amount
        ExternalMatchResult memory matchResult =
            TypesLib.buildExternalMatchResult(quoteAmount, baseAmount, malleableMatchSettleStatement.matchResult);
        _custodySendTokens(matchResult);

        // Call the darkpool contract
        IDarkpool darkpool = IDarkpool(darkpoolAddress);
        uint256 receivedInMatch = darkpool.processMalleableAtomicMatchSettle{ value: msg.value }(
            quoteAmount,
            baseAmount,
            receiver,
            internalPartyMatchPayload,
            malleableMatchSettleStatement,
            matchProofs,
            matchLinkingProofs
        );

        return (matchResult, receivedInMatch);
    }

    // --- Transfer Helpers --- //

    /**
     * @notice Takes custody of the trader's tokens to proxy the match
     */
    function _custodySendTokens(ExternalMatchResult memory matchResult) internal {
        address sender = msg.sender;
        address sponsor = address(this);
        (address sendToken, uint256 sendAmount) = matchResult.externalPartySellMintAmount();

        // Only execute ERC20 transfer if not native ETH
        if (!DarkpoolConstants.isNativeToken(sendToken)) {
            IERC20 token = IERC20(sendToken);
            SafeERC20.safeIncreaseAllowance(token, darkpoolAddress, sendAmount);
            SafeERC20.safeTransferFrom(token, sender, sponsor, sendAmount);
        }
    }

    // --- Refund Helpers --- //

    /**
     * @notice Resolves the refund address to use
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
            return tx.origin;
        } else {
            // Otherwise default to the receiver
            return receiver;
        }
    }

    /**
     * @notice Refunds gas costs through native ETH
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
     * @notice Refunds gas costs through the buy-side token
     */
    function _refundThroughBuyToken(
        address refundAddress,
        address buyTokenAddr,
        uint256 refundAmount,
        uint256 nonce
    )
        internal
        returns (uint256)
    {
        // Check balance, do not revert if insufficient
        IERC20 buyToken = IERC20(buyTokenAddr);
        if (buyToken.balanceOf(address(this)) < refundAmount) {
            emit InsufficientSponsorBalance(nonce);
            return 0;
        }

        // Transfer tokens
        SafeERC20.safeTransfer(buyToken, refundAddress, refundAmount);
        emit SponsoredExternalMatch(refundAmount, buyTokenAddr, nonce);
        return refundAmount;
    }

    /**
     * @notice Refunds the user's gas costs
     */
    function _refundGasCost(
        bool refundNativeEth,
        address refundAddress,
        address buyTokenAddr,
        uint256 refundAmount,
        uint256 receivedInMatch,
        address receiver,
        uint256 nonce
    )
        internal
        returns (uint256)
    {
        address resolvedRefundAddress = _resolveRefundAddress(refundNativeEth, refundAddress, receiver);
        bool isNativeEthBuy = DarkpoolConstants.isNativeToken(buyTokenAddr);

        // Refund through appropriate method
        uint256 refundedAmount;
        if (refundNativeEth || isNativeEthBuy) {
            refundedAmount = _refundThroughNativeEth(resolvedRefundAddress, refundAmount, nonce);
        } else {
            refundedAmount = _refundThroughBuyToken(resolvedRefundAddress, buyTokenAddr, refundAmount, nonce);
        }

        // Calculate total received amount
        uint256 receivedAmount;
        if (isNativeEthBuy || !refundNativeEth) {
            // If buy token is ETH or refunding in-kind, include refund in total
            receivedAmount = receivedInMatch + refundedAmount;
        } else {
            receivedAmount = receivedInMatch;
        }

        return receivedAmount;
    }
}
