// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Initializable } from "oz-contracts/proxy/utils/Initializable.sol";
import { Ownable } from "oz-contracts/access/Ownable.sol";
import { Ownable2Step } from "oz-contracts/access/Ownable2Step.sol";
import { Pausable } from "oz-contracts/utils/Pausable.sol";

import { ECDSA } from "oz-contracts/utils/cryptography/ECDSA.sol";
import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";

import { IDarkpoolV2 } from "darkpoolv2-interfaces/IDarkpoolV2.sol";
import { BoundedMatchResult } from "darkpoolv2-types/BoundedMatchResult.sol";
import { SettlementBundle } from "darkpoolv2-types/settlement/SettlementBundle.sol";
import { DarkpoolConstants } from "darkpoolv2-lib/Constants.sol";

import { IERC20 } from "oz-contracts/token/ERC20/IERC20.sol";
import { SafeERC20 } from "oz-contracts/token/ERC20/utils/SafeERC20.sol";
import { SafeTransferLib } from "solmate/src/utils/SafeTransferLib.sol";

/// @notice Options for gas sponsorship
/// @dev This struct bundles the parameters needed to configure gas refunds for sponsored matches
struct GasSponsorOptions {
    /// @dev The address to refund gas costs to
    address refundAddress;
    /// @dev Whether to refund gas costs in native ETH
    bool refundNativeEth;
    /// @dev The amount to refund for gas costs
    uint256 refundAmount;
    /// @dev A unique nonce for this sponsorship (replay protection)
    uint256 nonce;
    /// @dev The signature authorizing the sponsorship
    bytes signature;
}

/// @title GasSponsorV2
/// @author Renegade Eng
/// @notice A contract used to sponsor gas costs of external matches in DarkpoolV2
contract GasSponsorV2 is Initializable, Ownable2Step, Pausable {
    // ------------------
    // | ERROR MESSAGES |
    // ------------------

    /// @notice Error thrown when a nonce has already been used
    error NonceAlreadyUsed();
    /// @notice Error thrown when the signature is invalid
    error InvalidSignature();
    /// @notice Error thrown when the signature length is invalid
    error InvalidSignatureLength();

    // ----------
    // | EVENTS |
    // ----------

    /// @notice Emitted when a nonce is used
    /// @param nonce The nonce that was used
    event NonceUsed(uint256 indexed nonce);
    /// @notice Emitted when the auth address is rotated
    /// @param newAuthAddress The new auth address
    event AuthAddressRotated(address indexed newAuthAddress);
    /// @notice Emitted when the sponsor balance is insufficient for a refund
    /// @param nonce The nonce of the sponsorship attempt
    event InsufficientSponsorBalance(uint256 indexed nonce);
    /// @notice Emitted when an external match is successfully sponsored
    /// @param refundAmount The amount refunded
    /// @param token The token used for refund (address(0) for native ETH)
    /// @param nonce The nonce of the sponsorship
    event SponsoredExternalMatch(uint256 refundAmount, address token, uint256 indexed nonce);
    /// @notice Emitted with the output amount of a sponsored match
    /// @param receivedAmount The amount received by the external party
    /// @param nonce The nonce of the sponsorship
    event SponsoredExternalMatchOutput(uint256 receivedAmount, uint256 indexed nonce);
    /// @notice Emitted when gas sponsorship is skipped (paused or zero refund)
    /// @param nonce The nonce of the sponsorship
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

    /// @notice Constructor that disables initializers for the implementation contract
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() Ownable(msg.sender) {
        _disableInitializers();
    }

    // ----------------------
    // | EXTERNAL FUNCTIONS |
    // ----------------------

    // --- Initialization --- //

    /// @notice Initializes the gas sponsor contract with the given darkpool address and auth pubkey
    /// @param initialOwner The initial owner of the gas sponsor contract
    /// @param _darkpoolAddress The address of the darkpool proxy contract
    /// @param _authAddress The public key used to authenticate gas sponsorship
    function initialize(address initialOwner, address _darkpoolAddress, address _authAddress) public initializer {
        _transferOwnership(initialOwner);
        darkpoolAddress = _darkpoolAddress;
        authAddress = _authAddress;
    }

    // --- Key Rotation --- //

    /// @notice Rotates the auth address to the given new address
    /// @param newAuthAddress The new auth address
    function rotateAuthAddress(address newAuthAddress) external onlyOwner {
        authAddress = newAuthAddress;
        emit AuthAddressRotated(newAuthAddress);
    }

    // --- Funding --- //

    /// @notice Receives ETH from the caller
    receive() external payable { }

    /// @notice Withdraws ETH from the gas sponsor contract to the given receiver
    /// @param receiver The address to receive the ETH
    /// @param amount The amount of ETH to withdraw
    function withdrawEth(address receiver, uint256 amount) external onlyOwner {
        SafeTransferLib.safeTransferETH(receiver, amount);
    }

    /// @notice Withdraws ERC20 tokens from the gas sponsor contract to the given receiver
    /// @param receiver The address to receive the tokens
    /// @param token The token address
    /// @param amount The amount of tokens to withdraw
    function withdrawTokens(address receiver, address token, uint256 amount) external onlyOwner {
        IERC20 tokenContract = IERC20(token);
        SafeERC20.safeTransfer(tokenContract, receiver, amount);
    }

    // --- Gas Sponsorship --- //

    /// @notice Sponsor the gas costs of an external match settlement
    /// @param externalPartyAmountIn The input amount for the external party
    /// @param recipient The address to receive the output tokens
    /// @param matchResult The bounded match result parameters
    /// @param internalPartySettlementBundle The settlement bundle for the internal party
    /// @param options The gas sponsorship options (refund address, amount, nonce, signature)
    /// @return The amount received by the external party
    function sponsorExternalMatch(
        uint256 externalPartyAmountIn,
        address recipient,
        BoundedMatchResult calldata matchResult,
        SettlementBundle calldata internalPartySettlementBundle,
        GasSponsorOptions calldata options
    )
        external
        payable
        returns (uint256)
    {
        // Resolve the recipient and verify the sponsorship signature
        address resolvedRecipient = recipient == address(0) ? msg.sender : recipient;
        _verifySigSpendNonce(options);

        // Execute the external match
        (address buyTokenAddr, uint256 receivedInMatch) =
            _doExternalMatch(externalPartyAmountIn, resolvedRecipient, matchResult, internalPartySettlementBundle);

        // If gas sponsorship is paused or refund amount is 0, return early
        if (paused() || options.refundAmount == 0) {
            emit GasSponsorshipSkipped(options.nonce);
            emit SponsoredExternalMatchOutput(receivedInMatch, options.nonce);
            return receivedInMatch;
        }

        // Refund the gas costs
        uint256 receivedAmount = _refundGasCost(options, buyTokenAddr, receivedInMatch, resolvedRecipient);

        emit SponsoredExternalMatchOutput(receivedAmount, options.nonce);
        return receivedAmount;
    }

    // ----------------------
    // | INTERNAL FUNCTIONS |
    // ----------------------

    // --- Authorization --- //

    /// @notice Verify the sponsorship signature and mark its nonce as used
    /// @param options The gas sponsorship options containing nonce, refund address, amount, and signature
    function _verifySigSpendNonce(GasSponsorOptions calldata options) internal {
        _assertSponsorshipSignature(options.nonce, options.refundAddress, options.refundAmount, options.signature);
        _markNonceUsed(options.nonce);
    }

    /// @notice Verify the signature over the nonce, refund address, and refund amount
    /// @param nonce The nonce to verify
    /// @param refundAddress The refund address
    /// @param refundAmount The refund amount
    /// @param signature The signature to verify
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

    /// @notice Marks the given nonce as used
    /// @param nonce The nonce to mark as used
    function _markNonceUsed(uint256 nonce) internal {
        if (usedNonces[nonce]) revert NonceAlreadyUsed();
        usedNonces[nonce] = true;
        emit NonceUsed(nonce);
    }

    // --- External Match Helper --- //

    /// @notice Executes an external match on the darkpool
    /// @param externalPartyAmountIn The input amount for the external party
    /// @param recipient The address to receive output tokens
    /// @param matchResult The bounded match result parameters
    /// @param internalPartySettlementBundle The settlement bundle for the internal party
    /// @return buyTokenAddr The address of the token the external party receives
    /// @return receivedInMatch The amount received by the external party in the match
    function _doExternalMatch(
        uint256 externalPartyAmountIn,
        address recipient,
        BoundedMatchResult calldata matchResult,
        SettlementBundle calldata internalPartySettlementBundle
    )
        internal
        returns (address buyTokenAddr, uint256 receivedInMatch)
    {
        // The external party's input token is the internal party's output token
        // The external party's output token is the internal party's input token
        address sendToken = matchResult.internalPartyOutputToken;
        buyTokenAddr = matchResult.internalPartyInputToken;

        // Take custody of the external party's input tokens
        _custodySendTokens(sendToken, externalPartyAmountIn);

        // Call the darkpool contract
        IDarkpoolV2 darkpool = IDarkpoolV2(darkpoolAddress);
        receivedInMatch =
            darkpool.settleExternalMatch(externalPartyAmountIn, recipient, matchResult, internalPartySettlementBundle);
    }

    // --- Transfer Helpers --- //

    /// @notice Takes custody of the trader's tokens to proxy the match
    /// @param sendToken The token address to take custody of
    /// @param sendAmount The amount of tokens to take custody of
    function _custodySendTokens(address sendToken, uint256 sendAmount) internal {
        address sender = msg.sender;
        address sponsor = address(this);

        // Only execute ERC20 transfer if not native ETH
        if (!DarkpoolConstants.isNativeToken(sendToken)) {
            IERC20 token = IERC20(sendToken);
            SafeERC20.safeIncreaseAllowance(token, darkpoolAddress, sendAmount);
            SafeERC20.safeTransferFrom(token, sender, sponsor, sendAmount);
        }
    }

    // --- Refund Helpers --- //

    /// @notice Resolves the refund address to use
    /// @param refundNativeEth Whether to refund in native ETH
    /// @param refundAddress The explicitly specified refund address
    /// @param receiver The receiver of the match output
    /// @return The resolved refund address
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

    /// @notice Refunds gas costs through native ETH
    /// @param refundAddress The address to receive the refund
    /// @param refundAmount The amount to refund in native ETH
    /// @param nonce The nonce of the sponsorship
    /// @return The amount actually refunded (0 if balance insufficient)
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

    /// @notice Refunds gas costs through the buy-side token
    /// @param refundAddress The address to receive the refund
    /// @param buyTokenAddr The token address to use for refund
    /// @param refundAmount The amount to refund in the buy token
    /// @param nonce The nonce of the sponsorship
    /// @return The amount actually refunded (0 if balance insufficient)
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

    /// @notice Refunds the user's gas costs
    /// @param options The gas sponsorship options containing refund parameters
    /// @param buyTokenAddr The buy token address from the match
    /// @param receivedInMatch The amount received from the match
    /// @param receiver The receiver of the match output
    /// @return The total amount received including refund
    function _refundGasCost(
        GasSponsorOptions calldata options,
        address buyTokenAddr,
        uint256 receivedInMatch,
        address receiver
    )
        internal
        returns (uint256)
    {
        address resolvedRefundAddress = _resolveRefundAddress(options.refundNativeEth, options.refundAddress, receiver);
        bool isNativeEthBuy = DarkpoolConstants.isNativeToken(buyTokenAddr);

        // Refund through appropriate method
        uint256 refundedAmount;
        if (options.refundNativeEth || isNativeEthBuy) {
            refundedAmount = _refundThroughNativeEth(resolvedRefundAddress, options.refundAmount, options.nonce);
        } else {
            refundedAmount =
                _refundThroughBuyToken(resolvedRefundAddress, buyTokenAddr, options.refundAmount, options.nonce);
        }

        // Calculate total received amount
        uint256 receivedAmount;
        if (isNativeEthBuy || !options.refundNativeEth) {
            // If buy token is ETH or refunding in-kind, include refund in total
            receivedAmount = receivedInMatch + refundedAmount;
        } else {
            receivedAmount = receivedInMatch;
        }

        return receivedAmount;
    }
}
