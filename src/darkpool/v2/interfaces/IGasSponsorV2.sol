// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { BoundedMatchResult } from "darkpoolv2-types/BoundedMatchResult.sol";
import { SettlementBundle } from "darkpoolv2-types/settlement/SettlementBundle.sol";

/// @title IGasSponsorV2
/// @author Renegade Eng
/// @notice Interface for the GasSponsorV2 contract, exposing sponsorship methods for DarkpoolV2
interface IGasSponsorV2 {
    // ------------------
    // | ERROR MESSAGES |
    // ------------------

    /// @notice Thrown when a sponsorship nonce has already been used
    error NonceAlreadyUsed();
    /// @notice Thrown when the signature length is invalid
    error InvalidSignatureLength();
    /// @notice Thrown when the signature is invalid
    error InvalidSignature();
    /// @notice Thrown when an address parameter is zero
    error AddressZero();

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

    // ----------------------
    // | EXTERNAL FUNCTIONS |
    // ----------------------

    /// @notice Initializes the gas sponsor contract with the given darkpool address and auth pubkey
    /// @param initialOwner The initial owner of the gas sponsor contract
    /// @param _darkpoolAddress The address of the DarkpoolV2 proxy contract
    /// @param _authAddress The public key used to authenticate gas sponsorship
    function initialize(address initialOwner, address _darkpoolAddress, address _authAddress) external;

    /// @notice Rotates the auth address to the given new address
    /// @param newAuthAddress The new auth address
    function rotateAuthAddress(address newAuthAddress) external;

    /// @notice Pauses the gas sponsor contract
    function pause() external;

    /// @notice Unpauses the gas sponsor contract
    function unpause() external;

    /// @notice Withdraws ETH from the gas sponsor contract to the given receiver
    /// @param receiver The address to receive the ETH
    /// @param amount The amount of ETH to withdraw
    function withdrawEth(address receiver, uint256 amount) external;

    /// @notice Withdraws ERC20 tokens from the gas sponsor contract to the given receiver
    /// @param receiver The address to receive the tokens
    /// @param token The token address
    /// @param amount The amount of tokens to withdraw
    function withdrawTokens(address receiver, address token, uint256 amount) external;

    /// @notice Sponsor the gas costs of an external match settlement on DarkpoolV2
    /// @param externalPartyAmountIn The input amount for the trade from the external party
    /// @param recipient The address to receive the output tokens (0 = msg.sender)
    /// @param matchResult The bounded match result parameters
    /// @param internalPartySettlementBundle The settlement bundle for the internal party
    /// @param refundAddress The address to refund gas costs to
    /// @param refundNativeEth Whether to refund gas costs in native ETH
    /// @param refundAmount The amount to refund
    /// @param nonce A unique nonce for this sponsorship
    /// @param signature The signature authorizing the sponsorship
    /// @return receivedAmount The amount received by the external party
    function sponsorExternalMatchSettle(
        uint256 externalPartyAmountIn,
        address recipient,
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
        returns (uint256 receivedAmount);

    // -----------
    // | GETTERS |
    // -----------

    /// @notice Returns the address of the DarkpoolV2 proxy contract
    function darkpoolAddress() external view returns (address);

    /// @notice Returns the public key used to authenticate gas sponsorship
    function authAddress() external view returns (address);

    /// @notice Returns whether a nonce has been used
    /// @param nonce The nonce to check
    function usedNonces(uint256 nonce) external view returns (bool);
}
