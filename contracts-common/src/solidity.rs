//! Solidity type definitions used throughout the project

#![allow(missing_docs)]

use alloc::vec::Vec;
use alloy_sol_types::sol;

// Types & methods from the Permit2 `ISignatureTransfer` interface, taken from https://github.com/Uniswap/permit2/blob/main/src/interfaces/ISignatureTransfer.sol
sol! {
    /// The token and amount details for a transfer signed in the permit transfer signature
    struct TokenPermissions {
        /// ERC20 token address
        address token;
        /// the maximum amount that can be spent
        uint256 amount;
    }

    /// The signed permit message for a single token transfer
    ///
    /// NOTE: This differs from the `PermitTransferFrom` struct in the `ISignatureTransfer` interface
    /// in that it includes the `spender` field. This field is signed and thus must be included in the
    /// EIP-712 hash, but is not included in the Solidity definition of the  `PermitTransferFrom` struct
    /// (as this field is injected by the Permit2 contract).
    struct PermitTransferFrom {
        /// The token permissions for the transfer
        TokenPermissions permitted;
        /// The address to which the transfer is made
        address spender;
        /// a unique value for every token owner's signature to prevent signature replays
        uint256 nonce;
        /// deadline on the permit signature
        uint256 deadline;
    }

    /// The permit message for a single token transfer
    ///
    /// This exactly matches the `PermitTransferFrom` struct in the `ISignatureTransfer` interface,
    /// and is what's expected as an argument to the `permitTransferFrom` method. It must be named
    /// differently so that the `PermitTransferFrom` name can be used in the EIP712 type hash of the
    /// struct above.
    struct CalldataPermitTransferFrom {
        /// The token permissions for the transfer
        TokenPermissions permitted;
        /// a unique value for every token owner's signature to prevent signature replays
        uint256 nonce;
        /// deadline on the permit signature
        uint256 deadline;
    }

    /// Specifies the recipient address and amount for batched transfers.
    /// Recipients and amounts correspond to the index of the signed token permissions array.
    /// Reverts if the requested amount is greater than the permitted signed amount.
    struct SignatureTransferDetails {
        /// recipient address
        address to;
        /// spender requested amount
        uint256 requestedAmount;
    }

    /// Transfers a token using a signed permit message
    /// Reverts if the requested amount is greater than the permitted signed amount
    /// permit The permit data signed over by the owner
    /// owner The owner of the tokens to transfer
    /// transferDetails The spender's requested transfer details for the permitted token
    /// signature The signature to verify
    function permitTransferFrom(
        CalldataPermitTransferFrom memory permit,
        SignatureTransferDetails calldata transferDetails,
        address owner,
        bytes calldata signature
    ) external;
}
