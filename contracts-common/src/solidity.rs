//! Solidity type definitions used throughout the project

#![allow(missing_docs)]

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

    /// The Permit2 witness type used in a deposit
    struct DepositWitness {
        /// The root public key of the wallet receiving the deposit
        uint256[4] pkRoot;
    }

    /// The signed permit message for a single token transfer
    ///
    /// NOTE: This differs from the `PermitTransferFrom` struct in the `ISignatureTransfer` interface
    /// in the following ways:
    /// - It is named `PermitWitnessTransferFrom`, which is indicated to be the proper EIP-712 type name
    ///   by the [_PERMIT_TRANSFER_FROM_WITNESS_TYPEHASH_STUB](https://github.com/Uniswap/permit2/blob/main/src/libraries/PermitHash.sol#L31)
    ///   in the Permit2 contract source code.
    /// - It includes the `spender` and `witness` fields, which are signed and thus must be included in the
    ///   EIP-712 hash, but are not included in the Solidity definition of the  `PermitTransferFrom` struct
    ///   (as these fields are injected by the Permit2 contract).
    struct PermitWitnessTransferFrom {
        /// The token permissions for the transfer
        TokenPermissions permitted;
        /// The address to which the transfer is made
        address spender;
        /// a unique value for every token owner's signature to prevent signature replays
        uint256 nonce;
        /// deadline on the permit signature
        uint256 deadline;
        /// The witness for the transfer
        DepositWitness witness;
    }

    /// The permit message for a single token transfer
    ///
    /// This exactly matches the `PermitTransferFrom` struct in the `ISignatureTransfer` interface,
    /// and is what's expected as an argument to the `permitWitnessTransferFrom` method. It must be named
    /// differently so that the `PermitTransferFrom` name can be used in the EIP712 type hash of the
    /// struct above.
    struct CalldataPermitWitnessTransferFrom {
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
    /// Includes extra data provided by the caller to verify signature over
    /// The witness type string must follow EIP712 ordering of nested structs and must include the TokenPermissions type definition
    /// Reverts if the requested amount is greater than the permitted signed amount
    /// permit The permit data signed over by the owner
    /// owner The owner of the tokens to transfer
    /// transferDetails The spender's requested transfer details for the permitted token
    /// witness Extra data to include when checking the user signature
    /// witnessTypeString The EIP-712 type definition for remaining string stub of the typehash
    /// signature The signature to verify
    function permitWitnessTransferFrom(
        CalldataPermitWitnessTransferFrom memory permit,
        SignatureTransferDetails calldata transferDetails,
        address owner,
        bytes32 witness,
        string calldata witnessTypeString,
        bytes calldata signature
    ) external;
}
