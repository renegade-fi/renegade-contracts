// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import { BN254 } from "solidity-bn254/BN254.sol";
import { PublicRootKey } from "./Types.sol";
import { IHasher } from "../poseidon2/IHasher.sol";
import { console2 } from "forge-std/console2.sol";

// --- Helpers --- //

/// @dev Create a uint256 from a pair of BN254.ScalarField words, in little-endian order
function scalarWordsToUint(BN254.ScalarField low, BN254.ScalarField high) pure returns (uint256) {
    return BN254.ScalarField.unwrap(low) + (BN254.ScalarField.unwrap(high) * BN254.R_MOD);
}

/// @dev Split a uint256 into a pair of BN254.ScalarField words, in little-endian order
function uintToScalarWords(uint256 value) pure returns (BN254.ScalarField low, BN254.ScalarField high) {
    low = BN254.ScalarField.wrap(value % BN254.R_MOD);
    high = BN254.ScalarField.wrap(value / BN254.R_MOD);
}

// --- Library --- //

library WalletOperations {
    /// @notice Compute a commitment to a wallet's shares
    function computeWalletCommitment(
        BN254.ScalarField[] memory publicShares,
        BN254.ScalarField privateShareCommitment,
        IHasher hasher
    )
        internal
        view
        returns (BN254.ScalarField)
    {
        uint256[] memory hashInputs = new uint256[](publicShares.length + 1);
        hashInputs[0] = BN254.ScalarField.unwrap(privateShareCommitment);
        for (uint256 i = 1; i <= publicShares.length; i++) {
            hashInputs[i] = BN254.ScalarField.unwrap(publicShares[i - 1]);
        }

        uint256 walletCommitment = hasher.spongeHash(hashInputs);
        return BN254.ScalarField.wrap(walletCommitment);
    }

    /// @notice Verify a wallet update signature
    /// @dev The signature is expected in the following format:
    /// @dev r || s || v, for a total of 65 bytes where:
    /// @dev bytes [0:32] = r
    /// @dev bytes [32:64] = s
    /// @dev bytes [64] = v
    function verifyWalletUpdateSignature(
        BN254.ScalarField walletCommitment,
        bytes calldata newSharesCommitmentSig,
        PublicRootKey memory oldRootKey
    )
        internal
        view
        returns (bool)
    {
        // 1. Hash the wallet commitment
        bytes32 commitmentHash = walletCommitmentDigest(walletCommitment);

        // 2. Verify the signature
        require(newSharesCommitmentSig.length == 65, "Invalid signature length");

        bytes32 r = bytes32(newSharesCommitmentSig[:32]);
        bytes32 s = bytes32(newSharesCommitmentSig[32:64]);
        uint8 v = uint8(newSharesCommitmentSig[64]);
        // Clients (notably ethers) sometimes use v = 0 or 1, the ecrecover precompile expects 27 or 28
        if (v == 0 || v == 1) {
            v += 27;
        }

        // Recover signer address using ecrecover
        address signer = ecrecover(commitmentHash, v, r, s);
        require(signer != address(0), "Invalid signature");

        // Convert oldRootKey to address and compare
        address oldRootKeyAddress = addressFromRootKey(oldRootKey);
        return signer == oldRootKeyAddress;
    }

    /// @notice Get the digest of a wallet commitment
    function walletCommitmentDigest(BN254.ScalarField walletCommitment) internal pure returns (bytes32) {
        bytes32 walletCommitmentBytes = bytes32(BN254.ScalarField.unwrap(walletCommitment));
        return keccak256(abi.encode(walletCommitmentBytes));
    }

    /// @notice Get an ethereum address from a public root key
    function addressFromRootKey(PublicRootKey memory rootKey) internal pure returns (address) {
        uint256 x = scalarWordsToUint(rootKey.x[0], rootKey.x[1]);
        uint256 y = scalarWordsToUint(rootKey.y[0], rootKey.y[1]);
        // Pack x and y into 64 bytes
        bytes memory packed = abi.encodePacked(x, y);

        // Hash and convert last 20 bytes to address
        bytes32 hash = keccak256(packed);
        return address(uint160(uint256(hash)));
    }
}
