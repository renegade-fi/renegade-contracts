// SPDX-License-Identifier: MIT
/* solhint-disable gas-small-strings */
/* solhint-disable func-name-mixedcase */
pragma solidity ^0.8.24;

import { DarkpoolV2TestUtils } from "../DarkpoolV2TestUtils.sol";
import { SignatureWithNonce } from "darkpoolv2-types/settlement/SignatureWithNonce.sol";
import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";
import { IDarkpoolV2 } from "darkpoolv2-interfaces/IDarkpoolV2.sol";
import { DarkpoolStateLib } from "darkpoolv2-lib/DarkpoolState.sol";
import { DarkpoolConstants } from "darkpoolv2-lib/Constants.sol";

/// @title NonceRevocationTest
/// @author Renegade Eng
/// @notice Tests for the nonce revocation functionality in DarkpoolV2
contract NonceRevocationTest is DarkpoolV2TestUtils {
    // -----------
    // | Helpers |
    // -----------

    /// @notice Create a revocation signature signed with the given private key
    /// @param nonceToRevoke The nonce to revoke
    /// @param privateKey The private key to sign with
    /// @return signature The revocation signature
    function _createRevokeNonceSignature(
        uint256 nonceToRevoke,
        uint256 privateKey
    )
        internal
        returns (SignatureWithNonce memory signature)
    {
        uint256 authNonce = vm.randomUint();
        bytes32 revokeDigest =
            keccak256(abi.encodePacked(DarkpoolConstants.REVOKE_NONCE_DOMAIN, bytes32(nonceToRevoke)));
        bytes32 signatureHash = EfficientHashLib.hash(revokeDigest, bytes32(authNonce), bytes32(block.chainid));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, signatureHash);
        bytes memory sigBytes = abi.encodePacked(r, s, v);
        signature = SignatureWithNonce({ nonce: authNonce, signature: sigBytes });
    }

    /// @notice Create a revocation signature with correct signer (owner)
    /// @param nonceToRevoke The nonce to revoke
    /// @return signature The revocation signature signed by the intent owner
    function createRevokeNonceSignature(uint256 nonceToRevoke) internal returns (SignatureWithNonce memory signature) {
        return _createRevokeNonceSignature(nonceToRevoke, intentOwner.privateKey);
    }

    /// @notice Create a revocation signature with wrong signer
    /// @param nonceToRevoke The nonce to revoke
    /// @return signature The revocation signature signed by the wrong signer
    function createRevokeNonceSignatureWrongSigner(uint256 nonceToRevoke)
        internal
        returns (SignatureWithNonce memory signature)
    {
        return _createRevokeNonceSignature(nonceToRevoke, wrongSigner.privateKey);
    }

    // ---------
    // | Tests |
    // ---------

    /// @notice Test that revoking a nonce succeeds
    function test_revokeNonce_succeeds() public {
        uint256 nonceToRevoke = vm.randomUint();
        SignatureWithNonce memory signature = createRevokeNonceSignature(nonceToRevoke);

        // Execute the revocation - should succeed
        vm.prank(intentOwner.addr);
        darkpool.revokeNonce(intentOwner.addr, nonceToRevoke, signature);

        // Verify nonce is spent by trying to revoke it again (should fail)
        SignatureWithNonce memory signature2 = createRevokeNonceSignature(nonceToRevoke);
        vm.prank(intentOwner.addr);
        vm.expectRevert(DarkpoolStateLib.NonceAlreadySpent.selector);
        darkpool.revokeNonce(intentOwner.addr, nonceToRevoke, signature2);
    }

    /// @notice Test that the same nonce cannot be revoked twice (replay protection)
    function test_revokeNonce_nonceReplay() public {
        uint256 nonceToRevoke = vm.randomUint();
        SignatureWithNonce memory signature = createRevokeNonceSignature(nonceToRevoke);

        // Execute the revocation once - should succeed
        vm.prank(intentOwner.addr);
        darkpool.revokeNonce(intentOwner.addr, nonceToRevoke, signature);

        // Try to revoke the same nonce again - should revert because nonce is already spent
        SignatureWithNonce memory signature2 = createRevokeNonceSignature(nonceToRevoke);
        vm.prank(intentOwner.addr);
        vm.expectRevert(DarkpoolStateLib.NonceAlreadySpent.selector);
        darkpool.revokeNonce(intentOwner.addr, nonceToRevoke, signature2);
    }

    /// @notice Test that revoking a nonce requires the correct owner signature
    function test_revokeNonce_requiresOwnerSignature() public {
        uint256 nonceToRevoke = vm.randomUint();
        SignatureWithNonce memory signature = createRevokeNonceSignatureWrongSigner(nonceToRevoke);

        // Should revert due to invalid signature
        vm.prank(intentOwner.addr);
        vm.expectRevert(IDarkpoolV2.InvalidOrderCancellationSignature.selector);
        darkpool.revokeNonce(intentOwner.addr, nonceToRevoke, signature);
    }
}
