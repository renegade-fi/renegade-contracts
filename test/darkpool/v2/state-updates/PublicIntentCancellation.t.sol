// SPDX-License-Identifier: MIT
/* solhint-disable gas-small-strings */
/* solhint-disable func-name-mixedcase */
pragma solidity ^0.8.24;

import { stdStorage, StdStorage } from "forge-std/Test.sol";
import { DarkpoolV2TestUtils } from "../DarkpoolV2TestUtils.sol";
import { OrderCancellationAuth } from "darkpoolv2-types/OrderCancellation.sol";
import { Intent } from "darkpoolv2-types/Intent.sol";
import { SignatureWithNonce } from "darkpoolv2-types/settlement/SignatureWithNonce.sol";
import { PublicIntentPermit, PublicIntentPermitLib } from "darkpoolv2-types/settlement/IntentBundle.sol";
import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";
import { IDarkpoolV2 } from "darkpoolv2-interfaces/IDarkpoolV2.sol";
import { DarkpoolStateLib } from "darkpoolv2-lib/DarkpoolState.sol";
import { DarkpoolConstants } from "darkpoolv2-lib/Constants.sol";

/// @title PublicIntentCancellationTest
/// @author Renegade Eng
/// @notice Tests for the public intent cancellation functionality in DarkpoolV2
contract PublicIntentCancellationTest is DarkpoolV2TestUtils {
    using PublicIntentPermitLib for PublicIntentPermit;
    using stdStorage for StdStorage;

    /// @notice Set up the test environment
    function setUp() public override {
        super.setUp();
    }

    // -----------
    // | Helpers |
    // -----------

    /// @notice Set the open intent amount directly in storage
    /// @param intentHash The intent hash
    /// @param amount The amount to set
    function _setOpenIntentAmount(bytes32 intentHash, uint256 amount) internal {
        stdstore.target(address(darkpool)).sig("openPublicIntents(bytes32)").with_key(intentHash).checked_write(amount);
    }

    /// @notice Generate a random public intent permit
    /// @return permit The random public intent permit
    function generateRandomPublicIntentPermit() internal returns (PublicIntentPermit memory permit) {
        Intent memory intent = Intent({
            inToken: address(baseToken),
            outToken: address(quoteToken),
            owner: intentOwner.addr,
            minPrice: randomPrice(),
            amountIn: randomUint()
        });

        permit = PublicIntentPermit({ intent: intent, executor: executor.addr });
    }

    /// @notice Create a cancellation auth signed with the given private key
    /// @param permit The permit to cancel
    /// @param privateKey The private key to sign with
    /// @return auth The cancellation authorization
    function _createOrderCancellationAuth(
        PublicIntentPermit memory permit,
        uint256 privateKey
    )
        internal
        returns (OrderCancellationAuth memory auth)
    {
        uint256 nonce = vm.randomUint();
        bytes32 intentHash = permit.computeHash();
        bytes32 cancelDigest = keccak256(abi.encodePacked(DarkpoolConstants.CANCEL_DOMAIN, intentHash));
        bytes32 signatureHash = EfficientHashLib.hash(cancelDigest, bytes32(nonce), bytes32(block.chainid));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, signatureHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        auth = OrderCancellationAuth({ signature: SignatureWithNonce({ nonce: nonce, signature: signature }) });
    }

    /// @notice Create a cancellation auth with correct signature (owner)
    function createOrderCancellationAuth(PublicIntentPermit memory permit)
        internal
        returns (OrderCancellationAuth memory)
    {
        return _createOrderCancellationAuth(permit, intentOwner.privateKey);
    }

    /// @notice Create a cancellation auth with wrong signer
    function createOrderCancellationAuthWrongSigner(PublicIntentPermit memory permit)
        internal
        returns (OrderCancellationAuth memory)
    {
        return _createOrderCancellationAuth(permit, wrongSigner.privateKey);
    }

    /// @notice Create a cancellation auth with a specific nonce value
    /// @param permit The permit to cancel
    /// @param privateKey The private key to sign with
    /// @param nonce The specific nonce value to use
    /// @return auth The cancellation authorization
    function _createOrderCancellationAuthWithNonce(
        PublicIntentPermit memory permit,
        uint256 privateKey,
        uint256 nonce
    )
        internal
        returns (OrderCancellationAuth memory auth)
    {
        bytes32 intentHash = permit.computeHash();
        bytes32 cancelDigest = keccak256(abi.encodePacked(DarkpoolConstants.CANCEL_DOMAIN, intentHash));
        bytes32 signatureHash = EfficientHashLib.hash(cancelDigest, bytes32(nonce), bytes32(block.chainid));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, signatureHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        auth = OrderCancellationAuth({ signature: SignatureWithNonce({ nonce: nonce, signature: signature }) });
    }

    // ---------
    // | Tests |
    // ---------

    /// @notice Test that the same nonce cannot be reused (replay protection)
    function test_cancel_nonceReplay() public {
        // Generate a random permit
        PublicIntentPermit memory permit = generateRandomPublicIntentPermit();

        // Create the cancellation auth
        OrderCancellationAuth memory auth = createOrderCancellationAuth(permit);

        // Execute the cancellation once - should succeed
        darkpool.cancelPublicOrder(auth, permit);

        // Try to execute the same cancellation again with the same nonce
        // Should revert because the nonce is already spent
        vm.expectRevert(DarkpoolStateLib.NonceAlreadySpent.selector);
        darkpool.cancelPublicOrder(auth, permit);
    }

    /// @notice Test public intent cancellation with invalid signature (wrong signer)
    function test_cancel_invalidSignature() public {
        // Generate a random permit
        PublicIntentPermit memory permit = generateRandomPublicIntentPermit();

        // Create auth with wrong signer
        OrderCancellationAuth memory auth = createOrderCancellationAuthWrongSigner(permit);

        // Should revert due to invalid signature
        vm.expectRevert(IDarkpoolV2.InvalidOrderCancellationSignature.selector);
        darkpool.cancelPublicOrder(auth, permit);
    }

    /// @notice Test cancelling an open intent with non-zero amount remaining
    function test_cancel_openIntent() public {
        // Generate a random permit
        PublicIntentPermit memory permit = generateRandomPublicIntentPermit();
        bytes32 intentHash = permit.computeHash();

        // Set a non-zero amount in storage to simulate an open intent
        uint256 openAmount = 1000 ether;
        _setOpenIntentAmount(intentHash, openAmount);

        // Verify the amount was set
        uint256 amountBefore = darkpool.openPublicIntents(intentHash);
        assertEq(amountBefore, openAmount, "Intent should have non-zero amount");

        // Create and execute the cancellation
        OrderCancellationAuth memory auth = createOrderCancellationAuth(permit);
        darkpool.cancelPublicOrder(auth, permit);

        // Amount should now be 0
        uint256 amountAfter = darkpool.openPublicIntents(intentHash);
        assertEq(amountAfter, 0, "Intent amount should be 0 after cancellation");
    }

    /// @notice Test that a signature for one permit cannot cancel a different permit
    function test_cancel_wrongPermit() public {
        // Generate two different permits
        PublicIntentPermit memory permitA = generateRandomPublicIntentPermit();
        PublicIntentPermit memory permitB = generateRandomPublicIntentPermit();

        // Create cancellation auth signed for permit A
        OrderCancellationAuth memory authForA = createOrderCancellationAuth(permitA);

        // Try to cancel permit B using the signature for permit A
        // Should fail because the signature is over the wrong intentHash
        vm.expectRevert(IDarkpoolV2.InvalidOrderCancellationSignature.selector);
        darkpool.cancelPublicOrder(authForA, permitB);
    }

    /// @notice Test that two different users can use the same nonce value (namespaced nonces)
    /// @dev This test demonstrates that the DoS vector from global nonces is fixed
    function test_cancel_sameNonceDifferentUsers() public {
        // Generate two different permits for two different users
        PublicIntentPermit memory permitA = generateRandomPublicIntentPermit();
        PublicIntentPermit memory permitB = generateRandomPublicIntentPermit();
        permitB.intent.owner = wrongSigner.addr;

        // Set up both intents as open (simulate they were created)
        bytes32 intentHashA = permitA.computeHash();
        bytes32 intentHashB = permitB.computeHash();
        uint256 openAmount = 1000 ether;
        _setOpenIntentAmount(intentHashA, openAmount);
        _setOpenIntentAmount(intentHashB, openAmount);

        // Use the same nonce value for both users
        uint256 sharedNonce = 12_345;

        // Create cancellation auths for both users with the same nonce
        // Each auth must be signed by the permit's owner
        OrderCancellationAuth memory authA =
            _createOrderCancellationAuthWithNonce(permitA, intentOwner.privateKey, sharedNonce);
        OrderCancellationAuth memory authB =
            _createOrderCancellationAuthWithNonce(permitB, wrongSigner.privateKey, sharedNonce);

        // Both cancellations should succeed because nonces are namespaced by signer
        // (Previously, the second cancellation would revert with NonceAlreadySpent)
        darkpool.cancelPublicOrder(authA, permitA);
        darkpool.cancelPublicOrder(authB, permitB);

        // Verify both intents were cancelled
        assertEq(darkpool.openPublicIntents(intentHashA), 0, "Intent A should be cancelled");
        assertEq(darkpool.openPublicIntents(intentHashB), 0, "Intent B should be cancelled");
    }
}
