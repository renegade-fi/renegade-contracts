// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { BN254 } from "solidity-bn254/BN254.sol";
import { DarkpoolTestBase } from "./DarkpoolTestBase.sol";
import { EncryptionKey } from "renegade-lib/darkpool/types/Ciphertext.sol";

contract AdminMethodsTest is DarkpoolTestBase {
    // --- Constants --- //
    bytes4 constant UNAUTHORIZED_ACCOUNT_ERROR = bytes4(keccak256("OwnableUnauthorizedAccount(address)"));

    // --- Admin Methods --- //

    /// @notice Test the owner method
    function test_getOwner() public view {
        assertEq(darkpool.owner(), darkpoolOwner);
    }

    /// @notice Test setting the protocol fee rate
    function test_setProtocolFeeRate() public {
        uint256 newFee = 10;

        // Try without the owner
        vm.expectPartialRevert(UNAUTHORIZED_ACCOUNT_ERROR);
        darkpool.setProtocolFeeRate(newFee);

        // Try to set the fee to zero
        vm.expectRevert("Fee cannot be zero");
        vm.prank(darkpoolOwner);
        darkpool.setProtocolFeeRate(0);

        // Set the new fee
        vm.prank(darkpoolOwner);
        darkpool.setProtocolFeeRate(newFee);
        assertEq(darkpool.protocolFeeRate(), newFee);
    }

    /// @notice Test setting the external match fee rate for a token
    function test_setTokenExternalMatchFeeRate() public {
        address token = vm.randomAddress();
        uint256 newFee = 10;

        // Try without the owner
        vm.expectPartialRevert(UNAUTHORIZED_ACCOUNT_ERROR);
        darkpool.setTokenExternalMatchFeeRate(token, newFee);

        // Set the new fee
        vm.prank(darkpoolOwner);
        darkpool.setTokenExternalMatchFeeRate(token, newFee);
        assertEq(darkpool.getTokenExternalMatchFeeRate(token), newFee);

        // Remove the fee override without the owner
        vm.expectPartialRevert(UNAUTHORIZED_ACCOUNT_ERROR);
        darkpool.removeTokenExternalMatchFeeRate(token);

        // Remove the fee override with the owner
        vm.prank(darkpoolOwner);
        darkpool.removeTokenExternalMatchFeeRate(token);
        assertEq(darkpool.getTokenExternalMatchFeeRate(token), darkpool.protocolFeeRate());
    }

    /// @notice Set the protocol fee encryption key
    function test_setProtocolFeeKey() public {
        uint256 newPubkeyX = 1;
        uint256 newPubkeyY = 2;

        // Try without the owner
        vm.expectPartialRevert(UNAUTHORIZED_ACCOUNT_ERROR);
        darkpool.setProtocolFeeKey(newPubkeyX, newPubkeyY);

        // Set the new key
        vm.prank(darkpoolOwner);
        darkpool.setProtocolFeeKey(newPubkeyX, newPubkeyY);

        EncryptionKey memory key = darkpool.getProtocolFeeKey();
        assertEq(BN254.ScalarField.unwrap(key.point.x), newPubkeyX);
        assertEq(BN254.ScalarField.unwrap(key.point.y), newPubkeyY);
    }

    /// @notice Test setting the protocol fee recipient
    function test_setProtocolFeeRecipient() public {
        address newRecipient = vm.randomAddress();

        // Try without the owner
        vm.expectPartialRevert(UNAUTHORIZED_ACCOUNT_ERROR);
        darkpool.setProtocolFeeRecipient(newRecipient);

        // Set the new recipient
        vm.prank(darkpoolOwner);
        darkpool.setProtocolFeeRecipient(newRecipient);
        assertEq(darkpool.getProtocolFeeRecipient(), newRecipient);
    }
}
