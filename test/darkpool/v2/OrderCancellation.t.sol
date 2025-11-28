// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { BN254 } from "solidity-bn254/BN254.sol";

import { DarkpoolV2TestUtils } from "./DarkpoolV2TestUtils.sol";
import { OrderCancellationProofBundle } from "darkpoolv2-types/ProofBundles.sol";
import { OrderCancellationAuth } from "darkpoolv2-types/OrderCancellation.sol";
import { ValidOrderCancellationStatement } from "darkpoolv2-lib/public_inputs/OrderCancellation.sol";
import { EfficientHashLib } from "solady/utils/EfficientHashLib.sol";
import { DarkpoolV2 } from "darkpoolv2-contracts/DarkpoolV2.sol";
import { NullifierLib } from "renegade-lib/NullifierSet.sol";

/// @title OrderCancellationTest
/// @notice Tests for the order cancellation functionality in DarkpoolV2
contract OrderCancellationTest is DarkpoolV2TestUtils {
    function setUp() public override {
        super.setUp();
    }

    // -----------
    // | Helpers |
    // -----------

    /// @notice Generate random order cancellation calldata (auth + proof bundle)
    /// @return auth The order cancellation authorization
    /// @return proofBundle The order cancellation proof bundle
    function generateRandomOrderCancellationCalldata()
        internal
        returns (OrderCancellationAuth memory auth, OrderCancellationProofBundle memory proofBundle)
    {
        proofBundle = createOrderCancellationProofBundle();
        auth = createOrderCancellationAuth(proofBundle.statement.oldIntentNullifier);
    }

    /// @notice Create an order cancellation auth for testing
    /// @param intentNullifier The intent nullifier to sign
    function createOrderCancellationAuth(BN254.ScalarField intentNullifier)
        internal
        view
        returns (OrderCancellationAuth memory)
    {
        // Sign the intent nullifier
        bytes32 nullifierHash = EfficientHashLib.hash(BN254.ScalarField.unwrap(intentNullifier));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(intentOwner.privateKey, nullifierHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        return OrderCancellationAuth({ signature: signature });
    }

    /// @notice Create an order cancellation proof bundle for testing
    function createOrderCancellationProofBundle() internal returns (OrderCancellationProofBundle memory) {
        BN254.ScalarField merkleRoot = randomScalar();
        BN254.ScalarField oldIntentNullifier = randomScalar();
        address owner = intentOwner.addr;

        ValidOrderCancellationStatement memory statement = ValidOrderCancellationStatement({
            merkleRoot: merkleRoot,
            oldIntentNullifier: oldIntentNullifier,
            owner: owner
        });

        return OrderCancellationProofBundle({ statement: statement, proof: createDummyProof() });
    }

    /// @notice Create an order cancellation auth with wrong signer
    /// @param intentNullifier The intent nullifier to sign
    function createOrderCancellationAuthWrongSigner(BN254.ScalarField intentNullifier)
        internal
        view
        returns (OrderCancellationAuth memory)
    {
        // Sign the intent nullifier with wrong signer
        bytes32 nullifierHash = EfficientHashLib.hash(BN254.ScalarField.unwrap(intentNullifier));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(wrongSigner.privateKey, nullifierHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        return OrderCancellationAuth({ signature: signature });
    }

    // ---------
    // | Tests |
    // ---------

    /// @notice Test a successful order cancellation
    function test_orderCancellation_success() public {
        // Generate test data
        (OrderCancellationAuth memory auth, OrderCancellationProofBundle memory proofBundle) =
            generateRandomOrderCancellationCalldata();
        BN254.ScalarField intentNullifier = proofBundle.statement.oldIntentNullifier;

        // Check that the nullifier is spent only in the cancellation
        assertFalse(darkpool.nullifierSpent(intentNullifier), "Nullifier should not be spent before cancellation");
        darkpool.cancelOrder(auth, proofBundle);
        assertTrue(darkpool.nullifierSpent(intentNullifier), "Nullifier should be spent after cancellation");
    }

    /// @notice Test that a nullifier cannot be reused
    function test_orderCancellation_duplicateNullifier() public {
        // Generate test data
        (OrderCancellationAuth memory auth, OrderCancellationProofBundle memory proofBundle) =
            generateRandomOrderCancellationCalldata();

        // Execute the cancellation once
        darkpool.cancelOrder(auth, proofBundle);

        // Try to execute the same cancellation again with the same nullifier
        // Should revert because the nullifier is already spent
        vm.expectRevert(NullifierLib.NullifierAlreadySpent.selector);
        darkpool.cancelOrder(auth, proofBundle);
    }

    /// @notice Test order cancellation with invalid signature
    function test_orderCancellation_invalidSignature() public {
        // Generate test data
        OrderCancellationProofBundle memory proofBundle = createOrderCancellationProofBundle();
        BN254.ScalarField intentNullifier = proofBundle.statement.oldIntentNullifier;

        // Create auth with wrong signer
        OrderCancellationAuth memory auth = createOrderCancellationAuthWrongSigner(intentNullifier);

        // Should revert due to invalid signature
        vm.expectRevert(DarkpoolV2.InvalidOrderCancellationSignature.selector);
        darkpool.cancelOrder(auth, proofBundle);
    }
}
