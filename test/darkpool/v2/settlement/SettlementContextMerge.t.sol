// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import { Test } from "forge-std/Test.sol";
import { BN254 } from "solidity-bn254/BN254.sol";
import { BN254Helpers } from "renegade-lib/verifier/BN254Helpers.sol";
import {
    PlonkProof,
    VerificationKey,
    LinkingProof,
    ProofLinkingInstance,
    ProofLinkingVK
} from "renegade-lib/verifier/Types.sol";
import { SettlementContext, SettlementContextLib } from "darkpoolv2-types/settlement/SettlementContext.sol";
import { SimpleTransfer, SimpleTransferType } from "darkpoolv2-types/transfers/SimpleTransfer.sol";
import { SignedPermitSingle } from "darkpoolv2-types/transfers/SignedPermitSingle.sol";
import { IAllowanceTransfer } from "permit2-lib/interfaces/IAllowanceTransfer.sol";
import {
    SettlementTransfers,
    SettlementTransfersLib,
    SettlementTransfersList,
    SettlementTransfersListLib
} from "darkpoolv2-types/transfers/TransfersList.sol";
import {
    VerificationList,
    VerificationListLib,
    ProofLinkingList,
    ProofLinkingListLib
} from "darkpoolv2-types/VerificationList.sol";

/// @title SettlementContextMergeTest
/// @notice Tests for the SettlementContext merge functionality
contract SettlementContextMergeTest is Test {
    using SettlementContextLib for SettlementContext;
    using SettlementTransfersLib for SettlementTransfers;
    using SettlementTransfersListLib for SettlementTransfersList;
    using VerificationListLib for VerificationList;
    using ProofLinkingListLib for ProofLinkingList;

    // --- Helpers --- //

    /// @notice Create a dummy simple transfer for testing
    /// @param account The account address
    /// @param mint The token address
    /// @param amount The amount
    function createDummyTransfer(
        address account,
        address mint,
        uint256 amount
    )
        internal
        pure
        returns (SimpleTransfer memory)
    {
        return SimpleTransfer({
            account: account,
            mint: mint,
            amount: amount,
            transferType: SimpleTransferType.Withdrawal,
            allowancePermit: _emptyPermit()
        });
    }

    /// @notice Create an empty permit for testing
    function _emptyPermit() internal pure returns (SignedPermitSingle memory) {
        return SignedPermitSingle({
            permitSingle: IAllowanceTransfer.PermitSingle({
                details: IAllowanceTransfer.PermitDetails({ token: address(0), amount: 0, expiration: 0, nonce: 0 }),
                spender: address(0),
                sigDeadline: 0
            }),
            signature: ""
        });
    }

    /// @notice Create a dummy PlonkProof for testing
    function createDummyProof() internal pure returns (PlonkProof memory) {
        BN254.G1Point memory pointZero = BN254.P1();

        BN254.G1Point[5] memory wireComms;
        BN254.G1Point[5] memory quotientComms;
        BN254.ScalarField[5] memory wireEvals;
        BN254.ScalarField[4] memory sigmaEvals;

        for (uint256 i = 0; i < 5; i++) {
            wireComms[i] = pointZero;
            quotientComms[i] = pointZero;
            wireEvals[i] = BN254Helpers.ZERO;
            if (i < 4) {
                sigmaEvals[i] = BN254Helpers.ZERO;
            }
        }

        return PlonkProof({
            wireComms: wireComms,
            zComm: pointZero,
            quotientComms: quotientComms,
            wZeta: pointZero,
            wZetaOmega: pointZero,
            wireEvals: wireEvals,
            sigmaEvals: sigmaEvals,
            zBar: BN254Helpers.ZERO
        });
    }

    /// @notice Create a dummy VerificationKey for testing
    function createDummyVk() internal pure returns (VerificationKey memory) {
        BN254.G1Point memory g1Zero = BN254.P1();
        BN254.G2Point memory g2Zero = BN254.P2();

        // NUM_WIRE_TYPES = 5, NUM_SELECTORS = 13
        BN254.ScalarField[5] memory k;
        BN254.G1Point[13] memory qComms;
        BN254.G1Point[5] memory sigmaComms;

        for (uint256 i = 0; i < 5; i++) {
            k[i] = BN254Helpers.ZERO;
            sigmaComms[i] = g1Zero;
        }
        for (uint256 i = 0; i < 13; i++) {
            qComms[i] = g1Zero;
        }

        return VerificationKey({
            n: 1024,
            l: 10,
            k: k,
            qComms: qComms,
            sigmaComms: sigmaComms,
            g: g1Zero,
            h: g2Zero,
            xH: g2Zero
        });
    }

    /// @notice Create a dummy LinkingProof for testing
    function createDummyLinkingProof() internal pure returns (LinkingProof memory) {
        BN254.G1Point memory pointZero = BN254.P1();
        return LinkingProof({ linkingQuotientPolyComm: pointZero, linkingPolyOpening: pointZero });
    }

    /// @notice Create a dummy ProofLinkingInstance for testing
    function createDummyProofLinkingInstance() internal pure returns (ProofLinkingInstance memory) {
        BN254.G1Point memory pointZero = BN254.P1();
        return ProofLinkingInstance({
            wireComm0: pointZero,
            wireComm1: pointZero,
            proof: createDummyLinkingProof(),
            vk: ProofLinkingVK({ linkGroupGenerator: BN254Helpers.ZERO, linkGroupOffset: 0, linkGroupSize: 0 })
        });
    }

    // --- Basic Merge Tests --- //

    /// @notice Test merging two empty contexts
    function test_mergeEmptyContexts() public pure {
        SettlementContext memory a = SettlementContextLib.newContext(0, 0, 0, 0);
        SettlementContext memory b = SettlementContextLib.newContext(0, 0, 0, 0);

        SettlementContext memory merged = SettlementContextLib.merge(a, b);

        assertEq(merged.numDeposits(), 0);
        assertEq(merged.numWithdrawals(), 0);
        assertEq(merged.numProofs(), 0);
        assertEq(merged.numProofLinkingArguments(), 0);
    }

    /// @notice Test merging contexts with deposits and withdrawals
    function test_mergeTransfers() public {
        // Create context a with 2 deposits
        SettlementContext memory a = SettlementContextLib.newContext(2, 0, 0, 0);
        SimpleTransfer memory deposit1 = createDummyTransfer(address(1), address(100), 1000);
        SimpleTransfer memory deposit2 = createDummyTransfer(address(2), address(200), 2000);
        a.pushDeposit(deposit1);
        a.pushDeposit(deposit2);

        // Create context b with 1 deposit and 2 withdrawals
        SettlementContext memory b = SettlementContextLib.newContext(1, 2, 0, 0);
        SimpleTransfer memory deposit3 = createDummyTransfer(address(3), address(300), 3000);
        SimpleTransfer memory withdrawal1 = createDummyTransfer(address(4), address(400), 4000);
        SimpleTransfer memory withdrawal2 = createDummyTransfer(address(5), address(500), 5000);
        b.pushDeposit(deposit3);
        b.pushWithdrawal(withdrawal1);
        b.pushWithdrawal(withdrawal2);

        // Merge and verify
        SettlementContext memory merged = SettlementContextLib.merge(a, b);

        assertEq(merged.numDeposits(), 3);
        assertEq(merged.numWithdrawals(), 2);

        // Verify deposit order (a's deposits first, then b's)
        assertEq(merged.transfers.deposits.transfers[0].account, address(1));
        assertEq(merged.transfers.deposits.transfers[1].account, address(2));
        assertEq(merged.transfers.deposits.transfers[2].account, address(3));

        // Verify withdrawal order
        assertEq(merged.transfers.withdrawals.transfers[0].account, address(4));
        assertEq(merged.transfers.withdrawals.transfers[1].account, address(5));
    }

    /// @notice Test that merge does not modify the original contexts
    function test_mergeDoesNotModifyOriginals() public {
        // Create context a with data
        SettlementContext memory a = SettlementContextLib.newContext(1, 1, 0, 0);
        SimpleTransfer memory deposit = createDummyTransfer(address(1), address(100), 1000);
        SimpleTransfer memory withdrawal = createDummyTransfer(address(2), address(200), 2000);
        a.pushDeposit(deposit);
        a.pushWithdrawal(withdrawal);

        // Create context b with data
        SettlementContext memory b = SettlementContextLib.newContext(1, 0, 0, 0);
        SimpleTransfer memory deposit2 = createDummyTransfer(address(3), address(300), 3000);
        b.pushDeposit(deposit2);

        // Store original lengths
        uint256 aDepositsLen = a.numDeposits();
        uint256 aWithdrawalsLen = a.numWithdrawals();
        uint256 bDepositsLen = b.numDeposits();

        // Merge
        SettlementContext memory merged = SettlementContextLib.merge(a, b);

        // Verify originals are unchanged
        assertEq(a.numDeposits(), aDepositsLen);
        assertEq(a.numWithdrawals(), aWithdrawalsLen);
        assertEq(b.numDeposits(), bDepositsLen);

        // Verify merged has combined data
        assertEq(merged.numDeposits(), aDepositsLen + bDepositsLen);
        assertEq(merged.numWithdrawals(), aWithdrawalsLen);
    }

    /// @notice Test merging a full context with an empty context
    function test_mergeWithEmptyContext() public {
        // Create a context with data
        SettlementContext memory a = SettlementContextLib.newContext(2, 1, 0, 0);
        a.pushDeposit(createDummyTransfer(address(1), address(100), 1000));
        a.pushDeposit(createDummyTransfer(address(2), address(200), 2000));
        a.pushWithdrawal(createDummyTransfer(address(3), address(300), 3000));

        // Create empty context
        SettlementContext memory b = SettlementContextLib.newContext(0, 0, 0, 0);

        // Merge a with empty b
        SettlementContext memory merged = SettlementContextLib.merge(a, b);

        assertEq(merged.numDeposits(), 2);
        assertEq(merged.numWithdrawals(), 1);

        // Merge empty b with a
        SettlementContext memory merged2 = SettlementContextLib.merge(b, a);

        assertEq(merged2.numDeposits(), 2);
        assertEq(merged2.numWithdrawals(), 1);
    }

    /// @notice Test merging three contexts together (simulating obligation + party0 + party1)
    function test_mergeThreeContexts() public {
        // Create obligation context (e.g., with proof for private obligations)
        SettlementContext memory obligationCtx = SettlementContextLib.newContext(0, 0, 0, 0);

        // Create party0 context
        SettlementContext memory party0Ctx = SettlementContextLib.newContext(1, 2, 0, 0);
        party0Ctx.pushDeposit(createDummyTransfer(address(10), address(100), 1000));
        party0Ctx.pushWithdrawal(createDummyTransfer(address(11), address(100), 900));
        party0Ctx.pushWithdrawal(createDummyTransfer(address(12), address(100), 100));

        // Create party1 context
        SettlementContext memory party1Ctx = SettlementContextLib.newContext(1, 2, 0, 0);
        party1Ctx.pushDeposit(createDummyTransfer(address(20), address(200), 2000));
        party1Ctx.pushWithdrawal(createDummyTransfer(address(21), address(200), 1800));
        party1Ctx.pushWithdrawal(createDummyTransfer(address(22), address(200), 200));

        // Merge all three (simulating the settleMatch flow)
        SettlementContext memory merged =
            SettlementContextLib.merge(obligationCtx, SettlementContextLib.merge(party0Ctx, party1Ctx));

        // Verify totals
        assertEq(merged.numDeposits(), 2);
        assertEq(merged.numWithdrawals(), 4);

        // Verify order: party0 deposits first, then party1 deposits
        assertEq(merged.transfers.deposits.transfers[0].account, address(10));
        assertEq(merged.transfers.deposits.transfers[1].account, address(20));

        // Verify withdrawal order
        assertEq(merged.transfers.withdrawals.transfers[0].account, address(11));
        assertEq(merged.transfers.withdrawals.transfers[1].account, address(12));
        assertEq(merged.transfers.withdrawals.transfers[2].account, address(21));
        assertEq(merged.transfers.withdrawals.transfers[3].account, address(22));
    }

    /// @notice Test merging contexts with proofs and proof linking arguments
    /// @dev This simulates a RENEGADE_SETTLED_PRIVATE_FILL match where both parties have proofs and linking args
    function test_mergeWithProofsAndLinking() public {
        // Create obligation context with 1 settlement proof (for private obligations)
        SettlementContext memory obligationCtx = SettlementContextLib.newContext(0, 0, 1, 0);
        BN254.ScalarField[] memory obligationPublicInputs = new BN254.ScalarField[](2);
        obligationPublicInputs[0] = BN254.ScalarField.wrap(100);
        obligationPublicInputs[1] = BN254.ScalarField.wrap(200);
        obligationCtx.pushProof(obligationPublicInputs, createDummyProof(), createDummyVk());

        // Create party0 context with 2 proofs and 1 proof linking argument
        // (simulating validity proof + output balance proof with linking between them)
        SettlementContext memory party0Ctx = SettlementContextLib.newContext(0, 2, 2, 1);
        party0Ctx.pushWithdrawal(createDummyTransfer(address(11), address(100), 50)); // relayer fee
        party0Ctx.pushWithdrawal(createDummyTransfer(address(12), address(100), 50)); // protocol fee

        BN254.ScalarField[] memory party0Proof1Inputs = new BN254.ScalarField[](1);
        party0Proof1Inputs[0] = BN254.ScalarField.wrap(1001);
        party0Ctx.pushProof(party0Proof1Inputs, createDummyProof(), createDummyVk());

        BN254.ScalarField[] memory party0Proof2Inputs = new BN254.ScalarField[](1);
        party0Proof2Inputs[0] = BN254.ScalarField.wrap(1002);
        party0Ctx.pushProof(party0Proof2Inputs, createDummyProof(), createDummyVk());

        party0Ctx.pushProofLinkingArgument(createDummyProofLinkingInstance());

        // Create party1 context with 2 proofs and 1 proof linking argument
        SettlementContext memory party1Ctx = SettlementContextLib.newContext(0, 2, 2, 1);
        party1Ctx.pushWithdrawal(createDummyTransfer(address(21), address(200), 100)); // relayer fee
        party1Ctx.pushWithdrawal(createDummyTransfer(address(22), address(200), 100)); // protocol fee

        BN254.ScalarField[] memory party1Proof1Inputs = new BN254.ScalarField[](1);
        party1Proof1Inputs[0] = BN254.ScalarField.wrap(2001);
        party1Ctx.pushProof(party1Proof1Inputs, createDummyProof(), createDummyVk());

        BN254.ScalarField[] memory party1Proof2Inputs = new BN254.ScalarField[](1);
        party1Proof2Inputs[0] = BN254.ScalarField.wrap(2002);
        party1Ctx.pushProof(party1Proof2Inputs, createDummyProof(), createDummyVk());

        party1Ctx.pushProofLinkingArgument(createDummyProofLinkingInstance());

        // Merge all three contexts (exactly as settleMatch does)
        SettlementContext memory merged =
            SettlementContextLib.merge(obligationCtx, SettlementContextLib.merge(party0Ctx, party1Ctx));

        // Verify totals
        assertEq(merged.numDeposits(), 0);
        assertEq(merged.numWithdrawals(), 4); // 2 from party0 + 2 from party1
        assertEq(merged.numProofs(), 5); // 1 from obligation + 2 from party0 + 2 from party1
        assertEq(merged.numProofLinkingArguments(), 2); // 1 from party0 + 1 from party1

        // Verify proof order (obligation first, then party0, then party1)
        assertEq(
            BN254.ScalarField.unwrap(merged.verifications.publicInputs[0][0]), 100, "First proof should be obligation"
        );
        assertEq(
            BN254.ScalarField.unwrap(merged.verifications.publicInputs[1][0]), 1001, "Second proof should be party0 #1"
        );
        assertEq(
            BN254.ScalarField.unwrap(merged.verifications.publicInputs[2][0]), 1002, "Third proof should be party0 #2"
        );
        assertEq(
            BN254.ScalarField.unwrap(merged.verifications.publicInputs[3][0]), 2001, "Fourth proof should be party1 #1"
        );
        assertEq(
            BN254.ScalarField.unwrap(merged.verifications.publicInputs[4][0]), 2002, "Fifth proof should be party1 #2"
        );

        // Verify withdrawal order
        assertEq(merged.transfers.withdrawals.transfers[0].account, address(11));
        assertEq(merged.transfers.withdrawals.transfers[1].account, address(12));
        assertEq(merged.transfers.withdrawals.transfers[2].account, address(21));
        assertEq(merged.transfers.withdrawals.transfers[3].account, address(22));
    }

    // --- Cross-Boundary Merge Tests --- //

    /// @notice Test merging contexts across external call boundaries
    /// @dev This simulates how the settlement flow works with external library calls
    function test_mergeAcrossExternalBoundary() public {
        // Create a context in this contract
        SettlementContext memory localContext = SettlementContextLib.newContext(1, 0, 0, 0);
        localContext.pushDeposit(createDummyTransfer(address(1), address(100), 1000));

        // Call an external function that creates and returns its own context
        SettlementContext memory externalContext = this.externalCreateContext();

        // Merge the two contexts
        SettlementContext memory merged = SettlementContextLib.merge(localContext, externalContext);

        // Verify the merged context has data from both
        assertEq(merged.numDeposits(), 2); // 1 local + 1 from external
        assertEq(merged.numWithdrawals(), 2); // 2 from external
        assertEq(merged.transfers.deposits.transfers[0].account, address(1)); // local deposit
        assertEq(merged.transfers.deposits.transfers[1].account, address(10)); // external deposit
    }

    /// @notice External function that allocates and returns a settlement context
    /// @dev Simulates how NativeSettledPublicIntentLib.execute works with external visibility
    function externalCreateContext() external view returns (SettlementContext memory) {
        SettlementContext memory ctx = SettlementContextLib.newContext(1, 2, 0, 0);
        ctx.pushDeposit(createDummyTransfer(address(10), address(100), 1000));
        ctx.pushWithdrawal(createDummyTransfer(address(11), address(100), 800));
        ctx.pushWithdrawal(createDummyTransfer(address(12), address(100), 200));
        return ctx;
    }

    /// @notice Test merging multiple contexts from external calls (simulating full settlement flow)
    function test_mergeMultipleExternalContexts() public {
        // Simulate: obligation context (from validateObligationBundle)
        SettlementContext memory obligationContext = SettlementContextLib.newContext(0, 0, 0, 0);

        // Simulate: party0 context (from executeSettlementBundle -> NativeSettledPublicIntentLib.execute)
        SettlementContext memory party0Context = this.externalCreateParty0Context();

        // Simulate: party1 context (from executeSettlementBundle -> RenegadeSettledPrivateIntentLib.execute)
        SettlementContext memory party1Context = this.externalCreateParty1Context();

        // Merge all three (exactly as settleMatch does)
        SettlementContext memory merged =
            SettlementContextLib.merge(obligationContext, SettlementContextLib.merge(party0Context, party1Context));

        // Verify combined counts
        assertEq(merged.numDeposits(), 2); // 1 from party0 + 1 from party1
        assertEq(merged.numWithdrawals(), 4); // 2 from party0 + 2 from party1

        // Verify order is preserved (party0 first, then party1)
        assertEq(merged.transfers.deposits.transfers[0].account, address(100)); // party0 deposit
        assertEq(merged.transfers.deposits.transfers[1].account, address(200)); // party1 deposit
        assertEq(merged.transfers.withdrawals.transfers[0].account, address(101)); // party0 withdrawal
        assertEq(merged.transfers.withdrawals.transfers[1].account, address(102)); // party0 withdrawal
        assertEq(merged.transfers.withdrawals.transfers[2].account, address(201)); // party1 withdrawal
        assertEq(merged.transfers.withdrawals.transfers[3].account, address(202)); // party1 withdrawal
    }

    /// @notice External helper to create party0 context
    function externalCreateParty0Context() external view returns (SettlementContext memory) {
        SettlementContext memory ctx = SettlementContextLib.newContext(1, 2, 0, 0);
        ctx.pushDeposit(createDummyTransfer(address(100), address(10), 1000));
        ctx.pushWithdrawal(createDummyTransfer(address(101), address(20), 900));
        ctx.pushWithdrawal(createDummyTransfer(address(102), address(20), 100));
        return ctx;
    }

    /// @notice External helper to create party1 context
    function externalCreateParty1Context() external view returns (SettlementContext memory) {
        SettlementContext memory ctx = SettlementContextLib.newContext(1, 2, 0, 0);
        ctx.pushDeposit(createDummyTransfer(address(200), address(20), 2000));
        ctx.pushWithdrawal(createDummyTransfer(address(201), address(10), 1800));
        ctx.pushWithdrawal(createDummyTransfer(address(202), address(10), 200));
        return ctx;
    }
}
