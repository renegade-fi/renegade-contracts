// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Vm } from "forge-std/Vm.sol";
import { ERC20Mock } from "oz-contracts/mocks/token/ERC20Mock.sol";
import { BN254 } from "solidity-bn254/BN254.sol";
import { ISignatureTransfer } from "permit2-lib/interfaces/ISignatureTransfer.sol";

import { DarkpoolConstants } from "darkpoolv2-lib/Constants.sol";
import { DarkpoolV2TestUtils } from "./DarkpoolV2TestUtils.sol";
import { DepositProofBundle } from "darkpoolv2-types/ProofBundles.sol";
import { MerkleMountainLib } from "renegade-lib/merkle/MerkleMountain.sol";
import {
    Deposit, DepositAuth, DepositWitness, DEPOSIT_WITNESS_TYPE_STRING
} from "darkpoolv2-types/transfers/Deposit.sol";
import { ExistingBalanceDepositValidityStatement } from "darkpoolv2-lib/PublicInputs.sol";

/// @title DepositTest
/// @notice Tests for the deposit functionality in DarkpoolV2
contract DepositTest is DarkpoolV2TestUtils {
    using MerkleMountainLib for MerkleMountainLib.MerkleMountainRange;

    // Test wallets
    Vm.Wallet internal depositor;
    ERC20Mock internal depositToken;

    // Test state
    MerkleMountainLib.MerkleMountainRange private testMountain;

    function setUp() public override {
        super.setUp();
        depositor = vm.createWallet("depositor");
        depositToken = baseToken;
    }

    // -----------
    // | Helpers |
    // -----------

    /// @notice Generate random deposit calldata (auth + proof bundle)
    /// @return deposit The deposit struct
    /// @return auth The deposit authorization
    /// @return proofBundle The deposit proof bundle
    function generateRandomDepositCalldata()
        internal
        returns (Deposit memory deposit, DepositAuth memory auth, DepositProofBundle memory proofBundle)
    {
        deposit = createTestDeposit();
        proofBundle = createDepositProofBundle(deposit);
        auth = createDepositAuth(deposit, proofBundle.statement.newBalanceCommitment);
        capitalizeDepositor(deposit);
    }

    /// @notice Create a deposit for testing
    function createTestDeposit() internal returns (Deposit memory) {
        uint256 amount = randomAmount();
        return Deposit({ from: depositor.addr, token: address(depositToken), amount: amount });
    }

    /// @notice Create a deposit auth for testing
    function createDepositAuth(
        Deposit memory deposit,
        BN254.ScalarField newBalanceCommitment
    )
        internal
        returns (DepositAuth memory)
    {
        // Generate permit2 params
        uint256 nonce = randomUint();
        uint256 deadline = block.timestamp + 1 days;

        // Build the permit message
        ISignatureTransfer.TokenPermissions memory tokenPermissions =
            ISignatureTransfer.TokenPermissions({ token: deposit.token, amount: deposit.amount });
        ISignatureTransfer.PermitTransferFrom memory permit =
            ISignatureTransfer.PermitTransferFrom({ permitted: tokenPermissions, nonce: nonce, deadline: deadline });
        uint256 commitment = BN254.ScalarField.unwrap(newBalanceCommitment);
        DepositWitness memory witness = DepositWitness({ newBalanceCommitment: commitment });

        // Sign the permit with witness
        bytes32 witnessHash =
            keccak256(abi.encode(keccak256("DepositWitness(uint256 newBalanceCommitment)"), commitment));
        bytes memory signature = signPermit2WitnessTransfer(
            permit, address(darkpool), DEPOSIT_WITNESS_TYPE_STRING, witnessHash, depositor.privateKey
        );

        return DepositAuth({ permit2Nonce: nonce, permit2Deadline: deadline, permit2Signature: signature });
    }

    /// @notice Sign a permit2 witness transfer
    function signPermit2WitnessTransfer(
        ISignatureTransfer.PermitTransferFrom memory permit,
        address spender,
        string memory witnessTypeString,
        bytes32 witness,
        uint256 privateKey
    )
        internal
        view
        returns (bytes memory)
    {
        bytes32 tokenPermissionsHash = keccak256(
            abi.encode(
                keccak256("TokenPermissions(address token,uint256 amount)"),
                permit.permitted.token,
                permit.permitted.amount
            )
        );

        bytes32 msgHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                permit2.DOMAIN_SEPARATOR(),
                keccak256(
                    abi.encode(
                        keccak256(
                            abi.encodePacked(
                                "PermitWitnessTransferFrom(TokenPermissions permitted,address spender,uint256 nonce,uint256 deadline,",
                                witnessTypeString
                            )
                        ),
                        tokenPermissionsHash,
                        spender,
                        permit.nonce,
                        permit.deadline,
                        witness
                    )
                )
            )
        );

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, msgHash);
        return abi.encodePacked(r, s, v);
    }

    /// @notice Create a deposit proof bundle for testing
    function createDepositProofBundle(Deposit memory deposit) internal returns (DepositProofBundle memory) {
        BN254.ScalarField balanceNullifier = randomScalar();
        BN254.ScalarField newBalanceCommitment = randomScalar();
        uint256 merkleDepth = DarkpoolConstants.DEFAULT_MERKLE_DEPTH;
        ExistingBalanceDepositValidityStatement memory statement = ExistingBalanceDepositValidityStatement({
            merkleDepth: merkleDepth,
            deposit: deposit,
            balanceNullifier: balanceNullifier,
            newBalanceCommitment: newBalanceCommitment
        });

        return DepositProofBundle({ statement: statement, proof: createDummyProof() });
    }

    /// @notice Capitalize the depositor's balance
    function capitalizeDepositor(Deposit memory deposit) internal {
        depositToken.mint(depositor.addr, deposit.amount);

        vm.prank(depositor.addr);
        depositToken.approve(address(permit2), deposit.amount);
    }

    // ---------
    // | Tests |
    // ---------

    /// @notice Test a successful deposit
    function test_deposit_success() public {
        // Generate test data
        (Deposit memory deposit, DepositAuth memory auth, DepositProofBundle memory proofBundle) =
            generateRandomDepositCalldata();
        uint256 depositAmount = deposit.amount;

        // Record balances before
        uint256 depositorBalanceBefore = depositToken.balanceOf(depositor.addr);
        uint256 darkpoolBalanceBefore = depositToken.balanceOf(address(darkpool));

        // Execute the deposit
        darkpool.deposit(auth, proofBundle);

        // Check balances after
        uint256 depositorBalanceAfter = depositToken.balanceOf(depositor.addr);
        uint256 darkpoolBalanceAfter = depositToken.balanceOf(address(darkpool));

        assertEq(depositorBalanceAfter, depositorBalanceBefore - depositAmount, "Depositor balance should decrease");
        assertEq(darkpoolBalanceAfter, darkpoolBalanceBefore + depositAmount, "Darkpool balance should increase");

        // Check that the nullifier was spent
        assertTrue(darkpool.nullifierSpent(proofBundle.statement.balanceNullifier), "Balance nullifier should be spent");
    }

    /// @notice Test the Merkle root after a deposit
    function test_deposit_merkleRoot() public {
        // Generate test data
        (Deposit memory deposit, DepositAuth memory auth, DepositProofBundle memory proofBundle) =
            generateRandomDepositCalldata();

        // Execute the deposit
        darkpool.deposit(auth, proofBundle);

        // Check that the Merkle root is in the history
        // Build a parallel merkle tree with the same operation
        uint256 depth = proofBundle.statement.merkleDepth;
        testMountain.insertLeaf(depth, proofBundle.statement.newBalanceCommitment, hasher);
        BN254.ScalarField root = testMountain.getRoot(depth);

        // The root should be in the darkpool's history
        bool rootInHistory = darkpool.rootInHistory(root);
        assertTrue(rootInHistory, "Merkle root should be in history");
    }

    /// @notice Test deposit with zero amount
    function test_deposit_zeroAmount() public {
        // Generate test data
        Deposit memory deposit = Deposit({ from: depositor.addr, token: address(depositToken), amount: 0 });
        DepositProofBundle memory proofBundle = createDepositProofBundle(deposit);
        DepositAuth memory auth = createDepositAuth(deposit, proofBundle.statement.newBalanceCommitment);

        // Should succeed with zero amount
        vm.prank(depositor.addr);
        darkpool.deposit(auth, proofBundle);
    }

    /// @notice Test deposit with insufficient balance
    function test_deposit_insufficientBalance_reverts() public {
        // Generate test data
        (Deposit memory deposit, DepositAuth memory auth, DepositProofBundle memory proofBundle) =
            generateRandomDepositCalldata();

        // Burn the balance of the depositor
        depositToken.burn(depositor.addr, deposit.amount);

        // Should revert due to insufficient balance
        vm.prank(depositor.addr);
        vm.expectRevert();
        darkpool.deposit(auth, proofBundle);
    }
}
