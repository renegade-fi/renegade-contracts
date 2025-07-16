// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import { DarkpoolExecutor } from "renegade-executor/DarkpoolExecutor.sol";
import { Vm } from "forge-std/Vm.sol";
import { UniswapXExecutorProxy } from "proxies/UniswapXExecutorProxy.sol";
import { IUniswapXExecutor } from "renegade-lib/interfaces/IUniswapXExecutor.sol";
import { IReactorCallback } from "uniswapx/interfaces/IReactorCallback.sol";
import { ResolvedOrder, SignedOrder } from "uniswapx/base/ReactorStructs.sol";
import { ERC20 } from "solmate/src/tokens/ERC20.sol";
import { IPermit2 } from "permit2-lib/interfaces/IPermit2.sol";
import { DarkpoolTestBase } from "test/darkpool/DarkpoolTestBase.sol";
import { BN254 } from "solidity-bn254/BN254.sol";

import { PriorityOrderReactor } from "uniswapx/reactors/PriorityOrderReactor.sol";
import { PriorityOrderLib } from "uniswapx/lib/PriorityOrderLib.sol";
import { PriorityFeeLib } from "uniswapx/lib/PriorityFeeLib.sol";
import {
    PriorityOrder,
    OrderInfo,
    PriorityInput,
    PriorityOutput,
    PriorityCosignerData
} from "uniswapx/lib/PriorityOrderLib.sol";
import { PermitSignature } from "uniswapx-test/util/PermitSignature.sol";
import { IValidationCallback } from "uniswapx/interfaces/IValidationCallback.sol";
import {
    PartyMatchPayload,
    MatchAtomicProofs,
    MatchAtomicLinkingProofs,
    MalleableMatchAtomicProofs,
    ExternalMatchDirection,
    ExternalMatchResult
} from "renegade-lib/darkpool/types/Settlement.sol";
import {
    ValidMatchSettleAtomicStatement,
    ValidMalleableMatchSettleAtomicStatement
} from "renegade-lib/darkpool/PublicInputs.sol";
import { Permit2Lib } from "uniswapx/lib/Permit2Lib.sol";
import { PermitHash } from "permit2/src/libraries/PermitHash.sol";
import { ISignatureTransfer } from "permit2/src/interfaces/ISignatureTransfer.sol";
import { console2 } from "forge-std/console2.sol";
import { SignatureVerification } from "permit2/src/libraries/SignatureVerification.sol";

/// @title UniswapXExecutorTest
/// @notice Test contract for the UniswapXExecutor
/// @dev This contract tests the UniswapXExecutor contract
contract UniswapXExecutorTest is DarkpoolTestBase, PermitSignature {
    using Permit2Lib for ResolvedOrder;
    using PriorityOrderLib for PriorityOrder;
    using PriorityFeeLib for PriorityInput;
    using PriorityFeeLib for PriorityOutput[];
    using PermitHash for ISignatureTransfer.PermitTransferFrom;

    PriorityOrderReactor reactor;
    IUniswapXExecutor executor;

    /// @notice Sets up the test environment
    /// @dev For now we test against a `PriorityOrderReactor`, which is the flavor deployed on Base
    function setUp() public override {
        // Deploy the darkpool and tokens
        super.setUp();
        address protocolFeeOwner = vm.randomAddress();

        // Deploy the reactor
        reactor = new PriorityOrderReactor(permit2, protocolFeeOwner);

        // Initialize the UniswapXExecutorProxy
        DarkpoolExecutor executorImpl = new DarkpoolExecutor();
        UniswapXExecutorProxy executorProxy =
            new UniswapXExecutorProxy(address(executorImpl), darkpoolOwner, address(darkpool), address(reactor));
        executor = IUniswapXExecutor(address(executorProxy));
    }

    /// @notice Test that the owner is set correctly
    function testOwner() public view {
        // Check that the owner is set correctly
        assertEq(executor.owner(), darkpoolOwner);
    }

    /// @notice Test that unauthorized callers are rejected in reactor callback
    function test_reactorCallback_unauthorizedCaller() public {
        bytes memory callbackData = abi.encodeWithSelector(
            darkpool.processAtomicMatchSettle.selector, address(0), address(0), address(0), address(0), address(0)
        );

        ResolvedOrder[] memory resolvedOrders = new ResolvedOrder[](0);

        vm.expectRevert(DarkpoolExecutor.UnauthorizedCaller.selector);
        IReactorCallback(address(executor)).reactorCallback(resolvedOrders, callbackData);
    }

    /// @notice Test atomic match settlement through executeAtomicMatchSettle - external party buy side
    function test_executeAtomicMatchSettle_externalPartyBuySide() public {
        uint256 QUOTE_AMT = 1_000_000;
        uint256 BASE_AMT = 5_000_000;

        // Setup tokens
        quoteToken.mint(address(executor), QUOTE_AMT);
        baseToken.mint(address(darkpool), BASE_AMT);

        // Get initial balances
        uint256 reactorBaseBalance1 = baseToken.balanceOf(address(reactor));
        uint256 reactorQuoteBalance1 = quoteToken.balanceOf(address(reactor));

        // Setup the match
        ExternalMatchResult memory matchResult = ExternalMatchResult({
            quoteMint: address(quoteToken),
            baseMint: address(baseToken),
            quoteAmount: QUOTE_AMT,
            baseAmount: BASE_AMT,
            direction: ExternalMatchDirection.InternalPartySell
        });

        // Setup calldata
        BN254.ScalarField merkleRoot = darkpool.getMerkleRoot();
        (
            PartyMatchPayload memory internalPartyPayload,
            ValidMatchSettleAtomicStatement memory statement,
            MatchAtomicProofs memory proofs,
            MatchAtomicLinkingProofs memory linkingProofs
        ) = settleAtomicMatchCalldataWithMatchResult(merkleRoot, matchResult);
        SignedOrder memory signedOrder = _createSignedOrder(matchResult);

        vm.startBroadcast(address(executor));
        quoteToken.approve(address(darkpool), QUOTE_AMT);

        // Call executeAtomicMatchSettle
        DarkpoolExecutor(address(executor)).executeAtomicMatchSettle(
            signedOrder, internalPartyPayload, statement, proofs, linkingProofs
        );
        vm.stopBroadcast();
    }

    // -----------
    // | Helpers |
    // -----------

    // --- UniswapX Helpers --- //

    /// @notice Creates a dummy signed priority order for a given match result, simulating a user order for UniswapX
    /// execution tests.
    /// @param matchResult The ExternalMatchResult specifying the quote/base tokens and amounts for the order.
    /// @return A SignedOrder struct representing the signed priority order.
    function _createSignedOrder(ExternalMatchResult memory matchResult) internal returns (SignedOrder memory) {
        // Create a dummy user
        Vm.Wallet memory userWallet = randomEthereumWallet();
        console2.log("userWallet", userWallet.addr);

        // Create the input
        PriorityInput memory input = PriorityInput({
            token: ERC20(address(quoteToken)),
            amount: matchResult.quoteAmount,
            mpsPerPriorityFeeWei: 0
        });

        // Create the output
        PriorityOutput memory output = PriorityOutput({
            token: address(baseToken),
            amount: matchResult.baseAmount,
            mpsPerPriorityFeeWei: 0,
            recipient: userWallet.addr
        });
        PriorityOutput[] memory outputs = new PriorityOutput[](1);
        outputs[0] = output;

        // Create the order
        uint256 nonce = randomUint();
        OrderInfo memory info = OrderInfo({
            reactor: reactor,
            swapper: userWallet.addr,
            nonce: nonce,
            deadline: block.timestamp + 1 days,
            additionalValidationContract: IValidationCallback(address(0)),
            additionalValidationData: ""
        });

        // Create the cosigner data
        PriorityCosignerData memory cosignerData = PriorityCosignerData({ auctionTargetBlock: block.number });
        bytes memory cosignature = bytes("");

        // Create the order
        PriorityOrder memory order = PriorityOrder({
            info: info,
            cosigner: address(0),
            auctionStartBlock: block.number,
            baselinePriorityFeeWei: 0,
            input: input,
            outputs: outputs,
            cosignerData: cosignerData,
            cosignature: cosignature
        });

        // Create the permit signature
        SignedOrder memory signedOrder = _signPriorityOrder(userWallet, order);
        return signedOrder;
    }

    /// @notice Constructs and signs a PriorityOrder for the given user and match result, returning a SignedOrder with a
    /// valid Permit2 signature.
    /// @param userWallet The wallet of the user who is signing the order.
    /// @param order The PriorityOrder to sign.
    /// @return signedOrder The SignedOrder with a valid Permit2 signature.
    function _signPriorityOrder(
        Vm.Wallet memory userWallet,
        PriorityOrder memory order
    )
        internal
        returns (SignedOrder memory signedOrder)
    {
        uint256 inputAmount = order.input.amount;
        address inputToken = address(order.input.token);
        ISignatureTransfer.PermitTransferFrom memory permit = ISignatureTransfer.PermitTransferFrom({
            permitted: ISignatureTransfer.TokenPermissions({ token: inputToken, amount: inputAmount }),
            nonce: order.info.nonce,
            deadline: order.info.deadline
        });

        bytes32 witness = order.hash();
        bytes32 domainSeparator = permit2.DOMAIN_SEPARATOR();
        bytes memory sig = getPermitWitnessTransferSignature(
            permit, address(reactor), userWallet.privateKey, PRIORITY_ORDER_TYPE_HASH, witness, domainSeparator
        );

        // Create the signed order
        signedOrder = SignedOrder({ order: abi.encode(order), sig: sig });
        return signedOrder;
    }
}
