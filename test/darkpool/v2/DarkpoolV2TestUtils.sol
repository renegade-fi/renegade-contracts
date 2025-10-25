// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Vm } from "forge-std/Vm.sol";
import { DarkpoolV2TestBase } from "./DarkpoolV2TestBase.sol";

import { BN254 } from "solidity-bn254/BN254.sol";
import { BN254Helpers } from "renegade-lib/verifier/BN254Helpers.sol";

import { SettlementObligation } from "darkpoolv2-types/Obligation.sol";
import { Intent } from "darkpoolv2-types/Intent.sol";
import { DarkpoolState } from "darkpoolv2-contracts/DarkpoolV2.sol";

import { PlonkProof } from "renegade-lib/verifier/Types.sol";
import { FixedPoint, FixedPointLib } from "renegade-lib/FixedPoint.sol";

contract DarkpoolV2TestUtils is DarkpoolV2TestBase {
    using FixedPointLib for FixedPoint;

    // Test wallets
    Vm.Wallet internal intentOwner;
    // Party 0 in a simulated trade
    Vm.Wallet internal party0;
    // Party 1 in a simulated trade
    Vm.Wallet internal party1;
    Vm.Wallet internal executor;
    Vm.Wallet internal wrongSigner;

    // Bundled darkpool state for testing
    DarkpoolState internal darkpoolState;

    function setUp() public virtual override {
        super.setUp();

        // Create test wallets
        intentOwner = vm.createWallet("intent_owner");
        party0 = vm.createWallet("party0");
        party1 = vm.createWallet("party1");
        executor = vm.createWallet("executor");
        wrongSigner = vm.createWallet("wrong_signer");
    }

    // --- Dummy Data --- //

    /// @dev Create a dummy intent
    function createSampleIntent() internal returns (Intent memory) {
        (Intent memory intent,) = createSampleIntentAndObligation();
        return intent;
    }

    /// @dev Create a sample intent and settlement obligation
    function createSampleIntentAndObligation() internal returns (Intent memory, SettlementObligation memory) {
        Intent memory intent = Intent({
            inToken: address(baseToken),
            outToken: address(quoteToken),
            owner: intentOwner.addr,
            minPrice: FixedPointLib.wrap(2 << FixedPointLib.FIXED_POINT_PRECISION_BITS), // 1:1 price for simplicity
            amountIn: 100
        });

        // Sample an obligation
        uint256 amountIn = vm.randomUint(1, intent.amountIn);
        uint256 amountOut = intent.minPrice.unsafeFixedPointMul(amountIn);
        SettlementObligation memory obligation = SettlementObligation({
            inputToken: address(baseToken),
            outputToken: address(quoteToken),
            amountIn: amountIn,
            amountOut: amountOut
        });

        return (intent, obligation);
    }

    /// @dev Create two dummy obligations which are compatible with one another
    function createCompatibleObligations(
        address baseToken,
        address quoteToken
    )
        internal
        pure
        returns (SettlementObligation memory, SettlementObligation memory)
    {
        SettlementObligation memory party0Obligation =
            SettlementObligation({ inputToken: baseToken, outputToken: quoteToken, amountIn: 100, amountOut: 200 });
        SettlementObligation memory party1Obligation =
            SettlementObligation({ inputToken: quoteToken, outputToken: baseToken, amountIn: 200, amountOut: 100 });

        return (party0Obligation, party1Obligation);
    }

    /// @dev Create a dummy PlonkProof
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
}
