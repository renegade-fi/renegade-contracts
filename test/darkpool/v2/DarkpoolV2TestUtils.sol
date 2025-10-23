// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { Vm } from "forge-std/Vm.sol";
import { ERC20Mock } from "oz-contracts/mocks/token/ERC20Mock.sol";
import { DarkpoolV2TestBase } from "./DarkpoolV2TestBase.sol";

import { BN254 } from "solidity-bn254/BN254.sol";
import { BN254Helpers } from "renegade-lib/verifier/BN254Helpers.sol";

import { ObligationBundle, ObligationType } from "darkpoolv2-types/settlement/ObligationBundle.sol";
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

    // --- ERC20 Balances --- //

    /// @dev Capitalize a party for an intent
    function capitalizeParty(address addr, Intent memory intent) public {
        capitalizeParty(addr, intent.inToken, intent.amountIn);
    }

    /// @dev Capitalize a party for an obligation
    function capitalizeParty(address addr, SettlementObligation memory obligation) public {
        capitalizeParty(addr, obligation.inputToken, obligation.amountIn);
    }

    /// @dev Capitalize a party for a given token and amount
    function capitalizeParty(address addr, address token, uint256 amount) public {
        // Mint the tokens to the party
        ERC20Mock erc20 = ERC20Mock(token);
        erc20.mint(addr, amount);

        // Approve the permit2 contract to spend tokens and generate a permit2 approval for the darkpool
        vm.startPrank(addr);
        erc20.approve(address(permit2), type(uint256).max);
        uint48 expiration = uint48(block.timestamp + 1 days);
        permit2.approve(token, address(darkpool), type(uint160).max, expiration);
        permit2.approve(token, address(darkpoolRealVerifier), type(uint160).max, expiration);
        vm.stopPrank();
    }

    // --- Fuzzing Helpers --- //

    /// @notice Generate a random price for a trade
    function randomPrice() internal returns (FixedPoint memory price) {
        // Min price of 0.01
        FixedPoint memory minPrice = FixedPointLib.integerToFixedPoint(1);
        minPrice = minPrice.divByInteger(100);
        FixedPoint memory maxPrice = FixedPointLib.integerToFixedPoint(1e12);

        price = randomFixedPoint(minPrice, maxPrice);
    }

    /// @notice Generate a random fixed point between two fixed point values
    /// @dev This is inclusive of the bounds, so [min, max]
    /// @param min The minimum fixed point value
    /// @param max The maximum fixed point value
    /// @return result The random fixed point value
    function randomFixedPoint(
        FixedPoint memory min,
        FixedPoint memory max
    )
        internal
        returns (FixedPoint memory result)
    {
        uint256 minRepr = min.repr;
        uint256 maxRepr = max.repr;
        uint256 randomRepr = vm.randomUint(minRepr, maxRepr);
        result = FixedPointLib.wrap(randomRepr);
    }

    // --- Dummy Data --- //

    /// @dev Create an intent for an obligation
    function createIntentForObligation(SettlementObligation memory obligation) internal returns (Intent memory) {
        // Compute the min price
        FixedPoint memory outAmtFixed = FixedPointLib.integerToFixedPoint(obligation.amountOut);
        FixedPoint memory inAmtFixed = FixedPointLib.integerToFixedPoint(obligation.amountIn);
        FixedPoint memory minPrice = outAmtFixed.div(inAmtFixed).divByInteger(2);

        // Compute the input amount
        uint256 amountIn = randomUint(obligation.amountIn, 2 ** 100);
        return Intent({
            inToken: obligation.inputToken,
            outToken: obligation.outputToken,
            owner: intentOwner.addr,
            minPrice: minPrice,
            amountIn: amountIn
        });
    }

    /// @dev Create two obligations for a simulated trade with random price and amount
    /// @return obligation0 The first party's obligation (selling base, buying quote)
    /// @return obligation1 The second party's obligation (selling quote, buying base)
    function createTradeObligations()
        internal
        returns (
            SettlementObligation memory obligation0,
            SettlementObligation memory obligation1,
            FixedPoint memory price
        )
    {
        price = randomPrice();
        uint256 baseAmount = randomAmount();
        uint256 quoteAmount = price.unsafeFixedPointMul(baseAmount);

        obligation0 = SettlementObligation({
            inputToken: address(baseToken),
            outputToken: address(quoteToken),
            amountIn: baseAmount,
            amountOut: quoteAmount
        });
        obligation1 = SettlementObligation({
            inputToken: address(quoteToken),
            outputToken: address(baseToken),
            amountIn: quoteAmount,
            amountOut: baseAmount
        });
    }

    /// @dev Build an obligation bundle from two obligations
    function buildObligationBundle(
        SettlementObligation memory obligation0,
        SettlementObligation memory obligation1
    )
        internal
        returns (ObligationBundle memory)
    {
        return ObligationBundle({ obligationType: ObligationType.PUBLIC, data: abi.encode(obligation0, obligation1) });
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
