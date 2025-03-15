// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { Test } from "forge-std/Test.sol";
import { BN254 } from "solidity-bn254/BN254.sol";
import { FixedPoint } from "renegade-lib/darkpool/types/TypesLib.sol";
import { PublicKeychain, PublicRootKey, PublicIdentificationKey } from "renegade-lib/darkpool/types/Keychain.sol";
import { EncryptionKey, BabyJubJubPoint } from "renegade-lib/darkpool/types/Ciphertext.sol";
import {
    ExternalMatchResult,
    ExternalMatchDirection,
    OrderSettlementIndices
} from "renegade-lib/darkpool/types/Settlement.sol";
import { WalletShare, WalletLib, BalanceShare, OrderShare } from "src/libraries/darkpool/types/Wallet.sol";
import { FeeTakeRate, FeeTake } from "renegade-lib/darkpool/types/Fees.sol";
import { TypesLib } from "renegade-lib/darkpool/types/TypesLib.sol";
import { DarkpoolConstants } from "renegade-lib/darkpool/Constants.sol";
import { WalletOperations } from "renegade-lib/darkpool/WalletOperations.sol";
import { TestUtils } from "test/utils/TestUtils.sol";

contract WalletTest is TestUtils {
    using BN254 for BN254.ScalarField;
    using WalletLib for WalletShare;
    using TypesLib for FeeTakeRate;
    using TypesLib for FeeTake;

    /// @notice Test wallet serialization and deserialization
    function test_walletSerialization() public {
        // Generate random scalars
        BN254.ScalarField[] memory scalars = randomWalletShares();

        // Deserialize into a wallet then re-serialize
        WalletShare memory wallet = WalletLib.scalarDeserialize(scalars);
        BN254.ScalarField[] memory reserialized = wallet.scalarSerialize();

        // Verify all scalars match
        for (uint256 i = 0; i < DarkpoolConstants.N_WALLET_SHARES; i++) {
            assertEq(scalars[i], reserialized[i]);
        }
    }

    /// @notice Test the application of an external match to the wallet's shares
    function test_applyExternalMatchToShares_sellSide() public {
        // Generate a random wallet share and an external match result
        WalletShare memory walletShare = randomWalletShare();
        ExternalMatchResult memory matchResult = randomExternalMatchResult(ExternalMatchDirection.InternalPartySell);
        OrderSettlementIndices memory indices = randomOrderSettlementIndices();
        FeeTakeRate memory feeRates = randomFeeTakeRate();

        // Apply the match to the wallet's shares
        BN254.ScalarField[] memory oldShares = walletShare.scalarSerialize();
        BN254.ScalarField[] memory newShares =
            WalletOperations.applyExternalMatchToShares(oldShares, feeRates, matchResult, indices);

        // Verify the shares have been updated correctly
        WalletShare memory newWalletShare = WalletLib.scalarDeserialize(newShares);
        BN254.ScalarField quoteAmtScalar = BN254.ScalarField.wrap(matchResult.quoteAmount);
        BN254.ScalarField baseAmtScalar = BN254.ScalarField.wrap(matchResult.baseAmount);
        BN254.ScalarField expectedOrderSize = walletShare.orders[indices.order].amount.sub(baseAmtScalar);
        BN254.ScalarField expectedBalanceSend = walletShare.balances[indices.balanceSend].amount.sub(baseAmtScalar);

        FeeTake memory expectedFees = feeRates.computeFeeTake(matchResult.quoteAmount);
        uint256 expectedReceiveAmount = matchResult.quoteAmount - expectedFees.total();
        BN254.ScalarField expectedRecvScalar = BN254.ScalarField.wrap(expectedReceiveAmount);
        BN254.ScalarField expectedBalanceReceive =
            walletShare.balances[indices.balanceReceive].amount.add(expectedRecvScalar);
        BN254.ScalarField expectedRelayerFee = walletShare.balances[indices.balanceReceive].relayerFeeBalance.add(
            BN254.ScalarField.wrap(expectedFees.relayerFee)
        );
        BN254.ScalarField expectedProtocolFee = walletShare.balances[indices.balanceReceive].protocolFeeBalance.add(
            BN254.ScalarField.wrap(expectedFees.protocolFee)
        );

        assertEq(newWalletShare.balances[indices.balanceSend].amount, expectedBalanceSend);
        assertEq(newWalletShare.balances[indices.balanceReceive].amount, expectedBalanceReceive);
        assertEq(newWalletShare.balances[indices.balanceReceive].relayerFeeBalance, expectedRelayerFee);
        assertEq(newWalletShare.balances[indices.balanceReceive].protocolFeeBalance, expectedProtocolFee);
        assertEq(newWalletShare.orders[indices.order].amount, expectedOrderSize);
    }

    /// @notice Test the application of an external match to the wallet's shares
    function test_applyExternalMatchToShares_buySide() public {
        // Generate a random wallet share and an external match result
        WalletShare memory walletShare = randomWalletShare();
        ExternalMatchResult memory matchResult = randomExternalMatchResult(ExternalMatchDirection.InternalPartyBuy);
        OrderSettlementIndices memory indices = randomOrderSettlementIndices();
        FeeTakeRate memory feeRates = randomFeeTakeRate();

        // Apply the match to the wallet's shares
        BN254.ScalarField[] memory oldShares = walletShare.scalarSerialize();
        BN254.ScalarField[] memory newShares =
            WalletOperations.applyExternalMatchToShares(oldShares, feeRates, matchResult, indices);

        // Verify the shares have been updated correctly
        WalletShare memory newWalletShare = WalletLib.scalarDeserialize(newShares);
        BN254.ScalarField quoteAmtScalar = BN254.ScalarField.wrap(matchResult.quoteAmount);
        BN254.ScalarField baseAmtScalar = BN254.ScalarField.wrap(matchResult.baseAmount);
        BN254.ScalarField expectedOrderSize = walletShare.orders[indices.order].amount.sub(baseAmtScalar);
        BN254.ScalarField expectedBalanceSend = walletShare.balances[indices.balanceSend].amount.sub(quoteAmtScalar);

        FeeTake memory expectedFees = feeRates.computeFeeTake(matchResult.baseAmount);
        uint256 expectedReceiveAmount = matchResult.baseAmount - expectedFees.total();
        BN254.ScalarField expectedRecvScalar = BN254.ScalarField.wrap(expectedReceiveAmount);
        BN254.ScalarField expectedBalanceReceive =
            walletShare.balances[indices.balanceReceive].amount.add(expectedRecvScalar);
        BN254.ScalarField expectedRelayerFee = walletShare.balances[indices.balanceReceive].relayerFeeBalance.add(
            BN254.ScalarField.wrap(expectedFees.relayerFee)
        );
        BN254.ScalarField expectedProtocolFee = walletShare.balances[indices.balanceReceive].protocolFeeBalance.add(
            BN254.ScalarField.wrap(expectedFees.protocolFee)
        );

        assertEq(newWalletShare.balances[indices.balanceSend].amount, expectedBalanceSend);
        assertEq(newWalletShare.balances[indices.balanceReceive].amount, expectedBalanceReceive);
        assertEq(newWalletShare.balances[indices.balanceReceive].relayerFeeBalance, expectedRelayerFee);
        assertEq(newWalletShare.balances[indices.balanceReceive].protocolFeeBalance, expectedProtocolFee);
        assertEq(newWalletShare.orders[indices.order].amount, expectedOrderSize);
    }

    // --- Helpers --- //

    /// @dev Generate a random wallet share
    function randomWalletShare() internal returns (WalletShare memory) {
        BN254.ScalarField[] memory scalars = randomWalletShares();
        return WalletLib.scalarDeserialize(scalars);
    }

    /// @dev Generate a random external match result
    function randomExternalMatchResult(ExternalMatchDirection direction)
        internal
        returns (ExternalMatchResult memory matchResult)
    {
        matchResult = ExternalMatchResult({
            baseMint: vm.randomAddress(),
            quoteMint: vm.randomAddress(),
            baseAmount: randomAmount(),
            quoteAmount: randomAmount(),
            direction: direction
        });
    }

    /// @dev Generate a random set of order settlement indices
    function randomOrderSettlementIndices() internal returns (OrderSettlementIndices memory indices) {
        uint256 bal1 = randomUint(DarkpoolConstants.MAX_BALANCES);
        uint256 bal2 = randomUint(DarkpoolConstants.MAX_BALANCES);
        while (bal2 == bal1) {
            bal2 = randomUint(DarkpoolConstants.MAX_BALANCES);
        }
        uint256 order = randomUint(DarkpoolConstants.MAX_ORDERS);

        indices = OrderSettlementIndices({ balanceSend: bal1, balanceReceive: bal2, order: order });
    }

    /// @dev Generate a random fee take rate
    function randomFeeTakeRate() internal returns (FeeTakeRate memory feeRates) {
        feeRates = FeeTakeRate({ relayerFeeRate: randomTakeRate(), protocolFeeRate: randomTakeRate() });
    }

    /// @dev Generate a random take rate
    function randomTakeRate() internal returns (FixedPoint memory feeRate) {
        // Generate a random fee between 1bp and 10bps
        // We use a fixed point representation of `x * 2^63` as is used throughout the system
        // and generate a random integer representation between our bounds
        uint256 oneBpFp = 922_337_203_685_477;
        uint256 tenBpsFp = oneBpFp * 10;
        uint256 randRepr = randomUint(oneBpFp, tenBpsFp);
        feeRate = FixedPoint({ repr: randRepr });
    }
}
