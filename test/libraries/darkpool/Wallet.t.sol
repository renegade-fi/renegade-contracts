// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { Test } from "forge-std/Test.sol";
import { BN254 } from "solidity-bn254/BN254.sol";
import { FixedPoint } from "renegade-lib/darkpool/types/TypesLib.sol";
import { PublicKeychain, PublicRootKey, PublicIdentificationKey } from "renegade-lib/darkpool/types/Keychain.sol";
import { EncryptionKey, BabyJubJubPoint } from "renegade-lib/darkpool/types/Ciphertext.sol";
import { WalletShare, WalletLib, OrderSide, Balance, Order } from "src/libraries/darkpool/types/Wallet.sol";
import { TestUtils } from "test/utils/TestUtils.sol";

contract WalletTest is TestUtils {
    /// @notice Test wallet serialization and deserialization
    function test_walletSerialization() public {
        // Create a random wallet
        WalletShare memory wallet = createRandomWallet();

        // Serialize then deserialize the wallet
        BN254.ScalarField[] memory serialized = WalletLib.scalarSerialize(wallet);
        WalletShare memory deserialized = WalletLib.scalarDeserialize(serialized);

        // Verify all fields match
        verifyWalletsEqual(wallet, deserialized);
    }

    /// @notice Create a random wallet for testing
    function createRandomWallet() internal returns (WalletShare memory wallet) {
        // Fill balances
        for (uint256 i = 0; i < 10; i++) {
            wallet.balances[i] = Balance({
                token: address(uint160(randomUint())),
                amount: randomUint(),
                relayerFeeBalance: randomUint(),
                protocolFeeBalance: randomUint()
            });
        }

        // Fill orders
        for (uint256 i = 0; i < 4; i++) {
            wallet.orders[i] = Order({
                quoteMint: address(uint160(randomUint())),
                baseMint: address(uint160(randomUint())),
                side: OrderSide(randomUint() % 2),
                amount: randomUint(),
                worstCasePrice: FixedPoint({ repr: randomUint() })
            });
        }

        // Fill keychain
        wallet.keychain = PublicKeychain({
            pkRoot: PublicRootKey({ x: [randomScalar(), randomScalar()], y: [randomScalar(), randomScalar()] }),
            pkMatch: PublicIdentificationKey({ key: randomScalar() }),
            nonce: randomUint()
        });

        // Fill remaining fields
        wallet.maxMatchFee = FixedPoint({ repr: randomUint() });
        wallet.managingCluster = EncryptionKey({ point: BabyJubJubPoint({ x: randomScalar(), y: randomScalar() }) });
        wallet.blinder = randomScalar();
    }

    /// @notice Verify that two wallets have matching fields
    function verifyWalletsEqual(WalletShare memory a, WalletShare memory b) internal {
        // Verify balances
        for (uint256 i = 0; i < 10; i++) {
            assertEq(a.balances[i].token, b.balances[i].token);
            assertEq(a.balances[i].amount, b.balances[i].amount);
            assertEq(a.balances[i].relayerFeeBalance, b.balances[i].relayerFeeBalance);
            assertEq(a.balances[i].protocolFeeBalance, b.balances[i].protocolFeeBalance);
        }

        // Verify orders
        for (uint256 i = 0; i < 4; i++) {
            assertEq(a.orders[i].quoteMint, b.orders[i].quoteMint);
            assertEq(a.orders[i].baseMint, b.orders[i].baseMint);
            assertEq(uint256(a.orders[i].side), uint256(b.orders[i].side));
            assertEq(a.orders[i].amount, b.orders[i].amount);
            assertEq(a.orders[i].worstCasePrice.repr, b.orders[i].worstCasePrice.repr);
        }

        // Verify keychain
        assertEq(BN254.ScalarField.unwrap(a.keychain.pkRoot.x[0]), BN254.ScalarField.unwrap(b.keychain.pkRoot.x[0]));
        assertEq(BN254.ScalarField.unwrap(a.keychain.pkRoot.x[1]), BN254.ScalarField.unwrap(b.keychain.pkRoot.x[1]));
        assertEq(BN254.ScalarField.unwrap(a.keychain.pkRoot.y[0]), BN254.ScalarField.unwrap(b.keychain.pkRoot.y[0]));
        assertEq(BN254.ScalarField.unwrap(a.keychain.pkRoot.y[1]), BN254.ScalarField.unwrap(b.keychain.pkRoot.y[1]));
        assertEq(BN254.ScalarField.unwrap(a.keychain.pkMatch.key), BN254.ScalarField.unwrap(b.keychain.pkMatch.key));
        assertEq(a.keychain.nonce, b.keychain.nonce);

        // Verify remaining fields
        assertEq(a.maxMatchFee.repr, b.maxMatchFee.repr);
        assertEq(
            BN254.ScalarField.unwrap(a.managingCluster.point.x), BN254.ScalarField.unwrap(b.managingCluster.point.x)
        );
        assertEq(
            BN254.ScalarField.unwrap(a.managingCluster.point.y), BN254.ScalarField.unwrap(b.managingCluster.point.y)
        );
        assertEq(BN254.ScalarField.unwrap(a.blinder), BN254.ScalarField.unwrap(b.blinder));
    }
}
