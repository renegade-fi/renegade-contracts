// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { BN254 } from "solidity-bn254/BN254.sol";
import { FixedPoint } from "renegade-lib/darkpool/types/TypesLib.sol";
import { DarkpoolConstants } from "renegade-lib/darkpool/Constants.sol";
import { PublicKeychain } from "renegade-lib/darkpool/types/Keychain.sol";
import { EncryptionKey } from "renegade-lib/darkpool/types/Ciphertext.sol";

// This file contains types for operating on wallet shares

/// @dev The maximum number of orders in a wallet
uint256 constant MAX_ORDERS = 4;
/// @dev The maximum number of balances in a wallet
uint256 constant MAX_BALANCES = 10;

/// @title WalletShare
/// @notice A public secret share of a wallet
struct WalletShare {
    /// @dev The list of balances in the wallet
    Balance[MAX_BALANCES] balances;
    /// @dev The list of orders in the wallet
    Order[MAX_ORDERS] orders;
    /// @dev The keychain of the wallet
    PublicKeychain keychain;
    /// @dev The maximum match fee that the user is willing to pay for a match
    FixedPoint maxMatchFee;
    /// @dev The public key of the cluster that the wallet has authorized to collect match fees
    EncryptionKey managingCluster;
    /// @dev The public share of the wallet's blinder
    BN254.ScalarField blinder;
}

/// @title Balance
/// @notice A balance in the wallet
struct Balance {
    /// @dev The address of the token
    address token;
    /// @dev The amount of the balance
    uint256 amount;
    /// @dev The amount of the balance owed to the managing relayer cluster
    uint256 relayerFeeBalance;
    /// @dev The amount of the balance owed to the protocol
    uint256 protocolFeeBalance;
}

/// @title Order
/// @notice An order in the wallet
struct Order {
    /// @dev The address of the quote mint
    address quoteMint;
    /// @dev The address of the base mint
    address baseMint;
    /// @dev The direction of the order
    OrderSide side;
    /// @dev The amount of the order
    uint256 amount;
    /// @dev The worst case price that the user is willing to accept on this order
    /// @dev If the order is a buy, this is the maximum price the user is willing to
    /// @dev pay. If the order is a sell, this is the minimum price the user is
    /// @dev willing to accept
    FixedPoint worstCasePrice;
}

/// @title OrderSide
/// @notice The side of the order
enum OrderSide {
    /// @dev The buy side
    Buy,
    /// @dev The sell side
    Sell
}

/// @title WalletLib
/// @notice A library for operating on wallets
library WalletLib {
    /// @notice The number of scalars in a serialized wallet share
    uint256 constant NUM_WALLET_SCALARS = 70;

    /// @notice Serialize a wallet share into a list of scalars
    /// @param wallet The wallet to serialize
    /// @return scalars The serialized wallet as a list of scalar field elements
    function scalarSerialize(WalletShare memory wallet) internal pure returns (BN254.ScalarField[] memory scalars) {
        scalars = new BN254.ScalarField[](NUM_WALLET_SCALARS);

        // Serialize the balances
        uint256 offset = 0;
        for (uint256 i = 0; i < MAX_BALANCES; i++) {
            scalars[offset++] = BN254.ScalarField.wrap(uint256(uint160(wallet.balances[i].token)));
            scalars[offset++] = BN254.ScalarField.wrap(wallet.balances[i].amount);
            scalars[offset++] = BN254.ScalarField.wrap(wallet.balances[i].relayerFeeBalance);
            scalars[offset++] = BN254.ScalarField.wrap(wallet.balances[i].protocolFeeBalance);
        }

        // Serialize the orders
        for (uint256 i = 0; i < MAX_ORDERS; i++) {
            scalars[offset++] = BN254.ScalarField.wrap(uint256(uint160(wallet.orders[i].quoteMint)));
            scalars[offset++] = BN254.ScalarField.wrap(uint256(uint160(wallet.orders[i].baseMint)));
            scalars[offset++] = BN254.ScalarField.wrap(uint256(wallet.orders[i].side));
            scalars[offset++] = BN254.ScalarField.wrap(wallet.orders[i].amount);
            scalars[offset++] = BN254.ScalarField.wrap(wallet.orders[i].worstCasePrice.repr);
        }

        // Serialize the keychain
        scalars[offset++] = wallet.keychain.pkRoot.x[0];
        scalars[offset++] = wallet.keychain.pkRoot.x[1];
        scalars[offset++] = wallet.keychain.pkRoot.y[0];
        scalars[offset++] = wallet.keychain.pkRoot.y[1];
        scalars[offset++] = wallet.keychain.pkMatch.key;
        scalars[offset++] = BN254.ScalarField.wrap(wallet.keychain.nonce);

        // Serialize the max match fee
        scalars[offset++] = BN254.ScalarField.wrap(wallet.maxMatchFee.repr);

        // Serialize the managing cluster
        scalars[offset++] = wallet.managingCluster.point.x;
        scalars[offset++] = wallet.managingCluster.point.y;

        // Serialize the blinder
        scalars[offset++] = wallet.blinder;
    }

    /// @notice Deserialize a wallet share from a list of scalars
    /// @param scalars The serialized wallet
    /// @return wallet The deserialized wallet
    function scalarDeserialize(BN254.ScalarField[] memory scalars) internal pure returns (WalletShare memory wallet) {
        uint256 offset = 0;

        // Deserialize the balances
        for (uint256 i = 0; i < MAX_BALANCES; i++) {
            wallet.balances[i].token = address(uint160(BN254.ScalarField.unwrap(scalars[offset++])));
            wallet.balances[i].amount = BN254.ScalarField.unwrap(scalars[offset++]);
            wallet.balances[i].relayerFeeBalance = BN254.ScalarField.unwrap(scalars[offset++]);
            wallet.balances[i].protocolFeeBalance = BN254.ScalarField.unwrap(scalars[offset++]);
        }

        // Deserialize the orders
        for (uint256 i = 0; i < MAX_ORDERS; i++) {
            wallet.orders[i].quoteMint = address(uint160(BN254.ScalarField.unwrap(scalars[offset++])));
            wallet.orders[i].baseMint = address(uint160(BN254.ScalarField.unwrap(scalars[offset++])));
            wallet.orders[i].side = OrderSide(BN254.ScalarField.unwrap(scalars[offset++]));
            wallet.orders[i].amount = BN254.ScalarField.unwrap(scalars[offset++]);
            wallet.orders[i].worstCasePrice = FixedPoint({ repr: BN254.ScalarField.unwrap(scalars[offset++]) });
        }

        // Deserialize the keychain
        wallet.keychain.pkRoot.x[0] = scalars[offset++];
        wallet.keychain.pkRoot.x[1] = scalars[offset++];
        wallet.keychain.pkRoot.y[0] = scalars[offset++];
        wallet.keychain.pkRoot.y[1] = scalars[offset++];
        wallet.keychain.pkMatch.key = scalars[offset++];
        wallet.keychain.nonce = BN254.ScalarField.unwrap(scalars[offset++]);

        // Deserialize the max match fee
        wallet.maxMatchFee = FixedPoint({ repr: BN254.ScalarField.unwrap(scalars[offset++]) });

        // Deserialize the managing cluster
        wallet.managingCluster.point.x = scalars[offset++];
        wallet.managingCluster.point.y = scalars[offset++];

        // Deserialize the blinder
        wallet.blinder = scalars[offset++];
    }
}
