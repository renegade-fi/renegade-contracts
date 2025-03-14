// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { DarkpoolTestBase } from "./DarkpoolTestBase.sol";
import { ValidWalletCreateStatement } from "renegade-lib/darkpool/PublicInputs.sol";
import { PlonkProof } from "renegade-lib/verifier/Types.sol";

contract CreateWalletTest is DarkpoolTestBase {
    // --- Create Wallet --- //

    /// @notice Test creating a wallet
    function test_createWallet() public {
        (ValidWalletCreateStatement memory statement, PlonkProof memory proof) = createWalletCalldata();
        darkpool.createWallet(statement, proof);
    }
}
