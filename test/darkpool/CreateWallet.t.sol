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

    /// @notice Test creating a wallet with an invalid proof
    function test_createWallet_invalidProof() public {
        (ValidWalletCreateStatement memory statement, PlonkProof memory proof) = createWalletCalldata();
        vm.expectRevert("Verification failed for wallet create");
        darkpoolRealVerifier.createWallet(statement, proof);
    }
}
