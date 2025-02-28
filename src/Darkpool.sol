// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { PlonkProof, VerificationKey, NUM_SELECTORS, NUM_WIRE_TYPES } from "./libraries/verifier/Types.sol";
import { BN254 } from "solidity-bn254/BN254.sol";
import { VerifierCore } from "./libraries/verifier/Verifier.sol";
import { VerificationKeys } from "./VerificationKeys.sol";
import { console2 } from "forge-std/console2.sol";

contract Darkpool {
    /// @notice Create a wallet in the darkpool
    /// @param publicInputs The public inputs to the proof
    /// @param proof The proof of `VALID WALLET CREATE`
    function createWallet(BN254.ScalarField[] memory publicInputs, PlonkProof memory proof) public {
        // Load the verification key from the constant
        VerificationKey memory vk = abi.decode(VerificationKeys.VALID_WALLET_CREATE_VKEY, (VerificationKey));

        // 1. Verify the proof
        // VerifierCore.verify(proof, publicInputs, vk);
    }
}
