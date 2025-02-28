// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { PlonkProof, VerificationKey, NUM_SELECTORS, NUM_WIRE_TYPES } from "./libraries/verifier/Types.sol";
import { BN254 } from "solidity-bn254/BN254.sol";
import { VerifierCore } from "./libraries/verifier/Verifier.sol";
import { VerificationKeys } from "./VerificationKeys.sol";
import { console2 } from "forge-std/console2.sol";
import { IHasher } from "./libraries/merkle/IHasher.sol";
import { ValidWalletCreateStatement, StatementSerializer } from "./libraries/darkpool/PublicInputs.sol";

// Use the StatementSerializer for all statements
using StatementSerializer for ValidWalletCreateStatement;

contract Darkpool {
    /// @notice The hasher for the darkpool
    IHasher public hasher;

    /// @notice The constructor for the darkpool
    /// @param hasher_ The hasher for the darkpool
    constructor(IHasher hasher_) {
        hasher = hasher_;
    }

    /// @notice Create a wallet in the darkpool
    /// @param statement The statement to verify
    /// @param proof The proof of `VALID WALLET CREATE`
    function createWallet(ValidWalletCreateStatement memory statement, PlonkProof memory proof) public view {
        // Load the verification key from the constant
        VerificationKey memory vk = abi.decode(VerificationKeys.VALID_WALLET_CREATE_VKEY, (VerificationKey));

        // 1. Verify the proof
        // Serialize the public inputs
        BN254.ScalarField[] memory publicInputs = statement.scalarSerialize();
        VerifierCore.verify(proof, publicInputs, vk);
    }
}
