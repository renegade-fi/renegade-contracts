// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import { PlonkProof, VerificationKey, NUM_SELECTORS, NUM_WIRE_TYPES } from "./libraries/verifier/Types.sol";
import { BN254 } from "solidity-bn254/BN254.sol";
import { VerifierCore } from "./libraries/verifier/VerifierCore.sol";
import { VerificationKeys } from "./libraries/darkpool/VerificationKeys.sol";
import { console2 } from "forge-std/console2.sol";
import { IHasher } from "./libraries/merkle/IHasher.sol";
import { IVerifier } from "./libraries/verifier/IVerifier.sol";
import { ValidWalletCreateStatement, StatementSerializer } from "./libraries/darkpool/PublicInputs.sol";

// Use the StatementSerializer for all statements
using StatementSerializer for ValidWalletCreateStatement;

contract Darkpool {
    /// @notice The hasher for the darkpool
    IHasher public hasher;
    /// @notice The verifier for the darkpool
    IVerifier public verifier;

    /// @notice The constructor for the darkpool
    /// @param hasher_ The hasher for the darkpool
    /// @param verifier_ The verifier for the darkpool
    constructor(IHasher hasher_, IVerifier verifier_) {
        hasher = hasher_;
        verifier = verifier_;
    }

    /// @notice Create a wallet in the darkpool
    /// @param statement The statement to verify
    /// @param proof The proof of `VALID WALLET CREATE`
    function createWallet(ValidWalletCreateStatement memory statement, PlonkProof memory proof) public view {
        // 1. Verify the proof
        verifier.verifyValidWalletCreate(statement, proof);

        // 2. Compute a commitment to the wallet shares
        uint256[] memory hashInputs = new uint256[](statement.publicShares.length + 1);
        hashInputs[0] = BN254.ScalarField.unwrap(statement.privateShareCommitment);
        for (uint256 i = 1; i <= statement.publicShares.length; i++) {
            hashInputs[i] = BN254.ScalarField.unwrap(statement.publicShares[i - 1]);
        }
        uint256 walletCommitment = hasher.spongeHash(hashInputs);
        console2.log("walletCommitment", walletCommitment);

        // 3. Insert the wallet commitment into the Merkle tree
        // TODO: Implement Merkle tree
    }
}
