// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { PlonkProof } from "./Types.sol";
import {
    ValidWalletCreateStatement,
    ValidWalletUpdateStatement,
    ValidMatchSettleStatement
} from "../darkpool/PublicInputs.sol";
import { PartyMatchPayload, MatchProofs } from "../darkpool/Types.sol";

interface IVerifier {
    /// @notice Verify a proof of `VALID WALLET CREATE`
    /// @param proof The proof to verify
    /// @param statement The public inputs to the proof
    /// @return True if the proof is valid, false otherwise
    function verifyValidWalletCreate(
        ValidWalletCreateStatement calldata statement,
        PlonkProof calldata proof
    )
        external
        view
        returns (bool);

    /// @notice Verify a proof of `VALID WALLET UPDATE`
    /// @param proof The proof to verify
    /// @param statement The public inputs to the proof
    /// @return True if the proof is valid, false otherwise
    function verifyValidWalletUpdate(
        ValidWalletUpdateStatement calldata statement,
        PlonkProof calldata proof
    )
        external
        view
        returns (bool);

    /// @notice Verify a match bundle
    /// @param party0MatchPayload The payload for the first party
    /// @param party1MatchPayload The payload for the second party
    /// @param matchSettleStatement The statement of `VALID MATCH SETTLE`
    /// @param proofs The proofs for the match, including two sets of validity proofs and a settlement proof
    /// @return True if the match bundle is valid, false otherwise
    function verifyMatchBundle(
        PartyMatchPayload calldata party0MatchPayload,
        PartyMatchPayload calldata party1MatchPayload,
        ValidMatchSettleStatement calldata matchSettleStatement,
        MatchProofs calldata proofs
    )
        external
        view
        returns (bool);
}
