// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {
    PlonkProof,
    VerificationKey,
    OpeningElements,
    ProofLinkingVK,
    ProofLinkingInstance
} from "./libraries/verifier/Types.sol";
import {
    ValidWalletCreateStatement,
    ValidWalletUpdateStatement,
    ValidCommitmentsStatement,
    ValidReblindStatement,
    ValidMatchSettleStatement,
    ValidMatchSettleAtomicStatement,
    StatementSerializer
} from "./libraries/darkpool/PublicInputs.sol";
import {
    PartyMatchPayload,
    MatchProofs,
    MatchLinkingProofs,
    MatchAtomicProofs,
    MatchAtomicLinkingProofs
} from "./libraries/darkpool/Types.sol";
import { VerificationKeys } from "./libraries/darkpool/VerificationKeys.sol";
import { IVerifier } from "./libraries/verifier/IVerifier.sol";
import { VerifierCore } from "./libraries/verifier/VerifierCore.sol";
import { ProofLinkingCore } from "./libraries/verifier/ProofLinking.sol";
import { BN254 } from "solidity-bn254/BN254.sol";

using StatementSerializer for ValidWalletCreateStatement;
using StatementSerializer for ValidWalletUpdateStatement;
using StatementSerializer for ValidCommitmentsStatement;
using StatementSerializer for ValidReblindStatement;
using StatementSerializer for ValidMatchSettleStatement;
using StatementSerializer for ValidMatchSettleAtomicStatement;

/// @title PlonK Verifier with the Jellyfish-style arithmetization
/// @notice The methods on this contract are darkpool-specific

contract Verifier is IVerifier {
    uint256 public constant NUM_MATCH_PROOFS = 5;
    uint256 public constant NUM_MATCH_LINKING_PROOFS = 4;
    uint256 public constant NUM_ATOMIC_MATCH_PROOFS = 3;
    uint256 public constant NUM_ATOMIC_MATCH_LINKING_PROOFS = 2;

    /// @notice Verify a proof of `VALID WALLET CREATE`
    /// @param statement The public inputs to the proof
    /// @param proof The proof to verify
    /// @return True if the proof is valid, false otherwise

    function verifyValidWalletCreate(
        ValidWalletCreateStatement memory statement,
        PlonkProof memory proof
    )
        external
        view
        returns (bool)
    {
        VerificationKey memory vk = abi.decode(VerificationKeys.VALID_WALLET_CREATE_VKEY, (VerificationKey));
        BN254.ScalarField[] memory publicInputs = statement.scalarSerialize();
        return VerifierCore.verify(proof, publicInputs, vk);
    }

    /// @notice Verify a proof of `VALID WALLET UPDATE`
    /// @param statement The public inputs to the proof
    /// @param proof The proof to verify
    /// @return True if the proof is valid, false otherwise
    function verifyValidWalletUpdate(
        ValidWalletUpdateStatement memory statement,
        PlonkProof memory proof
    )
        external
        view
        returns (bool)
    {
        VerificationKey memory vk = abi.decode(VerificationKeys.VALID_WALLET_UPDATE_VKEY, (VerificationKey));
        BN254.ScalarField[] memory publicInputs = statement.scalarSerialize();
        return VerifierCore.verify(proof, publicInputs, vk);
    }

    /// @notice Verify a match bundle
    /// @param party0MatchPayload The payload for the first party
    /// @param party1MatchPayload The payload for the second party
    /// @param matchSettleStatement The statement of `VALID MATCH SETTLE`
    /// @param matchProofs The proofs for the match, including two sets of validity proofs and a settlement proof
    /// @return True if the match bundle is valid, false otherwise
    function verifyMatchBundle(
        PartyMatchPayload calldata party0MatchPayload,
        PartyMatchPayload calldata party1MatchPayload,
        ValidMatchSettleStatement calldata matchSettleStatement,
        MatchProofs calldata matchProofs,
        MatchLinkingProofs calldata matchLinkingProofs
    )
        external
        view
        returns (bool)
    {
        // Load the verification keys
        VerificationKey memory commitmentsVk = abi.decode(VerificationKeys.VALID_COMMITMENTS_VKEY, (VerificationKey));
        VerificationKey memory reblindVk = abi.decode(VerificationKeys.VALID_REBLIND_VKEY, (VerificationKey));
        VerificationKey memory settleVk = abi.decode(VerificationKeys.VALID_MATCH_SETTLE_VKEY, (VerificationKey));

        // Build the batch
        PlonkProof[] memory proofs = new PlonkProof[](NUM_MATCH_PROOFS);
        BN254.ScalarField[][] memory publicInputs = new BN254.ScalarField[][](NUM_MATCH_PROOFS);
        VerificationKey[] memory vks = new VerificationKey[](NUM_MATCH_PROOFS);
        proofs[0] = matchProofs.validCommitments0;
        proofs[1] = matchProofs.validReblind0;
        proofs[2] = matchProofs.validCommitments1;
        proofs[3] = matchProofs.validReblind1;
        proofs[4] = matchProofs.validMatchSettle;

        publicInputs[0] = party0MatchPayload.validCommitmentsStatement.scalarSerialize();
        publicInputs[1] = party0MatchPayload.validReblindStatement.scalarSerialize();
        publicInputs[2] = party1MatchPayload.validCommitmentsStatement.scalarSerialize();
        publicInputs[3] = party1MatchPayload.validReblindStatement.scalarSerialize();
        publicInputs[4] = matchSettleStatement.scalarSerialize();

        vks[0] = commitmentsVk;
        vks[1] = reblindVk;
        vks[2] = commitmentsVk;
        vks[3] = reblindVk;
        vks[4] = settleVk;

        // Add proof linking instances to the opening
        ProofLinkingInstance[] memory instances = createMatchLinkingInstances(matchProofs, matchLinkingProofs);
        OpeningElements memory linkOpenings = ProofLinkingCore.createOpeningElements(instances);

        // Verify the batch
        return VerifierCore.batchVerify(proofs, publicInputs, vks, linkOpenings);
    }

    /// @notice Verify an atomic match bundle
    /// @param internalPartyPayload The payload for the internal party
    /// @param matchSettleStatement The statement of `VALID MATCH SETTLE ATOMIC`
    /// @param matchProofs The proofs for the match, including a validity proof and a settlement proof
    /// @param matchLinkingProofs The proof linking arguments for the match
    /// @return True if the atomic match bundle is valid, false otherwise
    function verifyAtomicMatchBundle(
        PartyMatchPayload calldata internalPartyPayload,
        ValidMatchSettleAtomicStatement calldata matchSettleStatement,
        MatchAtomicProofs calldata matchProofs,
        MatchAtomicLinkingProofs calldata matchLinkingProofs
    )
        external
        view
        returns (bool)
    {
        // Load the verification keys
        VerificationKey memory commitmentsVk = abi.decode(VerificationKeys.VALID_COMMITMENTS_VKEY, (VerificationKey));
        VerificationKey memory reblindVk = abi.decode(VerificationKeys.VALID_REBLIND_VKEY, (VerificationKey));
        VerificationKey memory settleVk = abi.decode(VerificationKeys.VALID_MATCH_SETTLE_ATOMIC_VKEY, (VerificationKey));

        // Build the batch
        PlonkProof[] memory proofs = new PlonkProof[](NUM_ATOMIC_MATCH_PROOFS);
        BN254.ScalarField[][] memory publicInputs = new BN254.ScalarField[][](NUM_ATOMIC_MATCH_PROOFS);
        VerificationKey[] memory vks = new VerificationKey[](NUM_ATOMIC_MATCH_PROOFS);
        proofs[0] = matchProofs.validCommitments;
        proofs[1] = matchProofs.validReblind;
        proofs[2] = matchProofs.validMatchSettleAtomic;

        publicInputs[0] = internalPartyPayload.validCommitmentsStatement.scalarSerialize();
        publicInputs[1] = internalPartyPayload.validReblindStatement.scalarSerialize();
        publicInputs[2] = matchSettleStatement.scalarSerialize();

        vks[0] = commitmentsVk;
        vks[1] = reblindVk;
        vks[2] = settleVk;

        // Add proof linking instances to the opening
        ProofLinkingInstance[] memory instances = createAtomicMatchLinkingInstances(matchProofs, matchLinkingProofs);
        OpeningElements memory linkOpenings = ProofLinkingCore.createOpeningElements(instances);

        // Verify the batch
        return VerifierCore.batchVerify(proofs, publicInputs, vks, linkOpenings);
    }

    // --- Helpers --- //

    /// @notice Create a set of match linking instances
    /// @param matchProofs The proofs for the match, including two sets of validity proofs and a settlement proof
    /// @param matchLinkingProofs The proof linking arguments for the match
    /// @return instances A set of match linking instances
    function createMatchLinkingInstances(
        MatchProofs calldata matchProofs,
        MatchLinkingProofs calldata matchLinkingProofs
    )
        internal
        pure
        returns (ProofLinkingInstance[] memory instances)
    {
        instances = new ProofLinkingInstance[](NUM_MATCH_LINKING_PROOFS);
        ProofLinkingVK memory reblindCommitmentsVk =
            abi.decode(VerificationKeys.VALID_REBLIND_COMMITMENTS_LINK_VKEY, (ProofLinkingVK));
        ProofLinkingVK memory commitmentsMatchSettleVk0 =
            abi.decode(VerificationKeys.VALID_COMMITMENTS_MATCH_SETTLE_LINK0_VKEY, (ProofLinkingVK));
        ProofLinkingVK memory commitmentsMatchSettleVk1 =
            abi.decode(VerificationKeys.VALID_COMMITMENTS_MATCH_SETTLE_LINK1_VKEY, (ProofLinkingVK));

        // Party 0: VALID REBLIND -> VALID COMMITMENTS
        instances[0] = ProofLinkingInstance({
            wire_comm0: matchProofs.validReblind0.wire_comms[0],
            wire_comm1: matchProofs.validCommitments0.wire_comms[0],
            proof: matchLinkingProofs.validReblindCommitments0,
            vk: reblindCommitmentsVk
        });

        // Party 0: VALID COMMITMENTS -> VALID MATCH SETTLE
        instances[1] = ProofLinkingInstance({
            wire_comm0: matchProofs.validCommitments0.wire_comms[0],
            wire_comm1: matchProofs.validMatchSettle.wire_comms[0],
            proof: matchLinkingProofs.validCommitmentsMatchSettle0,
            vk: commitmentsMatchSettleVk0
        });

        // Party 1: VALID REBLIND -> VALID COMMITMENTS
        instances[2] = ProofLinkingInstance({
            wire_comm0: matchProofs.validReblind1.wire_comms[0],
            wire_comm1: matchProofs.validCommitments1.wire_comms[0],
            proof: matchLinkingProofs.validReblindCommitments1,
            vk: reblindCommitmentsVk
        });

        // Party 1: VALID COMMITMENTS -> VALID MATCH SETTLE
        instances[3] = ProofLinkingInstance({
            wire_comm0: matchProofs.validCommitments1.wire_comms[0],
            wire_comm1: matchProofs.validMatchSettle.wire_comms[0],
            proof: matchLinkingProofs.validCommitmentsMatchSettle1,
            vk: commitmentsMatchSettleVk1
        });
    }

    /// @notice Create a set of match linking instances for an atomic match bundle
    /// @param matchProofs The proofs for the match, including a validity proof and a settlement proof
    /// @param matchLinkingProofs The proof linking arguments for the match
    /// @return instances A set of match linking instances
    function createAtomicMatchLinkingInstances(
        MatchAtomicProofs calldata matchProofs,
        MatchAtomicLinkingProofs calldata matchLinkingProofs
    )
        internal
        pure
        returns (ProofLinkingInstance[] memory instances)
    {
        instances = new ProofLinkingInstance[](NUM_MATCH_LINKING_PROOFS);
        ProofLinkingVK memory reblindCommitmentsVk =
            abi.decode(VerificationKeys.VALID_REBLIND_COMMITMENTS_LINK_VKEY, (ProofLinkingVK));

        // We link the internal party in an atomic match into the layout of the first party in an
        // internal match, so we use that vkey directly here
        ProofLinkingVK memory commitmentsMatchSettleVk =
            abi.decode(VerificationKeys.VALID_COMMITMENTS_MATCH_SETTLE_LINK0_VKEY, (ProofLinkingVK));

        // VALID REBLIND -> VALID COMMITMENTS
        instances[0] = ProofLinkingInstance({
            wire_comm0: matchProofs.validReblind.wire_comms[0],
            wire_comm1: matchProofs.validCommitments.wire_comms[0],
            proof: matchLinkingProofs.validReblindCommitments,
            vk: reblindCommitmentsVk
        });

        // VALID COMMITMENTS -> VALID MATCH SETTLE ATOMIC
        instances[1] = ProofLinkingInstance({
            wire_comm0: matchProofs.validCommitments.wire_comms[0],
            wire_comm1: matchProofs.validMatchSettleAtomic.wire_comms[0],
            proof: matchLinkingProofs.validCommitmentsMatchSettleAtomic,
            vk: commitmentsMatchSettleVk
        });
    }
}
