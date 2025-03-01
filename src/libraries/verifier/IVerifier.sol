// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { PlonkProof } from "./Types.sol";
import { ValidWalletCreateStatement } from "../darkpool/PublicInputs.sol";

interface IVerifier {
    /// @notice Verify a proof of `VALID WALLET CREATE`
    /// @param proof The proof to verify
    /// @param statement The public inputs to the proof
    /// @return True if the proof is valid, false otherwise
    function verifyValidWalletCreate(
        ValidWalletCreateStatement memory statement,
        PlonkProof memory proof
    )
        external
        view
        returns (bool);
}
