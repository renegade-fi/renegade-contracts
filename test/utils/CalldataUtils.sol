// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import { BN254 } from "solidity-bn254/BN254.sol";
import { Vm } from "forge-std/Vm.sol";
import { TestUtils, uintToScalarWords } from "./TestUtils.sol";
import { PlonkProof } from "../../src/libraries/verifier/Types.sol";
import { ExternalTransfer, PublicRootKey, TransferType } from "../../src/libraries/darkpool/Types.sol";
import { ValidWalletCreateStatement, ValidWalletUpdateStatement } from "../../src/libraries/darkpool/PublicInputs.sol";

// Utilities for generating darkpool calldata

contract CalldataUtils is TestUtils {
    /// @dev The first testing address
    address public constant DUMMY_ADDRESS = address(0x1);
    /// @dev A dummy wallet address
    address public constant DUMMY_WALLET_ADDRESS = address(0x2);

    // ---------------------
    // | Darkpool Calldata |
    // ---------------------

    /// @notice Generate calldata for creating a wallet
    function createWalletCalldata()
        internal
        returns (ValidWalletCreateStatement memory statement, PlonkProof memory proof)
    {
        statement = ValidWalletCreateStatement({
            privateShareCommitment: BN254.ScalarField.wrap(randomFelt()),
            publicShares: randomWalletShares()
        });
        proof = dummyPlonkProof();
    }

    /// @notice Generate calldata for updating a wallet
    function updateWalletCalldata()
        internal
        returns (ValidWalletUpdateStatement memory statement, PlonkProof memory proof)
    {
        statement = ValidWalletUpdateStatement({
            previousNullifier: randomScalar(),
            newPublicShares: randomWalletShares(),
            newPrivateShareCommitment: randomScalar(),
            merkleRoot: randomScalar(),
            externalTransfer: emptyExternalTransfer(),
            oldPkRoot: randomRootKey()
        });
        proof = dummyPlonkProof();
    }

    // ------------------
    // | Calldata Types |
    // ------------------

    /// @notice Generate an empty external transfer
    function emptyExternalTransfer() internal pure returns (ExternalTransfer memory transfer) {
        transfer =
            ExternalTransfer({ account: address(0), mint: address(0), amount: 0, transferType: TransferType.Deposit });
    }

    /// @notice Generate a random root key
    function randomRootKey() internal returns (PublicRootKey memory rootKey) {
        Vm.Wallet memory wallet = randomEthereumWallet();
        (BN254.ScalarField xLow, BN254.ScalarField xHigh) = uintToScalarWords(wallet.publicKeyX);
        (BN254.ScalarField yLow, BN254.ScalarField yHigh) = uintToScalarWords(wallet.publicKeyY);
        rootKey = PublicRootKey({ x: [xLow, xHigh], y: [yLow, yHigh] });
    }

    /// @notice Generates a dummy PlonK proof
    function dummyPlonkProof() internal pure returns (PlonkProof memory proof) {
        BN254.ScalarField dummyScalar = BN254.ScalarField.wrap(1);
        BN254.G1Point memory dummyPoint = BN254.P1();
        BN254.ScalarField[] memory publicInputs = new BN254.ScalarField[](1);
        publicInputs[0] = dummyScalar;

        proof = PlonkProof({
            wire_comms: [dummyPoint, dummyPoint, dummyPoint, dummyPoint, dummyPoint],
            z_comm: dummyPoint,
            quotient_comms: [dummyPoint, dummyPoint, dummyPoint, dummyPoint, dummyPoint],
            w_zeta: dummyPoint,
            w_zeta_omega: dummyPoint,
            wire_evals: [dummyScalar, dummyScalar, dummyScalar, dummyScalar, dummyScalar],
            sigma_evals: [dummyScalar, dummyScalar, dummyScalar, dummyScalar],
            z_bar: dummyScalar
        });
    }
}
