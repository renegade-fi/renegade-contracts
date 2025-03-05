// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import { BN254 } from "solidity-bn254/BN254.sol";
import { Vm } from "forge-std/Vm.sol";
import { TestUtils } from "./TestUtils.sol";
import { PlonkProof } from "../../src/libraries/verifier/Types.sol";
import { IHasher } from "../../src/libraries/poseidon2/IHasher.sol";
import { ExternalTransfer, PublicRootKey, TransferType } from "../../src/libraries/darkpool/Types.sol";
import { uintToScalarWords, WalletOperations } from "../../src/libraries/darkpool/WalletOperations.sol";
import { ValidWalletCreateStatement, ValidWalletUpdateStatement } from "../../src/libraries/darkpool/PublicInputs.sol";
import { console2 } from "forge-std/console2.sol";

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
    function updateWalletCalldata(IHasher hasher)
        internal
        returns (
            bytes memory newSharesCommitmentSig,
            ValidWalletUpdateStatement memory statement,
            PlonkProof memory proof
        )
    {
        Vm.Wallet memory rootKeyWallet = randomEthereumWallet();
        statement = ValidWalletUpdateStatement({
            previousNullifier: randomScalar(),
            newPublicShares: randomWalletShares(),
            newPrivateShareCommitment: randomScalar(),
            merkleRoot: randomScalar(),
            externalTransfer: emptyExternalTransfer(),
            oldPkRoot: forgeWalletToRootKey(rootKeyWallet)
        });
        proof = dummyPlonkProof();

        // Sign the new shares commitment
        BN254.ScalarField newSharesCommitment = WalletOperations.computeWalletCommitment(
            statement.newPublicShares, statement.newPrivateShareCommitment, hasher
        );

        bytes32 digest = WalletOperations.walletCommitmentDigest(newSharesCommitment);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(rootKeyWallet.privateKey, digest);
        newSharesCommitmentSig = abi.encodePacked(r, s, v);
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
        rootKey = forgeWalletToRootKey(wallet);
    }

    /// @notice Convert a forge wallet to a public root key
    function forgeWalletToRootKey(Vm.Wallet memory wallet) internal pure returns (PublicRootKey memory rootKey) {
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
