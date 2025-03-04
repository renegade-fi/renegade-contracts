// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { BN254 } from "solidity-bn254/BN254.sol";
import { Test } from "forge-std/Test.sol";
import { TestUtils } from "./utils/TestUtils.sol";
import { HuffDeployer } from "foundry-huff/HuffDeployer.sol";
import { console2 } from "forge-std/console2.sol";

import { PlonkProof } from "../src/libraries/verifier/Types.sol";
import { Darkpool } from "../src/Darkpool.sol";
import { Nullifiers } from "../src/libraries/darkpool/NullifierSet.sol";
import { IHasher } from "../src/libraries/poseidon2/IHasher.sol";
import { IVerifier } from "../src/libraries/verifier/IVerifier.sol";
import { TestVerifier } from "./test-contracts/TestVerifier.sol";
import { ValidWalletCreateStatement } from "../src/libraries/darkpool/PublicInputs.sol";

contract DarkpoolTest is TestUtils {
    using Nullifiers for Nullifiers.NullifierSet;

    Darkpool public darkpool;
    Nullifiers.NullifierSet private testNullifierSet;

    function setUp() public {
        IHasher hasher = IHasher(HuffDeployer.deploy("libraries/poseidon2/poseidonHasher"));
        IVerifier verifier = new TestVerifier();
        darkpool = new Darkpool(hasher, verifier);
    }

    // --- Library Primitive Tests --- //

    /// @notice Test the nullifier set
    function test_nullifierSet() public {
        BN254.ScalarField nullifier = BN254.ScalarField.wrap(randomFelt());
        testNullifierSet.spend(nullifier); // Should succeed

        // Check that the nullifier is spent
        assertEq(testNullifierSet.isSpent(nullifier), true);

        // Should fail
        vm.expectRevert("Nullifier already spent");
        testNullifierSet.spend(nullifier);
    }

    // --- Darkpool Method Tests --- //

    /// @notice Test creating a wallet
    function test_createWallet() public {
        BN254.ScalarField dummyScalar = BN254.ScalarField.wrap(1);
        BN254.G1Point memory dummyPoint = BN254.P1();
        BN254.ScalarField[] memory publicInputs = new BN254.ScalarField[](1);
        publicInputs[0] = dummyScalar;

        PlonkProof memory proof = PlonkProof({
            wire_comms: [dummyPoint, dummyPoint, dummyPoint, dummyPoint, dummyPoint],
            z_comm: dummyPoint,
            quotient_comms: [dummyPoint, dummyPoint, dummyPoint, dummyPoint, dummyPoint],
            w_zeta: dummyPoint,
            w_zeta_omega: dummyPoint,
            wire_evals: [dummyScalar, dummyScalar, dummyScalar, dummyScalar, dummyScalar],
            sigma_evals: [dummyScalar, dummyScalar, dummyScalar, dummyScalar],
            z_bar: dummyScalar
        });

        BN254.ScalarField privateShareCommitment = BN254.ScalarField.wrap(randomFelt());
        BN254.ScalarField[] memory publicShares = randomWalletShares();
        ValidWalletCreateStatement memory statement =
            ValidWalletCreateStatement({ privateShareCommitment: privateShareCommitment, publicShares: publicShares });

        uint256 gasStart = gasleft();
        darkpool.createWallet(statement, proof);
        uint256 gasEnd = gasleft();
        console2.log("Gas used:", gasStart - gasEnd);
    }
}
