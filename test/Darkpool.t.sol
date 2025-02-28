// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import { Test } from "forge-std/Test.sol";
import { TestUtils } from "./utils/TestUtils.sol";
import { PlonkProof } from "../src/libraries/verifier/Types.sol";
import { Darkpool } from "../src/Darkpool.sol";
import { BN254 } from "solidity-bn254/BN254.sol";

contract DarkpoolTest is TestUtils {
    Darkpool public darkpool;

    function setUp() public {
        darkpool = new Darkpool();
    }

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

        darkpool.createWallet(publicInputs, proof);
    }
}
