//! Solidity ABI definitions for the contracts used in integration tests

use ethers::prelude::abigen;

abigen!(
    PrecompileTestContract,
    r#"[
        function testEcAdd() external view
        function testEcMul() external view
        function testEcPairing() external view
    ]"#
);

abigen!(
    VerifierContract,
    r#"[
        function verify(bytes memory vkey, bytes memory proof, bytes memory public_inputs) external view returns (bool)
    ]"#
);
