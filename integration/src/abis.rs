//! Solidity ABI definitions for the contracts used in integration tests

use ethers::prelude::abigen;

abigen!(
    PrecompileTestContract,
    r#"[
        function testAdd() external view
        function testMul() external view
        function testPairing() external view
    ]"#
);

abigen!(
    VerifierContract,
    r#"[
        function verify(bytes memory vkey, bytes memory proof, bytes memory public_inputs) external view returns (bool)
    ]"#
);
