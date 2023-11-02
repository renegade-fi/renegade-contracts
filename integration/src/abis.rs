//! Solidity ABI definitions for the contracts used in integration tests

use ethers::prelude::abigen;

abigen!(
    DarkpoolTestContract,
    r#"[
        function isNullifierSpent(bytes32 memory nullifier) external view returns (bool)
        function markNullifierSpent(bytes32 memory nullifier) external
        function setVerifierAddress(address memory _address) external
        function addVerificationKey(uint8 memory circuit_id, bytes memory vkey) external
        function verify(uint8 memory circuit_id, bytes memory proof, bytes memory public_inputs) external view returns (bool)
    ]"#
);

abigen!(
    VerifierTestContract,
    r#"[
        function verify(address memory verifier_address, bytes memory verification_bundle_ser) external view returns (bool)
    ]"#
);

abigen!(
    PrecompileTestContract,
    r#"[
        function testEcAdd() external view
        function testEcMul() external view
        function testEcPairing() external view
    ]"#
);
