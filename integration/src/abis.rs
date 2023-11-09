//! Solidity ABI definitions for the contracts used in integration tests

use ethers::prelude::abigen;

abigen!(
    DarkpoolTestContract,
    r#"[
        function transferOwnership(address memory newOwner) external

        function setVerifierAddress(address memory _address) external

        function setValidWalletCreateVkey(bytes memory vkey) external
        function setValidWalletUpdateVkey(bytes memory vkey) external
        function setValidCommitmentsVkey(bytes memory vkey) external
        function setValidReblindVkey(bytes memory vkey) external
        function setValidMatchSettleVkey(bytes memory vkey) external

        function isNullifierSpent(bytes memory nullifier) external view returns (bool)
        function markNullifierSpent(bytes memory nullifier) external

        function newWallet(bytes memory wallet_blinder_share, bytes memory proof, bytes memory valid_wallet_create_statement_bytes) external
        function updateWallet(bytes memory wallet_blinder_share, bytes memory proof, bytes memory valid_wallet_update_statement_bytes, bytes memory public_inputs_signature) external
        function processMatchSettle(bytes memory party_0_match_payload, bytes memory party_0_valid_commitments_proof, bytes memory party_0_valid_reblind_proof, bytes memory party_1_match_payload, bytes memory party_1_valid_commitments_proof, bytes memory party_1_valid_reblind_proof, bytes memory valid_match_settle_proof, bytes memory valid_match_settle_statement_bytes,) external

        function verify(uint8 memory circuit_id, bytes memory proof, bytes memory public_inputs) external view returns (bool)

        function executeExternalTransfer(bytes memory transfer) external
    ]"#
);

abigen!(
    MerkleContract,
    r#"[
        function init() external
        function root() external view returns (bytes)
        function rootInHistory(bytes root) external view returns (bool)
        function insert(bytes value) external
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
        function testEcAdd(bytes memory a_bytes, bytes memory b_bytes) external view returns (bytes)
        function testEcMul(bytes memory a_bytes, bytes memory b_bytes) external view returns (bytes)
        function testEcPairing(bytes memory a_bytes, bytes memory b_bytes) external view returns (bool)
        function testEcRecover(bytes memory msg_hash, bytes memory signature) external view returns (bytes)
    ]"#
);

abigen!(
    DummyErc20Contract,
    r#"[
        function mint(address memory _address, uint256 memory value) external
        function balanceOf(address memory _address) external view returns (uint256)
    ]"#
);
