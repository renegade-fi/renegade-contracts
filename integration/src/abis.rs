//! Solidity ABI definitions for the contracts used in integration tests

use ethers::prelude::abigen;

abigen!(
    DarkpoolTestContract,
    r#"[
        function initialize(address memory verifier_address, address memory vkeys_address, address memory merkle_address, uint256 memory protocol_fee) external

        function owner() external view returns (address)
        function transferOwnership(address memory new_owner) external

        function paused() external view returns (bool)
        function pause() external
        function unpause() external

        function setFee(uint256 memory new_fee) external
        function setVerifierAddress(address memory verifier_address) external
        function setVkeysAddress(address memory vkeys_address) external
        function setMerkleAddress(address memory merkle_address) external

        function isNullifierSpent(uint256 memory nullifier) external view returns (bool)

        function getRoot() external view returns (uint256)

        function newWallet(bytes memory proof, bytes memory valid_wallet_create_statement_bytes) external
        function updateWallet(bytes memory proof, bytes memory valid_wallet_update_statement_bytes, bytes memory public_inputs_signature) external
        function processMatchSettle(bytes memory party_0_match_payload, bytes memory party_0_valid_commitments_proof, bytes memory party_0_valid_reblind_proof, bytes memory party_1_match_payload, bytes memory party_1_valid_commitments_proof, bytes memory party_1_valid_reblind_proof, bytes memory valid_match_settle_proof, bytes memory valid_match_settle_statement_bytes) external

        function markNullifierSpent(uint256 memory nullifier) external
        function executeExternalTransfer(bytes memory transfer) external
        function isImplementationUpgraded(uint8 memory address_selector) external view returns (bool)
        function clearMerkle() external
    ]"#
);

abigen!(
    MerkleContract,
    r#"[
        function init() external
        function root() external view returns (uint256)
        function rootInHistory(uint256 root) external view returns (bool)
        function insertSharesCommitment(uint256[] shares) external
    ]"#
);

abigen!(
    VerifierContract,
    r#"[
        function verify(bytes memory verification_bundle) external view returns (bool)
        function verifyMatch(bytes memory match_bundle) external view returns (bool)
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

abigen!(
    DarkpoolProxyAdminContract,
    r#"[
        function upgradeAndCall(address proxy, address implementation, bytes memory data) external
    ]"#
);

abigen!(
    DummyUpgradeTargetContract,
    r#"[
        function isDummyUpgradeTarget() external view returns (bool)
    ]"#
);
