//! Solidity ABI definitions for the contracts used in integration tests

use ethers::prelude::abigen;

abigen!(
    DarkpoolTestContract,
    r#"[
        function initialize(address memory core_wallet_ops_address, address memory core_settlement_address, address memory verifier_core_address, address memory verifier_settlement_address, address memory vkeys_address, address memory merkle_address, address memory transfer_executor_address, address memory permit2_address, uint256 memory protocol_fee, uint256[2] protocol_public_encryption_key) external

        function owner() external view returns (address)
        function transferOwnership(address memory new_owner) external

        function paused() external view returns (bool)
        function pause() external
        function unpause() external

        function setFee(uint256 memory new_fee) external
        function setExternalMatchFeeOverride(address memory asset, uint256 memory new_fee) external
        function removeExternalMatchFeeOverride(address memory asset) external
        function setCoreWalletOpsAddress(address memory core_wallet_ops_address) external
        function setCoreSettlementAddress(address memory core_settlement_address) external
        function setVerifierCoreAddress(address memory verifier_core_address) external
        function setVerifierSettlementAddress(address memory verifier_settlement_address) external
        function setVkeysAddress(address memory vkeys_address) external
        function setMerkleAddress(address memory merkle_address) external
        function setTransferExecutorAddress(address memory transfer_executor_address) external

        function isNullifierSpent(uint256 memory nullifier) external view returns (bool)

        function getRoot() external view returns (uint256)
        function getFee() external view returns (uint256)
        function getExternalMatchFeeForAsset(address memory asset) external view returns (uint256)
        function getPubkey() external view returns (uint256[2])
        function getProtocolExternalFeeCollectionAddress() external view returns (address)

        function newWallet(bytes memory proof, bytes memory valid_wallet_create_statement_bytes) external
        function updateWallet(bytes memory proof, bytes memory valid_wallet_update_statement_bytes, bytes memory wallet_commitment_signature, bytes memory transfer_aux_data) external
        function processMatchSettle(bytes memory party_0_match_payload, bytes memory party_1_match_payload, bytes memory valid_match_settle_statement, bytes memory match_proofs, bytes memory match_linking_proofs) external
        function processAtomicMatchSettle(bytes memory internal_party_match_payload, bytes memory valid_match_settle_atomic_statement, bytes memory match_proofs, bytes memory match_linking_proofs) external payable
        function processAtomicMatchSettleWithReceiver(address receiver, bytes memory internal_party_match_payload, bytes memory valid_match_settle_atomic_statement, bytes memory match_proofs, bytes memory match_linking_proofs) external payable
        function settleOnlineRelayerFee(bytes memory proof, bytes memory valid_relayer_fee_settlement_statement, bytes memory relayer_wallet_commitment_signature) external
        function settleOfflineFee(bytes memory proof, bytes memory valid_offline_fee_settlement_statement) external
        function redeemFee(bytes memory proof, bytes memory valid_fee_redemption_statement, bytes memory recipient_wallet_commitment_signature) external

        function markNullifierSpent(uint256 memory nullifier) external
        function isImplementationUpgraded(uint8 memory address_selector) external view returns (bool)
        function clearMerkle() external
    ]"#
);

abigen!(
    TransferExecutorContract,
    r#"[
        function init(address permit2_address) external
        function executeExternalTransfer(bytes memory old_pk_root, bytes memory transfer, bytes memory transfer_aux_data) external
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
        function verifyBatch(bytes memory verification_bundle) external view returns (bool)
    ]"#
);

abigen!(
    VerifierSettlementContract,
    r#"[
        function verifyMatch(bytes memory match_bundle) external view returns (bool)
        function verifyMatchAtomic(bytes memory match_bundle) external view returns (bool)
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
        function totalSupply() external view returns (uint256)
        function balanceOf(address account) external view returns (uint256)
        function mint(address memory _address, uint256 memory value) external
        function burn(address memory _address, uint256 memory value) external
        function transfer(address to, uint256 value) external returns (bool)
        function allowance(address owner, address spender) external view returns (uint256)
        function approve(address spender, uint256 value) external returns (bool)
        function transferFrom(address from, address to, uint256 value) external returns (bool)
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

abigen!(
    IAtomicMatchSettleContract,
    r#"[
        function processAtomicMatchSettle(bytes memory internal_party_match_payload, bytes memory valid_match_settle_atomic_statement, bytes memory match_proofs, bytes memory match_linking_proofs) external payable
        function processAtomicMatchSettleWithReceiver(address receiver, bytes memory internal_party_match_payload, bytes memory valid_match_settle_atomic_statement, bytes memory match_proofs, bytes memory match_linking_proofs) external payable
    ]"#
);

abigen!(
    GasSponsorContract,
    r#"[
        function pause() external
        function unpause() external
        function receiveEth() external payable
        function withdrawEth(address receiver, uint256 amount) external
        function processAtomicMatchSettle(bytes memory internal_party_match_payload, bytes memory valid_match_settle_atomic_statement, bytes memory match_proofs, bytes memory match_linking_proofs) external payable
        function processAtomicMatchSettleWithReceiver(address receiver, bytes memory internal_party_match_payload, bytes memory valid_match_settle_atomic_statement, bytes memory match_proofs, bytes memory match_linking_proofs) external payable
        function sponsorAtomicMatchSettle(bytes memory internal_party_match_payload, bytes memory valid_match_settle_atomic_statement, bytes memory match_proofs, bytes memory match_linking_proofs, address memory refund_address, uint256 memory nonce, bytes memory signature) external payable
        function sponsorAtomicMatchSettleWithReceiver(address receiver, bytes memory internal_party_match_payload, bytes memory valid_match_settle_atomic_statement, bytes memory match_proofs, bytes memory match_linking_proofs, address memory refund_address, uint256 memory nonce, bytes memory signature) external payable
        function sponsorAtomicMatchSettleWithRefundOptions(address receiver, bytes memory internal_party_match_payload, bytes memory valid_match_settle_atomic_statement, bytes memory match_proofs, bytes memory match_linking_proofs, address memory refund_address, uint256 memory nonce, bool memory refund_native_eth, uint256 memory conversion_rate, bytes memory signature) external payable
    ]"#
);
