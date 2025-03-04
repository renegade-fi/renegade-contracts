//! Solidity ABI definitions for the contracts used in integration tests

use ethers::prelude::abigen;

abigen!(
    DarkpoolTestContract,
    r#"[
        function initialize(address core_wallet_ops_address, address core_settlement_address, address verifier_core_address, address verifier_settlement_address, address vkeys_address, address merkle_address, address transfer_executor_address, address permit2_address, uint256 protocol_fee, uint256[2] protocol_public_encryption_key) external

        function owner() external view returns (address)
        function transferOwnership(address new_owner) external

        function paused() external view returns (bool)
        function pause() external
        function unpause() external

        function setFee(uint256 new_fee) external
        function setExternalMatchFeeOverride(address asset, uint256 new_fee) external
        function removeExternalMatchFeeOverride(address asset) external
        function setCoreWalletOpsAddress(address core_wallet_ops_address) external
        function setCoreSettlementAddress(address core_settlement_address) external
        function setVerifierCoreAddress(address verifier_core_address) external
        function setVerifierSettlementAddress(address verifier_settlement_address) external
        function setVkeysAddress(address vkeys_address) external
        function setMerkleAddress(address merkle_address) external
        function setTransferExecutorAddress(address transfer_executor_address) external

        function isNullifierSpent(uint256 nullifier) external view returns (bool)

        function getRoot() external view returns (uint256)
        function getFee() external view returns (uint256)
        function getExternalMatchFeeForAsset(address asset) external view returns (uint256)
        function getPubkey() external view returns (uint256[2])
        function getProtocolExternalFeeCollectionAddress() external view returns (address)

        function newWallet(bytes proof, bytes valid_wallet_create_statement_bytes) external
        function updateWallet(bytes proof, bytes valid_wallet_update_statement_bytes, bytes wallet_commitment_signature, bytes transfer_aux_data) external
        function processMatchSettle(bytes party_0_match_payload, bytes party_1_match_payload, bytes valid_match_settle_statement, bytes match_proofs, bytes match_linking_proofs) external
        function processAtomicMatchSettle(bytes internal_party_match_payload, bytes valid_match_settle_atomic_statement, bytes match_proofs, bytes match_linking_proofs) external payable
        function processAtomicMatchSettleWithReceiver(address receiver, bytes internal_party_match_payload, bytes valid_match_settle_atomic_statement, bytes match_proofs, bytes match_linking_proofs) external payable
        function settleOnlineRelayerFee(bytes proof, bytes valid_relayer_fee_settlement_statement, bytes relayer_wallet_commitment_signature) external
        function settleOfflineFee(bytes proof, bytes valid_offline_fee_settlement_statement) external
        function redeemFee(bytes proof, bytes valid_fee_redemption_statement, bytes recipient_wallet_commitment_signature) external

        function markNullifierSpent(uint256 nullifier) external
        function isImplementationUpgraded(uint8 address_selector) external view returns (bool)
        function clearMerkle() external
    ]"#
);

abigen!(
    TransferExecutorContract,
    r#"[
        function init(address permit2_address) external
        function executeExternalTransfer(bytes old_pk_root, bytes transfer, bytes transfer_aux_data) external
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
        function verify(bytes verification_bundle) external view returns (bool)
        function verifyBatch(bytes verification_bundle) external view returns (bool)
    ]"#
);

abigen!(
    VerifierSettlementContract,
    r#"[
        function verifyMatch(bytes match_bundle) external view returns (bool)
        function verifyMatchAtomic(bytes match_bundle) external view returns (bool)
    ]"#
);

abigen!(
    PrecompileTestContract,
    r#"[
        function testEcAdd(bytes a_bytes, bytes b_bytes) external view returns (bytes)
        function testEcMul(bytes a_bytes, bytes b_bytes) external view returns (bytes)
        function testEcPairing(bytes a_bytes, bytes b_bytes) external view returns (bool)
        function testEcRecover(bytes msg_hash, bytes signature) external view returns (bytes)
    ]"#
);

abigen!(
    DummyErc20Contract,
    r#"[
        function totalSupply() external view returns (uint256)
        function balanceOf(address account) external view returns (uint256)
        function mint(address _address, uint256 value) external
        function burn(address _address, uint256 value) external
        function transfer(address to, uint256 value) external returns (bool)
        function allowance(address owner, address spender) external view returns (uint256)
        function approve(address spender, uint256 value) external returns (bool)
        function transferFrom(address from, address to, uint256 value) external returns (bool)
    ]"#
);

abigen!(
    DarkpoolProxyAdminContract,
    r#"[
        function upgradeAndCall(address proxy, address implementation, bytes data) external
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
        function processAtomicMatchSettle(bytes internal_party_match_payload, bytes valid_match_settle_atomic_statement, bytes match_proofs, bytes match_linking_proofs) external payable
        function processAtomicMatchSettleWithReceiver(address receiver, bytes internal_party_match_payload, bytes valid_match_settle_atomic_statement, bytes match_proofs, bytes match_linking_proofs) external payable
    ]"#
);

abigen!(
    GasSponsorContract,
    r#"[
        function pause() external
        function unpause() external
        function receiveEth() external payable
        function withdrawEth(address receiver, uint256 amount) external
        function receiveTokens(address token, uint256 amount) external
        function withdrawTokens(address receiver, address token, uint256 amount) external
        function processAtomicMatchSettle(bytes internal_party_match_payload, bytes valid_match_settle_atomic_statement, bytes match_proofs, bytes match_linking_proofs) external payable
        function processAtomicMatchSettleWithReceiver(address receiver, bytes internal_party_match_payload, bytes valid_match_settle_atomic_statement, bytes match_proofs, bytes match_linking_proofs) external payable
        function sponsorAtomicMatchSettle(bytes internal_party_match_payload, bytes valid_match_settle_atomic_statement, bytes match_proofs, bytes match_linking_proofs, uint256 nonce, uint256 conversion_rate, bytes signature) external payable
        function sponsorAtomicMatchSettleWithReceiver(address receiver, bytes internal_party_match_payload, bytes valid_match_settle_atomic_statement, bytes match_proofs, bytes match_linking_proofs, uint256 nonce, uint256 conversion_rate, bytes signature) external payable
    ]"#
);
