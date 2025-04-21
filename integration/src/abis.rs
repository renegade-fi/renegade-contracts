//! Solidity ABI definitions for the contracts used in integration tests

use alloy_sol_types::sol;

sol!(
    #[allow(clippy::too_many_arguments)]
    #[sol(rpc)]
    contract DarkpoolTestContract {
        function initialize(address memory core_wallet_ops_address, address memory core_settlement_address, address memory verifier_core_address, address memory verifier_settlement_address, address memory vkeys_address, address memory merkle_address, address memory transfer_executor_address, address memory permit2_address, uint256 memory protocol_fee, uint256[2] protocol_public_encryption_key) external;

        function owner() external view returns (address);
        function transferOwnership(address memory new_owner) external;

        function paused() external view returns (bool);
        function pause() external;
        function unpause() external;

        function setFee(uint256 memory new_fee) external;
        function setExternalMatchFeeOverride(address memory asset, uint256 memory new_fee) external;
        function removeExternalMatchFeeOverride(address memory asset) external;
        function setCoreWalletOpsAddress(address memory core_wallet_ops_address) external;
        function setCoreMatchSettleAddress(address memory core_match_settle_address) external;
        function setCoreAtomicMatchSettleAddress(address memory core_atomic_match_settle_address) external;
        function setCoreMalleableMatchSettleAddress(address memory core_malleable_match_settle_address) external;
        function setVerifierCoreAddress(address memory verifier_core_address) external;
        function setVerifierSettlementAddress(address memory verifier_settlement_address) external;
        function setVkeysAddress(address memory vkeys_address) external;
        function setMerkleAddress(address memory merkle_address) external;
        function setTransferExecutorAddress(address memory transfer_executor_address) external;

        function isNullifierSpent(uint256 memory nullifier) external view returns (bool);

        function getRoot() external view returns (uint256);
        function getFee() external view returns (uint256);
        function getExternalMatchFeeForAsset(address memory asset) external view returns (uint256);
        function getPubkey() external view returns (uint256[2]);
        function getProtocolExternalFeeCollectionAddress() external view returns (address);

        function newWallet(bytes memory proof, bytes memory valid_wallet_create_statement_bytes) external;
        function updateWallet(bytes memory proof, bytes memory valid_wallet_update_statement_bytes, bytes memory wallet_commitment_signature, bytes memory transfer_aux_data) external;
        function processMatchSettle(bytes memory party_0_match_payload, bytes memory party_1_match_payload, bytes memory valid_match_settle_statement, bytes memory match_proofs, bytes memory match_linking_proofs) external;
        function processMatchSettleWithCommitments(bytes memory party_0_match_payload, bytes memory party_1_match_payload, bytes memory valid_match_settle_statement, bytes memory match_proofs, bytes memory match_linking_proofs) external;
        function processAtomicMatchSettle(bytes memory internal_party_match_payload, bytes memory valid_match_settle_atomic_statement, bytes memory match_proofs, bytes memory match_linking_proofs) external payable;
        function processAtomicMatchSettleWithReceiver(address receiver, bytes memory internal_party_match_payload, bytes memory valid_match_settle_atomic_statement, bytes memory match_proofs, bytes memory match_linking_proofs) external payable;
        function processMalleableAtomicMatchSettle(uint256 memory base_amount, address receiver, bytes memory internal_party_payload, bytes memory malleable_match_settle_atomic_statement, bytes memory proofs, bytes memory linking_proofs) external payable;
        function settleOnlineRelayerFee(bytes memory proof, bytes memory valid_relayer_fee_settlement_statement, bytes memory relayer_wallet_commitment_signature) external;
        function settleOfflineFee(bytes memory proof, bytes memory valid_offline_fee_settlement_statement) external;
        function redeemFee(bytes memory proof, bytes memory valid_fee_redemption_statement, bytes memory recipient_wallet_commitment_signature) external;

        function markNullifierSpent(uint256 memory nullifier) external;
        function isImplementationUpgraded(uint8 memory address_selector) external view returns (bool);
        function clearMerkle() external;

        event ExternalMatchOutput(uint256 indexed received_amount);
    }
);

sol!(
    #[sol(rpc)]
    contract TransferExecutorContract {
        function init(address permit2_address) external;
        function executeExternalTransfer(bytes memory old_pk_root, bytes memory transfer, bytes memory transfer_aux_data) external;
    }
);

sol!(
    #[sol(rpc)]
    contract MerkleContract {
        function init() external;
        function root() external view returns (uint256);
        function rootInHistory(uint256 root) external view returns (bool);
        function insertSharesCommitment(uint256[] shares) external;
    }
);

sol!(
    #[sol(rpc)]
    contract VerifierContract {
        function verify(bytes memory verification_bundle) external view returns (bool);
        function verifyBatch(bytes memory verification_bundle) external view returns (bool);
    }
);

sol!(
    #[sol(rpc)]
    contract VerifierSettlementContract {
        function verifyMatch(bytes memory match_bundle) external view returns (bool);
        function verifyMatchAtomic(bytes memory match_bundle) external view returns (bool);
    }
);

sol!(
    #[sol(rpc)]
    contract PrecompileTestContract {
        function testEcAdd(bytes memory a_bytes, bytes memory b_bytes) external view returns (bytes);
        function testEcMul(bytes memory a_bytes, bytes memory b_bytes) external view returns (bytes);
        function testEcPairing(bytes memory a_bytes, bytes memory b_bytes) external view returns (bool);
        function testEcRecover(bytes memory msg_hash, bytes memory signature) external view returns (bytes);
    }
);

sol!(
    #[sol(rpc)]
    contract DummyErc20Contract {
        function totalSupply() external view returns (uint256);
        function balanceOf(address account) external view returns (uint256);
        function mint(address memory _address, uint256 memory value) external;
        function burn(address memory _address, uint256 memory value) external;
        function transfer(address to, uint256 value) external returns (bool);
        function allowance(address owner, address spender) external view returns (uint256);
        function approve(address spender, uint256 value) external returns (bool);
        function transferFrom(address from, address to, uint256 value) external returns (bool);
    }
);

sol!(
    #[sol(rpc)]
    contract DarkpoolProxyAdminContract {
        function upgradeAndCall(address proxy, address implementation, bytes memory data) external;
    }
);

sol!(
    #[sol(rpc)]
    contract DummyUpgradeTargetContract {
        function isDummyUpgradeTarget() external view returns (bool);
    }
);

sol!(
    #[allow(clippy::too_many_arguments)]
    #[sol(rpc)]
    contract GasSponsorContract {
        function pause() external;
        function unpause() external;
        function receiveEth() external payable;
        function withdrawEth(address receiver, uint256 amount) external;
        function sponsorAtomicMatchSettleWithRefundOptions(
            address receiver,
            bytes memory internal_party_match_payload,
            bytes memory valid_match_settle_atomic_statement,
            bytes memory match_proofs,
            bytes memory match_linking_proofs,
            address memory refund_address,
            uint256 memory nonce,
            bool memory refund_native_eth,
            uint256 memory refund_amount,
            bytes memory signature
        ) external payable returns (uint256);

        event SponsoredExternalMatchOutput(uint256 indexed received_amount, uint256 indexed nonce);
    }
);
