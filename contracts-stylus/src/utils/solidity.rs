//! Various Solidity definitions, including ABI-compatible interfaces, events,
//! functions, etc.

#![allow(clippy::too_many_arguments)]

use alloy_sol_types::sol;
use stylus_sdk::prelude::sol_interface;

// Various methods and events used in the Renegade smart contracts
sol! {

    // -------------
    // | FUNCTIONS |
    // -------------

    // Core wallet ops functions
    function newWallet(bytes memory proof, bytes memory valid_wallet_create_statement_bytes) external;
    function updateWallet(bytes memory proof, bytes memory valid_wallet_update_statement_bytes, bytes memory wallet_commitment_signature, bytes memory transfer_aux_data) external;
    function settleOnlineRelayerFee(bytes memory proof, bytes memory valid_relayer_fee_settlement_statement, bytes memory relayer_wallet_commitment_signature) external;
    function settleOfflineFee(bytes memory proof, bytes memory valid_offline_fee_settlement_statement) external;
    function redeemFee(bytes memory proof, bytes memory valid_fee_redemption_statement, bytes memory recipient_wallet_commitment_signature) external;

    // Core settlement functions
    function processMatchSettle(bytes memory party_0_match_payload, bytes memory party_1_match_payload, bytes memory valid_match_settle_statement, bytes memory match_proofs, bytes memory match_linking_proofs) external;
    function processMatchSettleWithCommitments(bytes memory party_0_match_payload, bytes memory party_1_match_payload, bytes memory valid_match_settle_statement, bytes memory match_proofs, bytes memory match_linking_proofs) external;
    function processAtomicMatchSettle(address receiver, bytes memory internal_party_match_payload, bytes memory valid_match_settle_statement, bytes memory match_proofs, bytes memory match_linking_proofs) external payable returns (uint256);
    function processAtomicMatchSettleWithCommitments(address receiver, bytes memory internal_party_match_payload, bytes memory valid_match_settle_statement, bytes memory match_proofs, bytes memory match_linking_proofs) external payable returns (uint256);
    function processMalleableAtomicMatchSettle(uint256 quoteAmount, uint256 baseAmount, address receiver, bytes memory internal_party_match_payload, bytes memory valid_match_settle_statement, bytes memory match_proofs, bytes memory match_linking_proofs) external payable returns (uint256);

    // Merkle functions
    function init() external;
    function root() external view returns (uint256);
    function rootInHistory(uint256 root) external view returns (bool);
    function insertSharesCommitment(uint256[] shares) external;
    function insertSharesWithSig(uint256[] shares, bytes sig, uint256[4] old_pk_root) external;
    function insertCommitment(uint256 commitment) external;
    function insertCommitmentWithSig(uint256 commitment, bytes sig, uint256[4] old_pk_root) external;

    // Vkeys functions
    function validWalletCreateVkey() external view returns (bytes);
    function validWalletUpdateVkey() external view returns (bytes);
    function processMatchSettleVkeys() external view returns (bytes);
    function processMatchSettleWithCommitmentsVkeys() external view returns (bytes);
    function processAtomicMatchSettleVkeys() external view returns (bytes);
    function processAtomicMatchSettleWithCommitmentsVkeys() external view returns (bytes);
    function processMalleableAtomicMatchSettleVkeys() external view returns (bytes);
    function validRelayerFeeSettlementVkey() external view returns (bytes);
    function validOfflineFeeSettlementVkey() external view returns (bytes);
    function validFeeRedemptionVkey() external view returns (bytes);

    // Verifier functions
    function verify(bytes memory verification_bundle) external view returns (bool);
    function verifyBatch(bytes memory verification_bundle) external view returns (bool);
    function verifyMatch(bytes memory match_bundle) external view returns (bool);
    function verifyAtomicMatch(bytes memory atomic_match_bundle) external view returns (bool);

    // Transfer executor functions
    function init(address memory permit2_address) external;
    function executeExternalTransfer(bytes memory old_pk_root, bytes memory transfer, bytes memory transfer_aux_data) external;
    function executeTransferBatch(bytes memory transfers) external;

    // ERC20 functions
    // Taken from https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.0.0/contracts/token/ERC20/IERC20.sol#L41
    function transfer(address to, uint256 value) external returns (bool);
    function transferFrom(address from, address to, uint256 value) external returns (bool);

    // Native asset wrapper functions
    function deposit() external payable;
    function withdrawTo(address to, uint256 value) external;

    // Testing functions
    function isDummyUpgradeTarget() external view returns (bool);

    // ----------
    // | EVENTS |
    // ----------

    // Merkle events; we emit the opening path of the inserted node
    event MerkleOpeningNode(uint8 indexed height, uint128 indexed index, uint256 indexed new_value);
    event MerkleInsertion(uint128 indexed index, uint256 indexed value);

    // Darkpool user interaction events
    event NullifierSpent(uint256 indexed nullifier);
    event WalletUpdated(uint256 indexed wallet_blinder_share);
    event ExternalTransfer(address indexed account, address indexed mint, bool indexed is_withdrawal, uint256 amount);
    event NotePosted(uint256 indexed note_commitment);
    event ExternalMatchOutput(uint256 indexed received_amount);

    // Darkpool controls events
    event FeeChanged(uint256 indexed new_fee);
    event ExternalMatchFeeChanged(address indexed asset, uint256 indexed new_fee);
    event PubkeyRotated(uint256 indexed new_pubkey_x, uint256 indexed new_pubkey_y);
    event ExternalFeeCollectionAddressChanged(address indexed new_address);
    event OwnershipTransferred(address indexed new_owner);
    event Paused();
    event Unpaused();
    event CoreWalletOpsAddressChanged(address indexed new_address);
    event CoreMatchSettlementAddressChanged(address indexed new_address);
    event CoreAtomicMatchSettlementAddressChanged(address indexed new_address);
    event CoreMalleableMatchSettlementAddressChanged(address indexed new_address);
    event VerifierCoreAddressChanged(address indexed new_address);
    event VerifierSettlementAddressChanged(address indexed new_address);
    event VkeysAddressChanged(address indexed new_address);
    event MerkleAddressChanged(address indexed new_address);
    event TransferExecutorAddressChanged(address indexed new_address);

    // Gas sponsorship events
    event InsufficientSponsorBalance(uint256 indexed nonce);
    event NonceUsed(uint256 indexed nonce);
    event GasSponsorPausedFallback(uint256 indexed nonce);
    event SponsoredExternalMatch(uint256 indexed refund_amount, address indexed token, uint256 indexed nonce);
    event SponsoredExternalMatchOutput(uint256 indexed received_amount, uint256 indexed nonce);
}

sol_interface! {
    interface IDarkpool {
        function processAtomicMatchSettleWithReceiver(address receiver, bytes memory internal_party_match_payload, bytes memory valid_match_settle_atomic_statement, bytes memory match_proofs, bytes memory match_linking_proofs) external payable returns (uint256);
        function processMalleableAtomicMatchSettleWithReceiver(uint256 quote_amount, uint256 base_amount, address receiver, bytes memory internal_party_match_payload, bytes memory malleable_match_settle_atomic_statement, bytes memory proofs, bytes memory linking_proofs) external payable returns (uint256);
    }

    interface IErc20 {
        function transferFrom(address from, address to, uint256 value) external returns (bool);
        function transfer(address to, uint256 value) external returns (bool);
        function approve(address spender, uint256 value) external returns (bool);
        function balanceOf(address account) external view returns (uint256);
    }
}
