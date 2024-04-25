//! Various Solidity definitions, including ABI-compatible interfaces, events, functions, etc.

use alloy_sol_types::sol;

// Various methods and events used in the Renegade smart contracts
sol! {

    // -------------
    // | FUNCTIONS |
    // -------------

    // Core functions
    function newWallet(bytes memory proof, bytes memory valid_wallet_create_statement_bytes) external;
    function updateWallet(bytes memory proof, bytes memory valid_wallet_update_statement_bytes, bytes memory wallet_commitment_signature, bytes memory transfer_aux_data) external;
    function processMatchSettle(bytes memory party_0_match_payload, bytes memory party_1_match_payload, bytes memory valid_match_settle_statement, bytes memory match_proofs, bytes memory match_linking_proofs) external;
    function settleOnlineRelayerFee(bytes memory proof, bytes memory valid_relayer_fee_settlement_statement, bytes memory relayer_wallet_commitment_signature) external;
    function settleOfflineFee(bytes memory proof, bytes memory valid_offline_fee_settlement_statement) external;
    function redeemFee(bytes memory proof, bytes memory valid_fee_redemption_statement, bytes memory recipient_wallet_commitment_signature) external;

    // Merkle functions
    function init() external;
    function root() external view returns (uint256);
    function rootInHistory(uint256 root) external view returns (bool);
    function insertSharesCommitment(uint256[] shares) external;
    function verifyStateSigAndInsert(uint256[] shares, bytes sig, uint256[4] old_pk_root) external;
    function insertNoteCommitment(uint256 note_commitment) external;

    // Vkeys functions
    function validWalletCreateVkey() external view returns (bytes);
    function validWalletUpdateVkey() external view returns (bytes);
    function processMatchSettleVkeys() external view returns (bytes);
    function validRelayerFeeSettlementVkey() external view returns (bytes);
    function validOfflineFeeSettlementVkey() external view returns (bytes);
    function validFeeRedemptionVkey() external view returns (bytes);

    // Verifier functions
    function verify(bytes memory verification_bundle) external view returns (bool);
    function verifyMatch(bytes memory match_bundle) external view returns (bool);

    // Transfer executor functions
    function init(address memory permit2_address) external;
    function executeExternalTransfer(bytes memory old_pk_root, bytes memory transfer, bytes memory transfer_aux_data) external;

    /// The native `transfer` function on the ERC20 interface.
    /// Taken from https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.0.0/contracts/token/ERC20/IERC20.sol#L41
    function transfer(address to, uint256 value) external returns (bool);

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

    // Darkpool controls events
    event FeeChanged(uint256 indexed new_fee);
    event PubkeyRotated(uint256 indexed new_pubkey_x, uint256 indexed new_pubkey_y);
    event OwnershipTransferred(address indexed new_owner);
    event Paused();
    event Unpaused();
    event DarkpoolCoreAddressChanged(address indexed new_address);
    event VerifierAddressChanged(address indexed new_address);
    event VkeysAddressChanged(address indexed new_address);
    event MerkleAddressChanged(address indexed new_address);
    event TransferExecutorAddressChanged(address indexed new_address);
}
