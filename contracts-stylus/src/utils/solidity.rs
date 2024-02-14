//! Various Solidity definitions, including ABI-compatible interfaces, events, functions, etc.

use alloy_sol_types::sol;

// Various methods and events used in the Renegade smart contracts
sol! {

    // -------------
    // | FUNCTIONS |
    // -------------

    // Merkle functions
    function init() external;
    function root() external view returns (uint256);
    function rootInHistory(uint256 root) external view returns (bool);
    function insertSharesCommitment(uint256[] shares) external;
    function verifyStateSigAndInsert(uint256[] shares, bytes sig, uint256[4] old_pk_root) external;

    // Vkeys functions
    function validWalletCreateVkey() external view returns (bytes);
    function validWalletUpdateVkey() external view returns (bytes);
    function processMatchSettleVkeys() external view returns (bytes);

    // Verifier functions
    function verify(bytes memory verification_bundle) external view returns (bool);
    function verifyMatch(bytes memory match_bundle) external view returns (bool);

    // Testing functions
    function isDummyUpgradeTarget() external view returns (bool);

    /// The native `transfer` function on the ERC20 interface.
    /// Taken from https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.0.0/contracts/token/ERC20/IERC20.sol#L41
    function transfer(address to, uint256 value) external returns (bool);

    // ----------
    // | EVENTS |
    // ----------

    // Merkle events
    event NodeChanged(uint8 indexed height, uint128 indexed index, uint256 indexed new_value);

    // Darkpool user interaction events
    event NullifierSpent(uint256 indexed nullifier);
    event WalletUpdated(uint256 indexed wallet_blinder_share);
    event ExternalTransfer(address indexed account, address indexed mint, bool indexed is_withdrawal, uint256 amount);

    // Darkpool controls events
    event FeeChanged(uint256 indexed new_fee);
    event OwnershipTransferred(address indexed new_owner);
    event Paused();
    event Unpaused();
    event VerifierAddressChanged(address indexed new_address);
    event VkeysAddressChanged(address indexed new_address);
    event MerkleAddressChanged(address indexed new_address);
}
