//! Various Solidity definitions, including ABI-compatible interfaces, events, functions, etc.

use alloy_sol_types::sol;
use stylus_sdk::stylus_proc::sol_interface;

sol_interface! {
    // Taken from https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.0.0/contracts/token/ERC20/IERC20.sol
    interface IERC20 {
        function transferFrom(address from, address to, uint256 value) external returns (bool);
    }
}

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

    // ----------
    // | EVENTS |
    // ----------

    // Merkle events
    event NodeChanged(uint8 indexed height, uint128 indexed index, uint256 indexed new_value);

    // Darkpool events
    event NullifierSpent(uint256 indexed nullifier);
    event WalletUpdated(uint256 indexed wallet_blinder_share);
    event ExternalTransfer(address indexed account, address indexed mint, bool indexed is_withdrawal, uint256 amount);
}
