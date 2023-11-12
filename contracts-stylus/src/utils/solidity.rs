//! Various Solidity definitions, including ABI-compatible interfaces, events, functions, etc.

use alloy_sol_types::sol;
use stylus_sdk::stylus_proc::sol_interface;

sol_interface! {
    // Taken from https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.0.0/contracts/token/ERC20/IERC20.sol
    interface IERC20 {
        event Transfer(address indexed from, address indexed to, uint256 value);
        event Approval(address indexed owner, address indexed spender, uint256 value);

        function totalSupply() external view returns (uint256);
        function balanceOf(address account) external view returns (uint256);
        function transfer(address to, uint256 value) external returns (bool);
        function allowance(address owner, address spender) external view returns (uint256);
        function approve(address spender, uint256 value) external returns (bool);
        function transferFrom(address from, address to, uint256 value) external returns (bool);
    }

    interface IMerkle {
        function init() external;
        function root() external view returns (bytes);
        function rootInHistory(bytes root) external view returns (bool);
        function insertSharesCommitment(bytes shares) external;
    }
}

sol! {

    // -------------
    // | FUNCTIONS |
    // -------------

    // Merkle functions
    function init() external;
    function root() external view returns (bytes);
    function rootInHistory(bytes root) external view returns (bool);
    function insertSharesCommitment(bytes shares) external;

    // ----------
    // | EVENTS |
    // ----------

    // Indexed `bytes` event parameters are encoded as their Keccak-256 hash
    // https://docs.soliditylang.org/en/latest/abi-spec.html#encoding-of-indexed-event-parameters

    // Ownable events
    event InvalidOwner(address owner);
    event OwnershipTransferred(address indexed previous_owner, address indexed new_owner);

    // Initializable events
    event Initialized(uint64 version);

    // Merkle events
    event RootChanged(bytes indexed prev_root, bytes indexed new_root);
    event ValueInserted(uint128 indexed index, bytes indexed value);
    event InternalNodeChanged(uint8 indexed height, uint128 indexed index, bytes indexed new_value);
}
