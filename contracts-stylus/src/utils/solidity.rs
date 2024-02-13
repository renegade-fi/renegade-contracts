//! Various Solidity definitions, including ABI-compatible interfaces, events, functions, etc.

use alloc::vec::Vec;
use alloy_sol_types::sol;
use stylus_sdk::stylus_proc::sol_interface;

sol_interface! {
    // Taken from https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v5.0.0/contracts/token/ERC20/IERC20.sol
    interface IERC20 {
        function transferFrom(address from, address to, uint256 value) external returns (bool);
    }
}

// Various methods and events defined in the Renegade smart contracts
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

// Types & methods from the Permit2 `ISignatureTransfer` interface, taken from https://github.com/Uniswap/permit2/blob/main/src/interfaces/ISignatureTransfer.sol
sol! {
    /// The token and amount details for a transfer signed in the permit transfer signature
    struct TokenPermissions {
        // ERC20 token address
        address token;
        // the maximum amount that can be spent
        uint256 amount;
    }

    /// The signed permit message for a single token transfer
    struct PermitTransferFrom {
        TokenPermissions permitted;
        // a unique value for every token owner's signature to prevent signature replays
        uint256 nonce;
        // deadline on the permit signature
        uint256 deadline;
    }

    /// Specifies the recipient address and amount for batched transfers.
    /// Recipients and amounts correspond to the index of the signed token permissions array.
    /// Reverts if the requested amount is greater than the permitted signed amount.
    struct SignatureTransferDetails {
        // recipient address
        address to;
        // spender requested amount
        uint256 requestedAmount;
    }

    /// Transfers a token using a signed permit message
    /// Reverts if the requested amount is greater than the permitted signed amount
    /// permit The permit data signed over by the owner
    /// owner The owner of the tokens to transfer
    /// transferDetails The spender's requested transfer details for the permitted token
    /// signature The signature to verify
    function permitTransferFrom(
        PermitTransferFrom memory permit,
        SignatureTransferDetails calldata transferDetails,
        address owner,
        bytes calldata signature
    ) external;
}
