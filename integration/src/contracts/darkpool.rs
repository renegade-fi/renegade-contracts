//! Contains ABI definitions for the Darkpool and associated contracts

use alloy::sol_types::sol;

// The ABI for the Darkpool contract
sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    IDarkpool,
    "src/contracts/abis/IDarkpool.json"
}
