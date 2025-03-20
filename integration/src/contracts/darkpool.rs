//! Contains ABI definitions for the Darkpool and associated contracts
pub use IDarkpool::*;

use alloy::sol_types::sol;
use eyre::Result;
use renegade_constants::Scalar;

use crate::{util::call_helper, Darkpool};

use super::type_conversion::scalar_to_u256;

// The ABI for the Darkpool contract
sol! {
    #[allow(missing_docs)]
    #[sol(rpc)]
    IDarkpool,
    "src/contracts/abis/IDarkpool.json"
}

impl Darkpool {
    /// Check whether a given root is a valid historical root
    pub async fn check_root(&self, root: Scalar) -> Result<bool> {
        let root_u256 = scalar_to_u256(root);
        let call = self.rootInHistory(root_u256);
        let res = call_helper(call).await?;
        Ok(res._0)
    }
}
