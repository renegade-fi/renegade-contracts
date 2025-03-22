//! Contains ABI definitions for the Darkpool and associated contracts
use alloy::primitives::{Bytes, U256};
pub use IDarkpool::*;

use alloy::sol_types::sol;
use eyre::Result;
use renegade_constants::Scalar;

use crate::util::transactions::call_helper;
use crate::Darkpool;

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

impl Default for TransferAuthorization {
    fn default() -> Self {
        Self {
            permit2Nonce: U256::ZERO,
            permit2Deadline: U256::ZERO,
            permit2Signature: Bytes::new(),
            externalTransferSignature: Bytes::new(),
        }
    }
}

impl TransferAuthorization {
    /// Create a withdrawal authorization
    pub fn withdrawal(sig_bytes: Vec<u8>) -> Self {
        Self {
            permit2Nonce: U256::ZERO,
            permit2Deadline: U256::ZERO,
            permit2Signature: Bytes::new(),
            externalTransferSignature: Bytes::from(sig_bytes),
        }
    }
}
