//! Default implementation for SignedPermitSingle

use crate::v2::{IDarkpoolV2::SignedPermitSingle, IAllowanceTransfer};

impl Default for SignedPermitSingle {
    fn default() -> Self {
        Self {
            permitSingle: IAllowanceTransfer::PermitSingle {
                details: IAllowanceTransfer::PermitDetails {
                    token: Default::default(),
                    amount: Default::default(),
                    expiration: Default::default(),
                    nonce: Default::default(),
                },
                spender: Default::default(),
                sigDeadline: Default::default(),
            },
            signature: Default::default(),
        }
    }
}
