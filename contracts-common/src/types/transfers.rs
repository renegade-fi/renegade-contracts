//! Types related to darkpool deposits and withdrawals

use alloc::vec::Vec;
use alloy_primitives::{Address, U256};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::serde_def_types::*;

/// Represents an external transfer of an ERC20 token
#[serde_as]
#[derive(Serialize, Deserialize, Default)]
pub struct ExternalTransfer {
    /// The address of the account contract to deposit from or withdraw to
    #[serde_as(as = "AddressDef")]
    pub account_addr: Address,
    /// The mint (contract address) of the token being transferred
    #[serde_as(as = "AddressDef")]
    pub mint: Address,
    /// The amount of the token transferred
    #[serde_as(as = "U256Def")]
    pub amount: U256,
    /// Whether or not the transfer is a withdrawal (otherwise a deposit)
    pub is_withdrawal: bool,
}

/// Auxiliary authorization data for an external transfer
///
/// Passed alongside an external transfer to verify its validity.
/// This includes a signature over the external transfer, and in the case of a
/// deposit, the associated Permit2 data ([reference](https://docs.uniswap.org/contracts/permit2/reference/signature-transfer))
#[serde_as]
#[derive(Default, Serialize, Deserialize)]
pub struct TransferAuxData {
    /// The `PermitTransferFrom` nonce
    #[serde_as(as = "Option<U256Def>")]
    pub permit_nonce: Option<U256>,
    /// The `PermitTransferFrom` deadline
    #[serde_as(as = "Option<U256Def>")]
    pub permit_deadline: Option<U256>,
    /// The signature of the `PermitTransferFrom` typed data
    pub permit_signature: Option<Vec<u8>>,
    /// The signature of the external transfer
    pub transfer_signature: Option<Vec<u8>>,
}

/// A simple erc20 transfer
///
/// For deposits, we directly use the erc20 contracts `transfer` function
/// assuming that the caller has approved the darkpool contract to spend the
/// deposit. This means that no permit2 logic is needed.
#[serde_as]
#[derive(Serialize, Deserialize)]
pub struct SimpleErc20Transfer {
    /// The address of the account contract to deposit from or withdraw to
    #[serde_as(as = "AddressDef")]
    pub account_addr: Address,
    /// The mint (contract address) of the token being transferred
    #[serde_as(as = "AddressDef")]
    pub mint: Address,
    /// The amount of the token to transfer
    #[serde_as(as = "U256Def")]
    pub amount: U256,
    /// Whether or not the transfer is a withdrawal (otherwise a deposit)
    pub is_withdrawal: bool,
}

#[cfg(feature = "core-settlement")]
impl SimpleErc20Transfer {
    /// Create a new withdraw transfer
    pub fn new_withdraw(to: Address, mint: Address, amount: U256) -> Self {
        Self { mint, account_addr: to, amount, is_withdrawal: true }
    }

    /// Create a new deposit transfer
    pub fn new_deposit(from: Address, mint: Address, amount: U256) -> Self {
        Self { mint, account_addr: from, amount, is_withdrawal: false }
    }
}
