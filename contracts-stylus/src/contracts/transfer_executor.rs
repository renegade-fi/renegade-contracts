//! The transfer executor contract, responsible for executing external transfers to/from the darkpool
//! (it is intended to be delegate-called by the darkpool)

use crate::utils::{
    constants::{
        MERKLE_STORAGE_GAP_SIZE, MISSING_PK_ROOT_ERROR_MESSAGE,
        MISSING_TRANSFER_AUX_DATA_ERROR_MESSAGE,
    },
    helpers::{assert_valid_signature, call_helper, deserialize_from_calldata, postcard_serialize},
    solidity::{transferCall, ExternalTransfer as ExternalTransferEvent},
};
use alloc::vec::Vec;
use contracts_common::{
    solidity::{
        permitTransferFromCall, CalldataPermitTransferFrom, SignatureTransferDetails,
        TokenPermissions,
    },
    types::{ExternalTransfer, PublicSigningKey, TransferAuxData},
};
use stylus_sdk::{
    abi::Bytes,
    alloy_primitives::Address,
    contract, evm,
    prelude::*,
    storage::{StorageAddress, StorageArray, StorageU256},
};

/// The transfer executor contract's storage layout
#[solidity_storage]
#[entrypoint]
pub struct TransferExecutorContract {
    /// Storage gap to prevent collisions with the Merkle contract
    __gap: StorageArray<StorageU256, MERKLE_STORAGE_GAP_SIZE>,

    /// The address of the Permit2 contract being used
    permit2_address: StorageAddress,
}

#[external]
impl TransferExecutorContract {
    /// Initializes the transfer executor with the address of the Permit2 contract being used
    // TODO: Deploy Permit2 using `CREATE2` and use a static address
    pub fn init(&mut self, permit2_address: Address) -> Result<(), Vec<u8>> {
        self.permit2_address.set(permit2_address);
        Ok(())
    }

    /// Executes an external transfer to/from the contract,
    /// using the auxiliary transfer data for validation as appropriate
    /// depending on the transfer direction.
    pub fn execute_external_transfer(
        &mut self,
        old_pk_root: Bytes,
        transfer: Bytes,
        transfer_aux_data: Bytes,
    ) -> Result<(), Vec<u8>> {
        let transfer: ExternalTransfer = deserialize_from_calldata(&transfer)?;
        let transfer_aux_data: TransferAuxData = deserialize_from_calldata(&transfer_aux_data)?;

        let ExternalTransfer {
            mint,
            account_addr,
            amount,
            is_withdrawal,
        } = transfer;

        if is_withdrawal {
            // In the case of a withdrawal, we check the signature over the external transfer,
            // and then make a simple `transfer` call from the contract to the user.

            let old_pk_root: Option<PublicSigningKey> = deserialize_from_calldata(&old_pk_root)?;

            assert_valid_signature(
                &old_pk_root.ok_or(MISSING_PK_ROOT_ERROR_MESSAGE)?,
                &postcard_serialize(&transfer)?,
                &transfer_aux_data
                    .transfer_signature
                    .ok_or(MISSING_TRANSFER_AUX_DATA_ERROR_MESSAGE)?,
            )?;

            call_helper::<transferCall>(
                self,
                mint, /* address */
                (account_addr /* to */, amount),
            )?;
        } else {
            // In the case of a deposit, we make a `permitTransferFrom` call through
            // the `Permit2` contract using the calldata-serialized `PermitPayload`

            let contract_address = contract::address();
            let permit2_address = self.permit2_address.get();

            let permit = CalldataPermitTransferFrom {
                permitted: TokenPermissions {
                    amount,
                    token: mint,
                },
                nonce: transfer_aux_data
                    .permit_nonce
                    .ok_or(MISSING_TRANSFER_AUX_DATA_ERROR_MESSAGE)?,
                deadline: transfer_aux_data
                    .permit_deadline
                    .ok_or(MISSING_TRANSFER_AUX_DATA_ERROR_MESSAGE)?,
            };

            let signature_transfer_details = SignatureTransferDetails {
                to: contract_address,
                requestedAmount: amount,
            };

            call_helper::<permitTransferFromCall>(
                self,
                permit2_address, /* address */
                (
                    permit,
                    signature_transfer_details,
                    account_addr, /* owner */
                    transfer_aux_data
                        .permit_signature
                        .ok_or(MISSING_TRANSFER_AUX_DATA_ERROR_MESSAGE)?,
                ),
            )?;
        };

        evm::log(ExternalTransferEvent {
            account: account_addr,
            mint,
            is_withdrawal,
            amount,
        });

        Ok(())
    }
}
