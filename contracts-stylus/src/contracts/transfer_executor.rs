//! The transfer executor contract, responsible for executing external transfers
//! to/from the darkpool (it is intended to be delegate-called by the darkpool)
use crate::{
    if_verifying,
    utils::{
        constants::{
            INVALID_ARR_LEN_ERROR_MESSAGE, MERKLE_STORAGE_GAP_SIZE,
            MISSING_TRANSFER_AUX_DATA_ERROR_MESSAGE,
        },
        helpers::{
            assert_valid_signature, call_helper, deserialize_from_calldata, get_weth_address,
            is_native_eth_address, postcard_serialize,
        },
        solidity::{
            depositCall, transferCall, transferFromCall, withdrawToCall,
            ExternalTransfer as ExternalTransferEvent,
        },
    },
};
use alloc::{string::ToString, vec::Vec};
use alloy_sol_types::SolStruct;
use contracts_common::{
    constants::DEPOSIT_WITNESS_TYPE_STRING,
    custom_serde::pk_to_u256s,
    solidity::{
        permitWitnessTransferFromCall, CalldataPermitWitnessTransferFrom, DepositWitness,
        SignatureTransferDetails, TokenPermissions,
    },
    types::{ExternalTransfer, PublicSigningKey, SimpleErc20Transfer, TransferAuxData},
};
#[allow(deprecated)]
use stylus_sdk::{
    abi::Bytes,
    alloy_primitives::{Address, U256},
    call::Call as CallWithValue,
    prelude::*,
    storage::{StorageAddress, StorageArray, StorageU256},
};

/// The error message emitted when a simple ERC20 deposit fails
const SIMPLE_ERC20_DEPOSIT_ERROR_MESSAGE: &[u8] = b"Simple ERC20 deposit failed";
/// The error message emitted when a simple ERC20 withdrawal fails
const SIMPLE_ERC20_WITHDRAWAL_ERROR_MESSAGE: &[u8] = b"Simple ERC20 withdrawal failed";
/// The error message emitted when the transaction payable amount is invalid
const INVALID_TRANSACTION_PAYABLE_AMOUNT_ERROR_MESSAGE: &[u8] =
    b"Invalid transaction payable amount";

/// The transfer executor contract's storage layout
#[storage]
#[entrypoint]
pub struct TransferExecutorContract {
    /// Storage gap to prevent collisions with the Merkle contract
    __gap: StorageArray<StorageU256, MERKLE_STORAGE_GAP_SIZE>,

    /// The address of the Permit2 contract being used
    permit2_address: StorageAddress,
}

#[public]
impl TransferExecutorContract {
    /// Initializes the transfer executor with the address of the Permit2
    /// contract being used
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
        old_pk_root_bytes: Bytes,
        transfer: Bytes,
        transfer_aux_data: Bytes,
    ) -> Result<(), Vec<u8>> {
        let transfer: ExternalTransfer = deserialize_from_calldata(&transfer)?;
        let transfer_aux_data: TransferAuxData = deserialize_from_calldata(&transfer_aux_data)?;

        let ExternalTransfer { mint, account_addr, amount, is_withdrawal } = transfer;

        let old_pk_root: PublicSigningKey = deserialize_from_calldata(&old_pk_root_bytes)?;

        if is_withdrawal {
            // In the case of a withdrawal, we check the signature over the external
            // transfer, and then make a simple `transfer` call from the
            // contract to the user.

            if_verifying!(assert_valid_signature(
                &old_pk_root,
                &postcard_serialize(&transfer)?,
                &transfer_aux_data
                    .transfer_signature
                    .ok_or(MISSING_TRANSFER_AUX_DATA_ERROR_MESSAGE)?,
            )?);

            call_helper::<transferCall>(
                &mut *self,
                mint, // address
                (account_addr /* to */, amount),
            )?;
        } else {
            // In the case of a deposit, we make a `permitTransferFrom` call through
            // the `Permit2` contract using the calldata-serialized `PermitPayload`

            let contract_address = self.vm().contract_address();
            let permit2_address = self.permit2_address.get();

            let permit = CalldataPermitWitnessTransferFrom {
                permitted: TokenPermissions { amount, token: mint },
                nonce: transfer_aux_data
                    .permit_nonce
                    .ok_or(MISSING_TRANSFER_AUX_DATA_ERROR_MESSAGE)?,
                deadline: transfer_aux_data
                    .permit_deadline
                    .ok_or(MISSING_TRANSFER_AUX_DATA_ERROR_MESSAGE)?,
            };

            let signature_transfer_details =
                SignatureTransferDetails { to: contract_address, requestedAmount: amount };

            // Hash the Permit2 witness data for the deposit
            let deposit_witness = DepositWitness {
                pkRoot: pk_to_u256s(&old_pk_root)
                    .map_err(|_| INVALID_ARR_LEN_ERROR_MESSAGE.to_vec())?,
            };
            let deposit_witness_hash = deposit_witness.eip712_hash_struct().0;

            call_helper::<permitWitnessTransferFromCall>(
                &mut *self,
                permit2_address, // address
                (
                    permit,
                    signature_transfer_details,
                    account_addr, // owner
                    deposit_witness_hash.into(),
                    DEPOSIT_WITNESS_TYPE_STRING.to_string(),
                    transfer_aux_data
                        .permit_signature
                        .ok_or(MISSING_TRANSFER_AUX_DATA_ERROR_MESSAGE)?
                        .into(),
                ),
            )?;
        };

        let transfer_log =
            ExternalTransferEvent { account: account_addr, mint, is_withdrawal, amount };
        log(self.vm(), transfer_log);

        Ok(())
    }

    /// Execute a batch of simple erc20 transfers
    #[payable]
    pub fn execute_transfer_batch(&mut self, transfers: Bytes) -> Result<(), Vec<u8>> {
        let transfers: Vec<SimpleErc20Transfer> = deserialize_from_calldata(&transfers)?;
        for transfer in transfers {
            self.execute_simple_erc20_transfer(transfer)?;
        }

        Ok(())
    }
}

impl TransferExecutorContract {
    /// Execute a single simple erc20 transfer
    fn execute_simple_erc20_transfer(
        &mut self,
        transfer: SimpleErc20Transfer,
    ) -> Result<(), Vec<u8>> {
        // Do nothing if the transfer is zero
        if transfer.amount == U256::ZERO {
            return Ok(());
        }

        if transfer.is_withdrawal {
            self.execute_simple_erc20_withdrawal(transfer)
        } else {
            self.execute_simple_erc20_deposit(transfer)
        }
    }

    /// Execute a simple erc20 deposit
    fn execute_simple_erc20_deposit(
        &mut self,
        transfer: SimpleErc20Transfer,
    ) -> Result<(), Vec<u8>> {
        // If the deposit is for native ETH, wrap it
        let erc20_address = transfer.mint;
        if is_native_eth_address(erc20_address) {
            return self.handle_native_eth_deposit(transfer);
        }

        // Otherwise, deposit the ERC20
        let contract_address = self.vm().contract_address();
        let res = call_helper::<transferFromCall>(
            self,
            erc20_address,
            (transfer.account_addr, contract_address, transfer.amount),
        )?;

        if !res._0 {
            return Err(SIMPLE_ERC20_DEPOSIT_ERROR_MESSAGE.to_vec());
        }
        Ok(())
    }

    /// Execute a simple erc20 withdrawal
    fn execute_simple_erc20_withdrawal(
        &mut self,
        transfer: SimpleErc20Transfer,
    ) -> Result<(), Vec<u8>> {
        // If the withdrawal is for native ETH, unwrap it
        let erc20_address = transfer.mint;
        if is_native_eth_address(erc20_address) {
            return self.handle_native_eth_withdrawal(transfer);
        }

        let res = call_helper::<transferCall>(
            self,
            erc20_address,
            (transfer.account_addr, transfer.amount),
        )?;

        if !res._0 {
            return Err(SIMPLE_ERC20_WITHDRAWAL_ERROR_MESSAGE.to_vec());
        }
        Ok(())
    }

    /// Deposit native ETH into the contract by wrapping the transaction payable
    /// amount
    fn handle_native_eth_deposit(&mut self, transfer: SimpleErc20Transfer) -> Result<(), Vec<u8>> {
        let payable = self.vm().msg_value();
        if transfer.amount != payable {
            return Err(INVALID_TRANSACTION_PAYABLE_AMOUNT_ERROR_MESSAGE.to_vec());
        }

        // Wrap the native asset
        let weth_address = get_weth_address();
        #[allow(deprecated)]
        let call_ctx = CallWithValue::new_in(self).value(payable);
        call_helper::<depositCall>(call_ctx, weth_address, ())?;
        Ok(())
    }

    /// Withdraw native ETH from the contract to the caller by unwrapping the
    /// transfer amount
    fn handle_native_eth_withdrawal(
        &mut self,
        transfer: SimpleErc20Transfer,
    ) -> Result<(), Vec<u8>> {
        let weth_address = get_weth_address();
        call_helper::<withdrawToCall>(
            self,
            weth_address,
            (transfer.account_addr, transfer.amount),
        )?;
        Ok(())
    }
}
