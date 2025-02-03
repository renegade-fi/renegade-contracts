//! The gas sponsor contract, used to sponsor the gas costs of external (atomic)
//! matches

use contracts_common::{
    constants::{NUM_BYTES_ADDRESS, NUM_BYTES_SIGNATURE, NUM_BYTES_U256},
    types::ValidMatchSettleAtomicStatement,
};
use contracts_core::crypto::ecdsa::ecdsa_verify;
use stylus_sdk::{
    abi::Bytes,
    alloy_primitives::{hex, Address, U256, U64},
    block,
    call::{call, Call},
    console, contract, evm, msg,
    prelude::*,
    storage::{StorageAddress, StorageBool, StorageMap, StorageU64},
    tx,
};

use crate::{
    assert_result,
    utils::{
        backends::{PrecompileEcRecoverBackend, StylusHasher},
        helpers::{check_address_not_zero, deserialize_from_calldata, is_native_eth_address},
        solidity::{
            GasSponsorPausedFallback, IArbGasInfo, IDarkpool, IErc20, InsufficientSponsorBalance,
            NonceUsed, OwnershipTransferred, Paused, SponsoredExternalMatch, Unpaused,
        },
    },
    ECDSA_ERROR_MESSAGE, INVALID_ARR_LEN_ERROR_MESSAGE, INVALID_SIGNATURE_ERROR_MESSAGE,
    INVALID_VERSION_ERROR_MESSAGE, NOT_OWNER_ERROR_MESSAGE,
};

// ------------------
// | ERROR MESSAGES |
// ------------------

/// The revert message returned when a nonce has already been used
const ERR_NONCE_ALREADY_USED: &[u8] = b"nonce already used";

/// The revert message returned when the sponsor does not have enough ETH to
/// withdraw
const ERR_INSUFFICIENT_BALANCE: &[u8] = b"insufficient balance";

// -------------
// | CONSTANTS |
// -------------

/// The number of bytes in a function selector
const NUM_BYTES_SELECTOR: usize = 4;

/// The base gas cost of any Ethereum transaction, including the maximum
/// gas cost of calling a Stylus contract (https://docs.arbitrum.io/stylus/concepts/gas-metering#stylus-gas-costs)
const INVOCATION_BASE_GAS_COST: u64 = 21_000 + 2048;

/// The cost in gas of a (non-zero) byte of calldata
const GAS_PER_CALLDATA_BYTE: u64 = 16;

/// The cost in gas of the refund operations which take place after the final
/// gas metering check, obtained empirically and rounded to a reasonable value
const REFUND_OPS_GAS_COST: u64 = 10_000;

/// A buffer in gas to account for empirically-observed gas overheads when
/// selling native ETH. This may be due to some overhead in transferring ETH
/// from the (Solidity) proxy to the (Stylus) implementation.
const NATIVE_ETH_SELL_GAS_BUFFER: u64 = 50_000;

/// The address of the ArbGasInfo precompile
const ARB_GAS_INFO_ADDRESS: Address =
    Address::new(hex!("000000000000000000000000000000000000006C"));

// -----------------------
// | CONTRACT DEFINITION |
// -----------------------

/// The gas sponsor contract's storage layout
#[storage]
#[entrypoint]
pub struct GasSponsorContract {
    /// The owner of the gas sponsor contract
    owner: StorageAddress,
    /// The version to which the gas sponsor has been initialized
    initialized: StorageU64,
    /// Whether or not gas sponsorship is paused
    paused: StorageBool,
    /// The address of the darkpool proxy contract
    darkpool_address: StorageAddress,
    /// The public key used to authenticate gas sponsorship,
    /// stored as an address for ergonomics
    auth_address: StorageAddress,
    /// The set of used nonces for sponsored matches
    used_nonces: StorageMap<U256, StorageBool>,
}

// --------------
// | PUBLIC API |
// --------------

#[public]
impl GasSponsorContract {
    // ------------
    // | CONTROLS |
    // ------------

    /// Initializes the gas sponsor contract w/ the given darkpool address and
    /// auth pubkey
    pub fn initialize(
        &mut self,
        darkpool_address: Address,
        auth_address: Address,
    ) -> Result<(), Vec<u8>> {
        self.darkpool_address.set(darkpool_address);
        self.auth_address.set(auth_address);

        self._transfer_ownership(msg::sender());

        self._initialize(1)?;
        Ok(())
    }

    /// Returns the current owner of the gas sponsor
    pub fn owner(&self) -> Result<Address, Vec<u8>> {
        Ok(self.owner.get())
    }

    /// Transfers ownership of the gas sponsor to the provided address
    pub fn transfer_ownership(&mut self, new_owner: Address) -> Result<(), Vec<u8>> {
        self._check_owner()?;

        check_address_not_zero(new_owner)?;
        self._transfer_ownership(new_owner);

        Ok(())
    }

    /// Pauses gas sponsorship
    pub fn pause(&mut self) -> Result<(), Vec<u8>> {
        self._check_owner()?;
        self.paused.set(true);
        evm::log(Paused {});
        Ok(())
    }

    /// Unpauses gas sponsorship
    pub fn unpause(&mut self) -> Result<(), Vec<u8>> {
        self._check_owner()?;
        self.paused.set(false);
        evm::log(Unpaused {});
        Ok(())
    }

    /// Checks whether gas sponsorship is paused
    pub fn is_paused(&self) -> Result<bool, Vec<u8>> {
        Ok(self.paused.get())
    }

    // ----------------
    // | KEY ROTATION |
    // ----------------

    /// Rotates the auth address to the given new address.
    pub fn rotate_auth_address(&mut self, new_auth_address: Address) -> Result<(), Vec<u8>> {
        self._check_owner()?;
        self.auth_address.set(new_auth_address);
        Ok(())
    }

    // -----------
    // | FUNDING |
    // -----------

    /// Receives ETH from the caller.
    #[payable]
    pub fn receive_eth() {}

    /// Withdraws ETH from the gas sponsor contract to the given receiver
    pub fn withdraw_eth(&mut self, receiver: Address, amount: U256) -> Result<(), Vec<u8>> {
        self._check_owner()?;
        let balance = contract::balance();
        assert_result!(balance >= amount, ERR_INSUFFICIENT_BALANCE)?;
        call(Call::new().value(amount), receiver, &[])?;
        Ok(())
    }

    // ------------------------
    // | SPONSORED SETTLEMENT |
    // ------------------------

    /// Sponsor the gas costs of an atomic match settlement with the caller as
    /// the receiver
    #[payable]
    #[allow(clippy::too_many_arguments)]
    pub fn sponsor_atomic_match_settle(
        &mut self,
        internal_party_match_payload: Bytes,
        valid_match_settle_atomic_statement: Bytes,
        match_proofs: Bytes,
        match_linking_proofs: Bytes,
        refund_address: Address,
        nonce: U256,
        signature: Bytes,
    ) -> Result<(), Vec<u8>> {
        let receiver = msg::sender();
        self.sponsor_atomic_match_settle_with_receiver(
            receiver,
            internal_party_match_payload,
            valid_match_settle_atomic_statement,
            match_proofs,
            match_linking_proofs,
            refund_address,
            nonce,
            signature,
        )
    }

    /// Sponsor the gas costs of an atomic match settlement with the given
    /// receiver
    #[payable]
    #[allow(clippy::too_many_arguments)]
    pub fn sponsor_atomic_match_settle_with_receiver(
        &mut self,
        receiver: Address,
        internal_party_match_payload: Bytes,
        valid_match_settle_atomic_statement: Bytes,
        match_proofs: Bytes,
        match_linking_proofs: Bytes,
        refund_address: Address,
        nonce: U256,
        signature: Bytes,
    ) -> Result<(), Vec<u8>> {
        // Take note of the initial tx gas budget
        let initial_gas = evm::gas_left();

        // If gas sponsorship is paused, follow through with naive settlement
        if self.is_paused()? {
            evm::log(GasSponsorPausedFallback { nonce });
            return self.process_atomic_match_settle_with_receiver(
                receiver,
                internal_party_match_payload,
                valid_match_settle_atomic_statement,
                match_proofs,
                match_linking_proofs,
            );
        }

        // Calculate the calldata cost of invoking this method before we consume the
        // args
        let calldata_len = NUM_BYTES_SELECTOR
            + NUM_BYTES_ADDRESS
            + internal_party_match_payload.0.len()
            + valid_match_settle_atomic_statement.0.len()
            + match_proofs.0.len()
            + match_linking_proofs.0.len()
            + NUM_BYTES_ADDRESS
            + NUM_BYTES_U256
            + NUM_BYTES_SIGNATURE;

        let calldata_gas = (calldata_len as u64) * GAS_PER_CALLDATA_BYTE;

        // Verify the signature over the nonce + refund address,
        // then mark the nonce as used
        let mut message = nonce.to_be_bytes::<NUM_BYTES_U256>().to_vec();
        message.extend_from_slice(refund_address.as_slice());
        self.assert_valid_signature(&message, &signature)?;
        self.mark_nonce_used(nonce)?;

        // Invoke the underlying atomic match settlement
        self.process_atomic_match_settle_with_receiver(
            receiver,
            internal_party_match_payload,
            valid_match_settle_atomic_statement,
            match_proofs,
            match_linking_proofs,
        )?;

        // Track the total gas spent, including cost of remaining operations.
        // We frontload as many operations as possible so the final evm::gas_left()
        // call is as accurate as possible.

        let refund_address =
            if refund_address == Address::ZERO { tx::origin() } else { refund_address };

        let transfer_config = Call::new().gas(REFUND_OPS_GAS_COST);

        // Check if this is a native ETH sell, for which it is sufficient to check that
        // the message value is non-zero. If this is not a native ETH sell and the value
        // is non-zero, there will be a revert in the darkpool.
        let is_native_eth_sell = msg::value() > U256::ZERO;

        // Get the L2 gas price. On Arbitrum, this is always the basefee:
        // https://docs.arbitrum.io/how-arbitrum-works/gas-fees#l2-tips
        let gas_price = block::basefee();

        // Get the L1 gas cost - this is the cost in wei
        let l1_gas_cost =
            IArbGasInfo::new(ARB_GAS_INFO_ADDRESS).get_current_tx_l_1_gas_fees(Call::new())?;

        let final_gas = evm::gas_left();

        let gas_spent = U256::from(
            INVOCATION_BASE_GAS_COST
                + calldata_gas
                + (initial_gas - final_gas)
                + REFUND_OPS_GAS_COST
                + if is_native_eth_sell { NATIVE_ETH_SELL_GAS_BUFFER } else { 0 },
        );

        let gas_cost = gas_price * gas_spent + l1_gas_cost;

        // If the gas sponsor doesn't have enough Ether to refund the user,
        // emit an event but don't revert.
        if contract::balance() < gas_cost {
            evm::log(InsufficientSponsorBalance { nonce });
            return Ok(());
        }

        // Refund the user's gas costs
        call(
            transfer_config.value(gas_cost),
            refund_address,
            &[], // calldata
        )?;

        evm::log(SponsoredExternalMatch { amount: gas_cost, nonce });

        Ok(())
    }

    // --------------------------
    // | UNSPONSORED SETTLEMENT |
    // --------------------------

    /// Processes the atomic match settlement through the darkpool contract
    #[payable]
    fn process_atomic_match_settle(
        &mut self,
        internal_party_match_payload: Bytes,
        valid_match_settle_atomic_statement: Bytes,
        match_proofs: Bytes,
        match_linking_proofs: Bytes,
    ) -> Result<(), Vec<u8>> {
        let receiver = msg::sender();
        self.process_atomic_match_settle_with_receiver(
            receiver,
            internal_party_match_payload,
            valid_match_settle_atomic_statement,
            match_proofs,
            match_linking_proofs,
        )
    }

    /// Calls the darkpool contract's
    /// `process_atomic_match_settle_with_receiver` method, transferring the
    /// input tokens from the caller to the gas sponsor
    #[payable]
    pub fn process_atomic_match_settle_with_receiver(
        &mut self,
        receiver: Address,
        internal_party_match_payload: Bytes,
        valid_match_settle_atomic_statement: Bytes,
        match_proofs: Bytes,
        match_linking_proofs: Bytes,
    ) -> Result<(), Vec<u8>> {
        let sender = msg::sender();
        let sponsor = contract::address();
        let darkpool_address = self.darkpool_address.get();

        // Transfer the input tokens from the caller to the gas sponsor
        let statement: ValidMatchSettleAtomicStatement =
            deserialize_from_calldata(&valid_match_settle_atomic_statement)?;

        let match_result = &statement.match_result;
        let (send_mint, send_amount) = match_result.external_party_sell_mint_amount();

        // Only execute an ERC20 transfer if the input token is not the native asset
        if !is_native_eth_address(send_mint) {
            let send_token = IErc20::new(send_mint);
            send_token.approve(Call::new(), darkpool_address, send_amount)?;
            send_token.transfer_from(Call::new(), sender, sponsor, send_amount)?;
        }

        // Call the darkpool contract's `process_atomic_match_settle_with_receiver`
        // method. We pass along the message value in case the input token is
        // the native asset
        let darkpool = IDarkpool::new(darkpool_address);
        darkpool.process_atomic_match_settle_with_receiver(
            Call::new().value(msg::value()),
            receiver,
            internal_party_match_payload.0.into(),
            valid_match_settle_atomic_statement.0.into(),
            match_proofs.0.into(),
            match_linking_proofs.0.into(),
        )?;

        Ok(())
    }
}

// -------------------
// | PRIVATE HELPERS |
// -------------------

impl GasSponsorContract {
    /// Initializes this contract with the given version.
    pub fn _initialize(&mut self, version: u64) -> Result<(), Vec<u8>> {
        let version_uint64 = U64::from_limbs([version]);
        assert_result!(self.initialized.get() < version_uint64, INVALID_VERSION_ERROR_MESSAGE)?;
        self.initialized.set(version_uint64);
        Ok(())
    }

    /// Checks that the sender is the owner
    pub fn _check_owner(&self) -> Result<(), Vec<u8>> {
        assert_result!(self.owner.get() == msg::sender(), NOT_OWNER_ERROR_MESSAGE)
    }

    /// Updates the stored owner address to `new_owner`
    pub fn _transfer_ownership(&mut self, new_owner: Address) {
        self.owner.set(new_owner);
        evm::log(OwnershipTransferred { new_owner })
    }

    /// Asserts the validity of the given signature using the auth address
    fn assert_valid_signature(&self, message: &[u8], signature: &[u8]) -> Result<(), Vec<u8>> {
        let auth_address = self.auth_address.get();
        let auth_address_bytes = auth_address.0 .0;
        assert_result!(
            ecdsa_verify::<StylusHasher, PrecompileEcRecoverBackend>(
                auth_address_bytes,
                message,
                signature.try_into().map_err(|_| INVALID_ARR_LEN_ERROR_MESSAGE)?,
            )
            .map_err(|_| ECDSA_ERROR_MESSAGE)?,
            INVALID_SIGNATURE_ERROR_MESSAGE
        )
    }

    /// Marks the given nonce as used
    fn mark_nonce_used(&mut self, nonce: U256) -> Result<(), Vec<u8>> {
        assert_result!(!self.used_nonces.get(nonce), ERR_NONCE_ALREADY_USED)?;
        self.used_nonces.insert(nonce, true);
        evm::log(NonceUsed { nonce });

        Ok(())
    }
}
