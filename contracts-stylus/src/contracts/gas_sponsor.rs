//! The gas sponsor contract, used to sponsor the gas costs of external (atomic)
//! matches

use contracts_common::{
    constants::NUM_BYTES_U256,
    types::{ExternalMatchResult, ValidMatchSettleAtomicStatement},
};
use contracts_core::crypto::ecdsa::ecdsa_verify;
use stylus_sdk::{
    abi::Bytes,
    alloy_primitives::{Address, U256, U64},
    prelude::{calls::context::Call, *},
    storage::{StorageAddress, StorageBool, StorageMap, StorageU64},
};

#[allow(deprecated)]
use stylus_sdk::call::Call as InterfaceCall;

use crate::{
    assert_result,
    utils::{
        backends::{PrecompileEcRecoverBackend, StylusHasher},
        helpers::{check_address_not_zero, deserialize_from_calldata, is_native_eth_address},
        solidity::{
            GasSponsorPausedFallback, IDarkpool, IErc20, InsufficientSponsorBalance, NonceUsed,
            OwnershipTransferred, Paused, SponsoredExternalMatch, Unpaused,
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

        self._transfer_ownership(self.vm().msg_sender());

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
        log(self.vm(), Paused {});
        Ok(())
    }

    /// Unpauses gas sponsorship
    pub fn unpause(&mut self) -> Result<(), Vec<u8>> {
        self._check_owner()?;
        self.paused.set(false);
        log(self.vm(), Unpaused {});
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
        let contract_address = self.vm().contract_address();
        let balance = self.vm().balance(contract_address);
        assert_result!(balance >= amount, ERR_INSUFFICIENT_BALANCE)?;
        let ctx = Call::new().value(amount);
        self.vm().call(&ctx, receiver, &[])?;
        Ok(())
    }

    /// Withdraws ERC20 tokens from the gas sponsor contract to the given
    /// receiver
    pub fn withdraw_tokens(
        &mut self,
        receiver: Address,
        token: Address,
        amount: U256,
    ) -> Result<(), Vec<u8>> {
        self._check_owner()?;
        let token_contract = IErc20::new(token);
        let contract_address = self.vm().contract_address();
        let balance = token_contract.balance_of(&(*self), contract_address)?;
        assert_result!(balance >= amount, ERR_INSUFFICIENT_BALANCE)?;
        token_contract.transfer(self, receiver, amount)?;
        Ok(())
    }

    // ------------------------
    // | SPONSORED SETTLEMENT |
    // ------------------------

    /// Sponsor the gas costs of an atomic match settlement, with the given
    /// options (receiver, refund address, native ETH vs buy-side token
    /// refund, refund amount).
    /// If the `receiver` is the zero address, we use `msg::sender()` as the
    /// receiver.
    #[payable]
    #[allow(clippy::too_many_arguments)]
    pub fn sponsor_atomic_match_settle_with_refund_options(
        &mut self,
        receiver: Address,
        internal_party_match_payload: Bytes,
        valid_match_settle_atomic_statement: Bytes,
        match_proofs: Bytes,
        match_linking_proofs: Bytes,
        refund_address: Address,
        nonce: U256,
        refund_native_eth: bool,
        refund_amount: U256,
        signature: Bytes,
    ) -> Result<(), Vec<u8>> {
        // Resolve the receiver to use
        let receiver = if receiver == Address::ZERO { self.vm().msg_sender() } else { receiver };

        let match_result = self.sponsored_match_inner(
            receiver,
            internal_party_match_payload,
            valid_match_settle_atomic_statement,
            match_proofs,
            match_linking_proofs,
            refund_address,
            nonce,
            refund_amount,
            signature,
        )?;

        // If gas sponsorship is paused, return early, no refunding will be done
        if self.is_paused()? {
            log(self.vm(), GasSponsorPausedFallback { nonce });
            return Ok(());
        }

        // Refund the gas costs
        let (buy_token_addr, _) = match_result.external_party_buy_mint_amount();
        self.refund_gas_cost(
            refund_native_eth,
            refund_address,
            buy_token_addr,
            refund_amount,
            receiver,
            nonce,
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
        assert_result!(self.owner.get() == self.vm().msg_sender(), NOT_OWNER_ERROR_MESSAGE)
    }

    /// Updates the stored owner address to `new_owner`
    pub fn _transfer_ownership(&mut self, new_owner: Address) {
        self.owner.set(new_owner);
        log(self.vm(), OwnershipTransferred { new_owner })
    }

    /// Verify the signature over the nonce, refund address, and potentially
    /// refund amount
    fn assert_sponsorship_signature(
        &self,
        nonce: &U256,
        refund_address: &Address,
        refund_amount: &U256,
        signature: &[u8],
    ) -> Result<(), Vec<u8>> {
        let mut message = nonce.to_be_bytes::<NUM_BYTES_U256>().to_vec();
        message.extend_from_slice(refund_address.as_slice());
        if !refund_amount.is_zero() {
            message.extend_from_slice(refund_amount.to_be_bytes::<NUM_BYTES_U256>().as_slice());
        }
        self.assert_valid_signature(&message, signature)
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
        log(self.vm(), NonceUsed { nonce });

        Ok(())
    }

    /// Invokes a sponsored atomic match settlement, returning the match result.
    /// This includes invoking the underlying atomic match settlement on the
    /// darkpool, and checking the sponsorship signature & nonce.
    #[allow(clippy::too_many_arguments)]
    pub fn sponsored_match_inner(
        &mut self,
        receiver: Address,
        internal_party_match_payload: Bytes,
        valid_match_settle_atomic_statement: Bytes,
        match_proofs: Bytes,
        match_linking_proofs: Bytes,
        refund_address: Address,
        nonce: U256,
        refund_amount: U256,
        signature: Bytes,
    ) -> Result<ExternalMatchResult, Vec<u8>> {
        // Invoke the underlying atomic match settlement
        let match_result = self.atomic_match_inner(
            receiver,
            internal_party_match_payload.clone(),
            valid_match_settle_atomic_statement.clone(),
            match_proofs.clone(),
            match_linking_proofs.clone(),
        )?;

        // Verify the sponsorship signature
        self.assert_sponsorship_signature(&nonce, &refund_address, &refund_amount, &signature)?;

        // Mark the nonce as used
        self.mark_nonce_used(nonce)?;

        Ok(match_result)
    }

    /// Invokes the actual atomic match path on the darkpool contract,
    /// returning the match result.
    /// If the `receiver` is the zero address, we use `msg::sender()` as the
    /// receiver.
    pub fn atomic_match_inner(
        &mut self,
        receiver: Address,
        internal_party_match_payload: Bytes,
        valid_match_settle_atomic_statement: Bytes,
        match_proofs: Bytes,
        match_linking_proofs: Bytes,
    ) -> Result<ExternalMatchResult, Vec<u8>> {
        let sender = self.vm().msg_sender();
        let sponsor = self.vm().contract_address();
        let darkpool_address = self.darkpool_address.get();

        // Transfer the input tokens from the caller to the gas sponsor
        let statement: ValidMatchSettleAtomicStatement =
            deserialize_from_calldata(&valid_match_settle_atomic_statement)?;

        let match_result = statement.match_result;
        let (send_mint, send_amount) = match_result.external_party_sell_mint_amount();

        // Only execute an ERC20 transfer if the input token is not the native asset
        if !is_native_eth_address(send_mint) {
            let send_token = IErc20::new(send_mint);
            send_token.approve(&mut (*self), darkpool_address, send_amount)?;
            send_token.transfer_from(&mut (*self), sender, sponsor, send_amount)?;
        }

        #[allow(deprecated)]
        let ctx = InterfaceCall::new().value(self.vm().msg_value());

        // Call the darkpool contract's `process_atomic_match_settle_with_receiver`
        // method. We pass along the message value in case the input token is
        // the native asset
        let darkpool = IDarkpool::new(darkpool_address);
        darkpool.process_atomic_match_settle_with_receiver(
            ctx,
            receiver,
            internal_party_match_payload.0.into(),
            valid_match_settle_atomic_statement.0.into(),
            match_proofs.0.into(),
            match_linking_proofs.0.into(),
        )?;

        Ok(match_result)
    }

    /// Resolves the refund address to use for the given arguments.
    fn resolve_refund_address(
        &self,
        refund_native_eth: bool,
        refund_address: Address,
        receiver: Address,
    ) -> Address {
        // If the refund address is explicitly set, use it
        if refund_address != Address::ZERO {
            return refund_address;
        }

        // If we are deliberately refunding through native ETH,
        // we default to using the tx origin (original gas spender)
        // as the refund address
        if refund_native_eth {
            return self.vm().tx_origin();
        }

        // If we are refunding through the buy-side token,
        // we default to the receiver of the buy-side tokens
        // as the refund address
        receiver
    }

    /// Refunds the user's gas costs through native ETH.
    fn refund_through_native_eth(
        &mut self,
        refund_address: Address,
        refund_amount: U256,
        nonce: U256,
    ) -> Result<(), Vec<u8>> {
        // If the gas sponsor doesn't have enough Ether to refund the user,
        // emit an event but don't revert.
        let contract_address = self.vm().contract_address();
        let balance = self.vm().balance(contract_address);
        if balance < refund_amount {
            log(self.vm(), InsufficientSponsorBalance { nonce });
            return Ok(());
        }

        let ctx = Call::new().value(refund_amount);
        self.vm().call(
            &ctx,
            refund_address,
            &[], // calldata
        )?;

        log(
            self.vm(),
            SponsoredExternalMatch { amount: refund_amount, token: Address::ZERO, nonce },
        );

        Ok(())
    }

    /// Refunds the user's gas costs through the buy-side token.
    fn refund_through_buy_token(
        &mut self,
        refund_address: Address,
        buy_token_addr: Address,
        refund_amount: U256,
        nonce: U256,
    ) -> Result<(), Vec<u8>> {
        let buy_token = IErc20::new(buy_token_addr);

        // If the gas sponsor doesn't have enough of the buy-side token to refund the
        // user, emit an event but don't revert.
        let contract_address = self.vm().contract_address();
        if buy_token.balance_of(&mut (*self), contract_address)? < refund_amount {
            log(self.vm(), InsufficientSponsorBalance { nonce });
            return Ok(());
        }

        // Refund the user's gas costs
        buy_token.transfer(&mut (*self), refund_address, refund_amount)?;

        log(
            self.vm(),
            SponsoredExternalMatch { amount: refund_amount, token: buy_token_addr, nonce },
        );

        Ok(())
    }

    /// Refunds the user's gas costs, either through native ETH or the buy-side
    /// token.
    fn refund_gas_cost(
        &mut self,
        refund_native_eth: bool,
        refund_address: Address,
        buy_token_addr: Address,
        refund_amount: U256,
        receiver: Address,
        nonce: U256,
    ) -> Result<(), Vec<u8>> {
        let refund_address =
            self.resolve_refund_address(refund_native_eth, refund_address, receiver);

        let is_native_eth_buy = is_native_eth_address(buy_token_addr);

        // If we are deliberately refunding through native ETH, or if the buy-side
        // token is native ETH, we can just transfer the ETH directly.
        if refund_native_eth || is_native_eth_buy {
            self.refund_through_native_eth(refund_address, refund_amount, nonce)
        } else {
            self.refund_through_buy_token(refund_address, buy_token_addr, refund_amount, nonce)
        }
    }
}
