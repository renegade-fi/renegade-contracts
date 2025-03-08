//! The gas sponsor contract, used to sponsor the gas costs of external (atomic)
//! matches

use alloy_sol_types::SolCall;
use contracts_common::{
    constants::NUM_BYTES_U256,
    types::{ExternalMatchResult, ValidMatchSettleAtomicStatement},
};
use contracts_core::crypto::ecdsa::ecdsa_verify;
use stylus_sdk::{
    abi::Bytes,
    alloy_primitives::{hex, Address, U256, U64},
    block,
    call::{call, Call},
    console, contract, evm, msg,
    prelude::*,
    storage::{GlobalStorage, StorageAddress, StorageBool, StorageCache, StorageMap, StorageU64},
    tx,
};

use crate::{
    assert_result,
    utils::{
        backends::{PrecompileEcRecoverBackend, StylusHasher},
        helpers::{check_address_not_zero, deserialize_from_calldata, is_native_eth_address},
        solidity::{
            sponsorAtomicMatchSettleWithRefundOptionsCall, GasSponsorPausedFallback, IArbGasInfo,
            IArbWasm, IDarkpool, IErc20, InsufficientSponsorBalance, NonceUsed,
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

// -------------
// | CONSTANTS |
// -------------

/// The cost of invoking a sponsored match settlement, which includes:
/// 1. The base gas cost of any Ethereum transaction
/// 2. The overhead of the delegatecall from the proxy, assuming the contract
///    address is cold and using an empirical estimate of calldata size, rounded
///    to a reasonable value
const INVOCATION_BASE_GAS_COST: u64 = 21_000 + 3500;

/// The cost in gas of a (non-zero) byte of calldata
const GAS_PER_CALLDATA_BYTE: u64 = 16;

/// The cost in gas of the buy-side token refund operations which take place
/// after the final gas metering check, obtained empirically and rounded to a
/// reasonable value
const TOKEN_REFUND_OPS_GAS_COST: u64 = 55_000;

/// The cost in gas of the native ETH refund operations which take place after
/// the final gas metering check, obtained empirically and rounded to a
/// reasonable value
const NATIVE_REFUND_OPS_GAS_COST: u64 = 12_500;

/// A buffer in gas to account for empirically-observed gas overheads when
/// selling native ETH. It is not entirely clear what the cause of this overhead
/// is.
const NATIVE_ETH_SELL_GAS_BUFFER: u64 = 20_000;

/// The address of the ArbGasInfo precompile
const ARB_GAS_INFO_ADDRESS: Address =
    Address::new(hex!("000000000000000000000000000000000000006C"));

/// The address of the ArbWasm precompile
const ARB_WASM_ADDRESS: Address = Address::new(hex!("0000000000000000000000000000000000000071"));

/// The storage slot at which the implementation address of the gas sponsor
/// contract is stored, as specified by EIP-1967:
///
/// https://eips.ethereum.org/EIPS/eip-1967#logic-contract-address
const IMPL_ADDRESS_STORAGE_SLOT: U256 =
    U256::from_be_bytes(hex!("360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"));

/// The number of wei per ETH, i.e. 10^18
const WEI_PER_ETH: U256 = U256::from_limbs([1_000_000_000_000_000_000u64, 0, 0, 0]);

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
        let balance = token_contract.balance_of(Call::new(), contract::address())?;
        assert_result!(balance >= amount, ERR_INSUFFICIENT_BALANCE)?;
        token_contract.transfer(Call::new(), receiver, amount)?;
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
        self.sponsor_atomic_match_settle_with_refund_options(
            Address::ZERO,
            internal_party_match_payload,
            valid_match_settle_atomic_statement,
            match_proofs,
            match_linking_proofs,
            refund_address,
            nonce,
            true,       // refund_native_eth
            U256::ZERO, // conversion_rate
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
        self.sponsor_atomic_match_settle_with_refund_options(
            receiver,
            internal_party_match_payload,
            valid_match_settle_atomic_statement,
            match_proofs,
            match_linking_proofs,
            refund_address,
            nonce,
            true,       // refund_native_eth
            U256::ZERO, // conversion_rate
            signature,
        )
    }

    /// Sponsor the gas costs of an atomic match settlement, with the given
    /// options (receiver, refund address, native ETH vs buy-side token
    /// refund).
    /// The `gas_cost` is the estimated gas cost of the transaction
    /// in units of wei, and the `conversion_rate` is the signed price of
    /// the buy-side token in units of token/wei.
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
        conversion_rate: U256,
        signature: Bytes,
    ) -> Result<(), Vec<u8>> {
        // Take note of the initial tx gas budget
        let initial_gas = evm::gas_left();

        // Resolve the receiver to use
        let receiver = if receiver == Address::ZERO { msg::sender() } else { receiver };

        // Invoke the underlying atomic match settlement
        let match_result = self.atomic_match_inner(
            receiver,
            internal_party_match_payload.clone(),
            valid_match_settle_atomic_statement.clone(),
            match_proofs.clone(),
            match_linking_proofs.clone(),
        )?;

        // If gas sponsorship is paused, return early, no refunding will be done
        if self.is_paused()? {
            evm::log(GasSponsorPausedFallback { nonce });
            return Ok(());
        }

        // Verify the sponsorship signature
        self.assert_sponsorship_signature(&nonce, &refund_address, &conversion_rate, &signature)?;

        // Mark the nonce as used
        self.mark_nonce_used(nonce)?;

        let (buy_token_addr, _) = match_result.external_party_buy_mint_amount();

        // Estimate the gas cost of the transaction
        let gas_cost = estimate_final_gas_cost(
            initial_gas,
            buy_token_addr,
            receiver,
            internal_party_match_payload,
            valid_match_settle_atomic_statement,
            match_proofs,
            match_linking_proofs,
            refund_address,
            nonce,
            refund_native_eth,
            conversion_rate,
            signature,
        )?;

        // Refund the gas costs
        refund_gas_cost(
            refund_native_eth,
            refund_address,
            buy_token_addr,
            gas_cost,
            conversion_rate,
            receiver,
            nonce,
        )?;

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
        self.atomic_match_inner(
            receiver,
            internal_party_match_payload,
            valid_match_settle_atomic_statement,
            match_proofs,
            match_linking_proofs,
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

    /// Verify the signature over the nonce, refund address, and potentially
    /// conversion rate
    fn assert_sponsorship_signature(
        &self,
        nonce: &U256,
        refund_address: &Address,
        conversion_rate: &U256,
        signature: &[u8],
    ) -> Result<(), Vec<u8>> {
        let mut message = nonce.to_be_bytes::<NUM_BYTES_U256>().to_vec();
        message.extend_from_slice(refund_address.as_slice());
        if !conversion_rate.is_zero() {
            message.extend_from_slice(conversion_rate.to_be_bytes::<NUM_BYTES_U256>().as_slice());
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
        evm::log(NonceUsed { nonce });

        Ok(())
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
        let sender = msg::sender();
        let sponsor = contract::address();
        let darkpool_address = self.darkpool_address.get();

        // Transfer the input tokens from the caller to the gas sponsor
        let statement: ValidMatchSettleAtomicStatement =
            deserialize_from_calldata(&valid_match_settle_atomic_statement)?;

        let match_result = statement.match_result;
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

        Ok(match_result)
    }
}

// ----------------------
// | NON-MEMBER HELPERS |
// ----------------------

/// Estimates the units of gas used to invoke the
/// `sponsor_atomic_match_settle_with_receiver` method
#[allow(clippy::too_many_arguments)]
fn estimate_invocation_gas(
    receiver: Address,
    internal_party_match_payload: Bytes,
    valid_match_settle_atomic_statement: Bytes,
    match_proofs: Bytes,
    match_linking_proofs: Bytes,
    refund_address: Address,
    nonce: U256,
    refund_native_eth: bool,
    conversion_rate: U256,
    signature: Bytes,
) -> Result<u64, Vec<u8>> {
    // Compute the cost of calldata, assuming no zero bytes
    let calldata = sponsorAtomicMatchSettleWithRefundOptionsCall {
        receiver,
        internal_party_match_payload: internal_party_match_payload.0.into(),
        valid_match_settle_atomic_statement: valid_match_settle_atomic_statement.0.into(),
        match_proofs: match_proofs.0.into(),
        match_linking_proofs: match_linking_proofs.0.into(),
        refund_address,
        nonce,
        refund_native_eth,
        conversion_rate,
        signature: signature.0.into(),
    };
    let calldata_len = calldata.abi_encoded_size();
    let calldata_gas = (calldata_len as u64) * GAS_PER_CALLDATA_BYTE;

    // Compute the initialization gas cost, pessimistically assuming
    // that the gas sponsor contract is uncached.

    // TODO: Check the `ArbWasmCache` precompile to see if the gas sponsor
    // contract is cached once we update the Stylus SDK

    // We need to use the address of the gas sponsor implementation contract, not
    // the proxy from which we assume this method is being delegate-called.
    // To do so, we read the implementation address from the designated
    // EIP-1967 storage slot.
    let gas_sponsor_impl_address_slot = StorageCache::get_word(IMPL_ADDRESS_STORAGE_SLOT);
    let gas_sponsor_impl_address = Address::from_word(gas_sponsor_impl_address_slot);

    let (init_gas, _) =
        IArbWasm::new(ARB_WASM_ADDRESS).program_init_gas(Call::new(), gas_sponsor_impl_address)?;

    // Check if this is a native ETH sell, as this requires accounting for some
    // opaque overhead. It is sufficient to check that the message value is
    // non-zero. If this is not a native ETH sell and the value is non-zero,
    // there will be a revert in the darkpool.
    let is_native_eth_sell = msg::value() > U256::ZERO;
    let native_eth_sell_gas = if is_native_eth_sell { NATIVE_ETH_SELL_GAS_BUFFER } else { 0 };

    Ok(INVOCATION_BASE_GAS_COST + init_gas + calldata_gas + native_eth_sell_gas)
}

/// Estimates the gas cost of the refund operations, which differ based on
/// whether native ETH or the buy-side token is used to refund the user.
fn estimate_refund_ops_gas(buy_token_addr: Address, refund_native_eth: bool) -> u64 {
    let is_native_eth_buy = is_native_eth_address(buy_token_addr);

    if is_native_eth_buy || refund_native_eth {
        NATIVE_REFUND_OPS_GAS_COST
    } else {
        TOKEN_REFUND_OPS_GAS_COST
    }
}

/// Estimate the total gas spent, including cost of remaining operations.
/// We frontload as many operations as possible so the final evm::gas_left()
/// call is as accurate as possible.
#[allow(clippy::too_many_arguments)]
fn estimate_final_gas_cost(
    initial_gas: u64,
    buy_token_addr: Address,
    receiver: Address,
    internal_party_match_payload: Bytes,
    valid_match_settle_atomic_statement: Bytes,
    match_proofs: Bytes,
    match_linking_proofs: Bytes,
    refund_address: Address,
    nonce: U256,
    refund_native_eth: bool,
    conversion_rate: U256,
    signature: Bytes,
) -> Result<U256, Vec<u8>> {
    let refund_ops_gas = estimate_refund_ops_gas(buy_token_addr, refund_native_eth);
    let invocation_gas = estimate_invocation_gas(
        receiver,
        internal_party_match_payload,
        valid_match_settle_atomic_statement,
        match_proofs,
        match_linking_proofs,
        refund_address,
        nonce,
        refund_native_eth,
        conversion_rate,
        signature,
    )?;

    // Get the L2 gas price. On Arbitrum, this is always the basefee:
    // https://docs.arbitrum.io/how-arbitrum-works/gas-fees#l2-tips
    let gas_price = block::basefee();

    // Get the L1 gas cost - this is the cost in wei
    let l1_gas_cost =
        IArbGasInfo::new(ARB_GAS_INFO_ADDRESS).get_current_tx_l_1_gas_fees(Call::new())?;

    // Precompute as much of the gas tallying arithmetic as possible
    let gas_tally = initial_gas + invocation_gas + refund_ops_gas;

    // Finally, check the remaining gas
    let remaining_gas = evm::gas_left();
    let gas_spent = U256::from(gas_tally - remaining_gas);

    // Compute the total gas cost
    let gas_cost = gas_price * gas_spent + l1_gas_cost;

    Ok(gas_cost)
}

/// Resolves the refund address to use for the given arguments.
fn resolve_refund_address(
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
        return tx::origin();
    }

    // If we are refunding through the buy-side token,
    // we default to the receiver of the buy-side tokens
    // as the refund address
    receiver
}

/// Refunds the user's gas costs through native ETH.
/// The `gas_cost` is the estimated gas cost of the transaction in units of wei.
fn refund_through_native_eth(
    refund_address: Address,
    gas_cost: U256,
    nonce: U256,
) -> Result<(), Vec<u8>> {
    // If the gas sponsor doesn't have enough Ether to refund the user,
    // emit an event but don't revert.
    if contract::balance() < gas_cost {
        evm::log(InsufficientSponsorBalance { nonce });
        return Ok(());
    }

    call(
        Call::new().value(gas_cost),
        refund_address,
        &[], // calldata
    )?;

    evm::log(SponsoredExternalMatch { amount: gas_cost, token: Address::ZERO, nonce });

    Ok(())
}

/// Refunds the user's gas costs through the buy-side token.
/// The `gas_cost` is the estimated gas cost of the transaction in units of wei,
/// and the `conversion_rate` is the price of the buy-side token in units of
/// token/eth
fn refund_through_buy_token(
    refund_address: Address,
    buy_token_addr: Address,
    gas_cost: U256,
    conversion_rate: U256,
    nonce: U256,
) -> Result<(), Vec<u8>> {
    let buy_token = IErc20::new(buy_token_addr);

    // Convert the gas cost to the buy-side token. The conversion rate is in terms
    // of token/eth, so we divide by wei/eth to get token/wei.
    let buy_token_surplus = gas_cost * conversion_rate / WEI_PER_ETH;

    // If the gas sponsor doesn't have enough of the buy-side token to refund the
    // user, emit an event but don't revert.
    if buy_token.balance_of(Call::new(), contract::address())? < buy_token_surplus {
        evm::log(InsufficientSponsorBalance { nonce });
        return Ok(());
    }

    // Refund the user's gas costs
    buy_token.transfer(Call::new(), refund_address, buy_token_surplus)?;

    evm::log(SponsoredExternalMatch { amount: buy_token_surplus, token: buy_token_addr, nonce });

    Ok(())
}

/// Refunds the user's gas costs, either through native ETH or the buy-side
/// token.
/// The `gas_cost` is the estimated gas cost of the transaction in units of wei,
/// and the `conversion_rate` is the price of the buy-side token in units of
/// token/wei
fn refund_gas_cost(
    refund_native_eth: bool,
    refund_address: Address,
    buy_token_addr: Address,
    gas_cost: U256,
    conversion_rate: U256,
    receiver: Address,
    nonce: U256,
) -> Result<(), Vec<u8>> {
    let refund_address = resolve_refund_address(refund_native_eth, refund_address, receiver);

    let is_native_eth_buy = is_native_eth_address(buy_token_addr);

    // If we are deliberately refunding through native ETH, or if the buy-side
    // token is native ETH, we can just transfer the ETH directly.
    if refund_native_eth || is_native_eth_buy {
        refund_through_native_eth(refund_address, gas_cost, nonce)
    } else {
        refund_through_buy_token(refund_address, buy_token_addr, gas_cost, conversion_rate, nonce)
    }
}
