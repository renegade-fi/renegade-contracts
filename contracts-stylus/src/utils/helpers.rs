//! Miscellaneous helper functions for the contracts.

use alloc::vec::Vec;
use alloy_sol_types::{SolCall, SolType};
use contracts_common::{
    custom_serde::{statement_to_public_inputs, ScalarSerializable},
    types::{
        MatchAtomicPublicInputs, MatchPublicInputs, PublicSigningKey, ScalarField,
        ValidCommitmentsStatement, ValidMalleableMatchSettleAtomicStatement,
        ValidMatchSettleAtomicStatement, ValidMatchSettleAtomicWithCommitmentsStatement,
        ValidMatchSettleStatement, ValidMatchSettleWithCommitmentsStatement, ValidReblindStatement,
    },
};
use contracts_core::crypto::ecdsa::ecdsa_verify_with_pubkey;
use core::str::FromStr;
use serde::{Deserialize, Serialize};
use stylus_sdk::{
    abi::Bytes, alloy_primitives::Address, call::MutatingCallContext, prelude::TopLevelStorage,
};

#[allow(deprecated)]
use stylus_sdk::call::{call, delegate_call, static_call};

use crate::{
    utils::{
        backends::{PrecompileEcRecoverBackend, StylusHasher},
        constants::{ECDSA_ERROR_MESSAGE, INVALID_SIGNATURE_ERROR_MESSAGE},
    },
    ZERO_ADDRESS_ERROR_MESSAGE,
};

use super::constants::{
    CALLDATA_DESER_ERROR_MESSAGE, CALLDATA_SER_ERROR_MESSAGE, CALL_RETDATA_DECODING_ERROR_MESSAGE,
    INVALID_ARR_LEN_ERROR_MESSAGE,
};

/// A helper to get the address of the WETH contract
#[cfg(any(
    feature = "transfer-executor",
    feature = "core-atomic-match-settle",
    feature = "core-malleable-match-settle"
))]
pub fn get_weth_address() -> Address {
    use crate::utils::constants::WETH_ADDRESS;
    Address::from_str(WETH_ADDRESS).expect("WETH_ADDRESS must be a valid address")
}

/// A helper to check if a given address is the address representing native ETH
#[cfg(any(
    feature = "transfer-executor",
    feature = "core-atomic-match-settle",
    feature = "core-malleable-match-settle",
    feature = "gas-sponsor"
))]
pub fn is_native_eth_address(addr: Address) -> bool {
    use super::constants::NATIVE_ETH_ADDRESS;
    let native_addr = Address::from_str(NATIVE_ETH_ADDRESS).unwrap();
    addr == native_addr
}

/// Deserializes a byte-serialized type from calldata
#[cfg_attr(
    not(any(feature = "darkpool-core", feature = "verifier", feature = "transfer-executor")),
    allow(dead_code)
)]
pub fn deserialize_from_calldata<'a, D: Deserialize<'a>>(
    calldata: &'a Bytes,
) -> Result<D, Vec<u8>> {
    postcard::from_bytes(calldata.as_slice()).map_err(|_| CALLDATA_DESER_ERROR_MESSAGE.to_vec())
}

/// Serializes the given type into bytes for calldata
#[cfg_attr(not(any(feature = "darkpool-core", feature = "transfer-executor")), allow(dead_code))]
pub fn postcard_serialize<S: Serialize>(s: &S) -> Result<Vec<u8>, Vec<u8>> {
    postcard::to_allocvec(s).map_err(map_calldata_ser_error)
}

/// Serializes the given statement into scalars, and then into bytes,
/// as expected by the verifier contract.
#[cfg_attr(not(feature = "darkpool-core"), allow(dead_code))]
pub fn serialize_statement_for_verification<S: ScalarSerializable>(
    statement: &S,
) -> Result<Vec<u8>, Vec<u8>> {
    let public_inputs = statement_to_public_inputs(statement).map_err(map_calldata_ser_error)?;
    postcard_serialize(&public_inputs)
}

/// Serializes the statements used in verifying the settlement of a
/// matched trade into scalars, builds the [`MatchPublicInputs`] struct,
/// and then serialized it into bytes, as expected by the verifier contract.
#[cfg_attr(not(feature = "core-match-settle"), allow(dead_code))]
pub fn serialize_match_statements_for_verification(
    valid_commitments_0: &ValidCommitmentsStatement,
    valid_commitments_1: &ValidCommitmentsStatement,
    valid_reblind_0: &ValidReblindStatement,
    valid_reblind_1: &ValidReblindStatement,
    valid_match_settle: &ValidMatchSettleStatement,
) -> Result<Vec<u8>, Vec<u8>> {
    let match_public_inputs = MatchPublicInputs {
        valid_commitments_0: statement_to_public_inputs(valid_commitments_0)
            .map_err(map_calldata_ser_error)?,
        valid_commitments_1: statement_to_public_inputs(valid_commitments_1)
            .map_err(map_calldata_ser_error)?,
        valid_reblind_0: statement_to_public_inputs(valid_reblind_0)
            .map_err(map_calldata_ser_error)?,
        valid_reblind_1: statement_to_public_inputs(valid_reblind_1)
            .map_err(map_calldata_ser_error)?,
        valid_match_settle: statement_to_public_inputs(valid_match_settle)
            .map_err(map_calldata_ser_error)?,
    };
    postcard_serialize(&match_public_inputs)
}

/// Serializes the statements used in verifying the settlement of a matched
/// trade with commitments
#[cfg_attr(not(feature = "core-match-settle"), allow(dead_code))]
pub fn serialize_match_statements_for_verification_with_commitments(
    valid_commitments0: &ValidCommitmentsStatement,
    valid_commitments1: &ValidCommitmentsStatement,
    valid_reblind0: &ValidReblindStatement,
    valid_reblind1: &ValidReblindStatement,
    valid_match_settle: &ValidMatchSettleWithCommitmentsStatement,
) -> Result<Vec<u8>, Vec<u8>> {
    let match_public_inputs = MatchPublicInputs {
        valid_commitments_0: statement_to_public_inputs(valid_commitments0)
            .map_err(map_calldata_ser_error)?,
        valid_commitments_1: statement_to_public_inputs(valid_commitments1)
            .map_err(map_calldata_ser_error)?,
        valid_reblind_0: statement_to_public_inputs(valid_reblind0)
            .map_err(map_calldata_ser_error)?,
        valid_reblind_1: statement_to_public_inputs(valid_reblind1)
            .map_err(map_calldata_ser_error)?,
        valid_match_settle: statement_to_public_inputs(valid_match_settle)
            .map_err(map_calldata_ser_error)?,
    };
    postcard_serialize(&match_public_inputs)
}

/// Serializes the statements used in verifying the settlement of an atomic
/// matched trade into scalars, builds the [`AtomicMatchSettlePublicInputs`]
/// struct, and then serializes it into bytes, as expected by the verifier
/// contract.
#[cfg_attr(not(feature = "core-atomic-match-settle"), allow(dead_code))]
pub fn serialize_atomic_match_statements_for_verification(
    valid_commitments: &ValidCommitmentsStatement,
    valid_reblind: &ValidReblindStatement,
    valid_match_settle_atomic: &ValidMatchSettleAtomicStatement,
) -> Result<Vec<u8>, Vec<u8>> {
    let match_atomic_public_inputs = MatchAtomicPublicInputs {
        valid_commitments: statement_to_public_inputs(valid_commitments)
            .map_err(map_calldata_ser_error)?,
        valid_reblind: statement_to_public_inputs(valid_reblind).map_err(map_calldata_ser_error)?,
        valid_match_settle_atomic: statement_to_public_inputs(valid_match_settle_atomic)
            .map_err(map_calldata_ser_error)?,
    };
    postcard_serialize(&match_atomic_public_inputs)
}

/// Serialized the statements used in verying the settlement of an atomic
/// match with full commitments attached
#[cfg_attr(not(feature = "core-atomic-match-settle"), allow(dead_code))]
pub fn serialize_atomic_match_statements_for_verification_with_commitments(
    valid_commitments: &ValidCommitmentsStatement,
    valid_reblind: &ValidReblindStatement,
    valid_match_settle_atomic: &ValidMatchSettleAtomicWithCommitmentsStatement,
) -> Result<Vec<u8>, Vec<u8>> {
    let match_atomic_public_inputs = MatchAtomicPublicInputs {
        valid_commitments: statement_to_public_inputs(valid_commitments)
            .map_err(map_calldata_ser_error)?,
        valid_reblind: statement_to_public_inputs(valid_reblind).map_err(map_calldata_ser_error)?,
        valid_match_settle_atomic: statement_to_public_inputs(valid_match_settle_atomic)
            .map_err(map_calldata_ser_error)?,
    };
    postcard_serialize(&match_atomic_public_inputs)
}

/// Serializes the statements used in verifying the settlement of a
/// matched trade into scalars, builds the [`MatchPublicInputs`] struct,
/// and then serialized it into bytes, as expected by the verifier
/// contract.
#[cfg_attr(not(feature = "core-malleable-match-settle"), allow(dead_code))]
pub fn serialize_malleable_match_statements_for_verification(
    valid_commitments: &ValidCommitmentsStatement,
    valid_reblind: &ValidReblindStatement,
    valid_match_settle_atomic: &ValidMalleableMatchSettleAtomicStatement,
) -> Result<Vec<u8>, Vec<u8>> {
    let match_atomic_public_inputs = MatchAtomicPublicInputs {
        valid_commitments: statement_to_public_inputs(valid_commitments)
            .map_err(map_calldata_ser_error)?,
        valid_reblind: statement_to_public_inputs(valid_reblind).map_err(map_calldata_ser_error)?,
        valid_match_settle_atomic: statement_to_public_inputs(valid_match_settle_atomic)
            .map_err(map_calldata_ser_error)?,
    };
    postcard_serialize(&match_atomic_public_inputs)
}

/// Fetch the public blinder from a set of public shares
///
/// Currently this is the last share, though we separate out this logic
/// to make changing this invariant easier
pub fn get_public_blinder_from_shares(shares: &[ScalarField]) -> ScalarField {
    *shares.last().unwrap()
}

/// Maps an error returned from an external contract call to a `Vec<u8>`,
/// which is the expected return type of external contract methods.
#[allow(deprecated)]
pub fn map_call_error(e: stylus_sdk::call::Error) -> Vec<u8> {
    match e {
        stylus_sdk::call::Error::Revert(msg) => msg,
        stylus_sdk::call::Error::AbiDecodingFailed(_) => {
            CALL_RETDATA_DECODING_ERROR_MESSAGE.to_vec()
        },
    }
}

/// Maps a generic error type, which represents a failure
/// in serializing some other type to calldata, to the `Vec<u8>`
/// form of the appropriate error message.
pub fn map_calldata_ser_error<E>(_e: E) -> Vec<u8> {
    CALLDATA_SER_ERROR_MESSAGE.to_vec()
}

/// Performs a `staticcall` to the given address, calling the function defined
/// as a `SolCall` with the given arguments
#[cfg_attr(
    not(any(feature = "darkpool-core", feature = "darkpool-test-contract")),
    allow(dead_code)
)]
#[allow(deprecated)]
pub fn static_call_helper<C: SolCall>(
    storage: &impl TopLevelStorage,
    address: Address,
    args: <C::Parameters<'_> as SolType>::RustType,
) -> Result<C::Return, Vec<u8>> {
    let calldata = C::new(args).abi_encode();
    let res = static_call(storage, address, &calldata).map_err(map_call_error)?;
    C::abi_decode_returns(&res, false /* validate */)
        .map_err(|_| CALL_RETDATA_DECODING_ERROR_MESSAGE.to_vec())
}

/// Performs a `delegatecall` to the given address, calling the function
/// defined as a `SolCall` with the given arguments.
#[cfg_attr(
    not(any(feature = "darkpool-core", feature = "darkpool", feature = "darkpool-test-contract")),
    allow(dead_code)
)]
#[allow(deprecated)]
pub fn delegate_call_helper<C: SolCall>(
    storage: &mut impl TopLevelStorage,
    address: Address,
    args: <C::Parameters<'_> as SolType>::RustType,
) -> Result<C::Return, Vec<u8>> {
    let calldata = C::new(args).abi_encode();
    let res = unsafe { delegate_call(storage, address, &calldata).map_err(map_call_error)? };
    C::abi_decode_returns(&res, false /* validate */)
        .map_err(|_| CALL_RETDATA_DECODING_ERROR_MESSAGE.to_vec())
}

/// Performs a `call` to the given address, calling the function
/// defined as a `SolCall` with the given arguments.
#[cfg_attr(not(feature = "transfer-executor"), allow(dead_code))]
#[allow(deprecated)]
pub fn call_helper<C: SolCall>(
    storage: impl MutatingCallContext,
    address: Address,
    args: <C::Parameters<'_> as SolType>::RustType,
) -> Result<C::Return, Vec<u8>> {
    let calldata = C::new(args).abi_encode();
    let res = call(storage, address, &calldata).map_err(map_call_error)?;
    C::abi_decode_returns(&res, false /* validate */)
        .map_err(|_| CALL_RETDATA_DECODING_ERROR_MESSAGE.to_vec())
}

/// Asserts the validity of the given signature using the given public signing
/// key
#[cfg_attr(
    not(any(feature = "transfer-executor", feature = "merkle", feature = "merkle-test-contract",)),
    allow(dead_code)
)]
pub fn assert_valid_signature(
    pk_root: &PublicSigningKey,
    message: &[u8],
    signature: &[u8],
) -> Result<(), Vec<u8>> {
    crate::assert_result!(
        ecdsa_verify_with_pubkey::<StylusHasher, PrecompileEcRecoverBackend>(
            pk_root,
            message,
            signature.try_into().map_err(|_| INVALID_ARR_LEN_ERROR_MESSAGE)?,
        )
        .map_err(|_| ECDSA_ERROR_MESSAGE)?,
        INVALID_SIGNATURE_ERROR_MESSAGE
    )
}

/// Checks that the given address is not the zero address
pub fn check_address_not_zero(address: Address) -> Result<(), Vec<u8>> {
    crate::assert_result!(address != Address::ZERO, ZERO_ADDRESS_ERROR_MESSAGE)
}

/// Asserts the given condition, and returns an error if it fails.
/// The "type" this macro returns is `Result<(), Vec<u8>>`, matching
/// the return type of external contract methods.
#[macro_export]
macro_rules! assert_result {
    ($x:expr, $msg:tt) => {
        if $x {
            Ok(())
        } else {
            Err($msg.to_vec())
        }
    };
}
