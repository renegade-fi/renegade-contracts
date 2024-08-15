//! Miscellaneous helper functions for the contracts.

use alloc::vec::Vec;
use alloy_sol_types::{SolCall, SolType};
use ark_ff::PrimeField;
use contracts_common::{
    constants::{NUM_BYTES_U256, SCALAR_CONVERSION_ERROR_MESSAGE},
    custom_serde::{bigint_from_le_bytes, statement_to_public_inputs, ScalarSerializable},
    types::{
        MatchPublicInputs, PublicSigningKey, ScalarField, ValidCommitmentsStatement,
        ValidMatchSettleStatement, ValidReblindStatement,
    },
};
use contracts_core::crypto::ecdsa::ecdsa_verify;
use serde::{Deserialize, Serialize};
use stylus_sdk::{
    abi::Bytes,
    alloy_primitives::{Address, U256},
    call::{call, delegate_call},
    storage::TopLevelStorage,
};

use crate::utils::{
    backends::{PrecompileEcRecoverBackend, StylusHasher},
    constants::{ECDSA_ERROR_MESSAGE, INVALID_SIGNATURE_ERROR_MESSAGE},
};

use super::constants::{
    CALLDATA_DESER_ERROR_MESSAGE, CALLDATA_SER_ERROR_MESSAGE, CALL_RETDATA_DECODING_ERROR_MESSAGE,
    INVALID_ARR_LEN_ERROR_MESSAGE,
};

/// Deserializes a byte-serialized type from calldata
#[cfg_attr(
    not(any(
        feature = "darkpool-core",
        feature = "verifier",
        feature = "transfer-executor"
    )),
    allow(dead_code)
)]
pub fn deserialize_from_calldata<'a, D: Deserialize<'a>>(
    calldata: &'a Bytes,
) -> Result<D, Vec<u8>> {
    postcard::from_bytes(calldata.as_slice()).map_err(|_| CALLDATA_DESER_ERROR_MESSAGE.to_vec())
}

/// Serializes the given type into bytes for calldata
#[cfg_attr(
    not(any(feature = "darkpool-core", feature = "transfer-executor")),
    allow(dead_code)
)]
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
#[cfg_attr(not(feature = "darkpool-core"), allow(dead_code))]
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

/// Fetch the public blinder from a set of public shares
///
/// Currently this is the last share, though we separate out this logic
/// to make changing this invariant easier
pub fn get_public_blinder_from_shares(shares: &[ScalarField]) -> ScalarField {
    *shares.last().unwrap()
}

/// Maps an error returned from an external contract call to a `Vec<u8>`,
/// which is the expected return type of external contract methods.
pub fn map_call_error(e: stylus_sdk::call::Error) -> Vec<u8> {
    match e {
        stylus_sdk::call::Error::Revert(msg) => msg,
        stylus_sdk::call::Error::AbiDecodingFailed(_) => {
            CALL_RETDATA_DECODING_ERROR_MESSAGE.to_vec()
        }
    }
}

/// Maps a generic error type, which represents a failure
/// in serializing some other type to calldata, to the `Vec<u8>`
/// form of the appropriate error message.
pub fn map_calldata_ser_error<E>(_e: E) -> Vec<u8> {
    CALLDATA_SER_ERROR_MESSAGE.to_vec()
}

/// Performs a `delegatecall` to the given address, calling the function
/// defined as a `SolCall` with the given arguments.
#[cfg_attr(
    not(any(
        feature = "darkpool-core",
        feature = "darkpool",
        feature = "darkpool-test-contract"
    )),
    allow(dead_code)
)]
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
pub fn call_helper<C: SolCall>(
    storage: &mut impl TopLevelStorage,
    address: Address,
    args: <C::Parameters<'_> as SolType>::RustType,
) -> Result<C::Return, Vec<u8>> {
    let calldata = C::new(args).abi_encode();
    let res = call(storage, address, &calldata).map_err(map_call_error)?;
    C::abi_decode_returns(&res, false /* validate */)
        .map_err(|_| CALL_RETDATA_DECODING_ERROR_MESSAGE.to_vec())
}

/// Converts a U256 to a scalar
#[cfg_attr(
    not(any(
        feature = "darkpool-test-contract",
        feature = "merkle",
        feature = "merkle-test-contract"
    )),
    allow(dead_code)
)]
pub fn u256_to_scalar(u256: U256) -> Result<ScalarField, Vec<u8>> {
    let bigint = bigint_from_le_bytes(&u256.to_le_bytes::<NUM_BYTES_U256>())
        .map_err(|_| SCALAR_CONVERSION_ERROR_MESSAGE.to_vec())?;
    ScalarField::from_bigint(bigint).ok_or(SCALAR_CONVERSION_ERROR_MESSAGE.to_vec())
}

/// Asserts the validity of the given signature using the given public signing key,
/// if verification is enabled
#[cfg_attr(
    not(any(
        feature = "transfer-executor",
        feature = "merkle",
        feature = "merkle-test-contract",
    )),
    allow(dead_code)
)]
pub fn assert_valid_signature(
    pk_root: &PublicSigningKey,
    message: &[u8],
    signature: &[u8],
) -> Result<(), Vec<u8>> {
    crate::assert_result!(
        ecdsa_verify::<StylusHasher, PrecompileEcRecoverBackend>(
            pk_root,
            message,
            signature
                .try_into()
                .map_err(|_| INVALID_ARR_LEN_ERROR_MESSAGE)?,
        )
        .map_err(|_| ECDSA_ERROR_MESSAGE)?,
        INVALID_SIGNATURE_ERROR_MESSAGE
    )
}

/// Expands to the given code block if verification is enabled,
/// otherwise guards the disablement of verification.
///
/// We guard against verification disablement here, instead of the
/// initialization of a contract, in the case that a contract is
/// upgraded to a version w/ verification disabled - the initialization
/// method may not be called.
#[macro_export]
macro_rules! if_verifying {
    ($($logic:tt)*) => {
        // If verification is enabled, execute the given logic
        #[cfg(not(feature = "no-verify"))]
        {
            $($logic)*
        }

        // Otherwise, ensure that verification disablement
        // is permitted (i.e., we are on the Renegade devnet)
        #[cfg(feature = "no-verify")]
        {
            use stylus_sdk::block;
            use contracts_common::constants::DEVNET_CHAINID;
            use $crate::{assert_result, utils::constants::VERIFICATION_DISABLED_ERROR_MESSAGE};

            assert_result!(block::chainid() == DEVNET_CHAINID, VERIFICATION_DISABLED_ERROR_MESSAGE)?;
        }
    };
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
