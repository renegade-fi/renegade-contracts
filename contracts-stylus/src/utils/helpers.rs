//! Miscellaneous helper functions for the contracts.

use alloc::vec::Vec;
use alloy_sol_types::{SolCall, SolType};
use ark_ff::PrimeField;
use contracts_common::{
    constants::NUM_SCALARS_PK,
    custom_serde::{
        bigint_from_le_bytes, pk_to_scalars, statement_to_public_inputs, BytesSerializable,
        ScalarSerializable, SerdeError,
    },
    types::{
        MatchPublicInputs, PublicSigningKey, ScalarField, ValidCommitmentsStatement,
        ValidMatchSettleStatement, ValidReblindStatement,
    },
};
use stylus_sdk::{
    alloy_primitives::{Address, U256},
    call::{delegate_call, static_call},
    storage::TopLevelStorage,
};

/// Serializes the given statement into scalars, and then into bytes,
/// as expected by the verifier contract.
#[cfg_attr(
    not(any(feature = "darkpool", feature = "darkpool-test-contract")),
    allow(dead_code)
)]
pub fn serialize_statement_for_verification<S: ScalarSerializable>(
    statement: &S,
) -> postcard::Result<Vec<u8>> {
    postcard::to_allocvec(&statement_to_public_inputs(statement))
}

/// Serializes the statements used in verifying the settlement of a
/// matched trade into scalars, builds the [`MatchPublicInputs`] struct,
/// and then serialized it into bytes, as expected by the verifier contract.
#[cfg_attr(
    not(any(feature = "darkpool", feature = "darkpool-test-contract")),
    allow(dead_code)
)]
pub fn serialize_match_statements_for_verification(
    valid_commitments_0: &ValidCommitmentsStatement,
    valid_commitments_1: &ValidCommitmentsStatement,
    valid_reblind_0: &ValidReblindStatement,
    valid_reblind_1: &ValidReblindStatement,
    valid_match_settle: &ValidMatchSettleStatement,
) -> postcard::Result<Vec<u8>> {
    let match_public_inputs = MatchPublicInputs {
        valid_commitments_0: statement_to_public_inputs(valid_commitments_0),
        valid_commitments_1: statement_to_public_inputs(valid_commitments_1),
        valid_reblind_0: statement_to_public_inputs(valid_reblind_0),
        valid_reblind_1: statement_to_public_inputs(valid_reblind_1),
        valid_match_settle: statement_to_public_inputs(valid_match_settle),
    };
    postcard::to_allocvec(&match_public_inputs)
}

/// Performs a `delegatecall` to the given address, calling the function
/// defined as a `SolCall` with the given arguments.
#[cfg_attr(
    not(any(feature = "darkpool", feature = "darkpool-test-contract")),
    allow(dead_code)
)]
pub fn delegate_call_helper<C: SolCall>(
    storage: &mut impl TopLevelStorage,
    address: Address,
    args: <C::Arguments<'_> as SolType>::RustType,
) -> Result<C::Return, Vec<u8>> {
    let calldata = C::new(args).encode();
    let res = unsafe {
        delegate_call(storage, address, &calldata).map_err(|e| match e {
            stylus_sdk::call::Error::Revert(msg) => msg,
            stylus_sdk::call::Error::AbiDecodingFailed(_) => b"abi decoding failed".to_vec(),
        })?
    };
    Ok(C::decode_returns(&res, true /* validate */).unwrap())
}

/// Performs a `staticcall` to the given address, calling the function
/// defined as a `SolCall` with the given arguments.
#[cfg_attr(
    not(any(feature = "darkpool", feature = "darkpool-test-contract")),
    allow(dead_code)
)]
pub fn static_call_helper<C: SolCall>(
    storage: &mut impl TopLevelStorage,
    address: Address,
    args: <C::Arguments<'_> as SolType>::RustType,
) -> C::Return {
    let calldata = C::new(args).encode();
    let res = static_call(storage, address, &calldata).unwrap();
    C::decode_returns(&res, true /* validate */).unwrap()
}

/// Converts a scalar to a U256
#[cfg_attr(
    not(any(
        feature = "darkpool",
        feature = "darkpool-test-contract",
        feature = "merkle",
        feature = "merkle-test-contract"
    )),
    allow(dead_code)
)]
pub fn scalar_to_u256(scalar: ScalarField) -> U256 {
    U256::from_be_slice(&scalar.serialize_to_bytes())
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
pub fn u256_to_scalar(u256: U256) -> Result<ScalarField, SerdeError> {
    let bigint = bigint_from_le_bytes(&u256.to_le_bytes_vec())?;
    ScalarField::from_bigint(bigint).ok_or(SerdeError::ScalarConversion)
}

/// Converts a [`PublicSigningKey`] into the [`U256`] array representing its scalar serialization
#[cfg_attr(
    not(any(feature = "darkpool", feature = "darkpool-test-contract")),
    allow(dead_code)
)]
pub fn pk_to_u256s(pk: &PublicSigningKey) -> [U256; NUM_SCALARS_PK] {
    let scalars = pk_to_scalars(pk);
    scalars
        .into_iter()
        .map(scalar_to_u256)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

/// Expands to the given code block if the `no-verify` feature is not enabled.
#[macro_export]
macro_rules! if_verifying {
    ($($logic:tt)*) => {
        #[cfg(not(feature = "no-verify"))]
        {
            $($logic)*
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
