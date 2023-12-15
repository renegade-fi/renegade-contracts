//! Miscellaneous helper functions for the contracts.

use alloc::vec::Vec;
use alloy_sol_types::{SolCall, SolType};
use common::{
    custom_serde::{BytesDeserializable, BytesSerializable, ScalarSerializable, SerdeError},
    serde_def_types::SerdeScalarField,
    types::ScalarField,
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
    postcard::to_allocvec(
        &statement
            .serialize_to_scalars()
            .unwrap()
            .into_iter()
            .map(SerdeScalarField)
            .collect::<Vec<_>>(),
    )
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
) -> C::Return {
    let calldata = C::new(args).encode();
    let res = unsafe { delegate_call(storage, address, &calldata).unwrap() };
    C::decode_returns(&res, true /* validate */).unwrap()
}

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
pub fn scalar_to_u256(scalar: ScalarField) -> U256 {
    U256::from_be_slice(&scalar.serialize_to_bytes())
}

/// Converts a U256 to a scalar
pub fn u256_to_scalar(u256: U256) -> Result<ScalarField, SerdeError> {
    ScalarField::deserialize_from_bytes(&u256.to_be_bytes_vec())
}

#[macro_export]
macro_rules! assert_if_verifying {
    ($cond:expr $(,)?) => {
        // Note: the "no-verify" feature is ONLY for testing purposes
        #[cfg(not(feature = "no-verify"))]
        {
            assert!($cond);
        }
    };
    ($cond:expr, $($arg:tt)+) => {
        // Note: the "no-verify" feature is ONLY for testing purposes
        #[cfg(not(feature = "no-verify"))]
        {
            assert!($cond, $($arg)+);
        }
    };
}
