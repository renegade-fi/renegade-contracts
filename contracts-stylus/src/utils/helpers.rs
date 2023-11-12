//! Miscellaneous helper functions for the contracts.

use alloc::vec::Vec;
use alloy_sol_types::{SolCall, SolType};
use common::{
    custom_serde::ScalarSerializable, serde_def_types::SerdeScalarField, types::ScalarField,
};
use stylus_sdk::{
    alloy_primitives::{Address, B256},
    call::delegate_call,
    crypto::keccak,
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

/// Computes the Keccak-256 hash of the given scalar when serialized to bytes
pub fn keccak_hash_scalar(scalar: ScalarField) -> B256 {
    keccak(postcard::to_allocvec(&SerdeScalarField(scalar)).unwrap())
}
