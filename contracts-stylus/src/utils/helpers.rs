//! Miscellaneous helper functions for the contracts.

use alloc::vec::Vec;
use common::{custom_serde::ScalarSerializable, serde_def_types::SerdeScalarField};

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
