//! Miscellaneous helper functions for the contracts.

use alloy_sol_types::{SolCall, SolType};
use ark_ff::{BigInteger, PrimeField};
use common::{
    constants::NUM_BYTES_ADDRESS,
    custom_serde::{bigint_from_le_bytes, BytesSerializable, SerdeError},
    types::ScalarField,
};
use stylus_sdk::{
    alloy_primitives::{Address, U256},
    call::{delegate_call, static_call},
    storage::TopLevelStorage,
};

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

/// Converts a scalar into an Ethereum address.
/// We interpret the first 20 bytes of the little-endian representation
/// of the scalar to be the address.
#[cfg_attr(
    not(any(feature = "darkpool", feature = "darkpool-test-contract",)),
    allow(dead_code)
)]
pub fn address_from_scalar(scalar: ScalarField) -> Address {
    Address::from_slice(&scalar.into_bigint().to_bytes_le()[..NUM_BYTES_ADDRESS])
}

/// Converts two scalars into a U256.
/// We interpret the first scalar as the high 128 bits of the U256,
/// and the second scalar as the low 128 bits of the U256.
#[cfg_attr(
    not(any(feature = "darkpool", feature = "darkpool-test-contract",)),
    allow(dead_code)
)]
pub fn u256_from_scalars(scalars: &[ScalarField; 2]) -> U256 {
    assert!(scalars.len() == 2);

    let high = scalar_to_u256(scalars[0]);
    let low = scalar_to_u256(scalars[1]);

    high << 128 | low
}

#[macro_export]
macro_rules! if_verifying {
    ($($logic:tt)*) => {
        #[cfg(not(feature = "no-verify"))]
        {
            $($logic)*
        }
    };
}
