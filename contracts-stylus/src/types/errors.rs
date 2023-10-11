//! Errors stemming from conversions between types used throughout the system.

use stylus_sdk::alloy_primitives::ruint::FromUintError;

/// Errors stemming from working with Solidity-ABI-compatible storage types
pub enum StorageError {
    /// An error that occurred while converting between a Solidity-ABI-compatible storage type and a Rust type
    TypeConversion,
    /// An error that occurred while serializing Rust types before conversion, or deserializing after conversion
    Serialization,
}

impl<T> From<FromUintError<T>> for StorageError {
    fn from(_value: FromUintError<T>) -> Self {
        StorageError::TypeConversion
    }
}

impl From<ark_serialize::SerializationError> for StorageError {
    fn from(_value: ark_serialize::SerializationError) -> Self {
        StorageError::Serialization
    }
}
