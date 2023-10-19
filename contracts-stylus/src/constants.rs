//! Constants used throughout the contracts

/// The last byte of the `ecAdd` precompile address, 0x06
pub const EC_ADD_ADDRESS_LAST_BYTE: u8 = 6;
/// The last byte of the `ecMul` precompile address, 0x07
pub const EC_MUL_ADDRESS_LAST_BYTE: u8 = 7;
/// The last byte of the `ecPairing` precompile address, 0x08
pub const EC_PAIRING_ADDRESS_LAST_BYTE: u8 = 8;
/// The index of the last byte of the `ecPairing` precompile result,
/// which is a boolean indicating whether the pairing check succeeded
pub const PAIRING_CHECK_RESULT_LAST_BYTE_INDEX: usize = 31;
