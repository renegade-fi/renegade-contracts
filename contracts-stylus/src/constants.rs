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

/// The ID of the `VALID_WALLET_CREATE` circuit
pub const VALID_WALLET_CREATE_CIRCUIT_ID: u8 = 0;
/// The ID of the `VALID_WALLET_UPDATE` circuit
pub const VALID_WALLET_UPDATE_CIRCUIT_ID: u8 = 1;
/// The ID of the `VALID_COMMITMENTS` circuit
pub const VALID_COMMITMENTS_CIRCUIT_ID: u8 = 2;
/// The ID of the `VALID_REBLIND` circuit
pub const VALID_REBLIND_CIRCUIT_ID: u8 = 3;
/// The ID of the `VALID_MATCH_SETTLE` circuit
pub const VALID_MATCH_SETTLE_CIRCUIT_ID: u8 = 4;
