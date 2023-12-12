//! Constants used throughout the contracts

/// The last byte of the `ecAdd` precompile address, 0x06
pub const EC_ADD_ADDRESS_LAST_BYTE: u8 = 6;
/// The last byte of the `ecMul` precompile address, 0x07
pub const EC_MUL_ADDRESS_LAST_BYTE: u8 = 7;
/// The last byte of the `ecPairing` precompile address, 0x08
pub const EC_PAIRING_ADDRESS_LAST_BYTE: u8 = 8;
/// The last byte of the `ecRecover` precompile address, 0x01
pub const EC_RECOVER_ADDRESS_LAST_BYTE: u8 = 1;

/// The index of the last byte of the `ecPairing` precompile result,
/// which is a boolean indicating whether the pairing check succeeded
pub const PAIRING_CHECK_RESULT_LAST_BYTE_INDEX: usize = 31;

/// The byte length of the input to the `ecRecover` precompile
pub const EC_RECOVER_INPUT_LEN: usize = 128;

/// The number of storage slots to use in the Darkpool contract's
/// storage gap, which ensures that there are no storage collisions
/// with the Merkle contract to which it delegatecalls
#[cfg(any(feature = "darkpool", feature = "darkpool-test-contract"))]
pub const STORAGE_GAP_SIZE: usize = 64;

/// The serialized VALID WALLET CREATE verification key
#[cfg(feature = "darkpool")]
pub const VALID_WALLET_CREATE_VKEY_BYTES: &[u8] =
    include_bytes!("../../vkeys/prod/valid_wallet_create");

/// The serialized testing VALID WALLET CREATE verification key
#[cfg(feature = "darkpool-test-contract")]
pub const VALID_WALLET_CREATE_VKEY_BYTES: &[u8] =
    include_bytes!("../../vkeys/test/valid_wallet_create");

/// The serialized VALID WALLET UPDATE verification key
#[cfg(feature = "darkpool")]
pub const VALID_WALLET_UPDATE_VKEY_BYTES: &[u8] =
    include_bytes!("../../vkeys/prod/valid_wallet_update");

/// The serialized testing VALID WALLET UPDATE verification key
#[cfg(feature = "darkpool-test-contract")]
pub const VALID_WALLET_UPDATE_VKEY_BYTES: &[u8] =
    include_bytes!("../../vkeys/test/valid_wallet_update");

/// The serialized VALID COMMITMENTS verification key
#[cfg(feature = "darkpool")]
pub const VALID_COMMITMENTS_VKEY_BYTES: &[u8] =
    include_bytes!("../../vkeys/prod/valid_commitments");

/// The serialized testing VALID COMMITMENTS verification key
#[cfg(feature = "darkpool-test-contract")]
pub const VALID_COMMITMENTS_VKEY_BYTES: &[u8] =
    include_bytes!("../../vkeys/test/valid_commitments");

/// The serialized VALID REBLIND verification key
#[cfg(feature = "darkpool")]
pub const VALID_REBLIND_VKEY_BYTES: &[u8] = include_bytes!("../../vkeys/prod/valid_reblind");

/// The serialized testing VALID REBLIND verification key
#[cfg(feature = "darkpool-test-contract")]
pub const VALID_REBLIND_VKEY_BYTES: &[u8] = include_bytes!("../../vkeys/test/valid_reblind");

/// The serialized VALID MATCH SETTLE verification key
#[cfg(feature = "darkpool")]
pub const VALID_MATCH_SETTLE_VKEY_BYTES: &[u8] =
    include_bytes!("../../vkeys/prod/valid_match_settle");

/// The serialized testing VALID MATCH SETTLE verification key
#[cfg(feature = "darkpool-test-contract")]
pub const VALID_MATCH_SETTLE_VKEY_BYTES: &[u8] =
    include_bytes!("../../vkeys/test/valid_match_settle");
