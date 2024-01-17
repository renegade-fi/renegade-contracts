//! Constants used in the integration tests

/// The default hostport that the Nitro devnet L2 node runs on
pub(crate) const DEFAULT_DEVNET_HOSTPORT: &str = "http://localhost:8547";

/// The default private key that the Nitro devnet is seeded with
pub(crate) const DEFAULT_DEVNET_PKEY: &str =
    "0xb6b15c8cb491557369f3c7d2c287b053eb229daa9c22138887752191c9520659";

/// The name of the `transfer_ownership` method on the Darkpool contract
pub(crate) const TRANSFER_OWNERSHIP_METHOD_NAME: &str = "transferOwnership";

/// The name of the `pause` method on the Darkpool contract
pub(crate) const PAUSE_METHOD_NAME: &str = "pause";

/// The name of the `unpause` method on the Darkpool contract
pub(crate) const UNPAUSE_METHOD_NAME: &str = "unpause";

/// The name of the `set_fee` method on the Darkpool contract
pub(crate) const SET_FEE_METHOD_NAME: &str = "setFee";

/// The name of the `set_verifier_address` method on the Darkpool contract
pub(crate) const SET_VERIFIER_ADDRESS_METHOD_NAME: &str = "setVerifierAddress";

/// The name of the `set_vkeys_address` method on the Darkpool contract
pub(crate) const SET_VKEYS_ADDRESS_METHOD_NAME: &str = "setVkeysAddress";

/// The name of the `set_merkle_address` method on the Darkpool contract
pub(crate) const SET_MERKLE_ADDRESS_METHOD_NAME: &str = "setMerkleAddress";
