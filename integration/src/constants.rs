//! Constants used in the integration tests

use alloy_primitives::U256;

/// The default hostport that the Nitro devnet L2 node runs on
pub(crate) const DEFAULT_DEVNET_HOSTPORT: &str = "http://localhost:8547";

/// The default private key that the Nitro devnet is seeded with
pub(crate) const DEFAULT_DEVNET_PKEY: &str =
    "0xb6b15c8cb491557369f3c7d2c287b053eb229daa9c22138887752191c9520659";

/// The name of the domain separator for Permit2 typed data
pub(crate) const PERMIT2_EIP712_DOMAIN_NAME: &str = "Permit2";

/// The amount of token to refund in an in-kind sponsorship test,
/// regardless of what asset is being used for refunding.
pub(crate) const REFUND_AMOUNT: U256 = U256::from_limbs([100_u64, 0, 0, 0]);
