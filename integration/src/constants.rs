//! Constants used in the integration tests

use alloy_primitives::U256 as AlloyU256;
use ethers::types::U256;
use ruint::uint;

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

/// The name of the `set_core_wallet_ops_address` method on the Darkpool
/// contract
pub(crate) const SET_CORE_WALLET_OPS_ADDRESS_METHOD_NAME: &str = "setCoreWalletOpsAddress";

/// The name of the `set_core_settlement_address` method on the Darkpool
/// contract
pub(crate) const SET_CORE_SETTLEMENT_ADDRESS_METHOD_NAME: &str = "setCoreSettlementAddress";

/// The name of the `set_verifier_core_address` method on the Darkpool contract
pub(crate) const SET_VERIFIER_CORE_ADDRESS_METHOD_NAME: &str = "setVerifierCoreAddress";

/// The name of the `set_verifier_settlement_address` method on the Darkpool
/// contract
pub(crate) const SET_VERIFIER_SETTLEMENT_ADDRESS_METHOD_NAME: &str = "setVerifierSettlementAddress";

/// The name of the `set_vkeys_address` method on the Darkpool contract
pub(crate) const SET_VKEYS_ADDRESS_METHOD_NAME: &str = "setVkeysAddress";

/// The name of the `set_merkle_address` method on the Darkpool contract
pub(crate) const SET_MERKLE_ADDRESS_METHOD_NAME: &str = "setMerkleAddress";

/// The name of the `set_transfer_executor_address` method on the Darkpool
/// contract
pub(crate) const SET_TRANSFER_EXECUTOR_ADDRESS_METHOD_NAME: &str = "setTransferExecutorAddress";

/// The name of the domain separator for Permit2 typed data
pub(crate) const PERMIT2_EIP712_DOMAIN_NAME: &str = "Permit2";

/// The gas cost tolerance, i.e. the margin of error in units of gas
/// that is permissible in our gas refund accounting
pub(crate) const GAS_COST_TOLERANCE: AlloyU256 = uint!(15_000U256);

/// The amount of token to refund in an in-kind sponsorship test,
/// regardless of what asset is being used for refunding.
pub(crate) const REFUND_AMOUNT: U256 = U256([100_u64, 0, 0, 0]);
