//! Type definitions used throughout the scripts

use std::fmt::{self, Display};

use clap::ValueEnum;
use contracts_common::types::{MatchLinkingVkeys, MatchVkeys, VerificationKey};

/// The possible Stylus contracts to deploy
#[derive(ValueEnum, Copy, Clone)]
pub enum StylusContract {
    /// The darkpool contract
    Darkpool,
    /// The darkpool core contract
    DarkpoolCore,
    /// The darkpool test contract
    DarkpoolTestContract,
    /// The Merkle contract
    Merkle,
    /// The Merkle test contract
    MerkleTestContract,
    /// The verifier contract
    Verifier,
    /// The verification keys contract
    Vkeys,
    /// The test verification keys contract
    TestVkeys,
    /// The transfer executor contract
    TransferExecutor,
    /// The dummy ERC20 contract
    DummyErc20,
    /// The dummy upgrade target contract
    DummyUpgradeTarget,
    /// The precompile test contract
    PrecompileTestContract,
}

impl Display for StylusContract {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StylusContract::Darkpool => write!(f, "darkpool"),
            StylusContract::DarkpoolCore => write!(f, "darkpool-core"),
            StylusContract::DarkpoolTestContract => write!(f, "darkpool-test-contract"),
            StylusContract::Merkle => write!(f, "merkle"),
            StylusContract::MerkleTestContract => write!(f, "merkle-test-contract"),
            StylusContract::Verifier => write!(f, "verifier"),
            StylusContract::Vkeys => write!(f, "vkeys"),
            StylusContract::TestVkeys => write!(f, "test-vkeys"),
            StylusContract::TransferExecutor => write!(f, "transfer-executor"),
            StylusContract::DummyErc20 => write!(f, "dummy-erc20"),
            StylusContract::DummyUpgradeTarget => write!(f, "dummy-upgrade-target"),
            StylusContract::PrecompileTestContract => write!(f, "precompile-test-contract"),
        }
    }
}

/// A convenience struct containing all of the verification keys in the protocol
pub struct RenegadeVerificationKeys {
    /// The `VALID WALLET CREATE` verification key
    pub valid_wallet_create: VerificationKey,
    /// The `VALID WALLET UPDATE` verification key
    pub valid_wallet_update: VerificationKey,
    /// The `VALID RELAYER FEE SETTLEMENT` verification key
    pub valid_relayer_fee_settlement: VerificationKey,
    /// The `VALID OFFLINE FEE SETTLEMENT` verification key
    pub valid_offline_fee_settlement: VerificationKey,
    /// The `VALID FEE REDEMPTION` verification key
    pub valid_fee_redemption: VerificationKey,
    /// The verification keys used in matching & settling a trade
    pub match_vkeys: MatchVkeys,
    /// The proof linking verification keys used in
    /// matching & settling a trade
    pub match_linking_vkeys: MatchLinkingVkeys,
}
