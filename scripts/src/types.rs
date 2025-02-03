//! Type definitions used throughout the scripts

use std::fmt::{self, Display};

use clap::ValueEnum;
use contracts_common::types::{
    MatchAtomicLinkingVkeys, MatchAtomicVkeys, MatchLinkingVkeys, MatchVkeys, VerificationKey,
};

/// The possible Stylus contracts to deploy
#[derive(ValueEnum, Clone)]
pub enum StylusContract {
    /// The darkpool contract
    Darkpool,
    /// The core wallet operations contract
    CoreWalletOps,
    /// The core settlement contract
    CoreSettlement,
    /// The darkpool test contract
    DarkpoolTestContract,
    /// The Merkle contract
    Merkle,
    /// The Merkle test contract
    MerkleTestContract,
    /// The verifier contract
    VerifierCore,
    /// The verifier settlement contract
    VerifierSettlement,
    /// The verification keys contract
    Vkeys,
    /// The test verification keys contract
    TestVkeys,
    /// The transfer executor contract
    TransferExecutor,
    /// The gas sponsor contract
    GasSponsor,
    /// The dummy ERC20 contract, containing the
    /// token symbol
    // We skip this value in the CLI as we have
    // a separate command for deploying ERC20s
    #[value(skip)]
    DummyErc20(String),
    /// The dummy WETH contract
    #[value(skip)]
    DummyWeth(String),
    /// The dummy upgrade target contract
    DummyUpgradeTarget,
    /// The precompile test contract
    PrecompileTestContract,
}

impl Display for StylusContract {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StylusContract::Darkpool => write!(f, "darkpool"),
            StylusContract::CoreWalletOps => write!(f, "core-wallet-ops"),
            StylusContract::CoreSettlement => write!(f, "core-settlement"),
            StylusContract::DarkpoolTestContract => write!(f, "darkpool-test-contract"),
            StylusContract::Merkle => write!(f, "merkle"),
            StylusContract::MerkleTestContract => write!(f, "merkle-test-contract"),
            StylusContract::VerifierCore => write!(f, "verifier-core"),
            StylusContract::VerifierSettlement => write!(f, "verifier-settlement"),
            StylusContract::Vkeys => write!(f, "vkeys"),
            StylusContract::TestVkeys => write!(f, "test-vkeys"),
            StylusContract::TransferExecutor => write!(f, "transfer-executor"),
            StylusContract::GasSponsor => write!(f, "gas-sponsor"),
            StylusContract::DummyErc20(_) => write!(f, "dummy-erc20"),
            StylusContract::DummyWeth(_) => write!(f, "dummy-weth"),
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
    /// The verification keys used in matching & settling a trade
    pub match_atomic_vkeys: MatchAtomicVkeys,
    /// The proof linking verification keys used in
    /// matching & settling a trade
    pub match_atomic_linking_vkeys: MatchAtomicLinkingVkeys,
}
