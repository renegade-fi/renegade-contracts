//! Defines arguments passed to each test

use std::{path::PathBuf, str::FromStr};

use alloy::{
    primitives::{Address, U256},
    providers::Provider,
    signers::local::PrivateKeySigner,
};
use eyre::Result;

use crate::{
    util::{
        darkpool::{create_darkpool_client, Darkpool},
        deployments::{read_deployment, DARKPOOL_PROXY_DEPLOYMENT_KEY},
        erc20::{ERC20Mock, ERC20},
    },
    CliArgs,
};

/// The CLI arguments for the integration tests
#[derive(Debug, Clone)]
pub(crate) struct TestArgs {
    /// The path to the deployments.json file
    pub deployments: PathBuf,
    /// A darkpool instance to use for testing
    pub darkpool: Darkpool,
    /// The signer for the wallet
    pub signer: PrivateKeySigner,
    /// The relayer's signer which is used to authorize fee payments
    pub relayer_signer: PrivateKeySigner,
}

impl TestArgs {
    /// Get the chain ID of the test
    pub async fn chain_id(&self) -> Result<u64> {
        let provider = self.darkpool.provider().clone();
        let chain_id = provider.get_chain_id().await?;
        Ok(chain_id)
    }

    /// Get the signer for the wallet
    pub fn signer(&self) -> PrivateKeySigner {
        self.signer.clone()
    }

    // --- Addresses and Contracts --- //

    /// Get the address of the wallet
    pub fn wallet_addr(&self) -> Address {
        self.signer.address()
    }

    /// Get the address of the base token
    pub fn base_addr(&self) -> Result<Address> {
        read_deployment("BaseToken", &self.deployments)
    }

    /// Read the ERC20 for the base token
    pub fn base_token(&self) -> Result<ERC20> {
        let addr = self.base_addr()?;
        self.erc20_from_addr(addr)
    }

    /// Read an ERC20 from an address
    pub fn erc20_from_addr(&self, addr: Address) -> Result<ERC20> {
        let provider = self.darkpool.provider().clone();
        let erc20 = ERC20Mock::new(addr, provider);
        Ok(erc20)
    }

    /// Get the address of the permit2 contract
    pub fn permit2_addr(&self) -> Result<Address> {
        read_deployment("Permit2", &self.deployments)
    }

    /// Get the address of the darkpool contract
    pub fn darkpool_addr(&self) -> Address {
        *self.darkpool.address()
    }

    /// Get the address of the relayer's signer
    pub fn relayer_signer_addr(&self) -> Address {
        self.relayer_signer.address()
    }

    // --- Balances --- //

    /// Get the base balance of the given address
    pub async fn base_balance(&self, addr: Address) -> Result<U256> {
        let erc20 = self.base_token()?;
        let balance = erc20.balanceOf(addr).call().await?;
        Ok(balance)
    }
}

impl From<CliArgs> for TestArgs {
    fn from(cli_args: CliArgs) -> Self {
        let darkpool_addr = read_deployment(DARKPOOL_PROXY_DEPLOYMENT_KEY, &cli_args.deployments)
            .expect("failed to read darkpool address from deployments file");
        let signer = PrivateKeySigner::from_str(&cli_args.pkey).unwrap();
        let darkpool = create_darkpool_client(darkpool_addr, signer.clone(), &cli_args.rpc_url)
            .expect("failed to create darkpool instance");
        let relayer_signer = PrivateKeySigner::random();

        Self {
            deployments: cli_args.deployments,
            darkpool,
            signer,
            relayer_signer,
        }
    }
}
