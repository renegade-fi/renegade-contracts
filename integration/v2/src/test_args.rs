//! Defines arguments passed to each test

use std::path::PathBuf;

use clap::Parser;

use crate::CliArgs;

/// The CLI arguments for the integration tests
#[derive(Debug, Clone, Parser)]
pub struct TestArgs {
    /// The path to the deployments.json file
    #[clap(long, default_value = "../deployments.devnet.json")]
    deployments: PathBuf,
}

impl From<CliArgs> for TestArgs {
    fn from(cli_args: CliArgs) -> Self {
        Self {
            deployments: cli_args.deployments,
        }
    }
}
