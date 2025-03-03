pub mod merkle_hash;
pub mod merkle_insert;
pub mod sponge_hash;
pub mod util;

use clap::{Parser, Subcommand};

/// The height of the Merkle tree
const TREE_HEIGHT: usize = 32;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Hash through a Merkle tree
    MerkleHash(MerkleHashArgs),

    /// Hash inputs using a Poseidon sponge
    SpongeHash(SpongeHashArgs),

    /// Compute the root after inserting elements into a Merkle tree sequentially
    InsertRoot(InsertRootArgs),
}

#[derive(Parser)]
struct MerkleHashArgs {
    /// Index in the Merkle tree
    idx: u64,

    /// Input value
    input: String,

    /// Sister leaves (32 values required)
    #[arg(num_args = 32)]
    sister_leaves: Vec<String>,
}

#[derive(Parser)]
struct SpongeHashArgs {
    /// Input values to hash
    #[arg(required = true)]
    inputs: Vec<String>,
}

#[derive(Parser)]
struct InsertRootArgs {
    /// Input values to insert sequentially (starting from index 0)
    #[arg(required = true)]
    inputs: Vec<String>,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::MerkleHash(args) => merkle_hash::handle_merkle_hash(args),
        Commands::SpongeHash(args) => sponge_hash::handle_sponge_hash(args),
        Commands::InsertRoot(args) => merkle_insert::handle_insert_root(args),
    }
}
