use clap::{Parser, Subcommand};
use renegade_constants::Scalar;
use renegade_crypto::fields::scalar_to_biguint;
use renegade_crypto::hash::compute_poseidon_hash;

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

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::MerkleHash(args) => handle_merkle_hash(args),
        Commands::SpongeHash(args) => handle_sponge_hash(args),
    }
}

fn handle_merkle_hash(args: MerkleHashArgs) {
    if args.sister_leaves.len() != TREE_HEIGHT {
        eprintln!(
            "Expected {} sister leaves, got {}",
            TREE_HEIGHT,
            args.sister_leaves.len()
        );
        std::process::exit(1);
    }

    let input = Scalar::from_decimal_string(&args.input).unwrap();

    // Parse sister leaves directly from arguments
    let sister_leaves: Vec<Scalar> = args
        .sister_leaves
        .iter()
        .map(|s| Scalar::from_decimal_string(s).unwrap())
        .collect();

    let results = hash_merkle(args.idx, input, &sister_leaves);

    // Output results as space-separated decimal values
    let result_strings: Vec<String> = results
        .iter()
        .map(|r| scalar_to_biguint(r).to_string())
        .collect();

    println!("RES:{}", result_strings.join(" "));
}

fn handle_sponge_hash(args: SpongeHashArgs) {
    // Parse input values to Scalars
    let inputs: Vec<Scalar> = args
        .inputs
        .iter()
        .map(|s| Scalar::from_decimal_string(s).unwrap())
        .collect();

    let res = compute_poseidon_hash(&inputs);
    let res_hex = format!("{:x}", res.to_biguint());
    println!("RES:0x{res_hex}");
}

/// Hash the input through the Merkle tree using the given sister nodes
///
/// Returns the incremental results at each level, representing the updated values to the insertion path
fn hash_merkle(idx: u64, input: Scalar, sister_leaves: &[Scalar]) -> Vec<Scalar> {
    let mut results = Vec::with_capacity(TREE_HEIGHT);
    let mut current = input;
    let mut current_idx = idx;

    for sister in sister_leaves.iter().copied() {
        // The input is a left-hand node if the index is even at this level
        let inputs = if current_idx % 2 == 0 {
            [current, sister]
        } else {
            [sister, current]
        };

        current = compute_poseidon_hash(&inputs);
        results.push(current);
        current_idx /= 2;
    }

    results
}

#[cfg(test)]
mod tests {
    //! We test the Merkle tree helper above against the reference implementation in Arkworks
    //! for a known reference implementation.
    //!
    //! It is difficult to test the huff contracts against the Arkworks impl because the Arkworks impl
    //! handles deep trees very inefficiently, making a 32-depth tree impossible to run.
    //!
    //! Instead, we opt to test our helper against Arkworks on a shallower tree, thereby testing the
    //! huff implementation only transitively.

    use std::borrow::Borrow;

    use ark_crypto_primitives::{
        crh::{CRHScheme, TwoToOneCRHScheme},
        merkle_tree::{Config, IdentityDigestConverter, MerkleTree},
    };
    use rand::{thread_rng, Rng};
    use renegade_constants::{Scalar, ScalarField};
    use renegade_crypto::hash::compute_poseidon_hash;

    use crate::hash_merkle;

    /// The height of the Merkle tree
    const TEST_TREE_HEIGHT: usize = 10;
    /// The number of leaves in the tree
    const N_LEAVES: usize = 1 << (TEST_TREE_HEIGHT - 1);

    // --- Hash Impls --- //

    struct IdentityHasher;
    impl CRHScheme for IdentityHasher {
        type Input = ScalarField;
        type Output = ScalarField;
        type Parameters = ();

        fn setup<R: Rng>(_: &mut R) -> Result<Self::Parameters, ark_crypto_primitives::Error> {
            Ok(())
        }

        fn evaluate<T: Borrow<Self::Input>>(
            _parameters: &Self::Parameters,
            input: T,
        ) -> Result<Self::Output, ark_crypto_primitives::Error> {
            Ok(*input.borrow())
        }
    }

    /// A dummy hasher to build an arkworks Merkle tree on top of
    struct Poseidon2Hasher;
    impl TwoToOneCRHScheme for Poseidon2Hasher {
        type Input = ScalarField;
        type Output = ScalarField;
        type Parameters = ();

        fn setup<R: Rng>(_: &mut R) -> Result<Self::Parameters, ark_crypto_primitives::Error> {
            Ok(())
        }

        fn evaluate<T: Borrow<Self::Input>>(
            _parameters: &Self::Parameters,
            left_input: T,
            right_input: T,
        ) -> Result<Self::Output, ark_crypto_primitives::Error> {
            let lhs = Scalar::new(*left_input.borrow());
            let rhs = Scalar::new(*right_input.borrow());
            let res = compute_poseidon_hash(&[lhs, rhs]);

            Ok(res.inner())
        }

        fn compress<T: Borrow<Self::Output>>(
            parameters: &Self::Parameters,
            left_input: T,
            right_input: T,
        ) -> Result<Self::Output, ark_crypto_primitives::Error> {
            <Self as TwoToOneCRHScheme>::evaluate(parameters, left_input, right_input)
        }
    }

    struct MerkleConfig {}
    impl Config for MerkleConfig {
        type Leaf = ScalarField;
        type LeafDigest = ScalarField;
        type InnerDigest = ScalarField;

        type LeafHash = IdentityHasher;
        type TwoToOneHash = Poseidon2Hasher;
        type LeafInnerDigestConverter = IdentityDigestConverter<ScalarField>;
    }

    /// Build an arkworks tree and fill it with random values
    fn build_arkworks_tree() -> MerkleTree<MerkleConfig> {
        let mut rng = thread_rng();

        let mut tree = MerkleTree::<MerkleConfig>::blank(&(), &(), TEST_TREE_HEIGHT).unwrap();
        for i in 0..N_LEAVES {
            let leaf = Scalar::random(&mut rng);
            tree.update(i, &leaf.inner()).unwrap();
        }

        tree
    }

    /// Test the Merkle helper against an arkworks tree
    #[test]
    fn test_merkle_tree() {
        // Build an arkworks tree and fill it with random values
        let mut rng = thread_rng();
        let mut tree = build_arkworks_tree();

        // Choose a random index to update into
        let idx = rng.gen_range(0..N_LEAVES);
        let input = Scalar::random(&mut rng);

        // Get a sibling path for the input
        let path = tree.generate_proof(idx).unwrap();
        let mut sister_scalars = vec![Scalar::new(path.leaf_sibling_hash)];
        sister_scalars.extend(path.auth_path.into_iter().rev().map(Scalar::new));

        // Get the updated path
        let res = hash_merkle(idx as u64, input, &sister_scalars);
        let new_root = res.last().unwrap();

        // Update the tree with the input
        tree.update(idx, &input.inner()).unwrap();
        assert_eq!(tree.root(), new_root.inner());
    }
}
