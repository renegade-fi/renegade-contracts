use clap::Parser;
use renegade_constants::Scalar;
use renegade_crypto::fields::scalar_to_biguint;
use renegade_crypto::hash::compute_poseidon_hash;

/// The height of the Merkle tree
const TREE_HEIGHT: usize = 32;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Index in the Merkle tree
    idx: u64,

    /// Input value
    input: String,

    /// Sister leaves (32 values required)
    #[arg(num_args = 32)]
    sister_leaves: Vec<String>,
}

fn main() {
    let args = Args::parse();

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

    println!("{}", result_strings.join(" "));
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
