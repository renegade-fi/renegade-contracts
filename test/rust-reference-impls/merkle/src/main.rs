use renegade_constants::Scalar;
use renegade_crypto::fields::scalar_to_biguint;
use renegade_crypto::hash::Poseidon2Sponge;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 4 {
        eprintln!("Usage: {} <input> <idx> <sister_leaves>", args[0]);
        std::process::exit(1);
    }

    let input = Scalar::from_decimal_string(&args[1]).unwrap();
    let idx = args[2].parse::<u64>().unwrap();
    let sister_leaves: Vec<Scalar> = args[3]
        .trim_matches(|c| c == '[' || c == ']')
        .split(',')
        .map(|s| Scalar::from_decimal_string(s).unwrap())
        .collect();

    let result = hash_merkle(input, idx, &sister_leaves);
    let res_biguint = scalar_to_biguint(&result);
    let res_hex = format!("{res_biguint:x}");
    println!("RES:0x{}", res_hex);
}

fn hash_merkle(input: Scalar, idx: u64, sister_leaves: &[Scalar]) -> Scalar {
    let mut current = input;
    let mut current_idx = idx;
    let mut sponge = Poseidon2Sponge::new();

    for sister in sister_leaves {
        let inputs = if current_idx % 2 == 0 {
            [current.inner(), sister.inner()]
        } else {
            [sister.inner(), current.inner()]
        };
        current = Scalar::new(sponge.hash(&inputs));
        current_idx /= 2;
    }

    current
}
