//! Constants that parameterize the Plonk proof system

use core::marker::PhantomData;

use ark_ff::{BigInt, Fp};

use crate::types::ScalarField;

/// Dedicated chain ID for Renegade devnets, for which we allow
/// verification to be disabled.
/// This is the first 6 digits of keccak256("renegade")
pub const DEVNET_CHAINID: u64 = 473474;

/// The number of wire types in the circuit
pub const NUM_WIRE_TYPES: usize = 5;

/// The number of selectors in the circuit
pub const NUM_SELECTORS: usize = 13;

/// The number of linking proofs in a match bundle
pub const NUM_MATCH_LINKING_PROOFS: usize = 4;

/// The number of linking proofs in an atomic match bundle
pub const NUM_ATOMIC_MATCH_LINKING_PROOFS: usize = 2;

/// The transcript has a 64 byte state size to accommodate two hash digests.
pub const TRANSCRIPT_STATE_SIZE: usize = 64;

/// The number of bytes in a hash digest used by the transcript
pub const HASH_OUTPUT_SIZE: usize = 32;

/// The number of bytes of hash output to sample for a challenge
pub const HASH_SAMPLE_BYTES: usize = 48;

/// The number of bytes to represent field elements of the base or scalar fields
/// for the G1 curve group, as well as the base field which is extended for the
/// G2 curve group
pub const NUM_BYTES_FELT: usize = 32;

/// The index at which to split a hash output so that it can be directly
/// converted to a field element.
pub const SPLIT_INDEX: usize = NUM_BYTES_FELT - 1;

/// The number of u64s it takes to represent a field element
pub const NUM_U64S_FELT: usize = 4;

/// The number of bytes it takes to represent a u64
pub const NUM_BYTES_U64: usize = 8;

/// The number of bytes it takes to represent an unsigned 128-bit integer
pub const NUM_BYTES_U128: usize = 16;

/// The number of bytes it takes to represent an unsigned 256-bit integer
pub const NUM_BYTES_U256: usize = 32;

/// The number of scalars it takes to encode a secp256k1 public key
pub const NUM_SCALARS_PK: usize = 4;

/// The number of bytes it takes to represent an Ethereum address
pub const NUM_BYTES_ADDRESS: usize = 20;

/// The number of bytes it takes to represent a secp256k1 ECDSA signature
/// as expected by the Ethereum `ecRecover` precompile.
///
/// Concretely, this is the concatenation of the `r` and `s` values of the
/// signature, and `v`, a 1-byte recovery identifier (whose value is either 27
/// or 28)
pub const NUM_BYTES_SIGNATURE: usize = 65;

/// The number of bits used to represent the fractional part of a real number in
/// the fixed-point representation used in the Renegade darkpool
///
/// That is, a fixed-point representation of a real number `r` is:
///     floor(r * 2^FIXED_POINT_PRECISION_BITS)
pub const FIXED_POINT_PRECISION_BITS: u64 = 63;

/// The height of the Merkle tree
pub const MERKLE_HEIGHT: usize = 32;

/// The height of the Merkle tree used in testing
pub const TEST_MERKLE_HEIGHT: usize = 3;

/// The value of an empty leaf in the Merkle tree,
/// computed as the Keccak-256 hash of the string "renegade",
/// reduced modulo the scalar field order when interpreted as a
/// big-endian unsigned integer
pub const EMPTY_LEAF_VALUE: ScalarField = Fp(
    BigInt([14542100412480080699, 1005430062575839833, 8810205500711505764, 2121377557688093532]),
    PhantomData,
);

/// The selector for the core wallet ops address in the
/// `is_implementation_upgraded` method on the Darkpool test contract
pub const CORE_WALLET_OPS_ADDRESS_SELECTOR: u8 = 0;

/// The selector for the core match settlement address in the
/// `is_implementation_upgraded` method on the Darkpool test contract
pub const CORE_MATCH_SETTLEMENT_ADDRESS_SELECTOR: u8 = 1;

/// The selector for the core atomic match settlement address in the
/// `is_implementation_upgraded` method on the Darkpool test contract
pub const CORE_ATOMIC_MATCH_SETTLEMENT_ADDRESS_SELECTOR: u8 = 2;

/// The selector for the core malleable match settlement address in the
/// `is_implementation_upgraded` method on the Darkpool test contract
pub const CORE_MALLEABLE_MATCH_SETTLEMENT_ADDRESS_SELECTOR: u8 = 3;

/// The selector for the verifier address in the `is_implementation_upgraded`
/// method on the Darkpool test contract
pub const VERIFIER_CORE_ADDRESS_SELECTOR: u8 = 4;

/// The selector for the verifier settlement address in the
/// `is_implementation_upgraded` method on the Darkpool test contract
pub const VERIFIER_SETTLEMENT_ADDRESS_SELECTOR: u8 = 5;

/// The selector for the vkeys address in the `is_implementation_upgraded`
/// method on the Darkpool test contract
pub const VKEYS_ADDRESS_SELECTOR: u8 = 6;

/// The selector for the merkle address in the `is_implementation_upgraded`
/// method on the Darkpool test contract
pub const MERKLE_ADDRESS_SELECTOR: u8 = 7;

/// The selector for the transfer executor address in the
/// `is_implementation_upgraded` method on the Darkpool test contract
pub const TRANSFER_EXECUTOR_ADDRESS_SELECTOR: u8 = 8;

/// The revert message when failing to convert a
/// u256 to a scalar
pub const SCALAR_CONVERSION_ERROR_MESSAGE: &[u8] = b"scalar conversion error";

/// The revert message when attempting to verify a proof
/// with malformed inputs
pub const INVALID_INPUTS_ERROR_MESSAGE: &[u8] = b"invalid inputs";

/// The revert message when an EC arithmetic backend
/// operation fails
pub const ARITHMETIC_BACKEND_ERROR_MESSAGE: &[u8] = b"arithmetic backend error";

/// The EIP-712 type string used for deposit witness data via
/// `permitWitnessTransferFrom`.
///
/// For more details see: https://docs.uniswap.org/contracts/permit2/reference/signature-transfer#single-permitwitnesstransferfrom
pub const DEPOSIT_WITNESS_TYPE_STRING: &str = "DepositWitness witness)DepositWitness(uint256[4] pkRoot)TokenPermissions(address token,uint256 amount)";
