use traits::{TryInto, Into};
use option::OptionTrait;
use array::{ArrayTrait, SpanTrait};
use keccak::keccak_u256s_le_inputs;
use ec::ec_mul;

use alexandria::data_structures::array_ext::ArrayTraitExt;
use renegade_contracts::verifier::scalar::{Scalar, ScalarSerializable};

use super::constants::{BASE_FIELD_ORDER, SCALAR_FIELD_ORDER, SHIFT_256_FELT, SHIFT_256_SCALAR};


/// Reduces a hash to an element of the scalar field,
/// ensuring an indistinguishable-from-uniform sampling of the field.
fn hash_to_scalar(hash: u256) -> Scalar {
    // We generate another hash to sample  total bytes.
    // We use this to construct a "u512" given by
    // low_u256 + (high_u256 << 256).
    // Reducing this "u512" modulo the STARK scalar field order `r`
    // allows us to get an indistinguishable-from-uniform sampling of the field.
    // This reduction is given by:
    // our_u512 % r = (low_u256 % r) + (high_u256 % r) * 2^256 % r

    let mut data = ArrayTrait::new();
    data.append(hash);
    let high_u256 = keccak_u256s_le_inputs(data.span());

    let low_scalar: Scalar = hash.into(); // low_u256 % r
    let high_scalar: Scalar = high_u256.into(); // high_u256 % r

    low_scalar + (high_scalar * SHIFT_256_SCALAR.into())
}

/// Reduces a hash to an element of the base field,
/// ensuring an indistinguishable-from-uniform sampling of the field.
fn hash_to_felt(hash: u256) -> felt252 {
    // Same idea as `hash_to_scalar`, but using the base field order `q` instead of `r`.

    let mut data = ArrayTrait::new();
    data.append(hash);
    let high_u256 = keccak_u256s_le_inputs(data.span());

    let low_felt = (hash % BASE_FIELD_ORDER).try_into().unwrap(); // low_u256 % q
    let high_felt = (high_u256 % BASE_FIELD_ORDER).try_into().unwrap(); // high_u256 % q

    low_felt + (high_felt * SHIFT_256_FELT)
}


/// Computes Pedersen commitments of the given public inputs using the given generators.
/// We use 1 as the scalar blinding factor for public inputs.
fn commit_public(B: EcPoint, B_blind: EcPoint, mut inputs: Span<Scalar>) -> Array<EcPoint> {
    let mut commitments = ArrayTrait::new();

    loop {
        match inputs.pop_front() {
            Option::Some(input) => {
                // Using 1 as scalar blinding factor => simply add B_blind
                commitments.append(ec_mul(B, (*input).into()) + B_blind);
            },
            Option::None(()) => {
                break;
            },
        };
    };

    commitments
}

fn append_statement_commitments<T, impl TScalarSerializable: ScalarSerializable<T>>(
    B: EcPoint, B_blind: EcPoint, statement: @T, ref witness_commitments: Array<EcPoint>
) {
    let statement_scalars = statement.to_scalars();
    let mut statement_commitments = commit_public(B, B_blind, statement_scalars.span());
    witness_commitments.append_all(ref statement_commitments);
}
