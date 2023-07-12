use traits::TryInto;
use option::OptionTrait;
use array::{ArrayTrait, SpanTrait};

use super::constants::STARK_FIELD_PRIME;


/// Get `num_powers` consecutive powers of `val`, starting from `val^1`
fn get_consecutive_powers(val: felt252, mut num_powers: usize) -> Array<felt252> {
    let mut val_powers = ArrayTrait::new();
    let mut prev_power = 1;
    loop {
        if num_powers == 0 {
            break;
        }

        let curr_power = prev_power * val;
        val_powers.append(curr_power);
        prev_power = curr_power;

        num_powers -= 1;
    };
    val_powers
}

/// Compute the element-wise multiplication of two vectors, i.e.
/// [a[0] * b[0], a[1] * b[1], ..., a[n] * b[n]]
fn elt_wise_mul(mut a: Span<felt252>, mut b: Span<felt252>) -> Array<felt252> {
    assert(a.len() == b.len(), 'vectors must be of equal length');
    let mut result = ArrayTrait::new();
    loop {
        match a.pop_front() {
            Option::Some(a_i) => {
                let b_i = b.pop_front().unwrap();
                result.append(*a_i * *b_i);
            },
            Option::None(_) => {
                break;
            },
        };
    };
    result
}

/// Compute base^exp using binary exponentiation.
/// This is effectively equivalent to getting the binary decomposition of `exp`,
/// computing base^{2^i} for each bit `i` in the decomposition, and multiplying
/// an accumulated result (initialized to 1) by base^{2^i} whenever the i-th bit
/// of the decomposition is set.
fn binary_exp(base: felt252, exp: usize) -> felt252 {
    if exp == 0 {
        1
    } else if exp % 2 == 0 {
        binary_exp(base * base, exp / 2)
    } else {
        base * binary_exp(base * base, (exp - 1) / 2)
    }
}

fn reduce_to_felt(val: u256) -> felt252 {
    (val % STARK_FIELD_PRIME).try_into().unwrap()
}
