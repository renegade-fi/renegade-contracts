use option::OptionTrait;
use array::{ArrayTrait, SpanTrait};


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

/// Compute the dot product of two vectors
fn dot_product(mut a: Span<felt252>, mut b: Span<felt252>) -> felt252 {
    assert(a.len() == b.len(), 'vectors must be of equal length');
    let mut result = 0;
    loop {
        match a.pop_front() {
            Option::Some(a_i) => {
                let b_i = b.pop_front().unwrap();
                result += *a_i * *b_i;
            },
            Option::None(_) => {
                break;
            },
        };
    };
    result
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

// FORKED FROM ALEXANDRIA, MADE COMPATIBLE W/ V2.0.0-RC2:
fn fast_power(mut base: u128, mut power: u128, modulus: u128) -> u128 {
    // Return invalid input error
    if base == 0 {
        panic_with_felt252('II')
    }

    if modulus == 1 {
        return 0;
    }

    let mut base: u256 = u256 { low: base, high: 0 };
    let modulus: u256 = u256 { low: modulus, high: 0 };
    let mut result: u256 = u256 { low: 1, high: 0 };

    let res = loop {
        if power == 0 {
            break result;
        }

        if power % 2 != 0 {
            result = (result * base) % modulus;
        }

        base = (base * base) % modulus;
        power = power / 2;
    };

    let u256{low: low, high: high } = res;

    if high != 0 {
        panic_with_felt252('value cant be larger than u128')
    }

    return low;
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
