use option::OptionTrait;
use array::{ArrayTrait, SpanTrait};


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
