use option::OptionTrait;
use array::ArrayTrait;
use array::SpanTrait;
use dict::Felt252DictTrait;
use nullable::FromNullableResult;
use box::BoxTrait;

use renegade_contracts::verifier::scalar::Scalar;


/// A trait for creating arbitrarily nested Span types, e.g. for matrices
trait DeepSpan<T, TSpan> {
    fn deep_span(self: @Array<T>) -> Span<TSpan>;
}

impl ArrayDeepSpanImpl<T> of DeepSpan<T, T> {
    fn deep_span(self: @Array<T>) -> Span<T> {
        self.span()
    }
}

impl NestedArrayDeepSpanImpl<T> of DeepSpan<Array<T>, Span<T>> {
    fn deep_span(self: @Array<Array<T>>) -> Span<Span<T>> {
        let mut spans = ArrayTrait::new();
        let mut top_span = self.span();
        loop {
            match top_span.pop_front() {
                Option::Some(span) => spans.append(span.deep_span()),
                Option::None(()) => {
                    break;
                },
            };
        };
        spans.span()
    }
}

/// Append `val` to `arr` `len` times
fn tile_arr<T, impl TDrop: Drop<T>, impl TCopy: Copy<T>>(
    ref arr: Array::<T>, val: T, mut len: usize
) {
    loop {
        if len == 0 {
            break;
        } else {
            arr.append(val);
            len -= 1;
        };
    }
}

/// Extend `arr1` with the contents of `arr2`, consuming it in the process.
/// This allows us to avoid requiring a `Copy` trait for `T`.
fn extend<T, impl TDrop: Drop<T>>(ref arr1: Array::<T>, mut arr2: Array::<T>) {
    match arr2.pop_front() {
        Option::Some(v) => {
            arr1.append(v);
            extend(ref arr1, arr2);
        },
        Option::None(()) => (),
    }
}

fn get_scalar_or_zero(ref dict: Felt252Dict<Nullable<Scalar>>, key: felt252) -> Scalar {
    let val = dict.get(key);
    match match_nullable(val) {
        FromNullableResult::Null(()) => Zeroable::zero(),
        FromNullableResult::NotNull(val) => val.unbox(),
    }
}

fn insert_scalar(ref dict: Felt252Dict<Nullable<Scalar>>, key: felt252, scalar: Scalar) {
    dict.insert(key, nullable_from_box(BoxTrait::new(scalar)));
}
