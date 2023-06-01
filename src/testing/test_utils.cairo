use option::OptionTrait;
use array::ArrayTrait;

fn serialized_element<T, impl TSerde: serde::Serde::<T>>(value: T) -> Span::<felt252> {
    let mut arr = ArrayTrait::new();
    serde::Serde::serialize(ref arr, value);
    arr.span()
}

fn single_deserialize<T, impl TSerde: serde::Serde::<T>>(ref data: Span::<felt252>) -> T {
    serde::Serde::deserialize(ref data).expect('missing data')
}
