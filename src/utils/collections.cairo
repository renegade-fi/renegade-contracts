use option::OptionTrait;
use array::ArrayTrait;
use array::SpanTrait;


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

fn fill_felt_arr(ref arr: Array::<felt252>, val: felt252, mut len: usize) {
    loop {
        if len == 0 {
            break;
        } else {
            arr.append(val);
            len -= 1;
        };
    }
}

fn extend<T, impl TDrop: Drop<T>>(ref arr1: Array::<T>, mut arr2: Array::<T>) {
    match arr2.pop_front() {
        Option::Some(v) => {
            arr1.append(v);
            extend(ref arr1, arr2);
        },
        Option::None(()) => (),
    }
}

// FORKED FROM ALEXANDRIA, MADE COMPATIBLE W/ V2.0.0-RC2:
#[generate_trait]
impl ArrayImpl<T, impl TDrop: Drop<T>> of ArrayTraitExt<T> {
    fn append_all(ref self: Array<T>, ref arr: Array<T>) {
        match arr.pop_front() {
            Option::Some(v) => {
                self.append(v);
                self.append_all(ref arr);
            },
            Option::None(()) => (),
        }
    }
}
