use option::OptionTrait;
use array::{ArrayTrait, SpanTrait};
use serde::Serde;
use ec::EcPoint;

use super::serde::EcPointSerde;


impl TupleSize2PartialEq<
    E0, E1, impl E0PartialEq: PartialEq<E0>, impl E1PartialEq: PartialEq<E1>
> of PartialEq<(E0, E1)> {
    fn eq(lhs: @(E0, E1), rhs: @(E0, E1)) -> bool {
        let (lhs1, lhs2) = lhs;
        let (rhs1, rhs2) = rhs;
        lhs1 == rhs1 && lhs2 == rhs2
    }
    fn ne(lhs: @(E0, E1), rhs: @(E0, E1)) -> bool {
        !(rhs == lhs)
    }
}

impl ArrayTPartialEq<T, impl TPartialEq: PartialEq<T>, impl TDrop: Drop<T>> of PartialEq<Array<T>> {
    fn eq(lhs: @Array<T>, rhs: @Array<T>) -> bool {
        let mut lhs_span = Span { snapshot: lhs };
        let mut rhs_span = Span { snapshot: rhs };
        @lhs_span == @rhs_span
    }
    fn ne(lhs: @Array<T>, rhs: @Array<T>) -> bool {
        !(lhs == rhs)
    }
}

impl SpanTPartialEq<T, impl TPartialEq: PartialEq<T>, impl TDrop: Drop<T>> of PartialEq<Span<T>> {
    fn eq(lhs: @Span<T>, rhs: @Span<T>) -> bool {
        let mut lhs_span = *lhs;
        let mut rhs_span = *rhs;
        if lhs_span.len() != rhs_span.len() {
            return false;
        }

        let mut arr_eq = true;
        loop {
            match lhs_span.pop_front() {
                Option::Some(lhs_i) => {
                    let rhs_i = rhs_span.pop_front().unwrap();
                    if lhs_i != rhs_i {
                        arr_eq = false;
                        break;
                    }
                },
                Option::None(_) => {
                    break;
                }
            };
        };

        arr_eq
    }
    fn ne(lhs: @Span<T>, rhs: @Span<T>) -> bool {
        !(lhs == rhs)
    }
}

impl EcPointPartialEq of PartialEq<EcPoint> {
    fn eq(lhs: @EcPoint, rhs: @EcPoint) -> bool {
        // Serializing EcPoint => obtaining x, y coords (felt252s)
        // Comparing equality of felt coords is an appropriate notion of equality for EcPoints
        let mut lhs_ser = ArrayTrait::new();
        lhs.serialize(ref lhs_ser);
        let mut rhs_ser = ArrayTrait::new();
        rhs.serialize(ref rhs_ser);

        lhs_ser == rhs_ser
    }
    fn ne(lhs: @EcPoint, rhs: @EcPoint) -> bool {
        !(lhs == rhs)
    }
}
impl OptionTPartialEq<
    T, impl TPartialEq: PartialEq<T>, impl TCopy: Copy<T>, impl TDrop: Drop<T>
> of PartialEq<Option<T>> {
    fn eq(lhs: @Option<T>, rhs: @Option<T>) -> bool {
        if lhs.is_none() && rhs.is_none() {
            return true;
        }

        if lhs.is_some() && rhs.is_some() {
            return (*lhs).unwrap() == (*rhs).unwrap();
        }

        return false;
    }
    fn ne(lhs: @Option<T>, rhs: @Option<T>) -> bool {
        !(lhs == rhs)
    }
}

