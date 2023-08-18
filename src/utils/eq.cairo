use option::OptionTrait;
use traits::Into;
use array::{ArrayTrait, SpanTrait};
use serde::Serde;
use ec::{EcPoint, ec_point_is_zero, ec_point_unwrap, ec_point_non_zero};
use zeroable::{IsZeroResult};

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
        if ec_point_is_zero(*lhs).into() && ec_point_is_zero(*rhs).into() {
            true
        } else if !ec_point_is_zero(*lhs).into() && !ec_point_is_zero(*rhs).into() {
            let (lhs_x, lhs_y) = ec_point_unwrap(ec_point_non_zero(*lhs));
            let (rhs_x, rhs_y) = ec_point_unwrap(ec_point_non_zero(*rhs));
            lhs_x == rhs_x && lhs_y == rhs_y
        } else {
            false
        }
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

