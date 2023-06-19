use serde::Serde;
use zeroable::{IsZeroResult, Zeroable};
use ec::{ec_point_new, ec_point_unwrap, ec_point_is_zero, ec_point_non_zero, ec_point_zero};


impl EcPointSerde of Serde<EcPoint> {
    fn serialize(self: @EcPoint, ref output: Array<felt252>) {
        match ec_point_is_zero(*self) {
            IsZeroResult::Zero(()) => {
                // (0, 0) is not an actual point on the STARK curve,
                // so this is safe
                0.serialize(ref output);
                0.serialize(ref output);
            },
            IsZeroResult::NonZero(point) => {
                let (x, y) = ec_point_unwrap(ec_point_non_zero(*self));
                x.serialize(ref output);
                y.serialize(ref output);
            }
        }
    }

    fn deserialize(ref serialized: Span<felt252>) -> Option<EcPoint> {
        let x: felt252 = Serde::deserialize(ref serialized)?;
        let y: felt252 = Serde::deserialize(ref serialized)?;
        if x.is_zero() && y.is_zero() {
            return Option::Some(ec_point_zero());
        }
        Option::Some(ec_point_new(x, y))
    }
}
