use serde::Serde;
use ec::ec_point_new;
use ec::ec_point_unwrap;
use ec::ec_point_non_zero;


impl EcPointSerde of Serde<EcPoint> {
    fn serialize(self: @EcPoint, ref output: Array<felt252>) {
        let (x, y) = ec_point_unwrap(ec_point_non_zero(*self));
        x.serialize(ref output);
        y.serialize(ref output);
    }

    fn deserialize(ref serialized: Span<felt252>) -> Option<EcPoint> {
        let x: felt252 = Serde::deserialize(ref serialized)?;
        let y: felt252 = Serde::deserialize(ref serialized)?;
        Option::Some(ec_point_new(x, y))
    }
}
