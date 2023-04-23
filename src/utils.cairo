use zeroable::Zeroable;

// Dalek curve scalar field order:
// 2^252 + 27742317777372353535851937790883648493 = 7237005577332262213973186563042994240857116359379907606001950938285454250989
// Defined here: https://doc.dalek.rs/curve25519_dalek/constants/constant.BASEPOINT_ORDER.html
fn dalek_order() -> u256 {
    u256 {
        low: 27742317777372353535851937790883648493_u128,
        high: 21267647932558653966460912964485513216_u128,
    }
}

// TODO: Once Starknet upgrades to Cairo 1.0.0-alpha.7,
// remove this in favor of the stdlib impl
impl U256Zeroable of Zeroable::<u256> {
    fn zero() -> u256 {
        u256 { low: 0_u128, high: 0_u128 }
    }

    #[inline(always)]
    fn is_zero(self: u256) -> bool {
        self.low == 0_u128 & self.high == 0_u128
    }

    #[inline(always)]
    fn is_non_zero(self: u256) -> bool {
        !self.is_zero()
    }
}
