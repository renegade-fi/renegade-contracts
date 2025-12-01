//! Conversion for obligation types

use crate::v2::{
    relayer_types::{u128_to_u256, u256_to_u128},
    IDarkpoolV2,
};

use renegade_circuit_types_v2::settlement_obligation::SettlementObligation as CircuitObligation;

impl From<IDarkpoolV2::SettlementObligation> for CircuitObligation {
    fn from(obligation: IDarkpoolV2::SettlementObligation) -> Self {
        Self {
            input_token: obligation.inputToken,
            output_token: obligation.outputToken,
            amount_in: u256_to_u128(obligation.amountIn),
            amount_out: u256_to_u128(obligation.amountOut),
        }
    }
}

impl From<CircuitObligation> for IDarkpoolV2::SettlementObligation {
    fn from(obligation: CircuitObligation) -> Self {
        Self {
            inputToken: obligation.input_token,
            outputToken: obligation.output_token,
            amountIn: u128_to_u256(obligation.amount_in),
            amountOut: u128_to_u256(obligation.amount_out),
        }
    }
}
