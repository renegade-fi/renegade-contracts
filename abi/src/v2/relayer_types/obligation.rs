//! Conversion for obligation types

#[cfg(feature = "v2-auth-helpers")]
use crate::v2::IDarkpoolV2::{FeeRate, SettlementObligation, SignatureWithNonce};
use crate::v2::{
    relayer_types::{u128_to_u256, u256_to_u128},
    IDarkpoolV2,
};

#[cfg(feature = "v2-auth-helpers")]
use alloy::signers::{local::PrivateKeySigner, Error as SignerError};
use darkpool_types::settlement_obligation::SettlementObligation as CircuitObligation;

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

#[cfg(feature = "v2-auth-helpers")]
impl SettlementObligation {
    /// Create an executor signature for a settlement obligation
    ///
    /// This includes the relayer's fee rate in the signed payload
    pub fn create_executor_signature(
        &self,
        relayer_fee_rate: &FeeRate,
        chain_id: u64,
        signer: &PrivateKeySigner,
    ) -> Result<SignatureWithNonce, SignerError> {
        use alloy::sol_types::SolValue;

        let payload = (relayer_fee_rate.clone(), self.clone()).abi_encode();
        SignatureWithNonce::sign(payload.as_slice(), chain_id, signer)
    }
}
