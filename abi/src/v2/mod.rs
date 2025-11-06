use alloy::sol;

#[cfg(feature = "permit2")]
pub mod permit2;

// We use a combined ABI between the darkpool v2, verifier, and vkeys interfaces as the sol macro currently requires all
// types to be present in the same macro invocation.
sol! {
    #[allow(missing_docs, clippy::too_many_arguments)]
    #[sol(rpc)]
    IDarkpoolV2,
    "ICombinedV2.json",
}

#[cfg(feature = "v2-relayer-types")]
pub mod relayer_types;
