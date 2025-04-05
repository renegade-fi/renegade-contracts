//! Integration tests for malleable atomic settlement
use eyre::Result;
use scripts::utils::send_tx;
use test_helpers::integration_test_async;

use crate::{
    utils::{serialize_to_calldata, setup_malleable_match_test},
    TestContext,
};

/// Test a basic malleable match
#[allow(non_snake_case)]
async fn test_malleable_match__basic(ctx: TestContext) -> Result<()> {
    let darkpool = ctx.darkpool_contract();
    let (base_amount, payload) = setup_malleable_match_test(&ctx).await?;

    let receiver = ctx.client.address();
    let tx = darkpool.processMalleableAtomicMatchSettle(
        base_amount,
        receiver,
        serialize_to_calldata(&payload.internal_party_match_payload)?,
        serialize_to_calldata(&payload.valid_malleable_match_settle_atomic_statement)?,
        serialize_to_calldata(&payload.match_atomic_proofs)?,
        serialize_to_calldata(&payload.match_atomic_linking_proofs)?,
    );
    send_tx(tx).await?;

    // TODO: Check the balances of the darkpool, receiver, and fee recipients
    Ok(())
}
integration_test_async!(test_malleable_match__basic);
