//! Wallet update tests

use test_helpers::integration_test_async;

use crate::TestArgs;

/// Update a wallet by placing an order
#[allow(non_snake_case)]
async fn test_update_wallet__place_order(args: TestArgs) -> Result<(), eyre::Error> {
    let wallet = args.wallet.clone();
    let darkpool = args.darkpool.clone();

    Ok(())
}
integration_test_async!(test_update_wallet__place_order);
