use eyre::Result;
use tests::{
    statement_serde::utils::{
        assert_valid_commitments_statement, assert_valid_commitments_statement_to_scalars,
        assert_valid_reblind_statement, assert_valid_reblind_statement_to_scalars,
        assert_valid_settle_statement, assert_valid_settle_statement_to_scalars,
        assert_valid_wallet_create_statement, assert_valid_wallet_create_statement_to_scalars,
        assert_valid_wallet_update_statement, assert_valid_wallet_update_statement_to_scalars,
    },
    utils::{global_teardown, setup_sequencer, TestConfig},
};

#[tokio::test]
async fn test_valid_wallet_create_statement_serde() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::StatementSerde).await?;

    assert_valid_wallet_create_statement(&sequencer.account()).await?;

    global_teardown(sequencer);

    Ok(())
}

#[tokio::test]
async fn test_valid_wallet_update_statement_serde() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::StatementSerde).await?;

    assert_valid_wallet_update_statement(&sequencer.account()).await?;

    global_teardown(sequencer);

    Ok(())
}

#[tokio::test]
async fn test_valid_reblind_statement_serde() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::StatementSerde).await?;

    assert_valid_reblind_statement(&sequencer.account()).await?;

    global_teardown(sequencer);

    Ok(())
}

#[tokio::test]
async fn test_valid_commitments_statement_serde() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::StatementSerde).await?;

    assert_valid_commitments_statement(&sequencer.account()).await?;

    global_teardown(sequencer);

    Ok(())
}

#[tokio::test]
async fn test_valid_settle_statement_serde() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::StatementSerde).await?;

    assert_valid_settle_statement(&sequencer.account()).await?;

    global_teardown(sequencer);

    Ok(())
}

#[tokio::test]
async fn test_valid_wallet_create_statement_to_scalars() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::StatementSerde).await?;

    assert_valid_wallet_create_statement_to_scalars(&sequencer.account()).await?;

    global_teardown(sequencer);

    Ok(())
}

#[tokio::test]
async fn test_valid_wallet_update_statement_to_scalars() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::StatementSerde).await?;

    assert_valid_wallet_update_statement_to_scalars(&sequencer.account()).await?;

    global_teardown(sequencer);

    Ok(())
}

#[tokio::test]
async fn test_valid_reblind_statement_to_scalars() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::StatementSerde).await?;

    assert_valid_reblind_statement_to_scalars(&sequencer.account()).await?;

    global_teardown(sequencer);

    Ok(())
}

#[tokio::test]
async fn test_valid_commitments_statement_to_scalars() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::StatementSerde).await?;

    assert_valid_commitments_statement_to_scalars(&sequencer.account()).await?;

    global_teardown(sequencer);

    Ok(())
}

#[tokio::test]
async fn test_valid_settle_statement_to_scalars() -> Result<()> {
    let sequencer = setup_sequencer(TestConfig::StatementSerde).await?;

    assert_valid_settle_statement_to_scalars(&sequencer.account()).await?;

    global_teardown(sequencer);

    Ok(())
}
