//! Tests for creating a new balance and depositing into it

use eyre::Result;
use renegade_abi::v2::{
    permit2::create_deposit_permit,
    relayer_types::u256_to_u128,
    IDarkpoolV2::{Deposit, DepositAuth, NewBalanceDepositProofBundle},
};
use renegade_circuit_types::{balance::Balance, state_wrapper::StateWrapper};
use renegade_circuits::{
    singleprover_prove,
    test_helpers::check_constraints_satisfied,
    zk_circuits::valid_balance_create::{
        ValidBalanceCreate, ValidBalanceCreateStatement, ValidBalanceCreateWitness,
    },
    zk_gadgets::test_helpers::random_csprng,
};
use renegade_constants::Scalar;
use renegade_crypto::fields::{scalar_to_u256, u256_to_scalar};
use test_helpers::{assert_eq_result, assert_true_result, integration_test_async};

use crate::{
    test_args::TestArgs,
    util::{random_amount, transactions::wait_for_tx_success},
};

/// A basic test that prints a message
async fn test_create_balance(args: TestArgs) -> Result<()> {
    // First, fund the signer with some of the ERC20 to deposit
    let deposit = random_deposit(&args)?;
    fund_signer(&args, &deposit).await?;

    // Build the calldata for the balance creation
    let bundle = create_proof_bundle(&deposit, &args)?;
    let commitment = u256_to_scalar(&bundle.statement.newBalanceCommitment);
    let deposit_auth = build_permit2_signature(commitment, &deposit, &args).await?;

    let my_addr = args.wallet_addr();
    let darkpool_addr = args.darkpool_addr();
    let my_balance_before = args.base_balance(my_addr).await?;
    let darkpool_balance_before = args.base_balance(darkpool_addr).await?;
    let call = args.darkpool.depositNewBalance(deposit_auth, bundle);
    wait_for_tx_success(call).await?;

    let my_balance_after = args.base_balance(my_addr).await?;
    let darkpool_balance_after = args.base_balance(darkpool_addr).await?;

    assert_eq_result!(my_balance_after, my_balance_before - deposit.amount)?;
    assert_eq_result!(
        darkpool_balance_after,
        darkpool_balance_before + deposit.amount
    )?;
    Ok(())
}
integration_test_async!(test_create_balance);

// -----------
// | Helpers |
// -----------

/// Generate a random deposit
fn random_deposit(args: &TestArgs) -> Result<Deposit> {
    Ok(Deposit {
        from: args.wallet_addr(),
        token: args.base_addr()?,
        amount: random_amount(),
    })
}

/// Fund the signer with some of the ERC20 deposit and approve the Permit2 contract to spend the tokens
async fn fund_signer(args: &TestArgs, deposit: &Deposit) -> Result<()> {
    // Fund the signer
    let erc20 = args.base_token()?;
    let mint_tx = erc20.mint(args.wallet_addr(), deposit.amount);
    wait_for_tx_success(mint_tx).await?;

    // Approve Permit2
    let permit2_addr = args.permit2_addr()?;
    let approve_tx = erc20.approve(permit2_addr, deposit.amount);
    wait_for_tx_success(approve_tx).await?;
    Ok(())
}

/// Build a permit2 signature for the deposit
async fn build_permit2_signature(
    new_balance_commitment: Scalar,
    deposit: &Deposit,
    args: &TestArgs,
) -> Result<DepositAuth> {
    // Compute a dummy note commitment for the deposit (random note for testing)
    // In real tests, you may want to compute an actual note, but for now, random is sufficient.
    let commitment = scalar_to_u256(&new_balance_commitment);

    let chain_id = args.chain_id().await?;
    let darkpool = args.darkpool_addr();
    let permit2 = args.permit2_addr()?;
    let signer = &args.signer();

    // Call create_deposit_permit with all required parameters
    let (witness, signature) = create_deposit_permit(
        commitment,
        deposit.clone(),
        chain_id,
        darkpool,
        permit2,
        signer,
    )?;

    let sig_bytes = signature.as_bytes().to_vec();
    Ok(DepositAuth {
        permit2Nonce: witness.nonce,
        permit2Deadline: witness.deadline,
        permit2Signature: sig_bytes.into(),
    })
}

// --- Circuits Helpers --- //

/// Create a proof of the balance creation
fn create_proof_bundle(deposit: &Deposit, args: &TestArgs) -> Result<NewBalanceDepositProofBundle> {
    let (witness, statement) = build_witness_statement(deposit, args)?;

    let valid = check_constraints_satisfied::<ValidBalanceCreate>(&witness, &statement);
    assert_true_result!(valid)?;

    let proof = singleprover_prove::<ValidBalanceCreate>(witness, statement.clone())?;
    let bundle = NewBalanceDepositProofBundle::new(statement, proof);
    Ok(bundle)
}

/// Build a witness and statement for the deposit
fn build_witness_statement(
    deposit: &Deposit,
    args: &TestArgs,
) -> Result<(ValidBalanceCreateWitness, ValidBalanceCreateStatement)> {
    // Build a state object
    let amount_u128 = u256_to_u128(deposit.amount);
    let balance = Balance::new(
        deposit.token,
        args.wallet_addr(),
        args.relayer_signer_addr(),
        args.wallet_addr(),
    )
    .with_amount(amount_u128);

    // Sample stream seeds
    let share_stream = random_csprng();
    let recovery_stream = random_csprng();

    // Encrypt the balance
    let mut initial_state =
        StateWrapper::new(balance.clone(), share_stream.seed, recovery_stream.seed);
    let balance_public_share = initial_state.public_share();
    let recovery_id = initial_state.compute_recovery_id();
    let balance_commitment = initial_state.compute_commitment();

    let witness = ValidBalanceCreateWitness {
        balance,
        initial_share_stream: share_stream,
        initial_recovery_stream: recovery_stream,
    };
    let statement = ValidBalanceCreateStatement {
        deposit: deposit.clone().into(),
        new_balance_share: balance_public_share,
        recovery_id,
        balance_commitment,
    };

    Ok((witness, statement))
}
