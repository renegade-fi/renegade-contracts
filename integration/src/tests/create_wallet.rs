//! Tests for creating a wallet

use eyre::Result;
use itertools::Itertools;
use rand::thread_rng;
use renegade_circuit_types::{
    elgamal::DecryptionKey, fixed_point::FixedPoint,
    native_helpers::compute_wallet_private_share_commitment, SizedWallet,
};
use renegade_circuits::{
    singleprover_prove,
    zk_circuits::{
        test_helpers::{create_wallet_shares_with_blinder_seed, PUBLIC_KEYS},
        valid_wallet_create::{
            SizedValidWalletCreate, SizedValidWalletCreateStatement, SizedValidWalletCreateWitness,
        },
    },
};
use renegade_constants::Scalar;
use test_helpers::integration_test_async;

use crate::{util::wait_for_tx_success, TestArgs};

// ---------
// | Tests |
// ---------

/// Test creating a wallet
async fn test_create_wallet(args: TestArgs) -> Result<()> {
    let darkpool = args.darkpool.clone();

    // Create a proof of `VALID WALLET CREATE`
    let (witness, statement) = create_sized_witness_statement();
    let proof = singleprover_prove::<SizedValidWalletCreate>(witness, statement.clone())?;

    let contract_statement = statement.into();
    let contract_proof = proof.into();
    let pending_tx = darkpool.createWallet(contract_statement, contract_proof);

    // Wait for the transaction receipt and ensure it was successful
    wait_for_tx_success(pending_tx).await
}
integration_test_async!(test_create_wallet);

// -----------
// | Helpers |
// -----------

/// Create a `VALID WALLET CREATE` statement and witness
pub fn create_sized_witness_statement() -> (
    SizedValidWalletCreateWitness,
    SizedValidWalletCreateStatement,
) {
    // Create an empty wallet
    let mut rng = thread_rng();
    let (_, enc) = DecryptionKey::random_pair(&mut rng);
    let mut wallet = SizedWallet {
        balances: create_default_arr(),
        orders: create_default_arr(),
        keys: PUBLIC_KEYS.clone(),
        max_match_fee: FixedPoint::from_f64_round_down(0.0001),
        managing_cluster: enc,
        blinder: Scalar::zero(),
    };

    let blinder_seed = Scalar::random(&mut rng);
    let (private_shares, public_shares) =
        create_wallet_shares_with_blinder_seed(&mut wallet, blinder_seed);
    let private_shares_commitment = compute_wallet_private_share_commitment(&private_shares);

    (
        SizedValidWalletCreateWitness {
            private_wallet_share: private_shares,
            blinder_seed,
        },
        SizedValidWalletCreateStatement {
            private_shares_commitment,
            public_wallet_shares: public_shares,
        },
    )
}

/// Create an array of default values
pub fn create_default_arr<const N: usize, D: Default>() -> [D; N]
where
    [D; N]: Sized,
{
    (0..N)
        .map(|_| D::default())
        .collect_vec()
        .try_into()
        .map_err(|_| "Failed to create default array")
        .unwrap()
}
