use dojo_test_utils::sequencer::{get_default_test_starknet_config, TestSequencer};
use katana_core::sequencer::SequencerConfig;
use mpc_stark::algebra::scalar::Scalar;
use num_bigint::{BigUint, RandBigInt};
use rand::thread_rng;
use starknet::core::types::FieldElement;
use std::sync::Once;
use tracing::debug;
use tracing_subscriber::{fmt, EnvFilter};

/// Name of env var representing path at which compiled contract artifacts are kept
pub const ARTIFACTS_PATH_ENV_VAR: &str = "ARTIFACTS_PATH";

static TRACING_INIT: Once = Once::new();

pub async fn global_setup() -> TestSequencer {
    // Set up logging
    TRACING_INIT.call_once(|| {
        fmt().with_env_filter(EnvFilter::from_default_env()).init();
    });

    // Start test sequencer
    debug!("Starting test sequencer...");
    TestSequencer::start(
        SequencerConfig::default(),
        get_default_test_starknet_config(),
    )
    .await
}

pub fn global_teardown(sequencer: TestSequencer) {
    debug!("Stopping test sequencer...");
    sequencer.stop().unwrap();
}

pub fn random_felt() -> FieldElement {
    let modulus = BigUint::from_bytes_be(&FieldElement::MAX.to_bytes_be()) + 1_u8;
    let rand_uint = thread_rng().gen_biguint_below(&modulus);
    FieldElement::from_byte_slice_be(&rand_uint.to_bytes_be()).unwrap()
}

pub fn random_scalar_as_felt() -> FieldElement {
    let scalar = Scalar::random(&mut thread_rng());
    // No need to reduce into modulues since the scalar field is smaller than the base field
    FieldElement::from_byte_slice_be(&scalar.to_bytes_be()).unwrap()
}
