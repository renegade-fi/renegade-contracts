use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let script = env::var("NILE_RS_TARGET_SCRIPT_NAME").unwrap();
    let network = env::var("NILE_RS_TARGET_SCRIPT_NETWORK").unwrap();

    let dest_path = Path::new("./src/main.rs");
    let contents = fs::read_to_string(format!("../{}.rs", script)).expect("Script not found.");
    let with_disclosure = [
        "// Auto-generated file. Don't edit directly.\n\n",
        &contents,
    ]
    .concat();

    fs::write(
        dest_path,
        with_disclosure
            + &r#"
pub mod utils;
pub mod merkle;
pub mod nullifier_set;
use tracing::log::{debug, error};
use tracing_subscriber::{EnvFilter, fmt, prelude::*};
use tokio::runtime::Builder;
use std::process::exit;

fn main() {

    let runtime = Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();

    let res = runtime.block_on(async {
        tracing_subscriber::registry()
            .with(fmt::layer())
            .with(EnvFilter::from_env("NILE_LOG"))
            .init();

        let mut devnet = utils::devnet_utils::spawn_devnet().await;
        let res = run().await;
        debug!("Killing devnet...");
        devnet.kill()?;
        res
    });

    match res {
        Ok(_) => exit(0),
        Err(e) => {
            error!("{}", e);
            exit(1)
        }
    }
}
"#
            .replace("<network>", &network),
    )
    .unwrap();
}
