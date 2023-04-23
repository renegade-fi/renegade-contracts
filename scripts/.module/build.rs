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
extern crate nile_rs;
use nile_rs::nre::NileRuntimeEnvironment;

#[tokio::main]
async fn main() {
    let nre = NileRuntimeEnvironment::new("<network>").unwrap();
    let mut devnet = utils::spawn_devnet().await;
    match run(nre).await {
        Ok(_) => {}
        Err(e) => {
            eprintln!("An error occurred: {}", e);
        }
    }
    println!("killing devnet");
    devnet.kill().unwrap();
}
"#
            .replace("<network>", &network),
    )
    .unwrap();
}
