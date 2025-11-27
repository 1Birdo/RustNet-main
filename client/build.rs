use std::fs;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=bot_token.txt");
    println!("cargo:rerun-if-changed=c2_address.txt");

    let token_path = Path::new("bot_token.txt");
    if token_path.exists() {
        let token = fs::read_to_string(token_path).expect("Failed to read bot_token.txt");
        println!("cargo:rustc-env=BOT_TOKEN={}", token.trim());
    } else {
        println!("cargo:warning=bot_token.txt not found. Using default/empty token.");
        println!("cargo:rustc-env=BOT_TOKEN=default_token_placeholder");
    }

    let c2_path = Path::new("c2_address.txt");
    if c2_path.exists() {
        let c2 = fs::read_to_string(c2_path).expect("Failed to read c2_address.txt");
        println!("cargo:rustc-env=C2_ADDRESS={}", c2.trim());
    } else {
        println!("cargo:warning=c2_address.txt not found. Using default.");
        println!("cargo:rustc-env=C2_ADDRESS=127.0.0.1:7002");
    }
}
