use std::path::PathBuf;

fn main() {
    let wasm_path = match std::env::args().nth(1) {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!("Usage: generate_manifest <path/to/app_bg.wasm>");
            std::process::exit(1);
        }
    };

    let wasm_bytes = match std::fs::read(&wasm_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Failed to read {}: {e}", wasm_path.display());
            std::process::exit(1);
        }
    };

    println!(
        "[integrity] Hashing {} ({} bytes)",
        wasm_path.display(),
        wasm_bytes.len()
    );

    let hash = runlicense_sdk_webassembly_rust::compute_wasm_sha256(&wasm_bytes);
    let hex = runlicense_sdk_webassembly_rust::hex_encode_hash(&hash);

    println!("[integrity] SHA-256: {hex}");

    let manifest = format!("{{\"wasm_sha256\":\"{hex}\"}}\n");

    let manifest_path = wasm_path
        .parent()
        .unwrap_or(&PathBuf::from("."))
        .join("wasm_manifest.json");

    match std::fs::write(&manifest_path, &manifest) {
        Ok(()) => println!("[integrity] Wrote manifest to {}", manifest_path.display()),
        Err(e) => {
            eprintln!(
                "[integrity] Failed to write {}: {e}",
                manifest_path.display()
            );
            std::process::exit(1);
        }
    }
}
