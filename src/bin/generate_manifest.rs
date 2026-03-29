use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut wasm_path: Option<PathBuf> = None;
    let mut src_dir: Option<PathBuf> = None;
    let mut _package = "local:module".to_string();
    let mut _world = "module".to_string();
    let mut _interface_name = "api".to_string();
    let mut _wit_output: Option<PathBuf> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--src" => {
                i += 1;
                src_dir = Some(PathBuf::from(&args[i]));
            }
            "--package" => {
                i += 1;
                _package = args[i].clone();
            }
            "--world" => {
                i += 1;
                _world = args[i].clone();
            }
            "--interface" => {
                i += 1;
                _interface_name = args[i].clone();
            }
            "--wit-output" => {
                i += 1;
                _wit_output = Some(PathBuf::from(&args[i]));
            }
            "--help" | "-h" => {
                print_usage();
                std::process::exit(0);
            }
            arg if !arg.starts_with('-') && wasm_path.is_none() => {
                wasm_path = Some(PathBuf::from(arg));
            }
            other => {
                eprintln!("Unknown argument: {other}");
                print_usage();
                std::process::exit(1);
            }
        }
        i += 1;
    }

    let wasm_path = match wasm_path {
        Some(p) => p,
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

    // --- Integrity manifest (always runs) ---

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

    // --- WIT generation (only when --src is provided and tools feature is enabled) ---

    #[cfg(feature = "tools")]
    if let Some(src_dir) = src_dir {
        if !src_dir.exists() {
            eprintln!(
                "[wit] Error: source directory does not exist: {}",
                src_dir.display()
            );
            std::process::exit(1);
        }

        let config = runlicense_sdk_webassembly_rust::wit_gen::WitConfig {
            package: _package,
            world: _world,
            interface_name: _interface_name,
        };

        println!("[wit] Scanning source directory: {}", src_dir.display());

        let doc = match runlicense_sdk_webassembly_rust::wit_gen::generate_wit(
            &wasm_bytes,
            &src_dir,
            config,
        ) {
            Ok(doc) => doc,
            Err(e) => {
                eprintln!("[wit] Error: {e}");
                std::process::exit(1);
            }
        };

        println!("[wit] Found {} exported function(s)", doc.functions.len());

        let wit_content = doc.render();

        let wit_path = _wit_output.unwrap_or_else(|| {
            wasm_path
                .parent()
                .unwrap_or(std::path::Path::new("."))
                .join("module.wit")
        });

        match std::fs::write(&wit_path, &wit_content) {
            Ok(()) => {
                println!("[wit] Wrote WIT file to {}", wit_path.display());
                println!();
                print!("{wit_content}");
            }
            Err(e) => {
                eprintln!("[wit] Failed to write {}: {e}", wit_path.display());
                std::process::exit(1);
            }
        }
    }

    #[cfg(not(feature = "tools"))]
    if src_dir.is_some() {
        eprintln!(
            "[wit] WIT generation requires the 'tools' feature. \
             Rebuild with: cargo run --features tools --bin generate_manifest -- ..."
        );
        std::process::exit(1);
    }
}

fn print_usage() {
    eprintln!(
        "Usage: generate_manifest <path/to/app_bg.wasm> [options]

Generate a WASM integrity manifest (SHA-256 hash) and optionally a WIT
interface file from the binary and Rust source.

Arguments:
  <wasm_path>              Path to compiled .wasm binary (required)

Options:
  --src <dir>              Rust source directory — enables WIT generation
                           (requires 'tools' feature)
  --package <name>         WIT package name (default: local:module)
  --world <name>           WIT world name (default: module)
  --interface <name>       WIT interface name (default: api)
  --wit-output <path>      Output .wit file path (default: alongside wasm as module.wit)
  -h, --help               Show this help message"
    );
}
