use serde::Deserialize;
use sha2::{Digest, Sha256};

mod types;
pub use types::*;

// Internal implementation — not part of the public API.
// These are `pub` only because macros need `$crate::__internal::` access.
#[doc(hidden)]
pub mod __internal;

#[cfg(feature = "tools")]
pub mod wit_gen;

#[cfg(feature = "wasm")]
pub(crate) use __internal::{console_log, console_warn};

// --- Public macros ---

/// Verify a license passed at runtime.
///
/// The license JSON is provided at runtime (typically passed from JavaScript),
/// while the public key (`keys/runlicense.key`) is embedded at compile time.
/// localStorage caching is automatically namespaced by `product_id` from the
/// license payload, so multiple licensed WASM modules coexist without collision.
///
/// **In WASM** (with the `wasm` feature): performs full verification including
/// signature, status/expiry, domain authorization, and phone-home validation.
/// Returns `Result<ValidationToken, LicenseVerificationError>` and must be `.await`ed.
///
/// **Outside WASM**: performs signature, status/expiry checks (no domain or phone-home).
/// Returns `Result<(), LicenseVerificationError>`.
///
/// # Example
///
/// ```ignore
/// // WASM (async) — license_json is passed from JavaScript at runtime:
/// let token = verify_license!(license_json).await?;
///
/// // Non-WASM (sync):
/// verify_license!(license_json)?;
/// ```
#[cfg(feature = "wasm")]
#[macro_export]
macro_rules! verify_license {
    ($license_json:expr) => {{
        $crate::__internal::verify_license_full_with_key(
            $license_json,
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/keys/runlicense.key")).trim(),
        )
    }};
}

/// Verify a license (non-WASM path).
///
/// See [`verify_license!`] for full documentation.
#[cfg(not(feature = "wasm"))]
#[macro_export]
macro_rules! verify_license {
    ($license_json:expr) => {{
        $crate::__internal::verify_license_detailed_with_key(
            $license_json,
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/keys/runlicense.key")).trim(),
        )
    }};
}

/// Generate a `main()` function for a CLI binary that validates a license JSON
/// string against the public key at `keys/runlicense.key` in the consuming project.
///
/// ```ignore
/// runlicense_sdk_webassembly_rust::validate_license_main!();
/// ```
///
/// Then runs:
///
/// ```sh
/// cargo run --bin validate_license -- '{"payload":"...","signature":"..."}'
/// ```
#[macro_export]
macro_rules! validate_license_main {
    () => {
        fn main() {
            let license_json = match ::std::env::args().nth(1) {
                Some(json) => json,
                None => {
                    eprintln!("Usage: validate_license '<license_json>'");
                    ::std::process::exit(1);
                }
            };

            match $crate::__internal::verify_license_detailed_with_key(
                license_json.as_str(),
                include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/keys/runlicense.key")).trim(),
            ) {
                Ok(()) => {
                    println!("License is valid.");
                }
                Err(e) => {
                    eprintln!("License invalid: {e}");
                    ::std::process::exit(1);
                }
            }
        }
    };
}

/// Generate a `main()` function for a CLI binary that computes the SHA-256
/// hash of a `.wasm` file and writes a `wasm_manifest.json` alongside it.
///
/// The consuming project creates `src/bin/generate_manifest.rs` containing:
///
/// ```ignore
/// runlicense_sdk_webassembly_rust::generate_manifest_main!();
/// ```
///
/// Then runs after building WASM:
///
/// ```sh
/// cargo run --bin generate_manifest -- pkg/app_bg.wasm
/// ```
///
/// With WIT generation (requires `tools` feature):
///
/// ```sh
/// cargo run --features tools --bin generate_manifest -- pkg/app_bg.wasm --src src --package mycompany:my-module
/// ```
#[macro_export]
macro_rules! generate_manifest_main {
    () => {
        fn main() {
            let args: Vec<String> = ::std::env::args().collect();

            let mut wasm_path: Option<::std::path::PathBuf> = None;
            let mut src_dir: Option<::std::path::PathBuf> = None;
            let mut package = "local:module".to_string();
            let mut world = "module".to_string();
            let mut interface_name = "api".to_string();
            let mut wit_output: Option<::std::path::PathBuf> = None;

            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--src" => {
                        i += 1;
                        src_dir = Some(::std::path::PathBuf::from(&args[i]));
                    }
                    "--package" => {
                        i += 1;
                        package = args[i].clone();
                    }
                    "--world" => {
                        i += 1;
                        world = args[i].clone();
                    }
                    "--interface" => {
                        i += 1;
                        interface_name = args[i].clone();
                    }
                    "--wit-output" => {
                        i += 1;
                        wit_output = Some(::std::path::PathBuf::from(&args[i]));
                    }
                    "--help" | "-h" => {
                        eprintln!(
                            "Usage: generate_manifest <path/to/app_bg.wasm> [options]\n\
                             \n\
                             Options:\n\
                             \x20 --src <dir>          Rust source directory (enables WIT generation)\n\
                             \x20 --package <name>     WIT package name (default: local:module)\n\
                             \x20 --world <name>       WIT world name (default: module)\n\
                             \x20 --interface <name>   WIT interface name (default: api)\n\
                             \x20 --wit-output <path>  Output .wit file path"
                        );
                        ::std::process::exit(0);
                    }
                    arg if !arg.starts_with('-') && wasm_path.is_none() => {
                        wasm_path = Some(::std::path::PathBuf::from(arg));
                    }
                    other => {
                        eprintln!("Unknown argument: {other}");
                        ::std::process::exit(1);
                    }
                }
                i += 1;
            }

            let wasm_path = match wasm_path {
                Some(p) => p,
                None => {
                    eprintln!("Usage: generate_manifest <path/to/app_bg.wasm>");
                    ::std::process::exit(1);
                }
            };

            let wasm_bytes = match ::std::fs::read(&wasm_path) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("[integrity] Failed to read {}: {e}", wasm_path.display());
                    ::std::process::exit(1);
                }
            };

            println!(
                "[integrity] Hashing {} ({} bytes)",
                wasm_path.display(),
                wasm_bytes.len()
            );

            let hash = $crate::compute_wasm_sha256(&wasm_bytes);
            let hex = $crate::hex_encode_hash(&hash);

            println!("[integrity] SHA-256: {hex}");

            let manifest = format!("{{\"wasm_sha256\":\"{hex}\"}}\n");

            let manifest_path = wasm_path
                .parent()
                .unwrap_or(&::std::path::PathBuf::from("."))
                .join("wasm_manifest.json");

            match ::std::fs::write(&manifest_path, &manifest) {
                Ok(()) => println!("[integrity] Wrote manifest to {}", manifest_path.display()),
                Err(e) => {
                    eprintln!(
                        "[integrity] Failed to write {}: {e}",
                        manifest_path.display()
                    );
                    ::std::process::exit(1);
                }
            }

            // WIT generation when --src is provided
            #[cfg(feature = "tools")]
            if let Some(src_dir) = src_dir {
                if !src_dir.exists() {
                    eprintln!(
                        "[wit] Error: source directory does not exist: {}",
                        src_dir.display()
                    );
                    ::std::process::exit(1);
                }

                let config = $crate::wit_gen::WitConfig {
                    package,
                    world,
                    interface_name,
                };

                println!("[wit] Scanning source directory: {}", src_dir.display());

                let doc = match $crate::wit_gen::generate_wit(&wasm_bytes, &src_dir, config) {
                    Ok(doc) => doc,
                    Err(e) => {
                        eprintln!("[wit] Error: {e}");
                        ::std::process::exit(1);
                    }
                };

                println!("[wit] Found {} exported function(s)", doc.functions.len());

                let wit_content = doc.render();

                let wit_path = wit_output.unwrap_or_else(|| {
                    wasm_path
                        .parent()
                        .unwrap_or(::std::path::Path::new("."))
                        .join("module.wit")
                });

                match ::std::fs::write(&wit_path, &wit_content) {
                    Ok(()) => {
                        println!("[wit] Wrote WIT file to {}", wit_path.display());
                        println!();
                        print!("{wit_content}");
                    }
                    Err(e) => {
                        eprintln!("[wit] Failed to write {}: {e}", wit_path.display());
                        ::std::process::exit(1);
                    }
                }
            }

            #[cfg(not(feature = "tools"))]
            if src_dir.is_some() {
                eprintln!(
                    "[wit] WIT generation requires the 'tools' feature. \
                     Rebuild with: cargo run --features tools --bin generate_manifest -- ..."
                );
                ::std::process::exit(1);
            }
        }
    };
}

// --- Public functions ---

/// Compute the SHA-256 hash of raw WASM bytes.
pub fn compute_wasm_sha256(wasm_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(wasm_bytes);
    hasher.finalize().into()
}

/// Verify that WASM bytes match the SHA-256 hash in a manifest JSON string.
///
/// The manifest must be a JSON object with a `wasm_sha256` field containing
/// the lowercase hex-encoded SHA-256 hash of the WASM binary.
pub fn verify_wasm_integrity(wasm_bytes: &[u8], manifest_json: &str) -> Result<(), IntegrityError> {
    #[cfg(feature = "wasm")]
    console_log(&format!(
        "[runlicense] Verifying WASM integrity ({} bytes)",
        wasm_bytes.len()
    ));

    #[derive(Deserialize)]
    struct WasmManifest {
        wasm_sha256: String,
    }

    let manifest: WasmManifest = serde_json::from_str(manifest_json).map_err(|_| {
        #[cfg(feature = "wasm")]
        console_warn("[runlicense] Failed to parse manifest JSON");
        IntegrityError::InvalidManifest
    })?;

    let expected = manifest.wasm_sha256.trim().to_lowercase();
    if expected.is_empty() {
        #[cfg(feature = "wasm")]
        console_warn("[runlicense] Manifest contains empty hash");
        return Err(IntegrityError::InvalidManifest);
    }

    let actual_hash = compute_wasm_sha256(wasm_bytes);
    let actual_hex = hex_encode(&actual_hash);

    #[cfg(feature = "wasm")]
    console_log(&format!("[runlicense] Expected: {expected}"));
    #[cfg(feature = "wasm")]
    console_log(&format!("[runlicense] Actual:   {actual_hex}"));

    if actual_hex != expected {
        #[cfg(feature = "wasm")]
        console_warn("[runlicense] WASM integrity check FAILED — binary has been tampered with");
        return Err(IntegrityError::HashMismatch);
    }

    #[cfg(feature = "wasm")]
    console_log("[runlicense] WASM integrity check passed");
    Ok(())
}

/// Encode a byte slice as a lowercase hex string.
pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        use core::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Encode a byte slice as a lowercase hex string (for use by the generate_manifest binary/macro).
pub fn hex_encode_hash(bytes: &[u8]) -> String {
    hex_encode(bytes)
}

#[cfg(test)]
mod tests;
