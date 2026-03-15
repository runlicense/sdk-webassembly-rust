use serde::Deserialize;
use sha2::{Digest, Sha256};

mod types;
pub use types::*;

// Internal implementation — not part of the public API.
// These are `pub` only because macros need `$crate::__internal::` access.
#[doc(hidden)]
pub mod __internal;

#[cfg(feature = "wasm")]
pub(crate) use __internal::{console_log, console_warn};

// --- Public macros ---

/// Verify a license by namespace.
///
/// Discovers the license file at `runlicense/<namespace>/license.json` in the
/// consuming crate's root directory. Both the license and the public key
/// (`keys/runlicense.key`) are embedded at compile time.
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
/// // WASM (async):
/// let token = runlicense_sdk_webassembly_rust::verify_license!("acme/image-processor").await?;
///
/// // Non-WASM (sync):
/// runlicense_sdk_webassembly_rust::verify_license!("acme/image-processor")?;
/// ```
#[cfg(feature = "wasm")]
#[macro_export]
macro_rules! verify_license {
    ($namespace:literal) => {{
        $crate::__internal::verify_license_full_with_key(
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/runlicense/",
                $namespace,
                "/license.json"
            )),
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/keys/runlicense.key")).trim(),
            $namespace,
        )
    }};
}

/// Verify a license by namespace (non-WASM path).
///
/// See [`verify_license!`] for full documentation.
#[cfg(not(feature = "wasm"))]
#[macro_export]
macro_rules! verify_license {
    ($namespace:literal) => {{
        $crate::__internal::verify_license_detailed_with_key(
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/runlicense/",
                $namespace,
                "/license.json"
            )),
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/keys/runlicense.key")).trim(),
        )
    }};
}

/// Verify a license from a JSON string directly.
///
/// Use this when you already have the license JSON (e.g., fetched from an API
/// or loaded dynamically). Performs the same verification as [`verify_license!`]
/// but without compile-time file discovery.
///
/// The `namespace` parameter is used to namespace localStorage caching in WASM
/// so that multiple licensed packages do not collide.
///
/// # Example
///
/// ```ignore
/// // WASM (async):
/// let token = runlicense_sdk_webassembly_rust::verify_license_json!(license_json, "acme/image-processor").await?;
///
/// // Non-WASM (sync):
/// runlicense_sdk_webassembly_rust::verify_license_json!(license_json)?;
/// ```
#[cfg(feature = "wasm")]
#[macro_export]
macro_rules! verify_license_json {
    ($license_json:expr, $namespace:expr) => {{
        $crate::__internal::verify_license_full_with_key(
            $license_json,
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/keys/runlicense.key")).trim(),
            $namespace,
        )
    }};
}

/// Verify a license from a JSON string directly (non-WASM path).
///
/// See [`verify_license_json!`] for full documentation.
#[cfg(not(feature = "wasm"))]
#[macro_export]
macro_rules! verify_license_json {
    ($license_json:expr, $namespace:expr) => {{
        $crate::__internal::verify_license_detailed_with_key(
            $license_json,
            include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/keys/runlicense.key")).trim(),
        )
    }};
}

/// Generate a `main()` function for a CLI binary that validates a namespaced license
/// against the public key at `keys/runlicense.key` in the consuming project.
///
/// The consuming project creates `src/bin/validate_license.rs` containing:
///
/// ```ignore
/// runlicense_sdk_webassembly_rust::validate_license_main!("acme/image-processor");
/// ```
///
/// Then runs:
///
/// ```sh
/// cargo run --bin validate_license
/// ```
#[macro_export]
macro_rules! validate_license_main {
    ($namespace:literal) => {
        fn main() {
            let license_json = include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/runlicense/",
                $namespace,
                "/license.json"
            ));

            match $crate::__internal::verify_license_detailed_with_key(
                license_json,
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
#[macro_export]
macro_rules! generate_manifest_main {
    () => {
        fn main() {
            let wasm_path = match ::std::env::args().nth(1) {
                Some(p) => ::std::path::PathBuf::from(p),
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
