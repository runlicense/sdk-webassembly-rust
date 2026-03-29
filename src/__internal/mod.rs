//! Internal implementation details for the RunLicense SDK.
//!
//! **Do not call these functions directly.** Use the [`verify_license!`] macro
//! and [`verify_wasm_integrity`](crate::verify_wasm_integrity) function instead.
//! These are only `pub` because macros need to reference them via `$crate::`.

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;

use crate::{LicensePayload, LicenseVerificationError, ValidationToken, VerificationError};

type HmacSha256 = Hmac<Sha256>;

#[cfg(feature = "wasm")]
mod wasm;

#[cfg(feature = "wasm")]
pub use wasm::verify_license_full_with_key;

#[cfg(feature = "wasm")]
pub(crate) use wasm::get_wasm_hostname;

#[cfg(feature = "wasm")]
pub(crate) fn console_log(msg: &str) {
    web_sys::console::log_1(&msg.into());
}

#[cfg(feature = "wasm")]
pub(crate) fn console_warn(msg: &str) {
    web_sys::console::warn_1(&msg.into());
}

#[derive(Deserialize)]
struct LicenseJson {
    payload: serde_json::Value,
    signature: String,
}

/// HMAC-SHA256 sign a nonce using the base64-encoded public key.
///
/// Returns the hex-encoded signature. The server verifies this by recomputing
/// the same HMAC with its copy of the public key.
pub fn sign_nonce(nonce: &str, public_key_b64: &str) -> Result<String, LicenseVerificationError> {
    let key_bytes = BASE64
        .decode(public_key_b64.trim())
        .map_err(|_| LicenseVerificationError::InvalidPublicKey)?;

    let mut mac = HmacSha256::new_from_slice(&key_bytes)
        .map_err(|_| LicenseVerificationError::InvalidPublicKey)?;
    mac.update(nonce.as_bytes());

    let result = mac.finalize();
    Ok(crate::hex_encode(&result.into_bytes()))
}

/// Verify the Ed25519 signature of a license JSON string.
///
/// Returns the payload string on success.
fn verify_signature(
    license_json: &str,
    public_key_b64: &str,
) -> Result<String, LicenseVerificationError> {
    #[cfg(feature = "wasm")]
    console_log("[runlicense] Verifying license signature...");

    let license: LicenseJson = serde_json::from_str(license_json).map_err(|_| {
        #[cfg(feature = "wasm")]
        console_warn("[runlicense] License verification failed: invalid JSON");
        LicenseVerificationError::InvalidJson
    })?;

    let payload_str = match &license.payload {
        serde_json::Value::String(s) => s.clone(),
        other => serde_json::to_string(other).map_err(|_| LicenseVerificationError::InvalidJson)?,
    };

    let key_bytes = BASE64.decode(public_key_b64.trim()).map_err(|_| {
        #[cfg(feature = "wasm")]
        console_warn("[runlicense] License verification failed: invalid public key");
        LicenseVerificationError::InvalidPublicKey
    })?;
    let key_bytes: [u8; 32] = key_bytes.try_into().map_err(|_| {
        #[cfg(feature = "wasm")]
        console_warn("[runlicense] License verification failed: invalid public key length");
        LicenseVerificationError::InvalidPublicKey
    })?;
    let verifying_key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| {
        #[cfg(feature = "wasm")]
        console_warn("[runlicense] License verification failed: invalid public key bytes");
        LicenseVerificationError::InvalidPublicKey
    })?;

    let sig_bytes = BASE64.decode(&license.signature).map_err(|_| {
        #[cfg(feature = "wasm")]
        console_warn("[runlicense] License verification failed: invalid signature encoding");
        LicenseVerificationError::InvalidSignature
    })?;
    let sig_bytes: [u8; 64] = sig_bytes.try_into().map_err(|_| {
        #[cfg(feature = "wasm")]
        console_warn("[runlicense] License verification failed: invalid signature length");
        LicenseVerificationError::InvalidSignature
    })?;
    let signature = Signature::from_bytes(&sig_bytes);

    verifying_key
        .verify(payload_str.as_bytes(), &signature)
        .map_err(|_| {
            #[cfg(feature = "wasm")]
            console_warn("[runlicense] License verification FAILED: signature mismatch");
            LicenseVerificationError::SignatureMismatch
        })?;

    #[cfg(feature = "wasm")]
    console_log("[runlicense] License signature verified");

    Ok(payload_str)
}

/// Verify license signature and parse the payload.
pub fn parse_license_payload_with_key(
    license_json: &str,
    public_key_b64: &str,
) -> Result<LicensePayload, LicenseVerificationError> {
    let payload_str = verify_signature(license_json, public_key_b64)?;
    serde_json::from_str(&payload_str).map_err(|_| LicenseVerificationError::InvalidJson)
}

/// Check license status, expiry, and domain authorization for a parsed payload.
fn verify_domain_checks(
    payload: &LicensePayload,
    hostname: &str,
) -> Result<(), LicenseVerificationError> {
    if payload.status != "active" {
        #[cfg(feature = "wasm")]
        console_warn(&format!(
            "[runlicense] License status is '{}', not 'active'",
            payload.status
        ));
        return Err(LicenseVerificationError::LicenseNotActive);
    }

    if let Some(ref expiry) = payload.expiry_date
        && is_iso8601_expired(expiry)
    {
        #[cfg(feature = "wasm")]
        console_warn("[runlicense] License has expired");
        return Err(LicenseVerificationError::LicenseExpired);
    }

    if payload.domains.is_empty() {
        #[cfg(feature = "wasm")]
        console_warn("[runlicense] License has no authorized domains configured");
        return Err(LicenseVerificationError::NoDomainsConfigured);
    }

    let hostname_lower = hostname.to_lowercase();
    let matching_domain = payload
        .domains
        .iter()
        .find(|d| d.domain.to_lowercase() == hostname_lower);

    let domain = match matching_domain {
        Some(d) => d,
        None => {
            #[cfg(feature = "wasm")]
            console_warn(&format!(
                "[runlicense] Domain '{hostname}' not in authorized list"
            ));
            return Err(LicenseVerificationError::DomainNotAuthorized);
        }
    };

    if let Some(ref expiry) = domain.expiry_date
        && is_iso8601_expired(expiry)
    {
        #[cfg(feature = "wasm")]
        console_warn(&format!(
            "[runlicense] Domain '{}' authorization has expired",
            domain.domain
        ));
        return Err(LicenseVerificationError::DomainExpired);
    }

    Ok(())
}

/// Verify license signature, status, expiry, and domain (with auto-detected hostname in WASM).
///
/// In non-WASM mode (without `wasm` feature), domain checks are skipped
/// because there is no browser hostname to check against.
pub fn verify_license_detailed_with_key(
    license_json: &str,
    public_key_b64: &str,
) -> Result<(), LicenseVerificationError> {
    let payload_str = verify_signature(license_json, public_key_b64)?;

    let payload = serde_json::from_str::<LicensePayload>(&payload_str).map_err(|_| {
        #[cfg(feature = "wasm")]
        console_warn("[runlicense] License payload does not conform to expected structure");
        LicenseVerificationError::InvalidJson
    })?;

    #[cfg(feature = "wasm")]
    {
        console_log(&format!("[runlicense] License ID: {}", payload.license_id));
        console_log(&format!(
            "[runlicense] License status: '{}'",
            payload.status
        ));
    }

    if payload.status != "active" {
        #[cfg(feature = "wasm")]
        console_warn(&format!(
            "[runlicense] License status is '{}', not 'active'",
            payload.status
        ));
        return Err(LicenseVerificationError::LicenseNotActive);
    }

    if let Some(ref expiry) = payload.expiry_date {
        #[cfg(feature = "wasm")]
        console_log(&format!("[runlicense] License expiry date: {expiry}"));
        if is_iso8601_expired(expiry) {
            #[cfg(feature = "wasm")]
            console_warn("[runlicense] License has expired");
            return Err(LicenseVerificationError::LicenseExpired);
        }
        #[cfg(feature = "wasm")]
        console_log("[runlicense] License expiry check passed");
    } else {
        #[cfg(feature = "wasm")]
        console_log("[runlicense] License has no expiry date (perpetual)");
    }

    #[cfg(feature = "wasm")]
    {
        if let Some(hostname) = get_wasm_hostname() {
            console_log(&format!(
                "[runlicense] Auto-detected hostname: '{hostname}'"
            ));
            console_log(&format!(
                "[runlicense] Authorized domains ({}):",
                payload.domains.len()
            ));
            for d in &payload.domains {
                let expiry = d.expiry_date.as_deref().unwrap_or("none");
                console_log(&format!(
                    "[runlicense]   - {} (expiry: {})",
                    d.domain, expiry
                ));
            }
            verify_domain_checks(&payload, &hostname)?;
            console_log(&format!("[runlicense] Domain '{hostname}' authorized"));
        } else {
            console_warn("[runlicense] Could not detect hostname, skipping domain check");
        }
    }

    Ok(())
}

/// Verify license signature with explicit domain hostname.
pub fn verify_license_domain_with_key(
    license_json: &str,
    public_key_b64: &str,
    hostname: &str,
) -> Result<LicensePayload, LicenseVerificationError> {
    let payload = parse_license_payload_with_key(license_json, public_key_b64)?;
    verify_domain_checks(&payload, hostname)?;
    Ok(payload)
}

/// Boolean wrapper for license verification.
pub fn verify_license_with_key(license_json: &str, public_key_b64: &str) -> bool {
    verify_license_detailed_with_key(license_json, public_key_b64).is_ok()
}

/// Verify the server's validation token.
pub fn verify_validation_token(
    token: &str,
    public_key_b64: &str,
    expected_nonce: &str,
    expected_license_id: &str,
) -> Result<ValidationToken, LicenseVerificationError> {
    #[cfg(feature = "wasm")]
    console_log("[runlicense] Verifying server validation token...");

    let parts: Vec<&str> = token.splitn(2, '.').collect();
    if parts.len() != 2 {
        #[cfg(feature = "wasm")]
        console_warn("[runlicense] Token format invalid — expected 'payload.signature'");
        return Err(LicenseVerificationError::InvalidValidationToken);
    }

    let token_payload_bytes = BASE64.decode(parts[0]).map_err(|_| {
        #[cfg(feature = "wasm")]
        console_warn("[runlicense] Failed to decode token payload from base64");
        LicenseVerificationError::InvalidValidationToken
    })?;

    let token_sig_bytes = BASE64.decode(parts[1]).map_err(|_| {
        #[cfg(feature = "wasm")]
        console_warn("[runlicense] Failed to decode token signature from base64");
        LicenseVerificationError::InvalidValidationToken
    })?;

    let key_bytes = BASE64.decode(public_key_b64.trim()).map_err(|_| {
        #[cfg(feature = "wasm")]
        console_warn("[runlicense] Failed to decode public key for token verification");
        LicenseVerificationError::InvalidPublicKey
    })?;
    let key_bytes: [u8; 32] = key_bytes.try_into().map_err(|_| {
        #[cfg(feature = "wasm")]
        console_warn("[runlicense] Public key wrong length for token verification");
        LicenseVerificationError::InvalidPublicKey
    })?;
    let verifying_key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| {
        #[cfg(feature = "wasm")]
        console_warn("[runlicense] Invalid public key bytes for token verification");
        LicenseVerificationError::InvalidPublicKey
    })?;

    let sig_bytes: [u8; 64] = token_sig_bytes.try_into().map_err(|_| {
        #[cfg(feature = "wasm")]
        console_warn("[runlicense] Token signature wrong length");
        LicenseVerificationError::InvalidValidationToken
    })?;
    let signature = Signature::from_bytes(&sig_bytes);

    verifying_key
        .verify(&token_payload_bytes, &signature)
        .map_err(|_| {
            #[cfg(feature = "wasm")]
            console_warn(
                "[runlicense] Token signature verification FAILED, server may be impersonated",
            );
            LicenseVerificationError::InvalidValidationToken
        })?;

    #[cfg(feature = "wasm")]
    console_log("[runlicense] Token signature verified, server is authentic");

    let token_payload_str = String::from_utf8(token_payload_bytes).map_err(|_| {
        #[cfg(feature = "wasm")]
        console_warn("[runlicense] Token payload is not valid UTF-8");
        LicenseVerificationError::InvalidValidationToken
    })?;

    let token_data: ValidationToken = serde_json::from_str(&token_payload_str).map_err(|_| {
        #[cfg(feature = "wasm")]
        console_warn("[runlicense] Failed to parse token payload JSON");
        LicenseVerificationError::InvalidValidationToken
    })?;

    #[cfg(feature = "wasm")]
    {
        console_log(&format!(
            "[runlicense] Token license_id: {}",
            token_data.license_id
        ));
        console_log(&format!("[runlicense] Token domain: {}", token_data.domain));
        console_log(&format!(
            "[runlicense] Token expires_at: {}",
            token_data.expires_at
        ));
    }

    if token_data.nonce != expected_nonce {
        #[cfg(feature = "wasm")]
        console_warn(&format!(
            "[runlicense] Nonce mismatch — expected '{}', got '{}'. Possible replay attack!",
            expected_nonce, token_data.nonce
        ));
        return Err(LicenseVerificationError::ValidationTokenNonceMismatch);
    }

    #[cfg(feature = "wasm")]
    console_log("[runlicense] Nonce matches — response is fresh");

    if token_data.license_id != expected_license_id {
        #[cfg(feature = "wasm")]
        console_warn(&format!(
            "[runlicense] License ID mismatch — expected '{}', got '{}'",
            expected_license_id, token_data.license_id
        ));
        return Err(LicenseVerificationError::ValidationTokenLicenseMismatch);
    }

    #[cfg(feature = "wasm")]
    console_log("[runlicense] License ID matches");

    if is_iso8601_expired(&token_data.expires_at) {
        #[cfg(feature = "wasm")]
        console_warn("[runlicense] Validation token has expired");
        return Err(LicenseVerificationError::ValidationTokenExpired);
    }

    #[cfg(feature = "wasm")]
    console_log("[runlicense] Validation token is valid and not expired");

    Ok(token_data)
}

// --- Combined license + integrity verification ---

pub fn verify_license_and_integrity_with_key(
    license_json: &str,
    public_key_b64: &str,
    wasm_bytes: &[u8],
    manifest_json: &str,
) -> Result<(), VerificationError> {
    #[cfg(feature = "wasm")]
    console_log("[runlicense] Starting license + integrity verification");

    verify_license_detailed_with_key(license_json, public_key_b64).map_err(|e| {
        #[cfg(feature = "wasm")]
        console_warn(&format!("[runlicense] License check failed: {e}"));
        VerificationError::License(e)
    })?;

    #[cfg(feature = "wasm")]
    console_log("[runlicense] License check passed");

    crate::verify_wasm_integrity(wasm_bytes, manifest_json)?;
    Ok(())
}

// --- Date/time helpers ---

pub(crate) fn is_iso8601_expired(date_str: &str) -> bool {
    let date_part = if date_str.len() >= 10 {
        &date_str[..10]
    } else {
        return false;
    };

    #[cfg(not(target_arch = "wasm32"))]
    let now_secs = {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    };

    #[cfg(all(target_arch = "wasm32", feature = "wasm"))]
    let now_secs = { (js_sys::Date::now() / 1000.0) as u64 };

    #[cfg(all(target_arch = "wasm32", not(feature = "wasm")))]
    let now_secs = { 0u64 };

    if now_secs == 0 {
        #[cfg(feature = "wasm")]
        console_warn(&format!(
            "[runlicense] No time source available — skipping expiry check for date '{date_str}'"
        ));
        return false;
    }

    let today = unix_secs_to_date_string(now_secs);
    date_part < today.as_str()
}

pub(crate) fn unix_secs_to_date_string(secs: u64) -> String {
    let days = (secs / 86400) as i64;

    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    format!("{:04}-{:02}-{:02}", y, m, d)
}
