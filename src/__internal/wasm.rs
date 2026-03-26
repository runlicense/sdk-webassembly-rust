//! WASM-specific browser functionality for the RunLicense SDK.
//!
//! Contains phone-home validation, localStorage caching, auto-renewal,
//! nonce generation, and hostname detection — all require a browser environment.

use serde::Deserialize;

use super::{
    console_log, console_warn, is_iso8601_expired, parse_license_payload_with_key, sign_nonce,
    verify_validation_token,
};
use crate::{LicenseVerificationError, ValidationToken};

/// Get the current hostname from `window.location` in a WASM environment.
pub(crate) fn get_wasm_hostname() -> Option<String> {
    let window = web_sys::window()?;
    let hostname = window.location().hostname().ok()?;
    if hostname.is_empty() {
        None
    } else {
        Some(hostname)
    }
}

/// Generate a cryptographically random nonce using the Web Crypto API.
///
/// Panics if `window.crypto.getRandomValues()` is not available — this
/// indicates an environment too old to provide secure randomness.
fn generate_nonce() -> String {
    let array = js_sys::Uint8Array::new_with_length(16);
    let crypto = web_sys::window()
        .expect("window object required for nonce generation")
        .crypto()
        .expect("Web Crypto API required for secure nonce generation");
    crypto
        .get_random_values_with_array_buffer_view(&array)
        .expect("getRandomValues failed");
    let bytes: Vec<u8> = array.to_vec();
    crate::hex_encode(&bytes)
}

// --- localStorage cache helpers ---

fn get_local_storage() -> Option<web_sys::Storage> {
    web_sys::window()?.local_storage().ok()?
}

fn cache_key_token(namespace: &str) -> String {
    format!("runlicense/{namespace}/cached_token")
}

fn cache_key_raw(namespace: &str) -> String {
    format!("runlicense/{namespace}/cached_token_raw")
}

fn cache_token(namespace: &str, raw_token: &str, token_data: &ValidationToken) {
    if let Some(storage) = get_local_storage() {
        if let Ok(json) = serde_json::to_string(token_data) {
            let _ = storage.set_item(&cache_key_token(namespace), &json);
            let _ = storage.set_item(&cache_key_raw(namespace), raw_token);
            console_log("[runlicense]   Cached validation token in localStorage");
        }
    } else {
        console_warn("[runlicense]   localStorage not available — token not cached");
    }
}

fn load_cached_token(namespace: &str) -> Option<ValidationToken> {
    let storage = get_local_storage()?;
    let json = storage.get_item(&cache_key_token(namespace)).ok()??;
    let token: ValidationToken = serde_json::from_str(&json).ok()?;
    if is_iso8601_expired(&token.expires_at) {
        console_log("[runlicense]   Cached token found but expired");
        let _ = storage.remove_item(&cache_key_token(namespace));
        let _ = storage.remove_item(&cache_key_raw(namespace));
        None
    } else {
        console_log(&format!(
            "[runlicense]   Cached token found, valid until {}",
            token.expires_at
        ));
        Some(token)
    }
}

fn clear_cached_token(namespace: &str) {
    if let Some(storage) = get_local_storage() {
        let _ = storage.remove_item(&cache_key_token(namespace));
        let _ = storage.remove_item(&cache_key_raw(namespace));
        console_log("[runlicense]   Cleared cached token from localStorage");
    }
}

// --- Auto-renewal ---

fn schedule_renewal(
    namespace: String,
    activation_url: String,
    public_key: String,
    license_id: String,
    ttl_secs: u64,
) {
    use std::cell::RefCell;
    use std::rc::Rc;
    use wasm_bindgen::JsCast;
    use wasm_bindgen::closure::Closure;

    let renewal_ms = (ttl_secs as f64 * 0.8 * 1000.0) as i32;
    console_log(&format!(
        "[runlicense] Auto-renewal scheduled in {}s (TTL: {}s)",
        renewal_ms / 1000,
        ttl_secs
    ));

    // Use Rc<RefCell<Option<Closure>>> so the closure can drop itself after firing,
    // avoiding the memory leak caused by Closure::forget().
    let closure_holder: Rc<RefCell<Option<Closure<dyn FnMut()>>>> = Rc::new(RefCell::new(None));
    let closure_holder_clone = closure_holder.clone();

    let closure = Closure::once(move || {
        // Drop the closure reference so its memory is reclaimed.
        let _ = closure_holder_clone.borrow_mut().take();

        wasm_bindgen_futures::spawn_local(async move {
            console_log("[runlicense] ──────────────────────────────────────────");
            console_log("[runlicense] Auto-renewal: phoning home...");
            console_log("[runlicense] ──────────────────────────────────────────");

            let nonce = generate_nonce();
            match do_phone_home(&activation_url, &nonce, &public_key, &license_id).await {
                Ok((token_data, raw_token)) => {
                    cache_token(&namespace, &raw_token, &token_data);
                    console_log("[runlicense] Auto-renewal: success — token refreshed");
                    schedule_renewal(namespace, activation_url, public_key, license_id, ttl_secs);
                }
                Err(LicenseVerificationError::ServerRejected(ref msg)) => {
                    console_warn(&format!(
                        "[runlicense] Auto-renewal: server rejected — {msg}"
                    ));
                    console_warn(
                        "[runlicense] LICENSE REVOKED — cached token cleared, next activation will fail",
                    );
                    clear_cached_token(&namespace);
                }
                Err(LicenseVerificationError::InvalidValidationToken)
                | Err(LicenseVerificationError::ValidationTokenNonceMismatch)
                | Err(LicenseVerificationError::ValidationTokenLicenseMismatch) => {
                    console_warn(
                        "[runlicense] Auto-renewal: token verification failed — possible tampering",
                    );
                    console_warn("[runlicense] Cached token cleared — next activation will fail");
                    clear_cached_token(&namespace);
                }
                Err(e) => {
                    console_warn(&format!("[runlicense] Auto-renewal: network error — {e}"));
                    console_log("[runlicense] Auto-renewal: retrying in 30s...");
                    schedule_renewal(namespace, activation_url, public_key, license_id, 30);
                }
            }
        });
    });

    if let Some(window) = web_sys::window() {
        let _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(
            closure.as_ref().unchecked_ref(),
            renewal_ms,
        );
        *closure_holder.borrow_mut() = Some(closure);
    }
}

// --- Phone home ---

async fn do_phone_home(
    activation_url: &str,
    nonce: &str,
    public_key_b64: &str,
    expected_license_id: &str,
) -> Result<(ValidationToken, String), LicenseVerificationError> {
    use wasm_bindgen::JsCast;
    use wasm_bindgen::JsValue;
    use wasm_bindgen_futures::JsFuture;

    let nonce_signature = sign_nonce(nonce, public_key_b64)?;
    let body = serde_json::json!({
        "nonce": nonce,
        "nonce_signature": nonce_signature,
    })
    .to_string();
    console_log(&format!("[runlicense]   POST {activation_url}"));

    let opts = web_sys::RequestInit::new();
    opts.set_method("POST");
    opts.set_body(&JsValue::from_str(&body));

    let headers = web_sys::Headers::new().map_err(|_| {
        LicenseVerificationError::PhoneHomeFailed("failed to create headers".into())
    })?;
    let _ = headers.set("Content-Type", "application/json");
    opts.set_headers(&headers);

    let request = web_sys::Request::new_with_str_and_init(activation_url, &opts).map_err(|e| {
        let msg = format!("{:?}", e);
        console_warn(&format!(
            "[runlicense] Failed to create fetch request: {msg}"
        ));
        LicenseVerificationError::PhoneHomeFailed(msg)
    })?;

    let window = web_sys::window().ok_or_else(|| {
        console_warn("[runlicense] No window object available for fetch");
        LicenseVerificationError::PhoneHomeFailed("no window object".into())
    })?;

    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|e| {
            let msg = format!("{:?}", e);
            console_warn(&format!("[runlicense] Fetch failed: {msg}"));
            LicenseVerificationError::PhoneHomeFailed(msg)
        })?;

    let resp: web_sys::Response = resp_value.dyn_into().map_err(|_| {
        console_warn("[runlicense] Response is not a Response object");
        LicenseVerificationError::PhoneHomeFailed("invalid response type".into())
    })?;

    console_log(&format!(
        "[runlicense]   Server responded: HTTP {}",
        resp.status()
    ));

    if !resp.ok() {
        let status = resp.status();
        let body_text =
            JsFuture::from(resp.text().map_err(|_| {
                LicenseVerificationError::PhoneHomeFailed(format!("HTTP {status}"))
            })?)
            .await
            .ok()
            .and_then(|v| v.as_string())
            .unwrap_or_default();

        let error_msg = serde_json::from_str::<serde_json::Value>(&body_text)
            .ok()
            .and_then(|v| {
                v.get("meta")
                    .and_then(|m| m.get("message"))
                    .or_else(|| v.get("message"))
                    .and_then(|m| m.as_str().map(String::from))
            })
            .unwrap_or(body_text);

        return Err(LicenseVerificationError::ServerRejected(format!(
            "HTTP {status}: {error_msg}"
        )));
    }

    let body_text = JsFuture::from(resp.text().map_err(|_| {
        LicenseVerificationError::PhoneHomeFailed("failed to read response body".into())
    })?)
    .await
    .map_err(|e| {
        let msg = format!("{:?}", e);
        LicenseVerificationError::PhoneHomeFailed(msg)
    })?;

    let body_str = body_text.as_string().ok_or_else(|| {
        LicenseVerificationError::PhoneHomeFailed("response body is not a string".into())
    })?;

    #[derive(Deserialize)]
    struct PhoneHomeResponseData {
        token: String,
    }

    #[derive(Deserialize)]
    struct PhoneHomeResponse {
        data: PhoneHomeResponseData,
    }

    let response: PhoneHomeResponse = serde_json::from_str(&body_str)
        .map_err(|_| LicenseVerificationError::PhoneHomeFailed("invalid response JSON".into()))?;

    console_log("[runlicense]   Verifying server token...");
    let token_data =
        verify_validation_token(&response.data.token, public_key_b64, nonce, expected_license_id)?;

    Ok((token_data, response.token))
}

// --- Full verification (WASM) ---

pub async fn verify_license_full_with_key(
    license_json: &str,
    public_key_b64: &str,
) -> Result<ValidationToken, LicenseVerificationError> {
    console_log("[runlicense] ══════════════════════════════════════════");
    console_log("[runlicense] Starting full license verification");
    console_log("[runlicense] ══════════════════════════════════════════");

    // Step 1: Verify signature and parse payload
    console_log("[runlicense] Step 1/4: Verifying license signature...");
    let payload = parse_license_payload_with_key(license_json, public_key_b64)?;
    console_log("[runlicense] License signature valid");

    // Derive cache namespace from product_id for localStorage isolation
    let namespace = &payload.product_id;

    // Step 2: Check status and expiry
    console_log("[runlicense] Step 2/4: Checking license status and expiry...");
    if payload.status != "active" {
        console_warn(&format!(
            "[runlicense] License status is '{}', expected 'active'",
            payload.status
        ));
        return Err(LicenseVerificationError::LicenseNotActive);
    }
    console_log("[runlicense] License status is 'active'");

    if let Some(ref expiry) = payload.expiry_date {
        console_log(&format!("[runlicense]   License expiry: {expiry}"));
        if is_iso8601_expired(expiry) {
            console_warn("[runlicense] License has expired");
            return Err(LicenseVerificationError::LicenseExpired);
        }
        console_log("[runlicense] License not expired");
    } else {
        console_log("[runlicense] License has no expiry (perpetual)");
    }

    // Step 3: Domain check
    console_log("[runlicense] Step 3/4: Checking domain authorization...");
    let hostname = match get_wasm_hostname() {
        Some(h) => {
            console_log(&format!("[runlicense]   Current hostname: '{h}'"));
            h
        }
        None => {
            console_warn("[runlicense] Could not detect hostname from window.location");
            return Err(LicenseVerificationError::DomainNotAuthorized);
        }
    };

    if payload.domains.is_empty() {
        console_warn("[runlicense] License has no authorized domains configured");
        return Err(LicenseVerificationError::NoDomainsConfigured);
    }

    console_log(&format!(
        "[runlicense]   Authorized domains ({}):",
        payload.domains.len()
    ));
    for d in &payload.domains {
        let expiry = d.expiry_date.as_deref().unwrap_or("perpetual");
        console_log(&format!(
            "[runlicense]     - {} (expiry: {})",
            d.domain, expiry
        ));
    }

    let hostname_lower = hostname.to_lowercase();
    let matching_domain = payload
        .domains
        .iter()
        .find(|d| d.domain.to_lowercase() == hostname_lower);

    let domain = match matching_domain {
        Some(d) => {
            console_log(&format!(
                "[runlicense] Domain '{}' found in authorized list",
                d.domain
            ));
            d
        }
        None => {
            console_warn(&format!(
                "[runlicense] Domain '{hostname}' not in authorized list"
            ));
            return Err(LicenseVerificationError::DomainNotAuthorized);
        }
    };

    if let Some(ref expiry) = domain.expiry_date {
        console_log(&format!("[runlicense]   Domain expiry: {expiry}"));
        if is_iso8601_expired(expiry) {
            console_warn(&format!(
                "[runlicense] Domain '{}' authorization has expired",
                domain.domain
            ));
            return Err(LicenseVerificationError::DomainExpired);
        }
        console_log("[runlicense] Domain not expired");
    } else {
        console_log("[runlicense] Domain has no expiry (perpetual)");
    }

    // Step 4: Phone home (with grace period caching)
    console_log("[runlicense] Step 4/4: Phoning home for server validation...");
    let activation_url = match &payload.activation_url {
        Some(url) => {
            console_log(&format!("[runlicense]   Validation URL: {url}"));
            url.clone()
        }
        None => {
            console_warn("[runlicense] License payload missing activation_url — cannot phone home");
            return Err(LicenseVerificationError::NoActivationUrl);
        }
    };

    let nonce = generate_nonce();

    match do_phone_home(&activation_url, &nonce, public_key_b64, &payload.license_id).await {
        Ok((token_data, raw_token)) => {
            cache_token(namespace, &raw_token, &token_data);
            let ttl = payload.token_ttl.unwrap_or(3600);
            schedule_renewal(
                namespace.to_string(),
                activation_url.clone(),
                public_key_b64.to_string(),
                payload.license_id.clone(),
                ttl,
            );
            console_log("[runlicense] Server token verified — server is authentic");
            console_log("[runlicense] ══════════════════════════════════════════");
            console_log("[runlicense] FULL LICENSE VERIFICATION PASSED");
            console_log("[runlicense] ══════════════════════════════════════════");
            Ok(token_data)
        }
        Err(LicenseVerificationError::ServerRejected(ref msg)) => {
            console_warn(&format!("[runlicense] Server rejected: {msg}"));
            clear_cached_token(namespace);
            Err(LicenseVerificationError::ServerRejected(msg.clone()))
        }
        Err(LicenseVerificationError::InvalidValidationToken)
        | Err(LicenseVerificationError::ValidationTokenNonceMismatch)
        | Err(LicenseVerificationError::ValidationTokenLicenseMismatch) => {
            console_warn(
                "[runlicense] Server response token failed verification — possible tampering",
            );
            clear_cached_token(namespace);
            Err(LicenseVerificationError::InvalidValidationToken)
        }
        Err(ref phone_home_err) => {
            console_warn(&format!(
                "[runlicense]   Phone-home failed: {phone_home_err}"
            ));
            console_log("[runlicense]   Checking for cached validation token...");

            match load_cached_token(namespace) {
                Some(cached_token) => {
                    if cached_token.license_id != payload.license_id {
                        console_warn(
                            "[runlicense] Cached token is for a different license — ignoring",
                        );
                        clear_cached_token(namespace);
                        return Err(LicenseVerificationError::PhoneHomeFailed(
                            "network error and no valid cached token".into(),
                        ));
                    }
                    console_log(&format!(
                        "[runlicense] Using cached token (grace period until {})",
                        cached_token.expires_at
                    ));
                    schedule_renewal(
                        namespace.to_string(),
                        activation_url.clone(),
                        public_key_b64.to_string(),
                        payload.license_id.clone(),
                        30,
                    );
                    console_log("[runlicense] ══════════════════════════════════════════");
                    console_log("[runlicense] VERIFICATION PASSED (grace period — cached token)");
                    console_log("[runlicense] ══════════════════════════════════════════");
                    Ok(cached_token)
                }
                None => {
                    console_warn("[runlicense] No cached token available — phone-home is required");
                    Err(LicenseVerificationError::PhoneHomeFailed(
                        "network error and no valid cached token".into(),
                    ))
                }
            }
        }
    }
}
