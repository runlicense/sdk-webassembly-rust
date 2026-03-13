use super::__internal;
use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

fn make_test_license(signing_key: &SigningKey, payload: &str) -> String {
    use ed25519_dalek::Signer;
    let signature = signing_key.sign(payload.as_bytes());
    let sig_b64 = BASE64.encode(signature.to_bytes());
    serde_json::json!({
        "payload": payload,
        "signature": sig_b64,
    })
    .to_string()
}

fn pub_key_b64(signing_key: &SigningKey) -> String {
    BASE64.encode(signing_key.verifying_key().to_bytes())
}

/// Build a valid full license with a proper LicensePayload structure.
fn make_valid_license(signing_key: &SigningKey) -> String {
    use ed25519_dalek::Signer;
    let payload = serde_json::json!({
        "license_id": "abc-123",
        "product_id": "prod-1",
        "customer_id": "cust-1",
        "status": "active",
        "expiry_date": null,
        "allowed_features": null,
        "usage_limit": null,
        "domains": [],
    })
    .to_string();
    let signature = signing_key.sign(payload.as_bytes());
    let sig_b64 = BASE64.encode(signature.to_bytes());
    serde_json::json!({
        "payload": payload,
        "signature": sig_b64,
    })
    .to_string()
}

fn make_license_with_domains(signing_key: &SigningKey, domains: &[(&str, Option<&str>)]) -> String {
    use ed25519_dalek::Signer;

    let domains_json: Vec<serde_json::Value> = domains
        .iter()
        .map(|(domain, expiry)| {
            serde_json::json!({
                "domain": domain,
                "expiry_date": expiry,
            })
        })
        .collect();

    let payload = serde_json::json!({
        "license_id": "test-license-id",
        "product_id": "test-product-id",
        "customer_id": "test-customer-id",
        "status": "active",
        "expiry_date": null,
        "allowed_features": null,
        "usage_limit": null,
        "domains": domains_json,
    })
    .to_string();

    let signature = signing_key.sign(payload.as_bytes());
    let sig_b64 = BASE64.encode(signature.to_bytes());
    serde_json::json!({
        "payload": payload,
        "signature": sig_b64,
    })
    .to_string()
}

fn make_license_with_status(
    signing_key: &SigningKey,
    status: &str,
    domains: &[(&str, Option<&str>)],
) -> String {
    use ed25519_dalek::Signer;

    let domains_json: Vec<serde_json::Value> = domains
        .iter()
        .map(|(domain, expiry)| {
            serde_json::json!({
                "domain": domain,
                "expiry_date": expiry,
            })
        })
        .collect();

    let payload = serde_json::json!({
        "license_id": "test-license-id",
        "product_id": "test-product-id",
        "customer_id": "test-customer-id",
        "status": status,
        "expiry_date": null,
        "allowed_features": null,
        "usage_limit": null,
        "domains": domains_json,
    })
    .to_string();

    let signature = signing_key.sign(payload.as_bytes());
    let sig_b64 = BASE64.encode(signature.to_bytes());
    serde_json::json!({
        "payload": payload,
        "signature": sig_b64,
    })
    .to_string()
}

fn make_validation_token(
    signing_key: &SigningKey,
    license_id: &str,
    domain: &str,
    nonce: &str,
    expires_at: &str,
) -> String {
    use ed25519_dalek::Signer;

    let token_payload = serde_json::json!({
        "license_id": license_id,
        "domain": domain,
        "nonce": nonce,
        "issued_at": "2026-03-06T00:00:00+00:00",
        "expires_at": expires_at,
    })
    .to_string();

    let signature = signing_key.sign(token_payload.as_bytes());
    let encoded_payload = BASE64.encode(token_payload.as_bytes());
    let encoded_sig = BASE64.encode(signature.to_bytes());

    format!("{encoded_payload}.{encoded_sig}")
}

// --- Signature verification tests ---

#[test]
fn valid_signature_roundtrip() {
    let sk = SigningKey::generate(&mut OsRng);
    let license_json = make_valid_license(&sk);
    let pk_b64 = pub_key_b64(&sk);

    assert!(__internal::verify_license_with_key(&license_json, &pk_b64));
    assert!(__internal::verify_license_detailed_with_key(&license_json, &pk_b64).is_ok());
}

#[test]
fn invalid_signature_returns_false() {
    let sk = SigningKey::generate(&mut OsRng);
    let payload = r#"{"license_id":"abc-123","product_id":"p","customer_id":"c","status":"active","expiry_date":null,"allowed_features":null,"usage_limit":null,"domains":[]}"#;
    let license_json = make_test_license(&sk, payload);

    let tampered = license_json.replace("abc-123", "xyz-999");
    let pk_b64 = pub_key_b64(&sk);

    assert!(!__internal::verify_license_with_key(&tampered, &pk_b64));
    assert_eq!(
        __internal::verify_license_detailed_with_key(&tampered, &pk_b64),
        Err(LicenseVerificationError::SignatureMismatch)
    );
}

#[test]
fn malformed_json_returns_false() {
    assert!(!__internal::verify_license_with_key("not json", "AAAA"));
    assert_eq!(
        __internal::verify_license_detailed_with_key("not json", "AAAA"),
        Err(LicenseVerificationError::InvalidJson)
    );
}

#[test]
fn invalid_base64_key_returns_false() {
    let sk = SigningKey::generate(&mut OsRng);
    let license_json = make_valid_license(&sk);

    assert!(!__internal::verify_license_with_key(
        &license_json,
        "not-valid-base64!!!"
    ));
    assert_eq!(
        __internal::verify_license_detailed_with_key(&license_json, "not-valid-base64!!!"),
        Err(LicenseVerificationError::InvalidPublicKey)
    );
}

#[test]
fn wrong_key_returns_false() {
    let sk1 = SigningKey::generate(&mut OsRng);
    let sk2 = SigningKey::generate(&mut OsRng);
    let license_json = make_valid_license(&sk1);
    let wrong_pk = pub_key_b64(&sk2);

    assert!(!__internal::verify_license_with_key(
        &license_json,
        &wrong_pk
    ));
    assert_eq!(
        __internal::verify_license_detailed_with_key(&license_json, &wrong_pk),
        Err(LicenseVerificationError::SignatureMismatch)
    );
}

// --- Integrity verification tests ---

#[test]
fn hash_computation_is_deterministic() {
    let data = b"hello wasm world";
    let h1 = compute_wasm_sha256(data);
    let h2 = compute_wasm_sha256(data);
    assert_eq!(h1, h2);
}

#[test]
fn hash_changes_with_different_input() {
    let h1 = compute_wasm_sha256(b"original");
    let h2 = compute_wasm_sha256(b"tampered");
    assert_ne!(h1, h2);
}

#[test]
fn verify_integrity_valid() {
    let wasm = b"fake wasm bytes for testing";
    let hash = hex_encode(&compute_wasm_sha256(wasm));
    let manifest = format!(r#"{{"wasm_sha256":"{hash}"}}"#);
    assert!(verify_wasm_integrity(wasm, &manifest).is_ok());
}

#[test]
fn verify_integrity_tampered() {
    let wasm = b"original wasm bytes";
    let hash = hex_encode(&compute_wasm_sha256(wasm));
    let manifest = format!(r#"{{"wasm_sha256":"{hash}"}}"#);

    let tampered = b"patched wasm bytes";
    assert_eq!(
        verify_wasm_integrity(tampered, &manifest),
        Err(IntegrityError::HashMismatch)
    );
}

#[test]
fn verify_integrity_bad_manifest() {
    let wasm = b"anything";
    assert_eq!(
        verify_wasm_integrity(wasm, "not json"),
        Err(IntegrityError::InvalidManifest)
    );
    assert_eq!(
        verify_wasm_integrity(wasm, r#"{"other_field":"value"}"#),
        Err(IntegrityError::InvalidManifest)
    );
}

#[test]
fn verify_integrity_empty_hash_in_manifest() {
    let wasm = b"anything";
    assert_eq!(
        verify_wasm_integrity(wasm, r#"{"wasm_sha256":""}"#),
        Err(IntegrityError::InvalidManifest)
    );
}

// --- Combined verification tests ---

#[test]
fn combined_verification_both_valid() {
    let sk = SigningKey::generate(&mut OsRng);
    let license_json = make_valid_license(&sk);
    let pk_b64 = pub_key_b64(&sk);

    let wasm = b"test wasm binary";
    let hash = hex_encode(&compute_wasm_sha256(wasm));
    let manifest = format!(r#"{{"wasm_sha256":"{hash}"}}"#);

    assert!(
        __internal::verify_license_and_integrity_with_key(&license_json, &pk_b64, wasm, &manifest)
            .is_ok()
    );
}

#[test]
fn combined_verification_bad_license() {
    let sk = SigningKey::generate(&mut OsRng);
    let license_json = make_valid_license(&sk);
    let tampered_license = license_json.replace("abc-123", "xyz-999");
    let pk_b64 = pub_key_b64(&sk);

    let wasm = b"test wasm binary";
    let hash = hex_encode(&compute_wasm_sha256(wasm));
    let manifest = format!(r#"{{"wasm_sha256":"{hash}"}}"#);

    assert_eq!(
        __internal::verify_license_and_integrity_with_key(
            &tampered_license,
            &pk_b64,
            wasm,
            &manifest
        ),
        Err(VerificationError::License(
            LicenseVerificationError::SignatureMismatch
        ))
    );
}

#[test]
fn combined_verification_bad_integrity() {
    let sk = SigningKey::generate(&mut OsRng);
    let license_json = make_valid_license(&sk);
    let pk_b64 = pub_key_b64(&sk);

    let wasm = b"original wasm binary";
    let hash = hex_encode(&compute_wasm_sha256(wasm));
    let manifest = format!(r#"{{"wasm_sha256":"{hash}"}}"#);

    let tampered_wasm = b"patched wasm binary";
    assert_eq!(
        __internal::verify_license_and_integrity_with_key(
            &license_json,
            &pk_b64,
            tampered_wasm,
            &manifest
        ),
        Err(VerificationError::Integrity(IntegrityError::HashMismatch))
    );
}

// --- Domain verification tests ---

#[test]
fn parse_license_payload_returns_domains() {
    let sk = SigningKey::generate(&mut OsRng);
    let pk_b64 = pub_key_b64(&sk);
    let license = make_license_with_domains(
        &sk,
        &[
            ("myapp.com", None),
            ("localhost", Some("2099-12-31T00:00:00+00:00")),
        ],
    );

    let payload = __internal::parse_license_payload_with_key(&license, &pk_b64).unwrap();
    assert_eq!(payload.domains.len(), 2);
    assert_eq!(payload.domains[0].domain, "myapp.com");
    assert_eq!(payload.domains[0].expiry_date, None);
    assert_eq!(payload.domains[1].domain, "localhost");
    assert!(payload.domains[1].expiry_date.is_some());
}

#[test]
fn parse_license_payload_works_without_domains() {
    let sk = SigningKey::generate(&mut OsRng);
    let pk_b64 = pub_key_b64(&sk);
    let payload_str = r#"{"license_id":"abc","product_id":"def","customer_id":"ghi","status":"active","expiry_date":null,"allowed_features":null,"usage_limit":null}"#;
    let license = make_test_license(&sk, payload_str);

    let payload = __internal::parse_license_payload_with_key(&license, &pk_b64).unwrap();
    assert!(payload.domains.is_empty());
}

#[test]
fn domain_verification_succeeds_for_authorized_domain() {
    let sk = SigningKey::generate(&mut OsRng);
    let pk_b64 = pub_key_b64(&sk);
    let license = make_license_with_domains(&sk, &[("myapp.com", None)]);

    let result = __internal::verify_license_domain_with_key(&license, &pk_b64, "myapp.com");
    assert!(result.is_ok());
}

#[test]
fn domain_verification_is_case_insensitive() {
    let sk = SigningKey::generate(&mut OsRng);
    let pk_b64 = pub_key_b64(&sk);
    let license = make_license_with_domains(&sk, &[("MyApp.COM", None)]);

    let result = __internal::verify_license_domain_with_key(&license, &pk_b64, "myapp.com");
    assert!(result.is_ok());
}

#[test]
fn domain_verification_rejects_unauthorized_domain() {
    let sk = SigningKey::generate(&mut OsRng);
    let pk_b64 = pub_key_b64(&sk);
    let license = make_license_with_domains(&sk, &[("myapp.com", None)]);

    let result = __internal::verify_license_domain_with_key(&license, &pk_b64, "evil.com");
    assert_eq!(result, Err(LicenseVerificationError::DomainNotAuthorized));
}

#[test]
fn domain_verification_rejects_expired_domain() {
    let sk = SigningKey::generate(&mut OsRng);
    let pk_b64 = pub_key_b64(&sk);
    let license =
        make_license_with_domains(&sk, &[("myapp.com", Some("2020-01-01T00:00:00+00:00"))]);

    let result = __internal::verify_license_domain_with_key(&license, &pk_b64, "myapp.com");
    assert_eq!(result, Err(LicenseVerificationError::DomainExpired));
}

#[test]
fn domain_verification_allows_future_expiry() {
    let sk = SigningKey::generate(&mut OsRng);
    let pk_b64 = pub_key_b64(&sk);
    let license =
        make_license_with_domains(&sk, &[("myapp.com", Some("2099-12-31T00:00:00+00:00"))]);

    let result = __internal::verify_license_domain_with_key(&license, &pk_b64, "myapp.com");
    assert!(result.is_ok());
}

#[test]
fn domain_verification_allows_null_expiry() {
    let sk = SigningKey::generate(&mut OsRng);
    let pk_b64 = pub_key_b64(&sk);
    let license = make_license_with_domains(&sk, &[("myapp.com", None)]);

    let result = __internal::verify_license_domain_with_key(&license, &pk_b64, "myapp.com");
    assert!(result.is_ok());
    let payload = result.unwrap();
    assert_eq!(payload.domains[0].expiry_date, None);
}

#[test]
fn domain_verification_rejects_inactive_license() {
    let sk = SigningKey::generate(&mut OsRng);
    let pk_b64 = pub_key_b64(&sk);
    let license = make_license_with_status(&sk, "suspended", &[("myapp.com", None)]);

    let result = __internal::verify_license_domain_with_key(&license, &pk_b64, "myapp.com");
    assert_eq!(result, Err(LicenseVerificationError::LicenseNotActive));
}

#[test]
fn domain_verification_rejects_revoked_license() {
    let sk = SigningKey::generate(&mut OsRng);
    let pk_b64 = pub_key_b64(&sk);
    let license = make_license_with_status(&sk, "revoked", &[("myapp.com", None)]);

    let result = __internal::verify_license_domain_with_key(&license, &pk_b64, "myapp.com");
    assert_eq!(result, Err(LicenseVerificationError::LicenseNotActive));
}

#[test]
fn domain_verification_multiple_domains_finds_match() {
    let sk = SigningKey::generate(&mut OsRng);
    let pk_b64 = pub_key_b64(&sk);
    let license = make_license_with_domains(
        &sk,
        &[
            ("prod.myapp.com", None),
            ("staging.myapp.com", Some("2099-01-01T00:00:00+00:00")),
            ("localhost", Some("2099-06-01T00:00:00+00:00")),
        ],
    );

    assert!(
        __internal::verify_license_domain_with_key(&license, &pk_b64, "staging.myapp.com").is_ok()
    );
    assert!(__internal::verify_license_domain_with_key(&license, &pk_b64, "localhost").is_ok());
    assert!(
        __internal::verify_license_domain_with_key(&license, &pk_b64, "prod.myapp.com").is_ok()
    );
    assert_eq!(
        __internal::verify_license_domain_with_key(&license, &pk_b64, "other.com"),
        Err(LicenseVerificationError::DomainNotAuthorized)
    );
}

// --- Date/time tests ---

#[test]
fn date_string_conversion_is_correct() {
    assert_eq!(
        __internal::unix_secs_to_date_string(1704067200),
        "2024-01-01"
    );
    assert_eq!(
        __internal::unix_secs_to_date_string(946684800),
        "2000-01-01"
    );
    assert_eq!(__internal::unix_secs_to_date_string(0), "1970-01-01");
}

// --- Validation token tests ---

#[test]
fn token_verification_succeeds_with_valid_token() {
    let sk = SigningKey::generate(&mut OsRng);
    let pk_b64 = pub_key_b64(&sk);

    let token = make_validation_token(
        &sk,
        "license-123",
        "myapp.com",
        "my-nonce",
        "2099-12-31T00:00:00+00:00",
    );

    let result = __internal::verify_validation_token(&token, &pk_b64, "my-nonce", "license-123");
    assert!(result.is_ok());

    let data = result.unwrap();
    assert_eq!(data.license_id, "license-123");
    assert_eq!(data.domain, "myapp.com");
    assert_eq!(data.nonce, "my-nonce");
}

#[test]
fn token_verification_rejects_wrong_signature() {
    let sk1 = SigningKey::generate(&mut OsRng);
    let sk2 = SigningKey::generate(&mut OsRng);
    let pk_b64 = pub_key_b64(&sk2);

    let token = make_validation_token(
        &sk1,
        "license-123",
        "myapp.com",
        "my-nonce",
        "2099-12-31T00:00:00+00:00",
    );

    let result = __internal::verify_validation_token(&token, &pk_b64, "my-nonce", "license-123");
    assert_eq!(
        result,
        Err(LicenseVerificationError::InvalidValidationToken)
    );
}

#[test]
fn token_verification_rejects_nonce_mismatch() {
    let sk = SigningKey::generate(&mut OsRng);
    let pk_b64 = pub_key_b64(&sk);

    let token = make_validation_token(
        &sk,
        "license-123",
        "myapp.com",
        "server-nonce",
        "2099-12-31T00:00:00+00:00",
    );

    let result =
        __internal::verify_validation_token(&token, &pk_b64, "different-nonce", "license-123");
    assert_eq!(
        result,
        Err(LicenseVerificationError::ValidationTokenNonceMismatch)
    );
}

#[test]
fn token_verification_rejects_license_id_mismatch() {
    let sk = SigningKey::generate(&mut OsRng);
    let pk_b64 = pub_key_b64(&sk);

    let token = make_validation_token(
        &sk,
        "license-123",
        "myapp.com",
        "my-nonce",
        "2099-12-31T00:00:00+00:00",
    );

    let result =
        __internal::verify_validation_token(&token, &pk_b64, "my-nonce", "different-license");
    assert_eq!(
        result,
        Err(LicenseVerificationError::ValidationTokenLicenseMismatch)
    );
}

#[test]
fn token_verification_rejects_expired_token() {
    let sk = SigningKey::generate(&mut OsRng);
    let pk_b64 = pub_key_b64(&sk);

    let token = make_validation_token(
        &sk,
        "license-123",
        "myapp.com",
        "my-nonce",
        "2020-01-01T00:00:00+00:00",
    );

    let result = __internal::verify_validation_token(&token, &pk_b64, "my-nonce", "license-123");
    assert_eq!(
        result,
        Err(LicenseVerificationError::ValidationTokenExpired)
    );
}

#[test]
fn token_verification_rejects_malformed_token() {
    let sk = SigningKey::generate(&mut OsRng);
    let pk_b64 = pub_key_b64(&sk);

    let result =
        __internal::verify_validation_token("not-a-valid-token", &pk_b64, "nonce", "license");
    assert_eq!(
        result,
        Err(LicenseVerificationError::InvalidValidationToken)
    );
}

#[test]
fn payload_includes_activation_url() {
    let sk = SigningKey::generate(&mut OsRng);
    let pk_b64 = pub_key_b64(&sk);

    use ed25519_dalek::Signer;

    let payload = serde_json::json!({
        "license_id": "test-id",
        "product_id": "prod-id",
        "customer_id": "cust-id",
        "status": "active",
        "expiry_date": null,
        "allowed_features": null,
        "usage_limit": null,
        "activation_url": "https://runlicense.com/api/v1/licenses/test-id/validate",
        "domains": [{"domain": "myapp.com", "expiry_date": null}],
    })
    .to_string();

    let signature = sk.sign(payload.as_bytes());
    let sig_b64 = BASE64.encode(signature.to_bytes());
    let license_json = serde_json::json!({
        "payload": payload,
        "signature": sig_b64,
    })
    .to_string();

    let parsed = __internal::parse_license_payload_with_key(&license_json, &pk_b64).unwrap();
    assert_eq!(
        parsed.activation_url.as_deref(),
        Some("https://runlicense.com/api/v1/licenses/test-id/validate")
    );
}
