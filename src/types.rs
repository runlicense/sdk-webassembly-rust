//! Public types for the RunLicense SDK.

use serde::Deserialize;

/// A domain entry within a license payload.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct LicenseDomain {
    pub domain: String,
    pub expiry_date: Option<String>,
}

/// The parsed contents of a license payload.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct LicensePayload {
    pub license_id: String,
    pub product_id: String,
    pub customer_id: String,
    pub status: String,
    pub expiry_date: Option<String>,
    pub allowed_features: Option<serde_json::Value>,
    pub usage_limit: Option<u64>,
    pub token_ttl: Option<u64>,
    pub activation_url: Option<String>,
    #[serde(default)]
    pub domains: Vec<LicenseDomain>,
}

/// Errors returned by license verification.
#[derive(Debug, PartialEq)]
pub enum LicenseVerificationError {
    InvalidJson,
    InvalidPublicKey,
    InvalidSignature,
    SignatureMismatch,
    NoDomainsConfigured,
    DomainNotAuthorized,
    DomainExpired,
    LicenseExpired,
    LicenseNotActive,
    NoActivationUrl,
    PhoneHomeFailed(String),
    InvalidValidationToken,
    ValidationTokenNonceMismatch,
    ValidationTokenExpired,
    ValidationTokenLicenseMismatch,
    ServerRejected(String),
    LicenseFileNotFound(String),
    LicenseFileReadError(String),
}

impl core::fmt::Display for LicenseVerificationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidJson => write!(f, "invalid license JSON"),
            Self::InvalidPublicKey => write!(f, "invalid public key"),
            Self::InvalidSignature => write!(f, "invalid signature encoding"),
            Self::SignatureMismatch => write!(f, "signature verification failed"),
            Self::NoDomainsConfigured => write!(f, "license has no authorized domains configured"),
            Self::DomainNotAuthorized => write!(f, "domain not authorized for this license"),
            Self::DomainExpired => write!(f, "domain authorization has expired"),
            Self::LicenseExpired => write!(f, "license has expired"),
            Self::LicenseNotActive => write!(f, "license is not active"),
            Self::NoActivationUrl => write!(f, "license payload missing activation_url"),
            Self::PhoneHomeFailed(msg) => write!(f, "phone-home request failed: {msg}"),
            Self::InvalidValidationToken => write!(f, "invalid validation token from server"),
            Self::ValidationTokenNonceMismatch => write!(
                f,
                "validation token nonce mismatch — possible replay attack"
            ),
            Self::ValidationTokenExpired => write!(f, "validation token has expired"),
            Self::ValidationTokenLicenseMismatch => {
                write!(f, "validation token license_id mismatch")
            }
            Self::ServerRejected(msg) => write!(f, "server rejected validation: {msg}"),
            Self::LicenseFileNotFound(path) => write!(f, "license file not found: {path}"),
            Self::LicenseFileReadError(msg) => write!(f, "failed to read license file: {msg}"),
        }
    }
}

/// The parsed contents of a server validation token.
#[derive(Debug, Deserialize, PartialEq)]
#[cfg_attr(feature = "wasm", derive(serde::Serialize))]
pub struct ValidationToken {
    pub license_id: String,
    pub domain: String,
    pub nonce: String,
    pub issued_at: String,
    pub expires_at: String,
}

/// Errors returned by WASM integrity verification.
#[derive(Debug, PartialEq)]
pub enum IntegrityError {
    InvalidManifest,
    HashMismatch,
}

impl core::fmt::Display for IntegrityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidManifest => write!(f, "invalid or missing wasm_sha256 in manifest"),
            Self::HashMismatch => write!(f, "WASM hash does not match manifest"),
        }
    }
}

/// Combined license + integrity error.
#[derive(Debug, PartialEq)]
pub enum VerificationError {
    License(LicenseVerificationError),
    Integrity(IntegrityError),
}

impl core::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::License(e) => write!(f, "license error: {e}"),
            Self::Integrity(e) => write!(f, "integrity error: {e}"),
        }
    }
}

impl From<LicenseVerificationError> for VerificationError {
    fn from(e: LicenseVerificationError) -> Self {
        Self::License(e)
    }
}

impl From<IntegrityError> for VerificationError {
    fn from(e: IntegrityError) -> Self {
        Self::Integrity(e)
    }
}
