use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const GITHUB_AUTHORIZATION_SCHEMA: &str = "crowsi://provider-egress/github-authorization/v1";
pub const GITHUB_COMMAND_SCHEMA: &str = "crowsi://provider-egress/github-command/v1";
pub const GITHUB_VERIFICATION_SCHEMA: &str =
    "crowsi://provider-egress/github-verification-receipt/v1";
pub const GITHUB_RECEIPT_SCHEMA: &str = "crowsi://provider-egress/github-receipt/v1";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubAuthorizationV1 {
    pub schema: String,
    pub authorization_id: String,
    pub issuer: String,
    pub audience: String,
    pub grant_digest_sha256: String,
    pub invocation_digest_sha256: String,
    pub api_request_digest_sha256: String,
    pub connection_ref_digest_sha256: String,
    pub pairwise_subject: String,
    pub device_ref: String,
    pub workload_id: String,
    pub grant_id: String,
    pub proof_key_ref: String,
    pub permission_resource: String,
    pub permission_operation: String,
    pub issued_at_epoch_s: u64,
    pub expires_at_epoch_s: u64,
    pub key_id: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubEgressCommandV1 {
    pub schema: String,
    pub mode: GitHubEgressMode,
    pub authorization: GitHubAuthorizationV1,
    pub grant_json: String,
    pub invocation_json: String,
    pub api_request_json: String,
    pub now_epoch_s: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GitHubEgressMode {
    Verify,
    Execute,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubVerificationReceiptV1 {
    pub schema: String,
    pub authorization_id: String,
    pub authorization_digest_sha256: String,
    pub grant_digest_sha256: String,
    pub invocation_digest_sha256: String,
    pub api_request_digest_sha256: String,
    pub expires_at_epoch_s: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GitHubEgressReceiptV1 {
    pub schema: String,
    pub authorization_id: String,
    pub authorization_digest_sha256: String,
    pub api_request_digest_sha256: String,
    pub provider_request_id: String,
    pub remote_reference: String,
    pub remote_digest_sha256: Option<String>,
    pub completed_at_epoch_s: u64,
}

/// Validates the bounded GitHub egress command and every content digest.
///
/// # Errors
///
/// Returns an error when the command is malformed, expired, or not exactly
/// correlated with its embedded documents.
pub fn validate_github_command(value: &GitHubEgressCommandV1) -> Result<(), &'static str> {
    let auth = &value.authorization;
    if value.schema != GITHUB_COMMAND_SCHEMA
        || auth.schema != GITHUB_AUTHORIZATION_SCHEMA
        || !id(&auth.authorization_id, 128)
        || !reference(&auth.issuer, 256)
        || auth.audience != "crowsi-github-transport"
        || !digest(&auth.grant_digest_sha256)
        || !digest(&auth.invocation_digest_sha256)
        || !digest(&auth.api_request_digest_sha256)
        || !digest(&auth.connection_ref_digest_sha256)
        || !reference(&auth.pairwise_subject, 128)
        || !reference(&auth.device_ref, 128)
        || !reference(&auth.workload_id, 256)
        || !id(&auth.grant_id, 128)
        || !reference(&auth.proof_key_ref, 128)
        || !id(&auth.permission_resource, 128)
        || !id(&auth.permission_operation, 128)
        || auth.issued_at_epoch_s > value.now_epoch_s
        || value.now_epoch_s >= auth.expires_at_epoch_s
        || auth.expires_at_epoch_s <= auth.issued_at_epoch_s
        || auth.expires_at_epoch_s - auth.issued_at_epoch_s > 300
        || !id(&auth.key_id, 128)
        || auth.signature_hex.len() != 128
        || !auth
            .signature_hex
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || value.grant_json.is_empty()
        || value.grant_json.len() > 262_144
        || value.invocation_json.is_empty()
        || value.invocation_json.len() > 262_144
        || value.api_request_json.is_empty()
        || value.api_request_json.len() > 1_048_576
        || github_document_digest(&value.grant_json) != auth.grant_digest_sha256
        || github_document_digest(&value.invocation_json) != auth.invocation_digest_sha256
        || github_document_digest(&value.api_request_json) != auth.api_request_digest_sha256
    {
        return Err("github-egress-command-invalid");
    }
    Ok(())
}

/// Correlates one verification receipt with the exact authorization command.
///
/// # Errors
///
/// Returns an error for any identity, digest, or expiry mismatch.
pub fn validate_github_verification_receipt(
    value: &GitHubVerificationReceiptV1,
    command: &GitHubEgressCommandV1,
) -> Result<(), &'static str> {
    if value.schema != GITHUB_VERIFICATION_SCHEMA
        || value.authorization_id != command.authorization.authorization_id
        || value.authorization_digest_sha256 != authorization_digest(&command.authorization)?
        || value.grant_digest_sha256 != command.authorization.grant_digest_sha256
        || value.invocation_digest_sha256 != command.authorization.invocation_digest_sha256
        || value.api_request_digest_sha256 != command.authorization.api_request_digest_sha256
        || value.expires_at_epoch_s != command.authorization.expires_at_epoch_s
    {
        return Err("github-verification-receipt-invalid");
    }
    Ok(())
}

/// Correlates a metadata-only provider receipt with the exact command.
///
/// # Errors
///
/// Returns an error for an invalid provider result or authorization mismatch.
pub fn validate_github_egress_receipt(
    value: &GitHubEgressReceiptV1,
    command: &GitHubEgressCommandV1,
) -> Result<(), &'static str> {
    if value.schema != GITHUB_RECEIPT_SCHEMA
        || value.authorization_id != command.authorization.authorization_id
        || value.authorization_digest_sha256 != authorization_digest(&command.authorization)?
        || value.api_request_digest_sha256 != command.authorization.api_request_digest_sha256
        || !id(&value.provider_request_id, 128)
        || !reference(&value.remote_reference, 512)
        || value
            .remote_digest_sha256
            .as_ref()
            .is_some_and(|item| !digest(item))
        || value.completed_at_epoch_s < command.authorization.issued_at_epoch_s
        || value.completed_at_epoch_s > command.now_epoch_s
    {
        return Err("github-egress-receipt-invalid");
    }
    Ok(())
}

/// Computes the domain-separated digest of the authorization without its signature.
///
/// # Errors
///
/// Returns an error if the closed authorization cannot be serialized.
pub fn authorization_digest(value: &GitHubAuthorizationV1) -> Result<String, &'static str> {
    let mut unsigned = value.clone();
    unsigned.signature_hex.clear();
    let bytes = serde_json::to_vec(&unsigned).map_err(|_| "github-authorization-invalid")?;
    let mut hash = Sha256::new();
    hash.update(b"crowsi:provider-egress:github-authorization:v1\0");
    hash.update(bytes);
    Ok(format!("sha256:{}", hex_digest(hash.finalize())))
}

#[must_use]
pub fn github_document_digest(value: &str) -> String {
    format!("sha256:{}", hex_digest(Sha256::digest(value.as_bytes())))
}

#[must_use]
pub fn github_connection_ref_digest(value: &str) -> String {
    let mut hash = Sha256::new();
    hash.update(b"crowsi:provider-egress:github-connection-ref:v1\0");
    hash.update(value.as_bytes());
    format!("sha256:{}", hex_digest(hash.finalize()))
}
fn digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}
fn id(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._:/".contains(&byte))
}
fn reference(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.bytes().any(|byte| byte.is_ascii_control())
}
fn hex_digest(value: impl AsRef<[u8]>) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    value
        .as_ref()
        .iter()
        .flat_map(|byte| {
            [
                HEX[(byte >> 4) as usize] as char,
                HEX[(byte & 0x0f) as usize] as char,
            ]
        })
        .collect()
}
