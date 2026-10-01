use url::Url;

use crate::{AuthorizedEgressRequest, EgressMethod, EgressPolicyError};

const AUTH_HOST: &str = "auth.openai.com";
const MAX_BODY_BYTES: usize = 64 * 1024;

pub struct OpenAiAuthorizationEgress;

impl OpenAiAuthorizationEgress {
    /// Physical readers use the policy owner's exact admission ceiling.
    pub const RESPONSE_BYTE_LIMIT: usize = MAX_BODY_BYTES;
    /// Validates one Zixcel-produced authorization request before transport.
    ///
    /// # Errors
    /// Rejects non-production routes and oversized bodies.
    pub fn authorize(
        method: EgressMethod,
        url: String,
        content_type: Option<&'static str>,
        body: Vec<u8>,
    ) -> Result<AuthorizedEgressRequest, EgressPolicyError> {
        let parsed = Url::parse(&url).map_err(|_| EgressPolicyError::InvalidRoute)?;
        let valid = parsed.scheme() == "https"
            && parsed.host_str() == Some(AUTH_HOST)
            && parsed.port().is_none_or(|port| port == 443)
            && parsed.username().is_empty()
            && parsed.password().is_none()
            && parsed.query().is_none()
            && parsed.fragment().is_none()
            && route_is_allowed(method, parsed.path(), content_type);
        if !valid {
            return Err(EgressPolicyError::InvalidRoute);
        }
        if body.len() > MAX_BODY_BYTES {
            return Err(EgressPolicyError::RequestTooLarge);
        }
        Ok(AuthorizedEgressRequest::new(
            method,
            url,
            content_type,
            body,
        ))
    }

    /// Checks the provider body before it returns to the protocol library.
    ///
    /// # Errors
    /// Rejects responses above the fixed authorization limit.
    pub fn validate_response(body: &[u8]) -> Result<(), EgressPolicyError> {
        Self::validate_response_size(body.len())
    }

    /// Checks an incremental provider response length before allocation grows.
    ///
    /// # Errors
    /// Rejects lengths above the fixed authorization limit.
    pub fn validate_response_size(size: usize) -> Result<(), EgressPolicyError> {
        (size <= MAX_BODY_BYTES)
            .then_some(())
            .ok_or(EgressPolicyError::ResponseTooLarge)
    }
}

fn route_is_allowed(method: EgressMethod, path: &str, content_type: Option<&str>) -> bool {
    matches!(
        (method, path, content_type),
        (EgressMethod::Get, "/.well-known/jwks.json", None)
            | (
                EgressMethod::Post,
                "/oauth/token",
                Some("application/json" | "application/x-www-form-urlencoded"),
            )
            | (
                EgressMethod::Post,
                "/oauth/revoke"
                    | "/api/accounts/deviceauth/usercode"
                    | "/api/accounts/deviceauth/token",
                Some("application/json"),
            )
    )
}

#[cfg(test)]
#[path = "openai_authorization_tests.rs"]
mod tests;
