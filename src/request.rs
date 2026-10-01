use zeroize::{Zeroize, Zeroizing};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EgressMethod {
    Get,
    Post,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EgressPolicyError {
    InvalidRoute,
    RequestTooLarge,
    ResponseTooLarge,
}

pub struct AuthorizedEgressRequest {
    method: EgressMethod,
    url: String,
    content_type: Option<&'static str>,
    body: Zeroizing<Vec<u8>>,
}

impl AuthorizedEgressRequest {
    pub(crate) fn new(
        method: EgressMethod,
        url: String,
        content_type: Option<&'static str>,
        body: Vec<u8>,
    ) -> Self {
        Self {
            method,
            url,
            content_type,
            body: Zeroizing::new(body),
        }
    }

    #[must_use]
    pub fn into_parts(mut self) -> (EgressMethod, String, Option<&'static str>, Vec<u8>) {
        (
            self.method,
            std::mem::take(&mut self.url),
            self.content_type,
            std::mem::take(&mut *self.body),
        )
    }
}

impl Drop for AuthorizedEgressRequest {
    fn drop(&mut self) {
        self.url.zeroize();
    }
}
