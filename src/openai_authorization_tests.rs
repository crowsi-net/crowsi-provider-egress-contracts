use super::*;

#[test]
fn accepts_only_the_managed_openai_authorization_origin() {
    let accepted = OpenAiAuthorizationEgress::authorize(
        EgressMethod::Get,
        "https://auth.openai.com/.well-known/jwks.json".into(),
        None,
        Vec::new(),
    )
    .expect("managed route");
    let (_, url, _, _) = accepted.into_parts();
    assert_eq!(url, "https://auth.openai.com/.well-known/jwks.json");

    for rejected in [
        "http://auth.openai.com/oauth/token",
        "https://example.com/oauth/token",
        "https://auth.openai.com:444/oauth/token",
        "https://user@auth.openai.com/oauth/token",
        "https://auth.openai.com/oauth/token#secret",
        "https://auth.openai.com/oauth/token?alternate=true",
        "https://auth.openai.com/unlisted",
    ] {
        assert_eq!(
            OpenAiAuthorizationEgress::authorize(
                EgressMethod::Post,
                rejected.into(),
                Some("application/json"),
                Vec::new(),
            )
            .err(),
            Some(EgressPolicyError::InvalidRoute),
        );
    }
    assert_eq!(
        OpenAiAuthorizationEgress::authorize(
            EgressMethod::Get,
            "https://auth.openai.com/oauth/token".into(),
            None,
            Vec::new(),
        )
        .err(),
        Some(EgressPolicyError::InvalidRoute),
    );
    assert_eq!(
        OpenAiAuthorizationEgress::authorize(
            EgressMethod::Post,
            "https://auth.openai.com/oauth/revoke".into(),
            Some("application/x-www-form-urlencoded"),
            Vec::new(),
        )
        .err(),
        Some(EgressPolicyError::InvalidRoute),
    );
}

#[test]
fn bounds_request_and_response_bodies() {
    let url = "https://auth.openai.com/oauth/token".to_owned();
    assert_eq!(
        OpenAiAuthorizationEgress::authorize(
            EgressMethod::Post,
            url,
            Some("application/json"),
            vec![0; MAX_BODY_BYTES + 1],
        )
        .err(),
        Some(EgressPolicyError::RequestTooLarge),
    );
    assert_eq!(
        OpenAiAuthorizationEgress::validate_response(&vec![0; MAX_BODY_BYTES + 1]),
        Err(EgressPolicyError::ResponseTooLarge),
    );
}
