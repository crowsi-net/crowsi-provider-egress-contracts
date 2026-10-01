# Crowsi provider egress contracts

This crate owns closed outbound-route policy for external provider adapters.
Provider libraries such as Zixcel create typed protocol plans; Crowsi validates
the destination and bounds the bytes before a product transport executes them.
The product cannot choose a different provider host or relax the response
limit.

`OpenAiAuthorizationEgress` is limited to `https://auth.openai.com`, rejects
userinfo, fragments and non-default ports, and accepts only GET and POST. It is
an account-authorization route, not a generic web proxy or a model-inference
authorization mechanism.

Hatter may transport an `AuthorizedEgressRequest`, but OpenAI endpoints, OAuth
fields and provider response interpretation remain in `zixcel-openai-auth`.
Persistent credential material remains in Crowsi custody.

## Verify

```bash
cargo test --locked --offline
cargo clippy --locked --offline --all-targets -- -D warnings
```
