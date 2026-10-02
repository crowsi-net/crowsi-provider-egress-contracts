# crowsi-provider-egress-contracts

Declare exactly where a provider request may go and how much data it may transfer.

## What you can do

- Validate destination, method and size limits.
- Share a strict egress contract with transport adapters.

## Current scope

The contracts describe allowed communication; the caller must supply authorization and enforcement.

Package distribution is not activated by this documentation. Use the checked-in source and the declared dependency versions; published availability must be verified separately.

## Getting started

Install Rust 1.97 or newer and make the declared dependencies available. Use the configured private registry when a dependency is not distributed publicly. Run from this repository:

```sh
cargo test --locked
```

## Documentation and source

[Interface reference](docs/interface-reference.md)

[Usage guide](docs/getting-started.md)

[Implementation and public interfaces](src) · [Contributing](CONTRIBUTING.md) · [Security reporting](SECURITY.md) · [License](LICENSE) · [Attribution notices](NOTICE)
