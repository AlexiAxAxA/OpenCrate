# Runnable examples

[Home](../README.md) · [Step-by-step setup](../docs/getting-started.md) · [Documentation](../docs/index.md)

The examples live beside the crate they exercise, so Cargo runs them without
an additional workspace or dependency setup. Run these commands from the
repository root.

## Authenticate a document header

Source: [`verify-header.rs`](../crates/oc-format/examples/verify-header.rs).

```sh
cargo run --locked -p oc-format --example verify-header -- tests/golden/basic.cc
```

The signature verifies; the author is reported as `UNKNOWN` because the example
uses an empty trust store. This demonstrates the difference between an authentic
signature and an identity that your application trusts.

Pass `Cargo.toml` instead of the fixture to try rejection. It must return a
nonzero exit code and `header authentication failed`.

## Make an access decision

Source: [`access-policy.rs`](../crates/oc-policy/examples/access-policy.rs).

```sh
cargo run --locked -p oc-policy --example access-policy
```

![Expected access-policy example outcomes](../docs/assets/access-decisions.svg)

The program checks each expected result and exits with an error if it changes.
Read the printed obligations on the successful request. Its device fingerprint,
policy hash and lease are synthetic demonstration inputs, not verified evidence.

## Seal a small file of any extension

Source: [`seal-file.rs`](../crates/opencrate/examples/seal-file.rs).

```sh
cargo run --locked -p opencrate --features app-data --example seal-file -- README.md
```

The example reads the named file as bytes, seals it for one temporary recipient,
opens it, and checks equality. Input is limited to 16 MiB. It writes no key or
envelope; applications that need persistence must protect the recipient secret
and store both the envelope and the metadata needed to reproduce purpose and
context. See the separate [SDK guide](https://github.com/AlexiAxAxA/OpenCrateSDK/blob/main/docs/usage-guide.md).

## Build your own consumer

The [getting-started guide](../docs/getting-started.md#4-use-it-in-your-own-application)
walks through creating a separate Rust application, adding a path dependency
and running the policy example there. Start with that small integration before
adding network transport, device keys or a document UI.
