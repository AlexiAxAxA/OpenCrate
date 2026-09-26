<p align="center">
  <img src="https://raw.githubusercontent.com/AlexiAxAxA/OpenCrate/main/docs/assets/open-crate-mark.svg" alt="OpenCrate" width="180">
</p>

# OpenCrate

Rust libraries for encrypted document containers and sealed application bytes.
`opencrate` brings the five core libraries into one dependency:
`crypto`, `format`, `protocol`, `policy`, and `engine`.

[![Core CI](https://github.com/AlexiAxAxA/OpenCrate/actions/workflows/ci.yml/badge.svg)](https://github.com/AlexiAxAxA/OpenCrate/actions/workflows/ci.yml)
[![MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-527fba)](https://github.com/AlexiAxAxA/OpenCrate/blob/main/LICENSE)

## Encrypt application bytes

Enable `app-data` for the small API from the separate
[OpenCrateSDK](https://github.com/AlexiAxAxA/OpenCrateSDK). It handles JSON,
messages, or the bytes of any file up to 16 MiB, for one X25519 recipient.

```toml
[dependencies]
opencrate = { version = "=0.0.3", features = ["app-data"] }
```

```rust
use opencrate::app_data::{generate_recipient, open_bytes, recipient_public, seal_bytes};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let secret = generate_recipient()?;
    let public = recipient_public(&secret);
    let purpose = "com.example.invoice.v1";
    let context = b"tenant-7:invoice-42";

    let envelope = seal_bytes(&public, purpose, context, br#"{"total":42}"#)?;
    let plaintext = open_bytes(&secret, purpose, context, &envelope)?;
    assert_eq!(&*plaintext, br#"{"total":42}"#);
    Ok(())
}
```

Keep the recipient key, authenticate its public key before sending, and save
the envelope. Opening requires the same `purpose` and `context`; neither is
stored in the envelope. The returned plaintext buffer wipes itself on drop,
but your application owns any copies it makes.

The SDK's `OCSB1` envelope has no author signature, access policy, lease, or
revocation. It is a preview without an independent security audit or a stable
compatibility promise. Read the
[integration guide](https://github.com/AlexiAxAxA/OpenCrateSDK/blob/main/docs/usage-guide.md)
before choosing it for data you need to keep.

## Use the document core

For `.cc` containers or individual building blocks, use the default facade:

```toml
[dependencies]
opencrate = "=0.0.3"
```

| Module | Responsibility |
| --- | --- |
| `crypto` | AEAD, key agreement, signatures, key derivation, and integrity trees |
| `format` | Container layout, TLV parsing, and header verification |
| `protocol` | Client/server documents and signed leases |
| `policy` | Access decisions from supplied rules and context |
| `engine` | Packing keys, recipient slots, and headers |

The default core performs no I/O and obtains neither time nor randomness from
the environment. It builds for `wasm32-unknown-unknown` with Rust 1.90+.
`app-data` requires Rust 1.96+ and an OS random source. Your application supplies
storage, key management, trusted time, transport, and enforcement of decisions.
These libraries do not install a viewer or run an authority server.

## Read and run the code

- [Getting started](https://github.com/AlexiAxAxA/OpenCrate/blob/main/docs/getting-started.md)
- [Container format](https://github.com/AlexiAxAxA/OpenCrate/blob/main/docs/format.md)
- [Runnable examples](https://github.com/AlexiAxAxA/OpenCrate/blob/main/examples/README.md)
- [Security policy](https://github.com/AlexiAxAxA/OpenCrate/blob/main/SECURITY.md)

The repository examples verify a frozen container header and evaluate an access
policy. Clone the repository to run them; the first Cargo build may take time.

![Example output](https://raw.githubusercontent.com/AlexiAxAxA/OpenCrate/main/docs/assets/quick-start.gif)

## License

Version 0.0.3 is licensed under
[MPL-2.0](https://github.com/AlexiAxAxA/OpenCrate/blob/main/LICENSE).
Commercial use is allowed. Distributed modifications to covered files remain
under MPL-2.0; separate application files can use other terms.
Older registry archives keep their original Community License. Dependencies
retain their own terms.
