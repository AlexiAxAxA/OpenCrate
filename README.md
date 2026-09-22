<div align="center">

# Open Crate

**Encrypted documents. Explicit trust. Inspectable Rust.**

Five Rust libraries for authenticated document containers, key handling,
protocol messages and access decisions.

[Website](https://closecrate.com/) · [Start here](docs/getting-started.md) ·
[Architecture](docs/architecture.md) · [Security](SECURITY.md) ·
[Licensing](docs/licensing.md)

</div>

Open Crate is the library core behind Close Crate. Use it to build applications
around encrypted `.cc` containers with signed headers, chunk authentication,
recipient key slots and explicit access policy.

The libraries own no filesystem, network, system clock or operating-system
random generator. The caller supplies those capabilities. WebAssembly builds
and Clippy boundary checks help keep that separation testable.

## What is included

| Library | Responsibility |
| --- | --- |
| `oc-format` | Container layout, parsing and authenticated header verification |
| `oc-crypto` | AEAD, key derivation, signatures, key encapsulation and integrity trees |
| `oc-protocol` | Signed leases, revocation and other protocol message codecs |
| `oc-policy` | Access decisions from policy and verified caller-provided facts |
| `oc-engine` | Packing plans, per-file secrets and header assembly |

The Close Crate viewer, server, device keystore and hosted service are separate.
This repository is a library workspace; it does not contain a ready-to-run
document-sharing application or JavaScript bindings.

## Try the core

Install Rust through rustup, clone this repository, then run:

```sh
cargo test --locked --workspace
cargo run --locked -p oc-format --example verify-header -- tests/golden/basic.cc
cargo doc --locked --workspace --no-deps
```

The example authenticates a committed test header and explicitly reports that
the signing identity is not pinned. It does not decrypt a document or grant
recipient access. See [integration responsibilities](docs/getting-started.md).

## Designed to be checked

- Frozen known-answer vectors and golden headers accompany the implementation.
- First-party core crates forbid unsafe Rust. Third-party dependencies have
  their own implementations and assurance boundaries.
- Policy defaults to denial; the application must enforce every obligation.
- Hybrid key slots support ML-KEM-768 with X25519 or P-256. Hybrid protection is
  selected per slot; it does not make every signature or access path quantum-safe.

## Status and limits

Pre-release `0.0.1`. Container version 5 is supported; versions 1–4 are rejected.
Do not treat a passing test suite as an independent cryptographic audit or FIPS
certification. No stable library API or production deployment guarantee is made.

The core cannot stop an administrator or a compromised application from reading
plaintext it has already received. Revocation requires a correctly implemented
application, current evidence and an explicit offline policy. It cannot recall
an extracted copy.

English guides are included. Full normative specifications and source API
comments are still undergoing translation; **this candidate is not ready for
the requested English-only public launch**.

## License

The [Open Crate Community License 1.0](LICENSE) is free for personal
non-commercial use and businesses with both less than **$1M annual group revenue**
and **fewer than 25 people**. Larger businesses need a commercial agreement:
write to god@closecrate.com or see [Licensing](docs/licensing.md).
There is a 90-day transition for existing qualifying businesses.

This is source-available software, not OSI-approved open source. See
[licensing](docs/licensing.md) for scope and third-party terms.

## Support the project

Open Crate is built by one independent developer. If the core is useful to you,
a tip helps keep it going. Tips are voluntary: they are not a license fee, do
not buy a commercial license and do not create any support obligation.

| Asset | Network | Address |
| --- | --- | --- |
| USDT | **TRON (TRC20) only** | `TR8Tj4kJ8v75hKrtHgFBg9eodt8CriFhpk` |

Send only USDT on the TRON (TRC20) network to this address. Other tokens or
other networks (Ethereum, BNB Chain and so on) will be lost. No memo or tag is
needed. Commercial licensing goes through god@closecrate.com, not through this
address.
