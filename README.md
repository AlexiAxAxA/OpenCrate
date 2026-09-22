![Open Crate — encrypted documents, explicit access decisions](docs/assets/open-crate-banner.svg)

<div align="center">

[Get started](docs/getting-started.md) · [Documentation](docs/index.md) · [Examples](examples/README.md) ·
[Architecture](docs/architecture.md) · [Security](SECURITY.md) ·
[Licensing](docs/licensing.md) · [Website](https://closecrate.com/)

</div>

Open Crate gives Rust applications the building blocks for encrypted documents:
signed headers, authenticated chunks, recipient key slots and explicit access
decisions. It is the five-library core behind Close Crate.

Your application supplies storage, transport, keys, secure randomness and time.
The core handles the container rules, cryptography and policy evaluation.
This separation also makes the same core buildable for WebAssembly.

## What you can build

| Your project | What Open Crate contributes |
| --- | --- |
| A document viewer with controlled access | Verify headers and chunks, then evaluate view, print, clipboard and export permissions |
| A document packaging pipeline | Plan recipient slots and assemble authenticated headers around encrypted content |
| A verifier or inspection tool | Check container authenticity and integrate your own author trust store |
| An access-control integration | Process signed lease/revocation messages and evaluate time, device and policy facts |

These are integration building blocks. Your application enforces the returned
decisions and obligations. Start with the two runnable examples below.

## What is included

| Library | Responsibility |
| --- | --- |
| `oc-format` | Container layout, parsing and authenticated header verification |
| `oc-crypto` | AEAD, key derivation, signatures, key encapsulation and integrity trees |
| `oc-protocol` | Signed leases, revocation and other protocol message codecs |
| `oc-policy` | Access decisions from policy and verified caller-provided facts |
| `oc-engine` | Packing plans, per-file secrets and header assembly |

## Try it

Install Rust through rustup, then run from a terminal:

```sh
git clone https://github.com/AlexiAxAxA/OpenCrate.git
cd OpenCrate
cargo run --locked -p oc-format --example verify-header -- tests/golden/basic.cc
cargo run --locked -p oc-policy --example access-policy
```

The first example verifies a real fixture's header signature and reports an
unknown author until your application pins that identity. The second lets you
explore a policy with synthetic facts:

```text
VIEW at t=1100: ALLOW (obligations: ...)
PRINT at t=1100: DENY (no print permission)
VIEW at t=2000: DENY (lease window has ended)
```

Both run locally, without an account or server. Follow the
[step-by-step guide](docs/getting-started.md) to add the libraries to your own
Rust application, understand the output and try a damaged-header check.

## Designed to be checked

- Frozen known-answer vectors and golden headers accompany the implementation.
- First-party core crates forbid unsafe Rust. Third-party dependencies have
  their own implementations and assurance boundaries.
- Policy defaults to denial; the application must enforce every obligation.
- Hybrid key slots support ML-KEM-768 with X25519 or P-256. Hybrid protection is
  selected per slot; it does not make every signature or access path quantum-safe.

## Integration status

Pre-release libraries with frozen test vectors and an evolving Rust API.
Pin a reviewed commit in your integration. Container compatibility is documented
in [Architecture](docs/architecture.md#format-compatibility); the threat boundaries
and independent-audit status are in [Security](SECURITY.md).

The application owns key protection and enforcement. Revocation controls future
authorized access within the configured lease/offline windows; it cannot recall
plaintext already extracted by a recipient.

The guides, complete specifications and API documentation are available in English.
See [the documentation map](docs/index.md) for examples and library references.

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
