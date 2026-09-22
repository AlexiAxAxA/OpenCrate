# Getting started

The pinned Rust toolchain is in `rust-toolchain.toml`. These packages are not
published to crates.io. Start with a source checkout and path dependencies, and
pin a reviewed source revision and lockfile in your own integration.

```toml
[dependencies]
oc-format = { path = "../OpenCrate/crates/oc-format" }
oc-crypto = { path = "../OpenCrate/crates/oc-crypto" }
oc-protocol = { path = "../OpenCrate/crates/oc-protocol" }
oc-policy = { path = "../OpenCrate/crates/oc-policy" }
oc-engine = { path = "../OpenCrate/crates/oc-engine" }
```

Run the checked-in example:

```sh
cargo run --locked -p oc-format --example verify-header -- tests/golden/basic.cc
```

Expected: the signature verifies, and the example reports an **unknown author**.
Committed fixtures use test inputs. Never reuse their keys in an application.
Successful parsing is not an authorization decision.

## Recipient integration

1. Bound input sizes before allocating. Authenticate the header with
   `oc_format::verify::verify_and_parse`; require an appropriate `SignerTrust`.
2. Select a supported recipient slot and validate the target device binding.
3. Verify the lease signature, then decode the lease. Bind it to the same file,
   policy, authority and device. Apply current revocation evidence.
4. Populate `oc_policy::Context` from verified state. Protect sequence numbers,
   counters and time floors from replay and rollback.
5. Call `oc_policy::evaluate`. Enforce both the verdict and its obligations;
   deny access if your application cannot implement an obligation.
6. Authenticate each chunk before exposing its plaintext. Reevaluate expiration
   and revocation during a session, and clear sensitive buffers on failure.

The core does not provide `open(path)`. A complete recipient application must
implement this orchestration, transport and persistent state.

## Packing integration

Choose valid public keys and policy; validate chunk size with
`oc_format::check_chunk_size`. Call `oc_engine::plan` with caller-provided secure
entropy. Stream encryption according to the format, construct `SealedInfo` from
the actual output, and consume the session with `Session::assemble`. Derive and
sign the transcript from the final header bytes. Publish the completed file
atomically in the host application.

Keep the request consistent across planning and assembly. Treat `Session` and
`Plan` as sensitive. Use the existing nonce, AEAD and key-derivation APIs; do not
replace them with an apparently equivalent construction. Test-only features
`explicit-nonce`, `test-signer` and `ad-hoc-label` are not production defaults.

## Validate your integration

Test valid and wrong recipients, damaged signatures/MACs/chunks, mismatched and
expired leases, replay, clock rollback, network loss, restart and old-state
restoration. Test fail-closed enforcement of obligations. An author-only success
does not validate the recipient path. Check output against an independent reader.

Build the API reference with `cargo doc --locked --workspace --no-deps`.
The full normative format and protocol documents are included in this candidate
for fidelity, but are awaiting an English translation and publication review.
