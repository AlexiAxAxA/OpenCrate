# oc-crypto

Cryptographic operations used by the Open Crate format and protocol.

[Documentation](https://github.com/AlexiAxAxA/OpenCrate/blob/main/docs/index.md) · [Key scheme](https://github.com/AlexiAxAxA/OpenCrate/blob/main/docs/format.md) · [Source](https://github.com/AlexiAxAxA/OpenCrate/blob/main/crates/oc-crypto/src/lib.rs)

The crate supplies authenticated encryption, key derivation, signatures, sealing,
integrity trees and hybrid key mechanisms. Frozen known-answer vectors in
[`tests/kat`](https://github.com/AlexiAxAxA/OpenCrate/blob/main/tests/kat/) support reproducibility of these operations.

Its low-level operations accept byte slices; they do not check filenames or
extensions. For a small standalone sealed-byte envelope with OS randomness,
use [`opencrate-sdk`](https://github.com/AlexiAxAxA/OpenCrateSDK) or the
`opencrate` facade's `app-data` feature. The SDK uses this crate's sealing and
AEAD primitives; its `OCSB1` envelope is separate from the `.cc` container.

Use the existing domain-separated operations when integrating the format;
constructing an apparently equivalent nonce or key schedule can produce different
bytes and different security properties. Secure randomness is supplied by the host.

Hybrid protection is a property of the chosen recipient path. It does not turn
classical signatures or every alternative slot into post-quantum protection.
See the [security boundary](https://github.com/AlexiAxAxA/OpenCrate/blob/main/SECURITY.md).

From the repository root, build the reference with `cargo doc -p oc-crypto --no-deps`.
Test-only explicit-nonce, signer and label facilities are not production defaults.

## License

Licensed under [MPL-2.0](https://github.com/AlexiAxAxA/OpenCrate/blob/main/LICENSE).
