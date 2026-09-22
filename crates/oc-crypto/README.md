# oc-crypto

Cryptographic operations used by the Open Crate format and protocol.

[Documentation](../../docs/index.md) · [Key scheme](../../docs/format.md) · [Source](src/lib.rs)

The crate supplies authenticated encryption, key derivation, signatures, sealing,
integrity trees and hybrid key mechanisms. Frozen known-answer vectors in
[`tests/kat`](../../tests/kat/) support reproducibility of these operations.

Use the existing domain-separated operations when integrating the format;
constructing an apparently equivalent nonce or key schedule can produce different
bytes and different security properties. Secure randomness is supplied by the host.

Hybrid protection is a property of the chosen recipient path. It does not turn
classical signatures or every alternative slot into post-quantum protection.
See the [security boundary](../../SECURITY.md).

From the repository root, build the reference with `cargo doc -p oc-crypto --no-deps`.
Test-only explicit-nonce, signer and label facilities are not production defaults.
