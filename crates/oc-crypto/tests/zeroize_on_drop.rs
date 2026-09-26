// SPDX-License-Identifier: MPL-2.0
//! Require dependency secret types to implement `ZeroizeOnDrop`.
//!
//! Agreement copies use `x25519_dalek::StaticSecret` and `SharedSecret`; their
//! cleanup depends on the `zeroize` feature. These trait bounds fail compilation
//! if feature selection removes that cleanup. They do not prove stack-copy erasure.

fn zeroizes_on_drop<T: zeroize::ZeroizeOnDrop>() {}

#[test]
fn foreign_secret_types_zeroize_on_drop() {
    zeroizes_on_drop::<x25519_dalek::StaticSecret>();
    zeroizes_on_drop::<x25519_dalek::EphemeralSecret>();
    zeroizes_on_drop::<oc_crypto::secret::X25519Secret>();
    zeroizes_on_drop::<oc_crypto::secret::SecretA>();
    zeroizes_on_drop::<oc_crypto::secret::SecretB>();
}
