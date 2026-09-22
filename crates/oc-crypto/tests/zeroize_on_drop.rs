//! Secrets from dependency crates wipe on destruction too, not just ours.
//!
//! `seal::open` COPIES the long-term device secret into
//! `x25519_dalek::StaticSecret` for `diffie_hellman`, and the agreement result
//! lives in `SharedSecret`. Both are stack-resident, untouched by a wiping
//! allocator: only the type's own `Drop` wipes them. For `x25519-dalek`, the
//! `zeroize` feature controls this; `default-features = false` removes it with the others,
//! which is exactly what happened (review 2026-09-06): `Drop` was empty, leaving the device
//! secret copy unchanged in the stack frame.
//!
//! The check is at type level: without the feature, `StaticSecret` lacks `ZeroizeOnDrop`,
//! and this file fails to compile. Compilation proves the feature is enabled.

fn zeroizes_on_drop<T: zeroize::ZeroizeOnDrop>() {}

#[test]
fn foreign_secret_types_zeroize_on_drop() {
    zeroizes_on_drop::<x25519_dalek::StaticSecret>();
    zeroizes_on_drop::<x25519_dalek::EphemeralSecret>();
    zeroizes_on_drop::<oc_crypto::secret::X25519Secret>();
    zeroizes_on_drop::<oc_crypto::secret::SecretA>();
    zeroizes_on_drop::<oc_crypto::secret::SecretB>();
}
