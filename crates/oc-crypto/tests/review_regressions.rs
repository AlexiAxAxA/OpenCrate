// SPDX-License-Identifier: MPL-2.0
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
use oc_crypto::agreement::{KeyAgreement, P256Agreement};
use oc_crypto::{CryptoError, mlkem_p256, seal, secret::X25519Secret};

// Repeatable RNG for format and rejection checks only.
struct Fixed;
impl rand_core::TryRng for Fixed {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> { Ok(0x42424242) }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> { Ok(0x4242424242424242) }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        dest.fill(0x42);
        Ok(())
    }
}
impl rand_core::TryCryptoRng for Fixed {}

#[test]
fn hybrid_pair_debug_redacts_the_mlkem_seed() {
    let pair = mlkem_p256::keypair_from_seed(&[0x31; 32]).unwrap();
    let secret_rendering = format!("{:?}", pair.ml_kem_seed.as_slice());
    assert!(!format!("{pair:?}").contains(&secret_rendering),
        "Keypair Debug exposes the ML-KEM seed");
    assert!(format!("{pair:?}").contains("<redacted>"));
}

#[test]
fn compressed_p256_recipient_is_refused_before_sealing() {
    let recipient = P256Agreement::from_be_bytes(&[0x11; 32]).unwrap();
    let public = recipient.public_key();
    let valid = seal::seal_p256(&public, b"info", b"aad", b"secret", &mut Fixed).unwrap();
    assert_eq!(&*seal::open_with(&recipient, &valid, b"info", b"aad").unwrap(), b"secret");
    let mut compressed = vec![0x02 | (public[64] & 1)];
    compressed.extend_from_slice(&public[1..33]);
    // The point and DH result match; only the transcript encoding differs.
    assert!(recipient.agree(&compressed).unwrap().ct_eq(&recipient.agree(&public).unwrap()));
    let result = seal::seal_p256(&compressed, b"info", b"aad", b"secret", &mut Fixed);
    if let Ok(ref unusable) = result {
        assert!(seal::open_with(&recipient, unusable, b"info", b"aad").is_err());
    }
    assert!(matches!(result, Err(CryptoError::BadLength)));
}

#[test]
fn noncanonical_x25519_recipient_is_refused_before_sealing() {
    let recipient = X25519Secret::from_bytes([0x11; 32]);
    let public = seal::x25519_public(&recipient);
    let valid = seal::seal(&public, b"info", b"aad", b"secret", &mut Fixed).unwrap();
    assert_eq!(&*seal::open(&recipient, &valid, b"info", b"aad").unwrap(), b"secret");
    let mut alias = public;
    alias[31] |= 0x80;
    let agreement = oc_crypto::agreement::X25519Agreement::new(&recipient);
    assert!(agreement.agree(&alias).unwrap().ct_eq(&agreement.agree(&public).unwrap()));
    let result = seal::seal(&alias, b"info", b"aad", b"secret", &mut Fixed);
    if let Ok(ref unusable) = result {
        assert!(seal::open(&recipient, unusable, b"info", b"aad").is_err());
    }
    assert!(matches!(result, Err(CryptoError::BadKey)));
}
