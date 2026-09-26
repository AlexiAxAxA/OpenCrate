// SPDX-License-Identifier: MPL-2.0
#![allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
use oc_crypto::agreement::{KeyAgreement, P256Agreement};
use oc_crypto::{CryptoError, mlkem_p256, seal, secret::X25519Secret};

// Повторяемый RNG только для проб; счётчик подтверждает отказ до расхода энтропии.
#[derive(Default)]
struct Fixed {
    fills: usize,
}
impl rand_core::TryRng for Fixed {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(0x42424242)
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(0x4242424242424242)
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        self.fills = self.fills.saturating_add(1);
        dest.fill(0x42);
        Ok(())
    }
}
impl rand_core::TryCryptoRng for Fixed {}

#[test]
fn hybrid_pair_debug_redacts_the_mlkem_seed() {
    let mut pair = mlkem_p256::keypair_from_seed(&[0x31; 32]).unwrap();
    let secret_rendering = format!("{:?}", pair.ml_kem_seed.as_slice());
    let shown = format!("{pair:?}");
    let pretty = format!("{pair:#?}");
    assert!(!shown.contains(&secret_rendering), "Keypair Debug exposes the ML-KEM seed");
    assert!(shown.contains("<redacted>"));
    pair.ml_kem_seed.fill(0x7b);
    pair.classical = P256Agreement::from_be_bytes(&[0x12; 32]).unwrap();
    // Не печатаем значения в assert: старый Debug сам содержит секрет.
    assert!(shown == format!("{pair:?}"), "secret fields affect Debug");
    assert!(pretty == format!("{pair:#?}"), "secret fields affect pretty Debug");
}

#[test]
fn compressed_p256_recipient_is_refused_before_sealing() {
    let recipient = P256Agreement::from_be_bytes(&[0x11; 32]).unwrap();
    let public = recipient.public_key();
    let valid =
        seal::seal_p256(&public, b"info", b"aad", b"secret", &mut Fixed::default()).unwrap();
    assert_eq!(&*seal::open_with(&recipient, &valid, b"info", b"aad").unwrap(), b"secret");
    let mut compressed = vec![0x02 | (public[64] & 1)];
    compressed.extend_from_slice(&public[1..33]);
    // Точка и DH совпадают; различаются только байты контекста KDF.
    assert!(recipient.agree(&compressed).unwrap().ct_eq(&recipient.agree(&public).unwrap()));
    let mut rng = Fixed::default();
    let result = seal::seal_p256(&compressed, b"info", b"aad", b"secret", &mut rng);
    if let Ok(ref unusable) = result {
        assert!(seal::open_with(&recipient, unusable, b"info", b"aad").is_err());
    }
    assert!(matches!(result, Err(CryptoError::BadLength)));
    assert_eq!(rng.fills, 0);
}

#[test]
fn noncanonical_x25519_recipient_is_refused_before_sealing() {
    let recipient = X25519Secret::from_bytes([0x11; 32]);
    let public = seal::x25519_public(&recipient);
    let valid = seal::seal(&public, b"info", b"aad", b"secret", &mut Fixed::default()).unwrap();
    assert_eq!(&*seal::open(&recipient, &valid, b"info", b"aad").unwrap(), b"secret");
    let agreement = oc_crypto::agreement::X25519Agreement::new(&recipient);
    assert_eq!(&*seal::open_with(&agreement, &valid, b"info", b"aad").unwrap(), b"secret");
    let mut alias = public;
    alias[31] |= 0x80;
    assert!(agreement.agree(&alias).unwrap().ct_eq(&agreement.agree(&public).unwrap()));
    let mut rng = Fixed::default();
    let result = seal::seal(&alias, b"info", b"aad", b"secret", &mut rng);
    if let Ok(ref unusable) = result {
        assert!(seal::open(&recipient, unusable, b"info", b"aad").is_err());
    }
    assert!(matches!(result, Err(CryptoError::BadKey)));
    assert_eq!(rng.fills, 0);
}

fn compressed_p256(public: &[u8]) -> Vec<u8> {
    let mut compressed = vec![0x02 | (public[64] & 1)];
    compressed.extend_from_slice(&public[1..33]);
    compressed
}

#[test]
fn unsupported_p256_encodings_are_refused_before_entropy() {
    let pair = P256Agreement::from_be_bytes(&[0x11; 32]).unwrap();
    let public = pair.public_key();
    let mut hybrid = public.clone();
    hybrid[0] = 0x06 | (public[64] & 1);
    let mut wrong_prefix = public.clone();
    wrong_prefix[0] = 0x05;
    let mut overlong = public.clone();
    overlong.push(0);
    for key in [vec![], vec![0], public[..64].to_vec(), overlong, hybrid, wrong_prefix] {
        let mut rng = Fixed::default();
        assert!(matches!(
            seal::seal_p256(&key, b"info", b"aad", b"secret", &mut rng),
            Err(CryptoError::BadLength)
        ));
        assert_eq!(rng.fills, 0);
    }
}

#[test]
fn off_curve_uncompressed_p256_is_refused_before_entropy() {
    let mut invalid = [0; 65];
    invalid[0] = 0x04;
    let mut rng = Fixed::default();
    assert!(matches!(
        seal::seal_p256(&invalid, b"info", b"aad", b"secret", &mut rng),
        Err(CryptoError::BadKey)
    ));
    assert_eq!(rng.fills, 0);
}

#[test]
fn reduced_x25519_coordinate_alias_is_refused() {
    let secret = X25519Secret::from_bytes([0x11; 32]);
    let agreement = oc_crypto::agreement::X25519Agreement::new(&secret);
    let mut basepoint = [0; 32];
    basepoint[0] = 9;
    let mut alias = [0xff; 32];
    alias[0] = 0xf6; // p + 9, little-endian.
    alias[31] = 0x7f;
    assert!(agreement.agree(&basepoint).unwrap().ct_eq(&agreement.agree(&alias).unwrap()));
    assert!(seal::seal(&basepoint, b"info", b"aad", b"secret", &mut Fixed::default()).is_ok());
    let mut rng = Fixed::default();
    assert!(matches!(
        seal::seal(&alias, b"info", b"aad", b"secret", &mut rng),
        Err(CryptoError::BadKey)
    ));
    assert_eq!(rng.fills, 0);
}

#[test]
fn all_x25519_coordinates_from_modulus_to_high_bit_are_refused_before_entropy() {
    // Все 19 записей p..2^255-1 должны отвергаться, даже если DH ненулевой.
    for first in 0xed..=0xff {
        let mut public = [0xff; 32];
        public[0] = first;
        public[31] = 0x7f;
        let mut rng = Fixed::default();
        assert!(matches!(
            seal::seal(&public, b"info", b"aad", b"secret", &mut rng),
            Err(CryptoError::BadKey)
        ));
        assert_eq!(rng.fills, 0);
    }
}

#[test]
fn x25519_opening_refuses_noncanonical_ephemeral_keys() {
    let secret = X25519Secret::from_bytes([0x11; 32]);
    let agreement = oc_crypto::agreement::X25519Agreement::new(&secret);
    let valid = seal::seal(
        &seal::x25519_public(&secret),
        b"info",
        b"aad",
        b"secret",
        &mut Fixed::default(),
    )
    .unwrap();
    let mut high_bit = valid.enc.clone();
    high_bit[31] |= 0x80;
    let mut reduced = vec![0xff; 32];
    reduced[0] = 0xf6;
    reduced[31] = 0x7f;
    for enc in [high_bit, reduced] {
        let blob = seal::SealedBlob { enc, ..valid.clone() };
        assert!(matches!(seal::open(&secret, &blob, b"info", b"aad"), Err(CryptoError::BadKey)));
        assert!(matches!(
            seal::open_with(&agreement, &blob, b"info", b"aad"),
            Err(CryptoError::BadKey)
        ));
    }
}

#[test]
fn p256_opening_refuses_compressed_ephemeral_keys() {
    let recipient = P256Agreement::from_be_bytes(&[0x11; 32]).unwrap();
    let mut blob =
        seal::seal_p256(&recipient.public_key(), b"info", b"aad", b"secret", &mut Fixed::default())
            .unwrap();
    blob.enc = compressed_p256(&blob.enc);
    assert!(matches!(
        seal::open_with(&recipient, &blob, b"info", b"aad"),
        Err(CryptoError::BadLength)
    ));
}

struct PublicOverride<'a> {
    inner: &'a dyn KeyAgreement,
    public: Vec<u8>,
    calls: core::cell::Cell<usize>,
}

impl KeyAgreement for PublicOverride<'_> {
    fn public_key(&self) -> Vec<u8> {
        self.public.clone()
    }
    fn agree(&self, peer: &[u8]) -> Result<oc_crypto::agreement::SharedSecret, CryptoError> {
        self.calls.set(self.calls.get().saturating_add(1));
        self.inner.agree(peer)
    }
}

#[test]
fn opening_refuses_noncanonical_provider_keys_before_agreement() {
    let p256 = P256Agreement::from_be_bytes(&[0x11; 32]).unwrap();
    let blob =
        seal::seal_p256(&p256.public_key(), b"info", b"aad", b"secret", &mut Fixed::default())
            .unwrap();
    let provider = PublicOverride {
        inner: &p256,
        public: compressed_p256(&p256.public_key()),
        calls: core::cell::Cell::new(0),
    };
    assert!(matches!(
        seal::open_with(&provider, &blob, b"info", b"aad"),
        Err(CryptoError::BadLength)
    ));
    assert_eq!(provider.calls.get(), 0);

    let secret = X25519Secret::from_bytes([0x11; 32]);
    let x25519 = oc_crypto::agreement::X25519Agreement::new(&secret);
    let mut public = x25519.public_key();
    let blob = seal::seal(
        &seal::x25519_public(&secret),
        b"info",
        b"aad",
        b"secret",
        &mut Fixed::default(),
    )
    .unwrap();
    public[31] |= 0x80;
    let provider = PublicOverride { inner: &x25519, public, calls: core::cell::Cell::new(0) };
    assert!(matches!(seal::open_with(&provider, &blob, b"info", b"aad"), Err(CryptoError::BadKey)));
    assert_eq!(provider.calls.get(), 0);
}
