// SPDX-License-Identifier: MPL-2.0
#![allow(clippy::unwrap_used)]

use core::cell::Cell;
use oc_crypto::{AeadAlg, CryptoError, PayloadKey, stream::{StreamError, seal_chunks}};

#[derive(Default)]
struct CountingRng { draws: usize }

impl rand_core::TryRng for CountingRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.draws = self.draws.saturating_add(1);
        Ok(0x42424242)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.draws = self.draws.saturating_add(1);
        Ok(0x4242424242424242)
    }

    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Self::Error> {
        self.draws = self.draws.saturating_add(1);
        bytes.fill(0x42);
        Ok(())
    }
}

impl rand_core::TryCryptoRng for CountingRng {}

#[test]
fn xwing_seal_rejects_noncanonical_classical_key_before_rng() {
    let secret = [0x31; oc_crypto::xwing::SECRET_LEN];
    let public = oc_crypto::xwing::public_key(&secret).unwrap();
    let canonical = oc_crypto::seal::seal_xwing(
        &public, b"context", b"aad", b"secret", &mut CountingRng::default(),
    ).unwrap();
    let opened = oc_crypto::seal::open_xwing(&secret, &canonical, b"context", b"aad")
        .unwrap();
    assert_eq!(opened.as_slice(), b"secret");
    let mut alias = public;
    *alias.last_mut().unwrap() |= 0x80;
    let mut rng = CountingRng::default();
    let result = oc_crypto::seal::seal_xwing(&alias, b"context", b"aad", b"secret", &mut rng);
    if let Ok(blob) = &result {
        assert!(oc_crypto::seal::open_xwing(&secret, blob, b"context", b"aad").is_err(), "control did not reproduce mismatch");
    }
    assert!(matches!(result, Err(CryptoError::BadKey)), "noncanonical X-Wing key accepted");
    assert_eq!(rng.draws, 0);
}

#[test]
fn zero_chunk_size_is_rejected_before_callbacks_or_rng() {
    let reads = Cell::new(0_usize);
    let writes = Cell::new(0_usize);
    let mut rng = CountingRng::default();
    let result = seal_chunks(
        &PayloadKey::from_bytes([0x31; 32]),
        AeadAlg::XChaCha20Poly1305, &[0x42; 16], 0, &mut rng,
        |_| { reads.set(reads.get().saturating_add(1)); Ok::<_, core::convert::Infallible>(0) },
        |_| { writes.set(writes.get().saturating_add(1)); Ok(()) },
    );
    assert!(matches!(result, Err(StreamError::Crypto(CryptoError::BadLength))), "zero capacity accepted");
    assert_eq!(reads.get(), 0);
    assert_eq!(writes.get(), 0);
    assert_eq!(rng.draws, 0);
}
