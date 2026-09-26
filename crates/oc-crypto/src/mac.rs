// SPDX-License-Identifier: MPL-2.0
//! Message authentication codes.
//!
//! A separate module because MACs serve where signatures cannot:
//! the container's mutable region is authenticated by whoever holds the content key,
//! not by the author. The author is absent when the file is edited and physically
//! cannot sign the modified content.
//!
//! Input is only [`Transcript`], as with signatures. A domain label is mandatory for the
//! same reason: a MAC computed in one context must not be accepted in another.

use crate::secret::MacKey;
use crate::transcript::Transcript;
use crate::CryptoError;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

/// Authentication-code length.
pub const MAC_LEN: usize = 32;

/// Compute HMAC-SHA256 over a transcript.
pub fn compute(key: &MacKey, transcript: &Transcript) -> Result<[u8; MAC_LEN], CryptoError> {
    // Длина ключа фиксирована типом, поэтому отказ здесь недостижим; но паника в
    // этом крейте запрещена, и «недостижимо» проверяется компилятором, а не
    // комментарием.
    let mut mac = <Hmac<Sha256> as hmac::KeyInit>::new_from_slice(key.expose())
        .map_err(|_| CryptoError::BadLength)?;
    mac.update(transcript.as_bytes());
    let tag = mac.finalize().into_bytes();
    <[u8; MAC_LEN]>::try_from(tag.as_slice()).map_err(|_| CryptoError::BadLength)
}

/// Verify an authentication code.
///
/// Comparison must be constant-time. Ordinary array comparison exits
/// at the first mismatching byte, letting an adversary guess the tag byte by byte
/// from response timing, in 32×256 attempts rather than 2^256.
pub fn verify(
    key: &MacKey,
    transcript: &Transcript,
    expected: &[u8; MAC_LEN],
) -> Result<(), CryptoError> {
    let actual = compute(key, transcript)?;
    if bool::from(actual.ct_eq(expected)) {
        Ok(())
    } else {
        Err(CryptoError::Authentication)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::label;

    fn key(seed: u8) -> MacKey {
        MacKey::from_bytes([seed; 32])
    }

    fn transcript(domain: crate::label::Label, data: &[u8]) -> Transcript {
        let mut t = Transcript::new(domain);
        t.field(data);
        t
    }

    #[test]
    fn a_mac_verifies_under_the_key_that_produced_it() {
        let t = transcript(label::CONTENT_MAC, b"total_len=42");
        let tag = compute(&key(1), &t).unwrap();
        assert_eq!(verify(&key(1), &t, &tag), Ok(()));
    }

    #[test]
    fn a_mac_never_verifies_under_a_foreign_key() {
        let t = transcript(label::CONTENT_MAC, b"total_len=42");
        let tag = compute(&key(1), &t).unwrap();
        assert_eq!(verify(&key(2), &t, &tag), Err(CryptoError::Authentication));
    }

    #[test]
    fn a_mac_does_not_carry_over_to_another_domain_label() {
        // Тот же ключ и те же данные под другой меткой обязаны давать другой тег,
        // иначе MAC изменяемой области принимался бы как MAC чего-то ещё.
        let a = transcript(label::CONTENT_MAC, b"same data");
        let b = transcript(label::AUDIT_ENTRY, b"same data");
        let tag = compute(&key(1), &a).unwrap();
        assert_eq!(verify(&key(1), &b, &tag), Err(CryptoError::Authentication));
    }

    #[test]
    fn changing_one_byte_of_the_data_breaks_the_mac() {
        let tag = compute(&key(1), &transcript(label::CONTENT_MAC, b"version=7")).unwrap();
        let tampered = transcript(label::CONTENT_MAC, b"version=8");
        assert_eq!(verify(&key(1), &tampered, &tag), Err(CryptoError::Authentication));
    }

    #[test]
    fn a_tag_differing_only_in_the_last_byte_is_refused() {
        // Проверка постоянного времени обязана ловить несовпадение в любой
        // позиции, а не только в первой.
        let t = transcript(label::CONTENT_MAC, b"payload");
        let mut tag = compute(&key(1), &t).unwrap();
        let last = tag.len().saturating_sub(1);
        if let Some(byte) = tag.get_mut(last) {
            *byte ^= 0x01;
        }
        assert_eq!(verify(&key(1), &t, &tag), Err(CryptoError::Authentication));
    }
}
