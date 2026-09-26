// SPDX-License-Identifier: MPL-2.0
//! TPM 2.0 credential protection: the computable part of `TPM2_MakeCredential`
//! (B6a, `docs/protocol.md` §9.11).
//!
//! # Why in the core
//!
//! The server binds an attestation key to an endorsement key through credential
//! activation: it encrypts a secret so only the TPM containing both keys
//! can open it. Apart from the block cipher, everything is hash computation without
//! I/O, clocks, or an RNG: the seed is a parameter, like every source
//! of randomness in this crate, and every test is deterministic.
//!
//! # The form is not ours
//!
//! TPM 2.0, part 1, "Credential Protection", and KDFa from the same part (SP 800-108
//! in HMAC counter mode). Labels `"STORAGE"`, `"INTEGRITY"`, and `"IDENTITY"`
//! belong to the TPM specification, not the domain-label registry (I-12): we did not
//! choose them and cannot change them. Labels are supplied WITH the trailing
//! zero, as the reference TPM implementation hashes them and real TPMs
//! expect them; a discrepancy would silently produce credentials no TPM could
//! open. Thus the form is confirmed by activation using
//! a software TPM (`crates/cc-authority/tests/attest/`), not merely by reading the specification.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

/// Seed length: SHA-256 digest, the endorsement key's `nameAlg`.
pub const SEED_LEN: usize = 32;
/// Credential symmetric-key length: AES-128.
pub const STORAGE_KEY_LEN: usize = 16;
/// OAEP label for encrypting the seed to the endorsement key, including zero.
pub const IDENTITY_LABEL: &[u8] = b"IDENTITY\0";

const STORAGE: &[u8] = b"STORAGE\0";
const INTEGRITY: &[u8] = b"INTEGRITY\0";

/// KDFa(SHA-256): `K(i) = HMAC(key, u32(i) ‖ label ‖ contextU ‖ contextV ‖ u32(L))`.
///
/// The label already includes a trailing zero. Output length is a whole number of bytes;
/// only two lengths occur here (128 and 256 bits), so no trailing mask is needed.
fn kdfa(key: &[u8], label: &[u8], context_u: &[u8], context_v: &[u8], out: &mut [u8]) {
    let bits = u32::try_from(out.len().saturating_mul(8)).unwrap_or(u32::MAX).to_be_bytes();
    for (counter, chunk) in (1u32..).zip(out.chunks_mut(32)) {
        // `new_from_slice` у HMAC принимает ключ любой длины: ошибка недостижима.
        if let Ok(mut mac) = <Hmac<Sha256> as KeyInit>::new_from_slice(key) {
            mac.update(&counter.to_be_bytes());
            mac.update(label);
            mac.update(context_u);
            mac.update(context_v);
            mac.update(&bits);
            let block = Zeroizing::new(mac.finalize().into_bytes());
            let take = chunk.len();
            if let Some(head) = block.get(..take) {
                chunk.copy_from_slice(head);
            }
        }
    }
}

/// Credential AES-128 key: `KDFa(seed, "STORAGE", object name, empty, 128)`.
#[must_use]
pub fn storage_key(seed: &[u8; SEED_LEN], object_name: &[u8]) -> Zeroizing<[u8; STORAGE_KEY_LEN]> {
    let mut key = Zeroizing::new([0u8; STORAGE_KEY_LEN]);
    kdfa(seed, STORAGE, object_name, &[], key.as_mut_slice());
    key
}

/// Credential integrity: `HMAC(KDFa(seed, "INTEGRITY", empty, empty, 256),
/// encIdentity ‖ object name)`.
///
/// The object name enters here, making credentials addressed: the TPM
/// computes the tag using the name of the key requested for activation; a wrong
/// key gets a mismatch rather than the secret.
#[must_use]
pub fn integrity_tag(seed: &[u8; SEED_LEN], enc_identity: &[u8], object_name: &[u8]) -> [u8; 32] {
    let mut hmac_key = Zeroizing::new([0u8; 32]);
    kdfa(seed, INTEGRITY, &[], &[], hmac_key.as_mut_slice());
    let mut tag = [0u8; 32];
    if let Ok(mut mac) = <Hmac<Sha256> as KeyInit>::new_from_slice(hmac_key.as_slice()) {
        mac.update(enc_identity);
        mac.update(object_name);
        tag.copy_from_slice(mac.finalize().into_bytes().as_slice());
    }
    tag
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// Key and tag depend on object name and seed, or credentials
    /// would be neither addressed nor single-use.
    #[test]
    fn keys_depend_on_the_seed_and_the_name() {
        let seed = [7u8; SEED_LEN];
        let name_a = [1u8; 34];
        let name_b = [2u8; 34];
        assert_ne!(*storage_key(&seed, &name_a), *storage_key(&seed, &name_b));
        assert_ne!(*storage_key(&seed, &name_a), *storage_key(&[8u8; SEED_LEN], &name_a));
        assert_ne!(integrity_tag(&seed, b"x", &name_a), integrity_tag(&seed, b"x", &name_b));
        assert_ne!(integrity_tag(&seed, b"x", &name_a), integrity_tag(&seed, b"y", &name_a));
    }

    /// Labels include a terminating zero: without it KDFa yields another key, and the TPM
    /// will not open the credentials. Guards against "remove the extra zero" edits.
    #[test]
    fn tpm_labels_carry_their_terminating_zero() {
        for label in [STORAGE, INTEGRITY, IDENTITY_LABEL] {
            assert_eq!(label.last(), Some(&0u8));
            assert_eq!(label.iter().filter(|b| **b == 0).count(), 1);
        }
    }

    /// Output longer than one HMAC block concatenates blocks with counters 1, 2…
    #[test]
    fn kdfa_counter_starts_at_one_and_advances() {
        let mut long = [0u8; 40];
        kdfa(b"key", b"L\0", b"u", b"v", &mut long);
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(b"key").unwrap();
        mac.update(&1u32.to_be_bytes());
        mac.update(b"L\0uv");
        mac.update(&320u32.to_be_bytes());
        assert_eq!(&long[..32], mac.finalize().into_bytes().as_slice());
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(b"key").unwrap();
        mac.update(&2u32.to_be_bytes());
        mac.update(b"L\0uv");
        mac.update(&320u32.to_be_bytes());
        assert_eq!(&long[32..], &mac.finalize().into_bytes()[..8]);
    }
}
