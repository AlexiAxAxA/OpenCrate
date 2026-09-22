//! X-Wing: X25519 and ML-KEM-768 hybrid, slot mechanism `kem_id = 4`.
//!
//! Normative source: `draft-connolly-cfrg-xwing-kem-10` (March 2, 2026),
//! §5.2–5.5; decision choosing this construction and its rationale:
//! `docs/format.md`, "VERSION 3 OPENED", item 1 (the item itself lives in version 4).
//! Measurements supporting the decision: `spikes/ml-kem-cost/`.
//!
//! # What readers of this code should know
//!
//! **The private half is 32 bytes, not 2400.** Both pairs grow from one
//! seed through SHAKE256, so `device.key` remains a thirty-two-byte
//! file, as before the hybrid. This is a construction property, not our
//! optimization, and must not be lost: storing an expanded ML-KEM key would introduce
//! a second key-file format.
//!
//! **The combiner label comes LAST.** An implementation written from memory placed
//! it first, a silent mistake: two parties making the same mistake agree
//! with each other and disagree with the rest of the world. Caught by the draft's
//! vectors (`tests/kat/xwing.kat`), not by reasoning.
//!
//! **The hybrid targets X25519, hence a SOFTWARE key.** TPM keys are P-256,
//! where X-Wing is undefined. Post-quantum protection and recipient hardware
//! binding are currently mutually exclusive; see `docs/threat-model.md` §2.

use crate::CryptoError;
use ml_kem::array::{Array, ArrayN};
use ml_kem::{Decapsulate, DecapsulationKey768, EncapsulationKey768, FromSeed, KeyExport};
use ml_kem::{MlKem768, TryKeyInit};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Sha3_256, Shake256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Private-half seed: BOTH pairs grow from it.
pub const SECRET_LEN: usize = 32;

/// Wire public half: `pk_M(1184) ‖ pk_X(32)`.
pub const PUBLIC_KEY_LEN: usize = 1216;

/// Wire ciphertext: `ct_M(1088) ‖ ct_X(32)`.
pub const CIPHERTEXT_LEN: usize = 1120;

/// Shared secret: SHA3-256 output.
pub const SHARED_LEN: usize = 32;

/// Encapsulation seed: `m(32)` for ML-KEM and `ek_X(32)` for X25519.
pub const ENCAPS_SEED_LEN: usize = 64;

const ML_KEM_PUBLIC_LEN: usize = 1184;
const ML_KEM_CIPHERTEXT_LEN: usize = 1088;
const EXPANDED_LEN: usize = 96;

/// Six ASCII bytes: `\./` and `/^\`.
///
/// Written as bytes rather than a string literal for a reason: a literal
/// requires escaping backslashes, and `"\./"` in Rust is not what
/// it seems. The draft's value directly: `5c2e2f2f5e5c`.
const XWING_LABEL: [u8; 6] = [0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c];

/// X-Wing combiner (§5.3 of the draft).
///
/// Neither HKDF nor HMAC: one SHA3-256 call, the draft's decision rather than our
/// simplification: the SHA3 sponge needs no HMAC construction.
///
/// Input order is essential, and the label ENDS it. Reordering produces a different
/// secret from identical values without breaking anything on one's own side.
fn combiner(ss_m: &[u8], ss_x: &[u8], ct_x: &[u8], pk_x: &[u8]) -> Zeroizing<[u8; SHARED_LEN]> {
    let mut h = Sha3_256::new();
    Digest::update(&mut h, ss_m);
    Digest::update(&mut h, ss_x);
    Digest::update(&mut h, ct_x);
    Digest::update(&mut h, pk_x);
    Digest::update(&mut h, XWING_LABEL);
    Zeroizing::new(h.finalize().into())
}

/// Expanded private half. Never exposed: both pairs are rederived from
/// the seed on every use.
///
/// The draft permits caching expansion (§5.5.1); we do NOT do so.
/// The reason is not speed: an expanded key is 2400 secret bytes living
/// as long as the cache, whereas the thirty-two-byte seed is wiped
/// immediately. The price is one expansion per file opening, around forty
/// microseconds (measured in `spikes/ml-kem-cost/`), hence negligible.
struct Expanded {
    ml_kem: DecapsulationKey768,
    x25519: StaticSecret,
    ml_kem_public: [u8; ML_KEM_PUBLIC_LEN],
    x25519_public: [u8; 32],
}

/// `expandDecapsulationKey(sk)`: §5.2 of the draft.
fn expand(secret: &[u8; SECRET_LEN]) -> Result<Expanded, CryptoError> {
    let mut xof = Shake256::default();
    Update::update(&mut xof, secret);
    let mut expanded = Zeroizing::new([0u8; EXPANDED_LEN]);
    xof.finalize_xof().read(expanded.as_mut_slice());

    // Первые 64 байта — это ровно `(d, z)` из `ML-KEM.KeyGen_internal`, то есть
    // семя в понимании `ml_kem::FromSeed`. Резать их на две половины и склеивать
    // обратно незачем.
    let seed_bytes = expanded.get(..64).ok_or(CryptoError::BadLength)?;
    let seed = ArrayN::<u8, 64>::try_from(seed_bytes).map_err(|_| CryptoError::BadLength)?;
    let (ml_kem, ml_kem_ek) = MlKem768::from_seed(&seed);

    let x_bytes: [u8; 32] = expanded
        .get(64..EXPANDED_LEN)
        .ok_or(CryptoError::BadLength)?
        .try_into()
        .map_err(|_| CryptoError::BadLength)?;
    let x25519 = StaticSecret::from(x_bytes);
    let x25519_public = PublicKey::from(&x25519).to_bytes();

    let ml_kem_public: [u8; ML_KEM_PUBLIC_LEN] =
        ml_kem_ek.to_bytes().as_slice().try_into().map_err(|_| CryptoError::BadLength)?;

    Ok(Expanded { ml_kem, x25519, ml_kem_public, x25519_public })
}

/// Public half from the seed: `pk_M ‖ pk_X`, 1216 bytes.
///
/// # Errors
/// Only mismatched lengths, impossible with a functioning library;
/// checks remain because this crate forbids panics.
pub fn public_key(secret: &[u8; SECRET_LEN]) -> Result<[u8; PUBLIC_KEY_LEN], CryptoError> {
    let expanded = expand(secret)?;
    let mut out = [0u8; PUBLIC_KEY_LEN];
    let (head, tail) = out.split_at_mut(ML_KEM_PUBLIC_LEN);
    head.copy_from_slice(&expanded.ml_kem_public);
    tail.copy_from_slice(&expanded.x25519_public);
    Ok(out)
}

/// Encapsulation with a specified seed: `EncapsulateDerand` (§5.4.1 of the draft).
///
/// Separate from [`encapsulate`] for the same reason neighbors separate
/// all deterministic operations: KATs must be reproducible, and an RNG is
/// forbidden in this crate.
///
/// # Errors
/// Incorrect public-half length or unparseable ML-KEM key.
pub fn encapsulate_derand(
    public_key: &[u8],
    seed: &[u8; ENCAPS_SEED_LEN],
) -> Result<(Zeroizing<[u8; SHARED_LEN]>, [u8; CIPHERTEXT_LEN]), CryptoError> {
    if public_key.len() != PUBLIC_KEY_LEN {
        return Err(CryptoError::BadLength);
    }
    let pk_m = public_key.get(..ML_KEM_PUBLIC_LEN).ok_or(CryptoError::BadLength)?;
    let pk_x: [u8; 32] = public_key
        .get(ML_KEM_PUBLIC_LEN..PUBLIC_KEY_LEN)
        .ok_or(CryptoError::BadLength)?
        .try_into()
        .map_err(|_| CryptoError::BadLength)?;

    // Эфемерная половина X25519. Первые 32 байта семени уходят в ML-KEM, вторые
    // сюда — порядок задан черновиком, а не удобством.
    let ek_x_bytes: [u8; 32] =
        seed.get(32..ENCAPS_SEED_LEN).ok_or(CryptoError::BadLength)?.try_into().map_err(|_| CryptoError::BadLength)?;
    let ek_x = StaticSecret::from(ek_x_bytes);
    let ct_x = PublicKey::from(&ek_x).to_bytes();
    let ss_x = ek_x.diffie_hellman(&PublicKey::from(pk_x));

    let m_bytes = seed.get(..32).ok_or(CryptoError::BadLength)?;
    let m = ArrayN::<u8, 32>::try_from(m_bytes).map_err(|_| CryptoError::BadLength)?;
    // Ключ ML-KEM разбирается ЗДЕСЬ, а не принимается на веру: `public_key`
    // приходит из подписанного заголовка, но подпись автора не обещает, что
    // байты образуют исполнимый ключ.
    let ek_m =
        EncapsulationKey768::new_from_slice(pk_m).map_err(|_| CryptoError::BadKey)?;
    let (ct_m, ss_m) = ek_m.encapsulate_deterministic(&m);

    let shared = combiner(&ss_m, ss_x.as_bytes(), &ct_x, &pk_x);

    let mut ciphertext = [0u8; CIPHERTEXT_LEN];
    let (head, tail) = ciphertext.split_at_mut(ML_KEM_CIPHERTEXT_LEN);
    head.copy_from_slice(&ct_m);
    tail.copy_from_slice(&ct_x);
    Ok((shared, ciphertext))
}

/// Encapsulate to the recipient's public half.
///
/// The RNG arrives as a parameter under the crate rule. Sixty-four bytes
/// are taken in ONE call: two consecutive calls would shift RNG consumption order,
/// on which golden artifacts depend (same reasoning as `seal::seal_p256`).
///
/// # Errors
/// Incorrect public-half length or unparseable ML-KEM key.
pub fn encapsulate<R: rand_core::CryptoRng + ?Sized>(
    public_key: &[u8],
    rng: &mut R,
) -> Result<(Zeroizing<[u8; SHARED_LEN]>, [u8; CIPHERTEXT_LEN]), CryptoError> {
    let mut seed = Zeroizing::new([0u8; ENCAPS_SEED_LEN]);
    rng.fill_bytes(seed.as_mut_slice());
    encapsulate_derand(public_key, &seed)
}

/// Decapsulation: §5.5 of the draft.
///
/// There is and can be no "invalid ciphertext" rejection here: on corrupted
/// ciphertext ML-KEM performs IMPLICIT REJECTION, deriving a secret from `z` and
/// returning it normally. This is a scheme property, not an oversight:
/// a distinguishable failure would be an oracle. The caller detects the false secret
/// using the slot commitment (I-4) and AEAD tag, both in constant time.
///
/// # Errors
/// Incorrect ciphertext length. Everything else silently yields a different secret.
pub fn decapsulate(
    secret: &[u8; SECRET_LEN],
    ciphertext: &[u8],
) -> Result<Zeroizing<[u8; SHARED_LEN]>, CryptoError> {
    if ciphertext.len() != CIPHERTEXT_LEN {
        return Err(CryptoError::BadLength);
    }
    let expanded = expand(secret)?;

    let ct_m_bytes = ciphertext.get(..ML_KEM_CIPHERTEXT_LEN).ok_or(CryptoError::BadLength)?;
    let ct_m = Array::try_from(ct_m_bytes).map_err(|_| CryptoError::BadLength)?;
    let ct_x: [u8; 32] = ciphertext
        .get(ML_KEM_CIPHERTEXT_LEN..CIPHERTEXT_LEN)
        .ok_or(CryptoError::BadLength)?
        .try_into()
        .map_err(|_| CryptoError::BadLength)?;

    let ss_m = expanded.ml_kem.decapsulate(&ct_m);
    let ss_x = expanded.x25519.diffie_hellman(&PublicKey::from(ct_x));
    Ok(combiner(&ss_m, ss_x.as_bytes(), &ct_x, &expanded.x25519_public))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// ROUND TRIP: what encapsulation seals, decapsulation recovers.
    #[test]
    fn what_is_encapsulated_comes_back_out_of_decapsulation() {
        let secret = [0x3a_u8; SECRET_LEN];
        let public = public_key(&secret).unwrap();
        let (sent, ciphertext) = encapsulate_derand(&public, &[0x5c_u8; ENCAPS_SEED_LEN]).unwrap();
        let received = decapsulate(&secret, &ciphertext).unwrap();
        assert_eq!(sent.as_slice(), received.as_slice(), "секрет не сошёлся с обеих сторон");
    }

    /// CORRUPTED CIPHERTEXT YIELDS ANOTHER SECRET, NOT REJECTION.
    ///
    /// Guards precisely this property. A rejection here would mean someone
    /// added a distinguishable branch on hostile bytes, hence an oracle.
    #[test]
    fn a_corrupted_ciphertext_yields_a_different_secret_rather_than_an_error() {
        let secret = [0x3a_u8; SECRET_LEN];
        let public = public_key(&secret).unwrap();
        let (sent, mut ciphertext) =
            encapsulate_derand(&public, &[0x5c_u8; ENCAPS_SEED_LEN]).unwrap();

        for spot in [0_usize, 1087, 1088, 1119] {
            let mut broken = ciphertext;
            if let Some(byte) = broken.get_mut(spot) {
                *byte ^= 1;
            }
            let received = decapsulate(&secret, &broken).expect("отказ вместо неявного");
            assert_ne!(sent.as_slice(), received.as_slice(), "байт {spot} не повлиял на секрет");
        }

        // И обратное: нетронутый шифротекст по-прежнему сходится.
        ciphertext[0] ^= 0;
        assert_eq!(decapsulate(&secret, &ciphertext).unwrap().as_slice(), sent.as_slice());
    }

    /// WIRE LENGTHS MATCH THE FORMAT'S PROMISE.
    ///
    /// This is not "check arithmetic" but detect a change in ML-KEM level:
    /// 1024 would yield different numbers, while the format defines length as a function of
    /// (version, `kem_id`); it cannot change for an occupied number.
    #[test]
    fn the_wire_lengths_are_the_ones_the_format_promises() {
        let secret = [0x01_u8; SECRET_LEN];
        let public = public_key(&secret).unwrap();
        assert_eq!(public.len(), 1216);
        let (_, ciphertext) = encapsulate_derand(&public, &[0x02_u8; ENCAPS_SEED_LEN]).unwrap();
        assert_eq!(ciphertext.len(), 1120);
    }

    /// WRONG LENGTH IS REJECTED BEFORE ANY WORK.
    #[test]
    fn foreign_lengths_are_refused_before_any_work() {
        let secret = [0x01_u8; SECRET_LEN];
        assert!(encapsulate_derand(&[0u8; 1215], &[0u8; ENCAPS_SEED_LEN]).is_err());
        assert!(encapsulate_derand(&[0u8; 1217], &[0u8; ENCAPS_SEED_LEN]).is_err());
        assert!(decapsulate(&secret, &[0u8; 1119]).is_err());
        assert!(decapsulate(&secret, &[0u8; 1121]).is_err());
    }

    /// THE LABEL IS LAST, TESTED RATHER THAN ASSUMED.
    ///
    /// A separate probe because the error was real: implementation from memory
    /// placed the label first. The combiner is checked against an independent computation
    /// of the same hash: reordering inputs causes divergence right here,
    /// not a year later in a second implementation.
    #[test]
    fn the_label_terminates_the_combiner_input() {
        let (ss_m, ss_x, ct_x, pk_x) = ([1_u8; 32], [2_u8; 32], [3_u8; 32], [4_u8; 32]);
        let mut expected = Sha3_256::new();
        Digest::update(&mut expected, [1_u8; 32]);
        Digest::update(&mut expected, [2_u8; 32]);
        Digest::update(&mut expected, [3_u8; 32]);
        Digest::update(&mut expected, [4_u8; 32]);
        Digest::update(&mut expected, [0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c]);
        let expected: [u8; 32] = expected.finalize().into();
        assert_eq!(combiner(&ss_m, &ss_x, &ct_x, &pk_x).as_slice(), expected);
    }
}
