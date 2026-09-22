//! MLKEM768-P256: ML-KEM-768 and ECDH P-256 hybrid, slot mechanism `kem_id = 5`.
//!
//! Normative source: `draft-irtf-cfrg-concrete-hybrid-kems-03`, §4.1 and A.1.
//! This is a CFRG DRAFT, not a completed RFC, explicitly described that way in the decision
//! (`docs/format.md`, version 4, item 1). Feasibility evidence and a live
//! probe with a real TPM: `spikes/p256-mlkem-tpm/`.
//!
//! # Why alongside X-Wing rather than replacing it
//!
//! X-Wing is defined over X25519, while Platform Crypto Provider offers only ECDH
//! P-256. With just one hybrid, one had to choose between post-quantum
//! protection and a key never leaving the TPM. Here no choice is necessary: the classical
//! half resides in the TPM, the post-quantum half beside it, and an adversary needs BOTH:
//! disk theft yields only the latter, a quantum computer only the former.
//!
//! # Why not the TLS group `SecP256r1MLKEM768` (RFC 10024)
//!
//! Because its rationale relies on the TLS transcript (§6 of that RFC),
//! which cannot be transferred to a standalone KEM inside a file. IANA number 4587
//! identifies a TLS group, not our mechanism. That mistake was written into
//! the specification and corrected there.
//!
//! # What readers of this code should know
//!
//! **It has its own combiner; outer K10 does not replace it.** The shared secret uses
//! one SHA3-256 call over five values, the last being the label.
//! Order is essential: reordering produces a different secret while breaking nothing on
//! one's own side.
//!
//! **The P-256 scalar uses REJECTION SAMPLING.** Any thirty-two-byte string is
//! valid for X25519, but not for P-256: the scalar must be within the group order.
//! Both the key seed and encapsulation seed therefore include spare bytes,
//! from which the first valid piece is taken. Without the reserve, the number of attempts
//! would make construction nondeterministic; with it, bytes determine the result.

use crate::CryptoError;
use crate::agreement::{KeyAgreement, P256Agreement};
use ml_kem::array::{Array, ArrayN};
use ml_kem::{Decapsulate, DecapsulationKey768, EncapsulationKey768, FromSeed, KeyExport};
use ml_kem::{MlKem768, TryKeyInit};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Sha3_256, Shake256};
use zeroize::Zeroizing;

/// Wire public half: `pk_M(1184) ‖ pk_P256(65)`.
pub const PUBLIC_KEY_LEN: usize = 1249;

/// Wire ciphertext: `ct_M(1088) ‖ eph_P256(65)`.
pub const CIPHERTEXT_LEN: usize = 1153;

/// Shared secret: SHA3-256 output.
pub const SHARED_LEN: usize = 32;

/// ML-KEM seed: `d‖z` as used by `ML-KEM.KeyGen_internal`.
pub const ML_KEM_SEED_LEN: usize = 64;

/// Encapsulation seed: 32 bytes for ML-KEM and 128 for P-256 scalar rejection sampling.
pub const ENCAPS_SEED_LEN: usize = 160;

/// Whole-pair seed: only for vectors and the software path.
///
/// Production does NOT create the pair this way: halves are generated separately so
///  the P-256 private half can remain inside the TPM. A common seed would reconstruct
/// the hardware scalar in software, negating non-exportability.
pub const KEYPAIR_SEED_LEN: usize = 32;

const ML_KEM_PUBLIC_LEN: usize = 1184;
const ML_KEM_CIPHERTEXT_LEN: usize = 1088;
const P256_POINT_LEN: usize = 65;
const SCALAR_LEN: usize = 32;
/// Rejection-sampling reserve: four thirty-two-byte pieces.
const SCALAR_TRIES_LEN: usize = 128;
/// ML-KEM seed plus scalar reserve. Expressed as a sum, not a number: the relationship
/// between these values is the point of the layout, hidden by `192`.
const EXPANDED_LEN: usize = ML_KEM_SEED_LEN + SCALAR_TRIES_LEN;

/// Construction label, thirteen ASCII bytes.
const LABEL: &[u8] = b"MLKEM768-P256";

/// Combiner (§4.1 of the draft).
///
/// Five consecutive values, label last. Order comes from the source, not
/// convenience: move the label first and identical inputs produce a different
/// secret silently, as already happened with X-Wing.
fn combine(
    ss_pq: &[u8],
    ss_t: &[u8],
    ct_t: &[u8],
    pk_t: &[u8],
) -> Zeroizing<[u8; SHARED_LEN]> {
    let mut h = Sha3_256::new();
    Digest::update(&mut h, ss_pq);
    Digest::update(&mut h, ss_t);
    Digest::update(&mut h, ct_t);
    Digest::update(&mut h, pk_t);
    Digest::update(&mut h, LABEL);
    Zeroizing::new(h.finalize().into())
}

/// First valid P-256 scalar from the byte reserve.
///
/// Rejection sampling, not modular reduction: reduction would bias the distribution,
/// the very flaw criticized in homemade ECDSA implementations. The reserve is
/// finite, so exhaustion fails rather than looping forever.
fn scalar_from(bytes: &[u8]) -> Result<P256Agreement, CryptoError> {
    for part in bytes.chunks_exact(SCALAR_LEN) {
        let candidate: [u8; SCALAR_LEN] =
            part.try_into().map_err(|_| CryptoError::BadLength)?;
        if let Ok(pair) = P256Agreement::from_be_bytes(&candidate) {
            return Ok(pair);
        }
    }
    Err(CryptoError::BadKey)
}

/// A pair grown from a single seed.
///
/// A separate type, not a triple: in a tuple, callers distinguish three semantically different
/// values only by order; confusing the ML-KEM seed with the public
/// half would evade the compiler.
#[derive(Debug)]
pub struct Keypair {
    /// ML-KEM seed: `d‖z`.
    pub ml_kem_seed: Zeroizing<[u8; ML_KEM_SEED_LEN]>,
    /// Classical half. A TPM key takes its place in production.
    pub classical: P256Agreement,
    /// Composite public half, 1249 bytes.
    pub public_key: [u8; PUBLIC_KEY_LEN],
}

/// Pair from a single seed: vector and software-party path.
///
/// # Errors
/// The byte reserve yields no valid scalar, or lengths do not match.
pub fn keypair_from_seed(seed: &[u8; KEYPAIR_SEED_LEN]) -> Result<Keypair, CryptoError> {
    let mut xof = Shake256::default();
    Update::update(&mut xof, seed);
    let mut expanded = Zeroizing::new([0u8; EXPANDED_LEN]);
    xof.finalize_xof().read(expanded.as_mut_slice());

    let pq_seed: [u8; ML_KEM_SEED_LEN] = expanded
        .get(..ML_KEM_SEED_LEN)
        .ok_or(CryptoError::BadLength)?
        .try_into()
        .map_err(|_| CryptoError::BadLength)?;
    let pq_seed = Zeroizing::new(pq_seed);
    let classical =
        scalar_from(expanded.get(ML_KEM_SEED_LEN..EXPANDED_LEN).ok_or(CryptoError::BadLength)?)?;

    let public_key = public_key_from_parts(&pq_seed, &classical.public_key())?;
    Ok(Keypair { ml_kem_seed: pq_seed, classical, public_key })
}

/// ML-KEM seed from thirty-two stored bytes.
///
/// ML-KEM requires sixty-four (`d‖z`), while this repository's key files use
/// thirty-two: creation locking, DPAPI wrapping, and
/// `cc keygen --wrap` rewrapping depend on that length. SHAKE256 expansion reconciles
/// them using the same technique as X-Wing itself (§5.2 of its draft), where `d‖z` also
/// grows from thirty-two bytes.
///
/// There is NO domain label here, by decision rather than omission. Labels separate TWO
/// uses of one secret; here there is one use: the file is created for
/// the post-quantum half and used nowhere else. An empty label in the §3.6
/// registry would record a separation that does not exist.
///
/// Stored bytes must be INDEPENDENT: deriving them from the classical seed
/// is forbidden; see the `HYBRID_KEY_FILE` documentation in `cc-cli`.
#[must_use]
pub fn ml_kem_seed_from_stored(stored: &[u8; 32]) -> Zeroizing<[u8; ML_KEM_SEED_LEN]> {
    let mut xof = Shake256::default();
    Update::update(&mut xof, stored);
    let mut out = Zeroizing::new([0u8; ML_KEM_SEED_LEN]);
    xof.finalize_xof().read(out.as_mut_slice());
    out
}

/// Composite public half from TWO independent halves.
///
/// This is the production path: the P-256 private half resides in the TPM and never
/// leaves, so only its PUBLIC point is accepted here, while the ML-KEM seed
/// is independent and separately generated.
///
/// # Errors
/// Point length is wrong or the seed cannot be parsed as an ML-KEM key.
pub fn public_key_from_parts(
    ml_kem_seed: &[u8; ML_KEM_SEED_LEN],
    p256_public: &[u8],
) -> Result<[u8; PUBLIC_KEY_LEN], CryptoError> {
    if p256_public.len() != P256_POINT_LEN {
        return Err(CryptoError::BadLength);
    }
    let seed = ArrayN::<u8, ML_KEM_SEED_LEN>::try_from(ml_kem_seed.as_slice())
        .map_err(|_| CryptoError::BadLength)?;
    let (_, ek) = MlKem768::from_seed(&seed);

    let mut out = [0u8; PUBLIC_KEY_LEN];
    let (head, tail) = out.split_at_mut(ML_KEM_PUBLIC_LEN);
    head.copy_from_slice(ek.to_bytes().as_slice());
    tail.copy_from_slice(p256_public);
    Ok(out)
}

/// Encapsulation with a specified seed: vector path.
///
/// Separate from [`encapsulate`] for the same reason as its neighbors: KATs must be
/// reproducible, and RNGs are forbidden in this crate.
///
/// # Errors
/// Incorrect public-half length, unparseable ML-KEM key, or the byte reserve
/// yields no valid ephemeral scalar.
pub fn encapsulate_derand(
    public_key: &[u8],
    seed: &[u8; ENCAPS_SEED_LEN],
) -> Result<(Zeroizing<[u8; SHARED_LEN]>, [u8; CIPHERTEXT_LEN]), CryptoError> {
    if public_key.len() != PUBLIC_KEY_LEN {
        return Err(CryptoError::BadLength);
    }
    let pk_pq = public_key.get(..ML_KEM_PUBLIC_LEN).ok_or(CryptoError::BadLength)?;
    let pk_t = public_key.get(ML_KEM_PUBLIC_LEN..PUBLIC_KEY_LEN).ok_or(CryptoError::BadLength)?;

    // Ключ ML-KEM разбирается ЗДЕСЬ, а не принимается на веру: открытая половина
    // приходит из подписанного заголовка, но подпись автора не обещает, что
    // байты образуют исполнимый ключ.
    let ek = EncapsulationKey768::new_from_slice(pk_pq).map_err(|_| CryptoError::BadKey)?;
    let m_bytes = seed.get(..SCALAR_LEN).ok_or(CryptoError::BadLength)?;
    let m = ArrayN::<u8, SCALAR_LEN>::try_from(m_bytes).map_err(|_| CryptoError::BadLength)?;
    let (ct_pq, ss_pq) = ek.encapsulate_deterministic(&m);

    let ephemeral =
        scalar_from(seed.get(SCALAR_LEN..ENCAPS_SEED_LEN).ok_or(CryptoError::BadLength)?)?;
    let ct_t = ephemeral.public_key();
    // Точка получателя проверяется на принадлежность кривой внутри `agree` —
    // для P-256 это защита от атаки invalid-curve, а не формальность.
    let ss_t = ephemeral.agree(pk_t)?;

    let shared = combine(&ss_pq, ss_t.expose(), &ct_t, pk_t);

    let mut ciphertext = [0u8; CIPHERTEXT_LEN];
    let (head, tail) = ciphertext.split_at_mut(ML_KEM_CIPHERTEXT_LEN);
    head.copy_from_slice(&ct_pq);
    tail.copy_from_slice(&ct_t);
    Ok((shared, ciphertext))
}

/// Encapsulate to the recipient's public half.
///
/// The RNG is a parameter, under the crate rule. One hundred sixty bytes are taken in
/// ONE call: two consecutive calls would shift RNG consumption order,
/// on which the golden artifacts depend.
///
/// # Errors
/// Same as [`encapsulate_derand`].
pub fn encapsulate<R: rand_core::CryptoRng + ?Sized>(
    public_key: &[u8],
    rng: &mut R,
) -> Result<(Zeroizing<[u8; SHARED_LEN]>, [u8; CIPHERTEXT_LEN]), CryptoError> {
    let mut seed = Zeroizing::new([0u8; ENCAPS_SEED_LEN]);
    rng.fill_bytes(seed.as_mut_slice());
    encapsulate_derand(public_key, &seed)
}

/// Decapsulation with BOTH halves, the classical half behind a trait.
///
/// The trait is the entire point of this mechanism: the P-256 private key may reside in
/// the TPM without leaving it, replacing the software key here without changing
/// a single byte of secret derivation.
///
/// The public point comes FROM THE PARTY ITSELF, not an argument: it enters
/// the combiner, so accepting it externally would make the shared secret externally controllable.
///
/// There is and can be no "invalid ciphertext" rejection here: ML-KEM responds
/// to corrupted ciphertext with implicit rejection, deriving a secret from `z` and
/// returning it normally. The caller detects the false secret
/// through the slot commitment (I-4) and AEAD tag, both in constant
/// time. Only structurally invalid input is rejected: an incorrect
/// length or an off-curve point.
///
/// # Errors
/// Incorrect ciphertext length, unparseable ML-KEM seed, or an ephemeral point not
/// on the curve.
pub fn decapsulate_with(
    ml_kem_seed: &[u8; ML_KEM_SEED_LEN],
    classical: &dyn KeyAgreement,
    ciphertext: &[u8],
) -> Result<Zeroizing<[u8; SHARED_LEN]>, CryptoError> {
    // Длина проверяется ДО согласования: считать ECDH ради заведомо негодного
    // входа значит дарить противнику измеримую работу на каждом мусорном байте.
    if ciphertext.len() != CIPHERTEXT_LEN {
        return Err(CryptoError::BadLength);
    }
    let seed = ArrayN::<u8, ML_KEM_SEED_LEN>::try_from(ml_kem_seed.as_slice())
        .map_err(|_| CryptoError::BadLength)?;
    let (dk, _) = MlKem768::from_seed(&seed);

    let ct_pq_bytes = ciphertext.get(..ML_KEM_CIPHERTEXT_LEN).ok_or(CryptoError::BadLength)?;
    let ct_pq = Array::try_from(ct_pq_bytes).map_err(|_| CryptoError::BadLength)?;
    let ct_t = ciphertext.get(ML_KEM_CIPHERTEXT_LEN..CIPHERTEXT_LEN).ok_or(CryptoError::BadLength)?;

    let ss_pq = DecapsulationKey768::decapsulate(&dk, &ct_pq);
    let ss_t = classical.agree(ct_t)?;
    let pk_t = classical.public_key();
    Ok(combine(&ss_pq, ss_t.expose(), ct_t, &pk_t))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// ROUND TRIP CLOSES WITH BOTH HALVES.
    #[test]
    fn what_is_encapsulated_comes_back_out_of_decapsulation() {
        let pair = keypair_from_seed(&[0x31; KEYPAIR_SEED_LEN]).unwrap();
        let (pq_seed, classical, public) = (pair.ml_kem_seed, pair.classical, pair.public_key);
        let (sent, ciphertext) =
            encapsulate_derand(&public, &[0x5c; ENCAPS_SEED_LEN]).unwrap();
        let received = decapsulate_with(&pq_seed, &classical, &ciphertext).unwrap();
        assert_eq!(sent.as_slice(), received.as_slice(), "секрет не сошёлся с обеих сторон");
    }

    /// SUBSTITUTING EITHER HALF DOES NOT YIELD THE SAME SECRET.
    ///
    /// Guards the hybrid's central property: it reduces to neither
    /// half. A corrupted post-quantum half yields another secret through ML-KEM
    /// implicit rejection; a substituted classical half yields another ECDH result.
    #[test]
    fn substituting_either_half_yields_a_different_secret() {
        let pair = keypair_from_seed(&[0x31; KEYPAIR_SEED_LEN]).unwrap();
        let (pq_seed, classical, public) = (pair.ml_kem_seed, pair.classical, pair.public_key);
        let (sent, ciphertext) =
            encapsulate_derand(&public, &[0x5c; ENCAPS_SEED_LEN]).unwrap();

        // Постквантовая половина.
        let mut broken = ciphertext;
        if let Some(byte) = broken.get_mut(0) {
            *byte ^= 1;
        }
        let got = decapsulate_with(&pq_seed, &classical, &broken).unwrap();
        assert_ne!(got.as_slice(), sent.as_slice(), "порча ML-KEM не повлияла на секрет");

        // Классическая: другая ЗАКОННАЯ точка, а не мусор.
        let other = P256Agreement::from_be_bytes(&[0x42; SCALAR_LEN]).unwrap();
        let mut swapped = ciphertext;
        if let Some(tail) = swapped.get_mut(ML_KEM_CIPHERTEXT_LEN..) {
            tail.copy_from_slice(&other.public_key());
        }
        let got = decapsulate_with(&pq_seed, &classical, &swapped).unwrap();
        assert_ne!(got.as_slice(), sent.as_slice(), "подмена точки не повлияла на секрет");
    }

    /// OFF-CURVE POINTS AND WRONG LENGTHS ARE REJECTED, NOT SILENTLY COMPUTED.
    ///
    /// A significant difference from X-Wing: X25519 permits any
    /// string, whereas P-256 off-curve points enable invalid-curve attacks,
    /// and ciphertext comes from a hostile file.
    #[test]
    fn an_off_curve_point_and_a_foreign_length_are_refused() {
        let pair = keypair_from_seed(&[0x31; KEYPAIR_SEED_LEN]).unwrap();
        let (pq_seed, classical, public) = (pair.ml_kem_seed, pair.classical, pair.public_key);
        let (_, ciphertext) = encapsulate_derand(&public, &[0x5c; ENCAPS_SEED_LEN]).unwrap();

        let mut zeroed = ciphertext;
        if let Some(tail) = zeroed.get_mut(ML_KEM_CIPHERTEXT_LEN..) {
            tail.fill(0);
        }
        assert!(decapsulate_with(&pq_seed, &classical, &zeroed).is_err(), "нулевая точка принята");
        assert!(
            decapsulate_with(&pq_seed, &classical, ciphertext.get(..1152).unwrap()).is_err(),
            "короткий шифротекст принят"
        );
    }

    /// WIRE LENGTHS MATCH THE FORMAT'S PROMISE.
    #[test]
    fn the_wire_lengths_are_the_ones_the_format_promises() {
        let public = keypair_from_seed(&[0x01; KEYPAIR_SEED_LEN]).unwrap().public_key;
        assert_eq!(public.len(), 1249);
        let (_, ciphertext) = encapsulate_derand(&public, &[0x02; ENCAPS_SEED_LEN]).unwrap();
        assert_eq!(ciphertext.len(), 1153);
    }

    /// THE LABEL ENDS THE COMBINER INPUT, AND THIS IS TESTED.
    ///
    /// A separate probe for the same reason as X-Wing: its implementation from memory
    /// already put the label first, producing a silent error.
    #[test]
    fn the_label_terminates_the_combiner_input() {
        let mut expected = Sha3_256::new();
        Digest::update(&mut expected, [1_u8; 32]);
        Digest::update(&mut expected, [2_u8; 32]);
        Digest::update(&mut expected, [3_u8; 65]);
        Digest::update(&mut expected, [4_u8; 65]);
        Digest::update(&mut expected, b"MLKEM768-P256");
        let expected: [u8; 32] = expected.finalize().into();
        assert_eq!(
            combine(&[1_u8; 32], &[2_u8; 32], &[3_u8; 65], &[4_u8; 65]).as_slice(),
            expected
        );
    }

    /// SEPARATE HALVES YIELD THE SAME PUBLIC PART AS A COMMON SEED.
    ///
    /// The production path is separate: P-256 is created in the TPM, ML-KEM independently.
    /// The probe shows this is the SAME mechanism, not merely a similar one.
    #[test]
    fn parts_assembled_separately_give_the_same_public_half() {
        let pair = keypair_from_seed(&[0x77; KEYPAIR_SEED_LEN]).unwrap();
        let from_parts =
            public_key_from_parts(&pair.ml_kem_seed, &pair.classical.public_key()).unwrap();
        assert_eq!(pair.public_key, from_parts);
    }
}
