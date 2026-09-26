// SPDX-License-Identifier: MPL-2.0
//! Seal secrets to a slot recipient's public key.
//!
//! The construction is Base-mode DHKEM(X25519, HKDF-SHA256) with
//! XChaCha20-Poly1305 AEAD, following RFC 9180. An off-the-shelf HPKE crate is deliberately
//! not used: it would pull in a second curve25519-dalek version and an RNG with
//! incompatible traits, while the TPM path in phase 1 already requires our own
//! key-agreement abstraction: Microsoft Platform Crypto Provider does not offer
//! X25519, and its private key cannot be passed to external code.
//!
//! **This is a hand-written construction and the first candidate for external review.**
//!
//! Key derivation includes both public keys, ephemeral and recipient. Otherwise
//! the same ciphertext could be bound to someone else's identity.

use crate::{CryptoError, KemAlg};
use crate::label::Label;
use crate::secret::X25519Secret;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use hkdf::Hkdf;
use rand_core::CryptoRng;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// X25519 public-key length.
pub const PUBLIC_KEY_LEN: usize = 32;

/// Default slot-sealing mechanism.
///
/// X25519 is the software default. P-256 supports TPM agreement keys, and the
/// hybrids use their respective paths. [`supports_kem`] reports executability.
pub const DEFAULT_SEALING_KEM: KemAlg = KemAlg::X25519HkdfSha256;

/// Whether this build implements the declared slot mechanism.
///
/// The caller decides whether an unsupported slot is skipped or rejected.
/// Format-version and length checks belong to `oc-format`; this table answers
/// only executability. The exhaustive match forces new KEMs to be considered.
pub fn supports_kem(kem: KemAlg) -> bool {
    match kem {
        KemAlg::X25519HkdfSha256 => true,
        // P-256 исполняется с версии 2 формата: Microsoft Platform Crypto
        // Provider не даёт X25519, поэтому ключ, живущий в TPM, обязан быть
        // P-256. Согласование идёт за трейтом [`crate::agreement::KeyAgreement`],
        // и аппаратная реализация подставляется вместо программной, не меняя
        // ничего в выводе ключа.
        KemAlg::P256HkdfSha256 => true,
        // RSA-OAEP: номер в реестре занят, формы полей не задаёт ни одна версия
        // формата, механизм не исполняется. Слот с ним пропускается.
        KemAlg::RsaOaepSha256 => false,
        // Гибрид X-Wing исполняется с версии 4 формата. Здесь ответ «умеем» без
        // оговорки о версии намеренно: версию знает разбор заголовка, и таблица
        // длин в `oc_format` уже отвергает четвёртый номер у версий 1–3. Две
        // проверки версии в двух крейтах разошлись бы — а расходятся такие пары
        // всегда в сторону «слот открылся там, где не должен был».
        KemAlg::XWing => true,
        // Аппаратный гибрид исполняется с версии 5. Оговорки о версии здесь нет
        // по той же причине, что у четвёртого: версию знает разбор заголовка, и
        // таблица длин в `oc_format` уже отвергает пятый номер у версий 1–4.
        // Две проверки версии в двух крейтах разошлись бы, а расходятся такие
        // пары всегда в сторону «слот открылся там, где не должен был».
        KemAlg::MlKem768P256 => true,
    }
}

/// Construct the shared writer/reader slot-sealing `info`.
///
/// The registered [`Label`], KEM identifier, and file ID bind the derived key to
/// the slot purpose and algorithm (`docs/format.md` §3.3, §3.6).
pub fn slot_info(purpose: Label, kem: KemAlg, file_id: &[u8; 16]) -> Vec<u8> {
    let purpose = purpose.as_bytes();
    let mut info = Vec::with_capacity(purpose.len().saturating_add(17));
    info.extend_from_slice(purpose);
    // Один байт фиксированной ширины между меткой и `file_id`: длина всех трёх
    // частей известна, поэтому конкатенация однозначна и разделители не нужны.
    info.push(kem as u8);
    info.extend_from_slice(file_id);
    info
}

/// K11 derivation `info`: server → device (`docs/format.md` §3.5).
///
/// ```text
/// info = "CC/v1/a-to-device" ‖ u8(kem_id) ‖ file_id(16) ‖ device_fpr(32) ‖ u64be(seq)
/// ```
///
/// Both parties use this helper. The sequence's big-endian encoding is frozen.
#[must_use]
pub fn a_to_device_info(
    kem: KemAlg,
    file_id: &[u8; 16],
    device_fpr: &[u8; 32],
    seq: u64,
) -> Vec<u8> {
    let mut info = Vec::with_capacity(64);
    info.extend_from_slice(crate::label::A_TO_DEVICE.as_bytes());
    info.push(kem as u8);
    info.extend_from_slice(file_id);
    info.extend_from_slice(device_fpr);
    info.extend_from_slice(&seq.to_be_bytes());
    info
}

/// K21 derivation `info`: author → requesting device (`docs/format.md`,
/// "Access request").
///
/// ```text
/// info = "CC/v1/b-to-device" ‖ u8(kem_id) ‖ file_id(16) ‖ device_fpr(32)
/// ```
///
/// There is NO lease sequence here, deliberately: share A is issued under rules
/// and lives between issuances; share B is issued to a person once and survives any
/// renewal. A sequence in `info` would bind it to a single lease.
///
/// In the core for the same reason as [`a_to_device_info`]: TWO parties assemble
/// these bytes, the author sealing the share and the device opening it.
#[must_use]
pub fn b_to_device_info(kem: KemAlg, file_id: &[u8; 16], device_fpr: &[u8; 32]) -> Vec<u8> {
    let mut info =
        Vec::with_capacity(crate::label::B_TO_DEVICE.len().saturating_add(49));
    info.extend_from_slice(crate::label::B_TO_DEVICE.as_bytes());
    info.push(kem as u8);
    info.extend_from_slice(file_id);
    info.extend_from_slice(device_fpr);
    info
}

/// Attestation-challenge `info`: domain label and device fingerprint.
///
/// ```text
/// info = "CC/v1/attest-nonce" ‖ device_fpr(32)
/// ```
///
/// The fingerprint enters `info`, not only AAD, preventing a challenge issued to one
/// device from opening with another device's key when agreement keys match.
///
/// Unlike shares A and B, `info` contains NO mechanism. This is not an omission but
/// the frozen handshake form: both halves of a hybrid key open
/// the challenge consecutively, using identical `info`. Adding
/// `kem_id` here would change wire bytes.
///
/// In the core for the same reason: TWO parties assemble it, the server sealing the challenge
/// and the device opening it. This string previously had three manual constructions.
#[must_use]
pub fn challenge_info(device_fpr: &[u8; 32]) -> Vec<u8> {
    let mut info = Vec::with_capacity(crate::label::ATTEST_NONCE.len().saturating_add(32));
    info.extend_from_slice(crate::label::ATTEST_NONCE.as_bytes());
    info.extend_from_slice(device_fpr);
    info
}

/// XChaCha20-Poly1305 nonce length.
const NONCE_LEN: usize = 24;

/// Poly1305 tag length. Ciphertext shorter than the tag is structurally impossible.
const TAG_LEN: usize = 16;

/// X25519 shared-secret and derived AEAD-key length.
const SHARED_LEN: usize = 32;

/// Sealed secret: ephemeral public key, nonce, and ciphertext with tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedBlob {
    /// Sender's ephemeral public key.
    ///
    /// Variable length: X25519 uses 32 bytes, P-256 uses 65. A fixed-length
    /// array occupied this field before format version 2, making a P-256 slot
    /// inexpressible. [`open`] checks length exactly before any
    /// cryptography: variable length in the type does not mean unchecked length.
    pub enc: Vec<u8>,
    /// AEAD nonce.
    ///
    /// **Stored, not derived**: the same rule as for payload
    /// chunks (§6.1 of the specification), for the same reason, with worse
    /// consequences here.
    ///
    /// A nonce derived from the shared PRK would be entirely determined by the ephemeral pair
    /// and would repeat with it. Repeated RNG state after virtual-machine
    /// snapshot rollback, disk-image cloning, or backup
    /// restoration would produce two blobs with the same key and nonce,
    /// hence one keystream. Then `ct₁ ⊕ ct₂ = pt₁ ⊕ pt₂`, and the plaintexts
    /// here are secret shares: `secret_A` and `secret_A‖secret_B`
    /// reveal `secret_B`, together they reveal KEK, and KEK reveals the content key.
    /// A full bypass without any private key. Twenty-four bytes
    /// alongside the already stored thirty-two close this completely: the key may
    /// repeat, but the keystream will not.
    pub nonce: [u8; NONCE_LEN],
    /// Ciphertext with appended tag.
    pub ct: Vec<u8>,
}

/// Public key from a private key.
pub fn x25519_public(secret: &X25519Secret) -> [u8; PUBLIC_KEY_LEN] {
    // `StaticSecret` сам зажимает скаляр при использовании, поэтому произвольные
    // 32 байта из генератора — корректный приватный ключ, и отдельная проверка
    // формы здесь не нужна.
    let sk = StaticSecret::from(*secret.expose());
    PublicKey::from(&sk).to_bytes()
}

/// Seal to a public key.
///
/// `info` separates slot purposes; `aad` binds the file context,
/// usually the policy hash, preventing ciphertext from moving to a container with
/// different rules.
pub fn seal<R: CryptoRng + ?Sized>(
    recipient_public: &[u8; PUBLIC_KEY_LEN],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    rng: &mut R,
) -> Result<SealedBlob, CryptoError> {
    // K10 связывает байты ключа, а получатель восстанавливает каноническую
    // координату. Алиас с тем же DH дал бы конверт, который не откроется.
    if !canonical_x25519_public(recipient_public) {
        return Err(CryptoError::BadKey);
    }
    // Эфемерная пара на каждый вызов даёт уникальность ключа AEAD.
    let mut eph_bytes = Zeroizing::new([0u8; SHARED_LEN]);
    rng.fill_bytes(eph_bytes.as_mut_slice());
    let eph_sk = StaticSecret::from(*eph_bytes);
    let eph_pk = PublicKey::from(&eph_sk).to_bytes();

    // Nonce хранится в блобе и **не выводится из общего секрета** — выведенный,
    // он определялся бы эфемерной парой и совпадал бы всегда, когда совпала она.
    //
    // Но и просто взять его из генератора недостаточно, и это стоило отдельного
    // решения (С-13). Эфемерная пара и nonce приходят из ОДНОГО генератора
    // подряд, поэтому полный повтор его состояния — откат снапшота виртуальной
    // машины, клон образа диска, восстановление из резервной копии — повторял бы
    // оба значения разом, а с ними и поток ключей. Здесь это дороже всего:
    // открытые тексты — доли секрета схемы 2-из-2.
    //
    // Поэтому случайные байты идут не в nonce, а в засев производной, куда
    // входит ещё и открытый текст: при повторе генератора и разных секретах
    // nonce расходятся. Подробности и границы гарантии — у `hedged_nonce`.
    let mut nonce_seed = Zeroizing::new([0u8; NONCE_LEN]);
    rng.fill_bytes(nonce_seed.as_mut_slice());
    let nonce = crate::kdf::hedged_nonce::<NONCE_LEN>(
        crate::label::SEAL_NONCE,
        nonce_seed.as_slice(),
        plaintext,
        aad,
    )?;

    let shared = eph_sk.diffie_hellman(&PublicKey::from(*recipient_public));
    let shared = crate::agreement::SharedSecret::from_be_bytes(*shared.as_bytes());

    seal_core(&shared, &eph_pk, recipient_public, info, aad, plaintext, nonce)
}

/// Seal to a P-256 key, for a recipient whose key resides in a TPM.
///
/// A separate function rather than a [`seal`] parameter, because of RNG
/// consumption order. For X25519 it is **frozen**: golden containers are built with
/// a seeded RNG; shifting its call order by even one call changes
/// artifact bytes although no algorithm changed. Everything after
/// agreement (`seal_core`) is therefore shared, while each mechanism retains
/// its own ephemeral-pair generation.
pub fn seal_p256<R: CryptoRng + ?Sized>(
    recipient_public: &[u8],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    rng: &mut R,
) -> Result<SealedBlob, CryptoError> {
    // K10 связывает байты; public_key() получателя возвращает несжатую точку.
    validate_dh_public(recipient_public, 65)?;
    use crate::agreement::KeyAgreement as _;

    let eph = crate::agreement::P256Agreement::generate(rng);
    let eph_pk = eph.public_key();

    let mut nonce_seed = Zeroizing::new([0u8; NONCE_LEN]);
    rng.fill_bytes(nonce_seed.as_mut_slice());
    let nonce = crate::kdf::hedged_nonce::<NONCE_LEN>(
        crate::label::SEAL_NONCE,
        nonce_seed.as_slice(),
        plaintext,
        aad,
    )?;

    // Согласование через трейт: точка получателя проверяется на принадлежность
    // кривой внутри. Для P-256 это обязательно — `recipient_public` приходит из
    // заголовка, то есть из файла.
    let shared = eph.agree(recipient_public)?;

    seal_core(&shared, &eph_pk, recipient_public, info, aad, plaintext, nonce)
}

/// Shared sealing body: key derivation and AEAD.
///
/// Extracted to avoid two similar but diverging implementations of the same
/// operation for two mechanisms. Such copies diverge neither immediately nor
/// visibly; the symptom is "slot does not open".
fn seal_core(
    shared: &crate::agreement::SharedSecret,
    eph_public: &[u8],
    recipient_public: &[u8],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    nonce: [u8; NONCE_LEN],
) -> Result<SealedBlob, CryptoError> {
    let key = derive_key(shared, eph_public, recipient_public, info)?;

    let cipher = XChaCha20Poly1305::new((&*key).into());
    let ct = cipher
        .encrypt((&nonce).into(), Payload { msg: plaintext, aad })
        // Единственная причина отказа шифрования — открытый текст, не влезающий в
        // адресуемый буфер. Это ошибка длины вызывающего, а не аутентификации.
        .map_err(|_| CryptoError::BadLength)?;

    Ok(SealedBlob { enc: eph_public.to_vec(), nonce, ct })
}

// Открытая little-endian координата должна быть меньше p = 2^255 - 19.
// Это ограничение Seal; низкоуровневый X25519 по-прежнему принимает RFC7748 aliases.
fn canonical_x25519_public(public: &[u8; PUBLIC_KEY_LEN]) -> bool {
    let mut modulus = [0xff; PUBLIC_KEY_LEN];
    if let Some(first) = modulus.first_mut() {
        *first = 0xed;
    }
    if let Some(last) = modulus.last_mut() {
        *last = 0x7f;
    }
    public.iter().rev().cmp(modulus.iter().rev()).is_lt()
}

// Проверяем представление до DH/KDF: K10 связывает именно байты ключа.
fn validate_dh_public(public: &[u8], expected_len: usize) -> Result<(), CryptoError> {
    match expected_len {
        PUBLIC_KEY_LEN => {
            let public = public.try_into().map_err(|_| CryptoError::BadLength)?;
            if !canonical_x25519_public(public) {
                return Err(CryptoError::BadKey);
            }
        }
        65 => {
            if public.len() != 65 || public.first() != Some(&0x04) {
                return Err(CryptoError::BadLength);
            }
            p256::PublicKey::from_sec1_bytes(public).map_err(|_| CryptoError::BadKey)?;
        }
        _ => return Err(CryptoError::BadLength),
    }
    Ok(())
}

/// Seal a slot using the X-Wing HYBRID, `kem_id = 4`.
///
/// A separate function beside [`seal`] and [`seal_p256`] for the same reason
/// those are separate: each mechanism has its own RNG consumption order,
/// while X25519's is frozen by golden artifacts. Here consumption is sixty-four bytes in one
/// call for encapsulation, then twenty-four for the nonce seed.
///
/// The X-Wing shared secret enters the same key schedule as a DH shared secret,
/// not as an adaptation: `derive_key` binds BOTH public values to it,
/// the ciphertext and recipient key. X-Wing binds its own half itself (§5.3
/// of the draft), but a second binding is free, while distinct schedules for different
/// mechanisms would mean two key schedules instead of one.
///
/// # Errors
/// Incorrect public-half length or unparseable ML-KEM key.
pub fn seal_xwing<R: CryptoRng + ?Sized>(
    recipient_public: &[u8],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    rng: &mut R,
) -> Result<SealedBlob, CryptoError> {
    if recipient_public.len() != crate::xwing::PUBLIC_KEY_LEN {
        return Err(CryptoError::BadLength);
    }
    let (_, classical) = recipient_public
        .split_last_chunk::<PUBLIC_KEY_LEN>()
        .ok_or(CryptoError::BadLength)?;
    // The recipient reconstructs a canonical public key for the combiner and K10.
    validate_dh_public(classical, PUBLIC_KEY_LEN)?;
    let (shared, ciphertext) = crate::xwing::encapsulate(recipient_public, rng)?;

    let mut nonce_seed = Zeroizing::new([0u8; NONCE_LEN]);
    rng.fill_bytes(nonce_seed.as_mut_slice());
    let nonce = crate::kdf::hedged_nonce::<NONCE_LEN>(
        crate::label::SEAL_NONCE,
        nonce_seed.as_slice(),
        plaintext,
        aad,
    )?;

    let shared = crate::agreement::SharedSecret::from_be_bytes(*shared);
    seal_core(&shared, &ciphertext, recipient_public, info, aad, plaintext, nonce)
}

/// Open a hybrid-sealed slot.
///
/// Our public half is RECOMPUTED from the seed, not accepted externally:
/// it enters `ikm`, so an argument would make key derivation externally
/// controllable. The same reasoning as [`open`].
///
/// Corrupted ciphertext does not directly cause rejection here: ML-KEM performs
/// implicit rejection, with the false secret caught by the AEAD tag below in constant
/// time. See [`crate::xwing::decapsulate`] documentation.
///
/// # Errors
/// Lengths mismatch or AEAD tag verification fails.
pub fn open_xwing(
    recipient_secret: &[u8; crate::xwing::SECRET_LEN],
    blob: &SealedBlob,
    info: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if blob.ct.len() < TAG_LEN {
        return Err(CryptoError::BadLength);
    }
    let shared = crate::xwing::decapsulate(recipient_secret, &blob.enc)?;
    let own_public = crate::xwing::public_key(recipient_secret)?;
    let shared = crate::agreement::SharedSecret::from_be_bytes(*shared);
    let key = derive_key(&shared, &blob.enc, &own_public, info)?;
    open_core(&key, blob, aad)
}

/// Seal a slot using the MLKEM768-P256 HARDWARE HYBRID, `kem_id = 5`.
///
/// A separate function beside [`seal_xwing`] for the same reason as all
/// neighbors: each mechanism has its own RNG consumption order, while X25519's is frozen
/// by golden artifacts. Here consumption is one hundred sixty bytes in one call
/// for encapsulation, then twenty-four for the nonce seed.
///
/// # Errors
/// Incorrect public-half length or unparseable ML-KEM key.
pub fn seal_mlkem_p256<R: CryptoRng + ?Sized>(
    recipient_public: &[u8],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    rng: &mut R,
) -> Result<SealedBlob, CryptoError> {
    let (shared, ciphertext) = crate::mlkem_p256::encapsulate(recipient_public, rng)?;

    let mut nonce_seed = Zeroizing::new([0u8; NONCE_LEN]);
    rng.fill_bytes(nonce_seed.as_mut_slice());
    let nonce = crate::kdf::hedged_nonce::<NONCE_LEN>(
        crate::label::SEAL_NONCE,
        nonce_seed.as_slice(),
        plaintext,
        aad,
    )?;

    let shared = crate::agreement::SharedSecret::from_be_bytes(*shared);
    seal_core(&shared, &ciphertext, recipient_public, info, aad, plaintext, nonce)
}

/// Open a hardware-hybrid slot.
///
/// The classical half arrives BEHIND A TRAIT, the mechanism's whole purpose:
/// the P-256 private key may reside in a TPM without leaving it. The post-quantum
/// half is a seed alongside it in protected storage.
///
/// Our public half is RECOMPUTED from both halves, not accepted as
/// an argument: it enters `ikm`, so external input would make key derivation
/// externally controllable. The same reasoning as [`open`].
///
/// # Errors
/// Lengths mismatch, an off-curve point, or AEAD tag verification failure.
pub fn open_mlkem_p256(
    ml_kem_seed: &[u8; crate::mlkem_p256::ML_KEM_SEED_LEN],
    classical: &dyn crate::agreement::KeyAgreement,
    blob: &SealedBlob,
    info: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if blob.ct.len() < TAG_LEN {
        return Err(CryptoError::BadLength);
    }
    let shared = crate::mlkem_p256::decapsulate_with(ml_kem_seed, classical, &blob.enc)?;
    let own_public =
        crate::mlkem_p256::public_key_from_parts(ml_kem_seed, &classical.public_key())?;
    let shared = crate::agreement::SharedSecret::from_be_bytes(*shared);
    let key = derive_key(&shared, &blob.enc, &own_public, info)?;
    open_core(&key, blob, aad)
}

/// Open a sealed secret.
pub fn open(
    recipient_secret: &X25519Secret,
    blob: &SealedBlob,
    info: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    // Шифротекст короче тега — структурная ошибка ввода, и отсечь её надо до
    // согласования ключей: считать DH ради заведомо неоткрываемого блоба значит
    // дарить противнику измеримую работу на каждом мусорном байте.
    if blob.ct.len() < TAG_LEN {
        return Err(CryptoError::BadLength);
    }

    // Длина эфемерного ключа проверяется здесь же, до согласования, и по той же
    // причине. Эта функция реализует X25519 и только его: `enc` иной длины —
    // не «чужой механизм, разберёмся ниже», а несоответствие входа контракту.
    // Решение «пропустить слот или отвергнуть файл» принимает вызывающий,
    // который знает версию контейнера; здесь ответ один — не наш вход.
    let enc: [u8; PUBLIC_KEY_LEN] =
        blob.enc.as_slice().try_into().map_err(|_| CryptoError::BadLength)?;
    validate_dh_public(&enc, PUBLIC_KEY_LEN)?;

    let sk = StaticSecret::from(*recipient_secret.expose());
    // Свой публичный ключ пересчитывается, а не принимается снаружи: он входит в
    // ikm, и подставленное значение сделало бы вывод ключа управляемым извне.
    let own_pk = PublicKey::from(&sk).to_bytes();

    let shared = sk.diffie_hellman(&PublicKey::from(enc));
    let shared = crate::agreement::SharedSecret::from_be_bytes(*shared.as_bytes());
    let key = derive_key(&shared, &enc, &own_pk, info)?;
    open_core(&key, blob, aad)
}

/// Open a DH seal through a software or hardware agreement provider.
/// Both public keys must use canonical X25519 or uncompressed P-256 encoding.
/// The provider supplies its own public key for K10; callers cannot override it.
pub fn open_with(
    agreement: &dyn crate::agreement::KeyAgreement,
    blob: &SealedBlob,
    info: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if blob.ct.len() < TAG_LEN {
        return Err(CryptoError::BadLength);
    }

    // Проверяем обе записи до согласования, включая аппаратного провайдера.
    let own_pk = agreement.public_key();
    validate_dh_public(&own_pk, own_pk.len())?;
    validate_dh_public(&blob.enc, own_pk.len())?;
    let shared = agreement.agree(&blob.enc)?;
    let key = derive_key(&shared, &blob.enc, &own_pk, info)?;
    open_core(&key, blob, aad)
}

/// Shared opening body: AEAD and tag-verification order.
fn open_core(
    key: &[u8; SHARED_LEN],
    blob: &SealedBlob,
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    // Nonce берётся из блоба. Подменить его противник может, но это ничего не
    // даёт: он входит в вычисление тега, и любая подмена ломает аутентификацию.
    let plaintext = cipher
        .decrypt((&blob.nonce).into(), Payload { msg: &blob.ct, aad })
        .map_err(|_| CryptoError::Authentication)?;

    // Открытый текст отдаётся только после проверки тега — `decrypt` не
    // возвращает ничего до неё — и сразу под владельцем, затирающим буфер.
    Ok(Zeroizing::new(plaintext))
}

/// Shared seal/open key schedule: derive the AEAD key from the DH shared secret
/// and both public keys.
///
/// The nonce is **not** derived here: stored in the blob, see [`SealedBlob::nonce`].
///
/// `ikm` contains **both** public keys. Omitting either the ephemeral key or
/// the recipient key individually allows binding the same
/// ciphertext to another identity: an adversary who knows their own private key
/// chooses a public key yielding the same shared secret, then presents someone else's blob as
/// addressed to them. All three fields have fixed 32-byte lengths, making
/// concatenation unambiguous without delimiters.
///
/// HKDF salt is deliberately empty: the parties have no shared random value at this
/// step, and domain separation relies entirely on `info`.
fn derive_key(
    shared: &crate::agreement::SharedSecret,
    eph_public: &[u8],
    recipient_public: &[u8],
    info: &[u8],
) -> Result<Zeroizing<[u8; SHARED_LEN]>, CryptoError> {
    let shared = shared.expose();
    // Нулевой общий секрет — признак точки малого порядка в роли публичного
    // ключа. Продолжив, обе стороны получили бы один и тот же ключ AEAD,
    // независимый от приватного ключа получателя: открыть блоб смог бы кто
    // угодно. Сравнение в постоянном времени, чтобы не давать оракул по времени.
    let zero = [0u8; SHARED_LEN];
    if bool::from(shared.as_slice().ct_eq(zero.as_slice())) {
        return Err(CryptoError::BadKey);
    }

    // `ikm = DH ‖ enc ‖ pk_получателя`. Конкатенация без разделителей и без длин,
    // и её однозначность держится НЕ на том, что все три по 32 байта: у P-256
    // ключи по 65. Держится она на том, что внутри одного `kem_id` все три длины
    // фиксированы, а сам `kem_id` входит в `info` (см. [`slot_info`]) и потому в
    // вывод ключа. Разобрать склейку двумя способами можно было бы только сменив
    // механизм — а смена механизма меняет ключ.
    let mut ikm = Zeroizing::new(Vec::with_capacity(
        shared.len().saturating_add(eph_public.len()).saturating_add(recipient_public.len()),
    ));
    ikm.extend_from_slice(shared);
    ikm.extend_from_slice(eph_public);
    ikm.extend_from_slice(recipient_public);

    let hk = Hkdf::<Sha256>::new(None, &ikm);

    let mut key = Zeroizing::new([0u8; SHARED_LEN]);
    hk.expand(&expand_info(crate::label::SEAL_KEY.as_bytes(), info), key.as_mut_slice())
        .map_err(|_| CryptoError::BadLength)?;

    Ok(key)
}

/// HKDF `info`: domain label and caller's argument.
fn expand_info(label: &[u8], info: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(label.len().saturating_add(info.len()));
    out.extend_from_slice(label);
    out.extend_from_slice(info);
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::arithmetic_side_effects)]
mod moved_info_tests {
    use super::*;

    /// Input freezing bytes of the three `info` constructions.
    ///
    /// Values are neither "pretty" nor repetitive: `[0x11; 16]` would miss
    /// swapping `file_id` with part of itself; an ascending sequence catches it.
    const FILE_ID: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];
    const DEVICE_FPR: [u8; 32] = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
        0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
        0x3e, 0x3f,
    ];
    /// Lease sequence. Neither zero nor a palindrome: distinguishes `u64be` from `u64le`.
    const SEQ: u64 = 0x0102_0304_0506_0708;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// THE THREE MOVED CONSTRUCTIONS HAVE THE SAME BYTES AS BEFORE THE MOVE.
    ///
    /// Golden values were printed by the OLD code before moving: `a_to_device_info` by both
    /// copies (`cc-authority` and `cc-cli` produced identical strings),
    /// `challenge_info` by the server implementation, `b_to_device_info` by the client.
    /// Comparing new with new would be tautological: moving normative bytes is
    /// verified only against values captured BEFORE the move.
    ///
    /// These strings enter key-derivation `info`, hence WIRE BYTES.
    /// One differing byte yields a different key, appearing as "share does not
    /// unwrap", a cryptographic failure where there is none.
    #[test]
    fn the_moved_derivation_inputs_are_byte_for_byte_what_they_were() {
        assert_eq!(
            hex(&a_to_device_info(KemAlg::P256HkdfSha256, &FILE_ID, &DEVICE_FPR, SEQ)),
            "43432f76312f612d746f2d64657669636502101112131415161718191a1b1c1d1e1f\
             202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
             0102030405060708",
        );
        assert_eq!(
            hex(&b_to_device_info(KemAlg::XWing, &FILE_ID, &DEVICE_FPR)),
            "43432f76312f622d746f2d64657669636504101112131415161718191a1b1c1d1e1f\
             202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        );
        assert_eq!(
            hex(&challenge_info(&DEVICE_FPR)),
            "43432f76312f6174746573742d6e6f6e6365\
             202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        );
    }

    /// THE MECHANISM ENTERS BOTH SHARES, BUT NOT THE CHALLENGE.
    ///
    /// The former is a property: a slot relabeled with another `kem_id` must yield
    /// a different key. The latter is the frozen handshake form: halves using different mechanisms
    /// open a challenge consecutively with the same `info`. This probe prevents
    /// adding "uniformity" here as a fourth byte.
    #[test]
    fn the_mechanism_binds_both_shares_and_deliberately_not_the_challenge() {
        assert_ne!(
            a_to_device_info(KemAlg::X25519HkdfSha256, &FILE_ID, &DEVICE_FPR, SEQ),
            a_to_device_info(KemAlg::P256HkdfSha256, &FILE_ID, &DEVICE_FPR, SEQ),
        );
        assert_ne!(
            b_to_device_info(KemAlg::X25519HkdfSha256, &FILE_ID, &DEVICE_FPR),
            b_to_device_info(KemAlg::XWing, &FILE_ID, &DEVICE_FPR),
        );
        assert_eq!(
            challenge_info(&DEVICE_FPR).len(),
            crate::label::ATTEST_NONCE.len() + 32,
            "в вызов добавился байт — это смена байтов на проводе",
        );
    }

    /// Share B does NOT contain the lease sequence; share A does. The difference is normative:
    /// author approval must not be required anew on every renewal.
    #[test]
    fn only_the_a_share_is_tied_to_a_lease_number() {
        let b = b_to_device_info(KemAlg::X25519HkdfSha256, &FILE_ID, &DEVICE_FPR);
        assert_eq!(b.len(), crate::label::B_TO_DEVICE.len() + 1 + 16 + 32);
        let a = a_to_device_info(KemAlg::X25519HkdfSha256, &FILE_ID, &DEVICE_FPR, SEQ);
        assert_eq!(a.len(), crate::label::A_TO_DEVICE.len() + 1 + 16 + 32 + 8);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod kem_binding_tests {
    use super::*;

    const FILE_ID: [u8; 16] = [0x5a; 16];

    #[test]
    fn relabelling_a_slot_with_another_kem_changes_the_key_it_derives() {
        // Свойство, ради которого идентификатор механизма вообще попал в `info`.
        //
        // §3.3 обещает, что слоты с разными KEM сосуществуют в одном файле.
        // Пока идентификатор не входил в вывод ключа, обещание не было
        // подкреплено ничем: слот, переразмеченный с X25519 на P-256, выводил
        // тот же самый ключ, и объявленный алгоритм оставался украшением.
        let as_x25519 = slot_info(crate::label::SLOT_SERVER, KemAlg::X25519HkdfSha256, &FILE_ID);
        let as_p256 = slot_info(crate::label::SLOT_SERVER, KemAlg::P256HkdfSha256, &FILE_ID);
        assert_ne!(as_x25519, as_p256, "переразметка KEM не меняет info");
    }

    #[test]
    fn a_blob_sealed_under_one_kem_label_does_not_open_under_another() {
        struct Fixed(u8);
        impl rand_core::TryRng for Fixed {
            type Error = core::convert::Infallible;
            fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
                Ok(u32::from(self.0))
            }
            fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
                Ok(u64::from(self.0))
            }
            fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
                for b in dst.iter_mut() {
                    self.0 = self.0.wrapping_add(1);
                    *b = self.0;
                }
                Ok(())
            }
        }
        impl rand_core::TryCryptoRng for Fixed {}

        let recipient = X25519Secret::from_bytes([0x11; 32]);
        let public = x25519_public(&recipient);
        let honest = slot_info(crate::label::SLOT_SERVER, KemAlg::X25519HkdfSha256, &FILE_ID);
        let forged = slot_info(crate::label::SLOT_SERVER, KemAlg::P256HkdfSha256, &FILE_ID);

        let blob = seal(&public, &honest, b"aad", b"share", &mut Fixed(1)).unwrap();
        assert!(open(&recipient, &blob, &honest, b"aad").is_ok());
        assert_eq!(
            open(&recipient, &blob, &forged, b"aad").err(),
            Some(CryptoError::Authentication),
            "слот открылся под чужой меткой механизма"
        );
    }

    /// Whether this build can execute the declared mechanism is a different question from
    /// whether it can parse the mechanism's shape.
    ///
    /// The P-256 assertion changed here **by decision**,
    /// recorded in `docs/format.md` ("VERSION 2 OPENED"), not simply following the code.
    /// Before version 2, the registry declared the mechanism without implementing it,
    /// and slots using it had to be skipped. It is now implemented because there is no other way
    /// to address a TPM key: Platform Crypto Provider lacks X25519.
    ///
    /// RSA-OAEP remains unimplemented, a tested property rather than unfinished work:
    /// the format must retain a numbered but unimplemented mechanism,
    /// or the "skip the slot rather than reject the file" branch ceases
    /// to be tested at all.
    #[test]
    fn the_build_executes_exactly_the_mechanisms_it_claims() {
        assert!(supports_kem(DEFAULT_SEALING_KEM));
        assert!(supports_kem(KemAlg::X25519HkdfSha256));
        assert!(supports_kem(KemAlg::P256HkdfSha256), "P-256 объявлен версией 2 и обязан исполняться");
        assert!(!supports_kem(KemAlg::RsaOaepSha256), "неисполнимый механизм обязан остаться");
    }

    /// Sealing to P-256 and opening through its agreement party agree.
    ///
    /// Checks the whole path: ephemeral pair, agreement behind the trait,
    /// key derivation with 65-byte keys in `ikm`, AEAD. Using a software party rather
    /// than a TPM is exactly why the software implementation exists: otherwise this path
    /// would be tested only on suitably equipped hardware.
    #[test]
    fn a_p256_slot_seals_and_opens_through_the_agreement_trait() {
        use crate::agreement::{KeyAgreement as _, P256Agreement};

        let recipient = P256Agreement::from_be_bytes(&[0x5e; 32]).unwrap();
        let recipient_public = recipient.public_key();
        assert_eq!(recipient_public.len(), 65);

        // Свой детерминированный генератор: воспроизводимость теста важнее
        // стойкости, а стойкость здесь и не проверяется.
        struct Counter(u8);
        impl rand_core::TryRng for Counter {
            type Error = core::convert::Infallible;
            fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
                Ok(u32::from(self.0))
            }
            fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
                Ok(u64::from(self.0))
            }
            fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
                for b in dst.iter_mut() {
                    self.0 = self.0.wrapping_add(1);
                    *b = self.0;
                }
                Ok(())
            }
        }
        impl rand_core::TryCryptoRng for Counter {}

        let info = slot_info(crate::label::SLOT_AUTHOR_DEVICE, KemAlg::P256HkdfSha256, &[0x11; 16]);
        let blob = seal_p256(&recipient_public, &info, b"aad", b"share", &mut Counter(7)).unwrap();
        assert_eq!(blob.enc.len(), 65, "эфемерный ключ P-256 на проводе — 65 байт");

        let opened = open_with(&recipient, &blob, &info, b"aad").unwrap();
        assert_eq!(opened.as_slice(), b"share");

        // Чужая сторона не открывает: проверка не только на то, что сошлось.
        let stranger = P256Agreement::from_be_bytes(&[0x77; 32]).unwrap();
        assert_eq!(
            open_with(&stranger, &blob, &info, b"aad").err(),
            Some(CryptoError::Authentication),
            "слот открылся чужим ключом"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    #[test]
    fn canonical_x25519_coordinates_are_strictly_below_the_modulus() {
        let mut modulus = [0xff; PUBLIC_KEY_LEN];
        *modulus.first_mut().unwrap() = 0xed;
        *modulus.last_mut().unwrap() = 0x7f;
        let mut below = modulus;
        *below.first_mut().unwrap() = 0xec;
        assert!(canonical_x25519_public(&below));
        assert!(canonical_x25519_public(&[0; PUBLIC_KEY_LEN]));
        assert!(!canonical_x25519_public(&modulus));
        assert!(!canonical_x25519_public(&[0xff; PUBLIC_KEY_LEN]));
        let mut high_bit = [0; PUBLIC_KEY_LEN];
        *high_bit.last_mut().unwrap() = 0x80;
        assert!(!canonical_x25519_public(&high_bit));
    }
    /// HARDWARE HYBRID: SEALED IN SOFTWARE, OPENED WITH BOTH HALVES.
    ///
    /// The classical half is substituted BEHIND THE TRAIT; this probe uses
    /// software P-256, replaced in production by a TPM key without changing
    /// a byte of derivation. The trait exists for this substitution.
    #[test]
    fn a_hardware_hybrid_slot_opens_with_both_halves() {
        let pair = crate::mlkem_p256::keypair_from_seed(&[0x2f; 32]).unwrap();
        let info = slot_info(crate::label::SLOT_RECIPIENT, crate::KemAlg::MlKem768P256, &[7u8; 16]);
        let aad = [0x9d_u8; 32];

        let mut rng = TestRng::seeded(0x51);
        let blob = seal_mlkem_p256(&pair.public_key, &info, &aad, b"secret share", &mut rng).unwrap();
        assert_eq!(blob.enc.len(), 1153, "enc аппаратного гибрида не 1153 байта");

        let opened =
            open_mlkem_p256(&pair.ml_kem_seed, &pair.classical, &blob, &info, &aad).unwrap();
        assert_eq!(opened.as_slice(), b"secret share");
    }

    /// ONE HALF IS INSUFFICIENT, WHICHEVER HALF.
    ///
    /// This is the hybrid's promise, tested on both sides: a wrong
    /// post-quantum half and a wrong classical half each prevent opening
    /// the slot. Without this probe, "hybrid" would be merely an assertion.
    #[test]
    fn neither_half_alone_opens_a_hardware_hybrid_slot() {
        let pair = crate::mlkem_p256::keypair_from_seed(&[0x2f; 32]).unwrap();
        let other = crate::mlkem_p256::keypair_from_seed(&[0x88; 32]).unwrap();
        let info = slot_info(crate::label::SLOT_RECIPIENT, crate::KemAlg::MlKem768P256, &[7u8; 16]);

        let mut rng = TestRng::seeded(0x51);
        let blob = seal_mlkem_p256(&pair.public_key, &info, &[0u8; 32], b"share", &mut rng).unwrap();

        // Своя классическая, чужая постквантовая.
        assert!(
            open_mlkem_p256(&other.ml_kem_seed, &pair.classical, &blob, &info, &[0u8; 32]).is_err(),
            "слот открылся без своей постквантовой половины"
        );
        // Своя постквантовая, чужая классическая.
        assert!(
            open_mlkem_p256(&pair.ml_kem_seed, &other.classical, &blob, &info, &[0u8; 32]).is_err(),
            "слот открылся без своей классической половины"
        );
    }

    /// A HYBRID SLOT IS SEALED AND OPENED WITH THE SAME SEED.
    #[test]
    fn a_hybrid_slot_seals_and_opens_with_the_same_seed() {
        let secret = [0x2f_u8; crate::xwing::SECRET_LEN];
        let public = crate::xwing::public_key(&secret).unwrap();
        let info = slot_info(crate::label::SLOT_RECIPIENT, crate::KemAlg::XWing, &[7u8; 16]);
        let aad = [0x9d_u8; 32];

        let mut rng = TestRng::seeded(0x51);
        let blob = seal_xwing(&public, &info, &aad, b"secret share", &mut rng).unwrap();
        assert_eq!(blob.enc.len(), crate::xwing::CIPHERTEXT_LEN, "enc гибрида не 1120 байт");

        let opened = open_xwing(&secret, &blob, &info, &aad).unwrap();
        assert_eq!(opened.as_slice(), b"secret share");
    }

    /// WRONG `info` DOES NOT OPEN THE HYBRID.
    ///
    /// `info` contains `u8(kem_id)`, so a slot relabeled with another
    /// mechanism will not open even with the same key. Exactly the property for
    /// which the mechanism entered key derivation.
    #[test]
    fn a_hybrid_slot_relabelled_with_another_mechanism_does_not_open() {
        let secret = [0x2f_u8; crate::xwing::SECRET_LEN];
        let public = crate::xwing::public_key(&secret).unwrap();
        let honest = slot_info(crate::label::SLOT_RECIPIENT, crate::KemAlg::XWing, &[7u8; 16]);
        let forged = slot_info(crate::label::SLOT_RECIPIENT, crate::KemAlg::X25519HkdfSha256, &[7u8; 16]);

        let mut rng = TestRng::seeded(0x51);
        let blob = seal_xwing(&public, &honest, &[0u8; 32], b"share", &mut rng).unwrap();
        assert!(open_xwing(&secret, &blob, &forged, &[0u8; 32]).is_err());
    }

    /// CORRUPTED HYBRID CIPHERTEXT PRODUCES AEAD REJECTION, NOT PLAINTEXT.
    ///
    /// ML-KEM implicit rejection yields another shared secret, which the AEAD tag
    /// must detect. This probe guards the junction of two mechanisms: a silent failure below
    /// must become an explicit failure above.
    #[test]
    fn a_corrupted_hybrid_ciphertext_is_caught_by_the_aead_tag() {
        let secret = [0x2f_u8; crate::xwing::SECRET_LEN];
        let public = crate::xwing::public_key(&secret).unwrap();
        let info = slot_info(crate::label::SLOT_RECIPIENT, crate::KemAlg::XWing, &[7u8; 16]);

        let mut rng = TestRng::seeded(0x51);
        let mut blob = seal_xwing(&public, &info, &[0u8; 32], b"share", &mut rng).unwrap();
        if let Some(byte) = blob.enc.get_mut(0) {
            *byte ^= 1;
        }
        assert!(matches!(
            open_xwing(&secret, &blob, &info, &[0u8; 32]),
            Err(CryptoError::Authentication)
        ));
    }

    use super::*;

    /// Deterministic RNG: reproducibility matters more than strength for this test;
    /// real randomness would make failures irreproducible.
    struct TestRng([u8; 32]);

    impl TestRng {
        fn seeded(seed: u8) -> Self {
            Self([seed; 32])
        }
    }

    impl rand_core::TryRng for TestRng {
        type Error = core::convert::Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            let mut b = [0u8; 4];
            self.try_fill_bytes(&mut b)?;
            Ok(u32::from_le_bytes(b))
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            let mut b = [0u8; 8];
            self.try_fill_bytes(&mut b)?;
            Ok(u64::from_le_bytes(b))
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            for out in dst.chunks_mut(32) {
                self.0 = blake3::hash(&self.0).into();
                for (o, s) in out.iter_mut().zip(self.0.iter()) {
                    *o = *s;
                }
            }
            Ok(())
        }
    }

    impl rand_core::TryCryptoRng for TestRng {}

    const INFO: &[u8] = b"CC/v1/slot-A\x01\x02\x03";
    const AAD: &[u8] = b"policy-hash";
    const PT: &[u8] = b"secret_A: 32 bytes worth of key ";

    fn recipient(seed: u8) -> X25519Secret {
        X25519Secret::from_bytes([seed; 32])
    }

    /// Opening error without requiring plaintext to implement `Debug`/`PartialEq`.
    fn open_err(r: Result<Zeroizing<Vec<u8>>, CryptoError>) -> CryptoError {
        match r {
            Ok(_) => panic!("открытие должно было провалиться, но вернуло открытый текст"),
            Err(e) => e,
        }
    }

    #[test]
    fn a_sealed_secret_opens_only_under_the_matching_private_key() {
        let mut rng = TestRng::seeded(1);
        let sk = recipient(7);
        let pk = x25519_public(&sk);

        let blob = seal(&pk, INFO, AAD, PT, &mut rng).unwrap();
        assert_eq!(blob.ct.len(), PT.len().saturating_add(TAG_LEN), "тег обязан быть приписан");

        let opened = open(&sk, &blob, INFO, AAD).unwrap();
        assert_eq!(opened.as_slice(), PT);
    }

    #[test]
    fn a_foreign_private_key_never_opens_the_blob() {
        // Это базовое свойство схемы: без приватного ключа получателя общий
        // секрет другой, ключ AEAD другой, тег не сходится.
        let mut rng = TestRng::seeded(2);
        let sk = recipient(7);
        let blob = seal(&x25519_public(&sk), INFO, AAD, PT, &mut rng).unwrap();

        let stranger = recipient(9);
        assert_eq!(open_err(open(&stranger, &blob, INFO, AAD)), CryptoError::Authentication);
    }

    #[test]
    fn a_blob_sealed_for_one_slot_does_not_open_under_another_slots_info() {
        // Разделение назначения слотов: секрет A из слота сервера не должен
        // открываться кодом, ожидающим секрет B получателя, даже если ключ тот же.
        let mut rng = TestRng::seeded(3);
        let sk = recipient(7);
        let blob = seal(&x25519_public(&sk), INFO, AAD, PT, &mut rng).unwrap();

        let other_info = b"CC/v1/slot-B\x01\x02\x03";
        assert_eq!(open_err(open(&sk, &blob, other_info, AAD)), CryptoError::Authentication);
    }

    #[test]
    fn a_blob_does_not_open_under_a_different_aad() {
        // Привязка к контексту файла: перенос шифротекста в контейнер с другой
        // политикой обязан проваливаться, иначе правила подменяются вокруг того
        // же ключа.
        let mut rng = TestRng::seeded(4);
        let sk = recipient(7);
        let blob = seal(&x25519_public(&sk), INFO, AAD, PT, &mut rng).unwrap();

        assert_eq!(open_err(open(&sk, &blob, INFO, b"other-policy")), CryptoError::Authentication);
    }

    #[test]
    fn substituting_the_encapsulated_public_key_breaks_the_blob() {
        // Эфемерный ключ входит в ikm, поэтому подмена enc меняет ключ AEAD, а не
        // только общий секрет: склеить чужой enc со своим шифротекстом нельзя.
        let mut rng = TestRng::seeded(5);
        let sk = recipient(7);
        let mut blob = seal(&x25519_public(&sk), INFO, AAD, PT, &mut rng).unwrap();

        let intruder = recipient(11);
        blob.enc = x25519_public(&intruder).to_vec();

        assert_eq!(open_err(open(&sk, &blob, INFO, AAD)), CryptoError::Authentication);
    }

    #[test]
    fn flipping_a_single_ciphertext_bit_is_detected() {
        let mut rng = TestRng::seeded(6);
        let sk = recipient(7);
        let mut blob = seal(&x25519_public(&sk), INFO, AAD, PT, &mut rng).unwrap();

        let flipped = blob.ct.first_mut().map(|b| {
            *b ^= 0x01;
        });
        assert!(flipped.is_some(), "шифротекст не может быть пустым");

        assert_eq!(open_err(open(&sk, &blob, INFO, AAD)), CryptoError::Authentication);
    }

    #[test]
    fn two_seals_of_the_same_input_never_repeat_enc_or_ciphertext() {
        // Эфемерность — не украшение: одинаковый enc означал бы одинаковый ключ
        // AEAD при выводимом nonce, то есть повторное использование пары
        // (ключ, nonce) и потерю конфиденциальности обоих открытых текстов.
        let mut rng = TestRng::seeded(8);
        let sk = recipient(7);
        let pk = x25519_public(&sk);

        let first = seal(&pk, INFO, AAD, PT, &mut rng).unwrap();
        let second = seal(&pk, INFO, AAD, PT, &mut rng).unwrap();

        assert_ne!(first.enc, second.enc, "эфемерный ключ повторился");
        assert_ne!(first.ct, second.ct, "шифротекст повторился при том же входе");

        // И обе версии всё ещё открываются — эфемерность не ломает схему.
        assert_eq!(open(&sk, &first, INFO, AAD).unwrap().as_slice(), PT);
        assert_eq!(open(&sk, &second, INFO, AAD).unwrap().as_slice(), PT);
    }

    #[test]
    fn a_low_order_public_key_is_refused_before_any_aead_work() {
        // Нулевая точка даёт нулевой общий секрет: ключ AEAD перестал бы зависеть
        // от приватного ключа получателя, и блоб открыл бы кто угодно.
        let mut rng = TestRng::seeded(10);
        let zero_pk = [0u8; PUBLIC_KEY_LEN];

        let sealed = seal(&zero_pk, INFO, AAD, PT, &mut rng);
        assert_eq!(sealed.err(), Some(CryptoError::BadKey));

        let sk = recipient(7);
        let blob = SealedBlob { enc: zero_pk.to_vec(), nonce: [0x01; 24], ct: vec![0u8; 48] };
        assert_eq!(open_err(open(&sk, &blob, INFO, AAD)), CryptoError::BadKey);
    }

    #[test]
    fn a_ciphertext_shorter_than_the_tag_is_a_length_error() {
        let sk = recipient(7);
        let blob = SealedBlob { enc: x25519_public(&recipient(3)).to_vec(), nonce: [0x01; 24], ct: vec![0u8; TAG_LEN - 1] };
        assert_eq!(open_err(open(&sk, &blob, INFO, AAD)), CryptoError::BadLength);
    }

    #[test]
    fn an_empty_plaintext_still_produces_an_authenticated_blob() {
        // Пустая полезная нагрузка — вырожденный, но допустимый случай: блоб
        // состоит из одного тега и обязан оставаться проверяемым.
        let mut rng = TestRng::seeded(12);
        let sk = recipient(7);
        let blob = seal(&x25519_public(&sk), INFO, AAD, b"", &mut rng).unwrap();

        assert_eq!(blob.ct.len(), TAG_LEN);
        assert!(open(&sk, &blob, INFO, AAD).unwrap().is_empty());
    }
}
