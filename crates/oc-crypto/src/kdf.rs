// SPDX-License-Identifier: MPL-2.0
//! Key schedule: derivations K1…K9 from `docs/format.md`, section 3.5.
//!
//! Each function corresponds to exactly one table row. No label is
//! used twice, and each derivation includes `file_id` to prevent keys from
//! matching across files even when the initial secrets match.

use crate::secret::{
    Cek, ClaimSecret, Kek, MacKey, MetaKey, PayloadKey, SecretA, SecretB, SessionMacKey, SECRET_LEN,
};
use crate::{label, AeadAlg, CryptoError};

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// K1 ikm length: exactly two 32-byte shares.
///
/// Hardcoded as a constant rather than derived from argument lengths because
/// fixed length is a condition of the combiner's correctness, not an
/// implementation detail.
const KEK_IKM_LEN: usize = 64;

/// Expand HKDF-SHA256 into a buffer whose length is specified by its type.
///
/// `expand` fails in only one case: requesting more than 255×32
/// bytes; here the array type specifies output length, at most 32 bytes,
/// so the error branch is unreachable. K1…K8 therefore return a key rather than `Result`:
/// threading an impossible variant through every key-schedule call would
/// train callers to use `?` where nothing can fail.
/// Returns a wiping wrapper rather than a bare array.
///
/// This function outputs key material. A bare `[u8; N]` remains on the stack until
/// the calling function ends and can enter the pagefile with it, without an owner
/// to wipe it on destruction. The wrapper makes wiping
/// a property of the type: previously every caller had to remember it individually,
/// and not all did.
fn hkdf_sha256<const N: usize>(salt: &[u8], ikm: &[u8], info: &[&[u8]]) -> Zeroizing<[u8; N]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = Zeroizing::new([0u8; N]);
    // Результат игнорируется осознанно: альтернатива — паника, запрещённая в
    // этом крейте. Вырождение буфера в нули поймал бы тест
    // `every_derivation_of_the_schedule_is_domain_separated`, который сравнивает
    // все производные схемы между собой.
    let _ = hk.expand_multi_info(info, okm.as_mut_slice());
    okm
}

/// Hedge a nonce against repeated RNG state (`docs/format.md` §3.1, §6.1).
///
/// Since version 3, `HKDF-Extract(salt = RNG seed,
/// ikm = u32be(len(pt)) ‖ pt ‖ u32be(len(aad)) ‖ aad)`, followed by
/// `Expand(info = label)`. Lengths separate variable-width inputs; AAD is exactly
/// what AEAD authenticates. Unrepresentable lengths return `BadLength`.
///
/// Changed plaintext or AAD changes the nonce even if the random seed repeats.
/// This is not SIV: the key is not an input, and fully repeated inputs still
/// repeat the nonce. The sender stores the nonce; the reader never derives it.
/// The seed is transient, and [`label::Label`] restricts the derivation domain.
pub fn hedged_nonce<const N: usize>(
    label: label::Label,
    seed: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<[u8; N], CryptoError> {
    let pt_len = u32::try_from(plaintext.len()).map_err(|_| CryptoError::BadLength)?;
    let aad_len = u32::try_from(aad.len()).map_err(|_| CryptoError::BadLength)?;
    // Потоковый Extract не создаёт вторую копию открытого текста в куче (И-11).
    let mut extract = hkdf::HkdfExtract::<Sha256>::new(Some(seed));
    extract.input_ikm(&pt_len.to_be_bytes());
    extract.input_ikm(plaintext);
    extract.input_ikm(&aad_len.to_be_bytes());
    extract.input_ikm(aad);
    let (_, hk) = extract.finalize();
    let mut out = [0u8; N];
    hk.expand(label.as_bytes(), &mut out).map_err(|_| CryptoError::BadLength)?;
    Ok(out)
}
/// `HMAC-SHA256` over a sequence of message pieces.
///
/// Pieces are fed sequentially rather than concatenated into a buffer: concatenation would
/// allocate memory for a message needed nowhere else.
fn hmac_sha256(key: &[u8], message: &[&[u8]]) -> [u8; 32] {
    let mut tag = [0u8; 32];
    // `new_from_slice` у HMAC принимает ключ любой длины (длинный хешируется,
    // короткий дополняется нулями), поэтому ошибка недостижима.
    if let Ok(mut mac) = <Hmac<Sha256> as KeyInit>::new_from_slice(key) {
        for part in message {
            mac.update(part);
        }
        // Выход HMAC-SHA256 всегда 32 байта, длины совпадают по построению.
        tag.copy_from_slice(mac.finalize().into_bytes().as_slice());
    }
    tag
}

/// Legacy K23 challenge echo, retained only for its frozen vector.
///
/// All challenge bytes enter the HMAC key; output is 32 bytes. This form does not
/// bind the conversation. The protocol uses [`echo_transcript`] (K31) instead,
/// and `the_old_unbound_echo_has_no_callers_outside_its_vector` guards that boundary.
pub fn prove_echo(challenge: &[u8], device_fpr: &[u8; 32]) -> [u8; 32] {
    hmac_sha256(challenge, &[label::PROVE_ECHO.as_bytes(), device_fpr])
}

/// K31 handshake transcript hash (`docs/protocol.md` §9.4).
///
/// `SHA-256("CC/v1/echo-transcript" ‖ 0x00 ‖ u32le(len(hello)) ‖ hello ‖
/// u32le(len(challenge)) ‖ challenge)`.
///
/// Both peers have these complete raw frames. Length prefixes prevent moving
/// bytes between them without changing the hash. Re-encoding parsed values would
/// lose changes to their original representation.
#[must_use]
pub fn handshake_transcript(hello_framed: &[u8], challenge_framed: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    let mut t = crate::transcript::Transcript::new(label::ECHO_TRANSCRIPT);
    t.field(hello_framed).field(challenge_framed);
    Sha256::digest(t.as_bytes()).into()
}

/// K31 proof-of-possession echo bound to the conversation.
///
/// `HMAC-SHA256(key = challenge secret, "CC/v1/echo-transcript" ‖ device_fpr ‖
/// handshake)`, where `handshake` comes from [`handshake_transcript`].
///
/// Including the transcript prevents an echo from moving to a different handshake
/// when the challenge secret repeats. It cannot distinguish a fully repeated
/// transcript after snapshot and clock rollback, or protect against a stolen key.
#[must_use]
pub fn echo_transcript(
    challenge: &[u8],
    device_fpr: &[u8; 32],
    handshake: &[u8; 32],
) -> [u8; 32] {
    hmac_sha256(challenge, &[label::ECHO_TRANSCRIPT.as_bytes(), device_fpr, handshake])
}

/// K24: a separate key authenticating requests in this conversation.
pub fn derive_session_mac_key(challenge: &[u8], device_fpr: &[u8; 32]) -> SessionMacKey {
    SessionMacKey::from_bytes(*hkdf_sha256::<SECRET_LEN>(
        &[], challenge, &[label::SESSION_MAC.as_bytes(), device_fpr],
    ))
}

/// K27 device fingerprint bound to its agreement mechanism and public key.
///
/// X25519 returns the public key itself for compatibility with frozen vectors.
/// Other supported mechanisms use
/// `SHA-256("CC/v1/device-fpr" ‖ 0x00 ‖ u8(kem_id) ‖ public)`.
/// Callers must compare this result with the presented fingerprint before using
/// the key; the mechanism byte prevents relabeling the same bytes.
///
/// # Errors
/// `public` has the wrong length, or the mechanism has no defined fingerprint.
pub fn device_fpr(kem: crate::KemAlg, public: &[u8]) -> Result<[u8; 32], CryptoError> {
    use crate::KemAlg;
    // Исполнимость спрашивается ОДНИМ именем, а не вторым `match` рядом с
    // таблицей длин. Раньше ответ «RSA-OAEP не умеем» стоял прямо в этой
    // таблице, и таких ответов по репозиторию было четыре: разойтись они могли
    // только в сторону «механизм, которого сборка не исполняет, где-то сочли
    // исполнимым».
    kem.ensure_supported()?;
    let Some(expected) = public_key_len(kem) else {
        // Недостижимо: пробел таблицы длин совпадает с неисполнимым механизмом,
        // и совпадение это не на памяти — его держит проба
        // `the_length_table_has_a_hole_exactly_where_the_build_has_no_mechanism`.
        return Err(CryptoError::UnsupportedAlgorithm);
    };
    if public.len() != expected {
        return Err(CryptoError::BadLength);
    }
    if kem == KemAlg::X25519HkdfSha256 {
        // Отпечаток И ЕСТЬ ключ — заморожено, см. выше.
        return <[u8; 32]>::try_from(public).map_err(|_| CryptoError::BadLength);
    }
    use sha2::Digest as _;
    let mut h = Sha256::new();
    h.update(label::DEVICE_FPR.as_bytes());
    h.update([0x00]);
    h.update([kem as u8]);
    h.update(public);
    Ok(h.finalize().into())
}

/// A mechanism's public-key length is a DIFFERENT question from executability.
///
/// `None` means "this mechanism defines no key shape", currently exactly
/// unimplemented RSA-OAEP: its keys have variable length and no defined
/// fingerprint. Agreement between the two tables, a gap here and `false` in
/// [`crate::seal::supports_kem`], is tested rather than assumed:
/// length is a property of shape, executability of a build; tomorrow a
/// mechanism may have a known shape that the build cannot yet execute.
///
/// `match` without `_`: a new [`crate::KemAlg`] member must break the build here.
fn public_key_len(kem: crate::KemAlg) -> Option<usize> {
    use crate::KemAlg;
    match kem {
        KemAlg::X25519HkdfSha256 => Some(32),
        KemAlg::P256HkdfSha256 => Some(65),
        KemAlg::XWing => Some(crate::xwing::PUBLIC_KEY_LEN),
        KemAlg::MlKem768P256 => Some(crate::mlkem_p256::PUBLIC_KEY_LEN),
        KemAlg::RsaOaepSha256 => None,
    }
}

/// K25: MAC of raw frame bytes including kind, but excluding the trailing MAC.
/// No label: K24 is dedicated to K25, and the kind inside the message separates requests.
pub fn request_mac(key: &SessionMacKey, framed: &[u8]) -> [u8; 32] {
    hmac_sha256(key.expose(), &[framed])
}

/// K28 wire operation identity (`docs/protocol.md` §9.10).
///
/// `SHA-256("CC/v1/operation-id" ‖ 0x00 ‖ seed(32) ‖ u8(kind) ‖ body)`.
/// `body` is the encoded request without the identity field itself.
///
/// Binding kind and body separates different operations when the RNG repeats;
/// identical requests retain the same identity. This public value provides
/// deduplication, not authentication.
#[must_use]
pub fn operation_id(seed: &[u8; 32], kind: u8, body: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    let mut h = Sha256::new();
    h.update(label::OPERATION_ID.as_bytes());
    h.update([0x00]);
    h.update(seed);
    h.update([kind]);
    h.update(body);
    h.finalize().into()
}

/// Purpose of a fresh server value: attestation challenge (`docs/protocol.md`
/// §9.11.1, step 1).
pub const FRESH_ATTEST_NONCE: u8 = 1;

/// Purpose of a fresh server value: proof-of-possession secret
/// (`docs/protocol.md` §9.4).
pub const FRESH_PROOF_SECRET: u8 = 2;

/// Purpose of a fresh server value: TPM credential secret
/// (`TPM2_MakeCredential`, `docs/protocol.md` §9.11.1, step 2).
pub const FRESH_CREDENTIAL_SECRET: u8 = 3;

/// Purpose of a fresh server value: TPM credential protection seed.
pub const FRESH_CREDENTIAL_SEED: u8 = 4;

/// Purpose of a fresh server value: OAEP seed for credential protection
/// with an RSA EK.
pub const FRESH_CREDENTIAL_OAEP: u8 = 5;

/// K30 server freshness (`docs/format.md`, "SERVER FRESHNESS IS DERIVED").
///
/// `prk = SHA-256("CC/v1/server-fresh" ‖ 0x00 ‖ seed(32) ‖ u8(kind) ‖
/// i64be(now) ‖ device_fpr(32))`, then `HKDF-Expand(prk, info = label)`.
///
/// Time separates calls for one device when random state repeats; the fingerprint
/// separates devices within one second. Fully repeated inputs, including clock
/// rollback, still produce the same output. The caller supplies the clock and seed.
///
/// # Errors
/// [`CryptoError::BadLength`] if more than 255×32 bytes are requested.
pub fn server_fresh(
    seed: &[u8; 32],
    kind: u8,
    now: i64,
    device_fpr: &[u8; 32],
    out: &mut [u8],
) -> Result<(), CryptoError> {
    use sha2::Digest as _;
    let mut h = Sha256::new();
    h.update(label::SERVER_FRESH.as_bytes());
    h.update([0x00]);
    h.update(seed);
    h.update([kind]);
    h.update(now.to_be_bytes());
    h.update(device_fpr);
    // Секрет доказательства владения — ключевой материал, и prk его порождает.
    // Голый массив на стеке уехал бы в файл подкачки без владельца, который его
    // затрёт (И-11).
    let prk = Zeroizing::new(<[u8; 32]>::from(h.finalize()));
    let hk = Hkdf::<Sha256>::from_prk(prk.as_slice()).map_err(|_| CryptoError::BadLength)?;
    hk.expand(label::SERVER_FRESH.as_bytes(), out).map_err(|_| CryptoError::BadLength)
}

/// K29: qualifying data for the TPM statement about a device key
/// (`docs/protocol.md` §9.11, link 4): `extraData` in `TPMS_ATTEST`.
///
/// The challenge binds the statement to the conversation and the fingerprint to the device:
/// a statement taken for another challenge or about another key will not match.
/// No secret: the challenge travels openly on the wire; uniqueness is required.
#[must_use]
pub fn attest_qualify(challenge: &[u8; 32], device_fpr: &[u8; 32]) -> [u8; 32] {
    use sha2::Digest as _;
    let mut h = Sha256::new();
    h.update(label::ATTEST_QUALIFY.as_bytes());
    h.update([0x00]);
    h.update(challenge);
    h.update(device_fpr);
    h.finalize().into()
}

/// K1: file wrapping key.
///
/// `HKDF-SHA256(salt=file_id, ikm=secret_A‖secret_B, info="CC/v1/kek"‖org_id‖file_id)`.
///
/// `HKDF-Extract` over concatenation is a valid combiner **only** when
/// both shares have fixed lengths; types guarantee that here.
pub fn derive_kek(file_id: &[u8; 16], org_id: &[u8], a: &SecretA, b: &SecretB) -> Kek {
    // Ровно 64 байта, по 32 на долю. При переменной длине пара (A‖B) стала бы
    // неоднозначной: другая пара с тем же склеенным представлением дала бы тот
    // же KEK, и схема «2 из 2» перестала бы быть схемой «2 из 2».
    let mut ikm = [0u8; KEK_IKM_LEN];
    let (first, second) = ikm.split_at_mut(SECRET_LEN);
    first.copy_from_slice(a.expose());
    second.copy_from_slice(b.expose());

    // `org_id` входит в `info` в каждой строке схемы: без него два арендатора с
    // совпавшими долями получили бы один ключ, а разделение арендаторов должно
    // держаться на криптографии, а не на проверке поля при чтении.
    let okm = hkdf_sha256::<SECRET_LEN>(file_id, &ikm, &[label::KEK.as_bytes(), org_id, file_id]);

    // Обе доли лежали на стеке в открытом виде. Затираем немедленно, а не
    // полагаемся на выход из функции: у копии нет владельца, который затрёт её
    // при уничтожении.
    ikm.zeroize();
    Kek::from_bytes(*okm)
}

/// K3: payload key.
///
/// `header_salt` is random for each packing operation, so repacking
/// the same content with the same CEK yields a different stream key and does not
/// produce matching ciphertexts.
pub fn derive_payload_key(
    cek: &Cek,
    header_salt: &[u8; 32],
    file_id: &[u8; 16],
    chunk_size: u32,
    aead: AeadAlg,
) -> PayloadKey {
    // `chunk_size` и `aead_id` входят в `info` потому, что оба задают способ
    // кадрирования потока. Тот же ключ при другом размере чанка означал бы, что
    // один и тот же поток ключей применён к другой разбивке открытого текста, а
    // при другом AEAD — к другой схеме nonce; и то, и другое ведёт к повторному
    // использованию ключевого потока на разных данных.
    PayloadKey::from_bytes(*hkdf_sha256::<SECRET_LEN>(
        header_salt,
        cek.expose(),
        &[
            label::PAYLOAD.as_bytes(),
            file_id.as_slice(),
            &chunk_size.to_be_bytes(),
            &[aead as u8],
        ],
    ))
}

/// K5: private-metadata key (the real filename and informational size).
///
/// A separate key lets metadata grow without affecting the payload.
pub fn derive_private_meta_key(cek: &Cek, header_salt: &[u8; 32], file_id: &[u8; 16]) -> MetaKey {
    MetaKey::from_bytes(*hkdf_sha256::<SECRET_LEN>(
        header_salt,
        cek.expose(),
        &[label::PRIVATE_META.as_bytes(), file_id.as_slice()],
    ))
}

/// K6: mutable-region MAC key.
pub fn derive_content_mac_key(cek: &Cek, header_salt: &[u8; 32], file_id: &[u8; 16]) -> MacKey {
    // Изменяемая область заверяется MAC на ключе от CEK, а не подписью автора:
    // правка происходит без автора, подписать он может только то, что видел.
    MacKey::from_bytes(*hkdf_sha256::<SECRET_LEN>(
        header_salt,
        cek.expose(),
        &[label::CONTENT_MAC.as_bytes(), file_id.as_slice()],
    ))
}

/// K12 key for authenticating a device's lease-cache head.
///
/// Derived from the device secret with empty salt and the registered cached-lease
/// label. It is independent of any file. It protects against corruption and other
/// users with write access to shared storage, not the owner of the device secret.
pub fn derive_witness_key(device: &crate::secret::X25519Secret) -> MacKey {
    MacKey::from_bytes(*hkdf_sha256::<SECRET_LEN>(
        &[],
        device.expose(),
        &[label::CACHED_LEASE.as_bytes()],
    ))
}

/// Semantic-mark variant selection (D5): `HMAC(organization key,
/// "CC/v1/mark-choice" ‖ layout ‖ u64be(copy mark) ‖ u32be(point))`,
/// the first eight bytes interpreted as `u64be`, modulo the variant count.
///
/// The key is a SEPARATE organization marking key, not a device or
/// author key: selection must be unpredictable for the recipient and reproducible for
/// whoever investigates a leak; this key serves no other purpose. The layout is
/// MAC-covered: one copy mark in two documents yields independent choices.
/// For up to sixteen variants, modulo bias is on the order of 2^-60 and
/// requires no correction.
///
/// # Errors
/// [`CryptoError::BadLength`]: zero variants.
pub fn mark_choice(key: &MacKey, layout: &[u8; 32], token: u64, point: u32, variants: u32) -> Result<u32, CryptoError> {
    if variants == 0 {
        return Err(CryptoError::BadLength);
    }
    let mut t = crate::Transcript::new(label::MARK_CHOICE);
    t.fixed(layout);
    t.u64be(token);
    t.u32be(point);
    let tag = crate::mac::compute(key, &t)?;
    let head: [u8; 8] = tag.get(..8).and_then(|h| h.try_into().ok()).ok_or(CryptoError::BadLength)?;
    let value = u64::from_be_bytes(head).checked_rem(u64::from(variants)).ok_or(CryptoError::BadLength)?;
    u32::try_from(value).map_err(|_| CryptoError::BadLength)
}

/// K14 claim secret from canonical code text: uppercase, without separators.
///
/// Hashing the text avoids a second bit-level encoding. The interface performs
/// canonicalization and checks generated entropy against [`crate::MIN_CLAIM_BITS`];
/// this function cannot infer entropy from an already chosen string.
pub fn claim_secret_from_code(canonical: &[u8]) -> ClaimSecret {
    let mut hasher = blake3::Hasher::new();
    hasher.update(label::CLAIM_CODE.as_bytes());
    hasher.update(&[0x00]);
    hasher.update(canonical);
    ClaimSecret::from_bytes(*hasher.finalize().as_bytes())
}

/// Heir-device X25519 secret derived from a claim code.
///
/// The bequest seals the existing share B to this derived device key; it does not
/// derive a replacement share. `file_id` is the salt, separating reuse of the same
/// code across files. X25519 performs scalar clamping when the key is used.
#[must_use]
pub fn device_secret_from_claim(file_id: &[u8; 16], claim: &ClaimSecret) -> [u8; 32] {
    *hkdf_sha256::<SECRET_LEN>(file_id, claim.expose(), &[label::CLAIM_DEVICE.as_bytes()])
}

pub fn secret_b_from_claim(file_id: &[u8; 16], claim: &ClaimSecret) -> (SecretB, [u8; 32]) {
    // Две разные метки над одним ikm дают независимые выходы, поэтому
    // обязательство не выдаёт ничего о доле. Обязательство вида `H(secret_B)`
    // связало бы их: кто угадал одно, получил бы проверку и для другого.
    let share = hkdf_sha256::<SECRET_LEN>(file_id, claim.expose(), &[label::SLOT_B_CLAIM.as_bytes()]);
    // `salt = file_id` не даёт строить общие таблицы: один и тот же код,
    // выданный дважды, в разных файлах превращается в разные доли.
    let commitment = hkdf_sha256::<SECRET_LEN>(file_id, claim.expose(), &[label::SLOT_B_COMMIT.as_bytes()]);
    // Обязательство секретом не является — оно и так уходит в контейнер, — а
    // доля является, и её транзитная копия исчезает вместе с обёрткой.
    (SecretB::from_bytes(*share), *commitment)
}

/// K9 slot commitment: `HMAC-SHA256(KEK, "CC/v1/slot-commit"‖core_hash)`.
///
/// Checked in constant time before AEAD opening: XChaCha20-Poly1305 alone is not
/// key-committing and could expose a claim-code partitioning oracle. `core_hash`
/// binds the header while excluding the slot and wrapped-key records, avoiding
/// a circular dependency.
pub fn slot_commitment(kek: &Kek, core_hash: &[u8; 32]) -> [u8; 32] {
    hmac_sha256(kek.expose(), &[label::SLOT_COMMIT.as_bytes(), core_hash.as_slice()])
}

/// Constant-time commitment comparison.
pub fn verify_commitment(expected: &[u8; 32], actual: &[u8; 32]) -> Result<(), CryptoError> {
    // Только `ct_eq`. Сравнение `==` выходит на первом различающемся байте, и по
    // времени ответа обязательство подбирается побайтово — за 32×256 попыток
    // вместо 2¹²⁸.
    if bool::from(expected.ct_eq(actual)) {
        Ok(())
    } else {
        // Тот же вариант ошибки, что и у неудачного тега AEAD: различить, что
        // именно не сошлось, вызывающий не должен.
        Err(CryptoError::Authentication)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    const FILE_ONE: [u8; 16] = [0x11; 16];
    const FILE_TWO: [u8; 16] = [0x12; 16];
    const SALT_ONE: [u8; 32] = [0x21; 32];
    const SALT_TWO: [u8; 32] = [0x22; 32];
    const ORG_ONE: &[u8] = b"acme";
    const ORG_TWO: &[u8] = b"acme-eu";

    fn shares() -> (SecretA, SecretB) {
        (SecretA::from_bytes([0xa1; 32]), SecretB::from_bytes([0xb2; 32]))
    }

    fn cek() -> Cek {
        Cek::from_bytes([0xc3; 32])
    }

    #[test]
    fn the_kek_follows_rfc5869_with_the_file_id_as_salt_and_the_shares_as_ikm() {
        // Перепутать местами `salt` и `ikm` — классическая ошибка применения
        // HKDF: она ничем не проявляется, кроме несовместимости с чужой
        // реализацией того же формата, а обнаружится уже после выпуска файлов.
        // Поэтому K1 пересчитывается вручную по RFC 5869: Extract с солью в роли
        // ключа HMAC, затем один блок Expand с суффиксом 0x01.
        let (a, b) = shares();
        let mut ikm = [0u8; KEK_IKM_LEN];
        let (first, second) = ikm.split_at_mut(SECRET_LEN);
        first.copy_from_slice(a.expose());
        second.copy_from_slice(b.expose());

        let prk = hmac_sha256(&FILE_ONE, &[&ikm]);
        let expected = hmac_sha256(&prk, &[label::KEK.as_bytes(), ORG_ONE, &FILE_ONE, &[0x01]]);

        assert_eq!(derive_kek(&FILE_ONE, ORG_ONE, &a, &b).expose(), &expected);
    }


    #[test]
    fn the_same_shares_in_two_files_never_yield_the_same_kek() {
        // Иначе одна вскрытая пара долей открывала бы все файлы арендатора, а не
        // один: `file_id` — единственное, что делает ключи файла его личными.
        let (a, b) = shares();
        let one = derive_kek(&FILE_ONE, ORG_ONE, &a, &b);
        let two = derive_kek(&FILE_TWO, ORG_ONE, &a, &b);
        assert_ne!(one.expose(), two.expose());
    }

    #[test]
    fn two_tenants_never_share_a_kek() {
        // Разделение арендаторов обязано держаться на криптографии: проверка
        // поля `org_id` при чтении — это решение, принимаемое клиентом, которого
        // противник контролирует.
        let (a, b) = shares();
        let one = derive_kek(&FILE_ONE, ORG_ONE, &a, &b);
        let two = derive_kek(&FILE_ONE, ORG_TWO, &a, &b);
        assert_ne!(one.expose(), two.expose());
    }

    #[test]
    fn swapping_the_two_shares_yields_a_different_kek() {
        // Проверяет порядок конкатенации: A‖B и B‖A — разные ikm. Если бы
        // порядок «поплыл» при рефакторинге, все ранее выпущенные файлы
        // перестали бы открываться, и заметить это надо на сборке, а не в поле.
        let straight = derive_kek(
            &FILE_ONE,
            ORG_ONE,
            &SecretA::from_bytes([0xa1; 32]),
            &SecretB::from_bytes([0xb2; 32]),
        );
        let swapped = derive_kek(
            &FILE_ONE,
            ORG_ONE,
            &SecretA::from_bytes([0xb2; 32]),
            &SecretB::from_bytes([0xa1; 32]),
        );
        assert_ne!(straight.expose(), swapped.expose());
    }

    #[test]
    fn an_org_id_boundary_cannot_be_shifted_into_the_file_id() {
        // `info` — конкатенация без разделителей, поэтому пара (org_id, file_id)
        // обязана оставаться однозначной. `file_id` фиксирован типом в 16 байт,
        // и сдвинуть границу можно только вместе с изменением `org_id`, что и
        // проверяется: два разных арендатора не сходятся к одному ключу.
        let (a, b) = shares();
        let long = derive_kek(&FILE_ONE, b"acme\x11\x11", &a, &b);
        let short = derive_kek(&FILE_ONE, b"acme", &a, &b);
        assert_ne!(long.expose(), short.expose());
    }

    #[test]
    fn a_repack_with_a_new_header_salt_changes_the_payload_key() {
        // Повторная упаковка того же содержимого тем же CEK не должна давать
        // совпадающих шифротекстов: иначе видно, что два контейнера содержат
        // одно и то же, без единого ключа.
        let key_one =
            derive_payload_key(&cek(), &SALT_ONE, &FILE_ONE, 65536, AeadAlg::XChaCha20Poly1305);
        let key_two =
            derive_payload_key(&cek(), &SALT_TWO, &FILE_ONE, 65536, AeadAlg::XChaCha20Poly1305);
        assert_ne!(key_one.expose(), key_two.expose());
    }

    #[test]
    fn the_payload_key_changes_with_the_chunk_size() {
        // Размер чанка задаёт разбивку открытого текста. Тот же ключ при другой
        // разбивке — это тот же ключевой поток на других данных.
        let small =
            derive_payload_key(&cek(), &SALT_ONE, &FILE_ONE, 16384, AeadAlg::XChaCha20Poly1305);
        let large =
            derive_payload_key(&cek(), &SALT_ONE, &FILE_ONE, 65536, AeadAlg::XChaCha20Poly1305);
        assert_ne!(small.expose(), large.expose());
    }

    #[test]
    fn the_payload_key_changes_with_the_aead_id() {
        // Смена профиля меняет схему nonce: у XChaCha он случайный и хранится, у
        // AES-GCM — счётчиковый. Общий ключ между профилями означал бы
        // повторное использование пары (ключ, nonce) в двух разных схемах.
        let xchacha =
            derive_payload_key(&cek(), &SALT_ONE, &FILE_ONE, 65536, AeadAlg::XChaCha20Poly1305);
        let gcm = derive_payload_key(&cek(), &SALT_ONE, &FILE_ONE, 65536, AeadAlg::Aes256Gcm);
        let siv = derive_payload_key(&cek(), &SALT_ONE, &FILE_ONE, 65536, AeadAlg::Aes256GcmSiv);
        assert_ne!(xchacha.expose(), gcm.expose());
        assert_ne!(gcm.expose(), siv.expose());
        assert_ne!(xchacha.expose(), siv.expose());
    }

    #[test]
    fn the_same_cek_in_two_files_never_yields_the_same_payload_key() {
        let one =
            derive_payload_key(&cek(), &SALT_ONE, &FILE_ONE, 65536, AeadAlg::XChaCha20Poly1305);
        let two =
            derive_payload_key(&cek(), &SALT_ONE, &FILE_TWO, 65536, AeadAlg::XChaCha20Poly1305);
        assert_ne!(one.expose(), two.expose());
    }

    #[test]
    fn private_metadata_and_content_mac_never_share_a_key_with_the_payload() {
        // Три ключа от одного CEK и одной соли. Совпадение любых двух означало
        // бы, что тег изменяемой области можно подделать ключом полезной
        // нагрузки или наоборот.
        let payload =
            derive_payload_key(&cek(), &SALT_ONE, &FILE_ONE, 65536, AeadAlg::XChaCha20Poly1305);
        let meta = derive_private_meta_key(&cek(), &SALT_ONE, &FILE_ONE);
        let mac = derive_content_mac_key(&cek(), &SALT_ONE, &FILE_ONE);
        assert_ne!(payload.expose(), meta.expose());
        assert_ne!(meta.expose(), mac.expose());
        assert_ne!(payload.expose(), mac.expose());
    }

    #[test]
    fn the_same_claim_code_in_two_files_yields_two_different_shares() {
        // Код-претензия может быть выдан повторно (тот же генератор, та же
        // длина). Соль `file_id` не даёт одному коду открыть два файла.
        let claim = ClaimSecret::from_bytes([0x7c; 32]);
        let (share_one, commit_one) = secret_b_from_claim(&FILE_ONE, &claim);
        let (share_two, commit_two) = secret_b_from_claim(&FILE_TWO, &claim);
        assert_ne!(share_one.expose(), share_two.expose());
        assert_ne!(commit_one, commit_two);
    }

    #[test]
    fn a_claim_commitment_never_equals_the_share_it_commits_to() {
        // Обязательство лежит в контейнере открытым текстом. Совпади оно с
        // долей — контейнер раздавал бы secret_B каждому, кто его прочитал.
        let claim = ClaimSecret::from_bytes([0x7c; 32]);
        let (share, commitment) = secret_b_from_claim(&FILE_ONE, &claim);
        assert_ne!(share.expose(), &commitment);
    }


    #[test]
    fn a_single_flipped_bit_in_a_commitment_is_refused() {
        let expected = [0x9a; 32];
        let mut actual = expected;
        if let Some(byte) = actual.get_mut(31) {
            *byte ^= 0x01;
        }
        assert_eq!(verify_commitment(&expected, &expected), Ok(()));
        assert_eq!(
            verify_commitment(&expected, &actual),
            Err(CryptoError::Authentication)
        );
    }

    #[test]
    fn every_derivation_of_the_schedule_is_domain_separated() {
        // Все производные получают максимально одинаковый вход: одни и те же 32
        // байта в роли долей, CEK, кода-претензии, KEK и соли. При таком входе
        // единственное, что разводит выходы, — метки домена. Совпадение любых
        // двух означало бы, что ключ одного назначения принимается вместо
        // другого: тег изменяемой области подделывается ключом метаданных,
        // обязательство слота подставляется как обязательство кода.
        let material = [0x55u8; 32];
        let file_id = [0x55u8; 16];
        let salt = material;

        let a = SecretA::from_bytes(material);
        let b = SecretB::from_bytes(material);
        let cek = Cek::from_bytes(material);
        let claim = ClaimSecret::from_bytes(material);
        let kek = Kek::from_bytes(material);

        let (share, claim_commitment) = secret_b_from_claim(&file_id, &claim);
        let derived: Vec<(&str, Vec<u8>)> = vec![
            ("K1 kek", derive_kek(&file_id, &material, &a, &b).expose().to_vec()),
            (
                "K3 payload",
                derive_payload_key(&cek, &salt, &file_id, 65536, AeadAlg::XChaCha20Poly1305)
                    .expose()
                    .to_vec(),
            ),
            (
                "K5 private-meta",
                derive_private_meta_key(&cek, &salt, &file_id).expose().to_vec(),
            ),
            (
                "K6 content-mac",
                derive_content_mac_key(&cek, &salt, &file_id).expose().to_vec(),
            ),
            ("K7 slot-b-claim", share.expose().to_vec()),
            ("K8 slot-b-commit", claim_commitment.to_vec()),
            ("K9 slot-commit", slot_commitment(&kek, &salt).to_vec()),
        ];

        for (index, (left_name, left)) in derived.iter().enumerate() {
            for (right_name, right) in derived.iter().skip(index.saturating_add(1)) {
                // Сравниваются общие префиксы, иначе K2 длиной 24 байта прошёл бы
                // тест «бесплатно», просто из-за другой длины.
                let common = left.len().min(right.len());
                let left_prefix: Vec<u8> = left.iter().copied().take(common).collect();
                let right_prefix: Vec<u8> = right.iter().copied().take(common).collect();
                assert_ne!(
                    left_prefix, right_prefix,
                    "{left_name} и {right_name} совпали: разделение доменов не работает"
                );
            }
        }

        // Заодно ловит вырождение буфера в нули: ни одна производная не должна
        // быть пустым ключом, даже если бы `expand` когда-нибудь отказал.
        for (name, value) in &derived {
            assert!(value.iter().any(|byte| *byte != 0), "{name} выродился в нули");
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod device_fpr_tests {
    use super::*;
    use crate::KemAlg;

    /// For X25519, the fingerprint IS the key: frozen by wire vectors.
    #[test]
    fn x25519_fingerprint_is_the_key_itself() {
        let key = [0x5a; 32];
        assert_eq!(device_fpr(KemAlg::X25519HkdfSha256, &key).unwrap(), key);
    }

    /// The mechanism number enters the preimage: identical bytes under another number mean
    /// a different device name. Otherwise relabeling the mechanism would preserve the name.
    #[test]
    fn the_mechanism_number_is_part_of_the_name() {
        let xw = crate::xwing::public_key(&[0x4d; 32]).unwrap();
        let a = device_fpr(KemAlg::XWing, &xw).unwrap();
        // Тот же префикс байтов, но заявленный как P-256 — длина не сходится.
        assert!(device_fpr(KemAlg::P256HkdfSha256, &xw[..65]).is_ok());
        assert_ne!(a, device_fpr(KemAlg::P256HkdfSha256, &xw[..65]).unwrap());
        assert_ne!(&a[..], &xw[..32], "хеш не должен совпадать с началом ключа");
    }

    /// Length is checked against the mechanism (I-8), not taken "as received".
    #[test]
    fn a_key_of_the_wrong_length_is_refused_not_hashed() {
        assert_eq!(device_fpr(KemAlg::X25519HkdfSha256, &[0; 31]), Err(CryptoError::BadLength));
        assert_eq!(device_fpr(KemAlg::P256HkdfSha256, &[4; 64]), Err(CryptoError::BadLength));
        assert_eq!(device_fpr(KemAlg::XWing, &[0; 1215]), Err(CryptoError::BadLength));
        assert_eq!(device_fpr(KemAlg::MlKem768P256, &[0; 1250]), Err(CryptoError::BadLength));
        assert_eq!(device_fpr(KemAlg::RsaOaepSha256, &[0; 256]), Err(CryptoError::UnsupportedAlgorithm));
    }

    /// The length table has a gap exactly where the build cannot execute a mechanism.
    ///
    /// The two tables answer DIFFERENT questions, "what shape is the key" and "can
    /// we execute this mechanism"; nothing guarantees their agreement except
    /// today's coincidence. Since `device_fpr` needs that agreement (otherwise the
    /// "no length" branch would have reachable meaning), it must be tested rather than
    /// assumed. Enumerate ALL members, not a list recalled from memory: a new
    /// mechanism will be included automatically.
    #[test]
    fn the_length_table_has_a_hole_exactly_where_the_build_has_no_mechanism() {
        // Члены берутся ИЗ РАЗБОРА, а не списком: список по памяти устареет в
        // день, когда реестр пополнят, и проба промолчит именно о новом номере.
        let all: Vec<KemAlg> = (0u8..=255).filter_map(|v| KemAlg::from_u8(v).ok()).collect();
        assert_eq!(all.len(), 5, "реестр механизмов изменился — проверьте таблицы");
        for kem in all {
            assert_eq!(
                public_key_len(kem).is_some(),
                kem.ensure_supported().is_ok(),
                "таблица длин разошлась с исполнимостью на {kem:?}"
            );
        }
    }

    /// A hashed fingerprint does not start with the label: the label is in the preimage, not the
    /// output. This guards against "fingerprint = label ‖ key" during refactoring.
    #[test]
    fn the_label_is_in_the_preimage_not_in_the_output() {
        let p = [0x04; 65];
        let f = device_fpr(KemAlg::P256HkdfSha256, &p).unwrap();
        assert!(!f.starts_with(b"CC/v1"));
    }
}
