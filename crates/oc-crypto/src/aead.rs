//! Payload chunk encryption.
//!
//! On-disk frame: `nonce(24) ‖ ciphertext ‖ tag(16)`.
//!
//! The nonce is **stored, never derived by the reader**. Deriving it from `(file_id, chunk
//! index)` is fatal: `file_id` must remain constant during editing, so
//! rewriting a chunk under the same key would reuse a nonce with different
//! plaintexts, recovering both plaintexts through XOR and recovering
//!  the one-time Poly1305 key.
//!
//! 192 bits suffice against random collisions, but NOT against repeated
//! RNG state, so the SENDER derives the nonce through hedging (§6.1
//! and §3.1). This used to say that the width exists "precisely to make
//! random values safe", a statement that contradicted §3.1 and
//! survived decision C-13.
//!
//! This determines the crate's API shape, which is the main point here: production
//! sealing paths accept a SEED rather than a nonce: [`seal_chunk_hedged`] and
//! [`seal_metadata_hedged`]. There is no way to pass a ready-made nonce; this is a property
//! of the signature, not caller discipline. Forms accepting a nonce
//! (`seal_chunk`, `seal_metadata`) remain only behind the
//! `explicit-nonce` feature, absent from production builds.
//!
//! An inviolable rule: unauthenticated bytes never leave the function.
//! On error, the output buffer is wiped.

use crate::merkle::{leaf_of, Leaf};
use crate::secret::{MetaKey, PayloadKey, SecretBuf};
use crate::{label, AeadAlg, CryptoError};
use chacha20poly1305::{
    aead::{Aead, AeadInOut, Payload},
    KeyInit, XChaCha20Poly1305,
};
use zeroize::Zeroizing;

/// Length of the stored nonce.
pub const NONCE_LEN: usize = 24;
/// Authentication tag length.
pub const TAG_LEN: usize = 16;
/// Chunk associated-data length: label(11) + file_id(16) + index(4) + algorithm(1).
pub const CHUNK_AAD_LEN: usize = 32;

/// Private-metadata associated-data length: label(18) + file_id(16).
pub const META_AAD_LEN: usize = label::PRIVATE_META.len().saturating_add(16);

/// The AAD layout is checked at build time, not by a test.
///
/// Otherwise, changing a domain label (or its version) would silently diverge from
/// [`CHUNK_AAD_LEN`]: the buffer is filled to the end, excess bytes would remain
/// zero, and two different chunks would receive identical AAD. Addition uses
/// `saturating_add` so that the expression is not treated as arithmetic with a side
///  effect.
const _: () = assert!(
    label::CHUNK
        .len()
        .saturating_add(16)
        .saturating_add(4)
        .saturating_add(1)
        == CHUNK_AAD_LEN,
    "метка \"CC/v1/chunk\" разъехалась с CHUNK_AAD_LEN"
);

/// Chunk associated data: `"CC/v1/chunk" ‖ file_id ‖ u32be(index) ‖ u8(alg)`.
///
/// Binds a chunk to its file and its position, so reordered chunks and
/// chunks substituted from another file cannot be decrypted.
///
/// `chunk_count` and the last-chunk flag are **not included**: they would
/// allow truncation detection on every chunk, but appending would invalidate
/// all existing chunks, turning every save into a rewrite
/// of the entire file.
pub fn chunk_aad(file_id: &[u8; 16], index: u32, alg: AeadAlg) -> [u8; CHUNK_AAD_LEN] {
    // Транскрипт здесь не годится: он ставит после метки нулевой байт, а
    // спецификация (§6.1) задаёт голую конкатенацию ровно в 32 байта.
    // Однозначность обеспечена иначе — все поля после метки фиксированной длины.
    let index_be = index.to_be_bytes();
    let alg_id = alg as u8;
    let source = label::CHUNK
        .as_bytes()
        .iter()
        .chain(file_id.iter())
        .chain(index_be.iter())
        .chain(core::iter::once(&alg_id));

    let mut aad = [0u8; CHUNK_AAD_LEN];
    for (slot, byte) in aad.iter_mut().zip(source) {
        *slot = *byte;
    }
    aad
}

/// Private-metadata associated data: `"CC/v1/private-meta" ‖ file_id`.
///
/// The label differs from the chunk label, so metadata cannot masquerade as
/// chunk zero or vice versa, even under the same key.
///
/// Public for the same reason as [`chunk_aad`]: this is a **normative wire
/// value** that a second implementation must construct, and a vector freezes it.
/// While this function was private, metadata AAD was neither specified nor
/// frozen, although adjacent chunk AAD had both a line in §6.1 and a vector.
pub fn metadata_aad(file_id: &[u8; 16]) -> [u8; META_AAD_LEN] {
    let source = label::PRIVATE_META.as_bytes().iter().chain(file_id.iter());
    let mut aad = [0u8; META_AAD_LEN];
    for (slot, byte) in aad.iter_mut().zip(source) {
        *slot = *byte;
    }
    aad
}

/// Whether this build supports encryption with the declared AEAD profile.
///
/// A second boundary for `aead_id`, symmetric to [`crate::merkle::ensure_supported`]
/// for the tree hash. Without it, an identifier in a signed header parsed
/// successfully, with rejection only at the first chunk, after signature
/// verification, slot parsing, key agreement, and CEK unwrapping. Parsing a number and
/// being able to execute it are different things; both must be resolved together,
/// at parsing time.
///
/// AES profiles are declared by the format (docs/format.md §6.1), but their crates are
/// not included: the AES-GCM counter nonce does not fit a 24-byte argument and
/// requires its own path, not a branch in `match`.
///
/// The `match` deliberately has no `_`: adding a member to [`AeadAlg`] must break
/// the build here, beside the cipher, rather than pass silently.
pub fn ensure_supported(alg: AeadAlg) -> Result<(), CryptoError> {
    match alg {
        AeadAlg::XChaCha20Poly1305 => Ok(()),
        AeadAlg::Aes256Gcm | AeadAlg::Aes256GcmSiv => Err(CryptoError::UnsupportedAlgorithm),
    }
}

/// The sole AEAD profile selection point for encryption.
///
/// AES profiles are declared by the format, but their crates are not included, so
/// the client honestly reports "unsupported algorithm" instead of substituting
/// another cipher. Silently replacing a profile silently downgrades security.
/// Moreover, the AES-GCM counter nonce (`N_base ‖ u32be(i)`, §6.1) does not
/// fit this function's 24-byte argument: supporting it requires
/// a dedicated path rather than a branch in this `match`.
/// The key here is raw bytes rather than a purpose-specific type: this internal function serves
/// both payload (K3) and private metadata (K5), while the public API must
/// distinguish purposes, as it does through the `PayloadKey` and
/// `MetaKey` types.
fn seal_with(
    key: &[u8; 32],
    alg: AeadAlg,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    match alg {
        AeadAlg::XChaCha20Poly1305 => XChaCha20Poly1305::new(key.into())
            .encrypt(nonce.into(), Payload { msg: plaintext, aad })
            // Единственная причина отказа при шифровании — слишком длинный вход.
            .map_err(|_| CryptoError::BadLength),
        AeadAlg::Aes256Gcm | AeadAlg::Aes256GcmSiv => Err(CryptoError::UnsupportedAlgorithm),
    }
}

/// The sole AEAD profile selection point for CHUNK decryption.
///
/// Decrypts in place: `buffer` contains ciphertext on input and plaintext
/// of the same length on output; the tag is a separate argument.
///
/// Exists to prevent plaintext from acquiring its own heap copy:
/// see the detailed explanation in [`open_chunk_inner`]. Rejection looks
/// identical for a substituted chunk, another file, and a corrupted byte, for the
/// same reason as in [`open_with`].
///
/// The contents of `buffer` on failure are unspecified and must not be relied
/// on: an implementation may leave partially decrypted bytes there.
/// The [`open_chunk`] wrapper guarantees wiping, structurally.
fn open_in_place(
    key: &[u8; 32],
    alg: AeadAlg,
    nonce: &[u8; NONCE_LEN],
    buffer: &mut [u8],
    tag: &[u8; TAG_LEN],
    aad: &[u8],
) -> Result<(), CryptoError> {
    match alg {
        AeadAlg::XChaCha20Poly1305 => XChaCha20Poly1305::new(key.into())
            .decrypt_inout_detached(nonce.into(), aad, buffer.into(), tag.into())
            .map_err(|_| CryptoError::Authentication),
        AeadAlg::Aes256Gcm | AeadAlg::Aes256GcmSiv => Err(CryptoError::UnsupportedAlgorithm),
    }
}

/// Decryption allocating a vector: the remaining path for private metadata.
///
/// Chunks no longer pass through it: their plaintext must stay in the
/// caller's buffer to avoid the unlocked heap. Metadata consists of
/// a filename and an informational size, tens of bytes per document; restructuring
/// TLV parsing to read from another buffer is unwarranted for that, and at this size,
/// "was swapped out" and "was not swapped out" are equally unprovable. This distinction is
/// explicit so the next reader does not assume metadata was forgotten.
fn open_with(
    key: &[u8; 32],
    alg: AeadAlg,
    nonce: &[u8; NONCE_LEN],
    ct_and_tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    match alg {
        AeadAlg::XChaCha20Poly1305 => XChaCha20Poly1305::new(key.into())
            .decrypt(nonce.into(), Payload { msg: ct_and_tag, aad })
            // Причина провала не раскрывается: подставной чанк, чужой файл и
            // испорченный байт обязаны быть неразличимы для противника.
            .map_err(|_| CryptoError::Authentication),
        AeadAlg::Aes256Gcm | AeadAlg::Aes256GcmSiv => Err(CryptoError::UnsupportedAlgorithm),
    }
}

/// Seal a chunk, DERIVING the nonce internally, and return it with the tree leaf.
///
/// # Why this function exists at all
///
/// Because it physically prevents passing a nonce, which is exactly what is required
/// when a chunk is REWRITTEN. Nonce reuse under one key is fatal (I-1):
/// two different plaintexts under one keystream are exposed through XOR, and
/// reuse of the one-time Poly1305 key enables tag forgery. Yet the most natural
/// approach when editing a document, "keep the nonce already in the frame",
/// leads directly to that failure.
///
/// Rewriting is safe today as a CONSEQUENCE of hedging, rather than by API design:
/// the nonce derives from the seed and plaintext, so a different plaintext
/// naturally produces a different nonce. The property is real, but depends on the caller
/// not getting clever. A comment cannot enforce it; only a function
/// signature with no room for a nonce can.
///
/// The seed is a parameter: this crate has no RNG and must not have one
/// (I-1 requires stored nonces, not reader-derived ones, but the SENDER derives them
/// from a random seed PLUS plaintext, so that repeating
/// RNG state after snapshot rollback does not repeat the nonce).
///
/// # Errors
/// Returns [`CryptoError`] on encryption failure or an incorrect output length.
pub fn seal_chunk_hedged(
    key: &PayloadKey,
    alg: AeadAlg,
    file_id: &[u8; 16],
    index: u32,
    nonce_seed: &[u8; NONCE_LEN],
    plaintext: &[u8],
    out: &mut Vec<u8>,
) -> Result<([u8; NONCE_LEN], Leaf), CryptoError> {
    let aad = chunk_aad(file_id, index, alg);
    let nonce = crate::kdf::hedged_nonce::<NONCE_LEN>(crate::label::FRAME_NONCE, nonce_seed, plaintext, &aad)?;
    let leaf = seal_chunk_with_aad(key, alg, index, &nonce, plaintext, &aad, out)?;
    Ok((nonce, leaf))
}

/// Encrypt a chunk, appending `ciphertext ‖ tag` to `out`, and return the tree leaf.
///
/// `out` is cleared before writing.
///
/// # The nonce is an argument here: this is the DANGEROUS form
///
/// Retained for frozen vectors and probes needing precisely the
/// nonce recorded in the artifact. Production paths do not use it: they use
/// [`seal_chunk_hedged`], where a nonce can be derived but cannot be supplied.
///
/// If you are writing a new call unrelated to KATs, this is not the function you need.
/// Rewriting a chunk with the nonce already in its frame destroys confidentiality
/// of both plaintexts at once (I-1).
///
/// # Why a feature gate rather than just a doc-comment warning
///
/// Because documentation is not a boundary. While production code can see the function,
/// the "dangerous form" relies on the next caller reading the paragraph above;
/// `explicit-nonce` is disabled by default and enabled ONLY through
/// `[dev-dependencies]`, so a production build cannot see this function
/// at all: the call does not compile. A boundary visible to the compiler cannot
/// be overlooked in a hurry.
#[cfg(any(test, feature = "explicit-nonce"))]
pub fn seal_chunk(
    key: &PayloadKey,
    alg: AeadAlg,
    file_id: &[u8; 16],
    index: u32,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    out: &mut Vec<u8>,
) -> Result<Leaf, CryptoError> {
    let aad = chunk_aad(file_id, index, alg);
    seal_chunk_with_aad(key, alg, index, nonce, plaintext, &aad, out)
}

// Один AAD используется и засевом, и AEAD; второй сборки контекста здесь нет.
fn seal_chunk_with_aad(
    key: &PayloadKey,
    alg: AeadAlg,
    index: u32,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8; CHUNK_AAD_LEN],
    out: &mut Vec<u8>,
) -> Result<Leaf, CryptoError> {
    // Здесь достаточно `clear`: в `out` лежит шифротекст предыдущего чанка, а не
    // секрет. Затирание нужно на пути расшифрования, где в буфере открытый текст.
    out.clear();

    let sealed = seal_with(key.expose(), alg, nonce, plaintext, aad)?;
    // Тег — последние 16 байт: крейт возвращает `ct ‖ tag` одним вектором.
    // Разрезается он здесь потому, что в лист входят ОБЕ части, и по отдельности:
    // шифротекст связывает содержимое, тег — ключ и связанные данные.
    let (ct, tag) = sealed.split_last_chunk::<TAG_LEN>().ok_or(CryptoError::BadLength)?;
    let leaf = leaf_of(index, nonce, tag, ct);

    out.extend_from_slice(&sealed);
    Ok(leaf)
}

/// Decrypt a chunk into `out` and return the tree leaf computed from the tag.
///
/// On any error, `out` is cleared and wiped: the caller must have no
/// opportunity to read unauthenticated bytes.
pub fn open_chunk(
    key: &PayloadKey,
    alg: AeadAlg,
    file_id: &[u8; 16],
    index: u32,
    nonce: &[u8; NONCE_LEN],
    ct_and_tag: &[u8],
    out: &mut SecretBuf,
) -> Result<Leaf, CryptoError> {
    // Тип буфера, а не обычный `Vec<u8>`: гарантия затирания обязана держаться на
    // сигнатуре, а не на дисциплине вызывающего. Обычный вектор уносил бы
    // расшифрованный чанк в кучу при каждом уничтожении и при каждом росте.
    //
    // Затирание на входе и на выходе, а не только на входе: правило §6.5 обязано
    // держаться и после будущих правок тела, которые начнут писать в `out`
    // раньше проверки тега. Обёртка гарантирует его структурно.
    out.wipe();
    match open_chunk_inner(key, alg, file_id, index, nonce, ct_and_tag, out) {
        Ok(leaf) => Ok(leaf),
        Err(err) => {
            out.wipe();
            Err(err)
        }
    }
}

/// Decryption body extracted for the wiping wrapper: every error
/// returns through [`open_chunk`], which guarantees clearing `out`.
fn open_chunk_inner(
    key: &PayloadKey,
    alg: AeadAlg,
    file_id: &[u8; 16],
    index: u32,
    nonce: &[u8; NONCE_LEN],
    ct_and_tag: &[u8],
    out: &mut SecretBuf,
) -> Result<Leaf, CryptoError> {
    let (ct, tag) = ct_and_tag
        .split_last_chunk::<TAG_LEN>()
        .ok_or(CryptoError::BadLength)?;
    let aad = chunk_aad(file_id, index, alg);

    // Расшифровка идёт НА МЕСТЕ, в буфере вызывающего, и это не оптимизация.
    //
    // Раньше здесь выделялся `Zeroizing<Vec<u8>>` под открытый текст, и он
    // затирался при уничтожении — то есть защищал от того, что блок достанется
    // аллокатору читаемым. От второй беды он не защищал вовсе: блок обычной кучи
    // может уехать в файл подкачки, пока живёт. Просмотрщик запирает свою память
    // (`VirtualLock`) именно затем, чтобы этого не случилось, и промежуточная
    // копия в незапертой куче сводила бы всю меру на нет — на каждый чанк.
    //
    // Порядок операций здесь единственно возможный: сначала объявить длину, потом
    // скопировать шифротекст, потом расшифровать. Затирать буфер перед копией
    // нельзя не по соображениям скорости — `as_declared_mut` не затирает
    // намеренно: стереть буфер после копии значило бы стереть вход.
    let room = out.as_capacity_mut().get_mut(..ct.len()).ok_or(CryptoError::BadLength)?;
    room.copy_from_slice(ct);
    out.declare_len(ct.len())?;
    open_in_place(key.expose(), alg, nonce, out.as_declared_mut(), tag, &aad)?;

    // Лист считается по тем же величинам, что и при запечатывании, — по nonce,
    // тегу и **шифротексту**, — поэтому читатель сверяет чанк с деревом, не имея
    // исходного открытого текста и не имея ключа.
    Ok(leaf_of(index, nonce, tag, ct))
}

/// Seal private metadata, DERIVING the nonce internally, and return it alongside.
///
/// # Why this function exists
///
/// For the same reason as [`seal_chunk_hedged`]. It was added later not
/// because metadata is safer: hedging existed here, but the CALLER assembled it;
/// the engine derived a nonce itself and passed it here ready-made. While
/// that derivation step is external, it can be skipped, and the function signature
/// cannot prevent that: it accepts any 24 bytes. Reuse here is especially
/// costly: `CEK` and `header_salt` come from the same RNG, so VM snapshot
/// rollback would repeat both the K5 key and nonce, while plaintexts
/// (the name and size of another document) would differ.
///
/// The seed is a parameter: this crate has no RNG and must not have one.
///
/// Returns `(nonce, ciphertext)`: the nonce is not secret, but the block cannot
/// be decrypted without it, and it is stored ready-made in the file (I-1).
///
/// # Errors
/// Returns [`CryptoError`] on nonce derivation or encryption failure.
pub fn seal_metadata_hedged(
    key: &MetaKey,
    file_id: &[u8; 16],
    nonce_seed: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<([u8; NONCE_LEN], Vec<u8>), CryptoError> {
    let aad = metadata_aad(file_id);
    // Метка своя (`"CC/v1/meta-nonce"`), а не чанковая: И-12 требует, чтобы два
    // разных вывода не совпали ни при каком совпадении остальных входов.
    let nonce =
        crate::kdf::hedged_nonce::<NONCE_LEN>(label::META_NONCE, nonce_seed, plaintext, &aad)?;
    let ct = seal_with(key.expose(), AeadAlg::XChaCha20Poly1305, &nonce, plaintext, &aad)?;
    Ok((nonce, ct))
}

/// Encrypt private header metadata under its own K5 key.
///
/// # The nonce is an argument here: this is the DANGEROUS form
///
/// The same caveat and `explicit-nonce` feature as for `seal_chunk`: this form
/// remains for vectors and probes needing precisely the nonce recorded in the
/// artifact. Production paths use [`seal_metadata_hedged`], where a nonce
/// can be derived but cannot be supplied.
#[cfg(any(test, feature = "explicit-nonce"))]
pub fn seal_metadata(
    key: &MetaKey,
    file_id: &[u8; 16],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // Профиль здесь не выбирается: K5 определён спецификацией как XChaCha, а
    // поле `private_meta` лежит в заголовке, который подписан до всякого выбора.
    let aad = metadata_aad(file_id);
    seal_with(key.expose(), AeadAlg::XChaCha20Poly1305, nonce, plaintext, &aad)
}

/// Decrypt private metadata.
pub fn open_metadata(
    key: &MetaKey,
    file_id: &[u8; 16],
    nonce: &[u8; NONCE_LEN],
    ct_and_tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let aad = metadata_aad(file_id);
    // Настоящее имя файла и его размер — те самые данные, ради сокрытия
    // которых поле вообще существует, поэтому наружу они уходят только в
    // затирающей обёртке.
    let plaintext = open_with(key.expose(), AeadAlg::XChaCha20Poly1305, nonce, ct_and_tag, &aad)?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    const FILE_ID: [u8; 16] = [0x11; 16];
    const OTHER_FILE_ID: [u8; 16] = [0x12; 16];
    const NONCE: [u8; NONCE_LEN] = [0x21; NONCE_LEN];
    const CHUNK_64_KIB: usize = 65536;

    /// A metadata key with the SAME bytes as the payload key.
    ///
    /// The equality is deliberate: the test
    /// `private_metadata_never_opens_as_a_chunk` checks that metadata
    /// cannot replace a chunk even when key and nonce coincide, meaning protection
    /// comes from domain separation in AAD rather than differing keys. After separating
    ///  the types (`MetaKey` versus `PayloadKey`), there is no other way to express "the same key",
    /// which is exactly why those types were separated.
    fn meta_key() -> MetaKey {
        MetaKey::from_bytes([0x33; 32])
    }

    fn key() -> PayloadKey {
        PayloadKey::from_bytes([0x33; 32])
    }

    /// Filler with no repeated block: identical blocks would hide an error
    /// in the frame layout.
    fn payload(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn chunk_aad_is_exactly_the_bytes_the_format_prescribes() {
        // Раскладка AAD — часть формата на диске: разъедься она с §6.1, файлы
        // одной сборки перестанут открываться другой.
        let aad = chunk_aad(&FILE_ID, 7, AeadAlg::XChaCha20Poly1305);
        let mut expected = Vec::new();
        expected.extend_from_slice(b"CC/v1/chunk");
        expected.extend_from_slice(&FILE_ID);
        expected.extend_from_slice(&7u32.to_be_bytes());
        expected.push(1);
        assert_eq!(expected.len(), CHUNK_AAD_LEN, "сумма полей AAD не 32 байта");
        assert_eq!(aad.as_slice(), expected.as_slice());
        assert_eq!(label::CHUNK.len(), 11, "метка чанка обязана быть 11 байт");
    }

    #[test]
    fn a_chunk_round_trips_at_every_boundary_length() {
        // Границы: пустой чанк (файл нулевой длины всё равно имеет чанк),
        // однобайтовый, неполный и полный чанк размера по умолчанию.
        for len in [0usize, 1, 65535, CHUNK_64_KIB] {
            let pt = payload(len);
            let mut frame = Vec::new();
            let sealed_leaf =
                seal_chunk(&key(), AeadAlg::XChaCha20Poly1305, &FILE_ID, 3, &NONCE, &pt, &mut frame)
                    .unwrap();
            assert_eq!(frame.len(), len.saturating_add(TAG_LEN), "кадр не равен ct‖tag");

            let mut got = SecretBuf::with_capacity(1 << 17);
            let opened_leaf =
                open_chunk(&key(), AeadAlg::XChaCha20Poly1305, &FILE_ID, 3, &NONCE, &frame, &mut got)
                    .unwrap();
            assert_eq!(got.as_slice(), pt.as_slice(), "длина {len}");
            assert_eq!(sealed_leaf, opened_leaf);
        }
    }

    #[test]
    fn the_leaf_from_sealing_equals_the_leaf_from_opening() {
        // Иначе читатель не смог бы сверить чанк с деревом, не расшифровав и не
        // перешифровав его заново.
        let pt = payload(1000);
        let mut frame = Vec::new();
        let sealed =
            seal_chunk(&key(), AeadAlg::XChaCha20Poly1305, &FILE_ID, 9, &NONCE, &pt, &mut frame)
                .unwrap();
        let mut got = SecretBuf::with_capacity(1 << 17);
        let opened =
            open_chunk(&key(), AeadAlg::XChaCha20Poly1305, &FILE_ID, 9, &NONCE, &frame, &mut got)
                .unwrap();
        assert_eq!(sealed, opened);
        // И лист действительно зависит от места чанка: иначе перестановка была бы
        // невидима дереву.
        let mut other = Vec::new();
        let neighbour =
            seal_chunk(&key(), AeadAlg::XChaCha20Poly1305, &FILE_ID, 10, &NONCE, &pt, &mut other)
                .unwrap();
        assert_ne!(sealed, neighbour);
    }

    #[test]
    fn a_chunk_offered_as_its_neighbour_does_not_open() {
        // Перестановка чанков внутри файла ловится тем, что номер входит в AAD.
        let pt = payload(4096);
        let mut frame = Vec::new();
        seal_chunk(&key(), AeadAlg::XChaCha20Poly1305, &FILE_ID, 4, &NONCE, &pt, &mut frame)
            .unwrap();

        let mut got = SecretBuf::with_capacity(1 << 17);
        let err =
            open_chunk(&key(), AeadAlg::XChaCha20Poly1305, &FILE_ID, 5, &NONCE, &frame, &mut got)
                .unwrap_err();
        assert_eq!(err, CryptoError::Authentication);
        assert!(got.is_empty());
    }

    #[test]
    fn a_chunk_from_another_file_does_not_open() {
        // Подстановка чанка из другого контейнера ловится тем, что file_id входит
        // в AAD, — при том что ключ у двух файлов теоретически может совпасть.
        let pt = payload(4096);
        let mut frame = Vec::new();
        seal_chunk(&key(), AeadAlg::XChaCha20Poly1305, &FILE_ID, 4, &NONCE, &pt, &mut frame)
            .unwrap();

        let mut got = SecretBuf::with_capacity(1 << 17);
        let err = open_chunk(
            &key(),
            AeadAlg::XChaCha20Poly1305,
            &OTHER_FILE_ID,
            4,
            &NONCE,
            &frame,
            &mut got,
        )
        .unwrap_err();
        assert_eq!(err, CryptoError::Authentication);
        assert!(got.is_empty());
    }

    #[test]
    fn flipping_any_byte_of_ciphertext_or_tag_is_caught() {
        let pt = payload(64);
        let mut frame = Vec::new();
        seal_chunk(&key(), AeadAlg::XChaCha20Poly1305, &FILE_ID, 0, &NONCE, &pt, &mut frame)
            .unwrap();

        for (pos, _) in frame.iter().enumerate() {
            let mut broken = frame.clone();
            *broken.get_mut(pos).unwrap() ^= 1;
            let mut got = SecretBuf::with_capacity(1 << 17);
            let err = open_chunk(
                &key(),
                AeadAlg::XChaCha20Poly1305,
                &FILE_ID,
                0,
                &NONCE,
                &broken,
                &mut got,
            )
            .unwrap_err();
            assert_eq!(err, CryptoError::Authentication, "байт {pos} прошёл проверку");
        }
    }

    #[test]
    fn a_failed_open_leaves_no_bytes_in_the_output_buffer() {
        // §6.5: непроверенные байты не покидают функцию. Проверяем на буфере,
        // который до вызова был непустым, — иначе тест прошёл бы и без затирания.
        let pt = payload(2048);
        let mut frame = Vec::new();
        seal_chunk(&key(), AeadAlg::XChaCha20Poly1305, &FILE_ID, 1, &NONCE, &pt, &mut frame)
            .unwrap();
        *frame.get_mut(0).unwrap() ^= 0xff;

        // Буфер намеренно непустой до вызова: проверяем, что неудача не только
        // не пишет новое, но и стирает то, что лежало раньше.
        let mut got = SecretBuf::with_capacity(4096);
        got.fill_from(&[0xaa; 4096]).unwrap();
        let err =
            open_chunk(&key(), AeadAlg::XChaCha20Poly1305, &FILE_ID, 1, &NONCE, &frame, &mut got)
                .unwrap_err();
        assert_eq!(err, CryptoError::Authentication);
        assert!(got.is_empty(), "в буфере осталось {} байт", got.len());

        // Слишком короткий кадр — тоже ошибка, и тоже с пустым буфером.
        let mut short = SecretBuf::with_capacity(32);
        let err = open_chunk(
            &key(),
            AeadAlg::XChaCha20Poly1305,
            &FILE_ID,
            1,
            &NONCE,
            &[0u8; 4],
            &mut short,
        )
        .unwrap_err();
        assert_eq!(err, CryptoError::BadLength);
        assert!(short.is_empty());
    }

    #[test]
    fn the_same_plaintext_under_different_nonces_never_repeats_a_ciphertext() {
        // Ради этого свойства nonce и хранится, а не выводится из (file_id, i):
        // при правке чанка nonce обязан смениться, иначе XOR двух шифротекстов
        // выдаёт оба открытых текста.
        let pt = payload(1024);
        let nonce_b: [u8; NONCE_LEN] = [0x22; NONCE_LEN];

        let mut first = Vec::new();
        seal_chunk(&key(), AeadAlg::XChaCha20Poly1305, &FILE_ID, 2, &NONCE, &pt, &mut first)
            .unwrap();
        let mut second = Vec::new();
        seal_chunk(&key(), AeadAlg::XChaCha20Poly1305, &FILE_ID, 2, &nonce_b, &pt, &mut second)
            .unwrap();

        assert_ne!(first, second, "тот же ключ и nonce дал бы повторное использование");
    }

    #[test]
    fn sealing_overwrites_whatever_the_output_buffer_held_before() {
        // Иначе кадр чанка склеился бы с предыдущим и файл стал бы нечитаемым.
        let pt = payload(10);
        let mut out = vec![0xcc; 100];
        seal_chunk(&key(), AeadAlg::XChaCha20Poly1305, &FILE_ID, 0, &NONCE, &pt, &mut out).unwrap();
        assert_eq!(out.len(), pt.len().saturating_add(TAG_LEN));
    }

    #[test]
    fn metadata_round_trips_under_its_own_key() {
        let meta = b"secret-report.docx\0application/pdf".to_vec();
        let sealed = seal_metadata(&meta_key(), &FILE_ID, &NONCE, &meta).unwrap();
        assert_eq!(sealed.len(), meta.len().saturating_add(TAG_LEN));
        let opened = open_metadata(&meta_key(), &FILE_ID, &NONCE, &sealed).unwrap();
        assert_eq!(opened.as_slice(), meta.as_slice());

        // Чужой file_id не открывает метаданные: заголовок нельзя перенести в
        // другой контейнер вместе с настоящим именем файла.
        let err = open_metadata(&meta_key(), &OTHER_FILE_ID, &NONCE, &sealed).unwrap_err();
        assert_eq!(err, CryptoError::Authentication);
    }

    #[test]
    fn private_metadata_never_opens_as_a_chunk() {
        // Разные метки домена: блок метаданных не подменяет чанк нулевого номера
        // даже при совпавшем ключе и nonce.
        let meta = payload(64);
        let sealed = seal_metadata(&meta_key(), &FILE_ID, &NONCE, &meta).unwrap();
        let mut got = SecretBuf::with_capacity(1 << 17);
        let err =
            open_chunk(&key(), AeadAlg::XChaCha20Poly1305, &FILE_ID, 0, &NONCE, &sealed, &mut got)
                .unwrap_err();
        assert_eq!(err, CryptoError::Authentication);
        assert!(got.is_empty());
    }

    #[test]
    fn unsupported_aead_profiles_are_refused_not_silently_substituted() {
        // Молчаливая подстановка другого шифра — понижение стойкости без следа в
        // формате. Отказ обязан быть явным на обоих направлениях.
        let pt = payload(32);
        for alg in [AeadAlg::Aes256Gcm, AeadAlg::Aes256GcmSiv] {
            let mut out = Vec::new();
            let err = seal_chunk(&key(), alg, &FILE_ID, 0, &NONCE, &pt, &mut out).unwrap_err();
            assert_eq!(err, CryptoError::UnsupportedAlgorithm);
            assert!(out.is_empty());

            let mut got = SecretBuf::with_capacity(1 << 17);
            let err =
                open_chunk(&key(), alg, &FILE_ID, 0, &NONCE, &[0u8; 48], &mut got).unwrap_err();
            assert_eq!(err, CryptoError::UnsupportedAlgorithm);
            assert!(got.is_empty());
        }
    }

    /// ONE SEED FOR TWO DIFFERENT PLAINTEXTS PRODUCES DIFFERENT NONCES.
    ///
    /// # What this test protects
    ///
    /// Chunk rewriting, which does not exist yet. When it arrives (phase 6),
    /// the most natural approach will be "take the nonce already in the
    /// frame", which would destroy confidentiality of both plaintexts at once:
    /// one keystream for two different plaintexts exposes them through XOR, and
    /// the one-time Poly1305 key permits tag forgery (I-1).
    ///
    /// This checks that protection is a PROPERTY OF DERIVATION rather than
    /// caller discipline: even with exactly the same seed, as after
    /// VM snapshot rollback, a different plaintext yields a different nonce.
    #[test]
    fn the_same_seed_still_yields_different_nonces_for_different_plaintexts() {
        let seed = [0x33u8; NONCE_LEN];
        let mut first = Vec::new();
        let mut second = Vec::new();

        let (nonce_a, _) =
            seal_chunk_hedged(&key(), AeadAlg::XChaCha20Poly1305, &FILE_ID, 0, &seed, b"one", &mut first)
                .unwrap();
        let (nonce_b, _) =
            seal_chunk_hedged(&key(), AeadAlg::XChaCha20Poly1305, &FILE_ID, 0, &seed, b"two", &mut second)
                .unwrap();

        assert_ne!(nonce_a, nonce_b, "разный текст обязан дать разный nonce при том же засеве");
        assert_ne!(first, second);
    }

    /// IDENTICAL PLAINTEXT WITH AN IDENTICAL SEED WILL MATCH: THIS IS THE BOUNDARY.
    ///
    /// Stated explicitly because this is the residual risk named in
    /// README: a full repeat of RNG state WITH IDENTICAL plaintext
    /// produces identical ciphertext, revealing equality of the inputs.
    /// The test guards against this boundary silently shifting in either direction.
    #[test]
    fn the_same_seed_and_the_same_plaintext_repeat_and_that_is_the_known_limit() {
        let seed = [0x44u8; NONCE_LEN];
        let mut first = Vec::new();
        let mut second = Vec::new();

        let (nonce_a, _) =
            seal_chunk_hedged(&key(), AeadAlg::XChaCha20Poly1305, &FILE_ID, 0, &seed, b"same", &mut first)
                .unwrap();
        let (nonce_b, _) =
            seal_chunk_hedged(&key(), AeadAlg::XChaCha20Poly1305, &FILE_ID, 0, &seed, b"same", &mut second)
                .unwrap();

        assert_eq!(nonce_a, nonce_b);
        assert_eq!(first, second);
    }
}
