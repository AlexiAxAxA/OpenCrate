// SPDX-License-Identifier: MPL-2.0
//! RSA-PSS-SHA256 verification for editing-device signatures.
//!
//! The format fixes RSA-2048, exponent 65537, and a 32-byte salt; other shapes are
//! rejected (`docs/format.md`, version 3, item 7). Only public operations run here,
//! using `crypto-bigint`, already supplied by `p256`. The verifier also builds for
//! WASM; signing belongs to the host's TPM adapter.
//!
//! `tests/kat/rsa_pss.kat` contains a frozen signature obtained from a TPM.
//! The custom padding parser remains a security-review surface.

use crate::CryptoError;
use crypto_bigint::modular::{BoxedMontyForm, BoxedMontyParams};
use crypto_bigint::{BoxedUint, Odd};
use sha2::{Digest, Sha256};

/// RSA-2048 modulus length in bytes. Also the signature length and `EM` encoding length.
pub const MODULUS_LEN: usize = 256;

/// Modulus bit width.
const BITS: u32 = 2048;

/// SHA-256 hash length.
const HLEN: usize = 32;

/// Salt length fixed by the format.
const SLEN: usize = 32;

/// `DB` length: `emLen − hLen − 1` = 256 − 32 − 1.
const DB_LEN: usize = 223;

/// Zero padding before the delimiter: `emLen − sLen − hLen − 2` = 256 − 32 − 32 − 2.
const PS_LEN: usize = 190;

/// Exponent. Fixed: see module documentation.
const EXPONENT: [u8; 3] = [0x01, 0x00, 0x01];

/// `MGF1` over SHA-256 (RFC 8017 §B.2.1), writing exactly the buffer length.
fn mgf1(seed: &[u8], out: &mut [u8]) {
    let mut counter: u32 = 0;
    for block in out.chunks_mut(HLEN) {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(counter.to_be_bytes());
        let digest = hasher.finalize();
        for (dst, src) in block.iter_mut().zip(digest.iter()) {
            *dst = *src;
        }
        // Переполнение недостижимо: блоков здесь семь. `wrapping_add` стоит
        // потому, что арифметика с побочными эффектами в этом workspace
        // запрещена, а «недостижимо» надо выражать кодом, а не комментарием.
        counter = counter.wrapping_add(1);
    }
}

/// Verify RSA-PSS-SHA256 with a 32-byte salt and exponent 65537.
///
/// # Errors
///
/// [`CryptoError::BadSignature`]: signature mismatch or encoding does not
/// conform to PSS. [`CryptoError::BadLength`]: incorrect signature length or
/// a modulus that cannot be parsed as a number of the required bit width.
///
/// Two distinct codes deliberately: "wrong length" means caller error or a
/// truncated file; "mismatch" means forgery or the wrong key. Merging them
/// would report "forgery" for our own error.
pub fn verify_pss_sha256(
    modulus: &[u8; MODULUS_LEN],
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    if signature.len() != MODULUS_LEN {
        return Err(CryptoError::BadLength);
    }

    let n = BoxedUint::from_be_slice(modulus.as_slice(), BITS).map_err(|_| CryptoError::BadLength)?;
    let s = BoxedUint::from_be_slice(signature, BITS).map_err(|_| CryptoError::BadLength)?;
    // `s < n` требует RFC, и без проверки представление подписи неоднозначно:
    // `s` и `s + n` дали бы одну кодировку.
    if s >= n {
        return Err(CryptoError::BadSignature);
    }
    // Модуль RSA нечётен по построению; чётный означает не «слабый ключ», а
    // подсунутый вместо ключа мусор.
    let odd = Odd::new(n).into_option().ok_or(CryptoError::BadLength)?;
    let params = BoxedMontyParams::new(odd);
    let exponent =
        BoxedUint::from_be_slice(&EXPONENT, BITS).map_err(|_| CryptoError::BadLength)?;

    let em = BoxedMontyForm::new(s, &params).pow(&exponent).retrieve().to_be_bytes();
    if em.len() != MODULUS_LEN {
        return Err(CryptoError::BadLength);
    }

    // Хвостовой байт кодировки.
    if em.last() != Some(&0xbc) {
        return Err(CryptoError::BadSignature);
    }

    let (masked_db, rest) = em.split_at_checked(DB_LEN).ok_or(CryptoError::BadLength)?;
    let h = rest.get(..HLEN).ok_or(CryptoError::BadLength)?;

    // Старший бит кодировки обязан быть нулевым: `emBits = 2047`, то есть на
    // один бит меньше, чем байтов. Без проверки кодировка перестаёт быть
    // однозначной.
    let first = masked_db.first().copied().ok_or(CryptoError::BadLength)?;
    if first & 0x80 != 0 {
        return Err(CryptoError::BadSignature);
    }

    let mut db = vec![0u8; DB_LEN];
    mgf1(h, &mut db);
    for (dst, src) in db.iter_mut().zip(masked_db.iter()) {
        *dst ^= *src;
    }
    if let Some(head) = db.first_mut() {
        *head &= 0x7f;
    }

    // Структура `DB`: 190 нулей, байт 0x01, 32 байта соли. Длина соли
    // ТРЕБУЕТСЯ, а не восстанавливается — см. шапку модуля.
    let (padding, tail) = db.split_at_checked(PS_LEN).ok_or(CryptoError::BadLength)?;
    if padding.iter().any(|byte| *byte != 0) {
        return Err(CryptoError::BadSignature);
    }
    let (separator, salt) = tail.split_first().ok_or(CryptoError::BadLength)?;
    if *separator != 0x01 || salt.len() != SLEN {
        return Err(CryptoError::BadSignature);
    }

    let mut hasher = Sha256::new();
    hasher.update([0u8; 8]);
    hasher.update(Sha256::digest(message));
    hasher.update(salt);
    let computed = hasher.finalize();

    let expected = <[u8; HLEN]>::try_from(computed.as_slice()).map_err(|_| CryptoError::BadLength)?;
    let found = <[u8; HLEN]>::try_from(h).map_err(|_| CryptoError::BadLength)?;

    // Сравнение постоянного времени. Здесь оно не обязательно — обе величины
    // публичны, — но доктрина сравнения дайджестов в репозитории одна на всё
    // (И-13), чтобы не приходилось каждый раз доказывать безопасность раннего
    // выхода заново.
    if crate::digest_eq(&expected, &found) {
        Ok(())
    } else {
        Err(CryptoError::BadSignature)
    }
}

// ---------------------------------------------------------------------------
// ОТКРЫТЫЕ ОПЕРАЦИИ ДЛЯ ПРОВЕРКИ АТТЕСТАЦИИ (B6a, `docs/protocol.md` §9.11).
//
// Подпись редактировавшего устройства выше прибита к RSA-2048 и PSS с солью 32:
// её производит наш подписывающий, и больше проверяющему уметь незачем. У
// аттестации подписывающие чужие — вендоры TPM и сам TPM, — и им нужно
// другое: PKCS#1 v1.5 (`sha256WithRSAEncryption` в сертификатах, RSASSA у
// ключа удостоверителя) и модули 3072 и 4096 бит у корней вендоров. Плюс одна
// операция в обратную сторону — OAEP-шифрование семени учётных данных на ключ
// подтверждения (TPM2_MakeCredential).
//
// Секрета у проверяющего здесь по-прежнему нет, кроме семени OAEP, а оно —
// ОСНОВАНИЕ, возводимое в открытую степень: время операции зависит от модуля и
// показателя, не от него. Засев OAEP приходит параметром, как всякая
// случайность в этом крейте.
// ---------------------------------------------------------------------------

/// Modulus lengths accepted by attestation verification: 2048, 3072, and 4096 bits.
///
/// Smaller lengths do not occur in TPM 2.0 and are rejected; larger ones do not occur with
/// vendors, and unbounded input would force the verifier to perform
/// arbitrary-length exponentiation.
pub const ATTESTATION_MODULUS_LENS: [usize; 3] = [256, 384, 512];

/// SHA-256 DigestInfo (RFC 8017 §9.2, note 1): the prefix before the hash.
const SHA256_DIGEST_INFO: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    0x05, 0x00, 0x04, 0x20,
];

/// `x^65537 mod n` for an allowed modulus length; output is exactly modulus length.
///
/// The modulus must have FULL bit width (the first byte's highest bit set):
/// a "2048-bit" modulus with a zero high byte is a 2040-bit key under
/// the wrong length. Input must be less than the modulus, or representation
/// would be ambiguous (`x` and `x + n` would give the same result).
fn public_op(modulus: &[u8], input: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, CryptoError> {
    let k = modulus.len();
    if !ATTESTATION_MODULUS_LENS.contains(&k) || input.len() != k {
        return Err(CryptoError::BadLength);
    }
    if modulus.first().is_none_or(|byte| byte & 0x80 == 0) {
        return Err(CryptoError::BadLength);
    }
    let bits = u32::try_from(k.saturating_mul(8)).map_err(|_| CryptoError::BadLength)?;
    let n = BoxedUint::from_be_slice(modulus, bits).map_err(|_| CryptoError::BadLength)?;
    let x = BoxedUint::from_be_slice(input, bits).map_err(|_| CryptoError::BadLength)?;
    if x >= n {
        return Err(CryptoError::BadSignature);
    }
    let odd = Odd::new(n).into_option().ok_or(CryptoError::BadLength)?;
    let params = BoxedMontyParams::new(odd);
    let exponent = BoxedUint::from_be_slice(&EXPONENT, bits).map_err(|_| CryptoError::BadLength)?;
    let out = BoxedMontyForm::new(x, &params).pow(&exponent).retrieve().to_be_bytes();
    if out.len() != k {
        return Err(CryptoError::BadLength);
    }
    Ok(zeroize::Zeroizing::new(out.to_vec()))
}

/// Verify RSASSA-PKCS1-v1_5 with SHA-256 and exponent 65537.
///
/// The encoding is CONSTRUCTED from the message and compared with the recovered value in full,
/// not parsed. PKCS#1 v1.5 padding parsing is a classic forgery site
/// (Bleichenbacher 2006: a verifier reading `00 01 FF… 00 DigestInfo` without
/// checking the tail accepted a signature crafted for `e = 3`); comparing with
/// the sole correct encoding leaves no such opening.
///
/// # Errors
/// [`CryptoError::BadLength`]: signature length differs from modulus length or modulus
/// length is disallowed; [`CryptoError::BadSignature`]: mismatch.
pub fn verify_pkcs1v15_sha256(
    modulus: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    use subtle::ConstantTimeEq as _;
    let k = modulus.len();
    if signature.len() != k {
        return Err(CryptoError::BadLength);
    }
    let recovered = public_op(modulus, signature)?;

    let t_len = SHA256_DIGEST_INFO.len().saturating_add(HLEN);
    let pad_end = k.checked_sub(t_len).ok_or(CryptoError::BadLength)?;
    let mut expected = vec![0xffu8; k];
    let (head, tail) = expected.split_at_mut(pad_end);
    // `00 01 FF…FF 00`: первый байт ноль, второй единица, разделитель — последний
    // байт набивки.
    if let Some(first) = head.first_mut() {
        *first = 0x00;
    }
    if let Some(second) = head.get_mut(1) {
        *second = 0x01;
    }
    if let Some(separator) = head.last_mut() {
        *separator = 0x00;
    }
    let (info, digest) = tail.split_at_mut(SHA256_DIGEST_INFO.len());
    info.copy_from_slice(&SHA256_DIGEST_INFO);
    digest.copy_from_slice(&Sha256::digest(message));
    // Набивки не меньше восьми байт FF (RFC 8017 §9.2): при допустимых длинах
    // модуля это верно всегда, но пусть будет сказано кодом.
    if pad_end < 11 {
        return Err(CryptoError::BadLength);
    }

    if bool::from(recovered.as_slice().ct_eq(expected.as_slice())) {
        Ok(())
    } else {
        Err(CryptoError::BadSignature)
    }
}

/// Encrypt `message` using RSAES-OAEP with SHA-256 and MGF1-SHA-256 (RFC 8017 §7.1.1).
///
/// `seed` is 32 random bytes from the caller. The TPM credential label is
/// `b"IDENTITY\0"`, including its terminating zero (TPM 2.0, part 1, "Credential
/// Protection"); it must be supplied in full; this function does not append to it.
///
/// # Errors
/// [`CryptoError::BadLength`]: disallowed modulus length or a message exceeding
/// `k − 2·32 − 2`.
pub fn encrypt_oaep_sha256(
    modulus: &[u8],
    label: &[u8],
    message: &[u8],
    seed: &[u8; HLEN],
) -> Result<Vec<u8>, CryptoError> {
    let k = modulus.len();
    if !ATTESTATION_MODULUS_LENS.contains(&k) {
        return Err(CryptoError::BadLength);
    }
    let room = k.checked_sub(HLEN.saturating_mul(2).saturating_add(2)).ok_or(CryptoError::BadLength)?;
    if message.len() > room {
        return Err(CryptoError::BadLength);
    }
    let db_len = k.saturating_sub(HLEN).saturating_sub(1);

    // DB = lHash ‖ PS (нули) ‖ 0x01 ‖ M. Буферы фиксированной длины и
    // затирающиеся: в них сообщение и семя (И-11).
    let mut db = zeroize::Zeroizing::new(vec![0u8; db_len]);
    let (l_hash, rest) = db.split_at_mut(HLEN);
    l_hash.copy_from_slice(&Sha256::digest(label));
    let marker_at = rest.len().checked_sub(message.len().saturating_add(1)).ok_or(CryptoError::BadLength)?;
    let (_, tail) = rest.split_at_mut(marker_at);
    let (marker, body) = tail.split_first_mut().ok_or(CryptoError::BadLength)?;
    *marker = 0x01;
    body.copy_from_slice(message);

    let mut db_mask = zeroize::Zeroizing::new(vec![0u8; db_len]);
    mgf1(seed, &mut db_mask);
    for (byte, mask) in db.iter_mut().zip(db_mask.iter()) {
        *byte ^= *mask;
    }
    let mut seed_mask = zeroize::Zeroizing::new([0u8; HLEN]);
    mgf1(&db, seed_mask.as_mut_slice());
    let mut masked_seed = zeroize::Zeroizing::new(*seed);
    for (byte, mask) in masked_seed.iter_mut().zip(seed_mask.iter()) {
        *byte ^= *mask;
    }

    let mut em = zeroize::Zeroizing::new(vec![0u8; k]);
    let (zero_and_seed, masked_db) = em.split_at_mut(HLEN.saturating_add(1));
    let (_, seed_slot) = zero_and_seed.split_at_mut(1);
    seed_slot.copy_from_slice(masked_seed.as_slice());
    masked_db.copy_from_slice(&db);

    Ok(public_op(modulus, &em)?.to_vec())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// Derived lengths must match the PSS layout rather than being
    /// manually copied numbers.
    #[test]
    fn the_derived_lengths_match_the_pss_layout() {
        assert_eq!(DB_LEN, MODULUS_LEN - HLEN - 1);
        assert_eq!(PS_LEN, MODULUS_LEN - SLEN - HLEN - 2);
        assert_eq!(PS_LEN + 1 + SLEN, DB_LEN);
    }

    #[test]
    fn a_signature_of_the_wrong_length_is_refused_by_length_not_by_verdict() {
        let modulus = [0xffu8; MODULUS_LEN];
        assert_eq!(
            verify_pss_sha256(&modulus, b"x", &[0u8; MODULUS_LEN - 1]),
            Err(CryptoError::BadLength)
        );
        assert_eq!(
            verify_pss_sha256(&modulus, b"x", &[0u8; MODULUS_LEN + 1]),
            Err(CryptoError::BadLength)
        );
    }

    /// An even modulus is garbage in place of a key, not a weak key.
    #[test]
    fn an_even_modulus_is_refused() {
        let mut modulus = [0xffu8; MODULUS_LEN];
        modulus[MODULUS_LEN - 1] = 0xfe;
        let signature = [0u8; MODULUS_LEN];
        assert_eq!(verify_pss_sha256(&modulus, b"x", &signature), Err(CryptoError::BadLength));
    }

    /// Incorrect modulus length or incomplete bit width causes a length rejection.
    #[test]
    fn attestation_moduli_are_limited_to_full_width_known_lengths() {
        let short = [0xffu8; 128];
        assert_eq!(verify_pkcs1v15_sha256(&short, b"x", &[0u8; 128]), Err(CryptoError::BadLength));
        let mut hollow = [0xffu8; 256];
        hollow[0] = 0x7f;
        assert_eq!(verify_pkcs1v15_sha256(&hollow, b"x", &[0u8; 256]), Err(CryptoError::BadLength));
        assert_eq!(encrypt_oaep_sha256(&short, b"", b"x", &[0u8; 32]), Err(CryptoError::BadLength));
        // Сообщение длиннее места OAEP — отказ, а не усечение.
        let modulus = [0xffu8; 256];
        assert_eq!(
            encrypt_oaep_sha256(&modulus, b"", &[0u8; 256 - 64 - 1], &[0u8; 32]),
            Err(CryptoError::BadLength)
        );
    }

    /// A signature not smaller than the modulus is rejected: representation would be ambiguous.
    #[test]
    fn a_pkcs1_signature_not_below_the_modulus_is_refused() {
        let modulus = [0xffu8; 256];
        assert_eq!(
            verify_pkcs1v15_sha256(&modulus, b"x", &[0xffu8; 256]),
            Err(CryptoError::BadSignature)
        );
    }

    /// A zero signature must fail for every modulus: `0^e = 0`, and
    /// the encoding's trailing byte will not match.
    #[test]
    fn a_zero_signature_never_verifies() {
        let modulus = [0xffu8; MODULUS_LEN];
        assert_eq!(
            verify_pss_sha256(&modulus, b"x", &[0u8; MODULUS_LEN]),
            Err(CryptoError::BadSignature)
        );
    }
}
