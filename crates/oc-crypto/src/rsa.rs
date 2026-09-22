//! Проверка подписи RSA-PSS-SHA256 — подпись редактировавшего устройства.
//!
//! # Почему своя реализация, а не крейт
//!
//! Проверка обязана жить в ЧИСТОМ крейте: `oc-format` и `oc-protocol` проверяют подписи и
//! собирается под `wasm32-unknown-unknown`, поэтому платформенным CNG обойтись
//! нельзя. Крейта `rsa` в дереве нет, и брать его неприятно — на нём висит
//! RUSTSEC-2023-0071 (Marvin), и хотя к нашему употреблению он относится
//! косвенно (атака про приватные операции, а подписывает TPM), исключение
//! пришлось бы выписывать руками.
//!
//! `crypto-bigint` в дереве уже есть, пришёл с `p256`. Всё, что нужно сверх
//! него, — возведение в степень по модулю с ОТКРЫТЫМ показателем и разбор
//! кодировки PSS. **Секретов в операции нет ни одного**, поэтому постоянное
//! время не требуется, и «своя крипта» здесь допустима ровно по этой причине, а
//! не потому, что так дешевле.
//!
//! # Чем это опасно и что отсюда следует
//!
//! Ломались исторически именно ПРОВЕРЯЮЩИЕ: атака Блайхенбахера на `e = 3` была
//! о небрежном разборе набивки, а не о стойкости RSA. Поэтому здесь:
//!
//! * **показатель не параметр.** Он прибит к 65537 внутри, и передать сюда `e = 3`
//!   нечем. Проверяющему незачем уметь то, чего наш подписывающий не производит;
//! * **длина соли не восстанавливается, а требуется.** Формат закрепил 32 байта
//!   (`docs/format.md`, «ВЕРСИЯ 3 ОТКРЫТА», п. 7), и подпись с другой солью —
//!   отказ, а не «примем, раз сходится». Восстановление длины по разделителю
//!   принимает больше, чем формат разрешает;
//! * **длина модуля задана типом.** RSA-2048 и только он.
//!
//! # Что проверено исполнением
//!
//! Вектор в `tests/kat/rsa_pss.kat` снят с ЖИВОГО TPM этой машины
//! (`spikes/rsa-pss-tpm/`), а не выдуман и не взят из документации. Заново из
//! спецификации он не выводится.

use crate::CryptoError;
use crypto_bigint::modular::{BoxedMontyForm, BoxedMontyParams};
use crypto_bigint::{BoxedUint, Odd};
use sha2::{Digest, Sha256};

/// Длина модуля RSA-2048 в байтах. Она же длина подписи и длина кодировки `EM`.
pub const MODULUS_LEN: usize = 256;

/// Разрядность модуля.
const BITS: u32 = 2048;

/// Длина хеша SHA-256.
const HLEN: usize = 32;

/// Длина соли, закреплённая форматом.
const SLEN: usize = 32;

/// Длина `DB`: `emLen − hLen − 1` = 256 − 32 − 1.
const DB_LEN: usize = 223;

/// Нулевая набивка перед разделителем: `emLen − sLen − hLen − 2` = 256 − 32 − 32 − 2.
const PS_LEN: usize = 190;

/// Показатель. Прибит: см. шапку модуля.
const EXPONENT: [u8; 3] = [0x01, 0x00, 0x01];

/// `MGF1` над SHA-256 (RFC 8017 §B.2.1), пишет ровно в длину буфера.
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

/// Проверить подпись RSA-PSS-SHA256 с солью 32 байта и показателем 65537.
///
/// # Errors
///
/// [`CryptoError::BadSignature`] — подпись не сходится либо её кодировка не
/// соответствует PSS. [`CryptoError::BadLength`] — не та длина подписи или
/// модуль, не разбирающийся как число нужной разрядности.
///
/// Два разных кода намеренно: «длина не та» — это ошибка вызывающего или
/// обрезанный файл, «не сходится» — это подделка либо чужой ключ. Свести их в
/// один значило бы отвечать «подделка» на собственную ошибку.
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

/// Длины модуля, принимаемые проверкой аттестации: 2048, 3072 и 4096 бит.
///
/// Меньше — не бывает у TPM 2.0 и не принимается; больше — не бывает у
/// вендоров, и вход без предела стоил бы проверяющему возведения в степень
/// произвольной длины.
pub const ATTESTATION_MODULUS_LENS: [usize; 3] = [256, 384, 512];

/// DigestInfo SHA-256 (RFC 8017 §9.2, примечание 1): префикс перед хешем.
const SHA256_DIGEST_INFO: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
    0x05, 0x00, 0x04, 0x20,
];

/// `x^65537 mod n` над модулем допустимой длины; результат — ровно длины модуля.
///
/// Модуль обязан иметь ПОЛНУЮ разрядность (старший бит первого байта поднят):
/// «2048-битный» модуль с нулевым старшим байтом — это 2040-битный ключ под
/// чужой длиной. Вход обязан быть меньше модуля: иначе представление
/// неоднозначно (`x` и `x + n` дали бы одно и то же).
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

/// Проверить подпись RSASSA-PKCS1-v1_5 с SHA-256 и показателем 65537.
///
/// Кодировка СОБИРАЕТСЯ из сообщения и сравнивается с восстановленной целиком,
/// а не разбирается. Разбор набивки PKCS#1 v1.5 — классическое место подделок
/// (Блайхенбахер 2006: проверяющий, который читал `00 01 FF… 00 DigestInfo` и не
/// проверял хвост, принимал подпись, подобранную под `e = 3`); сравнение с
/// единственно верной кодировкой такой лазейки не оставляет.
///
/// # Errors
/// [`CryptoError::BadLength`] — длина подписи не равна длине модуля или модуль
/// недопустимой длины; [`CryptoError::BadSignature`] — не сходится.
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

/// Зашифровать `message` RSAES-OAEP с SHA-256 и MGF1-SHA-256 (RFC 8017 §7.1.1).
///
/// `seed` — случайные 32 байта от вызывающего. Метка TPM для учётных данных —
/// `b"IDENTITY\0"`, с завершающим нулём (TPM 2.0, часть 1, «Credential
/// Protection»); передаётся целиком, функция её не дополняет.
///
/// # Errors
/// [`CryptoError::BadLength`] — модуль недопустимой длины или сообщение длиннее
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

    /// Производные длины обязаны сходиться с раскладкой PSS, а не быть
    /// переписанными от руки числами.
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

    /// Чётный модуль — не слабый ключ, а мусор на месте ключа.
    #[test]
    fn an_even_modulus_is_refused() {
        let mut modulus = [0xffu8; MODULUS_LEN];
        modulus[MODULUS_LEN - 1] = 0xfe;
        let signature = [0u8; MODULUS_LEN];
        assert_eq!(verify_pss_sha256(&modulus, b"x", &signature), Err(CryptoError::BadLength));
    }

    /// Модуль не той длины или без полной разрядности — отказ по длине.
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

    /// Подпись не меньше модуля — отказ: представление было бы неоднозначным.
    #[test]
    fn a_pkcs1_signature_not_below_the_modulus_is_refused() {
        let modulus = [0xffu8; 256];
        assert_eq!(
            verify_pkcs1v15_sha256(&modulus, b"x", &[0xffu8; 256]),
            Err(CryptoError::BadSignature)
        );
    }

    /// Нулевая подпись не должна проходить ни при каком модуле: `0^e = 0`, и
    /// хвостовой байт кодировки не совпадёт.
    #[test]
    fn a_zero_signature_never_verifies() {
        let modulus = [0xffu8; MODULUS_LEN];
        assert_eq!(
            verify_pss_sha256(&modulus, b"x", &[0u8; MODULUS_LEN]),
            Err(CryptoError::BadSignature)
        );
    }
}
