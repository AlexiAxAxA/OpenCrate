//! Отзывная: подписанный сервером документ «файл отозван».
//!
//! # Зачем документ, если отзыв и так действует
//!
//! Отзыв действует тем, что сервер перестаёт выдавать лизинги, — и потому
//! доходит только до того, кто к серверу ходит. Отзывная делает отзыв ДАННЫМИ:
//! подписанный ключом подписи лизингов документ, который читатель принимает
//! откуда угодно — по подписке, по запросу, файлом рядом с контейнером, от
//! соседа. Канал перестаёт быть единственной дорогой (Ф-18, ярус 3).
//!
//! Подделать её нельзя без ключа сервера; распространить настоящую — значит
//! распространить правду. Проверяется тем же ключом, что и лизинг: автор
//! закрепил его в заголовке контейнера под своей подписью, и второго доверия
//! отзывная не заводит.
//!
//! # Раскладка
//!
//! Как у лизинга: `подпись(64) ‖ тело`, тело — TLV по правилам И-7 и И-8,
//! транскрипт подписи — метка `"CC/v1/revocation"` из общего реестра §3.6
//! (метка была заведена заранее и до этого дня ни для чего не применялась).
//! Отзыв окончателен: эпоха в документе — для журнала и отчётов, а не для
//! сравнения «какой отзыв новее».

use oc_crypto::CryptoError;

use oc_format::FormatError;
use oc_format::tlv::{TlvReader, TlvWriter};

/// Версия документа. Своя, не контейнера.
pub const REVOCATION_VERSION: u16 = 1;

/// Длина подписи впереди тела.
pub const SIGNATURE_LEN: usize = 64;

/// Теги тела. Критичные все: незнакомый — отказ.
pub mod tag {
    /// `u16le`.
    pub const VERSION: u16 = 1;
    /// `bytes[16]`.
    pub const FILE_ID: u16 = 2;
    /// Эпоха файла после отзыва. `u64le`.
    pub const EPOCH: u16 = 3;
    /// Момент отзыва по часам сервера. `i64le`, секунды.
    pub const AT: u16 = 4;
}

/// Разобранная отзывная.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revocation {
    pub file_id: [u8; 16],
    pub epoch: u64,
    pub at: i64,
}

/// Транскрипт подписи — через [`oc_crypto::Transcript`], который требует метку.
#[must_use]
pub fn signing_transcript(body: &[u8]) -> oc_crypto::Transcript {
    let mut t = oc_crypto::Transcript::new(oc_crypto::label::REVOCATION);
    t.field(body);
    t
}

/// Собрать тело. Подпись накладывает тот, у кого ключ.
///
/// # Errors
/// [`FormatError`], если тело не кодируется.
pub fn encode(revocation: &Revocation) -> Result<Vec<u8>, FormatError> {
    let mut w = TlvWriter::new();
    w.put(tag::VERSION, &REVOCATION_VERSION.to_le_bytes())?;
    w.put(tag::FILE_ID, &revocation.file_id)?;
    w.put(tag::EPOCH, &revocation.epoch.to_le_bytes())?;
    w.put(tag::AT, &revocation.at.to_le_bytes())?;
    Ok(w.finish().to_vec())
}

/// Разобрать тело. Подпись здесь НЕ проверяется — см. [`verify_signed`].
///
/// # Errors
/// [`FormatError`] при незнакомом теге, неточной длине или пропуске поля.
pub fn decode(body: &[u8]) -> Result<Revocation, FormatError> {
    let mut reader = TlvReader::new(body);
    let mut version = None;
    let mut file_id = None;
    let mut epoch = None;
    let mut at = None;
    while let Some(field) = reader.next_field()? {
        match field.tag {
            tag::VERSION => version = Some(u16_le(field.tag, field.value)?),
            tag::FILE_ID => file_id = Some(exact16(field.tag, field.value)?),
            tag::EPOCH => epoch = Some(u64_le(field.tag, field.value)?),
            tag::AT => at = Some(u64_le(field.tag, field.value)?.cast_signed()),
            other => crate::unknown::refuse_if_critical(other)?,
        }
    }
    if version.ok_or(FormatError::MissingField { tag: tag::VERSION })? != REVOCATION_VERSION {
        return Err(FormatError::UnknownCriticalField { tag: tag::VERSION });
    }
    Ok(Revocation {
        file_id: file_id.ok_or(FormatError::MissingField { tag: tag::FILE_ID })?,
        epoch: epoch.ok_or(FormatError::MissingField { tag: tag::EPOCH })?,
        at: at.ok_or(FormatError::MissingField { tag: tag::AT })?,
    })
}

/// Проверить подпись тела ключом подписи лизингов из заголовка контейнера.
///
/// # Errors
/// [`CryptoError`], если подпись не сходится.
pub fn verify(
    body: &[u8],
    signature: &[u8; SIGNATURE_LEN],
    lease_verify_key: &[u8; 32],
) -> Result<(), CryptoError> {
    oc_crypto::sign::verify(lease_verify_key, &signing_transcript(body), signature)
}

/// Проверить подпись, потом разобрать — в этом порядке, и только в этом.
///
/// Разбор незаверенных байтов давал бы различимые отказы на том, что никто не
/// подписывал (И-5 для документов). Совпадение `file_id` с контейнером сверяет
/// вызывающий: здесь контейнера нет.
///
/// # Errors
/// [`FormatError::BadHeaderSignature`] при короткой или несошедшейся подписи,
/// иначе — ошибки разбора.
pub fn verify_signed(bytes: &[u8], lease_verify_key: &[u8; 32]) -> Result<Revocation, FormatError> {
    let (signature, body) =
        bytes.split_at_checked(SIGNATURE_LEN).ok_or(FormatError::BadHeaderSignature)?;
    let signature: [u8; SIGNATURE_LEN] =
        signature.try_into().map_err(|_| FormatError::BadHeaderSignature)?;
    verify(body, &signature, lease_verify_key).map_err(|_| FormatError::BadHeaderSignature)?;
    decode(body)
}

fn exact16(tag: u16, value: &[u8]) -> Result<[u8; 16], FormatError> {
    value.try_into().map_err(|_| FormatError::BadFieldLength { tag, len: value.len() })
}

fn u16_le(tag: u16, value: &[u8]) -> Result<u16, FormatError> {
    let bytes: [u8; 2] =
        value.try_into().map_err(|_| FormatError::BadFieldLength { tag, len: value.len() })?;
    Ok(u16::from_le_bytes(bytes))
}

fn u64_le(tag: u16, value: &[u8]) -> Result<u64, FormatError> {
    let bytes: [u8; 8] =
        value.try_into().map_err(|_| FormatError::BadFieldLength { tag, len: value.len() })?;
    Ok(u64::from_le_bytes(bytes))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use oc_crypto::sign::{Ed25519Signer, Signer};

    fn signed(revocation: &Revocation, signer: &Ed25519Signer) -> Vec<u8> {
        let body = encode(revocation).unwrap();
        let sig = signer.sign(&signing_transcript(&body)).unwrap();
        let mut out = sig.to_vec();
        out.extend_from_slice(&body);
        out
    }

    /// Подписанная отзывная проходит своим ключом и отвергается чужим, битой
    /// подписью, битым телом и коротким документом.
    #[test]
    fn a_signed_revocation_verifies_with_the_lease_key_and_nothing_else_passes() {
        let server = Ed25519Signer::from_seed(&[0x41; 32]);
        let stranger = Ed25519Signer::from_seed(&[0x42; 32]);
        let doc = Revocation { file_id: [0x5a; 16], epoch: 3, at: 1_755_561_600 };
        let bytes = signed(&doc, &server);

        assert_eq!(verify_signed(&bytes, &server.public_key()).unwrap(), doc);
        assert!(verify_signed(&bytes, &stranger.public_key()).is_err(), "чужой ключ принят");

        let mut bad_sig = bytes.clone();
        bad_sig[10] ^= 1;
        assert!(verify_signed(&bad_sig, &server.public_key()).is_err(), "битая подпись принята");

        let mut bad_body = bytes.clone();
        let last = bad_body.len() - 1;
        bad_body[last] ^= 1;
        assert!(verify_signed(&bad_body, &server.public_key()).is_err(), "битое тело принято");

        assert!(verify_signed(&bytes[..40], &server.public_key()).is_err(), "обрубок принят");
    }

    /// ПОДПИСЬ ПРОВЕРЯЕТСЯ ДО РАЗБОРА ТЕЛА — сторож на порядок двух строк.
    ///
    /// Соседняя проба подаёт разбираемое тело, а пробы на разбор зовут [`decode`]
    /// напрямую, поэтому перестановка `decode` перед `verify` внутри
    /// [`verify_signed`] не роняла ни одной из них. Случай, где встречаются оба
    /// условия — тело неразбираемое И подпись чужая, — не проверял никто, а он
    /// и есть тот, ради которого комбинатор написан: различимые коды разбора,
    /// выданные для незаверенных байтов, — оракул разбора (И-5 для документов).
    #[test]
    fn the_signature_is_checked_before_the_body_is_parsed() {
        let server = Ed25519Signer::from_seed(&[0x41; 32]);
        let stranger = Ed25519Signer::from_seed(&[0x42; 32]);

        // Два способа быть неразбираемым: нет обязательного поля и незнакомый
        // критичный тег — ветки разбора у них разные.
        let empty = TlvWriter::new().finish().to_vec();
        let mut w = TlvWriter::new();
        w.put(0x7FFF, &[0xab; 4]).unwrap();
        let unknown_critical = w.finish().to_vec();

        for (what, body) in [("пустое тело", empty), ("чужой критичный тег", unknown_critical)] {
            assert!(decode(&body).is_err(), "{what}: предпосылка пробы неверна, тело разбирается");
            let sig = stranger.sign(&signing_transcript(&body)).unwrap();
            let mut bytes = sig.to_vec();
            bytes.extend_from_slice(&body);
            let outcome = verify_signed(&bytes, &server.public_key());
            assert!(
                matches!(outcome, Err(FormatError::BadHeaderSignature)),
                "{what}: разбор произошёл до проверки подписи, ответ {outcome:?}"
            );
        }
    }

    /// Тело: незнакомый тег — отказ; неточная длина — отказ; чужая версия — отказ.
    #[test]
    fn the_body_is_parsed_strictly() {
        let doc = Revocation { file_id: [1; 16], epoch: 0, at: 0 };
        let body = encode(&doc).unwrap();
        assert_eq!(decode(&body).unwrap(), doc);

        let mut w = TlvWriter::new();
        w.put(tag::VERSION, &REVOCATION_VERSION.to_le_bytes()).unwrap();
        w.put(tag::FILE_ID, &[1; 15]).unwrap();
        w.put(tag::EPOCH, &0u64.to_le_bytes()).unwrap();
        w.put(tag::AT, &0i64.to_le_bytes()).unwrap();
        assert!(decode(&w.finish()).is_err(), "короткий идентификатор дополнен");

        let mut w = TlvWriter::new();
        w.put(tag::VERSION, &2u16.to_le_bytes()).unwrap();
        w.put(tag::FILE_ID, &[1; 16]).unwrap();
        w.put(tag::EPOCH, &0u64.to_le_bytes()).unwrap();
        w.put(tag::AT, &0i64.to_le_bytes()).unwrap();
        assert!(decode(&w.finish()).is_err(), "чужая версия принята");
    }
}
