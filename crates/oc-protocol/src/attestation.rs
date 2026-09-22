//! Документы аттестации ключа устройства на проводе (B6b, `docs/protocol.md`
//! §9.11.1).
//!
//! # Три шага, и почему не два
//!
//! Модель §9.11 — два хода проверяющего: учётные данные на EK для имени
//! удостоверителя, затем секрет и утверждение. Провайдер Windows устроен иначе:
//! удостоверитель рождается ВМЕСТЕ с утверждением (обёртка `KAST`, замер B6b), а
//! утверждению нужен вызов проверяющего заранее. Поэтому на проводе три шага:
//!
//! 1. устройство просит вызов — сервер отвечает `Nonce`;
//! 2. устройство присылает `Evidence` целиком — EK, удостоверитель, утверждение
//!    с этим вызовом — и получает учётные данные;
//! 3. устройство возвращает открытый секрет — сервер выносит вердикт.
//!
//! Все три запроса идут ПОСЛЕ доказательства владения и под MAC сессии (K25):
//! аттестация отвечает на вопрос о ключе, владение которым доказано в этом же
//! разговоре, а не о ключе, названном со слов.
//!
//! # Что здесь не проверяется
//!
//! Структуры TPM и сертификаты внутри — байты: их разбирает проверяющий
//! (`cc_authority::attest`), строго и по своим пределам. Здесь — только
//! раскладка документа и потолки длин, чтобы разбор конверта не выделял память
//! по слову отправителя.

use oc_format::tlv::{TlvReader, TlvWriter};
use oc_format::FormatError;

/// Потолок `TPM2B_PUBLIC`.
pub const MAX_PUBLIC: usize = 1026;
/// Потолок сертификата.
pub const MAX_CERTIFICATE: usize = 8 * 1024;
/// Сколько промежуточных сертификатов принимается: цепочка не длиннее четырёх.
pub const MAX_INTERMEDIATES: usize = 2;
/// Потолок `TPMS_ATTEST`.
pub const MAX_ATTEST: usize = 1024;
/// Потолок `TPMT_SIGNATURE`.
pub const MAX_SIGNATURE: usize = 600;
/// Потолок учётных данных: `TPM2B_ID_OBJECT ‖ TPM2B_ENCRYPTED_SECRET`.
pub const MAX_CREDENTIAL: usize = 2 + 132 + 2 + 512;
/// Длина вызова и секрета учётных данных.
pub const SECRET_LEN: usize = 32;

/// Основание доверия к ключу подтверждения, как его называет вердикт.
pub mod basis {
    /// Сертификат вендора до корня развёртывания.
    pub const VENDOR_CERTIFICATE: u8 = 1;
    /// Ключ подтверждения закреплён администратором.
    pub const ENROLLED_EK: u8 = 2;
}

/// Теги доказательства.
pub mod evidence_tag {
    /// `TPM2B_PUBLIC` ключа подтверждения.
    pub const EK_PUBLIC: u16 = 1;
    /// Сертификат EK (DER). Необязательное: во многих TPM его нет.
    pub const EK_CERTIFICATE: u16 = 2;
    /// Промежуточные сертификаты: `u16be(len) ‖ der` подряд, не больше двух.
    pub const INTERMEDIATES: u16 = 3;
    /// `TPM2B_PUBLIC` ключа удостоверителя.
    pub const IDENTITY_PUBLIC: u16 = 4;
    /// `TPMS_ATTEST` байтами, как его подписал TPM.
    pub const ATTEST: u16 = 5;
    /// `TPMT_SIGNATURE` под ним.
    pub const SIGNATURE: u16 = 6;
    /// `TPM2B_PUBLIC` аттестуемого ключа устройства.
    pub const DEVICE_PUBLIC: u16 = 7;
}

/// Всё, что устройство предъявляет о своём ключе.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    pub ek_public: Vec<u8>,
    pub ek_certificate: Option<Vec<u8>>,
    pub intermediates: Vec<Vec<u8>>,
    pub identity_public: Vec<u8>,
    pub attest: Vec<u8>,
    pub signature: Vec<u8>,
    pub device_public: Vec<u8>,
}

fn bounded(tag: u16, value: &[u8], limit: usize) -> Result<Vec<u8>, FormatError> {
    if value.is_empty() || value.len() > limit {
        return Err(FormatError::BadFieldLength { tag, len: value.len() });
    }
    Ok(value.to_vec())
}

/// Закодировать доказательство.
///
/// # Errors
/// [`FormatError`] — поле пустое, длиннее потолка, промежуточных больше двух.
pub fn encode_evidence(e: &Evidence) -> Result<Vec<u8>, FormatError> {
    let mut w = TlvWriter::new();
    w.put(evidence_tag::EK_PUBLIC, &bounded(evidence_tag::EK_PUBLIC, &e.ek_public, MAX_PUBLIC)?)?;
    if let Some(cert) = &e.ek_certificate {
        w.put(evidence_tag::EK_CERTIFICATE, &bounded(evidence_tag::EK_CERTIFICATE, cert, MAX_CERTIFICATE)?)?;
    }
    if !e.intermediates.is_empty() {
        if e.intermediates.len() > MAX_INTERMEDIATES {
            return Err(FormatError::BadFieldLength { tag: evidence_tag::INTERMEDIATES, len: e.intermediates.len() });
        }
        let mut chain = Vec::new();
        for cert in &e.intermediates {
            let cert = bounded(evidence_tag::INTERMEDIATES, cert, MAX_CERTIFICATE)?;
            let len = u16::try_from(cert.len())
                .map_err(|_| FormatError::BadFieldLength { tag: evidence_tag::INTERMEDIATES, len: cert.len() })?;
            chain.extend_from_slice(&len.to_be_bytes());
            chain.extend_from_slice(&cert);
        }
        w.put(evidence_tag::INTERMEDIATES, &chain)?;
    }
    w.put(evidence_tag::IDENTITY_PUBLIC, &bounded(evidence_tag::IDENTITY_PUBLIC, &e.identity_public, MAX_PUBLIC)?)?;
    w.put(evidence_tag::ATTEST, &bounded(evidence_tag::ATTEST, &e.attest, MAX_ATTEST)?)?;
    w.put(evidence_tag::SIGNATURE, &bounded(evidence_tag::SIGNATURE, &e.signature, MAX_SIGNATURE)?)?;
    w.put(evidence_tag::DEVICE_PUBLIC, &bounded(evidence_tag::DEVICE_PUBLIC, &e.device_public, MAX_PUBLIC)?)?;
    Ok(w.finish().to_vec())
}

/// Разобрать доказательство.
///
/// # Errors
/// [`FormatError`] — порядок тегов, незнакомый тег, длина, отсутствующее поле.
pub fn decode_evidence(bytes: &[u8]) -> Result<Evidence, FormatError> {
    if bytes.len() > crate::activation::MAX_DOCUMENT {
        return Err(FormatError::OffsetOverflow);
    }
    let mut reader = TlvReader::new(bytes);
    let (mut ek_public, mut ek_certificate, mut intermediates) = (None, None, Vec::new());
    let (mut identity_public, mut attest, mut signature, mut device_public) = (None, None, None, None);
    while let Some(field) = reader.next_field()? {
        let (tag, value) = (field.tag, field.value);
        match tag {
            evidence_tag::EK_PUBLIC => ek_public = Some(bounded(tag, value, MAX_PUBLIC)?),
            evidence_tag::EK_CERTIFICATE => ek_certificate = Some(bounded(tag, value, MAX_CERTIFICATE)?),
            evidence_tag::INTERMEDIATES => {
                let mut rest = value;
                if rest.is_empty() {
                    return Err(FormatError::BadFieldLength { tag, len: 0 });
                }
                while !rest.is_empty() {
                    if intermediates.len() >= MAX_INTERMEDIATES {
                        return Err(FormatError::BadFieldLength { tag, len: value.len() });
                    }
                    let (len, tail) = rest
                        .split_first_chunk::<2>()
                        .ok_or(FormatError::BadFieldLength { tag, len: value.len() })?;
                    let (cert, tail) = tail
                        .split_at_checked(usize::from(u16::from_be_bytes(*len)))
                        .ok_or(FormatError::BadFieldLength { tag, len: value.len() })?;
                    intermediates.push(bounded(tag, cert, MAX_CERTIFICATE)?);
                    rest = tail;
                }
            }
            evidence_tag::IDENTITY_PUBLIC => identity_public = Some(bounded(tag, value, MAX_PUBLIC)?),
            evidence_tag::ATTEST => attest = Some(bounded(tag, value, MAX_ATTEST)?),
            evidence_tag::SIGNATURE => signature = Some(bounded(tag, value, MAX_SIGNATURE)?),
            evidence_tag::DEVICE_PUBLIC => device_public = Some(bounded(tag, value, MAX_PUBLIC)?),
            other => crate::unknown::refuse_if_critical(other)?,
        }
    }
    Ok(Evidence {
        ek_public: ek_public.ok_or(FormatError::MissingField { tag: evidence_tag::EK_PUBLIC })?,
        ek_certificate,
        intermediates,
        identity_public: identity_public.ok_or(FormatError::MissingField { tag: evidence_tag::IDENTITY_PUBLIC })?,
        attest: attest.ok_or(FormatError::MissingField { tag: evidence_tag::ATTEST })?,
        signature: signature.ok_or(FormatError::MissingField { tag: evidence_tag::SIGNATURE })?,
        device_public: device_public.ok_or(FormatError::MissingField { tag: evidence_tag::DEVICE_PUBLIC })?,
    })
}

/// Учётные данные: `TPM2B_ID_OBJECT ‖ TPM2B_ENCRYPTED_SECRET`, та раскладка,
/// которую принимает свойство активации провайдера Windows (замер B6b).
///
/// # Errors
/// [`FormatError`] — пусто, длиннее потолка или поля не сходятся с длиной.
pub fn check_credential(bytes: &[u8]) -> Result<(), FormatError> {
    let bad = || FormatError::BadFieldLength { tag: 0, len: bytes.len() };
    if bytes.is_empty() || bytes.len() > MAX_CREDENTIAL {
        return Err(bad());
    }
    let (first, rest) = bytes.split_first_chunk::<2>().ok_or_else(bad)?;
    let (_, rest) = rest.split_at_checked(usize::from(u16::from_be_bytes(*first))).ok_or_else(bad)?;
    let (second, rest) = rest.split_first_chunk::<2>().ok_or_else(bad)?;
    if rest.len() != usize::from(u16::from_be_bytes(*second)) {
        return Err(bad());
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn sample() -> Evidence {
        Evidence {
            ek_public: vec![1; 316],
            ek_certificate: Some(vec![2; 900]),
            intermediates: vec![vec![3; 800], vec![4; 700]],
            identity_public: vec![5; 282],
            attest: vec![6; 173],
            signature: vec![7; 262],
            device_public: vec![8; 90],
        }
    }

    #[test]
    fn evidence_round_trips_with_and_without_optional_fields() {
        let full = sample();
        assert_eq!(decode_evidence(&encode_evidence(&full).unwrap()).unwrap(), full);
        let bare = Evidence { ek_certificate: None, intermediates: vec![], ..sample() };
        assert_eq!(decode_evidence(&encode_evidence(&bare).unwrap()).unwrap(), bare);
    }

    #[test]
    fn evidence_limits_are_enforced_both_ways() {
        let three = Evidence { intermediates: vec![vec![3; 10]; 3], ..sample() };
        assert!(encode_evidence(&three).is_err());
        let long = Evidence { attest: vec![0; MAX_ATTEST + 1], ..sample() };
        assert!(encode_evidence(&long).is_err());
        let empty = Evidence { signature: vec![], ..sample() };
        assert!(encode_evidence(&empty).is_err());

        // Три промежуточных, собранные руками, разбор не принимает.
        let bytes = encode_evidence(&Evidence { intermediates: vec![vec![3; 10]; 2], ..sample() }).unwrap();
        let mut w = TlvWriter::new();
        let mut chain = Vec::new();
        for _ in 0..3 {
            chain.extend_from_slice(&10u16.to_be_bytes());
            chain.extend_from_slice(&[3; 10]);
        }
        w.put(evidence_tag::EK_PUBLIC, &[1; 4]).unwrap();
        w.put(evidence_tag::INTERMEDIATES, &chain).unwrap();
        assert!(decode_evidence(&w.finish()).is_err());
        // Обрыв и хвост.
        assert!(decode_evidence(&bytes[..bytes.len() - 1]).is_err());
        let mut tail = bytes;
        tail.push(0);
        assert!(decode_evidence(&tail).is_err());
    }

    #[test]
    fn a_credential_must_be_exactly_two_sized_fields() {
        let mut good = vec![0, 2, 9, 9, 0, 3, 1, 2, 3];
        assert!(check_credential(&good).is_ok());
        good.push(0);
        assert!(check_credential(&good).is_err());
        assert!(check_credential(&[0, 2, 9, 9, 0, 3, 1, 2]).is_err());
        assert!(check_credential(&[]).is_err());
    }
}
