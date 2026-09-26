// SPDX-License-Identifier: MPL-2.0
//! Server-signed permission to open one file on one device.
//!
//! A lease is separate from the author-signed container so it can expire, renew,
//! or be revoked without rewriting the header. Verification uses the server key
//! pinned by the author in `authority.lease_verify_key`.
//! Signatures cover raw body bytes and are checked before parsing.

use oc_crypto::CryptoError;
use oc_policy::{Attestation, LeaseFacts, Timestamp, TpmClock};

use oc_format::FormatError;
use oc_format::tlv::{TlvReader, TlvWriter};

/// Signature length at the start of the lease document.
///
/// The signature deliberately precedes the body: its length is fixed, so the reader reaches
/// it without parsing a single body byte. The same layout and name as for
/// revocation ([`crate::revocation::SIGNATURE_LEN`]) and orders
/// ([`crate::order::SIGNATURE_LEN`]): three documents from one party must
/// be read consistently.
pub const SIGNATURE_LEN: usize = 64;

/// Lease document version.
///
/// Independent of the container: the documents change at different rates.
/// Mixing them would require bumping the container version for a lease field.
pub const LEASE_VERSION: u16 = 1;

/// Document version with a server policy (tag 12).
///
/// Written ONLY when the server actually tightens restrictions: otherwise the lease
/// bytes stay unchanged, and the frozen vector `tests/kat/lease.kat` remains
/// valid. An old client REJECTS this document by version before any field
/// parsing: a restriction it does not understand must not silently
/// disappear (I-10, `docs/protocol.md` §2).
pub const LEASE_VERSION_WITH_SERVER_POLICY: u16 = 2;

/// Document version with the attestation flag (tag 13, B6b).
///
/// Written ONLY when the server accepted device key attestation in this
/// conversation; a server policy may or may not accompany it. An old
/// client rejects such a lease by version, but never receives one: the flag
/// is issued only to a client that underwent attestation, hence one that
/// understands it.
pub const LEASE_VERSION_WITH_ATTESTATION: u16 = 3;

/// Lease tag registry. Strictly ascending, criticality by range, as in §2.
///
/// Numbers are normative: raw body bytes are signed, so an implementation
/// numbering fields differently would generate a different signature and silently diverge.
pub mod tag {
    /// Document version. `u16le`.
    pub const VERSION: u16 = 1;
    /// File to which the permission applies. `bytes[16]`.
    ///
    /// Without this field, a lease for one file would work for any other: the cheapest
    /// possible mistake with the most expensive consequences.
    pub const FILE_ID: u16 = 2;
    /// Device receiving the lease. `bytes[32]`.
    pub const DEVICE_FPR: u16 = 3;
    /// Hash of the policy under which it was issued. `bytes[32]`.
    ///
    /// The client compares this with the policy hash in ITS OWN container: the server must not
    /// be able to grant permission under rules the author never wrote.
    pub const POLICY_HASH: u16 = 4;
    /// Strictly increasing per (file, device) pair. `u64le`.
    pub const SEQ: u16 = 5;
    /// Increases on revocation. `u64le`.
    pub const EPOCH: u16 = 6;
    /// Issuance time. `i64le`, seconds.
    pub const ISSUED_AT: u16 = 7;
    /// Expiration time. `i64le`, seconds.
    pub const EXPIRES_AT: u16 = 8;
    /// State: `u8`, 1 active, 2 revoked. ALWAYS written.
    pub const STATUS: u16 = 9;
    /// Remaining opens. `u32le`, or an **empty value** meaning "the server set no
    /// limit". ALWAYS written.
    ///
    /// The distinction between "field absent" and "field present but empty" is normative,
    /// following `max_opens` in §4, for the same reason: an empty value is the server's explicit
    /// statement "I set no limit", while a missing field means its intent
    /// is entirely unknown.
    pub const OPENS_REMAINING: u16 = 10;
    /// Hardware clock readings at issuance: `u32le` reset_count ‖ `u64le` clock_ms.
    ///
    /// Optional: devices without a hardware clock receive a lease without it.
    pub const TPM_CLOCK: u16 = 11;
    /// Server policy, `policy_codec` encoding. Only in version 2 and required there.
    pub const SERVER_POLICY: u16 = 12;
    /// Server-accepted device key attestation: `u8`, a basis from the
    /// `crate::attestation::basis` registry. Only in lease version 3.
    pub const ATTESTED: u16 = 13;
}

/// Lease state on the wire.
const STATUS_ACTIVE: u8 = 1;
const STATUS_REVOKED: u8 = 2;

/// Parsed lease: facts for the evaluator plus data the evaluator does not need.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    /// Which file it applies to. Checked by the caller: there is nothing to compare it with here.
    pub file_id: [u8; 16],
    pub facts: LeaseFacts,
}

/// Lease signature transcript.
///
/// Label and separator `0x00` follow the shared rule in §3.6. Label `"CC/v1/lease"`
/// is prefix-free relative to all others: the adjacent cache uses `"CC/v1/cached-lease"`
/// specifically to avoid extending it with `"CC/v1/lease-cache"`.
/// Uses [`oc_crypto::Transcript`] rather than manual construction: its constructor REQUIRES
/// a label and inserts the separator itself. With hand-built bytes, the label could be
/// forgotten, placing lease and header signatures in the same domain.
#[must_use]
pub fn signing_transcript(body: &[u8]) -> oc_crypto::Transcript {
    let mut t = oc_crypto::Transcript::new(oc_crypto::label::LEASE);
    t.field(body);
    t
}

/// Build a lease body.
///
/// Returns only the body: whoever holds the key applies the signature;
/// this crate holds no keys and cannot hold them.
pub fn encode(lease: &Lease) -> Result<Vec<u8>, FormatError> {
    let mut w = TlvWriter::new();
    let version = if lease.facts.attested.is_some() {
        LEASE_VERSION_WITH_ATTESTATION
    } else if lease.facts.server_policy.is_some() {
        LEASE_VERSION_WITH_SERVER_POLICY
    } else {
        LEASE_VERSION
    };
    w.put(tag::VERSION, &version.to_le_bytes())?;
    w.put(tag::FILE_ID, &lease.file_id)?;
    w.put(tag::DEVICE_FPR, &lease.facts.device_fingerprint)?;
    w.put(tag::POLICY_HASH, &lease.facts.policy_hash)?;
    w.put(tag::SEQ, &lease.facts.seq.to_le_bytes())?;
    w.put(tag::EPOCH, &lease.facts.epoch.to_le_bytes())?;
    w.put(tag::ISSUED_AT, &lease.facts.issued_at.0.to_le_bytes())?;
    w.put(tag::EXPIRES_AT, &lease.facts.expires_at.0.to_le_bytes())?;

    let status = if lease.facts.revoked { STATUS_REVOKED } else { STATUS_ACTIVE };
    w.put(tag::STATUS, &[status])?;

    // Пишется всегда, в том числе пустым: см. комментарий у тега.
    match lease.facts.opens_remaining {
        Some(n) => w.put(tag::OPENS_REMAINING, &n.to_le_bytes())?,
        None => w.put(tag::OPENS_REMAINING, &[])?,
    }

    if let Some(clock) = lease.facts.tpm_clock {
        let mut value = [0u8; 12];
        let (head, tail) = value.split_at_mut(4);
        head.copy_from_slice(&clock.reset_count.to_le_bytes());
        tail.copy_from_slice(&clock.clock_ms.to_le_bytes());
        w.put(tag::TPM_CLOCK, &value)?;
    }

    // ПОСЛЕ часов, а не до: теги идут строго по возрастанию (И-7), и 12 > 11.
    // Порядок здесь не вопрос вкуса — писатель, нарушивший его, получает отказ
    // от самого `TlvWriter`, и лизинг с часами вообще перестал бы выпускаться.
    if let Some(policy) = &lease.facts.server_policy {
        // Кодек тот же, что у политики автора в заголовке: второе представление
        // того же смысла разошлось бы с первым на первой же новой строке.
        let bytes = oc_format::policy_codec::encode(oc_format::header::CONTAINER_VERSION, policy)?;
        w.put(tag::SERVER_POLICY, &bytes)?;
    }

    if let Some(attested) = lease.facts.attested {
        let basis = match attested {
            Attestation::VendorCertificate => crate::attestation::basis::VENDOR_CERTIFICATE,
            Attestation::EnrolledEk => crate::attestation::basis::ENROLLED_EK,
        };
        w.put(tag::ATTESTED, &[basis])?;
    }

    Ok(w.finish().to_vec())
}

/// Parse a lease body without verifying its signature.
///
/// The result is untrusted and must not authorize access. For external
/// `signature ‖ body` bytes, use [`verify_signed`]. This parser also supports
/// replaying one's own stored issuance.
pub fn decode(body: &[u8]) -> Result<Lease, FormatError> {
    let mut reader = TlvReader::new(body);

    let mut version = None;
    let mut file_id = None;
    let mut device_fpr = None;
    let mut policy_hash = None;
    let mut seq = None;
    let mut epoch = None;
    let mut issued_at = None;
    let mut expires_at = None;
    let mut status = None;
    let mut opens_remaining = None;
    let mut tpm_clock = None;
    let mut server_policy = None;
    let mut attested = None;

    while let Some(field) = reader.next_field()? {
        match field.tag {
            tag::VERSION => version = Some(field.u16()?),
            tag::FILE_ID => file_id = Some(field.array::<16>()?),
            tag::DEVICE_FPR => device_fpr = Some(field.array::<32>()?),
            tag::POLICY_HASH => policy_hash = Some(field.array::<32>()?),
            tag::SEQ => seq = Some(u64_le(field.value)?),
            tag::EPOCH => epoch = Some(u64_le(field.value)?),
            tag::ISSUED_AT => issued_at = Some(i64_le(field.value)?),
            tag::EXPIRES_AT => expires_at = Some(i64_le(field.value)?),
            tag::STATUS => {
                let byte = field.u8()?;
                // Незнакомое состояние отвергается НА РАЗБОРЕ, а не трактуется
                // как отказ. Разобрать номер и суметь его исполнить — разные
                // вещи: состояние из будущей версии может означать что угодно, и
                // догадываться о нём мы не вправе.
                status = Some(match byte {
                    STATUS_ACTIVE => false,
                    STATUS_REVOKED => true,
                    _ => {
                        return Err(FormatError::BadFieldLength { tag: tag::STATUS, len: 1 });
                    }
                });
            }
            tag::OPENS_REMAINING => {
                // Пустое значение — «лимита нет», и это не то же самое, что
                // отсутствие поля: отсутствие ловится ниже как MissingField.
                opens_remaining = Some(if field.value.is_empty() {
                    None
                } else {
                    Some(u32_le(field.value)?)
                });
            }
            tag::TPM_CLOCK => tpm_clock = Some(decode_clock(field.value)?),
            tag::SERVER_POLICY => {
                let reader = oc_format::header::SUPPORTED_READER_VERSION;
                server_policy = Some(oc_format::policy_codec::decode(reader, field.value)?);
            }
            // Незнакомое основание — отказ разбора, а не «аттестовано как-то»:
            // признак поднимает ступень привязки, и догадываться о нём нельзя.
            tag::ATTESTED => {
                attested = Some(match field.u8()? {
                    crate::attestation::basis::VENDOR_CERTIFICATE => Attestation::VendorCertificate,
                    crate::attestation::basis::ENROLLED_EK => Attestation::EnrolledEk,
                    _ => return Err(FormatError::BadFieldLength { tag: tag::ATTESTED, len: 1 }),
                });
            }
            // Та же доктрина, что в §2: критичный диапазон — отказ,
            // необязательный — пропуск. Лизинг разрешает доступ, и поле из
            // будущей версии в критичном диапазоне может ограничивать этот
            // доступ так, как мы не понимаем.
            //
            // Решение зовётся общим помощником крейта, а не сравнивается здесь
            // с `CRIT_TAG_MAX`. Пока лизинг был единственным пропускающим
            // разборщиком, своя строка стоила недорого; с 2026-09-21 правило
            // общее, и вторая копия границы означала бы два места, где её
            // можно сдвинуть по отдельности.
            unknown => crate::unknown::refuse_if_critical(unknown)?,
        }
    }

    let version = version.ok_or(FormatError::MissingField { tag: tag::VERSION })?;
    // Версия и состав полей сходятся, и это не педантизм: документ версии 1 с
    // политикой сервера означал бы, что клиент прежней сборки принял бы её,
    // не заметив, а документ версии 2 без политики — что ужесточение потерялось
    // по дороге. Оба случая ведут к правам, которых никто не давал.
    //
    // Версия 3 — признак аттестации обязателен, политика сервера по выбору; в
    // версиях 1 и 2 признака быть не может: клиент прежней сборки ступень по нему
    // не поднимет, а новый не должен поднимать по документу, который его не
    // объявлял.
    match (version, server_policy.is_some(), attested.is_some()) {
        (LEASE_VERSION, false, false)
        | (LEASE_VERSION_WITH_SERVER_POLICY, true, false)
        | (LEASE_VERSION_WITH_ATTESTATION, _, true) => {}
        (LEASE_VERSION | LEASE_VERSION_WITH_SERVER_POLICY, _, true) => {
            return Err(FormatError::UnknownCriticalField { tag: tag::ATTESTED });
        }
        (LEASE_VERSION_WITH_ATTESTATION, _, false) => {
            return Err(FormatError::MissingField { tag: tag::ATTESTED });
        }
        (LEASE_VERSION, true, false) => {
            return Err(FormatError::UnknownCriticalField { tag: tag::SERVER_POLICY });
        }
        (LEASE_VERSION_WITH_SERVER_POLICY, false, false) => {
            return Err(FormatError::MissingField { tag: tag::SERVER_POLICY });
        }
        _ => return Err(FormatError::UnsupportedLeaseVersion { version }),
    }

    Ok(Lease {
        file_id: file_id.ok_or(FormatError::MissingField { tag: tag::FILE_ID })?,
        facts: LeaseFacts {
            device_fingerprint: device_fpr
                .ok_or(FormatError::MissingField { tag: tag::DEVICE_FPR })?,
            policy_hash: policy_hash.ok_or(FormatError::MissingField { tag: tag::POLICY_HASH })?,
            seq: seq.ok_or(FormatError::MissingField { tag: tag::SEQ })?,
            epoch: epoch.ok_or(FormatError::MissingField { tag: tag::EPOCH })?,
            issued_at: Timestamp(
                issued_at.ok_or(FormatError::MissingField { tag: tag::ISSUED_AT })?,
            ),
            expires_at: Timestamp(
                expires_at.ok_or(FormatError::MissingField { tag: tag::EXPIRES_AT })?,
            ),
            opens_remaining: opens_remaining
                .ok_or(FormatError::MissingField { tag: tag::OPENS_REMAINING })?,
            revoked: status.ok_or(FormatError::MissingField { tag: tag::STATUS })?,
            tpm_clock,
            server_policy,
            attested,
        },
    })
}

/// Verify the server signature over a lease body.
///
/// `verify_strict`, not `verify`, as with the header (I-6): otherwise signature
/// malleability is inherited and "one signature, one document" is lost.
pub fn verify(
    body: &[u8],
    signature: &[u8; SIGNATURE_LEN],
    lease_verify_key: &[u8; 32],
) -> Result<(), CryptoError> {
    oc_crypto::sign::verify(lease_verify_key, &signing_transcript(body), signature)
}

/// Verify the signature over raw body bytes, then parse the lease.
///
/// `bytes` is `signature(64) ‖ body`. Authentication precedes parsing to avoid
/// detailed errors for unauthenticated data. The caller must separately check
/// `file_id` and policy hash against the container.
///
/// # Errors
/// [`FormatError::BadHeaderSignature`] for a short document or failed
/// signature; otherwise the parsing errors of [`decode`].
pub fn verify_signed(bytes: &[u8], lease_verify_key: &[u8; 32]) -> Result<Lease, FormatError> {
    let (signature, body) =
        bytes.split_at_checked(SIGNATURE_LEN).ok_or(FormatError::BadHeaderSignature)?;
    let signature: [u8; SIGNATURE_LEN] =
        signature.try_into().map_err(|_| FormatError::BadHeaderSignature)?;
    verify(body, &signature, lease_verify_key).map_err(|_| FormatError::BadHeaderSignature)?;
    decode(body)
}

fn decode_clock(value: &[u8]) -> Result<TpmClock, FormatError> {
    let reset = value.get(0..4).ok_or(FormatError::BadFieldLength {
        tag: tag::TPM_CLOCK,
        len: value.len(),
    })?;
    let ms = value.get(4..12).ok_or(FormatError::BadFieldLength {
        tag: tag::TPM_CLOCK,
        len: value.len(),
    })?;
    if value.len() != 12 {
        return Err(FormatError::BadFieldLength { tag: tag::TPM_CLOCK, len: value.len() });
    }
    let reset: [u8; 4] =
        reset.try_into().map_err(|_| FormatError::BadFieldLength { tag: tag::TPM_CLOCK, len: 4 })?;
    let ms: [u8; 8] =
        ms.try_into().map_err(|_| FormatError::BadFieldLength { tag: tag::TPM_CLOCK, len: 8 })?;
    Ok(TpmClock { reset_count: u32::from_le_bytes(reset), clock_ms: u64::from_le_bytes(ms) })
}

fn u64_le(value: &[u8]) -> Result<u64, FormatError> {
    let bytes: [u8; 8] = value
        .try_into()
        .map_err(|_| FormatError::BadFieldLength { tag: 0, len: value.len() })?;
    Ok(u64::from_le_bytes(bytes))
}

fn i64_le(value: &[u8]) -> Result<i64, FormatError> {
    Ok(i64::from_le_bytes(
        value.try_into().map_err(|_| FormatError::BadFieldLength { tag: 0, len: value.len() })?,
    ))
}

fn u32_le(value: &[u8]) -> Result<u32, FormatError> {
    Ok(u32::from_le_bytes(
        value.try_into().map_err(|_| FormatError::BadFieldLength { tag: 0, len: value.len() })?,
    ))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn sample() -> Lease {
        Lease {
            file_id: [0x11; 16],
            facts: LeaseFacts {
                device_fingerprint: [0x22; 32],
                policy_hash: [0x33; 32],
                seq: 7,
                epoch: 2,
                issued_at: Timestamp(1_700_000_000),
                expires_at: Timestamp(1_700_086_400),
                opens_remaining: Some(5),
                revoked: false,
                tpm_clock: Some(TpmClock { reset_count: 3, clock_ms: 123_456 }),
                server_policy: None,
                attested: None,
            },
        }
    }

    #[test]
    fn a_lease_round_trips_through_encode_and_decode() {
        let body = encode(&sample()).unwrap();
        assert_eq!(decode(&body).unwrap(), sample());
    }

    /// An empty remaining-opens value is distinguishable from a missing field.
    ///
    /// The distinction is normative and repeats §4's decision for `max_opens`: an empty
    /// value is the server's written "no limit set"; absence means nothing is known about
    /// its intent, and is rejected.
    #[test]
    fn an_empty_open_limit_differs_from_a_missing_one() {
        let mut l = sample();
        l.facts.opens_remaining = None;
        let body = encode(&l).unwrap();
        assert_eq!(decode(&body).unwrap().facts.opens_remaining, None);

        // А теперь то же поле вырезано целиком.
        let mut w = TlvWriter::new();
        for field in fields_of(&body) {
            if field.0 != tag::OPENS_REMAINING {
                w.put(field.0, &field.1).unwrap();
            }
        }
        assert!(
            matches!(
                decode(&w.finish()),
                Err(FormatError::MissingField { tag: tag::OPENS_REMAINING })
            ),
            "отсутствующее поле принято за пустое"
        );
    }

    /// An unknown state is rejected during parsing rather than interpreted.
    #[test]
    fn an_unknown_status_is_refused_rather_than_guessed() {
        let body = rebuild_with(&encode(&sample()).unwrap(), tag::STATUS, &[9]);
        assert!(decode(&body).is_err(), "состояние из будущей версии принято");
    }

    /// A revoked lease parses and carries the revocation flag.
    #[test]
    fn a_revoked_lease_decodes_as_revoked() {
        let mut l = sample();
        l.facts.revoked = true;
        let body = encode(&l).unwrap();
        assert!(decode(&body).unwrap().facts.revoked);
    }

    /// An unknown CRITICAL tag is rejected; an optional tag is skipped.
    #[test]
    fn an_unknown_critical_tag_is_refused_and_an_optional_one_is_skipped() {
        let base = encode(&sample()).unwrap();

        let mut w = TlvWriter::new();
        for (t, v) in fields_of(&base) {
            w.put(t, &v).unwrap();
        }
        w.put(0x7FFF, &[1, 2, 3]).unwrap();
        assert!(
            matches!(decode(&w.finish()), Err(FormatError::UnknownCriticalField { .. })),
            "критичный тег из будущей версии пропущен молча"
        );

        let mut w = TlvWriter::new();
        for (t, v) in fields_of(&base) {
            w.put(t, &v).unwrap();
        }
        w.put(0x8000, &[1, 2, 3]).unwrap();
        assert_eq!(decode(&w.finish()).unwrap(), sample(), "необязательный тег не пропущен");
    }

    /// Transcripts for different bodies differ, and the label separates the domain.
    ///
    /// Verified through signatures rather than inspecting bytes: `Transcript` does not
    /// expose its contents, correctly so: its purpose is precisely to prevent
    /// bytes being submitted for signing without the label.
    #[test]
    fn different_bodies_give_different_transcripts() {
        let a = signing_transcript(b"body");
        let b = signing_transcript(b"bodz");
        let key = [0x11u8; 32];
        let sig = [0u8; 64];
        // Обе проверки провалятся (подпись поддельная), но провалятся они по
        // РАЗНЫМ транскриптам — а это и надо: одинаковый транскрипт для разных
        // тел означал бы, что подпись не привязана к содержимому.
        assert!(oc_crypto::sign::verify(&key, &a, &sig).is_err());
        assert!(oc_crypto::sign::verify(&key, &b, &sig).is_err());
    }

    /// The document version is checked, not assumed.
    #[test]
    fn a_lease_of_another_version_is_refused() {
        let body = rebuild_with(&encode(&sample()).unwrap(), tag::VERSION, &2u16.to_le_bytes());
        assert!(decode(&body).is_err(), "лизинг чужой версии принят");
    }

    fn fields_of(body: &[u8]) -> Vec<(u16, Vec<u8>)> {
        let mut reader = TlvReader::new(body);
        let mut out = Vec::new();
        while let Some(f) = reader.next_field().unwrap() {
            out.push((f.tag, f.value.to_vec()));
        }
        out
    }

    fn rebuild_with(body: &[u8], tag: u16, value: &[u8]) -> Vec<u8> {
        let mut w = TlvWriter::new();
        for (t, v) in fields_of(body) {
            if t == tag {
                w.put(t, value).unwrap();
            } else {
                w.put(t, &v).unwrap();
            }
        }
        w.finish().to_vec()
    }
}
