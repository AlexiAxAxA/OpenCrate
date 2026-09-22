//! Лизинг: подписанное сервером разрешение открыть один файл на одном устройстве.
//!
//! # Почему это отдельный документ, а не поле контейнера
//!
//! Контейнер подписан автором и после выпуска не меняется. Лизинг живёт своей
//! жизнью: выдаётся, истекает, обновляется, отзывается — по многу раз на один и
//! тот же файл. Положи мы его внутрь, каждое обновление означало бы переписывание
//! контейнера, то есть новую подпись автора на файл, которого автор не трогал.
//!
//! Практическое следствие приятное: **версия формата контейнера не меняется**.
//! Места под сервер в заголовке уже размечены и подписаны (`authority.urls`,
//! `authority.sealing_kid`, `authority.lease_verify_key`), а лизинг имеет
//! собственную версию и собственный жизненный цикл.
//!
//! # Что делает лизинг доверенным
//!
//! Подпись ключом `authority.lease_verify_key` — тем самым, который **автор
//! закрепил в заголовке под своей подписью**. Поддельный сервер не подставит свой:
//! подменить ключ проверки значит подменить заголовок, а он подписан автором.
//!
//! Это единственное место, где клиент верит внешней стороне, и цепочка доверия
//! здесь короткая ровно потому, что автор поставил её сам.
//!
//! # Что подписывается
//!
//! **Сырые байты тела, а не пересобранная структура.** То же правило, что у
//! заголовка (§5) и изменяемой области (И-5), и по той же причине: пересборка
//! перед проверкой воспроизводит всё семейство ошибок канонизации, известное по
//! JWS и XML-DSig. Разобрали — проверяем то, что лежало на проводе.

use oc_crypto::CryptoError;
use oc_policy::{Attestation, LeaseFacts, Timestamp, TpmClock};

use oc_format::FormatError;
use oc_format::tlv::{TlvReader, TlvWriter};

/// Длина подписи в начале документа лизинга.
///
/// Подпись впереди тела намеренно: её длина фиксирована, и читатель добирается
/// до неё, не разобрав ни байта тела. Та же раскладка и то же имя, что у
/// отзывной ([`crate::revocation::SIGNATURE_LEN`]) и распоряжения
/// ([`crate::order::SIGNATURE_LEN`]): три документа одной стороны обязаны
/// читаться одинаково.
pub const SIGNATURE_LEN: usize = 64;

/// Версия документа лизинга.
///
/// Своя, не контейнерная: документы независимы и меняются в разном темпе.
/// Смешать их значило бы поднимать версию контейнера ради поля лизинга.
pub const LEASE_VERSION: u16 = 1;

/// Версия документа с политикой сервера (тег 12).
///
/// Пишется ТОЛЬКО когда сервер действительно ужесточает: без ужесточения байты
/// лизинга те же, что были, и замороженный вектор `tests/kat/lease.kat` остаётся
/// верен. Старый клиент такой документ ОТВЕРГАЕТ — по версии, до всякого
/// разбора полей: ограничение, которого он не понимает, не должно молча
/// пропасть (И-10, `docs/protocol.md` §2).
pub const LEASE_VERSION_WITH_SERVER_POLICY: u16 = 2;

/// Версия документа с признаком аттестации (тег 13, B6b).
///
/// Пишется ТОЛЬКО когда сервер признал аттестацию ключа устройства в этом
/// разговоре; политика сервера при этом может быть, а может не быть. Старый
/// клиент такой лизинг отвергает по версии — но и не получает его: признак
/// выдаётся лишь тому, кто аттестацию проходил, то есть клиенту, который о
/// ней знает.
pub const LEASE_VERSION_WITH_ATTESTATION: u16 = 3;

/// Реестр тегов лизинга. Возрастание строгое, критичность по диапазону — как в §2.
///
/// Номера нормативны: тело подписывается сырыми байтами, поэтому реализация,
/// пронумеровавшая поля иначе, соберёт другую подпись и молча разойдётся.
pub mod tag {
    /// Версия документа. `u16le`.
    pub const VERSION: u16 = 1;
    /// Файл, к которому относится разрешение. `bytes[16]`.
    ///
    /// Без него лизинг на один файл работал бы для любого другого — самая дешёвая
    /// из возможных ошибок и самая дорогая по последствиям.
    pub const FILE_ID: u16 = 2;
    /// Устройство, которому выдано. `bytes[32]`.
    pub const DEVICE_FPR: u16 = 3;
    /// Хеш политики, под которую выдано. `bytes[32]`.
    ///
    /// Клиент сверяет его с хешем политики из СВОЕГО контейнера: сервер не должен
    /// иметь возможности выдать разрешение под правила, которых автор не писал.
    pub const POLICY_HASH: u16 = 4;
    /// Строго возрастает на пару (файл, устройство). `u64le`.
    pub const SEQ: u16 = 5;
    /// Растёт при отзыве. `u64le`.
    pub const EPOCH: u16 = 6;
    /// Момент выдачи. `i64le`, секунды.
    pub const ISSUED_AT: u16 = 7;
    /// Момент истечения. `i64le`, секунды.
    pub const EXPIRES_AT: u16 = 8;
    /// Состояние: `u8`, 1 — действует, 2 — отозвано. Пишется ВСЕГДА.
    pub const STATUS: u16 = 9;
    /// Остаток открытий. `u32le`, либо **пустое значение** — «сервер лимита не
    /// ставил». Пишется ВСЕГДА.
    ///
    /// Различие «поля нет» и «поле есть и пусто» здесь нормативно — по образцу
    /// `max_opens` в §4, и по той же причине: пустое значение означает написанное
    /// сервером «лимита я не ставил», а отсутствие поля означает, что о его воле
    /// не известно ничего.
    pub const OPENS_REMAINING: u16 = 10;
    /// Показания аппаратных часов при выдаче: `u32le` reset_count ‖ `u64le` clock_ms.
    ///
    /// Необязательное: устройство без аппаратных часов получает лизинг без него.
    pub const TPM_CLOCK: u16 = 11;
    /// Политика сервера, кодек `policy_codec`. Только в версии 2 и обязателен в ней.
    pub const SERVER_POLICY: u16 = 12;
    /// Аттестация ключа устройства, признанная сервером: `u8`, основание из
    /// реестра `crate::attestation::basis`. Только в лизинге версии 3.
    pub const ATTESTED: u16 = 13;
}

/// Состояние лизинга на проводе.
const STATUS_ACTIVE: u8 = 1;
const STATUS_REVOKED: u8 = 2;

/// Разобранный лизинг: факты для решателя плюс то, что решателю не нужно.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    /// К какому файлу относится. Сверяет вызывающий — здесь его просто нет с чем.
    pub file_id: [u8; 16],
    pub facts: LeaseFacts,
}

/// Транскрипт подписи лизинга.
///
/// Метка и разделитель `0x00` — по общему правилу §3.6. Метка `"CC/v1/lease"`
/// беспрефиксна относительно всех прочих: соседний кеш назван `"CC/v1/cached-lease"`
/// именно затем, чтобы `"CC/v1/lease-cache"` не оказался её расширением.
/// Через [`oc_crypto::Transcript`], а не ручной сборкой: его конструктор ТРЕБУЕТ
/// метку и сам ставит разделитель. Собери мы байты руками — метку можно было бы
/// забыть, и подпись лизинга столкнулась бы с подписью заголовка в одном домене.
#[must_use]
pub fn signing_transcript(body: &[u8]) -> oc_crypto::Transcript {
    let mut t = oc_crypto::Transcript::new(oc_crypto::label::LEASE);
    t.field(body);
    t
}

/// Собрать тело лизинга.
///
/// Возвращает только тело: подпись накладывает тот, у кого есть ключ, а этот
/// крейт ключей не держит и держать не может.
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

/// Разобрать тело лизинга. **Результат НЕ ПРОВЕРЕН.**
///
/// Подпись здесь не проверяется вовсе, поэтому возвращённый [`Lease`] не
/// является свидетельством ничего: он ровно настолько правдив, насколько
/// правдивы байты, которые в него подали. Решать доступ по такому значению
/// нельзя.
///
/// # Что звать вместо неё
///
/// Для ЧУЖИХ байт — [`verify_signed`]: там подпись проверяется по сырому телу
/// ДО разбора, то есть в порядке, который здесь обязан соблюсти вызывающий и о
/// котором он может забыть. Функция осталась публичной не ради выбора «как
/// удобнее», а ради одного законного случая: разбора СОБСТВЕННОЙ выдачи, когда
/// подписывал её тот же, кто теперь читает, и проверять ему нечего
/// (`cc-authority`, повтор сохранённого ответа).
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

/// Проверить подпись сервера над телом лизинга.
///
/// `verify_strict`, а не `verify`, — как и у заголовка (И-6): иначе наследуется
/// malleability подписи и теряется «одна подпись — один документ».
pub fn verify(
    body: &[u8],
    signature: &[u8; SIGNATURE_LEN],
    lease_verify_key: &[u8; 32],
) -> Result<(), CryptoError> {
    oc_crypto::sign::verify(lease_verify_key, &signing_transcript(body), signature)
}

/// Проверить подпись, потом разобрать — в этом порядке, и только в этом.
///
/// `bytes` — документ целиком: `подпись(64) ‖ тело`.
///
/// # Почему комбинатор, а рядом остались обе половины
///
/// Потому что порядок «подпись → разбор» держался ВЫЗЫВАЮЩИМ, и обёртку вокруг
/// этих двух вызовов пришлось строить продукту (`cc_cli::lease`), хотя у
/// соседних документов — [`crate::revocation::verify_signed`] и
/// [`crate::order::verify_signed`] — она была с самого начала. Разбор
/// незаверенных байтов сам по себе оракул: различимые коды ошибок сообщаются о
/// том, чего никто не подписывал (И-5 для документов). Один вызов ошибиться
/// порядком не даёт.
///
/// Подпись проверяется по СЫРЫМ байтам тела, а не по пересобранной структуре, —
/// правило модуля, снимающее класс ошибок канонизации.
///
/// Совпадение `file_id` и хеша политики с контейнером сверяет вызывающий: здесь
/// контейнера нет.
///
/// # Errors
/// [`FormatError::BadHeaderSignature`] при коротком документе и при
/// несошедшейся подписи; иначе — ошибки разбора, как у [`decode`].
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

    /// Пустой остаток открытий отличим от отсутствующего.
    ///
    /// Различие нормативно и повторяет решение §4 про `max_opens`: пустое
    /// значение — написанное сервером «лимита не ставил», отсутствие поля — что о
    /// его воле не известно ничего, и это отказ.
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

    /// Незнакомое состояние отвергается на разборе, а не трактуется.
    #[test]
    fn an_unknown_status_is_refused_rather_than_guessed() {
        let body = rebuild_with(&encode(&sample()).unwrap(), tag::STATUS, &[9]);
        assert!(decode(&body).is_err(), "состояние из будущей версии принято");
    }

    /// Отозванный лизинг разбирается и несёт признак отзыва.
    #[test]
    fn a_revoked_lease_decodes_as_revoked() {
        let mut l = sample();
        l.facts.revoked = true;
        let body = encode(&l).unwrap();
        assert!(decode(&body).unwrap().facts.revoked);
    }

    /// Незнакомый КРИТИЧНЫЙ тег — отказ; необязательный — пропуск.
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

    /// Транскрипты разных тел различаются, а метка отделяет домен.
    ///
    /// Проверяется через подпись, а не разглядыванием байтов: `Transcript` не
    /// отдаёт содержимое наружу, и это правильно — он существует ровно затем,
    /// чтобы под подпись нельзя было подсунуть байты в обход метки.
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

    /// Версия документа проверяется, а не подразумевается.
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
