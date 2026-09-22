//! Контрольные документы authority (E2, B2; `docs/protocol.md` §9.16).
//!
//! Три документа, один кодек:
//!
//! * [`Binding`] — привязка сервера: организация, стабильное тождество,
//!   эпоха и ревизия, ключи, адреса и отпечатки TLS, профиль сохранности,
//!   режим восстановления, состояние обслуживания и состав управляющих ключей.
//!   Подписан ключом подписи лизингов — тем, что автор закрепил в заголовке.
//!   **Сам документ доверия не создаёт**: проверяется ключом, известным
//!   проверяющему заранее ([`Binding::open`]), а поле ключа внутри обязано с ним
//!   совпасть.
//! * [`ControlRequest`] — намерение управляющих: область (организация,
//!   тождество, эпоха), тождество операции, ожидаемая ревизия, срок и точное
//!   содержание. Подписей может быть несколько — все над ОДНИМ телом: для
//!   кворума подписывается одно намерение, и подписи разных намерений не
//!   складываются.
//! * [`Receipt`] — квитанция сервера: чем кончилась операция, какой стала
//!   ревизия и что именно зафиксировано. Отличает принятое от исполненного и
//!   от отложенного до подтверждения реплики.
//!
//! Раскладки — TLV с тегами по возрастанию (И-7), все поля критичны.
//! Транскрипты подписей — `CC/v1/authority-binding`, `CC/v1/control-request`,
//! `CC/v1/operation-receipt` поверх тела.

use oc_format::FormatError;
use oc_format::tlv::{TlvReader, TlvWriter};
use oc_crypto::sign::Signer;
use oc_crypto::transcript::Transcript;
use oc_crypto::{label, sha256};

/// Версия раскладки всех трёх документов.
pub const VERSION: u8 = 1;
/// Адресов в привязке.
pub const MAX_URLS: usize = 8;
/// Длина адреса, байт.
pub const MAX_URL_LEN: usize = 256;
/// Отпечатков TLS в привязке.
pub const MAX_PINS: usize = 8;
/// Ключей в составе управляющих.
pub const MAX_ROSTER: usize = 16;
/// Подписей под одним намерением.
pub const MAX_SIGNERS: usize = 16;
/// Наибольший срок намерения: сутки. Долгоживущее подписанное намерение —
/// заготовка для повтора, а порядок держит ревизия, не время.
pub const MAX_REQUEST_LIFETIME: i64 = 86_400;
/// Причина отказа или прекращения, знаков.
pub const MAX_REASON_CHARS: usize = 512;
/// Предел документа целиком.
pub const MAX_DOCUMENT_LEN: usize = 64 * 1024;

const SIG: usize = oc_crypto::sign::SIGNATURE_LEN;
const KEY: usize = oc_crypto::sign::PUBLIC_KEY_LEN;

fn bad(tag: u16, len: usize) -> FormatError {
    FormatError::BadFieldLength { tag, len }
}

/// Профиль сохранности (`docs/authority-lifecycle-design.md` §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Durability {
    /// Успех — после устойчивой записи сервера.
    Local = 0,
    /// Копия уходит реплике после успеха; хвост может быть не подтверждён.
    Mirrored = 1,
    /// Успех — только после устойчивого подтверждения реплики.
    Witnessed = 2,
}

impl Durability {
    /// Из байта; незнакомый — отказ (И-10).
    #[must_use]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Local),
            1 => Some(Self::Mirrored),
            2 => Some(Self::Witnessed),
            _ => None,
        }
    }
}

/// Объявленный режим восстановления сервера.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Recovery {
    /// Не объявлен: обещания нет.
    Undeclared = 0,
    /// Есть проверенный пакет восстановления (`cca recovery`).
    Package = 1,
    /// Сервер объявлен невосстановимым: потеря ключей — конец выдач.
    NotRecoverable = 2,
}

impl Recovery {
    #[must_use]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Undeclared),
            1 => Some(Self::Package),
            2 => Some(Self::NotRecoverable),
            _ => None,
        }
    }
}

/// Обслуживает ли сервер.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    /// Обычная работа.
    Serving = 0,
    /// Обслуживание прекращено: новых регистраций и выдач нет.
    Stopped = 1,
    /// Только архив: отзывные и головы журнала, выдач нет.
    ArchiveOnly = 2,
    /// Полномочия переданы преемнику (B7).
    Transferred = 3,
}

impl Status {
    #[must_use]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Serving),
            1 => Some(Self::Stopped),
            2 => Some(Self::ArchiveOnly),
            3 => Some(Self::Transferred),
            _ => None,
        }
    }
}

/// Имя организации: `[a-z0-9._-]`, 1..=64 байт — то же правило, что у
/// каталога ключей (D4).
fn check_tenant(tenant: &str, tag: u16) -> Result<(), FormatError> {
    let ok = !tenant.is_empty()
        && tenant.len() <= crate::directory::MAX_TENANT
        && tenant.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-' || b == b'_');
    if ok { Ok(()) } else { Err(bad(tag, tenant.len())) }
}

/// Адрес: печатный ASCII без пробелов, 1..=256 байт.
fn check_url(url: &str, tag: u16) -> Result<(), FormatError> {
    let ok = !url.is_empty() && url.len() <= MAX_URL_LEN && url.bytes().all(|b| b.is_ascii_graphic());
    if ok { Ok(()) } else { Err(bad(tag, url.len())) }
}

fn check_reason(text: &str, tag: u16) -> Result<(), FormatError> {
    if text.chars().count() > MAX_REASON_CHARS {
        return Err(bad(tag, text.len()));
    }
    if let Some(c) = text.chars().find(|c| oc_format::text::is_display_unsafe(*c)) {
        return Err(FormatError::BadNoteChar { tag, code: u32::from(c) });
    }
    Ok(())
}

fn encode_urls(urls: &[String], tag: u16) -> Result<Vec<u8>, FormatError> {
    if urls.is_empty() || urls.len() > MAX_URLS {
        return Err(bad(tag, urls.len()));
    }
    let mut out = Vec::new();
    for url in urls {
        check_url(url, tag)?;
        let len = u16::try_from(url.len()).map_err(|_| bad(tag, url.len()))?;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(url.as_bytes());
    }
    Ok(out)
}

fn decode_urls(mut rest: &[u8], tag: u16) -> Result<Vec<String>, FormatError> {
    let mut urls = Vec::new();
    while !rest.is_empty() {
        if urls.len() >= MAX_URLS {
            return Err(bad(tag, rest.len()));
        }
        let (len, tail) = rest.split_at_checked(2).ok_or(bad(tag, rest.len()))?;
        let len = usize::from(u16::from_le_bytes(len.try_into().map_err(|_| bad(tag, 2))?));
        let (url, tail) = tail.split_at_checked(len).ok_or(bad(tag, tail.len()))?;
        let url = core::str::from_utf8(url).map_err(|_| bad(tag, len))?;
        check_url(url, tag)?;
        if urls.iter().any(|u: &String| u == url) {
            return Err(bad(tag, len));
        }
        urls.push(url.to_owned());
        rest = tail;
    }
    if urls.is_empty() {
        return Err(bad(tag, 0));
    }
    Ok(urls)
}

/// Ключи подряд по 32 байта: строго по возрастанию — одна запись на ключ и
/// одно представление набора.
fn encode_keys(keys: &[[u8; 32]], max: usize, tag: u16) -> Result<Vec<u8>, FormatError> {
    if keys.len() > max || keys.windows(2).any(|w| w.first() >= w.get(1)) {
        return Err(bad(tag, keys.len()));
    }
    Ok(keys.iter().flatten().copied().collect())
}

fn decode_keys(bytes: &[u8], max: usize, tag: u16) -> Result<Vec<[u8; 32]>, FormatError> {
    if !bytes.len().is_multiple_of(32) {
        return Err(bad(tag, bytes.len()));
    }
    let keys: Vec<[u8; 32]> =
        bytes.chunks_exact(32).map(|c| <[u8; 32]>::try_from(c).map_err(|_| bad(tag, bytes.len()))).collect::<Result<_, _>>()?;
    if keys.len() > max || keys.windows(2).any(|w| w.first() >= w.get(1)) {
        return Err(bad(tag, bytes.len()));
    }
    Ok(keys)
}

fn u8_field(value: &[u8], tag: u16) -> Result<u8, FormatError> {
    match value {
        [b] => Ok(*b),
        _ => Err(bad(tag, value.len())),
    }
}

fn u64_field(value: &[u8], tag: u16) -> Result<u64, FormatError> {
    Ok(u64::from_le_bytes(value.try_into().map_err(|_| bad(tag, value.len()))?))
}

fn i64_field(value: &[u8], tag: u16) -> Result<i64, FormatError> {
    Ok(i64::from_le_bytes(value.try_into().map_err(|_| bad(tag, value.len()))?))
}

fn array<const N: usize>(value: &[u8], tag: u16) -> Result<[u8; N], FormatError> {
    value.try_into().map_err(|_| bad(tag, value.len()))
}

fn text(value: &[u8], tag: u16) -> Result<String, FormatError> {
    String::from_utf8(value.to_vec()).map_err(|_| bad(tag, value.len()))
}

fn split_signed(bytes: &[u8]) -> Result<([u8; SIG], &[u8]), FormatError> {
    if bytes.len() > MAX_DOCUMENT_LEN {
        return Err(bad(0, bytes.len()));
    }
    let (sig, body) = bytes.split_at_checked(SIG).ok_or(bad(0, bytes.len()))?;
    Ok((array(sig, 0)?, body))
}

fn transcript(label: oc_crypto::Label, body: &[u8]) -> Transcript {
    let mut t = Transcript::new(label);
    t.field(body);
    t
}

/// Отпечаток подписанного документа — для цепочки ревизий и квитанций.
#[must_use]
pub fn digest(bytes: &[u8]) -> [u8; 32] {
    sha256(bytes)
}

// ---------------------------------------------------------------------------
// Привязка.

mod binding_tag {
    pub const VERSION: u16 = 1;
    pub const TENANT: u16 = 2;
    pub const AUTHORITY_ID: u16 = 3;
    pub const EPOCH: u16 = 4;
    pub const REVISION: u16 = 5;
    pub const LEASE_PUBLIC: u16 = 6;
    pub const SEALING_PUBLIC: u16 = 7;
    pub const URLS: u16 = 8;
    pub const PINS: u16 = 9;
    pub const DURABILITY: u16 = 10;
    pub const RECOVERY: u16 = 11;
    pub const STATUS: u16 = 12;
    pub const ROSTER: u16 = 13;
    pub const THRESHOLD: u16 = 14;
    pub const OPERATION_ID: u16 = 15;
    pub const PREVIOUS: u16 = 16;
    pub const ISSUED_AT: u16 = 17;
    pub const EXPIRES_AT: u16 = 18;
}

/// Привязка сервера — см. шапку модуля.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub tenant: String,
    /// Стабильное тождество сервера: не меняется при смене ключей (B7).
    pub authority_id: [u8; 16],
    /// Эпоха полномочий: растёт только при передаче (B7).
    pub epoch: u64,
    /// Ревизия привязки внутри эпохи: растёт на каждой управляющей операции.
    pub revision: u64,
    pub lease_public: [u8; KEY],
    pub sealing_public: [u8; 32],
    pub urls: Vec<String>,
    /// SHA-256 от SubjectPublicKeyInfo сертификатов TLS, которым клиент верит.
    pub pins: Vec<[u8; 32]>,
    pub durability: Durability,
    pub recovery: Recovery,
    pub status: Status,
    /// Ключи управляющих, по возрастанию. Пусто — удалённого управления нет.
    pub roster: Vec<[u8; KEY]>,
    /// Сколько подписей состава нужно намерению; ноль — при пустом составе.
    pub threshold: u8,
    /// Операция, породившая эту ревизию; нули — заведение.
    pub operation_id: [u8; 16],
    /// Отпечаток предыдущей ревизии; нули у ревизии 0.
    pub previous: [u8; 32],
    pub issued_at: i64,
    /// После этого момента привязка не действует как текущая: её надо
    /// перечитать. Выданных лизингов срок привязки не касается.
    pub expires_at: i64,
}

impl Binding {
    fn check(&self) -> Result<(), FormatError> {
        use binding_tag as t;
        check_tenant(&self.tenant, t::TENANT)?;
        if self.pins.len() > MAX_PINS {
            return Err(bad(t::PINS, self.pins.len()));
        }
        let quorum_ok = if self.roster.is_empty() {
            self.threshold == 0
        } else {
            self.threshold >= 1 && usize::from(self.threshold) <= self.roster.len()
        };
        if !quorum_ok {
            return Err(bad(t::THRESHOLD, usize::from(self.threshold)));
        }
        if self.expires_at <= self.issued_at {
            return Err(bad(t::EXPIRES_AT, 8));
        }
        if self.revision == 0 && (self.previous != [0; 32] || self.operation_id != [0; 16]) {
            return Err(bad(t::PREVIOUS, 32));
        }
        if self.revision > 0 && self.previous == [0; 32] {
            return Err(bad(t::PREVIOUS, 32));
        }
        Ok(())
    }

    /// Тело без подписи.
    ///
    /// # Errors
    /// [`FormatError`] — поле вне правил.
    pub fn body(&self) -> Result<Vec<u8>, FormatError> {
        use binding_tag as t;
        self.check()?;
        let mut w = TlvWriter::new();
        w.put(t::VERSION, &[VERSION])?;
        w.put(t::TENANT, self.tenant.as_bytes())?;
        w.put(t::AUTHORITY_ID, &self.authority_id)?;
        w.put(t::EPOCH, &self.epoch.to_le_bytes())?;
        w.put(t::REVISION, &self.revision.to_le_bytes())?;
        w.put(t::LEASE_PUBLIC, &self.lease_public)?;
        w.put(t::SEALING_PUBLIC, &self.sealing_public)?;
        w.put(t::URLS, &encode_urls(&self.urls, t::URLS)?)?;
        w.put(t::PINS, &encode_keys(&self.pins, MAX_PINS, t::PINS)?)?;
        w.put(t::DURABILITY, &[self.durability as u8])?;
        w.put(t::RECOVERY, &[self.recovery as u8])?;
        w.put(t::STATUS, &[self.status as u8])?;
        w.put(t::ROSTER, &encode_keys(&self.roster, MAX_ROSTER, t::ROSTER)?)?;
        w.put(t::THRESHOLD, &[self.threshold])?;
        w.put(t::OPERATION_ID, &self.operation_id)?;
        w.put(t::PREVIOUS, &self.previous)?;
        w.put(t::ISSUED_AT, &self.issued_at.to_le_bytes())?;
        w.put(t::EXPIRES_AT, &self.expires_at.to_le_bytes())?;
        Ok(w.finish().to_vec())
    }

    /// Подписать ключом подписи лизингов, названным в самой привязке.
    ///
    /// # Errors
    /// [`FormatError`] — поле вне правил, ключ подписанта не тот, подпись не
    /// удалась.
    pub fn sign(&self, signer: &dyn Signer) -> Result<Vec<u8>, FormatError> {
        if signer.public_key() != self.lease_public {
            return Err(bad(binding_tag::LEASE_PUBLIC, KEY));
        }
        let body = self.body()?;
        let sig = signer
            .sign(&transcript(label::AUTHORITY_BINDING, &body))
            .map_err(|_| FormatError::BadHeaderSignature)?;
        let mut out = sig.to_vec();
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Разобрать и проверить ключом, которому проверяющий верит ЗАРАНЕЕ.
    ///
    /// Ключ внутри привязки обязан совпасть с якорем: иначе привязка
    /// называла бы доверенным ключ, которым сама подписана.
    ///
    /// # Почему подпись РАНЬШЕ разбора
    ///
    /// Тот же довод И-5, что у [`open_request`]: разбор незаверенных байтов
    /// сообщает различимые коды отказа о том, чего никто не подписывал. Ключ
    /// здесь приходит СНАРУЖИ (`anchor`), поэтому разбирать тело до проверки
    /// не нужно; [`Self::peek`] отделяет подпись сам и зовётся уже над
    /// заверенными байтами. Там, где якорь брать неоткуда, ключ достают
    /// именно `peek`-ом и знают цену: в [`verify_chain`] привязка новой эпохи
    /// сначала `peek`-ается ради своего же ключа, а доверие ей даёт не эта
    /// подпись, а подпись состава под сертификатом, несущим её байты.
    ///
    /// # Errors
    /// [`FormatError`] — раскладка, подпись, несовпадение с якорем.
    pub fn open(bytes: &[u8], anchor: &[u8; KEY]) -> Result<Self, FormatError> {
        let (sig, body) = split_signed(bytes)?;
        oc_crypto::sign::verify(anchor, &transcript(label::AUTHORITY_BINDING, body), &sig)
            .map_err(|_| FormatError::BadHeaderSignature)?;
        let binding = Self::peek(bytes)?;
        if !oc_crypto::public_key_eq(&binding.lease_public, anchor) {
            return Err(bad(binding_tag::LEASE_PUBLIC, KEY));
        }
        Ok(binding)
    }

    /// Разобрать БЕЗ проверки подписи — для того, кто сам её выпустил и хранит.
    ///
    /// # Errors
    /// [`FormatError`] — раскладка.
    pub fn peek(bytes: &[u8]) -> Result<Self, FormatError> {
        use binding_tag as t;
        let (_, body) = split_signed(bytes)?;
        let mut r = TlvReader::new(body);
        let mut skipped = crate::unknown::Skipped::default();
        let mut version = None;
        let (mut tenant, mut authority_id, mut epoch, mut revision) = (None, None, None, None);
        let (mut lease, mut sealing, mut urls, mut pins) = (None, None, None, None);
        let (mut durability, mut recovery, mut status, mut roster, mut threshold) = (None, None, None, None, None);
        let (mut operation_id, mut previous, mut issued_at, mut expires_at) = (None, None, None, None);
        while let Some(f) = r.next_field()? {
            let v = f.value;
            match f.tag {
                t::VERSION => version = Some(u8_field(v, f.tag)?),
                t::TENANT => tenant = Some(text(v, f.tag)?),
                t::AUTHORITY_ID => authority_id = Some(array(v, f.tag)?),
                t::EPOCH => epoch = Some(u64_field(v, f.tag)?),
                t::REVISION => revision = Some(u64_field(v, f.tag)?),
                t::LEASE_PUBLIC => lease = Some(array(v, f.tag)?),
                t::SEALING_PUBLIC => sealing = Some(array(v, f.tag)?),
                t::URLS => urls = Some(decode_urls(v, f.tag)?),
                t::PINS => pins = Some(decode_keys(v, MAX_PINS, f.tag)?),
                t::DURABILITY => {
                    durability = Some(Durability::from_u8(u8_field(v, f.tag)?).ok_or(bad(f.tag, 1))?);
                }
                t::RECOVERY => recovery = Some(Recovery::from_u8(u8_field(v, f.tag)?).ok_or(bad(f.tag, 1))?),
                t::STATUS => status = Some(Status::from_u8(u8_field(v, f.tag)?).ok_or(bad(f.tag, 1))?),
                t::ROSTER => roster = Some(decode_keys(v, MAX_ROSTER, f.tag)?),
                t::THRESHOLD => threshold = Some(u8_field(v, f.tag)?),
                t::OPERATION_ID => operation_id = Some(array(v, f.tag)?),
                t::PREVIOUS => previous = Some(array(v, f.tag)?),
                t::ISSUED_AT => issued_at = Some(i64_field(v, f.tag)?),
                t::EXPIRES_AT => expires_at = Some(i64_field(v, f.tag)?),
                _ => skipped.see(&f)?,
            }
        }
        if version != Some(VERSION) {
            return Err(bad(t::VERSION, 1));
        }
        let binding = Self {
            tenant: tenant.ok_or(FormatError::MissingField { tag: t::TENANT })?,
            authority_id: authority_id.ok_or(FormatError::MissingField { tag: t::AUTHORITY_ID })?,
            epoch: epoch.ok_or(FormatError::MissingField { tag: t::EPOCH })?,
            revision: revision.ok_or(FormatError::MissingField { tag: t::REVISION })?,
            lease_public: lease.ok_or(FormatError::MissingField { tag: t::LEASE_PUBLIC })?,
            sealing_public: sealing.ok_or(FormatError::MissingField { tag: t::SEALING_PUBLIC })?,
            urls: urls.ok_or(FormatError::MissingField { tag: t::URLS })?,
            pins: pins.ok_or(FormatError::MissingField { tag: t::PINS })?,
            durability: durability.ok_or(FormatError::MissingField { tag: t::DURABILITY })?,
            recovery: recovery.ok_or(FormatError::MissingField { tag: t::RECOVERY })?,
            status: status.ok_or(FormatError::MissingField { tag: t::STATUS })?,
            roster: roster.ok_or(FormatError::MissingField { tag: t::ROSTER })?,
            threshold: threshold.ok_or(FormatError::MissingField { tag: t::THRESHOLD })?,
            operation_id: operation_id.ok_or(FormatError::MissingField { tag: t::OPERATION_ID })?,
            previous: previous.ok_or(FormatError::MissingField { tag: t::PREVIOUS })?,
            issued_at: issued_at.ok_or(FormatError::MissingField { tag: t::ISSUED_AT })?,
            expires_at: expires_at.ok_or(FormatError::MissingField { tag: t::EXPIRES_AT })?,
        };
        binding.check()?;
        // Байты обязаны быть канонической кодировкой разобранного: иначе две
        // последовательности значили бы одну привязку, и отпечаток ревизии
        // зависел бы от того, кто её кодировал.
        //
        // Сверяется тело БЕЗ пропущенных необязательных записей (решение
        // 2026-09-21): их наш кодировщик не воспроизводит по построению, и
        // сверка со всем телом отменила бы необязательный диапазон обратно —
        // молча, отказом не по тому месту. Каноничность ЗНАКОМЫХ полей
        // остаётся под сторожем целиком.
        if binding.body()? != skipped.strip(body) {
            return Err(bad(0, body.len()));
        }
        Ok(binding)
    }

    /// Адрес назван в привязке — сравнение побайтное.
    #[must_use]
    pub fn names_url(&self, url: &str) -> bool {
        self.urls.iter().any(|u| u == url)
    }
}

/// Как новая привязка соотносится с виденной ранее.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Continuity {
    /// Та же ревизия, те же байты.
    Same,
    /// Новее. `adjacent` — следующая по номеру и ссылается на виденную.
    Newer { adjacent: bool },
    /// Старее виденной: откат.
    Rollback,
    /// Та же ревизия, другие байты, либо следующая ревизия не ссылается на
    /// виденную: развилка истории.
    Fork,
    /// Другой сервер, другая организация или другая эпоха.
    Unrelated,
}

/// Сравнить привязку с виденной ранее.
#[must_use]
pub fn continuity(seen: &Binding, seen_bytes: &[u8], new: &Binding, new_bytes: &[u8]) -> Continuity {
    if seen.authority_id != new.authority_id || seen.tenant != new.tenant || seen.epoch != new.epoch {
        return Continuity::Unrelated;
    }
    match new.revision.cmp(&seen.revision) {
        core::cmp::Ordering::Less => Continuity::Rollback,
        core::cmp::Ordering::Equal => {
            if oc_crypto::digest_eq(&digest(seen_bytes), &digest(new_bytes)) {
                Continuity::Same
            } else {
                Continuity::Fork
            }
        }
        core::cmp::Ordering::Greater => {
            let adjacent = seen.revision.checked_add(1) == Some(new.revision);
            if adjacent && !oc_crypto::digest_eq(&new.previous, &digest(seen_bytes)) {
                Continuity::Fork
            } else {
                Continuity::Newer { adjacent }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Намерение.

mod request_tag {
    pub const VERSION: u16 = 1;
    pub const TENANT: u16 = 2;
    pub const AUTHORITY_ID: u16 = 3;
    pub const EPOCH: u16 = 4;
    pub const OPERATION_ID: u16 = 5;
    pub const SCOPE: u16 = 6;
    pub const EXPECTED_REVISION: u16 = 7;
    pub const ISSUED_AT: u16 = 8;
    pub const EXPIRES_AT: u16 = 9;
    pub const PAYLOAD_KIND: u16 = 10;
    pub const PAYLOAD: u16 = 11;
}

/// Область намерения. Один вид сегодня — сервер целиком; поле есть, чтобы
/// намерение по одному файлу нельзя было принять за намерение по серверу.
pub const SCOPE_AUTHORITY: u8 = 1;

/// Что велено.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    /// Адреса и отпечатки TLS (P12).
    SetEndpoints { urls: Vec<String>, pins: Vec<[u8; 32]> },
    /// Профиль сохранности. Понижение — тем же подписанным решением.
    SetDurability(Durability),
    /// Состав управляющих и порог.
    SetRoster { keys: Vec<[u8; KEY]>, threshold: u8 },
    /// Объявленный режим восстановления.
    SetRecovery(Recovery),
    /// Прекращение обслуживания (P16): `Stopped` или `ArchiveOnly`.
    Decommission { status: Status, reason: String },
    /// Допустить ключ автора к регистрации по проводу (P01).
    AddAuthor([u8; KEY]),
    /// Снять допуск ключа автора.
    RemoveAuthor([u8; KEY]),
}

impl Payload {
    fn kind(&self) -> u8 {
        match self {
            Self::SetEndpoints { .. } => 1,
            Self::SetDurability(_) => 2,
            Self::SetRoster { .. } => 3,
            Self::SetRecovery(_) => 4,
            Self::Decommission { .. } => 5,
            Self::AddAuthor(_) => 6,
            Self::RemoveAuthor(_) => 7,
        }
    }

    fn encode(&self) -> Result<Vec<u8>, FormatError> {
        let mut w = TlvWriter::new();
        match self {
            Self::SetEndpoints { urls, pins } => {
                w.put(1, &encode_urls(urls, 1)?)?;
                w.put(2, &encode_keys(pins, MAX_PINS, 2)?)?;
            }
            Self::SetDurability(d) => w.put(1, &[*d as u8])?,
            Self::SetRoster { keys, threshold } => {
                w.put(1, &encode_keys(keys, MAX_ROSTER, 1)?)?;
                w.put(2, &[*threshold])?;
            }
            Self::SetRecovery(r) => w.put(1, &[*r as u8])?,
            Self::Decommission { status, reason } => {
                if !matches!(status, Status::Stopped | Status::ArchiveOnly) {
                    return Err(bad(1, 1));
                }
                check_reason(reason, 2)?;
                w.put(1, &[*status as u8])?;
                w.put(2, reason.as_bytes())?;
            }
            Self::AddAuthor(key) | Self::RemoveAuthor(key) => w.put(1, key)?,
        }
        Ok(w.finish().to_vec())
    }

    fn decode(kind: u8, body: &[u8]) -> Result<Self, FormatError> {
        let mut r = TlvReader::new(body);
        let mut skipped = crate::unknown::Skipped::default();
        let mut fields: [Option<&[u8]>; 2] = [None, None];
        while let Some(f) = r.next_field()? {
            let slot = match f.tag {
                1 => fields.get_mut(0),
                2 => fields.get_mut(1),
                _ => {
                    skipped.see(&f)?;
                    None
                }
            };
            if let Some(slot) = slot {
                *slot = Some(f.value);
            }
        }
        let [first, second] = fields;
        let one = first.ok_or(FormatError::MissingField { tag: 1 })?;
        let payload = match (kind, second) {
            (1, Some(pins)) => Self::SetEndpoints { urls: decode_urls(one, 1)?, pins: decode_keys(pins, MAX_PINS, 2)? },
            (2, None) => Self::SetDurability(Durability::from_u8(u8_field(one, 1)?).ok_or(bad(1, 1))?),
            (3, Some(threshold)) => {
                Self::SetRoster { keys: decode_keys(one, MAX_ROSTER, 1)?, threshold: u8_field(threshold, 2)? }
            }
            (4, None) => Self::SetRecovery(Recovery::from_u8(u8_field(one, 1)?).ok_or(bad(1, 1))?),
            (5, Some(reason)) => {
                let status = Status::from_u8(u8_field(one, 1)?).ok_or(bad(1, 1))?;
                if !matches!(status, Status::Stopped | Status::ArchiveOnly) {
                    return Err(bad(1, 1));
                }
                let reason = text(reason, 2)?;
                check_reason(&reason, 2)?;
                Self::Decommission { status, reason }
            }
            (6, None) => Self::AddAuthor(array(one, 1)?),
            (7, None) => Self::RemoveAuthor(array(one, 1)?),
            (1..=7, _) => return Err(bad(2, second.map_or(0, <[u8]>::len))),
            _ => return Err(bad(request_tag::PAYLOAD_KIND, 1)),
        };
        // Без пропущенных необязательных записей — см. довод у `Binding::peek`.
        if payload.encode()? != skipped.strip(body) {
            return Err(bad(request_tag::PAYLOAD, body.len()));
        }
        Ok(payload)
    }
}

/// Намерение управляющих — см. шапку модуля.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlRequest {
    pub tenant: String,
    pub authority_id: [u8; 16],
    pub epoch: u64,
    /// Случайные 128 бит от составителя: повтор с теми же байтами — тот же
    /// исход, с другими — `IdConflict`.
    pub operation_id: [u8; 16],
    /// Ревизия привязки, поверх которой намерение составлено.
    pub expected_revision: u64,
    pub issued_at: i64,
    pub expires_at: i64,
    pub payload: Payload,
}

/// Намерение с проверенными подписями.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRequest {
    pub request: ControlRequest,
    /// Отпечаток тела: общий для всех подписавших.
    pub body_hash: [u8; 32],
    /// Подписавшие, по возрастанию.
    pub signers: Vec<[u8; KEY]>,
}

impl ControlRequest {
    /// Тело без подписей.
    ///
    /// # Errors
    /// [`FormatError`] — поле вне правил.
    pub fn body(&self) -> Result<Vec<u8>, FormatError> {
        use request_tag as t;
        check_tenant(&self.tenant, t::TENANT)?;
        let lifetime = self.expires_at.checked_sub(self.issued_at).ok_or(bad(t::EXPIRES_AT, 8))?;
        if lifetime <= 0 || lifetime > MAX_REQUEST_LIFETIME {
            return Err(bad(t::EXPIRES_AT, 8));
        }
        let mut w = TlvWriter::new();
        w.put(t::VERSION, &[VERSION])?;
        w.put(t::TENANT, self.tenant.as_bytes())?;
        w.put(t::AUTHORITY_ID, &self.authority_id)?;
        w.put(t::EPOCH, &self.epoch.to_le_bytes())?;
        w.put(t::OPERATION_ID, &self.operation_id)?;
        w.put(t::SCOPE, &[SCOPE_AUTHORITY])?;
        w.put(t::EXPECTED_REVISION, &self.expected_revision.to_le_bytes())?;
        w.put(t::ISSUED_AT, &self.issued_at.to_le_bytes())?;
        w.put(t::EXPIRES_AT, &self.expires_at.to_le_bytes())?;
        w.put(t::PAYLOAD_KIND, &[self.payload.kind()])?;
        w.put(t::PAYLOAD, &self.payload.encode()?)?;
        Ok(w.finish().to_vec())
    }

    fn decode_body(body: &[u8]) -> Result<Self, FormatError> {
        use request_tag as t;
        let mut r = TlvReader::new(body);
        let mut skipped = crate::unknown::Skipped::default();
        let (mut version, mut tenant, mut authority_id, mut epoch, mut operation_id) = (None, None, None, None, None);
        let (mut scope, mut expected, mut issued_at, mut expires_at, mut kind, mut payload) =
            (None, None, None, None, None, None);
        while let Some(f) = r.next_field()? {
            let v = f.value;
            match f.tag {
                t::VERSION => version = Some(u8_field(v, f.tag)?),
                t::TENANT => tenant = Some(text(v, f.tag)?),
                t::AUTHORITY_ID => authority_id = Some(array(v, f.tag)?),
                t::EPOCH => epoch = Some(u64_field(v, f.tag)?),
                t::OPERATION_ID => operation_id = Some(array(v, f.tag)?),
                t::SCOPE => scope = Some(u8_field(v, f.tag)?),
                t::EXPECTED_REVISION => expected = Some(u64_field(v, f.tag)?),
                t::ISSUED_AT => issued_at = Some(i64_field(v, f.tag)?),
                t::EXPIRES_AT => expires_at = Some(i64_field(v, f.tag)?),
                t::PAYLOAD_KIND => kind = Some(u8_field(v, f.tag)?),
                t::PAYLOAD => payload = Some(v),
                _ => skipped.see(&f)?,
            }
        }
        if version != Some(VERSION) {
            return Err(bad(t::VERSION, 1));
        }
        if scope != Some(SCOPE_AUTHORITY) {
            return Err(bad(t::SCOPE, 1));
        }
        let kind = kind.ok_or(FormatError::MissingField { tag: t::PAYLOAD_KIND })?;
        let request = Self {
            tenant: tenant.ok_or(FormatError::MissingField { tag: t::TENANT })?,
            authority_id: authority_id.ok_or(FormatError::MissingField { tag: t::AUTHORITY_ID })?,
            epoch: epoch.ok_or(FormatError::MissingField { tag: t::EPOCH })?,
            operation_id: operation_id.ok_or(FormatError::MissingField { tag: t::OPERATION_ID })?,
            expected_revision: expected.ok_or(FormatError::MissingField { tag: t::EXPECTED_REVISION })?,
            issued_at: issued_at.ok_or(FormatError::MissingField { tag: t::ISSUED_AT })?,
            expires_at: expires_at.ok_or(FormatError::MissingField { tag: t::EXPIRES_AT })?,
            payload: Payload::decode(kind, payload.ok_or(FormatError::MissingField { tag: t::PAYLOAD })?)?,
        };
        // Без пропущенных необязательных записей — см. довод у `Binding::peek`.
        if request.body()? != skipped.strip(body) {
            return Err(bad(0, body.len()));
        }
        Ok(request)
    }

    /// Подписать одним ключом.
    ///
    /// # Errors
    /// [`FormatError`] — тело или подпись.
    pub fn sign(&self, signer: &dyn Signer) -> Result<Vec<u8>, FormatError> {
        assemble(&self.body()?, &[sign_body(&self.body()?, signer)?])
    }
}

fn sign_body(body: &[u8], signer: &dyn Signer) -> Result<([u8; KEY], [u8; SIG]), FormatError> {
    let sig = signer
        .sign(&transcript(label::CONTROL_REQUEST, body))
        .map_err(|_| FormatError::BadHeaderSignature)?;
    Ok((signer.public_key(), sig))
}

fn assemble(body: &[u8], signatures: &[([u8; KEY], [u8; SIG])]) -> Result<Vec<u8>, FormatError> {
    let mut sorted = signatures.to_vec();
    sorted.sort_by_key(|a| a.0);
    if sorted.is_empty() || sorted.len() > MAX_SIGNERS || sorted.windows(2).any(|w| w.first().map(|x| x.0) == w.get(1).map(|x| x.0)) {
        return Err(bad(0, sorted.len()));
    }
    let count = u8::try_from(sorted.len()).map_err(|_| bad(0, sorted.len()))?;
    let mut out = vec![count];
    for (key, sig) in &sorted {
        out.extend_from_slice(key);
        out.extend_from_slice(sig);
    }
    out.extend_from_slice(body);
    Ok(out)
}

/// Подпись под намерением: ключ и подпись.
type Signature = ([u8; KEY], [u8; SIG]);

fn split_request(bytes: &[u8]) -> Result<(Vec<Signature>, &[u8]), FormatError> {
    if bytes.len() > MAX_DOCUMENT_LEN {
        return Err(bad(0, bytes.len()));
    }
    let (count, mut rest) = bytes.split_first().ok_or(bad(0, 0))?;
    let count = usize::from(*count);
    if count == 0 || count > MAX_SIGNERS {
        return Err(bad(0, count));
    }
    let mut signatures = Vec::with_capacity(count);
    for _ in 0..count {
        let (key, tail) = rest.split_at_checked(KEY).ok_or(bad(0, rest.len()))?;
        let (sig, tail) = tail.split_at_checked(SIG).ok_or(bad(0, tail.len()))?;
        signatures.push((array(key, 0)?, array(sig, 0)?));
        rest = tail;
    }
    if signatures.windows(2).any(|w| w.first().map(|x| x.0) >= w.get(1).map(|x| x.0)) {
        return Err(bad(0, count));
    }
    Ok((signatures, rest))
}

/// Разобрать намерение и проверить КАЖДУЮ подпись.
///
/// Кто вправе подписывать — решает сервер по составу привязки; здесь только
/// «подпись сходится с названным ключом».
///
/// # Почему подпись РАНЬШЕ разбора
///
/// Тот же довод И-5, что у [`crate::revocation::verify_signed`] и соседей:
/// разбор незаверенных байтов сам по себе оракул — различимые коды отказа
/// (`MissingField`, `UnknownCriticalField`, `BadFieldLength` с номером тега)
/// сообщаются о том, чего никто не подписывал, и подделка становится отличима
/// от обрезания. Здесь разбор до проверки ничем не ВЫНУЖДЕН: ключи проверки
/// лежат в КОНВЕРТЕ, который `split_request` отделяет до всякого TLV, — в
/// отличие от заголовка контейнера, где ключ подписи лежит внутри
/// подписываемого и снаружи его взять неоткуда.
///
/// # Пустой конверт
///
/// Ноль подписей означал бы тривиально пройденный цикл: тело разобралось бы
/// незаверенным, и перестановка строк внутри этой функции от такого не спасает
/// — спасать обязан рубеж РАНЬШЕ. Он есть: `split_request` отвергает
/// `count == 0` до чтения самих подписей (проба
/// `documents_beyond_the_size_limits_are_refused_before_parsing`), так что до
/// цикла документ без подписей не доходит и улучшать здесь нечего.
///
/// Кворум — сколько подписей и ЧЬИ — считает вызывающий, и оба места известны:
/// `quorum_met` в `cc-authority/src/control.rs` (по составу текущей ревизии) и
/// сверка с `roster`/`threshold` прежней эпохи в [`verify_chain`], куда ведёт
/// `cc_cli::chain::check`.
///
/// # Errors
/// [`FormatError`] — раскладка или любая несходящаяся подпись.
pub fn open_request(bytes: &[u8]) -> Result<SignedRequest, FormatError> {
    let (signatures, body) = split_request(bytes)?;
    let t = transcript(label::CONTROL_REQUEST, body);
    for (key, sig) in &signatures {
        oc_crypto::sign::verify(key, &t, sig).map_err(|_| FormatError::BadHeaderSignature)?;
    }
    let request = ControlRequest::decode_body(body)?;
    Ok(SignedRequest { request, body_hash: sha256(body), signers: signatures.into_iter().map(|(k, _)| k).collect() })
}

/// Дописать подпись ещё одного управляющего под тем же телом.
///
/// # Errors
/// [`FormatError`] — раскладка, подпись, подписант уже подписал.
pub fn cosign(bytes: &[u8], signer: &dyn Signer) -> Result<Vec<u8>, FormatError> {
    let (mut signatures, body) = split_request(bytes)?;
    open_request(bytes)?;
    if signatures.iter().any(|(k, _)| *k == signer.public_key()) {
        return Err(bad(0, signatures.len()));
    }
    signatures.push(sign_body(body, signer)?);
    assemble(body, &signatures)
}

// ---------------------------------------------------------------------------
// Квитанция.

mod receipt_tag {
    pub const VERSION: u16 = 1;
    pub const REQUEST_HASH: u16 = 2;
    pub const OPERATION_ID: u16 = 3;
    pub const OUTCOME: u16 = 4;
    pub const REVISION: u16 = 5;
    pub const COMMIT: u16 = 6;
    pub const EPOCH: u16 = 7;
    pub const DURABILITY: u16 = 8;
    pub const REASON: u16 = 9;
    pub const AT: u16 = 10;
}

/// Чем кончилась операция.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Outcome {
    /// Исполнено и зафиксировано по профилю сохранности.
    Committed = 1,
    /// Отвергнуто; состояние не менялось. Причина — в `reason`.
    Rejected = 2,
    /// Зафиксировано у сервера, но подтверждение реплики не получено:
    /// успехом НЕ считается; повтор того же намерения спросит снова.
    PendingDurability = 3,
    /// Тождество операции уже занято другим телом.
    IdConflict = 4,
    /// Намерение составлено поверх другой ревизии.
    StaleRevision = 5,
}

impl Outcome {
    #[must_use]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Committed),
            2 => Some(Self::Rejected),
            3 => Some(Self::PendingDurability),
            4 => Some(Self::IdConflict),
            5 => Some(Self::StaleRevision),
            _ => None,
        }
    }
}

/// Квитанция сервера — см. шапку модуля.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub request_hash: [u8; 32],
    pub operation_id: [u8; 16],
    pub outcome: Outcome,
    /// Ревизия привязки ПОСЛЕ операции (у отказа — текущая).
    pub revision: u64,
    /// Отпечаток зафиксированной привязки; нули, если фиксации не было.
    pub commit: [u8; 32],
    pub epoch: u64,
    /// Достигнутая сохранность: профиль, по которому фиксация подтверждена.
    pub durability: Durability,
    pub reason: String,
    pub at: i64,
}

impl Receipt {
    /// Тело без подписи.
    ///
    /// # Errors
    /// [`FormatError`] — причина вне правил.
    pub fn body(&self) -> Result<Vec<u8>, FormatError> {
        use receipt_tag as t;
        check_reason(&self.reason, t::REASON)?;
        let mut w = TlvWriter::new();
        w.put(t::VERSION, &[VERSION])?;
        w.put(t::REQUEST_HASH, &self.request_hash)?;
        w.put(t::OPERATION_ID, &self.operation_id)?;
        w.put(t::OUTCOME, &[self.outcome as u8])?;
        w.put(t::REVISION, &self.revision.to_le_bytes())?;
        w.put(t::COMMIT, &self.commit)?;
        w.put(t::EPOCH, &self.epoch.to_le_bytes())?;
        w.put(t::DURABILITY, &[self.durability as u8])?;
        w.put(t::REASON, self.reason.as_bytes())?;
        w.put(t::AT, &self.at.to_le_bytes())?;
        Ok(w.finish().to_vec())
    }

    /// Подписать ключом подписи лизингов.
    ///
    /// # Errors
    /// [`FormatError`] — тело или подпись.
    pub fn sign(&self, signer: &dyn Signer) -> Result<Vec<u8>, FormatError> {
        let body = self.body()?;
        let sig = signer
            .sign(&transcript(label::OPERATION_RECEIPT, &body))
            .map_err(|_| FormatError::BadHeaderSignature)?;
        let mut out = sig.to_vec();
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Разобрать и проверить ключом сервера.
    ///
    /// # Errors
    /// [`FormatError`] — раскладка или подпись.
    pub fn open(bytes: &[u8], lease_public: &[u8; KEY]) -> Result<Self, FormatError> {
        use receipt_tag as t;
        let (sig, body) = split_signed(bytes)?;
        oc_crypto::sign::verify(lease_public, &transcript(label::OPERATION_RECEIPT, body), &sig)
            .map_err(|_| FormatError::BadHeaderSignature)?;
        let mut r = TlvReader::new(body);
        let mut skipped = crate::unknown::Skipped::default();
        let (mut version, mut hash, mut op, mut outcome, mut revision) = (None, None, None, None, None);
        let (mut commit, mut epoch, mut durability, mut reason, mut at) = (None, None, None, None, None);
        while let Some(f) = r.next_field()? {
            let v = f.value;
            match f.tag {
                t::VERSION => version = Some(u8_field(v, f.tag)?),
                t::REQUEST_HASH => hash = Some(array(v, f.tag)?),
                t::OPERATION_ID => op = Some(array(v, f.tag)?),
                t::OUTCOME => outcome = Some(Outcome::from_u8(u8_field(v, f.tag)?).ok_or(bad(f.tag, 1))?),
                t::REVISION => revision = Some(u64_field(v, f.tag)?),
                t::COMMIT => commit = Some(array(v, f.tag)?),
                t::EPOCH => epoch = Some(u64_field(v, f.tag)?),
                t::DURABILITY => {
                    durability = Some(Durability::from_u8(u8_field(v, f.tag)?).ok_or(bad(f.tag, 1))?);
                }
                t::REASON => reason = Some(text(v, f.tag)?),
                t::AT => at = Some(i64_field(v, f.tag)?),
                _ => skipped.see(&f)?,
            }
        }
        if version != Some(VERSION) {
            return Err(bad(t::VERSION, 1));
        }
        let receipt = Self {
            request_hash: hash.ok_or(FormatError::MissingField { tag: t::REQUEST_HASH })?,
            operation_id: op.ok_or(FormatError::MissingField { tag: t::OPERATION_ID })?,
            outcome: outcome.ok_or(FormatError::MissingField { tag: t::OUTCOME })?,
            revision: revision.ok_or(FormatError::MissingField { tag: t::REVISION })?,
            commit: commit.ok_or(FormatError::MissingField { tag: t::COMMIT })?,
            epoch: epoch.ok_or(FormatError::MissingField { tag: t::EPOCH })?,
            durability: durability.ok_or(FormatError::MissingField { tag: t::DURABILITY })?,
            reason: reason.ok_or(FormatError::MissingField { tag: t::REASON })?,
            at: at.ok_or(FormatError::MissingField { tag: t::AT })?,
        };
        // Без пропущенных необязательных записей — см. довод у `Binding::peek`.
        if receipt.body()? != skipped.strip(body) {
            return Err(bad(0, body.len()));
        }
        Ok(receipt)
    }
}


// ---------------------------------------------------------------------------
// Передача полномочий (B7).

mod transfer_tag {
    pub const VERSION: u16 = 1;
    pub const AUTHORITY_ID: u16 = 2;
    pub const FROM_EPOCH: u16 = 3;
    pub const TO_EPOCH: u16 = 4;
    pub const FROM_LEASE: u16 = 5;
    pub const TRANSITION_AT: u16 = 6;
    pub const OLD_LEASES: u16 = 7;
    pub const ISSUED_AT: u16 = 8;
    pub const EXPIRES_AT: u16 = 9;
    pub const BINDING: u16 = 10;
}

/// Что делать с лизингами, выданными прежним сервером.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OldLeases {
    /// Действуют до своего срока: обычный плановый перенос.
    Honour = 0,
    /// Не принимаются, если выданы ПОСЛЕ точки перехода: так отсекается
    /// прежний писатель, продолживший выдавать из резерва.
    RejectAfterTransition = 1,
}

impl OldLeases {
    /// Из байта; незнакомый — отказ (И-10).
    #[must_use]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Honour),
            1 => Some(Self::RejectAfterTransition),
            _ => None,
        }
    }
}

/// Сертификат передачи полномочий: прежняя эпоха называет следующую.
///
/// Подписывает его состав управляющих ПРЕЖНЕЙ эпохи — тот, что назван в её
/// привязке. Новая привязка едет внутри: её подпись своим ключом сама по себе
/// ничего не значит, значение ей даёт подпись состава под этим сертификатом.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transfer {
    /// Тождество сервера: при передаче НЕ меняется.
    pub authority_id: [u8; 16],
    pub from_epoch: u64,
    pub to_epoch: u64,
    /// Ключ подписи лизингов прежней эпохи — им проверена прежняя привязка.
    pub from_lease: [u8; KEY],
    /// С какого момента полномочия у новой эпохи.
    pub transition_at: i64,
    pub old_leases: OldLeases,
    pub issued_at: i64,
    pub expires_at: i64,
    /// Подписанная привязка НОВОЙ эпохи.
    pub binding: Vec<u8>,
}

impl Transfer {
    /// Тело без подписей.
    ///
    /// # Errors
    /// [`FormatError`] — эпохи не подряд, срок обратный, привязка вне пределов.
    pub fn body(&self) -> Result<Vec<u8>, FormatError> {
        use transfer_tag as t;
        if self.to_epoch != self.from_epoch.checked_add(1).ok_or(bad(t::TO_EPOCH, 8))? {
            return Err(bad(t::TO_EPOCH, 8));
        }
        if self.expires_at <= self.issued_at {
            return Err(bad(t::EXPIRES_AT, 8));
        }
        if self.binding.is_empty() || self.binding.len() > MAX_DOCUMENT_LEN {
            return Err(bad(t::BINDING, self.binding.len()));
        }
        let mut w = TlvWriter::new();
        w.put(t::VERSION, &[VERSION])?;
        w.put(t::AUTHORITY_ID, &self.authority_id)?;
        w.put(t::FROM_EPOCH, &self.from_epoch.to_le_bytes())?;
        w.put(t::TO_EPOCH, &self.to_epoch.to_le_bytes())?;
        w.put(t::FROM_LEASE, &self.from_lease)?;
        w.put(t::TRANSITION_AT, &self.transition_at.to_le_bytes())?;
        w.put(t::OLD_LEASES, &[self.old_leases as u8])?;
        w.put(t::ISSUED_AT, &self.issued_at.to_le_bytes())?;
        w.put(t::EXPIRES_AT, &self.expires_at.to_le_bytes())?;
        w.put(t::BINDING, &self.binding)?;
        Ok(w.finish().to_vec())
    }

    /// Подписать одним ключом состава.
    ///
    /// # Errors
    /// [`FormatError`] — тело или подпись.
    pub fn sign(&self, signer: &dyn Signer) -> Result<Vec<u8>, FormatError> {
        let body = self.body()?;
        let sig = signer
            .sign(&transcript(label::AUTHORITY_TRANSFER, &body))
            .map_err(|_| FormatError::BadHeaderSignature)?;
        assemble(&body, &[(signer.public_key(), sig)])
    }

    fn decode_body(body: &[u8]) -> Result<Self, FormatError> {
        use transfer_tag as t;
        let mut r = TlvReader::new(body);
        let mut skipped = crate::unknown::Skipped::default();
        let (mut version, mut id, mut from, mut to, mut key) = (None, None, None, None, None);
        let (mut at, mut old, mut issued, mut expires, mut binding) = (None, None, None, None, None);
        while let Some(f) = r.next_field()? {
            let v = f.value;
            match f.tag {
                t::VERSION => version = Some(u8_field(v, f.tag)?),
                t::AUTHORITY_ID => id = Some(array(v, f.tag)?),
                t::FROM_EPOCH => from = Some(u64_field(v, f.tag)?),
                t::TO_EPOCH => to = Some(u64_field(v, f.tag)?),
                t::FROM_LEASE => key = Some(array(v, f.tag)?),
                t::TRANSITION_AT => at = Some(i64_field(v, f.tag)?),
                t::OLD_LEASES => old = Some(OldLeases::from_u8(u8_field(v, f.tag)?).ok_or(bad(f.tag, 1))?),
                t::ISSUED_AT => issued = Some(i64_field(v, f.tag)?),
                t::EXPIRES_AT => expires = Some(i64_field(v, f.tag)?),
                t::BINDING => binding = Some(v.to_vec()),
                _ => skipped.see(&f)?,
            }
        }
        if version != Some(VERSION) {
            return Err(bad(t::VERSION, 1));
        }
        let transfer = Self {
            authority_id: id.ok_or(FormatError::MissingField { tag: t::AUTHORITY_ID })?,
            from_epoch: from.ok_or(FormatError::MissingField { tag: t::FROM_EPOCH })?,
            to_epoch: to.ok_or(FormatError::MissingField { tag: t::TO_EPOCH })?,
            from_lease: key.ok_or(FormatError::MissingField { tag: t::FROM_LEASE })?,
            transition_at: at.ok_or(FormatError::MissingField { tag: t::TRANSITION_AT })?,
            old_leases: old.ok_or(FormatError::MissingField { tag: t::OLD_LEASES })?,
            issued_at: issued.ok_or(FormatError::MissingField { tag: t::ISSUED_AT })?,
            expires_at: expires.ok_or(FormatError::MissingField { tag: t::EXPIRES_AT })?,
            binding: binding.ok_or(FormatError::MissingField { tag: t::BINDING })?,
        };
        // Без пропущенных необязательных записей — см. довод у `Binding::peek`.
        if transfer.body()? != skipped.strip(body) {
            return Err(bad(0, body.len()));
        }
        Ok(transfer)
    }
}

/// Разобрать сертификат передачи и проверить КАЖДУЮ подпись.
///
/// Кто вправе подписывать — решает проверяющий по составу прежней привязки;
/// здесь только «подпись сходится с названным ключом».
///
/// # Почему подпись РАНЬШЕ разбора
///
/// Довод и оговорка о пустом конверте — те же, что у [`open_request`], и
/// записаны там: конверт у обоих один (`split_request`), а разошлись эти два
/// комбинатора уже однажды — ровно та болезнь «один путь чинят, соседний
/// забывают», о которой говорит проба
/// `a_transfer_opens_only_while_every_signature_holds`.
///
/// # Errors
/// [`FormatError`] — раскладка или любая несходящаяся подпись.
pub fn open_transfer(bytes: &[u8]) -> Result<(Transfer, Vec<[u8; KEY]>), FormatError> {
    let (signatures, body) = split_request(bytes)?;
    let t = transcript(label::AUTHORITY_TRANSFER, body);
    for (key, sig) in &signatures {
        oc_crypto::sign::verify(key, &t, sig).map_err(|_| FormatError::BadHeaderSignature)?;
    }
    let transfer = Transfer::decode_body(body)?;
    Ok((transfer, signatures.into_iter().map(|(k, _)| k).collect()))
}

/// Дописать подпись ещё одного управляющего под тем же сертификатом.
///
/// # Errors
/// [`FormatError`] — раскладка, подпись, подписант уже подписал.
pub fn cosign_transfer(bytes: &[u8], signer: &dyn Signer) -> Result<Vec<u8>, FormatError> {
    let (mut signatures, body) = split_request(bytes)?;
    open_transfer(bytes)?;
    if signatures.iter().any(|(k, _)| *k == signer.public_key()) {
        return Err(bad(0, signatures.len()));
    }
    let sig = signer
        .sign(&transcript(label::AUTHORITY_TRANSFER, body))
        .map_err(|_| FormatError::BadHeaderSignature)?;
    signatures.push((signer.public_key(), sig));
    assemble(body, &signatures)
}

/// Кем сервер стал после цепочки передач.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Effective {
    /// Привязка действующей эпохи.
    pub binding: Binding,
    /// Её подписанные байты.
    pub bytes: Vec<u8>,
    /// Момент последнего перехода; `None` — передач не было.
    pub transition_at: Option<i64>,
    /// Судьба лизингов прежней эпохи.
    pub old_leases: Option<OldLeases>,
    /// Ключи прежних эпох по порядку: ими проверяются старые лизинги.
    pub previous_keys: Vec<[u8; KEY]>,
}

/// Почему цепочка не принята.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// Первая привязка не проверяется якорем.
    NotAnchored,
    /// Сертификат подписан не составом прежней эпохи.
    NotAuthorized { have: u8, need: u8 },
    /// Эпохи не подряд, тождество сменилось или ключ не тот.
    Broken(&'static str),
    /// Раскладка документа.
    Malformed(String),
    /// Сертификат просрочен на момент проверки.
    Expired { expires_at: i64, now: i64 },
}

impl core::fmt::Display for ChainError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotAnchored => {
                write!(f, "первая привязка цепочки не проверяется ключом сервера из контейнера")
            }
            Self::NotAuthorized { have, need } => write!(
                f,
                "передачу подписали {have} управляющих прежней эпохи из нужных {need}: \
                 произвольный новый сервер доверенным не становится"
            ),
            Self::Broken(why) => write!(f, "цепочка не сходится: {why}"),
            Self::Malformed(why) => write!(f, "документ цепочки не разбирается: {why}"),
            Self::Expired { expires_at, now } => {
                write!(f, "сертификат передачи просрочен ({expires_at} при текущем {now})")
            }
        }
    }
}

/// Проверить цепочку: первую привязку — якорем, каждую передачу — составом
/// прежней эпохи.
///
/// `anchor` — ключ подписи лизингов из ЗАГОЛОВКА контейнера. Ни один документ
/// цепочки не назначает себе доверие сам: сертификат проверяется составом,
/// названным в привязке, которая проверена раньше.
///
/// # Errors
/// [`ChainError`] — якорь, полномочие, непрерывность, срок или раскладка.
pub fn verify_chain(
    first: &[u8],
    transfers: &[Vec<u8>],
    anchor: &[u8; KEY],
    now: i64,
) -> Result<Effective, ChainError> {
    let mut binding = Binding::open(first, anchor).map_err(|e| match e {
        FormatError::BadHeaderSignature => ChainError::NotAnchored,
        other => ChainError::Malformed(other.to_string()),
    })?;
    let mut bytes = first.to_vec();
    let mut previous_keys = Vec::new();
    let mut transition_at = None;
    let mut old_leases = None;
    for signed in transfers {
        let (transfer, signers) =
            open_transfer(signed).map_err(|e| ChainError::Malformed(e.to_string()))?;
        if transfer.authority_id != binding.authority_id {
            return Err(ChainError::Broken("тождество сервера сменилось"));
        }
        if transfer.from_epoch != binding.epoch {
            return Err(ChainError::Broken("сертификат выписан не от действующей эпохи"));
        }
        if !oc_crypto::public_key_eq(&transfer.from_lease, &binding.lease_public) {
            return Err(ChainError::Broken("сертификат называет другой прежний ключ"));
        }
        if transfer.expires_at < now {
            return Err(ChainError::Expired { expires_at: transfer.expires_at, now });
        }
        let have = signers.iter().filter(|key| binding.roster.contains(key)).count();
        let have = u8::try_from(have).unwrap_or(u8::MAX);
        if binding.roster.is_empty() || binding.threshold == 0 || have < binding.threshold {
            return Err(ChainError::NotAuthorized { have, need: binding.threshold });
        }
        // Новая привязка проверяется СВОИМ ключом: доверие ей даёт подпись
        // состава под сертификатом, несущим её байты целиком.
        let next = Binding::peek(&transfer.binding).map_err(|e| ChainError::Malformed(e.to_string()))?;
        let next = Binding::open(&transfer.binding, &next.lease_public).map_err(|e| match e {
            FormatError::BadHeaderSignature => {
                ChainError::Broken("привязка новой эпохи не подписана своим ключом")
            }
            other => ChainError::Malformed(other.to_string()),
        })?;
        if next.epoch != transfer.to_epoch || next.authority_id != transfer.authority_id {
            return Err(ChainError::Broken("привязка новой эпохи не та, что названа сертификатом"));
        }
        previous_keys.push(binding.lease_public);
        transition_at = Some(transfer.transition_at);
        old_leases = Some(transfer.old_leases);
        bytes = transfer.binding.clone();
        binding = next;
    }
    Ok(Effective { binding, bytes, transition_at, old_leases, previous_keys })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use oc_crypto::sign::Ed25519Signer;

    fn server() -> Ed25519Signer {
        Ed25519Signer::from_seed(&[0x41; 32])
    }

    fn binding(signer: &Ed25519Signer) -> Binding {
        Binding {
            tenant: "acme".into(),
            authority_id: [0x0a; 16],
            epoch: 0,
            revision: 0,
            lease_public: signer.public_key(),
            sealing_public: [0x0b; 32],
            urls: vec!["127.0.0.1:4455".into()],
            pins: vec![],
            durability: Durability::Local,
            recovery: Recovery::Package,
            status: Status::Serving,
            roster: vec![],
            threshold: 0,
            operation_id: [0; 16],
            previous: [0; 32],
            issued_at: 1_800_000_000,
            expires_at: 1_800_086_400,
        }
    }

    #[test]
    fn a_binding_opens_only_under_the_key_trusted_in_advance() {
        let s = server();
        let b = binding(&s);
        let bytes = b.sign(&s).unwrap();
        assert_eq!(Binding::open(&bytes, &s.public_key()).unwrap(), b);
        // Чужой якорь — отказ, даже если подпись сходится с ключом внутри.
        let other = Ed25519Signer::from_seed(&[0x42; 32]);
        let mut forged = b.clone();
        forged.lease_public = other.public_key();
        let forged = forged.sign(&other).unwrap();
        assert!(Binding::open(&forged, &s.public_key()).is_err(), "привязка со своим ключом принята");
        for i in 0..bytes.len() {
            let mut spoiled = bytes.clone();
            spoiled[i] ^= 1;
            assert!(Binding::open(&spoiled, &s.public_key()).is_err(), "порча байта {i} не замечена");
        }
        // Подписать можно только ключом, названным внутри.
        assert!(b.sign(&other).is_err());
    }

    #[test]
    fn continuity_names_rollback_fork_and_gaps() {
        let s = server();
        let first = binding(&s);
        let first_bytes = first.sign(&s).unwrap();
        let mut second = first.clone();
        second.revision = 1;
        second.operation_id = [1; 16];
        second.previous = digest(&first_bytes);
        let second_bytes = second.sign(&s).unwrap();
        assert_eq!(continuity(&first, &first_bytes, &second, &second_bytes), Continuity::Newer { adjacent: true });
        assert_eq!(continuity(&second, &second_bytes, &first, &first_bytes), Continuity::Rollback);
        assert_eq!(continuity(&first, &first_bytes, &first, &first_bytes), Continuity::Same);
        let mut sibling = second.clone();
        sibling.urls = vec!["10.0.0.1:1".into()];
        let sibling_bytes = sibling.sign(&s).unwrap();
        assert_eq!(continuity(&second, &second_bytes, &sibling, &sibling_bytes), Continuity::Fork);
        let mut detached = second.clone();
        detached.previous = [9; 32];
        let detached_bytes = detached.sign(&s).unwrap();
        assert_eq!(continuity(&first, &first_bytes, &detached, &detached_bytes), Continuity::Fork);
        let mut far = second.clone();
        far.revision = 5;
        let far_bytes = far.sign(&s).unwrap();
        assert_eq!(continuity(&first, &first_bytes, &far, &far_bytes), Continuity::Newer { adjacent: false });
        let mut other_tenant = second;
        other_tenant.tenant = "globex".into();
        let other_bytes = other_tenant.sign(&s).unwrap();
        assert_eq!(continuity(&first, &first_bytes, &other_tenant, &other_bytes), Continuity::Unrelated);
    }

    fn request() -> ControlRequest {
        ControlRequest {
            tenant: "acme".into(),
            authority_id: [0x0a; 16],
            epoch: 0,
            operation_id: [0x77; 16],
            expected_revision: 3,
            issued_at: 1_800_000_000,
            expires_at: 1_800_000_600,
            payload: Payload::SetEndpoints { urls: vec!["a:1".into(), "b:2".into()], pins: vec![[5; 32]] },
        }
    }

    #[test]
    fn a_request_carries_several_signatures_over_one_body() {
        let a = Ed25519Signer::from_seed(&[0x51; 32]);
        let b = Ed25519Signer::from_seed(&[0x52; 32]);
        let one = request().sign(&a).unwrap();
        let two = cosign(&one, &b).unwrap();
        let opened = open_request(&two).unwrap();
        assert_eq!(opened.request, request());
        assert_eq!(opened.signers.len(), 2);
        assert_eq!(opened.body_hash, open_request(&one).unwrap().body_hash, "отпечаток намерения зависит от подписей");
        assert!(cosign(&two, &b).is_err(), "второй подписью того же ключа кворум набирается");
        for i in 0..two.len() {
            let mut spoiled = two.clone();
            spoiled[i] ^= 1;
            assert!(open_request(&spoiled).is_err(), "порча байта {i} намерения не замечена");
        }
    }

    #[test]
    fn every_payload_round_trips_and_a_long_lived_request_is_refused() {
        let a = Ed25519Signer::from_seed(&[0x53; 32]);
        let payloads = [
            Payload::SetEndpoints { urls: vec!["x:1".into()], pins: vec![] },
            Payload::SetDurability(Durability::Witnessed),
            Payload::SetRoster { keys: vec![[1; 32], [2; 32]], threshold: 2 },
            Payload::SetRecovery(Recovery::NotRecoverable),
            Payload::Decommission { status: Status::ArchiveOnly, reason: "договор окончен".into() },
            Payload::AddAuthor([3; 32]),
            Payload::RemoveAuthor([4; 32]),
        ];
        for payload in payloads {
            let r = ControlRequest { payload, ..request() };
            let bytes = r.sign(&a).unwrap();
            assert_eq!(open_request(&bytes).unwrap().request, r);
        }
        let long = ControlRequest { expires_at: 1_800_000_000 + MAX_REQUEST_LIFETIME + 1, ..request() };
        assert!(long.sign(&a).is_err(), "намерение дольше суток принято");
        let backwards = ControlRequest { expires_at: 1_800_000_000, ..request() };
        assert!(backwards.sign(&a).is_err());
        let unsorted = ControlRequest {
            payload: Payload::SetRoster { keys: vec![[2; 32], [1; 32]], threshold: 1 },
            ..request()
        };
        assert!(unsorted.sign(&a).is_err(), "неупорядоченный состав принят");
        let transfer = ControlRequest {
            payload: Payload::Decommission { status: Status::Transferred, reason: String::new() },
            ..request()
        };
        assert!(transfer.sign(&a).is_err(), "передача под видом прекращения принята");
    }

    #[test]
    fn a_receipt_is_bound_to_the_server_key() {
        let s = server();
        let receipt = Receipt {
            request_hash: [1; 32],
            operation_id: [2; 16],
            outcome: Outcome::PendingDurability,
            revision: 4,
            commit: [3; 32],
            epoch: 0,
            durability: Durability::Local,
            reason: "реплика не ответила".into(),
            at: 1_800_000_000,
        };
        let bytes = receipt.sign(&s).unwrap();
        assert_eq!(Receipt::open(&bytes, &s.public_key()).unwrap(), receipt);
        let other = Ed25519Signer::from_seed(&[0x43; 32]);
        assert!(Receipt::open(&bytes, &other.public_key()).is_err());
    }

    /// СЕРТИФИКАТ ПЕРЕДАЧИ ОТКРЫВАЕТСЯ, ПОКА КАЖДАЯ ЕГО ПОДПИСЬ СХОДИТСЯ.
    ///
    /// # Почему проба заведена отдельно от намерения
    ///
    /// Потому что `open_transfer` и `open_request` — два РАЗНЫХ комбинатора, и
    /// сторож был только у второго. Снятие `oc_crypto::sign::verify` из
    /// `open_transfer` не роняло ни одной пробы: сертификат разбирался,
    /// сверялся сам с собой (`transfer.body()? != body`) и объявлялся открытым —
    /// то есть переход полномочий к новой эпохе принимался бы без подписи
    /// прежнего состава. Ровно эта болезнь описана в CLAUDE.md как «один путь
    /// чинят, соседний забывают».
    ///
    /// Перебор по КАЖДОМУ байту, а не по трём выбранным: байты подписей и байты
    /// названных ключей тело собой не проверяет, и единственное, что их
    /// стережёт, — та самая проверка подписи.
    #[test]
    fn a_transfer_opens_only_while_every_signature_holds() {
        let s = server();
        let a = Ed25519Signer::from_seed(&[0x61; 32]);
        let b = Ed25519Signer::from_seed(&[0x62; 32]);
        let transfer = Transfer {
            authority_id: [0x60; 16],
            from_epoch: 0,
            to_epoch: 1,
            from_lease: a.public_key(),
            transition_at: 1_800_000_500,
            old_leases: OldLeases::RejectAfterTransition,
            issued_at: 1_800_000_000,
            expires_at: 1_800_086_400,
            binding: binding(&s).sign(&s).unwrap(),
        };

        let one = transfer.sign(&a).unwrap();
        let two = cosign_transfer(&one, &b).unwrap();
        let (opened, signers) = open_transfer(&two).unwrap();
        assert_eq!(opened, transfer, "честный сертификат не разобрался");
        assert_eq!(signers.len(), 2, "подписанты потерялись");
        assert!(signers.contains(&a.public_key()) && signers.contains(&b.public_key()));

        for i in 0..two.len() {
            let mut spoiled = two.clone();
            spoiled[i] ^= 1;
            assert!(
                open_transfer(&spoiled).is_err(),
                "порча байта {i} сертификата передачи не замечена"
            );
        }
    }

    /// НЕРАЗБИРАЕМОЕ ТЕЛО ОТВЕРГАЕТСЯ ПОДПИСЬЮ, А НЕ РАЗБОРОМ.
    ///
    /// Довод — И-5 для подписанных документов: различимый код отказа разбора,
    /// выданный о теле, которого никто не подписывал, и есть оракул. Тело здесь
    /// заведомо неразбираемое (незнакомый КРИТИЧНЫЙ тег `0x7ABC`), поэтому оба
    /// рубежа хотят ответить — и видно, который отвечает первым.
    ///
    /// # Почему без положительного контроля проба была бы слепа
    ///
    /// Потому что `BadHeaderSignature` при неверной подписи вернётся и при
    /// обратном порядке — для ЛЮБОГО тела, которое разбирается. Различает
    /// порядок только пара: то же самое тело с ВЕРНОЙ подписью обязано дать
    /// именно [`FormatError::UnknownCriticalField`]. Пройди обе половины при
    /// обратном порядке — проба не про порядок.
    ///
    /// Обе двери в одной пробе намеренно: конверт у них общий, а разошлись они
    /// уже однажды.
    #[test]
    fn an_unparsable_body_is_refused_by_the_signature_first() {
        let a = Ed25519Signer::from_seed(&[0x71; 32]);
        let mut w = TlvWriter::new();
        w.put(0x7ABC, b"no reader knows this tag").unwrap();
        let body = w.finish().to_vec();

        /// Дверь: как зовётся, под какой меткой подписана, чем открывается.
        /// Итог сводится к `()` — пробу занимает КОД отказа, а не содержимое.
        type Door<'a> = (&'a str, oc_crypto::Label, &'a dyn Fn(&[u8]) -> Result<(), FormatError>);

        let request_door = |bytes: &[u8]| open_request(bytes).map(|_| ());
        let transfer_door = |bytes: &[u8]| open_transfer(bytes).map(|_| ());
        let doors: [Door<'_>; 2] = [
            ("open_request", label::CONTROL_REQUEST, &request_door),
            ("open_transfer", label::AUTHORITY_TRANSFER, &transfer_door),
        ];

        for (name, who, open) in doors {
            let sig = a.sign(&transcript(who, &body)).unwrap();
            // ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: подпись сходится — отвечает разбор.
            let honest = assemble(&body, &[(a.public_key(), sig)]).unwrap();
            assert_eq!(
                open(&honest),
                Err(FormatError::UnknownCriticalField { tag: 0x7ABC }),
                "{name}: при верной подписи обязан отказать РАЗБОР, иначе проба не различает порядок"
            );
            let mut spoiled = sig;
            spoiled[0] ^= 1;
            let forged = assemble(&body, &[(a.public_key(), spoiled)]).unwrap();
            assert_eq!(
                open(&forged),
                Err(FormatError::BadHeaderSignature),
                "{name}: незаверенное тело разобрано до проверки подписи — код отказа сообщён о том, чего никто не подписывал"
            );
        }
    }

    /// ГРАНИЦЫ РАЗМЕРА — у документа, приходящего с провода, они обязаны быть
    /// проверены ДО разбора, а не после: разбор мусора длиной в мегабайты и
    /// есть отказ в обслуживании.
    #[test]
    fn documents_beyond_the_size_limits_are_refused_before_parsing() {
        let a = Ed25519Signer::from_seed(&[0x51; 32]);
        let good = request().sign(&a).unwrap();
        assert!(open_request(&good).is_ok(), "годное намерение не разобралось");

        // Длиннее предела — отказ, и неважно, что внутри.
        let mut huge = good.clone();
        huge.resize(MAX_DOCUMENT_LEN + 1, 0);
        assert!(open_request(&huge).is_err(), "документ длиннее предела разобран");

        // Число подписей больше предела — отказ по первому байту, до чтения
        // самих подписей.
        let mut many = good.clone();
        many[0] = u8::try_from(MAX_SIGNERS).unwrap() + 1;
        assert!(open_request(&many).is_err(), "подписей больше предела принято");

        // Ноль подписей — тоже отказ: документ без подписи не документ.
        let mut none = good.clone();
        none[0] = 0;
        assert!(open_request(&none).is_err(), "документ без подписей принят");

        // Сертификат передачи с привязкой длиннее предела не подписывается:
        // проверка стоит у составителя, а не только у читателя.
        let transfer = Transfer {
            authority_id: [0x60; 16],
            from_epoch: 0,
            to_epoch: 1,
            from_lease: a.public_key(),
            transition_at: 1_800_000_500,
            old_leases: OldLeases::RejectAfterTransition,
            issued_at: 1_800_000_000,
            expires_at: 1_800_086_400,
            binding: vec![0u8; MAX_DOCUMENT_LEN + 1],
        };
        assert!(transfer.sign(&a).is_err(), "передача с огромной привязкой подписана");
    }
}
