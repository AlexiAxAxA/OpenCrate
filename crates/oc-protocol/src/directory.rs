//! Каталог ключей организации: запись, её лист и доказательство
//! (`docs/protocol.md` §9.14, D4).
//!
//! # Что запись утверждает
//!
//! «Сервер организации `tenant` называет ключ `public` (механизм `kem`,
//! отпечаток K27 `fpr`) ключом участника `name`, версия `version`,
//! происхождение — `origin`». Это утверждение СЕРВЕРА, и само по себе оно не
//! доказывает, что за ключом стоит этот человек: имя — слова оператора, а не
//! криптография. Журнал каталога делает другое — не даёт серверу показать
//! разным людям разные записи незаметно: лист — хеш самой записи, голова
//! подписана сервером и свидетелем (`crate::witness`, вид `Directory`).
//!
//! # Чего здесь нет
//!
//! Доказательства ОТСУТСТВИЯ: «записи для этого имени нет» сервер утверждает
//! словом. Полноту проверяет монитор, читающий журнал целиком
//! (`DirectoryRecords`) и сверяющий корень с засвидетельствованной головой.

use oc_format::FormatError;
use oc_format::tlv::{TlvReader, TlvWriter};
use crate::witness::{Log, SIGNED_HEAD_LEN, SignedHead};
use oc_crypto::merkle::{Leaf, MerkleTree};
use oc_crypto::transcript::Transcript;
use oc_crypto::{KemAlg, label, sha256};

/// Длина имени организации, байт.
pub const MAX_TENANT: usize = 64;
/// Длина имени участника, знаков.
pub const MAX_NAME_CHARS: usize = 128;
/// Длина происхождения записи, знаков.
pub const MAX_ORIGIN_CHARS: usize = 512;
/// Длина записи, байт: самый длинный ключ (MLKEM768-P256) с запасом.
pub const MAX_RECORD_LEN: usize = 8 * 1024;
/// Записей в одной странице монитора.
pub const MAX_PAGE: u32 = 256;
/// Предел пути доказательства включения: дерево до 2^32 листьев — не длиннее 32.
pub const MAX_INCLUSION_PATH: usize = 64;

/// Теги записи. Все критичны и все обязательны, по возрастанию (И-7).
pub mod tag {
    pub const TENANT: u16 = 1;
    pub const NAME: u16 = 2;
    pub const KEM: u16 = 3;
    pub const PUBLIC: u16 = 4;
    pub const FPR: u16 = 5;
    pub const VERSION: u16 = 6;
    pub const STATE: u16 = 7;
    pub const ORIGIN: u16 = 8;
    pub const AT: u16 = 9;
}

/// Действует ли ключ записи.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyState {
    /// Ключ действует.
    Active = 0,
    /// Ключ снят: запись о снятии — тоже версия, а не удаление, иначе снятие
    /// нельзя было бы доказать.
    Withdrawn = 1,
}

/// Запись каталога.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub tenant: String,
    pub name: String,
    pub kem: KemAlg,
    pub public: Vec<u8>,
    /// K27 от `(kem, public)` — сверяется при разборе, а не принимается.
    pub fpr: [u8; 32],
    pub version: u64,
    pub state: KeyState,
    pub origin: String,
    pub at: i64,
}

fn bad(tag: u16, len: usize) -> FormatError {
    FormatError::BadFieldLength { tag, len }
}

/// Имя организации: `[a-z0-9._-]`, 1..=64 байт. Узкий алфавит — потому что
/// имя сравнивается побайтно, и двух написаний одной организации быть не
/// должно.
fn check_tenant(tenant: &str) -> Result<(), FormatError> {
    let ok = !tenant.is_empty()
        && tenant.len() <= MAX_TENANT
        && tenant.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-' || b == b'_');
    if ok { Ok(()) } else { Err(bad(tag::TENANT, tenant.len())) }
}

/// Текст для человека: непустой, в пределе, без знаков, опасных на экране.
fn check_text(text: &str, max_chars: usize, tag: u16) -> Result<(), FormatError> {
    if text.trim().is_empty() || text.chars().count() > max_chars {
        return Err(bad(tag, text.len()));
    }
    if let Some(c) = text.chars().find(|c| oc_format::text::is_display_unsafe(*c)) {
        return Err(FormatError::BadNoteChar { tag, code: u32::from(c) });
    }
    Ok(())
}

impl Record {
    /// Собрать запись; отпечаток считается здесь.
    ///
    /// # Errors
    /// [`FormatError`] — имя, текст, механизм или длина ключа негодны.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        tenant: &str,
        name: &str,
        kem: KemAlg,
        public: &[u8],
        version: u64,
        state: KeyState,
        origin: &str,
        at: i64,
    ) -> Result<Self, FormatError> {
        let fpr = oc_crypto::kdf::device_fpr(kem, public).map_err(|_| bad(tag::PUBLIC, public.len()))?;
        let record = Self {
            tenant: tenant.to_owned(),
            name: name.to_owned(),
            kem,
            public: public.to_vec(),
            fpr,
            version,
            state,
            origin: origin.to_owned(),
            at,
        };
        record.check()?;
        Ok(record)
    }

    fn check(&self) -> Result<(), FormatError> {
        check_tenant(&self.tenant)?;
        check_text(&self.name, MAX_NAME_CHARS, tag::NAME)?;
        check_text(&self.origin, MAX_ORIGIN_CHARS, tag::ORIGIN)?;
        if self.version == 0 {
            return Err(bad(tag::VERSION, 0));
        }
        let fpr = oc_crypto::kdf::device_fpr(self.kem, &self.public).map_err(|_| bad(tag::PUBLIC, self.public.len()))?;
        if !oc_crypto::digest_eq(&fpr, &self.fpr) {
            return Err(bad(tag::FPR, self.fpr.len()));
        }
        Ok(())
    }

    /// Байты записи.
    ///
    /// # Errors
    /// [`FormatError`] — запись негодна или длиннее предела.
    pub fn encode(&self) -> Result<Vec<u8>, FormatError> {
        self.check()?;
        let mut w = TlvWriter::new();
        w.put(tag::TENANT, self.tenant.as_bytes())?;
        w.put(tag::NAME, self.name.as_bytes())?;
        w.put(tag::KEM, &[self.kem as u8])?;
        w.put(tag::PUBLIC, &self.public)?;
        w.put(tag::FPR, &self.fpr)?;
        w.put(tag::VERSION, &self.version.to_le_bytes())?;
        w.put(tag::STATE, &[self.state as u8])?;
        w.put(tag::ORIGIN, self.origin.as_bytes())?;
        w.put(tag::AT, &self.at.to_le_bytes())?;
        let bytes = w.finish().to_vec();
        if bytes.len() > MAX_RECORD_LEN {
            return Err(bad(0, bytes.len()));
        }
        Ok(bytes)
    }

    /// Разобрать запись — строго: все девять полей, по порядку, точной длины;
    /// отпечаток пересчитывается и сверяется.
    ///
    /// # Errors
    /// [`FormatError`] — любое отклонение.
    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        if bytes.len() > MAX_RECORD_LEN {
            return Err(bad(0, bytes.len()));
        }
        let mut reader = TlvReader::new(bytes);
        let mut skipped = crate::unknown::Skipped::default();
        let mut fields: [Option<&[u8]>; 9] = [None; 9];
        let mut expected = tag::TENANT;
        while let Some(field) = reader.next_field()? {
            // Все ЗНАКОМЫЕ теги обязательны и идут подряд: следующий обязан быть
            // ровно ожидаемым, иначе запись — не наша. Знакомый тег не на своём
            // месте отвергается тем же вариантом, что и раньше: решение о нём
            // принимает та же функция, а для критичного диапазона она отвечает
            // «отказ».
            //
            // Незнакомый необязательный тег пропускается (решение 2026-09-21) и
            // ожидаемого номера не сдвигает: девятка знакомых полей обязана
            // остаться подряд, иначе правило «все девять по порядку» перестало
            // бы что-либо значить.
            if field.tag != expected {
                skipped.see(&field)?;
                continue;
            }
            let slot = fields.get_mut(usize::from(field.tag).saturating_sub(1)).ok_or(FormatError::UnknownCriticalField { tag: field.tag })?;
            *slot = Some(field.value);
            expected = expected.saturating_add(1);
        }
        let get = |t: u16| -> Result<&[u8], FormatError> {
            fields
                .get(usize::from(t).saturating_sub(1))
                .copied()
                .flatten()
                .ok_or(FormatError::MissingField { tag: t })
        };
        let text = |t: u16| -> Result<String, FormatError> {
            String::from_utf8(get(t)?.to_vec()).map_err(|_| FormatError::NotUtf8 { tag: t })
        };
        let byte = |t: u16| -> Result<u8, FormatError> {
            match get(t)? {
                [b] => Ok(*b),
                other => Err(bad(t, other.len())),
            }
        };
        let eight = |t: u16| -> Result<[u8; 8], FormatError> {
            let v = get(t)?;
            v.try_into().map_err(|_| bad(t, v.len()))
        };
        let kem = KemAlg::from_u8(byte(tag::KEM)?).map_err(|_| FormatError::UnknownCriticalField { tag: tag::KEM })?;
        let state = match byte(tag::STATE)? {
            0 => KeyState::Active,
            1 => KeyState::Withdrawn,
            _ => return Err(bad(tag::STATE, 1)),
        };
        let fpr_bytes = get(tag::FPR)?;
        let record = Self {
            tenant: text(tag::TENANT)?,
            name: text(tag::NAME)?,
            kem,
            public: get(tag::PUBLIC)?.to_vec(),
            fpr: fpr_bytes.try_into().map_err(|_| bad(tag::FPR, fpr_bytes.len()))?,
            version: u64::from_le_bytes(eight(tag::VERSION)?),
            state,
            origin: text(tag::ORIGIN)?,
            at: i64::from_le_bytes(eight(tag::AT)?),
        };
        record.check()?;
        // Каноничность: те же ЗНАКОМЫЕ поля обязаны давать те же байты, иначе у
        // одной записи было бы два листа.
        //
        // Сверяется запись без пропущенных необязательных записей (решение
        // 2026-09-21). Цена названа прямо: у записи, несущей незнакомое
        // необязательное поле, лист ДРУГОЙ — [`Self::leaf`] считается по сырым
        // байтам, и иначе быть не может, иначе старый читатель не проверил бы
        // включение вовсе. То есть каноничность здесь остаётся свойством
        // БАЙТОВ в журнале, а не свойством смысла, и две записи одного смысла с
        // разным составом необязательных полей — две разные версии каталога.
        // Это и есть цена расширяемости; прежнее правило платило за неё отказом
        // разобрать запись целиком.
        if record.encode()? != skipped.strip(bytes) {
            return Err(bad(0, bytes.len()));
        }
        Ok(record)
    }

    /// Лист журнала каталога от байтов записи.
    #[must_use]
    pub fn leaf(bytes: &[u8]) -> Leaf {
        let mut t = Transcript::new(label::DIRECTORY_ENTRY);
        t.tail_after_declared_length(bytes);
        Leaf(sha256(t.as_bytes()))
    }
}

/// Запрос записи: `u8 длина ‖ организация ‖ u16le длина ‖ имя ‖ u64le size`.
/// `size = 0` — в текущей голове.
///
/// # Errors
/// [`FormatError`] — имя организации или участника негодно.
pub fn encode_lookup_request(tenant: &str, name: &str, size: u64) -> Result<Vec<u8>, FormatError> {
    check_tenant(tenant)?;
    check_text(name, MAX_NAME_CHARS, tag::NAME)?;
    let tenant_len = u8::try_from(tenant.len()).map_err(|_| bad(tag::TENANT, tenant.len()))?;
    let name_len = u16::try_from(name.len()).map_err(|_| bad(tag::NAME, name.len()))?;
    let mut out = Vec::with_capacity(tenant.len().saturating_add(name.len()).saturating_add(11));
    out.push(tenant_len);
    out.extend_from_slice(tenant.as_bytes());
    out.extend_from_slice(&name_len.to_le_bytes());
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&size.to_le_bytes());
    Ok(out)
}

/// Разобрать запрос записи. Строго.
///
/// # Errors
/// [`FormatError`] — раскладка или имена негодны.
pub fn decode_lookup_request(bytes: &[u8]) -> Result<(String, String, u64), FormatError> {
    let whole = bad(0, bytes.len());
    let (tenant_len, rest) = bytes.split_first().ok_or(whole)?;
    let (tenant, rest) = rest.split_at_checked(usize::from(*tenant_len)).ok_or(whole)?;
    let (name_len, rest) = rest.split_at_checked(2).ok_or(whole)?;
    let name_len = u16::from_le_bytes(name_len.try_into().map_err(|_| whole)?);
    let (name, rest) = rest.split_at_checked(usize::from(name_len)).ok_or(whole)?;
    let size: [u8; 8] = rest.try_into().map_err(|_| whole)?;
    let tenant = String::from_utf8(tenant.to_vec()).map_err(|_| FormatError::NotUtf8 { tag: tag::TENANT })?;
    let name = String::from_utf8(name.to_vec()).map_err(|_| FormatError::NotUtf8 { tag: tag::NAME })?;
    check_tenant(&tenant)?;
    check_text(&name, MAX_NAME_CHARS, tag::NAME)?;
    Ok((tenant, name, u64::from_le_bytes(size)))
}

/// Ответ на запрос записи: запись, её место и доказательство включения в
/// голову, подписанную сервером.
///
/// Раскладка: `голова(104) ‖ u64le index ‖ u32le длина ‖ запись ‖ путь(32·N)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lookup {
    pub head: SignedHead,
    pub index: u64,
    pub record: Vec<u8>,
    pub path: Vec<[u8; 32]>,
}

/// Почему ответ каталога не принят.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupError {
    /// Голова не подписана этим сервером как голова каталога.
    ServerSignature,
    /// Запись не разбирается.
    Malformed,
    /// Запись о другой организации или другом участнике.
    OtherEntry,
    /// Доказательство не сходится с головой.
    NotIncluded,
}

impl std::fmt::Display for LookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::ServerSignature => "голова каталога подписана не этим сервером",
            Self::Malformed => "запись каталога не разбирается",
            Self::OtherEntry => "сервер ответил записью о ДРУГОЙ организации или другом участнике",
            Self::NotIncluded => "запись не входит в голову, которой сервер её подтверждает",
        })
    }
}

impl Lookup {
    /// Байты ответа.
    ///
    /// # Errors
    /// [`FormatError`] — запись длиннее предела или путь длиннее предела.
    pub fn encode(&self) -> Result<Vec<u8>, FormatError> {
        if self.record.len() > MAX_RECORD_LEN || self.path.len() > MAX_INCLUSION_PATH {
            return Err(bad(0, self.record.len()));
        }
        let len = u32::try_from(self.record.len()).map_err(|_| bad(0, self.record.len()))?;
        let mut out = Vec::with_capacity(SIGNED_HEAD_LEN.saturating_add(12).saturating_add(self.record.len()));
        out.extend_from_slice(&self.head.encode());
        out.extend_from_slice(&self.index.to_le_bytes());
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(&self.record);
        for node in &self.path {
            out.extend_from_slice(node);
        }
        Ok(out)
    }

    /// Разобрать ответ. Строго; содержание записи здесь не проверяется — это
    /// делает [`Self::verify`].
    ///
    /// # Errors
    /// [`FormatError`] — раскладка не сходится.
    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        let whole = bad(0, bytes.len());
        let (head, rest) = bytes.split_at_checked(SIGNED_HEAD_LEN).ok_or(whole)?;
        let (index, rest) = rest.split_at_checked(8).ok_or(whole)?;
        let (len, rest) = rest.split_at_checked(4).ok_or(whole)?;
        let len = u32::from_le_bytes(len.try_into().map_err(|_| whole)?);
        let len = usize::try_from(len).map_err(|_| whole)?;
        if len == 0 || len > MAX_RECORD_LEN {
            return Err(whole);
        }
        let (record, path) = rest.split_at_checked(len).ok_or(whole)?;
        if !path.len().is_multiple_of(32) || path.len() / 32 > MAX_INCLUSION_PATH {
            return Err(whole);
        }
        let mut nodes = Vec::with_capacity(path.len() / 32);
        for node in path.chunks_exact(32) {
            nodes.push(<[u8; 32]>::try_from(node).map_err(|_| whole)?);
        }
        Ok(Self {
            head: SignedHead::decode(head)?,
            index: u64::from_le_bytes(index.try_into().map_err(|_| whole)?),
            record: record.to_vec(),
            path: nodes,
        })
    }

    /// Проверить ответ на вопрос «(организация, участник)»: подпись головы,
    /// включение записи в голову, запись о том, о ком спрашивали.
    ///
    /// # Порядок здесь несущий
    ///
    /// Подпись головы — первой, включение записи — второй, разбор записи —
    /// только третьим. Байты записи заверены не подписью головы напрямую, а
    /// доказательством включения, и лист считается по СЫРЫМ байтам
    /// ([`Record::leaf`]) — разбирать их ради проверки не нужно. Разбери мы их
    /// раньше — [`LookupError::Malformed`] отвечал бы о записи, которой в
    /// журнале нет вовсе (тот же довод И-5, что у подписанных документов).
    ///
    /// # Errors
    /// [`LookupError`] — что не сошлось.
    pub fn verify(&self, server_key: &[u8; 32], tenant: &str, name: &str) -> Result<Record, LookupError> {
        if !self.head.signed_by(Log::Directory, server_key) {
            return Err(LookupError::ServerSignature);
        }
        let (Ok(index), Ok(size)) = (u32::try_from(self.index), u32::try_from(self.head.size)) else {
            return Err(LookupError::NotIncluded);
        };
        if !MerkleTree::verify_proof(&self.head.root, index, size, &Record::leaf(&self.record), &self.path) {
            return Err(LookupError::NotIncluded);
        }
        let record = Record::decode(&self.record).map_err(|_| LookupError::Malformed)?;
        if record.tenant != tenant || record.name != name {
            return Err(LookupError::OtherEntry);
        }
        Ok(record)
    }
}

/// Страница записей для монитора: подряд `u32le длина ‖ запись`.
///
/// # Errors
/// [`FormatError`] — запись длиннее предела или записей больше страницы.
pub fn encode_page(records: &[Vec<u8>]) -> Result<Vec<u8>, FormatError> {
    if records.len() > usize::try_from(MAX_PAGE).unwrap_or(usize::MAX) {
        return Err(bad(0, records.len()));
    }
    let mut out = Vec::new();
    for record in records {
        if record.is_empty() || record.len() > MAX_RECORD_LEN {
            return Err(bad(0, record.len()));
        }
        let len = u32::try_from(record.len()).map_err(|_| bad(0, record.len()))?;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(record);
    }
    Ok(out)
}

/// Разобрать страницу. Каждая запись обязана разбираться.
///
/// # Errors
/// [`FormatError`] — раскладка или запись негодны.
pub fn decode_page(bytes: &[u8]) -> Result<Vec<Vec<u8>>, FormatError> {
    let mut out = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        let (len, tail) = rest.split_at_checked(4).ok_or(bad(0, rest.len()))?;
        let len = usize::try_from(u32::from_le_bytes(len.try_into().map_err(|_| bad(0, 4))?)).map_err(|_| bad(0, 4))?;
        let (record, tail) = tail.split_at_checked(len).ok_or(bad(0, tail.len()))?;
        Record::decode(record)?;
        out.push(record.to_vec());
        if out.len() > usize::try_from(MAX_PAGE).unwrap_or(usize::MAX) {
            return Err(bad(0, out.len()));
        }
        rest = tail;
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use crate::witness::head_transcript;
    use oc_crypto::sign::{Ed25519Signer, Signer};

    fn record(name: &str, key: u8, version: u64) -> Record {
        Record::new("acme", name, KemAlg::X25519HkdfSha256, &[key; 32], version, KeyState::Active, "отдел кадров", 1_800_000_000)
            .unwrap()
    }

    #[test]
    fn a_record_round_trips_and_its_fingerprint_is_recomputed() {
        let r = record("Пётр", 7, 1);
        let bytes = r.encode().unwrap();
        assert_eq!(Record::decode(&bytes).unwrap(), r);
        assert_eq!(r.fpr, [7; 32], "у X25519 отпечаток и есть ключ");
        // Подменённый отпечаток — отказ, даже если байты разбираются.
        let mut forged = r.clone();
        forged.fpr = [8; 32];
        assert!(forged.encode().is_err());
        let mut raw = bytes.clone();
        let at = raw.windows(32).position(|w| w == [7; 32]).unwrap();
        // Первое вхождение — ключ; второе — отпечаток.
        let fpr_at = raw[at + 32..].windows(32).position(|w| w == [7; 32]).unwrap() + at + 32;
        raw[fpr_at] ^= 1;
        assert!(Record::decode(&raw).is_err(), "отпечаток, не равный K27 ключа, принят");
        // Обрыв, хвост, лишний тег.
        assert!(Record::decode(&bytes[..bytes.len() - 1]).is_err());
        let mut longer = bytes.clone();
        longer.extend_from_slice(&10u16.to_le_bytes());
        longer.extend_from_slice(&0u32.to_le_bytes());
        assert!(Record::decode(&longer).is_err());
        // Негодные поля.
        assert!(Record::new("ACME", "Пётр", KemAlg::X25519HkdfSha256, &[1; 32], 1, KeyState::Active, "о", 0).is_err());
        assert!(Record::new("acme", "Пётр\u{202e}", KemAlg::X25519HkdfSha256, &[1; 32], 1, KeyState::Active, "о", 0).is_err());
        assert!(Record::new("acme", "Пётр", KemAlg::X25519HkdfSha256, &[1; 31], 1, KeyState::Active, "о", 0).is_err());
        assert!(Record::new("acme", "Пётр", KemAlg::RsaOaepSha256, &[1; 32], 1, KeyState::Active, "о", 0).is_err());
        assert!(Record::new("acme", "Пётр", KemAlg::X25519HkdfSha256, &[1; 32], 0, KeyState::Active, "о", 0).is_err());
        // Лист связывает каждый байт записи.
        assert_ne!(Record::leaf(&bytes), Record::leaf(&record("Пётр", 7, 2).encode().unwrap()));
    }

    #[test]
    fn a_lookup_proves_only_the_asked_entry_in_the_signed_head() {
        let server = Ed25519Signer::from_seed(&[1; 32]);
        let records: Vec<Vec<u8>> =
            ["Анна", "Пётр", "Ольга"].iter().enumerate().map(|(i, n)| record(n, i as u8 + 1, 1).encode().unwrap()).collect();
        let leaves: Vec<Leaf> = records.iter().map(|r| Record::leaf(r)).collect();
        let tree = MerkleTree::build(&leaves).unwrap();
        let root = tree.root();
        let sig = server.sign(&head_transcript(Log::Directory, 3, &root)).unwrap();
        let head = SignedHead { size: 3, root, sig };
        let lookup = Lookup { head, index: 1, record: records[1].clone(), path: tree.proof(1).unwrap() };
        let back = Lookup::decode(&lookup.encode().unwrap()).unwrap();
        assert_eq!(back, lookup);
        let key = server.public_key();
        assert_eq!(back.verify(&key, "acme", "Пётр").unwrap().fpr, [2; 32]);
        assert_eq!(back.verify(&key, "acme", "Анна"), Err(LookupError::OtherEntry));
        assert_eq!(back.verify(&key, "beta", "Пётр"), Err(LookupError::OtherEntry));
        assert_eq!(back.verify(&[9; 32], "acme", "Пётр"), Err(LookupError::ServerSignature));
        // Голова журнала событий с тем же корнем — не голова каталога.
        let mut journal_head = back.clone();
        journal_head.head.sig = server.sign(&head_transcript(Log::Journal, 3, &root)).unwrap();
        assert_eq!(journal_head.verify(&key, "acme", "Пётр"), Err(LookupError::ServerSignature));
        // Подменённая запись (другой ключ под тем же именем) — не входит.
        let mut swapped = back.clone();
        swapped.record = record("Пётр", 9, 1).encode().unwrap();
        assert_eq!(swapped.verify(&key, "acme", "Пётр"), Err(LookupError::NotIncluded));
        let mut moved = back.clone();
        moved.index = 2;
        assert_eq!(moved.verify(&key, "acme", "Пётр"), Err(LookupError::NotIncluded));
        // Разбор строгий.
        let bytes = lookup.encode().unwrap();
        assert!(Lookup::decode(&bytes[..bytes.len() - 1]).is_err());
        assert!(Lookup::decode(&[bytes.as_slice(), &[0]].concat()).is_err());
    }

    #[test]
    fn requests_and_pages_are_strict() {
        let req = encode_lookup_request("acme", "Пётр", 5).unwrap();
        assert_eq!(decode_lookup_request(&req).unwrap(), ("acme".to_owned(), "Пётр".to_owned(), 5));
        assert!(decode_lookup_request(&req[..req.len() - 1]).is_err());
        assert!(decode_lookup_request(&[req.as_slice(), &[0]].concat()).is_err());
        assert!(encode_lookup_request("Acme", "Пётр", 0).is_err());
        let page = encode_page(&[record("Анна", 1, 1).encode().unwrap(), record("Анна", 2, 2).encode().unwrap()]).unwrap();
        assert_eq!(decode_page(&page).unwrap().len(), 2);
        assert!(decode_page(&page[..page.len() - 1]).is_err());
        assert_eq!(decode_page(&[]).unwrap().len(), 0);
    }
}
