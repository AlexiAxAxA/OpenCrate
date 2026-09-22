//! ACCESS REQUEST documents: the recipient requests, the author approves.
//!
//! # What this conversation is and how it differs from activation
//!
//! Activation asks "may THIS device open the file NOW?"
//! and the server decides under rules written by the author beforehand. An access
//! request asks a different question: "is this person among the intended
//! recipients at all?" No server rule can answer that:
//! the recipient was not named when the file was packed.
//!
//! The author decides. The server is a **blind intermediary**: it stores the queue, shows
//! it to the author and delivers the answer. It sees neither share B nor the contents:
//! the answer is sealed to the device key, not the server's.
//!
//! # Why this cost the format no bytes
//!
//! The `AuthorDevice` slot carries BOTH shares (`docs/format.md` §3.3), so the author
//! can give share B to anyone without changing the container or re-signing
//! the header. The issued share lives in a separate sealed block of the same shape
//! already returned by the server; the recipient stores it alongside the lease.
//!
//! # Who the "author" is from the server's perspective
//!
//! The server has no accounts, and none had to be added. The container header
//! carries `author_key` (tag 5), signed BY THAT SAME KEY with strict verification (I-6). Thus
//! the server learns the author's key on file registration, from the file itself,
//! and accepts approval only when signed by that key.
//!
//! The technique is the same as pinning the lease-signing key: authority to
//! decide comes from the signed header, not the peer's claims.

use oc_format::tlv::{TlvReader, TlvWriter};
use oc_format::{FormatError, MAX_HEADER_LEN};

/// Maximum size of a document in this conversation.
///
/// The same cap as activation documents, for the same reason: the largest
/// item is a sealed share block, which has the shape of a slot and cannot exceed
/// the maximum header size.
pub const MAX_DOCUMENT: usize = MAX_HEADER_LEN as usize;

/// Number of pending requests returned to the author at once: the queue WINDOW.
///
/// A wire quantity: a `Requests` response carries at most this many entries,
/// and the client rejects a larger response because the length comes from a foreign party.
///
/// Sixteen: the same as the number of server addresses in the header, for a similar
/// reason: a quantity a person can review visually. Resolved requests
/// leave the window, and the next numbered requests enter it (C4), so a hundred requests
/// are handled in windows of sixteen instead of hitting a cap.
pub const MAX_PENDING_PER_FILE: usize = 16;

/// Maximum unresolved requests the server agrees to REMEMBER per file.
///
/// The limit is necessary because a request is accepted BEFORE any approval:
/// anyone able to reach the server may ask. Without a cap, this queue
/// can be filled for free.
///
/// Previously the cap equaled the window (16), so a distribution to a hundred reviewers
/// left eighty-four with "queue full" (`docs/plan.md`, F-22 item 3).
/// Two hundred fifty-six provides headroom for that distribution; the cost is explicit:
/// up to ~400 KiB of state per file with hybrid keys (1216 key bytes and 256 note bytes
/// per entry). This is server-only and never appears on the wire.
pub const MAX_WAITING_PER_FILE: usize = 256;

/// Decision number reserved for a bequest.
///
/// A bequest is an ordinary signed author decision stored on the server until silence
/// (`docs/protocol.md` §11). The sequential decision queue starts at zero and grows,
/// so the largest possible number is unreachable: assigning it to a bequest
/// takes no number away from the queue.
///
/// It is reserved so that a bequest cannot masquerade as an ordinary
/// decision or vice versa. The receiving side does not check the number at all
/// (`cc_cli::granted::accept_against`), not an oversight but the very reason
/// bequests require no recipient changes: the server checks the number and uses
/// it to distinguish the two without adding a second document kind.
pub const HEIR_SEQ: u64 = u64::MAX;

mod tag {
    pub const FILE_ID: u16 = 1;
    pub const DEVICE_FPR: u16 = 2;
    pub const DEVICE_PUBLIC: u16 = 3;
    pub const DEVICE_KEM: u16 = 4;
    pub const NOTE: u16 = 5;
    pub const SEQ: u16 = 6;
    pub const AT: u16 = 7;
    pub const APPROVE: u16 = 8;
    pub const ENC: u16 = 9;
    pub const NONCE: u16 = 10;
    pub const CT: u16 = 11;
    pub const AUTHOR_KEY: u16 = 12;
    pub const SIGNATURE: u16 = 13;
}

/// An access request sent by a device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AskAccess {
    pub file_id: [u8; 16],
    pub device_fpr: [u8; 32],
    pub device_public: Vec<u8>,
    pub device_kem: u8,
    /// A person-to-person note: "this is Peter from accounting".
    ///
    /// Plain UTF-8 in ANY language: a person reads the note and a person
    /// writes it. Categories are excluded, not letters: control characters and
    /// bidirectional marks, because an outsider chooses text displayed
    /// alongside lines the author trusts. The rule is `note_char_is_safe`.
    pub note: String,
}

/// A request awaiting a decision, as seen by the author.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    /// Server queue number, used by the author to identify the request when approving it.
    pub seq: u64,
    pub file_id: [u8; 16],
    pub device_fpr: [u8; 32],
    pub device_public: Vec<u8>,
    pub device_kem: u8,
    pub note: String,
    /// When the request was accepted, by the SERVER clock.
    ///
    /// Specifically the server's: a requester's claimed time is unauthenticated,
    /// and the author needs to distinguish "requesting right now" from "requested
    /// a month ago".
    pub at: i64,
}

/// The author's decision.
///
/// Signed with the author key (`author_key` from the header); the signature covers
/// the ENTIRE decision, including the sealed share: otherwise an intermediary could
/// replace the share while keeping the approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub seq: u64,
    pub file_id: [u8; 16],
    /// Recipient. Duplicates the queue data deliberately: the signature
    /// covers the fingerprint, so approval cannot be redirected.
    pub device_fpr: [u8; 32],
    pub approve: bool,
    /// Share B, sealed to the device key. `None` for a denial.
    pub share_b: Option<Blob>,
    pub author_key: [u8; 32],
    pub signature: [u8; 64],
}

/// Sealed block: the same shape as a slot and the server share.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blob {
    pub enc: Vec<u8>,
    pub nonce: [u8; 24],
    pub ct: Vec<u8>,
}

/// Decision bytes WITHOUT the signature: what is signed and verified.
///
/// A separate function because signer and verifier must construct
/// identical bytes. Two constructions would silently diverge, and the signature would cease
/// to mean what it promises.
///
/// # Errors
/// Returns [`FormatError`] if the body cannot be encoded.
pub fn decision_body(decision: &Decision) -> Result<Vec<u8>, FormatError> {
    // Порядок полей — ПО ВОЗРАСТАНИЮ ТЕГА, как требует И-7. Записать их в
    // порядке чтения было бы естественнее для глаза, и первая редакция так и
    // сделала: `TlvWriter` отверг её сам, потому что возрастание он проверяет.
    let mut w = TlvWriter::new();
    w.put(tag::FILE_ID, &decision.file_id)?;
    w.put(tag::DEVICE_FPR, &decision.device_fpr)?;
    w.put(tag::SEQ, &decision.seq.to_le_bytes())?;
    w.put(tag::APPROVE, &[u8::from(decision.approve)])?;
    if let Some(blob) = &decision.share_b {
        w.put(tag::ENC, &blob.enc)?;
        w.put(tag::NONCE, &blob.nonce)?;
        w.put(tag::CT, &blob.ct)?;
    }
    w.put(tag::AUTHOR_KEY, &decision.author_key)?;
    Ok(w.finish().to_vec())
}

/// Decision signature transcript.
///
/// Uses [`oc_crypto::Transcript`] rather than manual construction: its constructor REQUIRES
/// a label and inserts the separator itself. Hand-building bytes could omit
/// the label, placing decision and header signatures in the same domain.
#[must_use]
pub fn decision_transcript(body: &[u8]) -> oc_crypto::Transcript {
    let mut t = oc_crypto::Transcript::new(oc_crypto::label::GRANT);
    t.field(body);
    t
}

/// Whether a character is suitable for a note.
///
/// # Why NOT printable ASCII, although server addresses use it
///
/// The first revision restricted notes to printable ASCII using the same rule that
/// prevents display spoofing in server addresses. The rule was correct, its transfer
/// was not; a live run between two machines caught this, not a test:
/// the Russian note "test from the HUAWEI laptop" was rejected by the server.
///
/// These are different things. A server address has a WIRE representation that is ASCII by
/// construction: non-Latin names travel over the network as punycode, so the restriction
/// excludes nothing legitimate. A note has no separate wire representation: it is a phrase from
/// one person to another, and people write in their own language. The example in
/// [`AskAccess::note`] ("this is Peter from accounting", in Russian) would itself fail validation:
/// the code prohibited precisely what the documentation used as an example.
///
/// # What is excluded
///
/// The same categories as for filenames (finding V-8), for the same reason: the danger lies in
/// CATEGORIES, not letters. The set and rationale for each category are in
/// [`oc_format::text`]; only the REACTION is local: reject.
///
/// The first revision carried its own copy of the list, the repository's fourth, and it was
/// incomplete in precisely the same place as the other three: nine Trojan Source code points
/// without the direction marks themselves (ALM, LRM, RLM). The copy is gone; the list is shared.
///
/// # Why newlines are NO LONGER allowed
///
/// The first revision allowed them: "a phrase may span two lines, and a newline cannot shift
/// output; it adds a line rather than rewriting its neighbor". That reasoning is valid
/// for OVERWRITING but misses LIST SPOOFING. A note is printed as a request-list
/// item, and a newline moves text outside that item: a note
/// containing "No. 2" and "device:" adds a nonexistent request to the displayed
/// queue.
///
/// Additionally, the only note consumer already replaced `\n` with a dot,
/// so a two-line note was NEVER displayed on two lines. The format
/// allowed something the display could not render.
fn note_char_is_safe(c: char) -> bool {
    !oc_format::text::is_display_unsafe(c)
}

/// Maximum note length. A phrase, not a letter.
pub const MAX_NOTE: usize = 256;

/// The note rule shared across the crate.
///
/// # Why the tag number is a parameter rather than an internal constant
///
/// Because notes occur elsewhere: an action EXECUTION request
/// ([`crate::action::ActionRequest`], stage 2) also carries one, with its own field number
/// in its own registry. Copying these ten lines elsewhere would recreate the repository's
/// familiar problem: one path fixed, its neighbor forgotten. The excluded-category
/// sets would diverge at the first change to
/// [`oc_format::text`]. A parameter costs less than a copy, and the rejection identifies
/// THE tag containing the note; otherwise the user would read a field number from
/// another document.
///
/// # Errors
/// [`FormatError::BadFieldLength`]: the note exceeds [`MAX_NOTE`];
/// [`FormatError::BadNoteChar`]: it contains a character from an excluded category.
pub(crate) fn check_note(note: &str, tag: u16) -> Result<(), FormatError> {
    if note.len() > MAX_NOTE {
        return Err(FormatError::BadFieldLength { tag, len: note.len() });
    }
    if let Some(bad) = note.chars().find(|c| !note_char_is_safe(*c)) {
        // Отдельно от адресов сервера, а не тем же отказом. Прежняя редакция
        // возвращала `BadAddressByte { byte: 0 }`, и человек читал «в адресе
        // байт 0x00» — неверно дважды: поле не адрес, а нулевого байта в его
        // записке не было вовсе.
        return Err(FormatError::BadNoteChar { tag, code: u32::from(bad) });
    }
    Ok(())
}

/// Encode a request.
///
/// # Errors
/// Returns [`FormatError`] if the note is too long or contains
/// unsafe characters.
pub fn encode_ask(ask: &AskAccess) -> Result<Vec<u8>, FormatError> {
    check_note(&ask.note, tag::NOTE)?;
    let mut w = TlvWriter::new();
    w.put(tag::FILE_ID, &ask.file_id)?;
    w.put(tag::DEVICE_FPR, &ask.device_fpr)?;
    w.put(tag::DEVICE_PUBLIC, &ask.device_public)?;
    w.put(tag::DEVICE_KEM, &[ask.device_kem])?;
    w.put(tag::NOTE, ask.note.as_bytes())?;
    Ok(w.finish().to_vec())
}

/// Parse a request.
///
/// # Errors
/// Returns [`FormatError`] for missing fields, invalid lengths or an unsafe
/// note.
pub fn decode_ask(bytes: &[u8]) -> Result<AskAccess, FormatError> {
    let mut reader = TlvReader::new(bytes);
    let (mut file_id, mut fpr, mut public, mut kem, mut note) = (None, None, None, None, None);
    while let Some(f) = reader.next_field()? {
        match f.tag {
            tag::FILE_ID => file_id = Some(f.array::<16>()?),
            tag::DEVICE_FPR => fpr = Some(f.array::<32>()?),
            tag::DEVICE_PUBLIC => public = Some(f.value.to_vec()),
            tag::DEVICE_KEM => kem = Some(one_byte(f.value, tag::DEVICE_KEM)?),
            tag::NOTE => {
                let text = core::str::from_utf8(f.value)
                    .map_err(|_| FormatError::NotUtf8 { tag: tag::NOTE })?;
                check_note(text, tag::NOTE)?;
                note = Some(text.to_string());
            }
            other => crate::unknown::refuse_if_critical(other)?,
        }
    }
    Ok(AskAccess {
        file_id: file_id.ok_or(FormatError::MissingField { tag: tag::FILE_ID })?,
        device_fpr: fpr.ok_or(FormatError::MissingField { tag: tag::DEVICE_FPR })?,
        device_public: public.ok_or(FormatError::MissingField { tag: tag::DEVICE_PUBLIC })?,
        device_kem: kem.ok_or(FormatError::MissingField { tag: tag::DEVICE_KEM })?,
        note: note.ok_or(FormatError::MissingField { tag: tag::NOTE })?,
    })
}

/// Encode a queue entry.
///
/// # Errors
/// Returns [`FormatError`] if the body cannot be encoded.
pub fn encode_pending(p: &Pending) -> Result<Vec<u8>, FormatError> {
    check_note(&p.note, tag::NOTE)?;
    let mut w = TlvWriter::new();
    w.put(tag::FILE_ID, &p.file_id)?;
    w.put(tag::DEVICE_FPR, &p.device_fpr)?;
    w.put(tag::DEVICE_PUBLIC, &p.device_public)?;
    w.put(tag::DEVICE_KEM, &[p.device_kem])?;
    w.put(tag::NOTE, p.note.as_bytes())?;
    w.put(tag::SEQ, &p.seq.to_le_bytes())?;
    w.put(tag::AT, &p.at.to_le_bytes())?;
    Ok(w.finish().to_vec())
}

/// Parse a queue entry.
///
/// # Errors
/// Returns [`FormatError`] for missing fields or invalid lengths.
pub fn decode_pending(bytes: &[u8]) -> Result<Pending, FormatError> {
    let mut reader = TlvReader::new(bytes);
    let (mut file_id, mut fpr, mut public, mut kem, mut note) = (None, None, None, None, None);
    let (mut seq, mut at) = (None, None);
    while let Some(f) = reader.next_field()? {
        match f.tag {
            tag::FILE_ID => file_id = Some(f.array::<16>()?),
            tag::DEVICE_FPR => fpr = Some(f.array::<32>()?),
            tag::DEVICE_PUBLIC => public = Some(f.value.to_vec()),
            tag::DEVICE_KEM => kem = Some(one_byte(f.value, tag::DEVICE_KEM)?),
            tag::NOTE => {
                let text = core::str::from_utf8(f.value)
                    .map_err(|_| FormatError::NotUtf8 { tag: tag::NOTE })?;
                check_note(text, tag::NOTE)?;
                note = Some(text.to_string());
            }
            tag::SEQ => seq = Some(u64::from_le_bytes(f.array::<8>()?)),
            tag::AT => at = Some(i64::from_le_bytes(f.array::<8>()?)),
            other => crate::unknown::refuse_if_critical(other)?,
        }
    }
    Ok(Pending {
        seq: seq.ok_or(FormatError::MissingField { tag: tag::SEQ })?,
        file_id: file_id.ok_or(FormatError::MissingField { tag: tag::FILE_ID })?,
        device_fpr: fpr.ok_or(FormatError::MissingField { tag: tag::DEVICE_FPR })?,
        device_public: public.ok_or(FormatError::MissingField { tag: tag::DEVICE_PUBLIC })?,
        device_kem: kem.ok_or(FormatError::MissingField { tag: tag::DEVICE_KEM })?,
        note: note.ok_or(FormatError::MissingField { tag: tag::NOTE })?,
        at: at.ok_or(FormatError::MissingField { tag: tag::AT })?,
    })
}

/// Why queue parsing failed.
///
/// A separate error type rather than a [`FormatError`] variant: truncation at an entry boundary
/// and an extra entry concern the queue ENVELOPE, not a TLV field, and have
/// no tag number. The reason is named in words because both hosts show it to a person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueueError {
    /// The body ended within an entry: during its length or before the declared length.
    Torn(&'static str),
    /// The entry was extracted but cannot be parsed.
    Record(FormatError),
    /// More entries than the [`MAX_PENDING_PER_FILE`] window.
    TooMany,
}

impl core::fmt::Display for QueueError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Torn(what) => f.write_str(what),
            Self::Record(e) => write!(f, "запись очереди не разбирается: {e}"),
            Self::TooMany => {
                f.write_str("сервер прислал больше запросов, чем помещается в очередь")
            }
        }
    }
}

/// Parse a queue: consecutive entries, each with its own length.
///
/// Each entry has a length rather than one for the whole body because entries vary:
/// the note and public key are variable-length. There is deliberately no total entry counter:
/// it would be a second source of truth for their number and could diverge from the body.
///
/// Lives here rather than in the caller because parsing has two hosts, `cc-cli` and
/// `cc-wasm`, and a second implementation of one layout would silently diverge. Before
/// the move there was one implementation in `cc_cli::decide`, inaccessible to a
/// `wasm32` module.
///
/// # Errors
/// [`QueueError`] if the body is truncated, an entry cannot be parsed, or the entry count exceeds
/// the window.
pub fn split_queue(mut rest: &[u8]) -> Result<Vec<Pending>, QueueError> {
    let mut out: Vec<Pending> = Vec::new();
    while !rest.is_empty() {
        let head: [u8; 4] = rest
            .get(..4)
            .and_then(|s| <[u8; 4]>::try_from(s).ok())
            .ok_or(QueueError::Torn("очередь оборвана на длине записи"))?;
        let len = u32::from_le_bytes(head) as usize;
        let body = rest
            .get(4..)
            .and_then(|s| s.get(..len))
            .ok_or(QueueError::Torn("запись очереди короче объявленной длины"))?;
        out.push(decode_pending(body).map_err(QueueError::Record)?);
        rest = rest.get(4usize.saturating_add(len)..).unwrap_or_default();

        // Окно то же, что у сервера (он помнит больше, но отдаёт не больше
        // окна). Предел здесь не украшение: длина очереди приходит от чужой
        // стороны, и без него «покажи очередь» означало бы «выдели столько,
        // сколько скажет собеседник».
        if out.len() > MAX_PENDING_PER_FILE {
            return Err(QueueError::TooMany);
        }
    }
    Ok(out)
}

/// Encode a decision together with its signature.
///
/// # Errors
/// Returns [`FormatError`] if the body cannot be encoded.
pub fn encode_decision(d: &Decision) -> Result<Vec<u8>, FormatError> {
    let mut out = decision_body(d)?;
    let mut w = TlvWriter::new();
    w.put(tag::SIGNATURE, &d.signature)?;
    out.extend_from_slice(&w.finish());
    Ok(out)
}

/// Parse a decision.
///
/// The signature is NOT checked here: whoever holds the author's key must
/// check it BEFORE any use of the fields. Parsing and
/// verification are deliberately separate: combining them would produce a function whose error
/// cannot distinguish "wrong bytes" from "signature mismatch".
///
/// # Errors
/// Returns [`FormatError`] for missing fields or invalid lengths.
pub fn decode_decision(bytes: &[u8]) -> Result<Decision, FormatError> {
    let mut reader = TlvReader::new(bytes);
    let (mut seq, mut file_id, mut fpr, mut approve) = (None, None, None, None);
    let (mut enc, mut nonce, mut ct) = (None, None, None);
    let (mut author_key, mut signature) = (None, None);
    while let Some(f) = reader.next_field()? {
        match f.tag {
            tag::SEQ => seq = Some(u64::from_le_bytes(f.array::<8>()?)),
            tag::FILE_ID => file_id = Some(f.array::<16>()?),
            tag::DEVICE_FPR => fpr = Some(f.array::<32>()?),
            // СТРОГО 0 ИЛИ 1, а не «байт не ноль». Прежняя редакция читала любой
            // ненулевой байт как одобрение, и значение 5 разбиралось в `true`,
            // кодируясь обратно единицей: две разные последовательности байтов
            // означали одно и то же — ровно то, что запрещает И-7. Одобрение при
            // этом самое дорогое поле разговора: им выдаётся доля B.
            //
            // `BadFieldLength` — тот вариант, которым весь крейт сообщает
            // «значение вне области» (`standing::decode`, `order::decode`,
            // `lease::decode`); заводить ради этого новый значило бы разводить
            // одну доктрину на два кода.
            tag::APPROVE => {
                approve = Some(match one_byte(f.value, tag::APPROVE)? {
                    0 => false,
                    1 => true,
                    _ => return Err(FormatError::BadFieldLength { tag: tag::APPROVE, len: 1 }),
                });
            }
            tag::ENC => enc = Some(f.value.to_vec()),
            tag::NONCE => nonce = Some(f.array::<24>()?),
            tag::CT => ct = Some(f.value.to_vec()),
            tag::AUTHOR_KEY => author_key = Some(f.array::<32>()?),
            tag::SIGNATURE => signature = Some(f.array::<64>()?),
            // ЕДИНСТВЕННЫЙ РАЗБОРЩИК КРЕЙТА, ОСТАВШИЙСЯ СТРОГИМ (решение
            // 2026-09-21). Необязательного диапазона у решения автора нет, и
            // это не недосмотр.
            //
            // Подпись решения проверяется НЕ по сырым байтам, а по телу,
            // собранному заново из разобранной структуры ([`decision_body`],
            // зовётся в `cc_authority::Authority::decide_access` и в
            // `cc_cli::granted::verified_decision`). Пропущенный тег из такой
            // сборки выпадает — значит посторонний дописал бы его к уже
            // подписанному решению, и подпись СОШЛАСЬ БЫ. У всех остальных
            // документов крейта подпись покрывает сырые байты, и потому там
            // дописать нельзя; здесь можно, и цена этому — самое дорогое поле
            // разговора, доля B.
            //
            // Расширения необязательный диапазон здесь не даёт и в обмен: поле,
            // которое новая сборка внесёт в `decision_body`, старая всё равно
            // отвергнет по подписи. То есть выбор стоял между «ничего не
            // приобрели» и «ничего не приобрели, но подписанный документ стал
            // ковким», а И-6 держит ровно обратное — одна подпись, один
            // документ.
            other => return Err(FormatError::UnknownCriticalField { tag: other }),
        }
    }
    let approve = approve.ok_or(FormatError::MissingField { tag: tag::APPROVE })?;
    // Доля обязана быть при одобрении и обязана отсутствовать при отказе.
    // Одобрение без доли — обещание без исполнения; отказ с долей — выдача,
    // замаскированная под отказ.
    let share_b = match (approve, enc, nonce, ct) {
        (true, Some(enc), Some(nonce), Some(ct)) => Some(Blob { enc, nonce, ct }),
        (true, ..) => return Err(FormatError::MissingField { tag: tag::CT }),
        (false, None, None, None) => None,
        (false, ..) => return Err(FormatError::BadFieldLength { tag: tag::CT, len: 0 }),
    };
    Ok(Decision {
        seq: seq.ok_or(FormatError::MissingField { tag: tag::SEQ })?,
        file_id: file_id.ok_or(FormatError::MissingField { tag: tag::FILE_ID })?,
        device_fpr: fpr.ok_or(FormatError::MissingField { tag: tag::DEVICE_FPR })?,
        approve,
        share_b,
        author_key: author_key.ok_or(FormatError::MissingField { tag: tag::AUTHOR_KEY })?,
        signature: signature.ok_or(FormatError::MissingField { tag: tag::SIGNATURE })?,
    })
}

fn one_byte(value: &[u8], tag: u16) -> Result<u8, FormatError> {
    match value {
        [b] => Ok(*b),
        _ => Err(FormatError::BadFieldLength { tag, len: value.len() }),
    }
}

#[cfg(test)]
// Тестам позволено разворачивать `Option` и падать с сообщением: проверяемый код
// на этих путях не исполняется.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn ask() -> AskAccess {
        AskAccess {
            file_id: [0x11; 16],
            device_fpr: [0x22; 32],
            device_public: vec![0x33; 32],
            device_kem: 1,
            note: "Petr from accounting".to_string(),
        }
    }

    #[test]
    fn an_ask_round_trips() {
        let a = ask();
        assert_eq!(decode_ask(&encode_ask(&a).unwrap()).unwrap(), a);
    }

    /// A HUMAN WILL SEE THE NOTE, SO IT MUST NOT MOVE THE CURSOR.
    ///
    /// The same class as server addresses and filenames: an outsider authors the
    /// text, but it is displayed alongside lines the person trusts.
    #[test]
    fn a_note_that_could_repaint_the_screen_is_refused() {
        for bad in [
            "ok\u{1b}[2K\u{1b}[Aevil",
            "\u{202e}gnp.exe",
            "carriage\rreturn",
            "nul\u{0}byte",
            // Метки направления, которых в списке из девяти не было. Каждая
            // переставляет текст при показе так же, как перечисленные девять.
            "alm\u{61c}mark",
            "lrm\u{200e}mark",
            "rlm\u{200f}mark",
            // Невидимки: две разные записки печатаются неотличимо.
            "buh\u{200b}galteria",
            "soft\u{ad}hyphen",
            "word\u{2060}joiner",
            "bom\u{feff}inside",
            // Разделители строки и абзаца: категории Zl и Zp, а не Cc.
            "line\u{2028}separator",
            "para\u{2029}separator",
            // Теговые символы — невидимая копия ASCII.
            "tag\u{e0041}smuggle",
            // Перевод строки: выводит текст из пункта перечня наружу и
            // дорисовывает в очередь просьбу, которой нет.
            "Petr\n\n  N 2\n     ustroystvo: 00",
        ] {
            let mut a = ask();
            a.note = bad.to_string();
            assert!(encode_ask(&a).is_err(), "записка принята: {bad:?}");
        }

        // Контроль: обычная фраза проходит.
        let mut a = ask();
        a.note = "Petr from accounting, phone 123".to_string();
        assert!(encode_ask(&a).is_ok());
    }

    /// The rejection identifies the FIELD and CODE POINT, not an unrelated problem or the character itself.
    ///
    /// The test pins the purpose of [`FormatError::BadNoteChar`]:
    /// the old revision returned `BadAddressByte { byte: 0 }`, so someone with a
    /// Russian note saw "address contains byte 0x00". Without this test, reverting to
    /// the old variant would pass, since `is_err()` is true for both.
    #[test]
    fn a_refused_note_names_the_field_and_the_code() {
        let mut a = ask();
        a.note = "moc.dab\u{202e}".to_string();
        match encode_ask(&a) {
            Err(FormatError::BadNoteChar { tag, code }) => {
                assert_eq!(tag, tag::NOTE);
                assert_eq!(code, 0x202e);
                // Сам символ в текст ошибки попасть не смеет: напечатать его
                // значило бы пропустить на экран тем самым путём, который
                // проверка и закрывает.
                let text = format!("{}", FormatError::BadNoteChar { tag, code });
                assert!(text.contains("U+202E"), "нет кода: {text}");
                assert!(!text.contains('\u{202e}'), "символ просочился: {text}");
            }
            other => panic!("ожидался BadNoteChar, получено {other:?}"),
        }
    }

    /// Non-UTF-8 in a note is reported as non-UTF-8, not as a length error.
    #[test]
    fn a_note_that_is_not_utf8_says_so() {
        let mut a = ask();
        a.note = "okay".to_string();
        let mut bytes = encode_ask(&a).unwrap();
        let at = bytes.windows(4).position(|w| w == b"okay").expect("записка на месте");
        // `get_mut`, а не индексация: `indexing_slicing` запрещён во всём
        // workspace, и тесты не исключение. Поймал это гейт CI
        // `cargo clippy --workspace --all-targets`, который прогоняется по
        // ВСЕМ целям, — обычный `cargo test` до тестового кода литами не
        // добирается.
        *bytes.get_mut(at).expect("смещение внутри документа") = 0xff;
        match decode_ask(&bytes) {
            Err(FormatError::NotUtf8 { tag }) => assert_eq!(tag, tag::NOTE),
            other => panic!("ожидался NotUtf8, получено {other:?}"),
        }
    }

    /// A note in one's own language is valid.
    ///
    /// A regression test: the first revision narrowed the set to printable
    /// ASCII, and NOT ONE test noticed because all used
    /// Latin letters. A live run between two machines found it.
    #[test]
    fn a_note_in_any_script_is_accepted() {
        for good in [
            "это Пётр из бухгалтерии",
            "проба с ноутбука HUAWEI",
            "会计部的彼得",
            "Pëtr, buhgalterija",
            "פטר מהנהלת חשבונות",
        ] {
            let mut a = ask();
            a.note = good.to_string();
            let bytes = encode_ask(&a).expect("законная записка отвергнута");
            assert_eq!(decode_ask(&bytes).unwrap().note, good);
        }
    }

    #[test]
    fn a_note_longer_than_allowed_is_refused() {
        let mut a = ask();
        a.note = "x".repeat(MAX_NOTE.saturating_add(1));
        assert!(encode_ask(&a).is_err());
    }

    fn decision(approve: bool) -> Decision {
        Decision {
            seq: 7,
            file_id: [0x11; 16],
            device_fpr: [0x22; 32],
            approve,
            share_b: approve.then(|| Blob {
                enc: vec![0x44; 32],
                nonce: [0x55; 24],
                ct: vec![0x66; 48],
            }),
            author_key: [0x77; 32],
            signature: [0x88; 64],
        }
    }

    #[test]
    fn a_decision_round_trips_both_ways() {
        for approve in [true, false] {
            let d = decision(approve);
            assert_eq!(decode_decision(&encode_decision(&d).unwrap()).unwrap(), d);
        }
    }

    /// APPROVAL WITHOUT A SHARE AND DENIAL WITH A SHARE ARE BOTH REJECTED.
    ///
    /// The first is a promise without delivery: the recipient would see "approved" but could not
    /// open the file. The second is worse: issuance disguised as denial;
    /// the author thinks access was denied, yet the share was sent.
    #[test]
    fn approval_without_a_share_and_refusal_with_one_are_both_refused() {
        let mut d = decision(true);
        d.share_b = None;
        assert!(decode_decision(&encode_decision(&d).unwrap()).is_err(), "одобрение без доли");

        let mut d = decision(false);
        d.share_b = Some(Blob { enc: vec![1; 32], nonce: [2; 24], ct: vec![3; 48] });
        assert!(decode_decision(&encode_decision(&d).unwrap()).is_err(), "отказ с долей");
    }

    /// THE APPROVAL FLAG IS EXACTLY 0 OR 1, NOTHING IN BETWEEN.
    ///
    /// Before 2026-09-20 it was read as "nonzero byte": a decision with byte 5
    /// parsed as approval and re-encoded as one, so two different
    /// byte sequences meant the same thing (I-7). This test specifically catches
    /// returning to that interpretation; `is_err()` is insufficient here, so
    /// the rejection CODE is checked too.
    #[test]
    fn the_approval_flag_is_exactly_zero_or_one() {
        // Смещение байта одобрения ищется по заголовку поля: тег 8, длина 1.
        // Считать его руками нельзя — перед ним стоят поля переменной длины.
        let head = {
            let mut h = Vec::with_capacity(6);
            h.extend_from_slice(&tag::APPROVE.to_le_bytes());
            h.extend_from_slice(&1u32.to_le_bytes());
            h
        };
        let bytes = encode_decision(&decision(true)).unwrap();
        let at = bytes
            .windows(head.len())
            .position(|w| w == head.as_slice())
            .and_then(|p| p.checked_add(head.len()))
            .expect("поле одобрения на месте");

        for good in [0u8, 1] {
            let mut forged = bytes.clone();
            *forged.get_mut(at).expect("смещение внутри документа") = good;
            let parsed = decode_decision(&forged);
            // Ноль здесь — отказ с долей, и он отвергается ДРУГОЙ проверкой:
            // важно, что не проверкой области значения.
            match (good, parsed) {
                (1, Ok(d)) => assert!(d.approve, "единица прочитана не как одобрение"),
                (0, Err(FormatError::BadFieldLength { tag: tag::CT, .. })) => {}
                (_, other) => panic!("законный байт {good} дал {other:?}"),
            }
        }

        for bad in [2u8, 5, 255] {
            let mut forged = bytes.clone();
            *forged.get_mut(at).expect("смещение внутри документа") = bad;
            match decode_decision(&forged) {
                Err(FormatError::BadFieldLength { tag, len }) => {
                    assert_eq!(tag, tag::APPROVE, "отказ назвал не то поле");
                    assert_eq!(len, 1);
                }
                other => panic!("байт одобрения {bad} принят: {other:?}"),
            }
        }
    }

    /// THE SIGNATURE COVERS THE SHARE, NOT ONLY THE WORD "APPROVED".
    ///
    /// Otherwise an intermediary could replace the share while keeping approval, and the recipient would open
    /// the wrong file, or fail to open it and blame the author.
    #[test]
    fn the_signed_body_changes_when_the_share_changes() {
        let a = decision(true);
        let mut b = a.clone();
        b.share_b = Some(Blob { enc: vec![0x99; 32], nonce: [0x55; 24], ct: vec![0x66; 48] });
        assert_ne!(decision_body(&a).unwrap(), decision_body(&b).unwrap());

        // И на отпечаток устройства тоже: одобрение нельзя переадресовать.
        let mut c = a.clone();
        c.device_fpr = [0x23; 32];
        assert_ne!(decision_body(&a).unwrap(), decision_body(&c).unwrap());
    }
}
