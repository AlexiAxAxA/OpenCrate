// SPDX-License-Identifier: MPL-2.0
//! Agent grants and delegation chains.
//!
//! A grant binds a door, subtree, expiry, and delegation depth. The door uses an
//! agreement key for sealed shares and a separate Ed25519 key for delegations;
//! the author's grant authenticates the latter as `door_verify`.
//!
//! Signatures cover `signature(64) ‖ body` layouts and verify raw body bytes before
//! TLV parsing. The caller supplies the trusted author key from the container or
//! registered file record; a key embedded in the submitted grant cannot establish
//! its own authority.

use oc_format::FormatError;
use oc_format::tlv::{TlvReader, TlvWriter};
use oc_policy::Policy;

use crate::access::Blob;

/// Signature length at the document start, as for leases ([`crate::lease::SIGNATURE_LEN`]).
///
/// The signature deliberately precedes the body: its length is fixed, so the reader reaches
/// it without parsing any body bytes.
pub const SIGNATURE_LEN: usize = 64;

/// Maximum files in one grant.
///
/// The limit is needed because a FOREIGN party supplies the list length; without it,
/// "parse the grant" would mean "allocate as many entries as the peer
/// asks for". Two hundred fifty-six is a subtree a person can
/// authorize in one decision; a larger tree is split into several grants,
/// more honestly than one grant whose contents the author can no longer assess.
pub const MAX_GRANT_FILES: usize = 256;

/// Maximum delegation depth a grant may allow.
///
/// The cap belongs to the FORMAT, not just the server; this is not duplication: chain
/// length is the length of a list the verifier must traverse, and clients
/// also traverse it. Four links is the limit beyond which the person issuing the grant
/// can no longer picture who has access.
pub const MAX_GRANT_DEPTH: u8 = 4;

/// The only key-agreement mechanism stage 1 EXECUTES for a door.
///
/// Door keys are ephemeral and reside in process memory; TPM is not involved,
/// and the door has no post-quantum half. Parsing a number and being able to execute it
/// are different things (CLAUDE.md, "How to change the format", rule 4), so another number
/// is rejected DURING PARSING, not on the first attempt to unseal a share.
const DOOR_KEM_X25519: u8 = 1;

/// Grant tag registry. Strictly ascending; criticality by range (I-7).
///
/// Numbers are normative: raw body bytes are signed, so an implementation
/// numbering fields differently would produce another signature and silently diverge.
pub mod tag {
    /// Grant name, referenced by revocation and delegations. `bytes[16]`.
    pub const GRANT_ID: u16 = 1;
    /// Fingerprint of the door's key-agreement public key. `bytes[32]`.
    pub const DOOR_FPR: u16 = 2;
    /// Door key-agreement mechanism. `u8`.
    pub const DOOR_KEM: u16 = 3;
    /// Door key-agreement public key, to which shares B are sealed.
    pub const DOOR_PUBLIC: u16 = 4;
    /// Door Ed25519 key, used to sign delegations. `bytes[32]`.
    pub const DOOR_VERIFY: u16 = 5;
    /// List of `(file_id, share B)`, nested TLV numbered by position.
    pub const ENTRIES: u16 = 6;
    /// Issuance time. `i64le`, seconds.
    pub const ISSUED_AT: u16 = 7;
    /// Expiration time. `i64le`, seconds.
    pub const EXPIRES_AT: u16 = 8;
    /// Policy restriction using `policy_codec`. Optional: absence means
    /// the grant adds no restrictions.
    pub const TIGHTENING: u16 = 9;
    /// Delegation depth limit. `u8`; 0 forbids delegation.
    pub const MAX_DEPTH: u16 = 10;
    /// Author key signing the grant. `bytes[32]`.
    pub const AUTHOR_KEY: u16 = 11;
}

/// Delegation tag registry, separate from the grant's.
///
/// A shared registry would save a dozen lines at a high cost: the documents have
/// different field sets, and a tag meaning "author key" in one and
/// "depth" in the other invites confusion when reading.
pub mod link_tag {
    /// Chain root. `bytes[16]`.
    pub const GRANT_ID: u16 = 1;
    /// Who delegates. `bytes[32]`.
    pub const PARENT_FPR: u16 = 2;
    /// Descendant door fingerprint. `bytes[32]`.
    pub const CHILD_FPR: u16 = 3;
    /// Descendant key-agreement mechanism. `u8`.
    pub const CHILD_KEM: u16 = 4;
    /// Descendant key-agreement public key.
    pub const CHILD_PUBLIC: u16 = 5;
    /// Descendant Ed25519 key. `bytes[32]`.
    pub const CHILD_VERIFY: u16 = 6;
    /// Subset of the parent's list; shares resealed to the descendant key.
    pub const ENTRIES: u16 = 7;
    /// Expiration time. `i64le`, seconds.
    pub const EXPIRES_AT: u16 = 8;
    /// Policy restriction using the same codec.
    pub const TIGHTENING: u16 = 9;
    /// Further links allowed BELOW this one. `u8`.
    pub const DEPTH: u16 = 10;
    /// Descendant action list: a SUBSET of the parent's rules
    /// (`oc_protocol::action::ActionRule`, Agent Protocol, stage 2).
    ///
    /// The tag is OPTIONAL (> `0x7FFF`), a requirement rather than decoration:
    /// a stage 1 reader must skip it and verify the FILE
    /// chain exactly as before (I-7). An absent field and an empty list both mean
    /// "no actions delegated to the descendant"; this default is DENIAL (I-10).
    ///
    /// The codec is the same as the action grant rule list (`action::encode_rules`):
    /// a second representation of the same meaning would diverge from the first upon the very
    /// first new line.
    pub const ACTIONS: u16 = 0x8001;
}

/// Tags for ONE file-list entry.
mod entry_tag {
    pub const FILE_ID: u16 = 1;
    pub const ENC: u16 = 2;
    pub const NONCE: u16 = 3;
    pub const CT: u16 = 4;
}

/// One grant file: its name and share B, sealed to the holder's key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub file_id: [u8; 16],
    /// The same sealed-block shape as a slot and the server share.
    pub share_b: Blob,
}

/// An agent grant, signed by the author.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentGrant {
    pub grant_id: [u8; 16],
    /// `fpr == device_fpr(kem, public)` is checked in constant time during
    /// parsing (K27): the triple `(fpr, kem, public)` comes from a foreign party;
    /// an intermediary supplying someone else's fingerprint with its own key would receive the share
    /// under someone else's name, sealed to its own key.
    pub door_fpr: [u8; 32],
    pub door_kem: u8,
    pub door_public: Vec<u8>,
    pub door_verify: [u8; 32],
    /// Ascending `file_id`, no duplicates. Ordering is normative: it gives
    /// "the same file set" one byte sequence rather than many.
    pub entries: Vec<Entry>,
    pub issued_at: i64,
    pub expires_at: i64,
    /// Policy restriction; `None` means "no additional restrictions".
    ///
    /// The codec is THE SAME as the server policy in leases and author policy in
    /// headers (`oc_format::policy_codec`): a second representation of the same
    /// meaning would diverge upon the first new line.
    pub tightening: Option<Policy>,
    pub max_depth: u8,
    pub author_key: [u8; 32],
    pub signature: [u8; SIGNATURE_LEN],
}

/// Grant bytes WITHOUT the signature: what is signed and verified.
///
/// A separate function because signer and verifier must construct
/// identical bytes. Two constructions would silently diverge, and the signature would cease
/// to mean what it promises.
///
/// # Errors
/// [`FormatError`] if the grant has a shape our reader would reject:
/// door name does not identify its key, unsupported mechanism, unsorted file list
/// or more than [`MAX_GRANT_FILES`] entries, depth exceeding
/// [`MAX_GRANT_DEPTH`], or expiration before issuance.
pub fn grant_body(grant: &AgentGrant) -> Result<Vec<u8>, FormatError> {
    // Форма проверяется НА ЗАПИСИ, а не только на чтении: наш писатель не должен
    // уметь произвести документ, который наш же читатель обязан отвергнуть, —
    // обнаружилось бы это у получателя, как «грант повреждён». Тот же приём, что
    // у `encode_known_slot` в заголовке.
    check_grant_shape(grant)?;

    // Порядок полей — ПО ВОЗРАСТАНИЮ ТЕГА, как требует И-7; `TlvWriter`
    // проверяет это сам.
    let mut w = TlvWriter::new();
    w.put(tag::GRANT_ID, &grant.grant_id)?;
    w.put(tag::DOOR_FPR, &grant.door_fpr)?;
    w.put(tag::DOOR_KEM, &[grant.door_kem])?;
    w.put(tag::DOOR_PUBLIC, &grant.door_public)?;
    w.put(tag::DOOR_VERIFY, &grant.door_verify)?;
    w.put(tag::ENTRIES, &encode_entries(&grant.entries)?)?;
    w.put(tag::ISSUED_AT, &grant.issued_at.to_le_bytes())?;
    w.put(tag::EXPIRES_AT, &grant.expires_at.to_le_bytes())?;
    if let Some(policy) = &grant.tightening {
        w.put(tag::TIGHTENING, &encode_tightening(policy)?)?;
    }
    w.put(tag::MAX_DEPTH, &[grant.max_depth])?;
    w.put(tag::AUTHOR_KEY, &grant.author_key)?;
    Ok(w.finish().to_vec())
}

/// Grant signature transcript.
///
/// Uses [`oc_crypto::Transcript`] rather than manual construction: its constructor REQUIRES
/// a label and inserts the separator. Hand-building bytes could omit
/// the label, placing grant and header signatures in the same domain.
#[must_use]
pub fn grant_transcript(body: &[u8]) -> oc_crypto::Transcript {
    let mut t = oc_crypto::Transcript::new(oc_crypto::label::AGENT_GRANT);
    t.field(body);
    t
}

/// Encode the complete grant: `signature(64) ‖ body`.
///
/// # Errors
/// [`FormatError`] if the body cannot be built; see [`grant_body`].
pub fn encode_grant(grant: &AgentGrant) -> Result<Vec<u8>, FormatError> {
    let body = grant_body(grant)?;
    let mut out = Vec::with_capacity(SIGNATURE_LEN.saturating_add(body.len()));
    out.extend_from_slice(&grant.signature);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Verify the author's signature, then parse: in this order only.
///
/// `bytes` is the complete document: `signature(64) ‖ body`. `author_key` comes from
/// the CALLER, obtained from the container header or the server's file
/// record, not the submitted document. The embedded key is compared with
/// the supplied key in constant time (I-13): it belongs to the signed body,
/// asserting "grant issued for this author", not serving as a source of truth.
///
/// # Errors
/// [`FormatError::BadHeaderSignature`] for a short document or a
/// failed signature; otherwise parsing and shape-validation errors.
pub fn decode_grant(bytes: &[u8], author_key: &[u8; 32]) -> Result<AgentGrant, FormatError> {
    let (signature, body) = split_signature(bytes)?;
    oc_crypto::sign::verify(author_key, &grant_transcript(body), &signature)
        .map_err(|_| FormatError::BadHeaderSignature)?;
    let mut grant = decode_grant_body(body)?;
    if !oc_crypto::digest_eq(&grant.author_key, author_key) {
        // Подпись СОШЛАСЬ, а имя автора внутри другое. Значит документ подписан
        // тем, кого он сам автором не называет: либо ключ подменён, либо грант
        // адресован другому дереву. Вариант ошибки тот, которым весь крейт
        // сообщает «значение вне области».
        return Err(FormatError::BadFieldLength { tag: tag::AUTHOR_KEY, len: 32 });
    }
    grant.signature = signature;
    Ok(grant)
}

/// Parse a grant body without verifying its signature.
///
/// The shape is checked, but every returned field is untrusted. Use the result
/// only to look up the verification key; call [`decode_grant`] before making
/// access decisions.
///
/// # Errors
/// [`FormatError`] for a short signature prefix or a malformed body.
pub fn peek_grant(bytes: &[u8]) -> Result<AgentGrant, FormatError> {
    let (signature, body) = split_signature(bytes)?;
    let mut grant = decode_grant_body(body)?;
    grant.signature = signature;
    Ok(grant)
}

/// Link body from signed bytes, WITHOUT signature verification.
///
/// The same rationale as [`peek_grant`], more directly here: the link's verification key
/// is the PARENT's `verify`, and the link itself names its parent
/// (`parent_fpr`). This field cannot be read without parsing the body.
///
/// # Errors
/// [`FormatError`] if bytes are shorter than the signature or the body cannot be parsed.
pub fn peek_delegation(bytes: &[u8]) -> Result<Delegation, FormatError> {
    let (signature, body) = split_signature(bytes)?;
    let mut link = decode_delegation_body(body)?;
    link.signature = signature;
    Ok(link)
}

fn decode_grant_body(body: &[u8]) -> Result<AgentGrant, FormatError> {
    let mut reader = TlvReader::new(body);
    let (mut grant_id, mut door_fpr, mut door_kem, mut door_public) = (None, None, None, None);
    let (mut door_verify, mut entries, mut issued_at, mut expires_at) = (None, None, None, None);
    let (mut tightening, mut max_depth, mut author_key) = (None, None, None);
    while let Some(f) = reader.next_field()? {
        match f.tag {
            tag::GRANT_ID => grant_id = Some(f.array::<16>()?),
            tag::DOOR_FPR => door_fpr = Some(f.array::<32>()?),
            tag::DOOR_KEM => door_kem = Some(f.u8()?),
            tag::DOOR_PUBLIC => door_public = Some(f.value.to_vec()),
            tag::DOOR_VERIFY => door_verify = Some(f.array::<32>()?),
            tag::ENTRIES => entries = Some(decode_entries(f.value, tag::ENTRIES)?),
            tag::ISSUED_AT => issued_at = Some(i64::from_le_bytes(f.array::<8>()?)),
            tag::EXPIRES_AT => expires_at = Some(i64::from_le_bytes(f.array::<8>()?)),
            tag::TIGHTENING => tightening = Some(decode_tightening(f.value)?),
            tag::MAX_DEPTH => max_depth = Some(f.u8()?),
            tag::AUTHOR_KEY => author_key = Some(f.array::<32>()?),
            // Общее правило крейта (И-7): критичный незнакомый тег — отказ,
            // необязательный — пропуск. Пропуск безопасен потому, что подпись
            // покрывает СЫРЫЕ байты тела: дописать тег по дороге третья сторона
            // не может, подпись перестанет сходиться.
            other => crate::unknown::refuse_if_critical(other)?,
        }
    }
    let grant = AgentGrant {
        grant_id: grant_id.ok_or(FormatError::MissingField { tag: tag::GRANT_ID })?,
        door_fpr: door_fpr.ok_or(FormatError::MissingField { tag: tag::DOOR_FPR })?,
        door_kem: door_kem.ok_or(FormatError::MissingField { tag: tag::DOOR_KEM })?,
        door_public: door_public.ok_or(FormatError::MissingField { tag: tag::DOOR_PUBLIC })?,
        door_verify: door_verify.ok_or(FormatError::MissingField { tag: tag::DOOR_VERIFY })?,
        entries: entries.ok_or(FormatError::MissingField { tag: tag::ENTRIES })?,
        issued_at: issued_at.ok_or(FormatError::MissingField { tag: tag::ISSUED_AT })?,
        expires_at: expires_at.ok_or(FormatError::MissingField { tag: tag::EXPIRES_AT })?,
        tightening,
        max_depth: max_depth.ok_or(FormatError::MissingField { tag: tag::MAX_DEPTH })?,
        author_key: author_key.ok_or(FormatError::MissingField { tag: tag::AUTHOR_KEY })?,
        // Подпись кладёт `decode_grant`: она лежит вне тела.
        signature: [0; SIGNATURE_LEN],
    };
    check_grant_shape(&grant)?;
    Ok(grant)
}

/// Shape checks shared by writing and reading.
///
/// One function, not two lists: divergence would create documents
/// we write but cannot read, or read but cannot write.
fn check_grant_shape(grant: &AgentGrant) -> Result<(), FormatError> {
    check_holder_name(
        &grant.door_fpr,
        grant.door_kem,
        &grant.door_public,
        tag::DOOR_KEM,
        tag::DOOR_FPR,
    )?;
    check_entries(&grant.entries, tag::ENTRIES)?;
    if grant.max_depth > MAX_GRANT_DEPTH {
        return Err(FormatError::BadFieldLength {
            tag: tag::MAX_DEPTH,
            len: grant.max_depth as usize,
        });
    }
    if grant.expires_at < grant.issued_at {
        // Срок, кончающийся раньше начала, не «уже истёк»: это документ, о
        // котором нельзя сказать, что он вообще когда-либо действовал, и
        // принимать его значит отдавать решение о сроке чужим часам.
        return Err(FormatError::BadFieldLength { tag: tag::EXPIRES_AT, len: 8 });
    }
    Ok(())
}

/// The holder name identifies the presented key: K27 for every
/// mechanism, BEFORE any use of `(fpr, kem, public)`.
fn check_holder_name(
    fpr: &[u8; 32],
    kem: u8,
    public: &[u8],
    kem_tag: u16,
    fpr_tag: u16,
) -> Result<(), FormatError> {
    if kem != DOOR_KEM_X25519 {
        // Отказ НА РАЗБОРЕ, а не при первой попытке распечатать долю: механизм,
        // которого дверь не исполняет, — это грант, который никогда не сработает,
        // и узнать об этом лучше здесь, чем посреди сессии агента.
        return Err(FormatError::BadFieldLength { tag: kem_tag, len: 1 });
    }
    let alg = oc_crypto::KemAlg::from_u8(kem)
        .map_err(|_| FormatError::BadFieldLength { tag: kem_tag, len: 1 })?;
    // Длина ключа проверяется по механизму ВНУТРИ `device_fpr` (И-8), поэтому
    // отдельной проверки длины здесь нет.
    let named = oc_crypto::kdf::device_fpr(alg, public)
        .map_err(|_| FormatError::BadFieldLength { tag: fpr_tag, len: public.len() })?;
    if !oc_crypto::digest_eq(fpr, &named) {
        return Err(FormatError::BadFieldLength { tag: fpr_tag, len: 32 });
    }
    Ok(())
}

/// File list: within the cap, strictly increasing by `file_id`.
fn check_entries(entries: &[Entry], list_tag: u16) -> Result<(), FormatError> {
    if entries.len() > MAX_GRANT_FILES {
        return Err(FormatError::BadFieldLength { tag: list_tag, len: entries.len() });
    }
    for (index, pair) in entries.windows(2).enumerate() {
        let (Some(a), Some(b)) = (pair.first(), pair.get(1)) else { continue };
        if a.file_id >= b.file_id {
            // Возрастание даёт бесплатно то же, что И-7 даёт тегам: дубликаты
            // невозможны, перестановка невозможна, и один набор файлов — одна
            // последовательность байтов. Номера записей здесь и есть их теги во
            // вложенном TLV, поэтому вариант ошибки тот же, каким сообщает о
            // порядке разборщик TLV.
            let previous = u16::try_from(index).unwrap_or(u16::MAX);
            let found = previous.saturating_add(1);
            return Err(FormatError::FieldsOutOfOrder { previous, found });
        }
    }
    Ok(())
}

/// List entries: nested TLV, tag = entry number.
///
/// Numbering by POSITION uses the same technique as header slots
/// (`oc-format`, entry 10). There is deliberately no separate entry count:
/// it would be a second source of truth for the number, potentially diverging from the body.
fn encode_entries(entries: &[Entry]) -> Result<Vec<u8>, FormatError> {
    let mut w = TlvWriter::new();
    for (index, entry) in entries.iter().enumerate() {
        let tag = u16::try_from(index).map_err(|_| FormatError::OffsetOverflow)?;
        let mut inner = TlvWriter::new();
        inner.put(entry_tag::FILE_ID, &entry.file_id)?;
        inner.put(entry_tag::ENC, &entry.share_b.enc)?;
        inner.put(entry_tag::NONCE, &entry.share_b.nonce)?;
        inner.put(entry_tag::CT, &entry.share_b.ct)?;
        let body = inner.finish().to_vec();
        w.put(tag, &body)?;
    }
    Ok(w.finish().to_vec())
}

fn decode_entries(bytes: &[u8], list_tag: u16) -> Result<Vec<Entry>, FormatError> {
    let mut reader = TlvReader::new(bytes);
    let mut out: Vec<Entry> = Vec::new();
    while let Some(field) = reader.next_field()? {
        // Потолок проверяется ВНУТРИ цикла, а не после него: длину списка
        // называет чужая сторона, и «разобрать всё, потом посчитать» означало бы
        // выделить столько, сколько скажет собеседник.
        if out.len() >= MAX_GRANT_FILES {
            return Err(FormatError::BadFieldLength { tag: list_tag, len: out.len() });
        }
        out.push(decode_entry(field.value)?);
    }
    check_entries(&out, list_tag)?;
    Ok(out)
}

fn decode_entry(bytes: &[u8]) -> Result<Entry, FormatError> {
    let mut reader = TlvReader::new(bytes);
    let (mut file_id, mut enc, mut nonce, mut ct) = (None, None, None, None);
    while let Some(f) = reader.next_field()? {
        match f.tag {
            entry_tag::FILE_ID => file_id = Some(f.array::<16>()?),
            entry_tag::ENC => enc = Some(f.value.to_vec()),
            entry_tag::NONCE => nonce = Some(f.array::<24>()?),
            entry_tag::CT => ct = Some(f.value.to_vec()),
            other => crate::unknown::refuse_if_critical(other)?,
        }
    }
    Ok(Entry {
        file_id: file_id.ok_or(FormatError::MissingField { tag: entry_tag::FILE_ID })?,
        share_b: Blob {
            enc: enc.ok_or(FormatError::MissingField { tag: entry_tag::ENC })?,
            nonce: nonce.ok_or(FormatError::MissingField { tag: entry_tag::NONCE })?,
            ct: ct.ok_or(FormatError::MissingField { tag: entry_tag::CT })?,
        },
    })
}

/// Restrictions use THE SAME codec as the server policy in a lease.
///
/// There must not be a second wire representation of policy: it would diverge upon the
/// first new line, while the policy hash is an interoperability surface.
fn encode_tightening(policy: &Policy) -> Result<Vec<u8>, FormatError> {
    oc_format::policy_codec::encode(oc_format::header::CONTAINER_VERSION, policy)
}

fn decode_tightening(bytes: &[u8]) -> Result<Policy, FormatError> {
    oc_format::policy_codec::decode(oc_format::header::SUPPORTED_READER_VERSION, bytes)
}

/// Delegation, signed with the PARENT's `door_verify` key.
///
/// A parent cannot grant more than it holds; this is enforced not by the parent
/// but by [`verify_grant_chain`]: the file list is a subset, expiration does not increase,
/// and depth decreases. The document holds only what the parent ASSERTS;
/// comparison with the parent's assertion is the chain's job.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegation {
    pub grant_id: [u8; 16],
    pub parent_fpr: [u8; 32],
    pub child_fpr: [u8; 32],
    pub child_kem: u8,
    pub child_public: Vec<u8>,
    pub child_verify: [u8; 32],
    /// Subset of the parent's list; shares resealed to the descendant key.
    pub entries: Vec<Entry>,
    pub expires_at: i64,
    pub tightening: Option<Policy>,
    /// Further links allowed BELOW this one.
    pub depth: u8,
    /// Actions passed to the descendant. An empty list means "none", which is
    /// the default: the tag is optional, and an absent rule means DENIAL.
    ///
    /// As with the file list, this holds only what the parent ASSERTS;
    /// comparison with the parent rule is the job of [`verify_grant_chain_with_actions`].
    pub actions: Vec<crate::action::ActionRule>,
    pub signature: [u8; SIGNATURE_LEN],
}

/// Delegation bytes WITHOUT the signature: what is signed and verified.
///
/// # Errors
/// [`FormatError`] if the link has a shape our own reader would reject.
pub fn delegation_body(link: &Delegation) -> Result<Vec<u8>, FormatError> {
    check_delegation_shape(link)?;

    let mut w = TlvWriter::new();
    w.put(link_tag::GRANT_ID, &link.grant_id)?;
    w.put(link_tag::PARENT_FPR, &link.parent_fpr)?;
    w.put(link_tag::CHILD_FPR, &link.child_fpr)?;
    w.put(link_tag::CHILD_KEM, &[link.child_kem])?;
    w.put(link_tag::CHILD_PUBLIC, &link.child_public)?;
    w.put(link_tag::CHILD_VERIFY, &link.child_verify)?;
    w.put(link_tag::ENTRIES, &encode_entries(&link.entries)?)?;
    w.put(link_tag::EXPIRES_AT, &link.expires_at.to_le_bytes())?;
    if let Some(policy) = &link.tightening {
        w.put(link_tag::TIGHTENING, &encode_tightening(policy)?)?;
    }
    w.put(link_tag::DEPTH, &[link.depth])?;
    // ПОСЛЕ глубины и только при непустом списке: теги идут строго по
    // возрастанию (И-7), а пустое значение и отсутствие поля здесь означают
    // одно и то же — писать его значило бы завести два представления одного
    // смысла, то есть две последовательности байтов на одно звено.
    if !link.actions.is_empty() {
        w.put(link_tag::ACTIONS, &crate::action::encode_rules(&link.actions)?)?;
    }
    Ok(w.finish().to_vec())
}

/// Delegation signature transcript.
///
/// A separate label, not [`oc_crypto::label::AGENT_GRANT`]: the author signs grants,
/// while the door signs delegations with its ephemeral key. If the domains matched,
/// a door receiving a grant could issue itself a new one with new depth and expiration.
#[must_use]
pub fn delegation_transcript(body: &[u8]) -> oc_crypto::Transcript {
    let mut t = oc_crypto::Transcript::new(oc_crypto::label::DELEGATION);
    t.field(body);
    t
}

/// Encode the complete delegation: `signature(64) ‖ body`.
///
/// # Errors
/// [`FormatError`] if the body cannot be built; see [`delegation_body`].
pub fn encode_delegation(link: &Delegation) -> Result<Vec<u8>, FormatError> {
    let body = delegation_body(link)?;
    let mut out = Vec::with_capacity(SIGNATURE_LEN.saturating_add(body.len()));
    out.extend_from_slice(&link.signature);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Verify the parent's signature, then parse: in this order only.
///
/// `parent_verify` is the PARENT's `verify` key supplied by the caller: for the first
/// link it is the grant's `door_verify`, for subsequent links the previous link's `child_verify`.
/// The document neither contains nor must contain this key; otherwise the link itself
/// would choose its verification key.
///
/// # Errors
/// [`FormatError::BadHeaderSignature`] for a short document or a
/// failed signature; otherwise parsing and shape-validation errors.
pub fn decode_delegation(
    bytes: &[u8],
    parent_verify: &[u8; 32],
) -> Result<Delegation, FormatError> {
    let (signature, body) = split_signature(bytes)?;
    oc_crypto::sign::verify(parent_verify, &delegation_transcript(body), &signature)
        .map_err(|_| FormatError::BadHeaderSignature)?;
    let mut link = decode_delegation_body(body)?;
    link.signature = signature;
    Ok(link)
}

fn decode_delegation_body(body: &[u8]) -> Result<Delegation, FormatError> {
    let mut reader = TlvReader::new(body);
    let (mut grant_id, mut parent_fpr, mut child_fpr, mut child_kem) = (None, None, None, None);
    let (mut child_public, mut child_verify, mut entries) = (None, None, None);
    let (mut expires_at, mut tightening, mut depth) = (None, None, None);
    let mut actions = Vec::new();
    while let Some(f) = reader.next_field()? {
        match f.tag {
            link_tag::GRANT_ID => grant_id = Some(f.array::<16>()?),
            link_tag::PARENT_FPR => parent_fpr = Some(f.array::<32>()?),
            link_tag::CHILD_FPR => child_fpr = Some(f.array::<32>()?),
            link_tag::CHILD_KEM => child_kem = Some(f.u8()?),
            link_tag::CHILD_PUBLIC => child_public = Some(f.value.to_vec()),
            link_tag::CHILD_VERIFY => child_verify = Some(f.array::<32>()?),
            link_tag::ENTRIES => entries = Some(decode_entries(f.value, link_tag::ENTRIES)?),
            link_tag::EXPIRES_AT => expires_at = Some(i64::from_le_bytes(f.array::<8>()?)),
            link_tag::TIGHTENING => tightening = Some(decode_tightening(f.value)?),
            link_tag::DEPTH => depth = Some(f.u8()?),
            // Тег необязательный, но ЗНАКОМЫЙ: раз мы его знаем — разбираем, и
            // мусор в нём отвергаем здесь, а не у сервера, где поздно. Читатель
            // первого этапа его не знает и пропускает (И-7), и цепочка файлов
            // от этого не меняется ничем.
            link_tag::ACTIONS => actions = crate::action::decode_rules(f.value)?,
            other => crate::unknown::refuse_if_critical(other)?,
        }
    }
    let link = Delegation {
        grant_id: grant_id.ok_or(FormatError::MissingField { tag: link_tag::GRANT_ID })?,
        parent_fpr: parent_fpr.ok_or(FormatError::MissingField { tag: link_tag::PARENT_FPR })?,
        child_fpr: child_fpr.ok_or(FormatError::MissingField { tag: link_tag::CHILD_FPR })?,
        child_kem: child_kem.ok_or(FormatError::MissingField { tag: link_tag::CHILD_KEM })?,
        child_public: child_public
            .ok_or(FormatError::MissingField { tag: link_tag::CHILD_PUBLIC })?,
        child_verify: child_verify
            .ok_or(FormatError::MissingField { tag: link_tag::CHILD_VERIFY })?,
        entries: entries.ok_or(FormatError::MissingField { tag: link_tag::ENTRIES })?,
        expires_at: expires_at.ok_or(FormatError::MissingField { tag: link_tag::EXPIRES_AT })?,
        tightening,
        depth: depth.ok_or(FormatError::MissingField { tag: link_tag::DEPTH })?,
        actions,
        signature: [0; SIGNATURE_LEN],
    };
    check_delegation_shape(&link)?;
    Ok(link)
}

fn check_delegation_shape(link: &Delegation) -> Result<(), FormatError> {
    check_holder_name(
        &link.child_fpr,
        link.child_kem,
        &link.child_public,
        link_tag::CHILD_KEM,
        link_tag::CHILD_FPR,
    )?;
    check_entries(&link.entries, link_tag::ENTRIES)?;
    if link.depth > MAX_GRANT_DEPTH {
        return Err(FormatError::BadFieldLength {
            tag: link_tag::DEPTH,
            len: link.depth as usize,
        });
    }
    if link.actions.len() > crate::action::MAX_ACTION_RULES {
        return Err(FormatError::BadFieldLength {
            tag: link_tag::ACTIONS,
            len: link.actions.len(),
        });
    }
    for rule in &link.actions {
        // Форма правила проверяется и здесь: наш писатель не должен уметь
        // произвести звено, которое наш же читатель обязан отвергнуть.
        crate::action::check_rule_shape(rule)?;
    }
    Ok(())
}

/// Verified access facts for the final link.
///
/// The caller must intersect all returned policies using `oc_policy::intersect`;
/// an extra restriction must never loosen an ancestor's permissions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainFacts {
    pub grant_id: [u8; 16],
    pub holder_fpr: [u8; 32],
    pub holder_verify: [u8; 32],
    pub files: Vec<[u8; 16]>,
    pub expires_at: i64,
    /// All chain restrictions from the root onward. The caller intersects them.
    pub tightening: Vec<Policy>,
    pub depth_left: u8,
    /// Actions permitted for the LAST link.
    ///
    /// Empty if the caller supplied no action grant: a rule with nothing to
    /// verify against is ineffective (I-10). Thus the old
    /// [`verify_grant_chain`] call returns an empty list even when chain links
    /// carry action tags; this is the default denial, not data loss.
    pub actions: Vec<crate::action::ActionRule>,
}

/// Why the chain was rejected.
///
/// A separate error type rather than a [`FormatError`] variant: a chain break concerns
/// the RELATIONSHIP between links, not a TLV field, so has no tag number. The link
/// number is included because both sides show the reason to people, and "chain
/// failed" without the break location says nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainRefusal {
    /// The grant could not be parsed, was not signed by this author or has invalid shape.
    BadGrant,
    /// The link could not be parsed or was not signed by the parent key.
    BadLink { index: usize },
    /// The link names a file absent from its parent.
    NotASubset { index: usize },
    /// The link outlives its parent.
    OutlivesParent { index: usize },
    /// Further delegation is forbidden: depth exhausted.
    DepthExhausted { index: usize },
    /// The link names a different parent or root.
    WrongParent { index: usize },
    /// Expired according to the supplied clock.
    Expired,
    /// Not yet valid according to the supplied clock.
    NotYetValid,
    /// The ACTION grant could not be parsed, was not signed by this author or has invalid shape.
    BadActionGrant,
    /// The action grant is bound to another file grant.
    ActionsWrongGrant,
    /// The action grant outlives the file grant to which it is bound.
    ActionsOutliveGrant,
    /// The link takes an action kind the parent does not hold.
    ActionNotGranted { index: usize },
    /// The link broadens a parent rule. Reason comes from `action`.
    ActionWidens { index: usize, why: crate::action::ActionRefusal },
}

impl core::fmt::Display for ChainRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadGrant => f.write_str("грант не принят: подпись автора не сошлась или документ не той формы"),
            Self::BadLink { index } => {
                write!(f, "звено {index} не принято: подпись родителя не сошлась или документ не той формы")
            }
            Self::NotASubset { index } => {
                write!(f, "звено {index} называет файл, которого нет у родителя")
            }
            Self::OutlivesParent { index } => write!(f, "звено {index} живёт дольше родителя"),
            Self::DepthExhausted { index } => {
                write!(f, "звено {index} лишнее: глубина делегирования исчерпана")
            }
            Self::WrongParent { index } => {
                write!(f, "звено {index} называет другого родителя или другой грант")
            }
            Self::Expired => f.write_str("срок гранта или звена уже истёк"),
            Self::NotYetValid => f.write_str("срок гранта ещё не начался"),
            Self::BadActionGrant => f.write_str(
                "грант действий не принят: подпись автора не сошлась или документ не той формы",
            ),
            Self::ActionsWrongGrant => {
                f.write_str("грант действий привязан к другому файловому гранту")
            }
            Self::ActionsOutliveGrant => {
                f.write_str("грант действий живёт дольше файлового гранта, к которому привязан")
            }
            Self::ActionNotGranted { index } => {
                write!(f, "звено {index} берёт вид действия, которого нет у родителя")
            }
            Self::ActionWidens { index, why } => {
                write!(f, "звено {index} расширяет правило действия: {why}")
            }
        }
    }
}

/// Verify the chain: grant, then links in order. Clock supplied as a PARAMETER.
///
/// `grant` and `links` are RAW bytes: signatures are verified here, each before
/// its body is parsed. Each link's verification key comes from its predecessor;
/// the first comes from the grant, whose key comes from outside,
/// from the container header.
///
/// Clock as a parameter, not from the system: expiration and time-travel tests
/// must be DATA; otherwise they test the machine clock rather than the rule.
///
/// # Errors
/// [`ChainRefusal`] with the link number where the chain broke.
pub fn verify_grant_chain(
    author_key: &[u8; 32],
    grant: &[u8],
    links: &[&[u8]],
    now: i64,
) -> Result<ChainFacts, ChainRefusal> {
    verify_grant_chain_with_actions(author_key, grant, links, None, now)
}

/// Verify a grant chain with an optional action grant.
///
/// `actions` contains raw [`crate::action::ActionGrant`] bytes signed by the
/// same externally supplied author key as the file grant.
/// With `None`, the result has no action rules, even if links contain action
/// tags: those restrictions cannot be verified without the root action grant.
///
/// # Errors
/// [`ChainRefusal`] identifies the link where verification failed.
pub fn verify_grant_chain_with_actions(
    author_key: &[u8; 32],
    grant: &[u8],
    links: &[&[u8]],
    actions: Option<&[u8]>,
    now: i64,
) -> Result<ChainFacts, ChainRefusal> {
    let grant = decode_grant(grant, author_key).map_err(|_| ChainRefusal::BadGrant)?;
    if now < grant.issued_at {
        return Err(ChainRefusal::NotYetValid);
    }
    if now > grant.expires_at {
        return Err(ChainRefusal::Expired);
    }

    // Грант действий разбирается ЗДЕСЬ, до обхода звеньев: его правила — корень
    // сужения, и звено, проверенное против пустого корня, прошло бы всё.
    let root_actions = match actions {
        None => Vec::new(),
        Some(bytes) => {
            let signed = crate::action::decode_grant(bytes, author_key)
                .map_err(|_| ChainRefusal::BadActionGrant)?;
            if signed.grant_id != grant.grant_id {
                // Привязка к ФАЙЛОВОМУ гранту и есть якорь: держатель, потолок
                // срока и погашение берутся оттуда. Грант действий с чужим
                // корнем — это права, выписанные другой двери.
                return Err(ChainRefusal::ActionsWrongGrant);
            }
            if signed.expires_at > grant.expires_at {
                // Проверка стоит здесь, а не только на сервере при
                // `PutActionGrant`: эта функция — единственное место, которое
                // видит ОБА документа сразу, и правило «срок не длиннее»
                // исполнимо только там, где есть с чем сравнивать.
                return Err(ChainRefusal::ActionsOutliveGrant);
            }
            if now < signed.issued_at {
                return Err(ChainRefusal::NotYetValid);
            }
            if now > signed.expires_at {
                return Err(ChainRefusal::Expired);
            }
            signed.rules
        }
    };

    let mut facts = ChainFacts {
        grant_id: grant.grant_id,
        holder_fpr: grant.door_fpr,
        holder_verify: grant.door_verify,
        files: grant.entries.iter().map(|entry| entry.file_id).collect(),
        expires_at: grant.expires_at,
        tightening: grant.tightening.into_iter().collect(),
        depth_left: grant.max_depth,
        actions: root_actions,
    };

    for (index, raw) in links.iter().enumerate() {
        // Подпись — ключом ПРЕДЫДУЩЕГО держателя, и проверяется она внутри
        // `decode_delegation`, то есть до разбора тела звена.
        let link = decode_delegation(raw, &facts.holder_verify)
            .map_err(|_| ChainRefusal::BadLink { index })?;

        // Звено обязано быть звеном ЭТОЙ цепочки: тот же корень и тот родитель,
        // чьим ключом оно подписано. Второе не следует из первого — ключ подписи
        // и согласовательный ключ у двери разные, и без сверки отпечатка звено
        // могло бы называть родителем кого угодно, оставаясь подписанным верно.
        if link.grant_id != facts.grant_id
            || !oc_crypto::digest_eq(&link.parent_fpr, &facts.holder_fpr)
        {
            return Err(ChainRefusal::WrongParent { index });
        }

        // Глубина: у родителя должно остаться хотя бы одно звено, и потомку
        // достаётся строго меньше. «Не больше» здесь недостаточно — цепочка
        // из звеньев одной глубины не кончалась бы никогда.
        if facts.depth_left == 0 || link.depth >= facts.depth_left {
            return Err(ChainRefusal::DepthExhausted { index });
        }

        if !link.entries.iter().all(|entry| facts.files.contains(&entry.file_id)) {
            return Err(ChainRefusal::NotASubset { index });
        }

        if link.expires_at > facts.expires_at {
            return Err(ChainRefusal::OutlivesParent { index });
        }
        if now > link.expires_at {
            return Err(ChainRefusal::Expired);
        }

        // Действия сужаются ровно как файлы: каждое правило потомка обязано
        // найти у родителя правило ТОГО ЖЕ ВИДА, которое оно не расширяет.
        // Считается это ДО присвоения новых фактов — иначе потомок сверялся бы
        // сам с собой.
        //
        // Когда грант действий не передан, список родителя пуст, и звено с
        // непустым тегом действий сюда не доходит вовсе: `narrow_actions`
        // зовётся только при известном корне. Так читатель первого этапа и
        // получает прежние факты на цепочке с тегом.
        facts.actions = if actions.is_some() {
            narrow_actions(&facts.actions, &link.actions, index)?
        } else {
            Vec::new()
        };

        facts.holder_fpr = link.child_fpr;
        facts.holder_verify = link.child_verify;
        facts.files = link.entries.iter().map(|entry| entry.file_id).collect();
        facts.expires_at = link.expires_at;
        facts.depth_left = link.depth;
        if let Some(policy) = link.tightening {
            facts.tightening.push(policy);
        }
    }

    Ok(facts)
}

/// Check that each child rule narrows at least one parent rule of the same kind.
///
/// Multiple parent rules may cover different subtrees; their order does not
/// determine authorization. If none permits the child, report the first
/// matching rule's constraint, or [`ChainRefusal::ActionNotGranted`] when
/// no parent rule has that kind.
fn narrow_actions(
    parents: &[crate::action::ActionRule],
    children: &[crate::action::ActionRule],
    index: usize,
) -> Result<Vec<crate::action::ActionRule>, ChainRefusal> {
    for child in children {
        let mut same_kind = parents.iter().filter(|p| p.kind == child.kind).peekable();
        if same_kind.peek().is_none() {
            return Err(ChainRefusal::ActionNotGranted { index });
        }
        let mut first_reason = None;
        let mut accepted = false;
        for parent in same_kind {
            match crate::action::narrower(child, parent) {
                Ok(()) => {
                    accepted = true;
                    break;
                }
                Err(why) => {
                    if first_reason.is_none() {
                        first_reason = Some(why);
                    }
                }
            }
        }
        if !accepted {
            let why = first_reason.unwrap_or(crate::action::ActionRefusal::WrongKind);
            return Err(ChainRefusal::ActionWidens { index, why });
        }
    }
    Ok(children.to_vec())
}

fn split_signature(bytes: &[u8]) -> Result<([u8; SIGNATURE_LEN], &[u8]), FormatError> {
    let (signature, body) =
        bytes.split_at_checked(SIGNATURE_LEN).ok_or(FormatError::BadHeaderSignature)?;
    let signature: [u8; SIGNATURE_LEN] =
        signature.try_into().map_err(|_| FormatError::BadHeaderSignature)?;
    Ok((signature, body))
}

#[cfg(test)]
// Тестам позволено разворачивать `Option`, падать с сообщением, индексировать и
// считать без проверки переполнения: проверяемый код на этих путях не
// исполняется, а выход за границы уронил бы тест, и уронил бы громко.
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use oc_crypto::sign::{Ed25519Signer, Signer as _};

    fn author() -> Ed25519Signer {
        Ed25519Signer::from_seed(&[0xa1; 32])
    }

    fn stranger() -> Ed25519Signer {
        Ed25519Signer::from_seed(&[0x77; 32])
    }

    /// Door SIGNING key, used to authenticate delegations.
    fn door() -> Ed25519Signer {
        Ed25519Signer::from_seed(&[0xd0; 32])
    }

    /// Door key-agreement public key. For X25519, the fingerprint IS the key (K27),
    /// so `door_fpr` matches it byte for byte.
    const DOOR_PUBLIC: [u8; 32] = [0xd1; 32];

    fn blob(seed: u8) -> Blob {
        Blob { enc: vec![seed; 32], nonce: [seed; 24], ct: vec![seed; 48] }
    }

    fn file_id(n: u16) -> [u8; 16] {
        let mut id = [0u8; 16];
        id[0] = (n >> 8) as u8;
        id[1] = n as u8;
        id
    }

    fn grant() -> AgentGrant {
        let mut g = AgentGrant {
            grant_id: [0x67; 16],
            door_fpr: DOOR_PUBLIC,
            door_kem: 1,
            door_public: DOOR_PUBLIC.to_vec(),
            door_verify: door().public_key(),
            entries: vec![
                Entry { file_id: file_id(1), share_b: blob(0x11) },
                Entry { file_id: file_id(2), share_b: blob(0x22) },
            ],
            issued_at: 1_700_000_000,
            expires_at: 1_700_086_400,
            tightening: None,
            max_depth: 2,
            author_key: author().public_key(),
            signature: [0; SIGNATURE_LEN],
        };
        sign_grant(&mut g, &author());
        g
    }

    fn sign_grant(g: &mut AgentGrant, signer: &Ed25519Signer) {
        let body = grant_body(g).expect("тело гранта собирается");
        g.signature = signer.sign(&grant_transcript(&body)).unwrap();
    }

    /// Body fields as "tag, value" pairs, for manual reconstruction.
    fn fields_of(body: &[u8]) -> Vec<(u16, Vec<u8>)> {
        let mut reader = TlvReader::new(body);
        let mut out = Vec::new();
        while let Some(f) = reader.next_field().unwrap() {
            out.push((f.tag, f.value.to_vec()));
        }
        out
    }

    /// Rebuild a body, replacing one tag's value, to obtain
    /// a document our writer refuses to produce; otherwise
    /// reader checks would remain untested.
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

    /// Rebuild a body, ADDING a tag (at the end to preserve ordering).
    fn rebuild_plus(body: &[u8], tag: u16, value: &[u8]) -> Vec<u8> {
        let mut w = TlvWriter::new();
        for (t, v) in fields_of(body) {
            w.put(t, &v).unwrap();
        }
        w.put(tag, value).unwrap();
        w.finish().to_vec()
    }

    /// Document from a ready-made body, signed with the named key.
    fn signed(body: &[u8], signer: &Ed25519Signer) -> Vec<u8> {
        let sig = signer.sign(&grant_transcript(body)).unwrap();
        let mut out = sig.to_vec();
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn grant_round_trips() {
        let g = grant();
        let bytes = encode_grant(&g).unwrap();
        assert_eq!(decode_grant(&bytes, &author().public_key()).unwrap(), g);
    }

    /// Restrictions use THE SAME codec as the server policy in a lease.
    ///
    /// This test accompanied the decision to store `Policy` in the structure rather than
    /// opaque bytes: unchecked bytes would let a grant with garbage in this
    /// field reach the server, where rejecting the restriction is already too late.
    #[test]
    fn a_tightening_policy_round_trips_through_the_same_codec() {
        let mut g = grant();
        let mut policy = Policy::no_tightening();
        policy.max_opens = Some(3);
        g.tightening = Some(policy.clone());
        sign_grant(&mut g, &author());

        let bytes = encode_grant(&g).unwrap();
        let back = decode_grant(&bytes, &author().public_key()).unwrap();
        assert_eq!(back.tightening, Some(policy));
        assert_eq!(back, g);
    }

    /// THE SIGNATURE IS VERIFIED BEFORE BODY PARSING.
    ///
    /// The body is deliberately UNPARSEABLE; two runs distinguish
    /// ordering: a WRONG signature must yield a signature error, a CORRECT one
    /// a parsing error. One run would not show this: `is_err()` is true for both
    /// orders.
    #[test]
    fn a_flipped_body_byte_fails_the_signature_before_parsing() {
        let good = grant_body(&grant()).unwrap();

        // Портится байт ВНУТРИ TLV так, чтобы разбор тоже упал: номер механизма
        // становится неисполнимым.
        let broken_kem = rebuild_with(&good, tag::DOOR_KEM, &[0x63]);
        // И второй способ быть неразбираемым — незнакомый критичный тег.
        let unknown_critical = rebuild_plus(&good, 0x7FFF, &[0xab; 4]);

        for (what, body) in
            [("неисполнимый механизм", broken_kem), ("чужой критичный тег", unknown_critical)]
        {
            // Предпосылка: своя подпись — и ответ РАЗБОРНЫЙ.
            let own = signed(&body, &author());
            let parsed = decode_grant(&own, &author().public_key());
            assert!(
                matches!(parsed, Err(FormatError::BadFieldLength { .. } | FormatError::UnknownCriticalField { .. })),
                "{what}: предпосылка неверна, тело разбирается: {parsed:?}"
            );

            // А теперь подпись настоящая, но ЧУЖАЯ: подделать документ противник
            // умеет, подписать ключом автора — нет.
            let forged = signed(&body, &stranger());
            let outcome = decode_grant(&forged, &author().public_key());
            assert!(
                matches!(outcome, Err(FormatError::BadHeaderSignature)),
                "{what}: разбор произошёл до проверки подписи, ответ {outcome:?}"
            );
        }
    }

    #[test]
    fn a_grant_signed_by_another_author_is_refused() {
        let mut g = grant();
        sign_grant(&mut g, &stranger());
        let bytes = encode_grant(&g).unwrap();
        assert!(matches!(
            decode_grant(&bytes, &author().public_key()),
            Err(FormatError::BadHeaderSignature)
        ));
    }

    /// THE EMBEDDED KEY MUST MATCH THE SUPPLIED KEY.
    ///
    /// The signature here VERIFIES: the real author signed the document, but it names
    /// another author. Without the comparison, a grant issued for one tree could be
    /// accepted for another; `is_err()` with a wrong signature cannot catch this,
    /// because the signature is not wrong.
    #[test]
    fn the_author_key_inside_must_match_the_one_supplied() {
        let mut g = grant();
        g.author_key = [0x99; 32];
        sign_grant(&mut g, &author());
        let bytes = encode_grant(&g).unwrap();
        match decode_grant(&bytes, &author().public_key()) {
            Err(FormatError::BadFieldLength { tag, .. }) => assert_eq!(tag, tag::AUTHOR_KEY),
            other => panic!("грант с чужим именем автора принят: {other:?}"),
        }
    }

    #[test]
    fn entries_out_of_order_or_repeated_are_refused() {
        let ordered = grant();

        for (what, entries) in [
            (
                "перестановка",
                vec![
                    Entry { file_id: file_id(2), share_b: blob(0x22) },
                    Entry { file_id: file_id(1), share_b: blob(0x11) },
                ],
            ),
            (
                "повтор",
                vec![
                    Entry { file_id: file_id(1), share_b: blob(0x11) },
                    Entry { file_id: file_id(1), share_b: blob(0x22) },
                ],
            ),
        ] {
            // Писатель отказывается сам.
            let mut g = ordered.clone();
            g.entries = entries.clone();
            assert!(grant_body(&g).is_err(), "{what}: писатель произвёл такой грант");

            // И читатель — по документу, собранному в обход писателя.
            let body = rebuild_with(
                &grant_body(&ordered).unwrap(),
                tag::ENTRIES,
                &encode_entries(&entries).unwrap(),
            );
            let outcome = decode_grant(&signed(&body, &author()), &author().public_key());
            assert!(
                matches!(outcome, Err(FormatError::FieldsOutOfOrder { .. })),
                "{what}: читатель принял, ответ {outcome:?}"
            );
        }
    }

    #[test]
    fn more_than_max_files_is_refused() {
        let ordered = grant();
        let many: Vec<Entry> = (0..=MAX_GRANT_FILES)
            .map(|n| Entry {
                file_id: file_id(u16::try_from(n).unwrap()),
                share_b: blob(0x33),
            })
            .collect();
        assert_eq!(many.len(), MAX_GRANT_FILES + 1);

        let mut g = ordered.clone();
        g.entries = many.clone();
        assert!(grant_body(&g).is_err(), "писатель выпустил грант длиннее потолка");

        let body = rebuild_with(
            &grant_body(&ordered).unwrap(),
            tag::ENTRIES,
            &encode_entries(&many).unwrap(),
        );
        let outcome = decode_grant(&signed(&body, &author()), &author().public_key());
        assert!(
            matches!(outcome, Err(FormatError::BadFieldLength { tag: tag::ENTRIES, .. })),
            "список длиннее потолка принят: {outcome:?}"
        );
    }

    #[test]
    fn depth_above_max_is_refused() {
        let ordered = grant();
        let mut g = ordered.clone();
        g.max_depth = MAX_GRANT_DEPTH + 1;
        assert!(grant_body(&g).is_err(), "писатель выпустил грант с глубиной выше потолка");

        let body = rebuild_with(
            &grant_body(&ordered).unwrap(),
            tag::MAX_DEPTH,
            &[MAX_GRANT_DEPTH + 1],
        );
        let outcome = decode_grant(&signed(&body, &author()), &author().public_key());
        assert!(
            matches!(outcome, Err(FormatError::BadFieldLength { tag: tag::MAX_DEPTH, .. })),
            "глубина выше потолка принята: {outcome:?}"
        );
    }

    /// THE FINGERPRINT MUST IDENTIFY THE PRESENTED KEY (K27).
    ///
    /// Otherwise an intermediary supplies someone else's fingerprint with its own key and receives shares
    /// sealed to its key under another name: cryptographic review finding N-1/N-4.
    #[test]
    fn a_door_fingerprint_that_is_not_the_name_of_its_key_is_refused() {
        let ordered = grant();
        let mut g = ordered.clone();
        g.door_fpr = [0xee; 32];
        assert!(grant_body(&g).is_err(), "писатель выпустил грант с чужим именем двери");

        let body = rebuild_with(&grant_body(&ordered).unwrap(), tag::DOOR_FPR, &[0xee; 32]);
        let outcome = decode_grant(&signed(&body, &author()), &author().public_key());
        assert!(
            matches!(outcome, Err(FormatError::BadFieldLength { tag: tag::DOOR_FPR, .. })),
            "имя, не называющее ключ, принято: {outcome:?}"
        );
    }

    /// A MECHANISM NOT EXECUTED BY STAGE 1 IS REJECTED DURING PARSING.
    ///
    /// The first case matters because its fingerprint is HONEST: the P-256 key is named
    /// correctly under K27, so rejection comes not from the name comparison but from
    /// the door's inability to execute that mechanism ("How to change the format", rule 4).
    #[test]
    fn an_unexecuted_kem_is_refused_on_parse() {
        let ordered = grant();
        let body = grant_body(&ordered).unwrap();

        let p256_public = {
            let mut key = vec![0x04u8; 65];
            key[1] = 0x11;
            key
        };
        let p256_fpr =
            oc_crypto::kdf::device_fpr(oc_crypto::KemAlg::P256HkdfSha256, &p256_public).unwrap();
        let honest_p256 = {
            let with_kem = rebuild_with(&body, tag::DOOR_KEM, &[2]);
            let with_key = rebuild_with(&with_kem, tag::DOOR_PUBLIC, &p256_public);
            rebuild_with(&with_key, tag::DOOR_FPR, &p256_fpr)
        };

        for (what, doc) in [
            ("честный P-256", honest_p256),
            ("номер вне реестра", rebuild_with(&body, tag::DOOR_KEM, &[0x63])),
        ] {
            let outcome = decode_grant(&signed(&doc, &author()), &author().public_key());
            assert!(
                matches!(outcome, Err(FormatError::BadFieldLength { tag: tag::DOOR_KEM, .. })),
                "{what}: механизм принят, ответ {outcome:?}"
            );
        }
    }

    #[test]
    fn unknown_optional_tag_is_skipped() {
        let body = rebuild_plus(&grant_body(&grant()).unwrap(), 0x8000, &[1, 2, 3]);
        let bytes = signed(&body, &author());
        let back = decode_grant(&bytes, &author().public_key()).unwrap();
        // Всё, кроме подписи, совпало: необязательное поле проехало мимо.
        let mut expected = grant();
        expected.signature = back.signature;
        assert_eq!(back, expected);
    }

    #[test]
    fn unknown_critical_tag_is_refused() {
        let body = rebuild_plus(&grant_body(&grant()).unwrap(), 0x7FFF, &[1, 2, 3]);
        let outcome = decode_grant(&signed(&body, &author()), &author().public_key());
        assert!(
            matches!(outcome, Err(FormatError::UnknownCriticalField { tag: 0x7FFF })),
            "критичный тег из будущей версии пропущен молча: {outcome:?}"
        );
    }

    #[test]
    fn expires_before_issued_is_refused() {
        let ordered = grant();
        let mut g = ordered.clone();
        g.expires_at = g.issued_at - 1;
        assert!(grant_body(&g).is_err(), "писатель выпустил грант с сроком раньше выдачи");

        let body = rebuild_with(
            &grant_body(&ordered).unwrap(),
            tag::EXPIRES_AT,
            &(ordered.issued_at - 1).to_le_bytes(),
        );
        let outcome = decode_grant(&signed(&body, &author()), &author().public_key());
        assert!(
            matches!(outcome, Err(FormatError::BadFieldLength { tag: tag::EXPIRES_AT, .. })),
            "срок раньше выдачи принят: {outcome:?}"
        );
    }

    // ------------------------------------------------------------------
    // Делегирование и цепочка.
    // ------------------------------------------------------------------

    /// First descendant's SIGNING key.
    fn child_a() -> Ed25519Signer {
        Ed25519Signer::from_seed(&[0xc0; 32])
    }

    /// First descendant's key-agreement public key, also its fingerprint (K27, X25519).
    const CHILD_A_PUBLIC: [u8; 32] = [0xc1; 32];

    fn child_b() -> Ed25519Signer {
        Ed25519Signer::from_seed(&[0xb0; 32])
    }

    const CHILD_B_PUBLIC: [u8; 32] = [0xb1; 32];

    fn child_c() -> Ed25519Signer {
        Ed25519Signer::from_seed(&[0xe0; 32])
    }

    const CHILD_C_PUBLIC: [u8; 32] = [0xe1; 32];

    /// Time at which the chain is checked. Data, not the system clock:
    /// otherwise expiration tests would test the machine clock rather than the rule.
    const NOW: i64 = 1_700_010_000;

    fn sign_link(d: &mut Delegation, signer: &Ed25519Signer) {
        let body = delegation_body(d).expect("тело звена собирается");
        d.signature = signer.sign(&delegation_transcript(&body)).unwrap();
    }

    /// First link: door → descendant A, one of two files, shorter lifetime than the grant.
    fn link_one() -> Delegation {
        let mut d = Delegation {
            grant_id: [0x67; 16],
            parent_fpr: DOOR_PUBLIC,
            child_fpr: CHILD_A_PUBLIC,
            child_kem: 1,
            child_public: CHILD_A_PUBLIC.to_vec(),
            child_verify: child_a().public_key(),
            entries: vec![Entry { file_id: file_id(1), share_b: blob(0x44) }],
            expires_at: 1_700_050_000,
            tightening: None,
            depth: 1,
            actions: Vec::new(),
            signature: [0; SIGNATURE_LEN],
        };
        sign_link(&mut d, &door());
        d
    }

    /// Second link: descendant A → descendant B.
    fn link_two() -> Delegation {
        let mut d = Delegation {
            grant_id: [0x67; 16],
            parent_fpr: CHILD_A_PUBLIC,
            child_fpr: CHILD_B_PUBLIC,
            child_kem: 1,
            child_public: CHILD_B_PUBLIC.to_vec(),
            child_verify: child_b().public_key(),
            entries: vec![Entry { file_id: file_id(1), share_b: blob(0x55) }],
            expires_at: 1_700_040_000,
            tightening: None,
            depth: 0,
            actions: Vec::new(),
            signature: [0; SIGNATURE_LEN],
        };
        sign_link(&mut d, &child_a());
        d
    }

    fn chain(grant: &AgentGrant, links: &[Delegation], now: i64) -> Result<ChainFacts, ChainRefusal> {
        let grant_bytes = encode_grant(grant).unwrap();
        let raw: Vec<Vec<u8>> = links.iter().map(|l| encode_delegation(l).unwrap()).collect();
        let refs: Vec<&[u8]> = raw.iter().map(Vec::as_slice).collect();
        verify_grant_chain(&author().public_key(), &grant_bytes, &refs, now)
    }

    #[test]
    fn delegation_round_trips() {
        let d = link_one();
        let bytes = encode_delegation(&d).unwrap();
        assert_eq!(decode_delegation(&bytes, &door().public_key()).unwrap(), d);
    }

    /// THE LINK SIGNATURE IS VERIFIED BEFORE BODY PARSING, just as for the grant.
    #[test]
    fn the_delegation_signature_is_checked_before_the_body_is_parsed() {
        let good = delegation_body(&link_one()).unwrap();
        let mut w = TlvWriter::new();
        for (t, v) in fields_of(&good) {
            w.put(t, &v).unwrap();
        }
        w.put(0x7FFF, &[0xab; 4]).unwrap();
        let body = w.finish().to_vec();

        // Своя подпись — ответ разборный.
        let own = {
            let sig = door().sign(&delegation_transcript(&body)).unwrap();
            let mut out = sig.to_vec();
            out.extend_from_slice(&body);
            out
        };
        assert!(
            matches!(
                decode_delegation(&own, &door().public_key()),
                Err(FormatError::UnknownCriticalField { .. })
            ),
            "предпосылка неверна: тело разбирается"
        );

        // Чужая подпись — ответ подписной, и только он.
        let forged = {
            let sig = stranger().sign(&delegation_transcript(&body)).unwrap();
            let mut out = sig.to_vec();
            out.extend_from_slice(&body);
            out
        };
        let outcome = decode_delegation(&forged, &door().public_key());
        assert!(
            matches!(outcome, Err(FormatError::BadHeaderSignature)),
            "разбор произошёл до проверки подписи: {outcome:?}"
        );
    }

    /// The descendant name must identify its key, the same K27 rule as for the door.
    #[test]
    fn a_child_fingerprint_that_is_not_the_name_of_its_key_is_refused() {
        let mut d = link_one();
        d.child_fpr = [0xee; 32];
        assert!(delegation_body(&d).is_err(), "писатель выпустил звено с чужим именем потомка");
    }

    #[test]
    fn a_two_link_chain_verifies() {
        let facts = chain(&grant(), &[link_one(), link_two()], NOW).expect("честная цепочка");
        assert_eq!(facts.grant_id, [0x67; 16]);
    }

    #[test]
    fn facts_name_the_last_holder() {
        let facts = chain(&grant(), &[link_one(), link_two()], NOW).unwrap();
        assert_eq!(facts.holder_fpr, CHILD_B_PUBLIC, "держателем назван не последний");
        assert_eq!(facts.holder_verify, child_b().public_key());
        assert_eq!(facts.files, vec![file_id(1)], "файлы взяты не у последнего звена");
        assert_eq!(facts.expires_at, 1_700_040_000, "срок взят не самый короткий");
        assert_eq!(facts.depth_left, 0);
        assert!(facts.tightening.is_empty());
    }

    #[test]
    fn a_link_adding_a_file_is_refused() {
        let mut d = link_one();
        d.entries.push(Entry { file_id: file_id(9), share_b: blob(0x66) });
        sign_link(&mut d, &door());
        assert_eq!(chain(&grant(), &[d], NOW), Err(ChainRefusal::NotASubset { index: 0 }));
    }

    #[test]
    fn a_link_outliving_its_parent_is_refused() {
        let g = grant();
        let mut d = link_one();
        d.expires_at = g.expires_at.saturating_add(1);
        sign_link(&mut d, &door());
        assert_eq!(chain(&g, &[d], NOW), Err(ChainRefusal::OutlivesParent { index: 0 }));
    }

    /// A third link at depth 2 is excessive: the second has no remaining depth.
    #[test]
    fn a_link_below_zero_depth_is_refused() {
        let mut third = Delegation {
            grant_id: [0x67; 16],
            parent_fpr: CHILD_B_PUBLIC,
            child_fpr: CHILD_C_PUBLIC,
            child_kem: 1,
            child_public: CHILD_C_PUBLIC.to_vec(),
            child_verify: child_c().public_key(),
            entries: vec![Entry { file_id: file_id(1), share_b: blob(0x77) }],
            expires_at: 1_700_030_000,
            tightening: None,
            depth: 0,
            actions: Vec::new(),
            signature: [0; SIGNATURE_LEN],
        };
        sign_link(&mut third, &child_b());
        assert_eq!(
            chain(&grant(), &[link_one(), link_two(), third], NOW),
            Err(ChainRefusal::DepthExhausted { index: 2 })
        );
    }

    #[test]
    fn max_depth_zero_forbids_any_link() {
        let mut g = grant();
        g.max_depth = 0;
        sign_grant(&mut g, &author());
        // Звено приходится переподписать: `door_verify` в гранте тот же, но
        // подпись звена от гранта не зависит — переподписывать нечего, и это
        // само по себе важно: глубину стережёт цепочка, а не подпись.
        assert_eq!(chain(&g, &[link_one()], NOW), Err(ChainRefusal::DepthExhausted { index: 0 }));
    }

    #[test]
    fn a_link_signed_by_a_stranger_is_refused() {
        let mut d = link_one();
        sign_link(&mut d, &stranger());
        assert_eq!(chain(&grant(), &[d], NOW), Err(ChainRefusal::BadLink { index: 0 }));
    }

    /// A LINK NAMING A DIFFERENT PARENT IS REJECTED EVEN WHEN ITS SIGNATURE VERIFIES.
    ///
    /// The signature is genuine: the door signed the link. Fingerprint comparison remains
    /// mandatory because the door's signing and key-agreement keys differ;
    /// without it, shares would be resealed to a key absent from the chain.
    #[test]
    fn a_link_naming_the_wrong_parent_is_refused() {
        let mut d = link_one();
        d.parent_fpr = [0xbb; 32];
        sign_link(&mut d, &door());
        assert_eq!(chain(&grant(), &[d], NOW), Err(ChainRefusal::WrongParent { index: 0 }));
    }

    #[test]
    fn links_from_another_grant_are_refused() {
        let mut d = link_one();
        d.grant_id = [0x68; 16];
        sign_link(&mut d, &door());
        assert_eq!(chain(&grant(), &[d], NOW), Err(ChainRefusal::WrongParent { index: 0 }));
    }

    /// TIME AS DATA; both boundaries are tested separately.
    #[test]
    fn an_expired_grant_is_refused_by_the_clock_given() {
        let g = grant();
        assert_eq!(chain(&g, &[], g.expires_at.saturating_add(1)), Err(ChainRefusal::Expired));
        assert_eq!(chain(&g, &[], g.issued_at.saturating_sub(1)), Err(ChainRefusal::NotYetValid));
        // Контроль: на краях срок ещё действует — иначе проба выше зеленела бы
        // и при правиле «истекло всегда».
        assert!(chain(&g, &[], g.issued_at).is_ok());
        assert!(chain(&g, &[], g.expires_at).is_ok());
    }

    /// An expired LINK disables the chain even while the grant remains valid.
    #[test]
    fn an_expired_link_is_refused_though_the_grant_lives() {
        let g = grant();
        let d = link_one();
        assert!(d.expires_at < g.expires_at, "предпосылка: звено короче гранта");
        assert_eq!(chain(&g, std::slice::from_ref(&d), d.expires_at.saturating_add(1)), Err(ChainRefusal::Expired));
    }

    /// EVERY REJECTION HAS A REASON IN WORDS.
    ///
    /// A test against "reason → empty string": an unexplained rejection
    /// passes every "rejected" check and is caught only this way.
    #[test]
    fn every_refusal_names_a_reason() {
        for refusal in [
            ChainRefusal::BadGrant,
            ChainRefusal::BadLink { index: 1 },
            ChainRefusal::NotASubset { index: 1 },
            ChainRefusal::OutlivesParent { index: 1 },
            ChainRefusal::DepthExhausted { index: 1 },
            ChainRefusal::WrongParent { index: 1 },
            ChainRefusal::Expired,
            ChainRefusal::NotYetValid,
        ] {
            let text = format!("{refusal}");
            assert!(text.len() > 10, "отказ {refusal:?} не объяснён: {text:?}");
        }
    }

    /// PEEKING WITHOUT SIGNATURE VERIFICATION RETURNS THE SAME BODY, AND DOES NOT REPLACE VERIFICATION.
    ///
    /// Two halves: for a legitimate document, `peek` and `decode` return the same data
    /// (otherwise the server would look up a key by some fields and trust others);
    /// for a document with a WRONG signature, `peek` succeeds while `decode` fails. The second
    /// half is the reason for this test: `peek` accidentally becoming
    /// a verifier would pass any "server accepted the grant" test.
    #[test]
    fn peeking_reads_the_same_body_but_never_stands_in_for_the_signature() {
        let g = grant();
        let bytes = encode_grant(&g).unwrap();
        assert_eq!(peek_grant(&bytes).unwrap(), g);
        assert_eq!(peek_grant(&bytes).unwrap(), decode_grant(&bytes, &author().public_key()).unwrap());

        let body = grant_body(&g).unwrap();
        let forged = signed(&body, &stranger());
        assert!(peek_grant(&forged).is_ok(), "взгляд обязан проходить и без своей подписи");
        assert!(
            matches!(decode_grant(&forged, &author().public_key()), Err(FormatError::BadHeaderSignature)),
            "чужая подпись принята"
        );

        let link = link_one();
        let raw = encode_delegation(&link).unwrap();
        assert_eq!(peek_delegation(&raw).unwrap(), link);
        let link_body = delegation_body(&link).unwrap();
        let sig = stranger().sign(&delegation_transcript(&link_body)).unwrap();
        let mut forged_link = sig.to_vec();
        forged_link.extend_from_slice(&link_body);
        assert!(peek_delegation(&forged_link).is_ok());
        assert!(
            matches!(
                decode_delegation(&forged_link, &door().public_key()),
                Err(FormatError::BadHeaderSignature)
            ),
            "звено с чужой подписью принято"
        );

        // Форма проверяется и здесь: незаверенный документ не той формы наружу
        // не уходит (И-9).
        let broken = rebuild_with(&body, tag::DOOR_KEM, &[0x63]);
        let mut document = [0u8; SIGNATURE_LEN].to_vec();
        document.extend_from_slice(&broken);
        assert!(peek_grant(&document).is_err(), "взгляд выпустил грант не той формы");
    }

    // ------------------------------------------------------------------
    // Делегирование ДЕЙСТВИЙ (этап 2).
    // ------------------------------------------------------------------

    use crate::action::{
        ActionGrant, ActionKind, ActionRefusal, ActionRule, Constraint, Method,
        grant_body as action_grant_body, grant_transcript as action_grant_transcript,
    };

    fn push_rule(branch: &str, max_uses: u32, delegable: bool) -> ActionRule {
        ActionRule {
            kind: ActionKind::GitPush,
            constraint: Constraint::GitPush {
                remote: "origin".to_string(),
                branch: branch.to_string(),
            },
            max_uses,
            confirm: false,
            delegable,
        }
    }

    fn remove_rule(prefix: &str) -> ActionRule {
        ActionRule {
            kind: ActionKind::TreeRemove,
            constraint: Constraint::TreeRemove { prefix: prefix.to_string() },
            max_uses: 0,
            confirm: false,
            delegable: true,
        }
    }

    fn http_rule() -> ActionRule {
        ActionRule {
            kind: ActionKind::HttpRequest,
            constraint: Constraint::HttpRequest {
                host: "api.example.com".to_string(),
                methods: vec![Method::Get, Method::Post],
                path_prefix: "/v1".to_string(),
                secret_ref: None,
            },
            max_uses: 100,
            confirm: false,
            delegable: true,
        }
    }

    /// An action grant for the same root, signed by the same author.
    fn action_grant(rules: Vec<ActionRule>) -> Vec<u8> {
        let mut g = ActionGrant {
            grant_id: [0x67; 16],
            rules,
            issued_at: 1_700_000_000,
            expires_at: 1_700_086_400,
            author_key: author().public_key(),
            signature: [0; SIGNATURE_LEN],
        };
        let body = action_grant_body(&g).expect("тело гранта действий собирается");
        g.signature = author().sign(&action_grant_transcript(&body)).unwrap();
        crate::action::encode_grant(&g).unwrap()
    }

    /// A first-level link with the specified actions.
    fn link_with(actions: Vec<ActionRule>) -> Delegation {
        let mut d = link_one();
        d.actions = actions;
        sign_link(&mut d, &door());
        d
    }

    fn chain_acting(
        links: &[Delegation],
        actions: Option<&[u8]>,
        now: i64,
    ) -> Result<ChainFacts, ChainRefusal> {
        let grant_bytes = encode_grant(&grant()).unwrap();
        let raw: Vec<Vec<u8>> = links.iter().map(|l| encode_delegation(l).unwrap()).collect();
        let refs: Vec<&[u8]> = raw.iter().map(Vec::as_slice).collect();
        verify_grant_chain_with_actions(
            &author().public_key(),
            &grant_bytes,
            &refs,
            actions,
            now,
        )
    }

    #[test]
    fn a_delegation_with_actions_round_trips() {
        let d = link_with(vec![push_rule("agent/work", 5, false), remove_rule("src/agent")]);
        let bytes = encode_delegation(&d).unwrap();
        assert_eq!(decode_delegation(&bytes, &door().public_key()).unwrap(), d);
    }

    /// NO TAG AND AN EMPTY LIST PRODUCE IDENTICAL BYTES.
    ///
    /// Two representations of one meaning would create two links for one assertion, while
    /// the signature covers RAW bytes: "the same link" would cease to be one
    /// sequence.
    #[test]
    fn an_empty_action_list_writes_no_tag_at_all() {
        let plain = delegation_body(&link_one()).unwrap();
        let mut empty = link_one();
        empty.actions = Vec::new();
        assert_eq!(delegation_body(&empty).unwrap(), plain);
        assert!(
            !fields_of(&plain).iter().any(|(t, _)| *t == link_tag::ACTIONS),
            "пустой список всё же записал тег"
        );
    }

    /// A STAGE 1 READER SEES THE OLD CHAIN.
    ///
    /// Both a requirement and the I-7 promise: the action tag is optional; the old
    /// [`verify_grant_chain`] call must traverse a chain WITH THE TAG and return
    /// the same file facts as a chain without it. The action list meanwhile
    /// is EMPTY: an unverified rule has no effect (I-10).
    #[test]
    fn the_stage_one_reader_sees_the_same_chain_through_the_action_tag() {
        let with_tag = link_with(vec![push_rule("agent/work", 5, false)]);
        let plain = link_one();

        let a = chain(&grant(), std::slice::from_ref(&with_tag), NOW).expect("цепочка с тегом");
        let b = chain(&grant(), std::slice::from_ref(&plain), NOW).expect("цепочка без тега");

        assert_eq!(a.files, b.files, "тег действий изменил список файлов");
        assert_eq!(a.expires_at, b.expires_at);
        assert_eq!(a.holder_fpr, b.holder_fpr);
        assert_eq!(a.depth_left, b.depth_left);
        assert!(a.actions.is_empty(), "старый вызов отдал действия, которых не проверял");
    }

    /// Narrowing passes, and the facts name the LAST holder's rules.
    #[test]
    fn a_narrowing_child_gets_the_actions_it_asked_for() {
        let raw = action_grant(vec![push_rule("agent/work", 10, true), http_rule()]);
        let child = push_rule("agent/work", 4, false);
        let link = link_with(vec![child.clone()]);

        let facts = chain_acting(std::slice::from_ref(&link), Some(&raw), NOW)
            .expect("честное сужение действий");
        assert_eq!(facts.actions, vec![child], "факты назвали не правила потомка");
    }

    /// Without an action grant, facts are empty even when a link requests actions.
    #[test]
    fn actions_unknown_to_the_verifier_never_take_effect() {
        let link = link_with(vec![push_rule("agent/work", 4, false)]);
        let facts = chain_acting(std::slice::from_ref(&link), None, NOW).unwrap();
        assert!(facts.actions.is_empty());
    }

    /// The chain root receives all action grant rules.
    #[test]
    fn with_no_links_the_door_itself_holds_the_granted_actions() {
        let rules = vec![push_rule("agent/work", 10, true), http_rule()];
        let raw = action_grant(rules.clone());
        let facts = chain_acting(&[], Some(&raw), NOW).unwrap();
        assert_eq!(facts.actions, rules);
    }

    /// An action-only holder can use a file grant with an empty file list.
    /// The verified grant still supplies the author-key anchor for action rules.
    #[test]
    fn a_file_grant_with_no_files_still_anchors_its_actions() {
        let mut g = grant();
        g.entries.clear();
        sign_grant(&mut g, &author());
        let bytes = encode_grant(&g).unwrap();
        assert!(
            decode_grant(&bytes, &author().public_key()).is_ok(),
            "грант без файлов отвергнут — двери «только действия» не существовать"
        );

        let rules = vec![push_rule("agent/work", 10, true)];
        let raw = action_grant(rules.clone());
        let facts = verify_grant_chain_with_actions(
            &author().public_key(),
            &bytes,
            &[],
            Some(&raw),
            NOW,
        )
        .expect("цепочка без файлов не принята");
        assert!(facts.files.is_empty(), "предпосылка: файлов у гранта нет");
        assert_eq!(facts.actions, rules, "действия не достались двери без файлов");
    }

    /// BROADENING EACH FIELD HAS ITS OWN REJECTION.
    #[test]
    fn every_way_of_widening_an_action_has_its_own_refusal() {
        let raw = action_grant(vec![push_rule("agent/work", 10, true), remove_rule("src")]);

        // Вид, которого у родителя нет вовсе.
        let link = link_with(vec![http_rule()]);
        assert_eq!(
            chain_acting(std::slice::from_ref(&link), Some(&raw), NOW),
            Err(ChainRefusal::ActionNotGranted { index: 0 })
        );

        // Другая ветка — равенство, а не вложенность.
        let link = link_with(vec![push_rule("main", 10, false)]);
        assert_eq!(
            chain_acting(std::slice::from_ref(&link), Some(&raw), NOW),
            Err(ChainRefusal::ActionWidens {
                index: 0,
                why: ActionRefusal::WiderLimiter { limiter: "branch" },
            })
        );

        // Больше исполнений, чем у родителя.
        let link = link_with(vec![push_rule("agent/work", 11, false)]);
        assert_eq!(
            chain_acting(std::slice::from_ref(&link), Some(&raw), NOW),
            Err(ChainRefusal::ActionWidens { index: 0, why: ActionRefusal::MoreUses })
        );

        // Соседний каталог: `src2` не под `src`, и по строке прошёл бы.
        let link = link_with(vec![remove_rule("src2")]);
        assert_eq!(
            chain_acting(std::slice::from_ref(&link), Some(&raw), NOW),
            Err(ChainRefusal::ActionWidens {
                index: 0,
                why: ActionRefusal::WiderLimiter { limiter: "prefix" },
            })
        );
    }

    /// A `confirm` rule is never delegated: the owner's live "yes" is issued
    /// for a specific door.
    #[test]
    fn a_confirm_rule_does_not_travel_down_the_chain() {
        let mut parent = push_rule("agent/work", 10, true);
        parent.confirm = true;
        let raw = action_grant(vec![parent]);
        let link = link_with(vec![push_rule("agent/work", 1, false)]);
        assert_eq!(
            chain_acting(std::slice::from_ref(&link), Some(&raw), NOW),
            Err(ChainRefusal::ActionWidens {
                index: 0,
                why: ActionRefusal::ConfirmNotDelegable,
            })
        );
    }

    /// `delegable` CAN ONLY BE REMOVED: if absent in the parent, the child cannot receive it.
    #[test]
    fn a_rule_not_marked_delegable_stops_at_its_holder() {
        let raw = action_grant(vec![push_rule("agent/work", 10, false)]);
        let link = link_with(vec![push_rule("agent/work", 1, false)]);
        assert_eq!(
            chain_acting(std::slice::from_ref(&link), Some(&raw), NOW),
            Err(ChainRefusal::ActionWidens { index: 0, why: ActionRefusal::NotDelegable })
        );
    }

    /// Narrowing is checked ALONG THE CHAIN, not against the root.
    ///
    /// The second link is compared with the FIRST link's rules, not the grant:
    /// otherwise a grandchild could restore rights its parent surrendered; checking against the root
    /// would pass the chain "10 → 4 → 8".
    #[test]
    fn the_second_link_narrows_the_first_and_not_the_root() {
        let raw = action_grant(vec![push_rule("agent/work", 10, true)]);
        let first = link_with(vec![push_rule("agent/work", 4, true)]);

        let widen = {
            let mut d = link_two();
            d.actions = vec![push_rule("agent/work", 8, false)];
            sign_link(&mut d, &child_a());
            d
        };
        assert_eq!(
            chain_acting(&[first.clone(), widen], Some(&raw), NOW),
            Err(ChainRefusal::ActionWidens { index: 1, why: ActionRefusal::MoreUses })
        );

        // Контроль: сужение на втором звене проходит.
        let narrow = {
            let mut d = link_two();
            d.actions = vec![push_rule("agent/work", 2, false)];
            sign_link(&mut d, &child_a());
            d
        };
        let facts = chain_acting(&[first, narrow], Some(&raw), NOW).unwrap();
        assert_eq!(facts.actions, vec![push_rule("agent/work", 2, false)]);
    }

    /// A link naming no actions DISABLES them for every descendant.
    #[test]
    fn a_link_that_names_no_actions_passes_none_down() {
        let raw = action_grant(vec![push_rule("agent/work", 10, true)]);
        let facts = chain_acting(std::slice::from_ref(&link_one()), Some(&raw), NOW).unwrap();
        assert!(facts.actions.is_empty(), "действия просочились через звено, их не назвавшее");
    }

    /// ACTION GRANT FROM ANOTHER ROOT OR AUTHOR, OR OUTLIVING THE FILE GRANT.
    #[test]
    fn the_action_grant_is_anchored_to_this_file_grant_and_this_author() {
        // Чужой корень: подпись сходится, привязка нет.
        let mut g = ActionGrant {
            grant_id: [0x68; 16],
            rules: vec![push_rule("agent/work", 10, true)],
            issued_at: 1_700_000_000,
            expires_at: 1_700_086_400,
            author_key: author().public_key(),
            signature: [0; SIGNATURE_LEN],
        };
        let body = action_grant_body(&g).unwrap();
        g.signature = author().sign(&action_grant_transcript(&body)).unwrap();
        let raw = crate::action::encode_grant(&g).unwrap();
        assert_eq!(chain_acting(&[], Some(&raw), NOW), Err(ChainRefusal::ActionsWrongGrant));

        // Чужой автор.
        let mut g = ActionGrant {
            grant_id: [0x67; 16],
            rules: vec![push_rule("agent/work", 10, true)],
            issued_at: 1_700_000_000,
            expires_at: 1_700_086_400,
            author_key: stranger().public_key(),
            signature: [0; SIGNATURE_LEN],
        };
        let body = action_grant_body(&g).unwrap();
        g.signature = stranger().sign(&action_grant_transcript(&body)).unwrap();
        let raw = crate::action::encode_grant(&g).unwrap();
        assert_eq!(chain_acting(&[], Some(&raw), NOW), Err(ChainRefusal::BadActionGrant));

        // Срок длиннее файлового гранта.
        let mut g = ActionGrant {
            grant_id: [0x67; 16],
            rules: vec![push_rule("agent/work", 10, true)],
            issued_at: 1_700_000_000,
            expires_at: 1_700_086_401,
            author_key: author().public_key(),
            signature: [0; SIGNATURE_LEN],
        };
        let body = action_grant_body(&g).unwrap();
        g.signature = author().sign(&action_grant_transcript(&body)).unwrap();
        let raw = crate::action::encode_grant(&g).unwrap();
        assert_eq!(chain_acting(&[], Some(&raw), NOW), Err(ChainRefusal::ActionsOutliveGrant));
    }

    /// An expired action grant disables actions even while the file grant remains valid.
    #[test]
    fn an_expired_action_grant_is_refused_by_the_clock_given() {
        let mut g = ActionGrant {
            grant_id: [0x67; 16],
            rules: vec![push_rule("agent/work", 10, true)],
            issued_at: 1_700_000_000,
            expires_at: 1_700_005_000,
            author_key: author().public_key(),
            signature: [0; SIGNATURE_LEN],
        };
        let body = action_grant_body(&g).unwrap();
        g.signature = author().sign(&action_grant_transcript(&body)).unwrap();
        let raw = crate::action::encode_grant(&g).unwrap();

        assert_eq!(chain_acting(&[], Some(&raw), NOW), Err(ChainRefusal::Expired));
        // Контроль: до истечения тот же грант принимается, иначе проба выше
        // зеленела бы и при правиле «истекло всегда».
        assert!(chain_acting(&[], Some(&raw), 1_700_004_999).is_ok());
    }

    /// Garbage in the optional tag is rejected DURING PARSING, not on the server.
    #[test]
    fn junk_in_the_action_tag_is_refused_when_the_link_is_parsed() {
        let good = delegation_body(&link_one()).unwrap();
        let body = rebuild_plus(&good, link_tag::ACTIONS, &[0xab; 7]);
        let sig = door().sign(&delegation_transcript(&body)).unwrap();
        let mut document = sig.to_vec();
        document.extend_from_slice(&body);
        assert!(
            decode_delegation(&document, &door().public_key()).is_err(),
            "мусор в теге действий проехал мимо разбора"
        );
    }

    /// NEW rejections also have reasons in words.
    #[test]
    fn every_action_refusal_of_the_chain_names_a_reason() {
        for refusal in [
            ChainRefusal::BadActionGrant,
            ChainRefusal::ActionsWrongGrant,
            ChainRefusal::ActionsOutliveGrant,
            ChainRefusal::ActionNotGranted { index: 1 },
            ChainRefusal::ActionWidens { index: 1, why: ActionRefusal::MoreUses },
        ] {
            let text = format!("{refusal}");
            assert!(text.len() > 10, "отказ {refusal:?} не объяснён: {text:?}");
        }
    }

    /// Parsing arbitrary bytes does not panic: the grant arrives from the wire.
    #[test]
    fn decoding_arbitrary_bytes_never_panics() {
        let key = author().public_key();
        let bytes = encode_grant(&grant()).unwrap();
        for cut in 0..bytes.len() {
            let _ = decode_grant(&bytes[..cut], &key);
        }
        let mut seed = 0x5eed_u64;
        for _ in 0..10_000 {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let len = (seed >> 33) as usize % 128;
            let mut junk = vec![0u8; len];
            for (i, b) in junk.iter_mut().enumerate() {
                *b = (seed >> (i % 8 * 8)) as u8;
            }
            let _ = decode_grant(&junk, &key);
        }
    }
}
