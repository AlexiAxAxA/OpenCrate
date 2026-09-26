// SPDX-License-Identifier: MPL-2.0
//! An author's order to the server: what to do with a file.
//!
//! Before 2026-09-03, registration and revocation were operator `cca` commands on
//! the server machine, so who counted as the author depended on who had access to
//! that machine. This cannot work over the wire: `file_id` is public in the header,
//! and without a signature anyone receiving the file could register it under their own
//! terms or revoke it for everyone (`docs/protocol.md` §9.3).
//!
//! An order is a TLV document signed by the AUTHOR KEY, the same key that
//! signed the container header. Registration carries the entire header alongside it:
//! the server verifies the header signature, extracts the author key and uses it
//! to verify the order. The server learns the author key not from the requester's claims but
//! from a document the recipient cannot modify. Revocation is verified using
//! the key remembered during registration.
//!
//! The layout matches revocations and leases: `signature(64) ‖ body`. The signature
//! comes first so that a truncated document cannot parse "almost successfully".
//!
//! Issuance time is part of the body and signature: the server accepts only
//! fresh orders (allowing clock skew), so a document resurfacing
//! after lying somewhere is not executed.
//!
//! Freshness is insufficient, although this documentation formerly claimed otherwise: "both operations are idempotent,
//! replay does nothing". That described two kinds, registration and
//! revocation; there are now eight, and replaying a vote, roster or thaw changes
//! state. Order BETWEEN commands is maintained by the server using a per-kind barrier
//! (`docs/protocol.md` §11.11), not by this check.

//! There are more than two order kinds: author proof of life and heir appointment
//! joined registration and revocation (`docs/protocol.md` §11). Layout,
//! signature and freshness rule are shared; only the field set differs.
//! The field set is checked against the kind in BOTH directions by one `check` function:
//! if encoding and decoding checks differed by even one field, an order
//! we refuse to issue could nevertheless be executed if received
//! from outside.

use oc_crypto::CryptoError;

use oc_format::FormatError;
use oc_format::tlv::{TlvReader, TlvWriter};

/// Order body version.
pub const ORDER_VERSION: u16 = 1;

/// Length of the Ed25519 signature preceding the body.
pub const SIGNATURE_LEN: usize = 64;

/// Maximum heirs accepted by one order.
///
/// Sixteen, the same limit as the roster and for the same reason: a human
/// reads the list, and one where they cannot find an entry visually is no better
/// than no list. The limit is also checked before allocation: otherwise a megabyte stream
/// would force collection of thousands of decisions only to reject them afterward.
pub const MAX_HEIRS: usize = 16;

/// Maximum keys in one coauthor or approver roster.
///
/// Sixteen, the same as server addresses in the header and requests in the
/// queue, for the same reason: a quantity a person can
/// review visually. Both parties share this limit: it belongs to the document format,
/// not server preference.
pub const MAX_KEYS: usize = 16;

/// Number of names for one device in a replacement.
///
/// Four: the mechanisms one device may have simultaneously are X25519, X-Wing, P-256
/// in a TPM and a hardware hybrid. More would no longer represent a single device.
pub const MAX_DEVICE_NAMES: usize = 4;

/// Body tags. All critical: an unknown tag is rejected (I-7).
pub mod tag {
    pub const VERSION: u16 = 1;
    pub const FILE_ID: u16 = 2;
    pub const KIND: u16 = 3;
    pub const AT: u16 = 4;
    /// Registration only: device limit.
    pub const MAX_DEVICES: u16 = 5;
    /// Registration only: issuance limit.
    pub const MAX_GRANTS: u16 = 6;
    /// `SetCoauthors`/`SetApprovers` only: consecutive 32-byte keys.
    ///
    /// An unnumbered stream rather than one tag per key: numbering by tag hits the
    /// 65536 ceiling (I-7), and is unnecessary here because element length
    /// is constant and position determines order.
    pub const KEYS: u16 = 7;
    /// `SetCoauthors`/`SetApprovers` only: required signatures from the
    /// roster. Zero with an empty roster means "no quorum".
    pub const THRESHOLD: u16 = 8;
    /// `ApproveDevice` only: the device being voted on.
    pub const DEVICE_FPR: u16 = 9;
    /// `ApproveDevice` only: for or against.
    pub const APPROVE: u16 = 10;
    /// `SetHeir{Open|Close}` only: seconds of author silence that constitute
    /// an event.
    pub const SILENCE_SECONDS: u16 = 11;
    /// `SetHeir` only: what to do after silence.
    pub const HEIR_MODE: u16 = 12;
    /// `SetHeir{Open}` only: completed author decisions for heirs, as a stream.
    ///
    /// # Why a stream, and why the number was not retired
    ///
    /// The tag was created for ONE decision. Multiple heirs were needed (customer decision
    /// of 2026-09-05), so the contents became a stream of
    /// `u32le length ‖ Decision`, repeated up to `MAX_HEIRS` times.
    ///
    /// The number was not repurposed for a different meaning; the same meaning was expressed
    /// more precisely: "who gets what after silence". I-7 forbids the former, not
    /// the latter. Retiring the number would be superstition rather than caution: no
    /// server with an appointed heir has shipped, and protocol documents other than
    /// leases are not frozen (`docs/protocol.md` §0). A single heir remains
    /// a valid case: a one-entry stream.
    pub const BEQUEST: u16 = 13;
    /// Whose key verifies the signature when it cannot be obtained from the file.
    ///
    /// # Why the name changed but the number did not
    ///
    /// The tag began as `AUTHOR_KEY`, "whose presence is recorded" in proof of life
    /// for all files. Approver voting revealed the field's broader
    /// meaning: a roster member signs, not the author, and that key also cannot be
    /// found from the file: the server remembers the AUTHOR's key. The name `author_key`
    /// would then be a lie presented as truth, containing someone else's key.
    ///
    /// The number deliberately remained unchanged. I-7 prohibits reusing numbers
    /// with a DIFFERENT meaning; this meaning is and always was "the key
    /// used to verify this document". Changing the number would retire it merely
    /// to refine the wording.
    ///
    /// Required for `Alive` with zero `file_id` and for `ApproveDevice`; forbidden
    /// everywhere else.
    pub const SIGNER_KEY: u16 = 14;
    /// `SetCoauthors` only: lifetime of a proposal lacking enough signatures.
    ///
    /// Optional: absence means "server default", not "zero". A file
    /// with no specified lifetime behaves as before.
    pub const PROPOSAL_TTL: u16 = 15;
    /// `Freeze` only: 1 freezes issuance for all files under the key, 0 unfreezes it.
    ///
    /// Direction belongs to the signed order, like heir mode:
    /// "stop everything" and "allow everything" are opposite commands, and the author
    /// must choose, not whoever has server access.
    pub const FROZEN: u16 = 16;
    /// `ReplaceDevice` only: OLD device names (K27), consecutive 32-byte entries,
    /// from one to [`super::MAX_DEVICE_NAMES`]. Multiple names because one
    /// device has several: classical, X-Wing and hardware.
    pub const OLD_DEVICES: u16 = 17;
    /// `ReplaceDevice` only: NEW device names (K27), in the same stream format.
    pub const NEW_DEVICES: u16 = 18;
    /// Required and exclusive to `SetRule`: file attribute rule,
    /// using [`crate::attribute_rule`]. An empty rule is valid and clears the previous one.
    pub const RULE: u16 = 19;
    /// Required and exclusive to `WatchAuthor`: the lease-signing key of the server
    /// to which the proof is addressed. Binds it to the server and
    /// tenant: each has its own key in the hosted profile.
    pub const AUTHORITY_KEY: u16 = 20;
    /// Required and exclusive to `RevokeGrant`: the agent grant name being
    /// revoked (`crate::agent::AgentGrant::grant_id`).
    ///
    /// Grant, not file: a grant covers a SUBTREE, so revoking it is one
    /// command rather than N commands for N files. Per-file revocation would leave
    /// the chain half alive precisely when the author wants to disable it.
    pub const GRANT_ID: u16 = 21;
}

/// What to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    /// Register the file with the specified limits.
    Register = 1,
    /// Revoke file access.
    Revoke = 2,
    /// Change device and issuance limits for an already registered file.
    SetLimits = 3,
    /// Set the coauthor roster and signature threshold.
    SetCoauthors = 4,
    /// Set the opening approver roster and vote threshold.
    SetApprovers = 5,
    /// An approver's vote on a specific device.
    ApproveDevice = 6,
    /// The author is here: postpone the silence deadline.
    Alive = 7,
    /// Appoint an heir, close after silence, or clear both.
    SetHeir = 8,
    /// Panic button: stop issuance for ALL files under the key, or resume it.
    ///
    /// All files at once, with no file required, like proof of life: a key leak
    /// or incident concerns the author, not a document; stopping files one by
    /// one would give the adversary time they should not
    /// have.
    Freeze = 9,
    /// Replace a lost device with a new one: release the old names and
    /// reserve their place for the new names in one write (F-26, B3b).
    ///
    /// Signed by the author through the §9.3 order interface, under a coauthor quorum
    /// when configured. Access and claim codes grant no replacement authority:
    /// whoever holds a code holds ONE issuance, not the right to displace someone else's place.
    ReplaceDevice = 10,
    /// Set a file rule based on holder attributes: issuance gate, lifetime
    /// cap and action restrictions (F-27, B4b).
    ///
    /// The rule concerns a FILE and is set by its owner: author signature or
    /// coauthor quorum through the same interface as limits. The dictionary and attribute holdings concern
    /// the organization and cannot be set through this interface: one author's signature changing
    /// holdings would change access to other authors' files.
    SetRule = 11,
    /// Proof of possession of the author key for subscribing to events for ALL their
    /// files (`docs/protocol.md` §9.9, B5).
    ///
    /// Not a command: the order interface does not execute it, and subscriptions do not
    /// accept other kinds. It uses the same document as orders; a second
    /// format with its own label would create a second definition of "what the author
    /// signed". This kind byte inside the signed body separates the domains.
    WatchAuthor = 12,
    /// Revoke an agent grant: the server stops issuing leases for the entire chain
    /// (Agent Protocol, stage 1, §4 step 6).
    ///
    /// Without a file and BYPASSING QUORUM, like the panic button, for the same reason:
    /// revocation is the safe direction (I-10), and the grant covers a subtree,
    /// so belongs to no individual file. A coauthor quorum
    /// is irrelevant here: the author issued the grant alone,
    /// and the same key revokes it.
    RevokeGrant = 13,
}

impl Kind {
    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Register),
            2 => Some(Self::Revoke),
            3 => Some(Self::SetLimits),
            4 => Some(Self::SetCoauthors),
            5 => Some(Self::SetApprovers),
            6 => Some(Self::ApproveDevice),
            7 => Some(Self::Alive),
            8 => Some(Self::SetHeir),
            9 => Some(Self::Freeze),
            10 => Some(Self::ReplaceDevice),
            11 => Some(Self::SetRule),
            12 => Some(Self::WatchAuthor),
            13 => Some(Self::RevokeGrant),
            _ => None,
        }
    }
}

/// What to do when the author's silence exceeds the interval.
///
/// Mode is part of the signed order, not server state: "open for
/// the heir" and "close for everyone" are opposite document outcomes, and the author
/// must choose. If mode lived only on the server, the outcome would be chosen by
/// whoever had server access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HeirMode {
    /// Clear the heir and interval entirely.
    ///
    /// A separate VALUE rather than an absent field: "clear" is an order
    /// the server must execute and journal; parsing must distinguish it from
    /// "field forgotten", without guessing.
    Off = 0,
    /// Open the bequest for the heir.
    Open = 1,
    /// Close the file for everyone.
    Close = 2,
}

impl HeirMode {
    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Off),
            1 => Some(Self::Open),
            2 => Some(Self::Close),
            _ => None,
        }
    }
}

/// The order as seen by both parties.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Order {
    pub file_id: [u8; 16],
    pub kind: Kind,
    /// Issuance time by the author's clock, UTC seconds.
    pub at: i64,
    /// Limits belong to registration and limit changes; they must not appear
    /// in other kinds.
    pub max_devices: Option<u32>,
    pub max_grants: Option<u32>,
    /// Roster for assigning coauthors and approvers.
    ///
    /// Key order has no semantic or execution effect; it is preserved
    /// so encoding round trips match byte for byte and the signature covers
    /// exactly what the author saw.
    pub keys: Option<Vec<[u8; 32]>>,
    /// Threshold accompanies the roster, and only the roster.
    pub threshold: Option<u8>,
    /// Device being voted on: `ApproveDevice` only.
    pub device_fpr: Option<[u8; 32]>,
    /// For or against: `ApproveDevice` only.
    pub approve: Option<bool>,
    /// Silence interval for heir appointment and closing after silence.
    pub silence_seconds: Option<u64>,
    /// Action after silence: `SetHeir` only.
    pub heir_mode: Option<HeirMode>,
    /// Bequests: complete ready-made author decisions for heirs.
    ///
    /// Bytes rather than parsed structures, deliberately: the server gives heirs
    /// these bytes AS IS, while any reconstruction could diverge from the author's signature,
    /// which covers the entire decision.
    ///
    /// Multiple entries because there may be multiple heirs; one heir is a one-entry
    /// stream, with no special case.
    pub bequests: Option<Vec<Vec<u8>>>,
    /// Whose key verifies the signature: `Alive` for all files, and voting.
    pub signer_key: Option<[u8; 32]>,
    /// Proposal lifetime: coauthor appointment.
    pub proposal_ttl: Option<u64>,
    /// Freeze (`true`) or resume (`false`) issuance: `Freeze` only.
    pub frozen: Option<bool>,
    /// Old device names: `ReplaceDevice` only.
    pub old_devices: Option<Vec<[u8; 32]>>,
    /// New device names: `ReplaceDevice` only.
    pub new_devices: Option<Vec<[u8; 32]>>,
    /// File attribute rule: `SetRule` only.
    pub rule: Option<crate::attribute_rule::Rule>,
    /// Subscription proof recipient: `WatchAuthor` only.
    pub authority_key: Option<[u8; 32]>,
    /// Agent grant to revoke: `RevokeGrant` only.
    pub grant_id: Option<[u8; 16]>,
}

impl Order {
    /// An order with no optional fields.
    ///
    /// Orders have more fields than any individual kind needs; filling
    /// all irrelevant fields with zeros on every side would mean rewriting this list
    /// for each new kind.
    #[must_use]
    pub fn new(file_id: [u8; 16], kind: Kind, at: i64) -> Self {
        Self {
            file_id,
            kind,
            at,
            max_devices: None,
            max_grants: None,
            keys: None,
            threshold: None,
            device_fpr: None,
            approve: None,
            silence_seconds: None,
            heir_mode: None,
            bequests: None,
            signer_key: None,
            proposal_ttl: None,
            frozen: None,
            old_devices: None,
            new_devices: None,
            rule: None,
            authority_key: None,
            grant_id: None,
        }
    }
}

/// A field required under exactly one condition and forbidden otherwise.
fn required(present: bool, wanted: bool, tag: u16) -> Result<(), FormatError> {
    match (present, wanted) {
        (false, true) => Err(FormatError::MissingField { tag }),
        (true, false) => Err(FormatError::UnknownCriticalField { tag }),
        _ => Ok(()),
    }
}

/// A field allowed only for certain kinds, and optional even there.
fn only_if(present: bool, allowed: bool, tag: u16) -> Result<(), FormatError> {
    if present && !allowed { Err(FormatError::UnknownCriticalField { tag }) } else { Ok(()) }
}

/// One place checks field-set consistency with kind for both sides.
///
/// # Errors
/// [`FormatError`] if a field belongs to another kind, is missing from its own kind, or
/// the bequest does not fit this file.
fn check(order: &Order) -> Result<(), FormatError> {
    let register = order.kind == Kind::Register;
    let set_limits = order.kind == Kind::SetLimits;
    only_if(order.max_devices.is_some(), register || set_limits, tag::MAX_DEVICES)?;
    only_if(order.max_grants.is_some(), register || set_limits, tag::MAX_GRANTS)?;
    // Смена пределов, не меняющая ни одного предела, — распоряжение, которое
    // ничего не велит. Принять его значило бы записать в журнал событие,
    // которого не было.
    if set_limits && order.max_devices.is_none() && order.max_grants.is_none() {
        return Err(FormatError::MissingField { tag: tag::MAX_DEVICES });
    }

    let roster = matches!(order.kind, Kind::SetCoauthors | Kind::SetApprovers);
    required(order.keys.is_some(), roster, tag::KEYS)?;
    required(order.threshold.is_some(), roster, tag::THRESHOLD)?;
    if let (Some(keys), Some(threshold)) = (&order.keys, order.threshold) {
        check_roster(keys, threshold)?;
    }

    let vote = order.kind == Kind::ApproveDevice;
    required(order.device_fpr.is_some(), vote, tag::DEVICE_FPR)?;
    required(order.approve.is_some(), vote, tag::APPROVE)?;

    required(order.heir_mode.is_some(), order.kind == Kind::SetHeir, tag::HEIR_MODE)?;
    required(
        order.silence_seconds.is_some(),
        matches!(order.heir_mode, Some(HeirMode::Open | HeirMode::Close)),
        tag::SILENCE_SECONDS,
    )?;
    required(order.bequests.is_some(), order.heir_mode == Some(HeirMode::Open), tag::BEQUEST)?;

    // Срок предложения — только у состава СОАВТОРОВ: у одобряющих предложений
    // нет вовсе, им нечему протухать. Ноль запрещён: снять срок нельзя, можно
    // лишь сменить, а предложение без срока копилось бы вечно.
    only_if(order.proposal_ttl.is_some(), order.kind == Kind::SetCoauthors, tag::PROPOSAL_TTL)?;
    if order.proposal_ttl == Some(0) {
        return Err(FormatError::BadFieldLength { tag: tag::PROPOSAL_TTL, len: 0 });
    }

    // Кнопка паники — всегда за все файлы ключа: файла у неё нет, а направление
    // обязательно. Файл здесь не «необязателен», он ЗАПРЕЩЁН: заморозка одного
    // файла есть отзыв, и у него свой вид.
    let freeze = order.kind == Kind::Freeze;
    required(order.frozen.is_some(), freeze, tag::FROZEN)?;
    if freeze && order.file_id != [0u8; 16] {
        return Err(FormatError::UnknownCriticalField { tag: tag::FILE_ID });
    }

    // Ключ называется ровно там, где по файлу его не взять: у признака жизни за
    // все файлы сразу файла нет вовсе, у кнопки паники — тоже, а у голоса
    // подписывает не автор, и ключ автора, записанный у файла, здесь ни при чём.
    // Доказательство подписки: за все файлы ключа — файла нет, ключ назван,
    // адресат назван.
    let watch = order.kind == Kind::WatchAuthor;
    required(order.authority_key.is_some(), watch, tag::AUTHORITY_KEY)?;
    if watch && order.file_id != [0u8; 16] {
        return Err(FormatError::UnknownCriticalField { tag: tag::FILE_ID });
    }

    // ПОГАШЕНИЕ ГРАНТА: имя гранта обязательно, файла нет вовсе. Файл здесь не
    // «необязателен», он ЗАПРЕЩЁН: грант выдан на поддерево, и веление, названное
    // одним его файлом, означало бы погашение то ли гранта, то ли файла — двух
    // разных судеб под одним документом.
    let revoke_grant = order.kind == Kind::RevokeGrant;
    required(order.grant_id.is_some(), revoke_grant, tag::GRANT_ID)?;
    if revoke_grant && order.file_id != [0u8; 16] {
        return Err(FormatError::UnknownCriticalField { tag: tag::FILE_ID });
    }

    required(
        order.signer_key.is_some(),
        (order.kind == Kind::Alive && order.file_id == [0u8; 16])
            || vote
            || freeze
            || watch
            || revoke_grant,
        tag::SIGNER_KEY,
    )?;

    if let Some(all) = &order.bequests {
        check_bequests(all, order.file_id)?;
    }

    // ЗАМЕНА УСТРОЙСТВА: у своего файла, имена по ОДНОМУ устройству с каждой
    // стороны, и ни одно имя не стоит сразу в обеих. «Заменить устройство им же»
    // — распоряжение, которое ничего не велит, а исполнить его значило бы
    // вычеркнуть устройство и тут же зарезервировать ему место заново.
    let replace = order.kind == Kind::ReplaceDevice;
    required(order.old_devices.is_some(), replace, tag::OLD_DEVICES)?;
    required(order.new_devices.is_some(), replace, tag::NEW_DEVICES)?;
    if replace && order.file_id == [0u8; 16] {
        return Err(FormatError::MissingField { tag: tag::FILE_ID });
    }
    if let (Some(old), Some(new)) = (&order.old_devices, &order.new_devices) {
        check_names(old, tag::OLD_DEVICES)?;
        check_names(new, tag::NEW_DEVICES)?;
        if old.iter().any(|name| new.contains(name)) {
            return Err(FormatError::UnknownCriticalField { tag: tag::NEW_DEVICES });
        }
    }

    // ПРАВИЛО ФАЙЛА: у своего файла и только у своего вида. Само правило
    // проверяется своим кодеком при записи — здесь достаточно присутствия.
    let set_rule = order.kind == Kind::SetRule;
    required(order.rule.is_some(), set_rule, tag::RULE)?;
    if set_rule && order.file_id == [0u8; 16] {
        return Err(FormatError::MissingField { tag: tag::FILE_ID });
    }
    Ok(())
}

/// Device names: one to [`MAX_DEVICE_NAMES`], no duplicates and no zero name.
fn check_names(names: &[[u8; 32]], tag: u16) -> Result<(), FormatError> {
    if names.is_empty() || names.len() > MAX_DEVICE_NAMES {
        return Err(FormatError::BadFieldLength { tag, len: names.len() });
    }
    for (at, name) in names.iter().enumerate() {
        if *name == [0u8; 32] || names.get(at.saturating_add(1)..).is_some_and(|rest| rest.contains(name)) {
            return Err(FormatError::UnknownCriticalField { tag });
        }
    }
    Ok(())
}

/// The roster is satisfiable and contains no person twice.
///
/// A threshold above the key count is a rule nobody can satisfy: the file
/// freezes forever, noticeable only once it has frozen. A duplicate
/// key creates the converse problem: one vote would count twice, allowing a
/// "two of three" threshold with one signature.
///
/// An empty roster with zero threshold is valid and means "no quorum": something
/// must remove a quorum, and no separate kind is needed for that.
fn check_roster(keys: &[[u8; 32]], threshold: u8) -> Result<(), FormatError> {
    if keys.len() > MAX_KEYS {
        return Err(FormatError::BadFieldLength { tag: tag::KEYS, len: keys.len() });
    }
    for (at, key) in keys.iter().enumerate() {
        if keys.get(at.saturating_add(1)..).is_some_and(|rest| rest.contains(key)) {
            return Err(FormatError::UnknownCriticalField { tag: tag::KEYS });
        }
    }
    let wanted = usize::from(threshold);
    let ok = if keys.is_empty() { wanted == 0 } else { wanted >= 1 && wanted <= keys.len() };
    if ok { Ok(()) } else { Err(FormatError::UnknownCriticalField { tag: tag::THRESHOLD }) }
}

/// Bequests are valid author decisions about THIS file, all for different people.
///
/// Parsed here, not only on the server, under I-9: the crate does not release
/// bytes it has not checked. Contents are checked, not the signature: the author's signature
/// covers the complete decision, so their decision about ANOTHER file is correctly
/// signed and indistinguishable by signature from the required one.
///
/// An empty list is rejected: "open the bequest" without a bequest is
/// an unexecutable order. Duplicate fingerprints are rejected too: two decisions for
/// one device would force the server to choose between them,
/// with no basis for choosing.
fn check_bequests(all: &[Vec<u8>], file_id: [u8; 16]) -> Result<(), FormatError> {
    if all.is_empty() || all.len() > MAX_HEIRS {
        return Err(FormatError::BadFieldLength { tag: tag::BEQUEST, len: all.len() });
    }
    let mut seen: Vec<[u8; 32]> = Vec::with_capacity(all.len());
    for bytes in all {
        let decision = crate::access::decode_decision(bytes)?;
        let fits = decision.file_id == file_id
            && decision.seq == crate::access::HEIR_SEQ
            && decision.approve
            && decision.share_b.is_some();
        if !fits {
            return Err(FormatError::UnknownCriticalField { tag: tag::BEQUEST });
        }
        if seen.contains(&decision.device_fpr) {
            return Err(FormatError::UnknownCriticalField { tag: tag::BEQUEST });
        }
        seen.push(decision.device_fpr);
    }
    Ok(())
}

/// Signature transcript: domain label and body as one field.
#[must_use]
pub fn signing_transcript(body: &[u8]) -> oc_crypto::Transcript {
    let mut t = oc_crypto::Transcript::new(oc_crypto::label::AUTHOR_ORDER);
    t.field(body);
    t
}

/// Encode the body.
///
/// # Errors
/// [`FormatError`] if the fields do not match the kind (`check`): such a
/// document has no meaning, and issuing it would create a second interpretation
/// of one body.
pub fn encode(order: &Order) -> Result<Vec<u8>, FormatError> {
    check(order)?;
    let mut w = TlvWriter::new();
    w.put(tag::VERSION, &ORDER_VERSION.to_le_bytes())?;
    w.put(tag::FILE_ID, &order.file_id)?;
    w.put(tag::KIND, &[order.kind as u8])?;
    w.put(tag::AT, &order.at.to_le_bytes())?;
    if let Some(n) = order.max_devices {
        w.put(tag::MAX_DEVICES, &n.to_le_bytes())?;
    }
    if let Some(n) = order.max_grants {
        w.put(tag::MAX_GRANTS, &n.to_le_bytes())?;
    }
    if let Some(keys) = &order.keys {
        let mut flat = Vec::with_capacity(keys.len().saturating_mul(32));
        for key in keys {
            flat.extend_from_slice(key);
        }
        w.put(tag::KEYS, &flat)?;
    }
    if let Some(threshold) = order.threshold {
        w.put(tag::THRESHOLD, &[threshold])?;
    }
    if let Some(fpr) = &order.device_fpr {
        w.put(tag::DEVICE_FPR, fpr)?;
    }
    if let Some(approve) = order.approve {
        w.put(tag::APPROVE, &[u8::from(approve)])?;
    }
    if let Some(n) = order.silence_seconds {
        w.put(tag::SILENCE_SECONDS, &n.to_le_bytes())?;
    }
    if let Some(mode) = order.heir_mode {
        w.put(tag::HEIR_MODE, &[mode as u8])?;
    }
    if let Some(all) = &order.bequests {
        let mut flat = Vec::new();
        for bytes in all {
            let len = u32::try_from(bytes.len())
                .map_err(|_| FormatError::BadFieldLength { tag: tag::BEQUEST, len: bytes.len() })?;
            flat.extend_from_slice(&len.to_le_bytes());
            flat.extend_from_slice(bytes);
        }
        w.put(tag::BEQUEST, &flat)?;
    }
    if let Some(key) = &order.signer_key {
        w.put(tag::SIGNER_KEY, key)?;
    }
    if let Some(n) = order.proposal_ttl {
        w.put(tag::PROPOSAL_TTL, &n.to_le_bytes())?;
    }
    if let Some(frozen) = order.frozen {
        w.put(tag::FROZEN, &[u8::from(frozen)])?;
    }
    for (names, name_tag) in [(&order.old_devices, tag::OLD_DEVICES), (&order.new_devices, tag::NEW_DEVICES)] {
        if let Some(names) = names {
            let flat: Vec<u8> = names.iter().flatten().copied().collect();
            w.put(name_tag, &flat)?;
        }
    }
    if let Some(rule) = &order.rule {
        w.put(tag::RULE, &crate::attribute_rule::encode(rule)?)?;
    }
    if let Some(key) = &order.authority_key {
        w.put(tag::AUTHORITY_KEY, key)?;
    }
    if let Some(grant_id) = &order.grant_id {
        w.put(tag::GRANT_ID, grant_id)?;
    }
    Ok(w.finish().to_vec())
}

/// Parse the body strictly: exact lengths, one version, fields determined by kind.
///
/// # Errors
/// [`FormatError`] for an unknown tag, invalid length, wrong version,
/// unknown kind or fields inconsistent with kind (`check`).
pub fn decode(body: &[u8]) -> Result<Order, FormatError> {
    let mut reader = TlvReader::new(body);
    let mut version = None;
    let mut file_id = None;
    let mut kind = None;
    let mut at = None;
    let mut max_devices = None;
    let mut max_grants = None;
    let mut keys = None;
    let mut threshold = None;
    let mut device_fpr = None;
    let mut approve = None;
    let mut silence_seconds = None;
    let mut heir_mode = None;
    let mut bequests = None;
    let mut signer_key = None;
    let mut proposal_ttl = None;
    let mut frozen = None;
    let mut old_devices = None;
    let mut new_devices = None;
    let mut rule = None;
    let mut authority_key = None;
    let mut grant_id = None;
    while let Some(field) = reader.next_field()? {
        match field.tag {
            tag::VERSION => version = Some(u16_le(field.tag, field.value)?),
            tag::FILE_ID => file_id = Some(exact16(field.tag, field.value)?),
            tag::KIND => {
                let byte = one_byte(tag::KIND, field.value)?;
                kind = Some(
                    Kind::from_byte(byte).ok_or(FormatError::UnknownCriticalField { tag: tag::KIND })?,
                );
            }
            tag::AT => at = Some(u64_le(field.tag, field.value)?.cast_signed()),
            tag::MAX_DEVICES => max_devices = Some(u32_le(field.tag, field.value)?),
            tag::MAX_GRANTS => max_grants = Some(u32_le(field.tag, field.value)?),
            tag::KEYS => keys = Some(split_keys(field.value)?),
            tag::THRESHOLD => threshold = Some(one_byte(tag::THRESHOLD, field.value)?),
            tag::DEVICE_FPR => device_fpr = Some(exact32(field.tag, field.value)?),
            tag::APPROVE => {
                approve = Some(match field.value {
                    [0] => false,
                    [1] => true,
                    other => {
                        return Err(FormatError::BadFieldLength {
                            tag: tag::APPROVE,
                            len: other.len(),
                        });
                    }
                });
            }
            tag::SILENCE_SECONDS => silence_seconds = Some(u64_le(field.tag, field.value)?),
            tag::HEIR_MODE => {
                let byte = one_byte(tag::HEIR_MODE, field.value)?;
                heir_mode = Some(
                    HeirMode::from_byte(byte)
                        .ok_or(FormatError::UnknownCriticalField { tag: tag::HEIR_MODE })?,
                );
            }
            tag::BEQUEST => bequests = Some(split_bequests(field.value)?),
            tag::SIGNER_KEY => signer_key = Some(exact32(field.tag, field.value)?),
            tag::PROPOSAL_TTL => proposal_ttl = Some(u64_le(field.tag, field.value)?),
            tag::FROZEN => {
                frozen = Some(match field.value {
                    [0] => false,
                    [1] => true,
                    other => {
                        return Err(FormatError::BadFieldLength {
                            tag: tag::FROZEN,
                            len: other.len(),
                        });
                    }
                });
            }
            tag::OLD_DEVICES => old_devices = Some(split_names(tag::OLD_DEVICES, field.value)?),
            tag::NEW_DEVICES => new_devices = Some(split_names(tag::NEW_DEVICES, field.value)?),
            tag::RULE => rule = Some(crate::attribute_rule::decode(field.value)?),
            tag::AUTHORITY_KEY => authority_key = Some(exact32(field.tag, field.value)?),
            tag::GRANT_ID => grant_id = Some(exact16(field.tag, field.value)?),
            other => crate::unknown::refuse_if_critical(other)?,
        }
    }
    if version.ok_or(FormatError::MissingField { tag: tag::VERSION })? != ORDER_VERSION {
        return Err(FormatError::UnknownCriticalField { tag: tag::VERSION });
    }
    let order = Order {
        file_id: file_id.ok_or(FormatError::MissingField { tag: tag::FILE_ID })?,
        kind: kind.ok_or(FormatError::MissingField { tag: tag::KIND })?,
        at: at.ok_or(FormatError::MissingField { tag: tag::AT })?,
        max_devices,
        max_grants,
        keys,
        threshold,
        device_fpr,
        approve,
        silence_seconds,
        heir_mode,
        bequests,
        signer_key,
        proposal_ttl,
        frozen,
        old_devices,
        new_devices,
        rule,
        authority_key,
        grant_id,
    };
    check(&order)?;
    Ok(order)
}

/// Order body from signed bytes, WITHOUT signature verification.
///
/// The server needs this to find the verification key by `file_id`:
/// it remembers the author key per file. Returned data is suitable only
/// for key lookup; the order may be executed after [`verify_signed`].
///
/// # Errors
/// [`FormatError`] if bytes are shorter than the signature or the body cannot be parsed.
pub fn peek(bytes: &[u8]) -> Result<Order, FormatError> {
    let (_, body) = bytes.split_at_checked(SIGNATURE_LEN).ok_or(FormatError::BadHeaderSignature)?;
    decode(body)
}

/// INTENT digest: what was ordered, without "when issued" or "who signed".
///
/// # Why it exists
///
/// Coauthor quorum collects signatures from DIFFERENT people on DIFFERENT machines,
/// each signing their own document: they type the same command, their client inserts its own
/// issuance time and key. If the server identified proposals by body hash, two
/// coauthors typing the same command in different seconds would create
/// two different proposals, and quorum would NEVER be reached.
///
/// Hence the rule: a proposal is identified by WHAT is ordered, not when it
/// was said. File, kind and every parameter must match; issuance time and
/// signer key are excluded from the digest, because they belong to the signature,
/// not the intent.
///
/// It is computed using exactly the body encoder: a second serializer for
/// hashing would create a second definition of "the same order" and
/// would diverge on the first newly added line.
///
/// # Errors
/// [`FormatError`] if the order cannot be encoded.
pub fn intent_digest(order: &Order) -> Result<[u8; 32], FormatError> {
    let canonical = Order { at: 0, signer_key: None, ..order.clone() };
    Ok(oc_crypto::sha256(&encode(&canonical)?))
}

/// Order kind from the BARE BODY, without a preceding signature.
///
/// Parsing is strict, as everywhere: unknown kinds are not guessed.
///
/// # Who calls this
///
/// Nobody today; saying so is more honest than omitting it. The function was
/// written for the coauthor proposal list, where kind came from the STORED
/// body; since F-20 item 15 (2026-09-04), the server stores no bodies at all:
/// a proposal is identified by intent (`intent_digest`), and kind is a record
/// field. The previous doc comment outlived that architectural change and
/// continued promising stored bodies.
///
/// # Errors
/// [`FormatError`] if the body cannot be parsed.
pub fn peek_kind(body: &[u8]) -> Result<u8, FormatError> {
    Ok(decode(body)?.kind as u8)
}

/// Verify the body signature with the author key.
///
/// # Errors
/// [`CryptoError`] if the signature does not verify.
pub fn verify(
    body: &[u8],
    signature: &[u8; SIGNATURE_LEN],
    author_key: &[u8; 32],
) -> Result<(), CryptoError> {
    oc_crypto::sign::verify(author_key, &signing_transcript(body), signature)
}

/// Verify and parse the complete signed document.
///
/// # Errors
/// [`FormatError::BadHeaderSignature`] for a short or invalid signature;
/// body parsing errors as in [`decode`].
pub fn verify_signed(bytes: &[u8], author_key: &[u8; 32]) -> Result<Order, FormatError> {
    let (signature, body) =
        bytes.split_at_checked(SIGNATURE_LEN).ok_or(FormatError::BadHeaderSignature)?;
    let signature: [u8; SIGNATURE_LEN] =
        signature.try_into().map_err(|_| FormatError::BadHeaderSignature)?;
    verify(body, &signature, author_key).map_err(|_| FormatError::BadHeaderSignature)?;
    decode(body)
}

fn exact16(tag: u16, value: &[u8]) -> Result<[u8; 16], FormatError> {
    value.try_into().map_err(|_| FormatError::BadFieldLength { tag, len: value.len() })
}

/// Bequest stream: each entry has its own length because decisions vary in size:
/// shares are sealed to different keys, and mechanisms have different `enc` values.
fn split_bequests(mut rest: &[u8]) -> Result<Vec<Vec<u8>>, FormatError> {
    let bad = |len: usize| FormatError::BadFieldLength { tag: tag::BEQUEST, len };
    let mut out = Vec::new();
    while !rest.is_empty() {
        // Предел проверяется В ЦИКЛЕ, до выделения следующей записи: поток в
        // мегабайт иначе заставил бы собрать тысячи решений, чтобы затем их
        // отвергнуть.
        if out.len() >= MAX_HEIRS {
            return Err(bad(out.len().saturating_add(1)));
        }
        let head: [u8; 4] =
            rest.get(..4).and_then(|s| <[u8; 4]>::try_from(s).ok()).ok_or_else(|| bad(rest.len()))?;
        let len = usize::try_from(u32::from_le_bytes(head)).map_err(|_| bad(0))?;
        let end = 4usize.saturating_add(len);
        out.push(rest.get(4..end).ok_or_else(|| bad(len))?.to_vec());
        rest = rest.get(end..).ok_or_else(|| bad(len))?;
    }
    Ok(out)
}

/// Consecutive thirty-two-byte keys.
///
/// Length is checked EXACTLY (I-8): an incorrectly sized tail lets the adversary
/// control which bytes become a key. The key-count limit is checked here too,
/// before any allocation; otherwise a megabyte field would force collecting
/// thirty thousand keys only to reject them afterward.
/// Device names as a stream of 32-byte entries. Limit checked before allocation.
fn split_names(tag: u16, value: &[u8]) -> Result<Vec<[u8; 32]>, FormatError> {
    if value.is_empty() || !value.len().is_multiple_of(32) || value.len() > MAX_DEVICE_NAMES.saturating_mul(32) {
        return Err(FormatError::BadFieldLength { tag, len: value.len() });
    }
    value
        .chunks(32)
        .map(|chunk| <[u8; 32]>::try_from(chunk).map_err(|_| FormatError::BadFieldLength { tag, len: chunk.len() }))
        .collect()
}

fn split_keys(value: &[u8]) -> Result<Vec<[u8; 32]>, FormatError> {
    if !value.len().is_multiple_of(32) || value.len() > MAX_KEYS.saturating_mul(32) {
        return Err(FormatError::BadFieldLength { tag: tag::KEYS, len: value.len() });
    }
    let mut out = Vec::with_capacity(value.len() / 32);
    for chunk in value.chunks(32) {
        out.push(
            <[u8; 32]>::try_from(chunk)
                .map_err(|_| FormatError::BadFieldLength { tag: tag::KEYS, len: chunk.len() })?,
        );
    }
    Ok(out)
}

fn exact32(tag: u16, value: &[u8]) -> Result<[u8; 32], FormatError> {
    value.try_into().map_err(|_| FormatError::BadFieldLength { tag, len: value.len() })
}

fn one_byte(tag: u16, value: &[u8]) -> Result<u8, FormatError> {
    match value {
        [b] => Ok(*b),
        other => Err(FormatError::BadFieldLength { tag, len: other.len() }),
    }
}

fn u16_le(tag: u16, value: &[u8]) -> Result<u16, FormatError> {
    let bytes: [u8; 2] =
        value.try_into().map_err(|_| FormatError::BadFieldLength { tag, len: value.len() })?;
    Ok(u16::from_le_bytes(bytes))
}

fn u32_le(tag: u16, value: &[u8]) -> Result<u32, FormatError> {
    let bytes: [u8; 4] =
        value.try_into().map_err(|_| FormatError::BadFieldLength { tag, len: value.len() })?;
    Ok(u32::from_le_bytes(bytes))
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

    fn signed(order: &Order, signer: &Ed25519Signer) -> Vec<u8> {
        let body = encode(order).unwrap();
        let sig = signer.sign(&signing_transcript(&body)).unwrap();
        let mut out = sig.to_vec();
        out.extend_from_slice(&body);
        out
    }

    fn register() -> Order {
        Order { max_devices: Some(3), ..Order::new([0x5a; 16], Kind::Register, 1_756_000_000) }
    }

    /// The author's signature verifies with their key and no other; corrupt
    /// signatures, corrupt bodies and truncation are rejected.
    #[test]
    fn a_signed_order_verifies_with_the_author_key_and_nothing_else_passes() {
        let author = Ed25519Signer::from_seed(&[0x41; 32]);
        let stranger = Ed25519Signer::from_seed(&[0x42; 32]);
        let order = register();
        let bytes = signed(&order, &author);

        assert_eq!(verify_signed(&bytes, &author.public_key()).unwrap(), order);
        assert_eq!(peek(&bytes).unwrap(), order, "заглянуть в тело можно и без ключа");
        assert!(verify_signed(&bytes, &stranger.public_key()).is_err(), "чужой ключ принят");

        let mut bad_sig = bytes.clone();
        bad_sig[10] ^= 1;
        assert!(verify_signed(&bad_sig, &author.public_key()).is_err(), "битая подпись принята");

        let mut bad_body = bytes.clone();
        let last = bad_body.len() - 1;
        bad_body[last] ^= 1;
        assert!(verify_signed(&bad_body, &author.public_key()).is_err(), "битое тело принято");

        assert!(verify_signed(&bytes[..40], &author.public_key()).is_err(), "обрубок принят");
        assert!(peek(&bytes[..40]).is_err(), "обрубок разобран");
    }

    /// THE SIGNATURE IS VERIFIED BEFORE BODY PARSING: a guard on two lines' order.
    ///
    /// The test above supplies a parseable body, while parsing tests call [`decode`]
    /// directly; moving `decode` before `verify` inside [`verify_signed`]
    /// broke none of them. Here the body is deliberately unparseable and the signature
    /// deliberately wrong: the only correct answer is `BadHeaderSignature`. A parsing
    /// code would mean unauthenticated bytes had already been read and distinguishable
    /// responses were returned about them (I-5 for documents).
    #[test]
    fn the_signature_is_checked_before_the_body_is_parsed() {
        let author = Ed25519Signer::from_seed(&[0x41; 32]);
        let stranger = Ed25519Signer::from_seed(&[0x42; 32]);

        let empty = TlvWriter::new().finish().to_vec();
        let mut w = TlvWriter::new();
        w.put(0x7FFF, &[0xab; 4]).unwrap();
        let unknown_critical = w.finish().to_vec();

        for (what, body) in [("пустое тело", empty), ("чужой критичный тег", unknown_critical)] {
            assert!(decode(&body).is_err(), "{what}: предпосылка пробы неверна, тело разбирается");
            let sig = stranger.sign(&signing_transcript(&body)).unwrap();
            let mut bytes = sig.to_vec();
            bytes.extend_from_slice(&body);
            let outcome = verify_signed(&bytes, &author.public_key());
            assert!(
                matches!(outcome, Err(FormatError::BadHeaderSignature)),
                "{what}: разбор произошёл до проверки подписи, ответ {outcome:?}"
            );
        }
    }

    /// Revocation without limits passes; revocation with limits can neither be encoded nor
    /// parsed: one body must not have two interpretations.
    #[test]
    fn a_revocation_carries_no_limits() {
        let revoke = Order::new([1; 16], Kind::Revoke, 7);
        assert_eq!(decode(&encode(&revoke).unwrap()).unwrap(), revoke);

        let with_limits = Order { max_grants: Some(1), ..revoke };
        assert!(encode(&with_limits).is_err(), "отзыв с пределом закодирован");

        let mut w = TlvWriter::new();
        w.put(tag::VERSION, &ORDER_VERSION.to_le_bytes()).unwrap();
        w.put(tag::FILE_ID, &[1; 16]).unwrap();
        w.put(tag::KIND, &[Kind::Revoke as u8]).unwrap();
        w.put(tag::AT, &7i64.to_le_bytes()).unwrap();
        w.put(tag::MAX_GRANTS, &1u32.to_le_bytes()).unwrap();
        assert!(decode(&w.finish()).is_err(), "отзыв с пределом разобран");
    }

    /// Body parsing is strict: a short identifier, wrong version and
    /// unknown kind are rejected.
    #[test]
    fn the_body_is_parsed_strictly() {
        let order = register();
        assert_eq!(decode(&encode(&order).unwrap()).unwrap(), order);

        let mut w = TlvWriter::new();
        w.put(tag::VERSION, &ORDER_VERSION.to_le_bytes()).unwrap();
        w.put(tag::FILE_ID, &[1; 15]).unwrap();
        w.put(tag::KIND, &[1]).unwrap();
        w.put(tag::AT, &0i64.to_le_bytes()).unwrap();
        assert!(decode(&w.finish()).is_err(), "короткий идентификатор дополнен");

        let mut w = TlvWriter::new();
        w.put(tag::VERSION, &2u16.to_le_bytes()).unwrap();
        w.put(tag::FILE_ID, &[1; 16]).unwrap();
        w.put(tag::KIND, &[1]).unwrap();
        w.put(tag::AT, &0i64.to_le_bytes()).unwrap();
        assert!(decode(&w.finish()).is_err(), "чужая версия принята");

        let mut w = TlvWriter::new();
        w.put(tag::VERSION, &ORDER_VERSION.to_le_bytes()).unwrap();
        w.put(tag::FILE_ID, &[1; 16]).unwrap();
        w.put(tag::KIND, &[9]).unwrap();
        w.put(tag::AT, &0i64.to_le_bytes()).unwrap();
        assert!(decode(&w.finish()).is_err(), "неизвестный вид принят");
    }

    /// A body bypassing checks, giving `decode` something to reject.
    ///
    /// Without this helper, there is no source of forbidden bodies: `encode` refuses to
    /// issue them, but PARSING must be tested for bodies received externally
    /// from a peer that did not call our writer.
    fn hand_written(order: &Order) -> Vec<u8> {
        let mut w = TlvWriter::new();
        w.put(tag::VERSION, &ORDER_VERSION.to_le_bytes()).unwrap();
        w.put(tag::FILE_ID, &order.file_id).unwrap();
        w.put(tag::KIND, &[order.kind as u8]).unwrap();
        w.put(tag::AT, &order.at.to_le_bytes()).unwrap();
        if let Some(n) = order.max_devices {
            w.put(tag::MAX_DEVICES, &n.to_le_bytes()).unwrap();
        }
        if let Some(n) = order.max_grants {
            w.put(tag::MAX_GRANTS, &n.to_le_bytes()).unwrap();
        }
        if let Some(keys) = &order.keys {
            let mut flat = Vec::new();
            for k in keys {
                flat.extend_from_slice(k);
            }
            w.put(tag::KEYS, &flat).unwrap();
        }
        if let Some(t) = order.threshold {
            w.put(tag::THRESHOLD, &[t]).unwrap();
        }
        if let Some(f) = &order.device_fpr {
            w.put(tag::DEVICE_FPR, f).unwrap();
        }
        if let Some(a) = order.approve {
            w.put(tag::APPROVE, &[u8::from(a)]).unwrap();
        }
        if let Some(n) = order.silence_seconds {
            w.put(tag::SILENCE_SECONDS, &n.to_le_bytes()).unwrap();
        }
        if let Some(m) = order.heir_mode {
            w.put(tag::HEIR_MODE, &[m as u8]).unwrap();
        }
        if let Some(all) = &order.bequests {
            let mut flat = Vec::new();
            for b in all {
                flat.extend_from_slice(&u32::try_from(b.len()).unwrap().to_le_bytes());
                flat.extend_from_slice(b);
            }
            w.put(tag::BEQUEST, &flat).unwrap();
        }
        if let Some(k) = &order.signer_key {
            w.put(tag::SIGNER_KEY, k).unwrap();
        }
        if let Some(n) = order.proposal_ttl {
            w.put(tag::PROPOSAL_TTL, &n.to_le_bytes()).unwrap();
        }
        w.finish().to_vec()
    }

    /// A bequest is an ordinary author decision with a reserved number.
    fn bequest_for(file_id: [u8; 16], device_fpr: [u8; 32]) -> Vec<u8> {
        crate::access::encode_decision(&crate::access::Decision {
            seq: crate::access::HEIR_SEQ,
            file_id,
            device_fpr,
            approve: true,
            share_b: Some(crate::access::Blob {
                enc: vec![0x11; 32],
                nonce: [0x22; 24],
                ct: vec![0x33; 48],
            }),
            author_key: [0x44; 32],
            signature: [0x55; 64],
        })
        .unwrap()
    }

    fn set_heir(file_id: [u8; 16], mode: HeirMode) -> Order {
        Order {
            heir_mode: Some(mode),
            // Тридцать суток.
            silence_seconds: match mode {
                HeirMode::Off => None,
                _ => Some(2_592_000),
            },
            bequests: match mode {
                HeirMode::Open => Some(vec![bequest_for(file_id, [0x77; 32])]),
                _ => None,
            },
            ..Order::new(file_id, Kind::SetHeir, 1_756_000_000)
        }
    }

    /// THE BEQUEST TRAVELS AS ONE VALUE AND RETURNS UNCHANGED.
    ///
    /// The encoding round trip checks not simply that "serialization works", but that
    /// the author's decision has not been scattered across order fields: the server must
    /// give the heir READY-MADE bytes rather than reconstructing the decision; reconstruction
    /// would not match the author's signature over the entire decision.
    #[test]
    fn a_bequest_travels_whole_inside_the_order() {
        let author = Ed25519Signer::from_seed(&[0x41; 32]);
        for mode in [HeirMode::Open, HeirMode::Close, HeirMode::Off] {
            let order = set_heir([0x5a; 16], mode);
            let bytes = signed(&order, &author);
            assert_eq!(
                verify_signed(&bytes, &author.public_key()).unwrap(),
                order,
                "распоряжение о наследнике не пережило круг: {mode:?}"
            );
        }
    }

    /// BEQUESTS BELONG ONLY TO THE OPENING MODE.
    ///
    /// Opening without a bequest is unexecutable; closing
    /// with a bequest gives the body two interpretations at once ("close for everyone" and "open
    /// for the heir"). Both are rejected in both directions: what we refuse to
    /// issue, we must also refuse to execute.
    #[test]
    fn a_bequest_belongs_to_an_opening_heir_and_nowhere_else() {
        let file_id = [0x5a; 16];

        let mut naked = set_heir(file_id, HeirMode::Open);
        naked.bequests = None;
        assert!(encode(&naked).is_err(), "открытие без завещания закодировано");
        assert!(decode(&hand_written(&naked)).is_err(), "открытие без завещания разобрано");

        let mut extra = set_heir(file_id, HeirMode::Close);
        extra.bequests = Some(vec![bequest_for(file_id, [0x77; 32])]);
        assert!(encode(&extra).is_err(), "закрытие с завещанием закодировано");
        assert!(decode(&hand_written(&extra)).is_err(), "закрытие с завещанием разобрано");

        let mut off = set_heir(file_id, HeirMode::Off);
        off.silence_seconds = Some(86_400);
        assert!(encode(&off).is_err(), "снятие со сроком закодировано");
        assert!(decode(&hand_written(&off)).is_err(), "снятие со сроком разобрано");

        // Завещание О ДРУГОМ ФАЙЛЕ отвергается ЗДЕСЬ, а не на сервере: подпись
        // автора покрывает решение целиком, поэтому чужое решение о чужом файле
        // подписано верно и от своего по подписи неотличимо.
        let mut alien = set_heir(file_id, HeirMode::Open);
        alien.bequests = Some(vec![bequest_for([0x99; 16], [0x77; 32])]);
        assert!(encode(&alien).is_err(), "завещание о другом файле закодировано");
        assert!(decode(&hand_written(&alien)).is_err(), "завещание о другом файле разобрано");

        // Номер очереди у завещания зарезервирован: с обычным номером оно встало
        // бы в очередь решений и заняло чужое место в ней.
        let mut numbered = set_heir(file_id, HeirMode::Open);
        numbered.bequests = Some(vec![
            crate::access::encode_decision(&crate::access::Decision {
                seq: 3,
                ..crate::access::decode_decision(&bequest_for(file_id, [0x77; 32])).unwrap()
            })
            .unwrap(),
        ]);
        assert!(encode(&numbered).is_err(), "завещание с очередным номером закодировано");
        assert!(decode(&hand_written(&numbered)).is_err(), "оно же разобрано");

        // Отказ вместо одобрения — распоряжение, которое нечего открывать.
        let mut refusal = set_heir(file_id, HeirMode::Open);
        refusal.bequests = Some(vec![
            crate::access::encode_decision(&crate::access::Decision {
                approve: false,
                share_b: None,
                ..crate::access::decode_decision(&bequest_for(file_id, [0x77; 32])).unwrap()
            })
            .unwrap(),
        ]);
        assert!(encode(&refusal).is_err(), "завещание с отказом закодировано");
        assert!(decode(&hand_written(&refusal)).is_err(), "оно же разобрано");
    }

    /// PROOF OF LIFE FOR ALL FILES MUST NAME THE KEY.
    ///
    /// Zero `file_id` means "all files under this key"; without the key in the body,
    /// the server cannot know whose presence is recorded: it verifies signatures with a key
    /// looked up BY FILE, and there is no file here. The converse is also forbidden:
    /// a key alongside a named file would be a second way to say the same thing.
    #[test]
    fn a_sign_of_life_for_every_file_names_the_key() {
        let alive_all = Order { signer_key: Some([0x41; 32]), ..Order::new([0; 16], Kind::Alive, 9) };
        assert_eq!(decode(&encode(&alive_all).unwrap()).unwrap(), alive_all);

        let mut nameless = alive_all.clone();
        nameless.signer_key = None;
        assert!(encode(&nameless).is_err(), "признак жизни за все файлы без ключа закодирован");
        assert!(decode(&hand_written(&nameless)).is_err(), "он же разобран");

        let one = Order::new([0x5a; 16], Kind::Alive, 9);
        assert_eq!(decode(&encode(&one).unwrap()).unwrap(), one);

        let both = Order { signer_key: Some([0x41; 32]), ..one };
        assert!(encode(&both).is_err(), "названы и файл, и ключ");
        assert!(decode(&hand_written(&both)).is_err(), "они же разобраны");

        // Ключ автора — только у признака жизни: у отзыва он был бы третьим
        // мнением о том, кто автор, рядом с записью файла и подписью.
        let revoke = Order { signer_key: Some([0x41; 32]), ..Order::new([0; 16], Kind::Revoke, 9) };
        assert!(encode(&revoke).is_err(), "ключ автора принят в отзыве");
        assert!(decode(&hand_written(&revoke)).is_err(), "он же разобран");
    }

    fn keys_of(n: u8) -> Vec<[u8; 32]> {
        (0..n).map(|i| [i.saturating_add(1); 32]).collect()
    }

    fn set_keys(kind: Kind, n: u8, threshold: u8) -> Order {
        Order {
            keys: Some(keys_of(n)),
            threshold: Some(threshold),
            ..Order::new([0x5a; 16], kind, 1_756_000_000)
        }
    }

    /// ROSTER AND THRESHOLD TRAVEL TOGETHER AND ROUND-TRIP UNCHANGED.
    #[test]
    fn a_roster_and_its_threshold_survive_the_round_trip() {
        let author = Ed25519Signer::from_seed(&[0x41; 32]);
        for kind in [Kind::SetCoauthors, Kind::SetApprovers] {
            for (n, threshold) in [(1u8, 1u8), (3, 2), (16, 16), (0, 0)] {
                let order = set_keys(kind, n, threshold);
                let bytes = signed(&order, &author);
                assert_eq!(
                    verify_signed(&bytes, &author.public_key()).unwrap(),
                    order,
                    "состав {n} с порогом {threshold} не пережил круг"
                );
            }
        }
    }

    /// THE ROSTER MUST BE ABLE TO SATISFY THE THRESHOLD.
    ///
    /// A threshold above the key count is a rule nobody can satisfy:
    /// the file freezes forever, noticeable only once it has frozen.
    /// Rejected in BOTH directions: what we refuse to issue, we must
    /// also refuse to execute.
    #[test]
    fn a_threshold_must_be_reachable_by_its_roster() {
        assert!(encode(&set_keys(Kind::SetCoauthors, 3, 4)).is_err(), "порог 4 из 3 закодирован");
        assert!(
            decode(&hand_written(&set_keys(Kind::SetCoauthors, 3, 4))).is_err(),
            "порог 4 из 3 разобран"
        );
        assert!(encode(&set_keys(Kind::SetCoauthors, 3, 0)).is_err(), "нулевой порог при составе");
        assert!(encode(&set_keys(Kind::SetCoauthors, 0, 1)).is_err(), "порог 1 при пустом составе");

        // Пустой состав с нулевым порогом — законное «снять кворум».
        assert!(encode(&set_keys(Kind::SetApprovers, 0, 0)).is_ok(), "снятие кворума отвергнуто");

        // Больше шестнадцати ключей не берётся: столько же, сколько адресов
        // сервера в заголовке, и по той же причине — величина, которую человек
        // в состоянии просмотреть глазами.
        let too_many = Order {
            keys: Some((0..17u8).map(|i| [i.saturating_add(1); 32]).collect()),
            threshold: Some(1),
            ..Order::new([0x5a; 16], Kind::SetCoauthors, 9)
        };
        assert!(encode(&too_many).is_err(), "семнадцать ключей закодированы");
        assert_eq!(MAX_KEYS, 16);

        // ПОВТОР КЛЮЧА — отказ. Иначе один человек считался бы за двоих, и порог
        // «двое из трёх» исполнялся бы одной подписью.
        let twice = Order {
            keys: Some(vec![[7u8; 32], [7u8; 32], [9u8; 32]]),
            threshold: Some(2),
            ..Order::new([0x5a; 16], Kind::SetCoauthors, 9)
        };
        assert!(encode(&twice).is_err(), "повторённый ключ закодирован");
        assert!(decode(&hand_written(&twice)).is_err(), "повторённый ключ разобран");
    }

    /// A DEVICE VOTE CARRIES A FINGERPRINT AND DECISION, NOTHING ELSE.
    #[test]
    fn a_vote_carries_a_fingerprint_and_a_verdict() {
        let author = Ed25519Signer::from_seed(&[0x41; 32]);
        for approve in [true, false] {
            let order = Order {
                device_fpr: Some([0x77; 32]),
                approve: Some(approve),
                signer_key: Some(author.public_key()),
                ..Order::new([0x5a; 16], Kind::ApproveDevice, 1_756_000_000)
            };
            let bytes = signed(&order, &author);
            assert_eq!(verify_signed(&bytes, &author.public_key()).unwrap(), order);
        }

        // ГОЛОС ОБЯЗАН НАЗВАТЬ СВОЙ КЛЮЧ. Подписывает не автор, а член состава, и
        // по файлу его ключ не найти: сервер помнит у файла ключ АВТОРА.
        let unsigned = Order {
            device_fpr: Some([0x77; 32]),
            approve: Some(true),
            ..Order::new([0x5a; 16], Kind::ApproveDevice, 9)
        };
        assert!(encode(&unsigned).is_err(), "голос без имени голосующего закодирован");
        assert!(decode(&hand_written(&unsigned)).is_err(), "он же разобран");

        // Без отпечатка голосовать не за что.
        let naked = Order {
            signer_key: Some([0x41; 32]),
            ..Order::new([0x5a; 16], Kind::ApproveDevice, 9)
        };
        assert!(encode(&naked).is_err(), "голос без отпечатка закодирован");
        assert!(decode(&hand_written(&naked)).is_err(), "голос без отпечатка разобран");

        // Отпечаток у чужого вида — запрещён: два способа сказать одно.
        let stray = Order {
            device_fpr: Some([0x77; 32]),
            approve: Some(true),
            ..Order::new([0x5a; 16], Kind::Revoke, 9)
        };
        assert!(encode(&stray).is_err(), "голос приделан к отзыву");
        assert!(decode(&hand_written(&stray)).is_err(), "он же разобран");
    }

    /// LIMITS BELONG TO REGISTRATION AND LIMIT CHANGES, NOWHERE ELSE.
    ///
    /// A limit change without any limit is an order that commands
    /// nothing: it cannot be executed, and accepting it would journal
    /// an event that never happened.
    #[test]
    fn limits_belong_to_registration_and_to_the_order_that_changes_them() {
        let change = Order {
            max_devices: Some(5),
            ..Order::new([0x5a; 16], Kind::SetLimits, 1_756_000_000)
        };
        assert_eq!(decode(&encode(&change).unwrap()).unwrap(), change);

        let both = Order { max_grants: Some(2), ..change.clone() };
        assert_eq!(decode(&encode(&both).unwrap()).unwrap(), both);

        let empty = Order::new([0x5a; 16], Kind::SetLimits, 9);
        assert!(encode(&empty).is_err(), "смена пределов без пределов закодирована");
        assert!(decode(&hand_written(&empty)).is_err(), "она же разобрана");

        let on_alive = Order {
            max_devices: Some(1),
            signer_key: Some([0x41; 32]),
            ..Order::new([0; 16], Kind::Alive, 9)
        };
        assert!(encode(&on_alive).is_err(), "предел приделан к признаку жизни");
    }

    /// A ROSTER CANNOT BE ATTACHED TO ANOTHER KIND; KEY LENGTHS ARE EXACT.
    #[test]
    fn a_roster_belongs_only_to_the_orders_that_set_one() {
        let stray = Order {
            keys: Some(keys_of(2)),
            threshold: Some(1),
            ..Order::new([0x5a; 16], Kind::Revoke, 9)
        };
        assert!(encode(&stray).is_err(), "состав приделан к отзыву");
        assert!(decode(&hand_written(&stray)).is_err(), "он же разобран");

        // Ключи идут подряд по тридцать два байта; хвост не той длины означает,
        // что противник управляет тем, какие байты станут ключом (И-8).
        let mut w = TlvWriter::new();
        w.put(tag::VERSION, &ORDER_VERSION.to_le_bytes()).unwrap();
        w.put(tag::FILE_ID, &[0x5a; 16]).unwrap();
        w.put(tag::KIND, &[Kind::SetCoauthors as u8]).unwrap();
        w.put(tag::AT, &9i64.to_le_bytes()).unwrap();
        w.put(tag::KEYS, &[7u8; 33]).unwrap();
        w.put(tag::THRESHOLD, &[1]).unwrap();
        assert!(decode(&w.finish()).is_err(), "тридцать три байта приняты за ключ");

        // Порог — ровно один байт.
        let mut w = TlvWriter::new();
        w.put(tag::VERSION, &ORDER_VERSION.to_le_bytes()).unwrap();
        w.put(tag::FILE_ID, &[0x5a; 16]).unwrap();
        w.put(tag::KIND, &[Kind::SetCoauthors as u8]).unwrap();
        w.put(tag::AT, &9i64.to_le_bytes()).unwrap();
        w.put(tag::KEYS, &[7u8; 32]).unwrap();
        w.put(tag::THRESHOLD, &[1, 0]).unwrap();
        assert!(decode(&w.finish()).is_err(), "двухбайтовый порог принят");
    }

    /// THE PANIC BUTTON ORDERS ALL FILES UNDER A KEY, LIKE PROOF OF LIFE.
    ///
    /// Zero `file_id` and signer key are required: freezing concerns
    /// the author, not a file; it has no file. The `frozen` field belongs only to this kind.
    #[test]
    fn a_freeze_covers_every_file_of_the_key_and_carries_its_direction() {
        let freeze = Order {
            signer_key: Some([0x41; 32]),
            frozen: Some(true),
            ..Order::new([0; 16], Kind::Freeze, 9)
        };
        let bytes = encode(&freeze).unwrap();
        assert_eq!(decode(&bytes).unwrap(), freeze);
        let thaw = Order { frozen: Some(false), ..freeze.clone() };
        assert_eq!(decode(&encode(&thaw).unwrap()).unwrap(), thaw);

        // Без направления — распоряжение, которое ничего не велит.
        let blank = Order { frozen: None, ..freeze.clone() };
        assert!(encode(&blank).is_err(), "заморозка без направления закодирована");
        // Без ключа — проверять подпись нечем: файла нет.
        let nameless = Order { signer_key: None, ..freeze.clone() };
        assert!(encode(&nameless).is_err(), "заморозка без ключа закодирована");
        // На один файл — не этот вид: файл отзывают, автора замораживают.
        let one = Order { ..Order::new([0x5a; 16], Kind::Freeze, 9) };
        let one = Order { signer_key: Some([0x41; 32]), frozen: Some(true), ..one };
        assert!(encode(&one).is_err(), "заморозка одного файла закодирована");
        // Направление у чужого вида — отказ.
        let stray = Order { frozen: Some(true), ..Order::new([0x5a; 16], Kind::Revoke, 9) };
        assert!(encode(&stray).is_err(), "frozen у отзыва закодирован");
    }

    /// PROPOSAL LIFETIME IS A FILE SETTING, NOT A PRODUCT CONSTANT.
    ///
    /// Customer decision of 2026-09-05: three days by default, any duration set by the author.
    /// An absent tag means "server default", not "zero": a file
    /// with no specified lifetime behaves as before, and old state records
    /// are read by a new build without qualifications.
    ///
    /// Zero is rejected: the lifetime can be changed, not removed. Proposals without
    /// expiration would accumulate forever on the server and resurface a month later when irrelevant,
    /// precisely the problem lifetime limits prevent.
    #[test]
    fn a_proposal_ttl_belongs_to_the_roster_and_cannot_be_zero() {
        let author = Ed25519Signer::from_seed(&[0x41; 32]);
        let with = Order {
            proposal_ttl: Some(5 * 86_400),
            ..set_keys(Kind::SetCoauthors, 2, 2)
        };
        let bytes = signed(&with, &author);
        assert_eq!(verify_signed(&bytes, &author.public_key()).unwrap(), with, "срок не пережил круг");

        // Без срока — законно и означает «как у сервера».
        let without = set_keys(Kind::SetCoauthors, 2, 2);
        assert_eq!(decode(&encode(&without).unwrap()).unwrap(), without);

        let zero = Order { proposal_ttl: Some(0), ..set_keys(Kind::SetCoauthors, 2, 2) };
        assert!(encode(&zero).is_err(), "нулевой срок закодирован");
        assert!(decode(&hand_written(&zero)).is_err(), "нулевой срок разобран");

        // Срок — только у состава СОАВТОРОВ: у одобряющих предложений нет вовсе,
        // им нечему протухать.
        let approvers = Order {
            proposal_ttl: Some(86_400),
            ..set_keys(Kind::SetApprovers, 2, 2)
        };
        assert!(encode(&approvers).is_err(), "срок приделан к составу одобряющих");
        assert!(decode(&hand_written(&approvers)).is_err(), "он же разобран");

        let stray = Order { proposal_ttl: Some(86_400), ..Order::new([0x5a; 16], Kind::Revoke, 9) };
        assert!(encode(&stray).is_err(), "срок приделан к отзыву");
        assert!(decode(&hand_written(&stray)).is_err(), "он же разобран");
    }

    /// THERE MAY BE MULTIPLE HEIRS, ALL DISTINCT.
    ///
    /// Customer decision of 2026-09-05. One heir is not a special case but a
    /// one-entry stream; the neighboring test ensures that this extension does not become
    /// a new document kind for the old case.
    ///
    /// Duplicate fingerprints are rejected: two decisions for one device would force
    /// the server to choose between them with no basis. An empty list
    /// is rejected too: "open the bequest" without a bequest is unexecutable.
    #[test]
    fn several_heirs_travel_together_and_all_of_them_differ() {
        let author = Ed25519Signer::from_seed(&[0x41; 32]);
        let file_id = [0x5a; 16];

        let three = Order {
            bequests: Some(
                (1..=3u8).map(|n| bequest_for(file_id, [n; 32])).collect(),
            ),
            ..set_heir(file_id, HeirMode::Open)
        };
        let bytes = signed(&three, &author);
        assert_eq!(
            verify_signed(&bytes, &author.public_key()).unwrap(),
            three,
            "трое наследников не пережили круг"
        );

        // Один — тот же путь, а не особый случай.
        let one = set_heir(file_id, HeirMode::Open);
        assert_eq!(decode(&encode(&one).unwrap()).unwrap(), one);

        let twice = Order {
            bequests: Some(vec![
                bequest_for(file_id, [7; 32]),
                bequest_for(file_id, [7; 32]),
            ]),
            ..set_heir(file_id, HeirMode::Open)
        };
        assert!(encode(&twice).is_err(), "два завещания одному устройству закодированы");
        assert!(decode(&hand_written(&twice)).is_err(), "они же разобраны");

        let none = Order { bequests: Some(Vec::new()), ..set_heir(file_id, HeirMode::Open) };
        assert!(encode(&none).is_err(), "пустой список завещаний закодирован");
        assert!(decode(&hand_written(&none)).is_err(), "он же разобран");

        // Семнадцатый отвергается, шестнадцать проходят: предел тот же, что у
        // состава, и по той же причине — список читает человек.
        let many = |n: u8| Order {
            bequests: Some((1..=n).map(|k| bequest_for(file_id, [k; 32])).collect()),
            ..set_heir(file_id, HeirMode::Open)
        };
        assert!(encode(&many(16)).is_ok(), "шестнадцать наследников отвергнуты");
        assert!(encode(&many(17)).is_err(), "семнадцать наследников приняты");
        assert_eq!(MAX_HEIRS, 16);

        // ОДНО НЕГОДНОЕ ЗАВЕЩАНИЕ ПОРТИТ ВЕСЬ СПИСОК, и это верно: принять его
        // частью значило бы исполнить распоряжение не так, как автор подписал.
        let mixed = Order {
            bequests: Some(vec![
                bequest_for(file_id, [1; 32]),
                bequest_for([0x99; 16], [2; 32]),
            ]),
            ..set_heir(file_id, HeirMode::Open)
        };
        assert!(encode(&mixed).is_err(), "чужой файл в списке принят");
        assert!(decode(&hand_written(&mixed)).is_err(), "он же разобран");
    }

    /// DEVICE REPLACEMENT: ENCODING ROUND TRIP AND FIELD SET BY KIND.
    #[test]
    fn an_author_scope_proof_names_its_server_and_no_file() {
        let proof = Order {
            signer_key: Some([0x0a; 32]),
            authority_key: Some([0x0b; 32]),
            ..Order::new([0u8; 16], Kind::WatchAuthor, 1_758_000_000)
        };
        let bytes = encode(&proof).unwrap();
        assert_eq!(decode(&bytes).unwrap(), proof);

        let bad = |order: Order, why: &str| assert!(encode(&order).is_err(), "записано: {why}");
        bad(Order { authority_key: None, ..proof.clone() }, "без адресата");
        bad(Order { signer_key: None, ..proof.clone() }, "без ключа автора");
        bad(Order { file_id: [1; 16], ..proof.clone() }, "с файлом");
        // Адресат — только у доказательства подписки.
        bad(
            Order { authority_key: Some([0x0b; 32]), ..Order::new([1; 16], Kind::Revoke, 1) },
            "адресат у отзыва",
        );
    }

    #[test]
    fn a_device_replacement_order_round_trips_and_its_names_are_checked() {
        let file_id = [0x6b; 16];
        let at = 1_760_000_000;
        let good = Order {
            old_devices: Some(vec![[0x01; 32], [0x02; 32]]),
            new_devices: Some(vec![[0x03; 32]]),
            ..Order::new(file_id, Kind::ReplaceDevice, at)
        };
        let author = Ed25519Signer::from_seed(&[0x41; 32]);
        let bytes = signed(&good, &author);
        assert_eq!(verify_signed(&bytes, &author.public_key()).unwrap(), good, "замена не пережила круг");

        let bad = |order: Order, why: &str| assert!(encode(&order).is_err(), "принята замена: {why}");
        bad(Order { new_devices: Some(vec![[0x03; 32]]), ..Order::new(file_id, Kind::ReplaceDevice, at) }, "без прежних");
        bad(Order { old_devices: Some(vec![[0x01; 32]]), ..Order::new(file_id, Kind::ReplaceDevice, at) }, "без новых");
        bad(Order { old_devices: Some(vec![]), new_devices: Some(vec![[0x03; 32]]), ..Order::new(file_id, Kind::ReplaceDevice, at) }, "пустые прежние");
        bad(Order { old_devices: Some(vec![[0x01; 32]; 2]), new_devices: Some(vec![[0x03; 32]]), ..Order::new(file_id, Kind::ReplaceDevice, at) }, "повтор имени");
        bad(Order { old_devices: Some(vec![[0x01; 32]]), new_devices: Some(vec![[0x01; 32]]), ..Order::new(file_id, Kind::ReplaceDevice, at) }, "устройство заменено им же");
        bad(Order { old_devices: Some(vec![[0u8; 32]]), new_devices: Some(vec![[0x03; 32]]), ..Order::new(file_id, Kind::ReplaceDevice, at) }, "нулевое имя");
        bad(
            Order { old_devices: Some((1..=5u8).map(|b| [b; 32]).collect()), new_devices: Some(vec![[0x09; 32]]), ..Order::new(file_id, Kind::ReplaceDevice, at) },
            "больше четырёх имён",
        );
        bad(Order { old_devices: Some(vec![[0x01; 32]]), new_devices: Some(vec![[0x03; 32]]), ..Order::new([0u8; 16], Kind::ReplaceDevice, at) }, "без файла");
        bad(Order { old_devices: Some(vec![[0x01; 32]]), ..Order::new(file_id, Kind::Revoke, at) }, "имена у чужого вида");

        // Имена у чужого вида не проходят и разбором — тело, собранное руками.
        let mut w = TlvWriter::new();
        w.put(tag::VERSION, &ORDER_VERSION.to_le_bytes()).unwrap();
        w.put(tag::FILE_ID, &file_id).unwrap();
        w.put(tag::KIND, &[Kind::Revoke as u8]).unwrap();
        w.put(tag::AT, &at.to_le_bytes()).unwrap();
        w.put(tag::OLD_DEVICES, &[0x01; 32]).unwrap();
        assert!(decode(&w.finish()).is_err(), "имена устройства у отзыва разобраны");
    }

    /// AGENT GRANT REVOCATION: grant name required, no file, key named.
    ///
    /// The field set is checked in BOTH directions, by encoder and parser:
    /// an order we refuse to issue must not be executed either
    /// when received externally.
    #[test]
    fn a_grant_revocation_round_trips_and_its_fields_are_checked_by_kind() {
        let at = 1_760_000_000;
        let author = Ed25519Signer::from_seed(&[0x41; 32]);
        let good = Order {
            grant_id: Some([0x67; 16]),
            signer_key: Some(author.public_key()),
            ..Order::new([0u8; 16], Kind::RevokeGrant, at)
        };
        let bytes = signed(&good, &author);
        assert_eq!(
            verify_signed(&bytes, &author.public_key()).unwrap(),
            good,
            "погашение гранта не пережило круг"
        );

        let bad = |order: Order, why: &str| assert!(encode(&order).is_err(), "принято: {why}");
        bad(
            Order { signer_key: Some(author.public_key()), ..Order::new([0u8; 16], Kind::RevokeGrant, at) },
            "погашение без имени гранта",
        );
        bad(
            Order { grant_id: Some([0x67; 16]), ..Order::new([0u8; 16], Kind::RevokeGrant, at) },
            "погашение без ключа подписавшего",
        );
        bad(
            Order {
                grant_id: Some([0x67; 16]),
                signer_key: Some(author.public_key()),
                ..Order::new([0x5a; 16], Kind::RevokeGrant, at)
            },
            "погашение с файлом",
        );
        bad(
            Order { grant_id: Some([0x67; 16]), ..Order::new([0x5a; 16], Kind::Revoke, at) },
            "имя гранта у чужого вида",
        );

        // Имя гранта у чужого вида не проходит и разбором — тело руками.
        let mut w = TlvWriter::new();
        w.put(tag::VERSION, &ORDER_VERSION.to_le_bytes()).unwrap();
        w.put(tag::FILE_ID, &[0x5a; 16]).unwrap();
        w.put(tag::KIND, &[Kind::Revoke as u8]).unwrap();
        w.put(tag::AT, &at.to_le_bytes()).unwrap();
        w.put(tag::GRANT_ID, &[0x67; 16]).unwrap();
        assert!(decode(&w.finish()).is_err(), "имя гранта у отзыва файла разобрано");

        // Длина имени гранта — точная (И-8).
        for len in [0usize, 15, 17] {
            let mut w = TlvWriter::new();
            w.put(tag::VERSION, &ORDER_VERSION.to_le_bytes()).unwrap();
            w.put(tag::FILE_ID, &[0u8; 16]).unwrap();
            w.put(tag::KIND, &[Kind::RevokeGrant as u8]).unwrap();
            w.put(tag::AT, &at.to_le_bytes()).unwrap();
            w.put(tag::SIGNER_KEY, &author.public_key()).unwrap();
            w.put(tag::GRANT_ID, &vec![0x67; len]).unwrap();
            assert!(decode(&w.finish()).is_err(), "имя гранта длиной {len} принято");
        }
    }
}
