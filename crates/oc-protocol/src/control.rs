//! Authority control documents (E2, B2; `docs/protocol.md` §9.16).
//!
//! Three documents, one codec:
//!
//! * [`Binding`]: server binding: organization, stable identity,
//!   epoch and revision, keys, addresses and TLS fingerprints, durability profile,
//!   recovery mode, service state and control-key roster.
//!   Signed with the lease-signing key pinned by the author in the header.
//!   **The document itself creates no trust**: it is verified with a key known
//!   to the verifier beforehand ([`Binding::open`]); the embedded key field must
//!   match it.
//! * [`ControlRequest`]: controller intent: scope (organization,
//!   identity, epoch), operation identity, expected revision, lifetime and exact
//!   content. Multiple signatures are allowed, all over ONE body: a
//!   quorum signs one intent, and signatures over different intents cannot
//!   be combined.
//! * [`Receipt`]: server receipt: operation outcome, resulting
//!   revision and precisely what was committed. Distinguishes acceptance from execution
//!   and from deferral pending replica acknowledgment.
//!
//! Layouts are TLV with ascending tags (I-7), all fields critical.
//! Signature transcripts are `CC/v1/authority-binding`, `CC/v1/control-request`,
//! `CC/v1/operation-receipt` over the body.

use oc_format::FormatError;
use oc_format::tlv::{TlvReader, TlvWriter};
use oc_crypto::sign::Signer;
use oc_crypto::transcript::Transcript;
use oc_crypto::{label, sha256};

/// Layout version of all three documents.
pub const VERSION: u8 = 1;
/// Addresses per binding.
pub const MAX_URLS: usize = 8;
/// Address length, bytes.
pub const MAX_URL_LEN: usize = 256;
/// TLS fingerprints per binding.
pub const MAX_PINS: usize = 8;
/// Keys in the controller roster.
pub const MAX_ROSTER: usize = 16;
/// Signatures over one intent.
pub const MAX_SIGNERS: usize = 16;
/// Maximum intent lifetime: one day. A long-lived signed intent is
/// replay material; the revision, not time, maintains order.
pub const MAX_REQUEST_LIFETIME: i64 = 86_400;
/// Rejection or termination reason, characters.
pub const MAX_REASON_CHARS: usize = 512;
/// Whole-document size limit.
pub const MAX_DOCUMENT_LEN: usize = 64 * 1024;

const SIG: usize = oc_crypto::sign::SIGNATURE_LEN;
const KEY: usize = oc_crypto::sign::PUBLIC_KEY_LEN;

fn bad(tag: u16, len: usize) -> FormatError {
    FormatError::BadFieldLength { tag, len }
}

/// Durability profile (`docs/authority-lifecycle-design.md` §7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Durability {
    /// Success follows durable server storage.
    Local = 0,
    /// A copy goes to the replica after success; the tail may be unacknowledged.
    Mirrored = 1,
    /// Success only after durable replica acknowledgment.
    Witnessed = 2,
}

impl Durability {
    /// From a byte; unknown means rejection (I-10).
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

/// Declared server recovery mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Recovery {
    /// Undeclared: no promise.
    Undeclared = 0,
    /// A verified recovery package exists (`cca recovery`).
    Package = 1,
    /// Server declared unrecoverable: lost keys end issuance.
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

/// Whether the server provides service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    /// Normal operation.
    Serving = 0,
    /// Service stopped: no new registrations or issuance.
    Stopped = 1,
    /// Archive only: revocations and journal heads, no issuance.
    ArchiveOnly = 2,
    /// Authority transferred to a successor (B7).
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

/// Organization name: `[a-z0-9._-]`, 1..=64 bytes, the same rule as the
/// key directory (D4).
fn check_tenant(tenant: &str, tag: u16) -> Result<(), FormatError> {
    let ok = !tenant.is_empty()
        && tenant.len() <= crate::directory::MAX_TENANT
        && tenant.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-' || b == b'_');
    if ok { Ok(()) } else { Err(bad(tag, tenant.len())) }
}

/// Address: printable ASCII without spaces, 1..=256 bytes.
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

/// Consecutive 32-byte keys, strictly ascending: one entry per key and
/// one representation per set.
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

/// Signed document fingerprint, for the revision and receipt chain.
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

/// Server binding; see the module documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub tenant: String,
    /// Stable server identity: unchanged across key changes (B7).
    pub authority_id: [u8; 16],
    /// Authority epoch: increases only on transfer (B7).
    pub epoch: u64,
    /// Binding revision within an epoch: increases on each control operation.
    pub revision: u64,
    pub lease_public: [u8; KEY],
    pub sealing_public: [u8; 32],
    pub urls: Vec<String>,
    /// SHA-256 of SubjectPublicKeyInfo of TLS certificates trusted by the client.
    pub pins: Vec<[u8; 32]>,
    pub durability: Durability,
    pub recovery: Recovery,
    pub status: Status,
    /// Controller keys in ascending order. Empty means no remote control.
    pub roster: Vec<[u8; KEY]>,
    /// Roster signatures required for an intent; zero for an empty roster.
    pub threshold: u8,
    /// Operation that produced this revision; zero for creation.
    pub operation_id: [u8; 16],
    /// Previous revision fingerprint; zero at revision 0.
    pub previous: [u8; 32],
    pub issued_at: i64,
    /// After this time, the binding is no longer current and must be
    /// reread. Binding expiration does not affect issued leases.
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

    /// Unsigned body.
    ///
    /// # Errors
    /// [`FormatError`]: a field violates the rules.
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

    /// Sign with the lease-signing key named in the binding itself.
    ///
    /// # Errors
    /// [`FormatError`]: invalid field, wrong signing key or failed
    /// signature.
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

    /// Parse and verify using a key the verifier trusts BEFOREHAND.
    ///
    /// The binding's embedded key must match the anchor; otherwise the binding
    /// would declare its own signing key trusted.
    ///
    /// # Why signature verification PRECEDES parsing
    ///
    /// The same I-5 rationale as [`open_request`]: parsing unauthenticated bytes
    /// returns distinguishable rejection codes for data nobody signed. The key
    /// comes from OUTSIDE (`anchor`), so the body need not be parsed before verification;
    /// [`Self::peek`] separates the signature itself and is called over already
    /// authenticated bytes. Where no anchor exists, `peek` extracts the key,
    /// with a known tradeoff: in [`verify_chain`], the new epoch binding is first
    /// read with `peek` to obtain its own key, but trust comes not from that
    /// signature; it comes from the roster's signature over the certificate carrying those bytes.
    ///
    /// # Errors
    /// [`FormatError`]: layout, signature or anchor mismatch.
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

    /// Parse WITHOUT signature verification, for the issuer storing its own document.
    ///
    /// # Errors
    /// [`FormatError`]: layout.
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

    /// Whether the address is named in the binding: bytewise comparison.
    #[must_use]
    pub fn names_url(&self, url: &str) -> bool {
        self.urls.iter().any(|u| u == url)
    }
}

/// How the new binding relates to a previously seen one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Continuity {
    /// Same revision, same bytes.
    Same,
    /// Newer. `adjacent` means the next numbered revision, referencing the previously seen one.
    Newer { adjacent: bool },
    /// Older than previously seen: rollback.
    Rollback,
    /// Same revision with different bytes, or the next revision does not reference the
    /// previously seen one: a history fork.
    Fork,
    /// Different server, organization or epoch.
    Unrelated,
}

/// Compare a binding with a previously seen one.
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

/// Intent scope. One kind today, the entire server; the field prevents
/// an intent for one file being mistaken for an intent for the whole server.
pub const SCOPE_AUTHORITY: u8 = 1;

/// What was ordered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Payload {
    /// Addresses and TLS fingerprints (P12).
    SetEndpoints { urls: Vec<String>, pins: Vec<[u8; 32]> },
    /// Durability profile. Downgrades use the same signed decision.
    SetDurability(Durability),
    /// Controller roster and threshold.
    SetRoster { keys: Vec<[u8; KEY]>, threshold: u8 },
    /// Declared recovery mode.
    SetRecovery(Recovery),
    /// Service termination (P16): `Stopped` or `ArchiveOnly`.
    Decommission { status: Status, reason: String },
    /// Authorize an author key for registration over the wire (P01).
    AddAuthor([u8; KEY]),
    /// Remove an author key's authorization.
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

/// Controller intent; see the module documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlRequest {
    pub tenant: String,
    pub authority_id: [u8; 16],
    pub epoch: u64,
    /// 128 random bits supplied by the creator: replay with the same bytes has the same
    /// outcome; different bytes yield `IdConflict`.
    pub operation_id: [u8; 16],
    /// Binding revision on which the intent was based.
    pub expected_revision: u64,
    pub issued_at: i64,
    pub expires_at: i64,
    pub payload: Payload,
}

/// An intent with verified signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedRequest {
    pub request: ControlRequest,
    /// Body fingerprint, shared by all signers.
    pub body_hash: [u8; 32],
    /// Signers in ascending order.
    pub signers: Vec<[u8; KEY]>,
}

impl ControlRequest {
    /// Body without signatures.
    ///
    /// # Errors
    /// [`FormatError`]: a field violates the rules.
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

    /// Sign with one key.
    ///
    /// # Errors
    /// [`FormatError`]: body or signature.
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

/// Intent signature: key and signature.
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

/// Parse an intent and verify EVERY signature.
///
/// The server determines who may sign from the binding roster; this only checks
/// that "the signature verifies with the named key".
///
/// # Why signature verification PRECEDES parsing
///
/// The same I-5 rationale as [`crate::revocation::verify_signed`] and its neighbors:
/// parsing unauthenticated bytes is itself an oracle; distinguishable rejection codes
/// (`MissingField`, `UnknownCriticalField`, `BadFieldLength` with a tag number)
/// report on data nobody signed, distinguishing forgery
/// from truncation. Nothing here REQUIRES parsing before verification: verification keys
/// are in the ENVELOPE, which `split_request` separates before any TLV,
/// unlike the container header, whose signing key resides within the
/// signed material and cannot be obtained from outside.
///
/// # Empty envelope
///
/// Zero signatures would trivially pass the loop, allowing unauthenticated body parsing;
/// reordering lines within this function would not prevent that.
/// An EARLIER boundary must prevent it. It exists: `split_request` rejects
/// `count == 0` before reading signatures (test
/// `documents_beyond_the_size_limits_are_refused_before_parsing`), so an unsigned
/// document never reaches the loop, leaving nothing to improve here.
///
/// The caller counts the quorum, how many signatures and WHOSE; both sites are known:
/// `quorum_met` in `cc-authority/src/control.rs` (using the current revision's roster), and
/// comparison with the previous epoch's `roster`/`threshold` in [`verify_chain`], reached by
/// `cc_cli::chain::check`.
///
/// # Errors
/// [`FormatError`]: layout or any failed signature.
pub fn open_request(bytes: &[u8]) -> Result<SignedRequest, FormatError> {
    let (signatures, body) = split_request(bytes)?;
    let t = transcript(label::CONTROL_REQUEST, body);
    for (key, sig) in &signatures {
        oc_crypto::sign::verify(key, &t, sig).map_err(|_| FormatError::BadHeaderSignature)?;
    }
    let request = ControlRequest::decode_body(body)?;
    Ok(SignedRequest { request, body_hash: sha256(body), signers: signatures.into_iter().map(|(k, _)| k).collect() })
}

/// Append another controller's signature over the same body.
///
/// # Errors
/// [`FormatError`]: layout, signature or duplicate signer.
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

/// Operation outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Outcome {
    /// Executed and committed under the durability profile.
    Committed = 1,
    /// Rejected; state unchanged. Reason in `reason`.
    Rejected = 2,
    /// Committed on the server, but replica acknowledgment has not arrived:
    /// NOT success; replaying the same intent asks again.
    PendingDurability = 3,
    /// Operation identity already occupied by another body.
    IdConflict = 4,
    /// The intent was based on another revision.
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

/// Server receipt; see the module documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub request_hash: [u8; 32],
    pub operation_id: [u8; 16],
    pub outcome: Outcome,
    /// Binding revision AFTER the operation (current revision for rejection).
    pub revision: u64,
    /// Committed binding fingerprint; zero if nothing was committed.
    pub commit: [u8; 32],
    pub epoch: u64,
    /// Achieved durability: the profile under which the commit was acknowledged.
    pub durability: Durability,
    pub reason: String,
    pub at: i64,
}

impl Receipt {
    /// Unsigned body.
    ///
    /// # Errors
    /// [`FormatError`]: the reason violates the rules.
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

    /// Sign with the lease-signing key.
    ///
    /// # Errors
    /// [`FormatError`]: body or signature.
    pub fn sign(&self, signer: &dyn Signer) -> Result<Vec<u8>, FormatError> {
        let body = self.body()?;
        let sig = signer
            .sign(&transcript(label::OPERATION_RECEIPT, &body))
            .map_err(|_| FormatError::BadHeaderSignature)?;
        let mut out = sig.to_vec();
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Parse and verify with the server key.
    ///
    /// # Errors
    /// [`FormatError`]: layout or signature.
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

/// How to handle leases issued by the previous server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OldLeases {
    /// Remain valid until expiration: ordinary planned migration.
    Honour = 0,
    /// Rejected if issued AFTER the transition point, cutting off
    /// an old writer that continued issuing from a backup.
    RejectAfterTransition = 1,
}

impl OldLeases {
    /// From a byte; unknown means rejection (I-10).
    #[must_use]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Honour),
            1 => Some(Self::RejectAfterTransition),
            _ => None,
        }
    }
}

/// Authority transfer certificate: the previous epoch names the next.
///
/// Signed by the PREVIOUS epoch's controller roster, the one named in its
/// binding. The new binding is carried inside: its self-signature means nothing
/// by itself; the roster's signature over this certificate gives it authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transfer {
    /// Server identity: does NOT change on transfer.
    pub authority_id: [u8; 16],
    pub from_epoch: u64,
    pub to_epoch: u64,
    /// Previous epoch's lease-signing key, used to verify the previous binding.
    pub from_lease: [u8; KEY],
    /// When the new epoch takes authority.
    pub transition_at: i64,
    pub old_leases: OldLeases,
    pub issued_at: i64,
    pub expires_at: i64,
    /// Signed binding of the NEW epoch.
    pub binding: Vec<u8>,
}

impl Transfer {
    /// Body without signatures.
    ///
    /// # Errors
    /// [`FormatError`]: nonconsecutive epochs, reversed time interval or out-of-bounds binding.
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

    /// Sign with one roster key.
    ///
    /// # Errors
    /// [`FormatError`]: body or signature.
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

/// Parse a transfer certificate and verify EVERY signature.
///
/// The verifier determines who may sign from the previous binding's roster;
/// this only checks that "the signature verifies with the named key".
///
/// # Why signature verification PRECEDES parsing
///
/// The rationale and empty-envelope caveat are the same as [`open_request`], documented
/// there: both use the same envelope (`split_request`), yet these two
/// combinators already diverged once, precisely the "one path fixed, its neighbor
/// forgotten" problem captured by the test
/// `a_transfer_opens_only_while_every_signature_holds`.
///
/// # Errors
/// [`FormatError`]: layout or any failed signature.
pub fn open_transfer(bytes: &[u8]) -> Result<(Transfer, Vec<[u8; KEY]>), FormatError> {
    let (signatures, body) = split_request(bytes)?;
    let t = transcript(label::AUTHORITY_TRANSFER, body);
    for (key, sig) in &signatures {
        oc_crypto::sign::verify(key, &t, sig).map_err(|_| FormatError::BadHeaderSignature)?;
    }
    let transfer = Transfer::decode_body(body)?;
    Ok((transfer, signatures.into_iter().map(|(k, _)| k).collect()))
}

/// Append another controller's signature over the same certificate.
///
/// # Errors
/// [`FormatError`]: layout, signature or duplicate signer.
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

/// What the server became after a transfer chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Effective {
    /// Binding of the active epoch.
    pub binding: Binding,
    /// Its signed bytes.
    pub bytes: Vec<u8>,
    /// Time of the last transition; `None` means no transfers.
    pub transition_at: Option<i64>,
    /// Treatment of the previous epoch's leases.
    pub old_leases: Option<OldLeases>,
    /// Previous epoch keys in order, used to verify old leases.
    pub previous_keys: Vec<[u8; KEY]>,
}

/// Why the chain was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainError {
    /// The first binding does not verify against the anchor.
    NotAnchored,
    /// The certificate was not signed by the previous epoch's roster.
    NotAuthorized { have: u8, need: u8 },
    /// Nonconsecutive epochs, changed identity or wrong key.
    Broken(&'static str),
    /// Document layout.
    Malformed(String),
    /// The certificate was expired at verification time.
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

/// Verify a chain: the first binding against the anchor, each transfer against the
/// previous epoch's roster.
///
/// `anchor` is the lease-signing key from the container HEADER. No document
/// in the chain declares itself trusted: a certificate is verified against the roster
/// named in the already verified binding.
///
/// # Errors
/// [`ChainError`]: anchor, authority, continuity, lifetime or layout.
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

    /// A TRANSFER CERTIFICATE OPENS ONLY WHILE EVERY SIGNATURE VERIFIES.
    ///
    /// # Why a separate test from the intent
    ///
    /// Because `open_transfer` and `open_request` are two DIFFERENT combinators,
    /// and only the second was guarded. Removing `oc_crypto::sign::verify` from
    /// `open_transfer` broke no tests: the certificate was parsed,
    /// compared with itself (`transfer.body()? != body`) and declared open,
    /// so a transfer of authority to a new epoch would be accepted without a signature
    /// from the previous roster. CLAUDE.md describes precisely this problem as "one path
    /// fixed, its neighbor forgotten".
    ///
    /// EVERY byte is tested, not three selected positions: the body does not authenticate
    /// signature bytes or named-key bytes itself; their only guard
    /// is that signature check.
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

    /// AN UNPARSEABLE BODY IS REJECTED BY SIGNATURE VERIFICATION, NOT PARSING.
    ///
    /// The rationale is I-5 for signed documents: a distinguishable parsing rejection
    /// for a body nobody signed is an oracle. The body here is deliberately
    /// unparseable (unknown CRITICAL tag `0x7ABC`), so both
    /// boundaries want to reject it, revealing which responds first.
    ///
    /// # Why the test would be blind without a positive control
    ///
    /// Because an invalid signature returns `BadHeaderSignature` even with
    /// reversed ordering, for ANY parseable body. Only a pair distinguishes
    /// the order: that same body with a VALID signature must yield
    /// exactly [`FormatError::UnknownCriticalField`]. If both halves passed under
    /// reversed ordering, the test would not be testing order.
    ///
    /// Both entry points intentionally share one test: their envelope is shared, yet they
    /// have already diverged once.
    #[test]
    fn an_unparsable_body_is_refused_by_the_signature_first() {
        let a = Ed25519Signer::from_seed(&[0x71; 32]);
        let mut w = TlvWriter::new();
        w.put(0x7ABC, b"no reader knows this tag").unwrap();
        let body = w.finish().to_vec();

        /// Entry point: its name, signing label and opening function.
        /// The result is reduced to `()`: the test cares about the rejection CODE, not contents.
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

    /// SIZE BOUNDARIES: for a document arriving from the wire, these must be
    /// checked BEFORE parsing, not afterward: parsing megabytes of garbage
    /// is itself denial of service.
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
