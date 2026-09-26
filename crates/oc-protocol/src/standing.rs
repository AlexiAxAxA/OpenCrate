// SPDX-License-Identifier: MPL-2.0
//! File standing on the server: what the author sees when asking "what is set there?".
//!
//! # Why a separate document
//!
//! The author gives the server orders: revoke, appoint an heir, set
//! a limit. Before this document, there was no way to SEE which
//! orders currently applied. The only mirror was the journal, a history
//! of actions rather than their result: "heir appointed" and "heir appointed, then
//! removed" are different histories with the same empty outcome, and the author should not
//! have to distinguish them by reading the journal tail.
//!
//! This is especially true for the dead man's switch, whose result is irreversible: someone who appointed
//! an heir has the right to verify that the interval is what they intended and that
//! the event is still far away.
//!
//! # What is absent here
//!
//! Secrets. Everything here was already disclosed to the server by the author, and is visible to recipients
//! in the queue and journal. The response therefore requires no proof of possession,
//! like the request queue (`Requests`). The bequest is absent: it belongs to
//! the heir, not anyone who asks, and is delivered by `Collect` after the event.

use oc_format::FormatError;
use oc_format::tlv::{TlvReader, TlvWriter};

/// Tags. All critical: unknown means rejection (I-7).
pub mod tag {
    pub const FILE_ID: u16 = 1;
    pub const REVOKED: u16 = 2;
    pub const MAX_DEVICES: u16 = 3;
    pub const MAX_GRANTS: u16 = 4;
    /// Consecutive coauthor keys, 32 bytes each.
    pub const COAUTHORS: u16 = 5;
    /// Required number of coauthor signatures.
    pub const COAUTHOR_THRESHOLD: u16 = 6;
    /// Proposal lifetime: the RESOLVED duration, not "whether it was assigned".
    pub const PROPOSAL_TTL: u16 = 16;
    /// Consecutive opening approver keys, 32 bytes each.
    pub const APPROVERS: u16 = 7;
    /// Required number of their votes.
    pub const APPROVER_THRESHOLD: u16 = 8;
    /// Action after silence: 1 open the bequest, 2 close the file.
    pub const HEIR_MODE: u16 = 9;
    pub const SILENCE_SECONDS: u16 = 10;
    /// When the author was last seen.
    pub const LAST_ALIVE: u16 = 11;
    /// When the silence event was detected.
    pub const HEIR_RELEASED_AT: u16 = 12;
    /// Bequest recipients: consecutive fingerprints, 32 bytes each.
    pub const HEIR_FPR: u16 = 13;
    /// Votes as a stream: `fingerprint(32) ‖ voter(32) ‖ approve(1) ‖ when(8)`.
    pub const VOTES: u16 = 14;
    /// Proposals as a stream, each with its own length.
    pub const PROPOSALS: u16 = 15;
    /// Issuance frozen by the author's panic button: `u8`, written only when true.
    ///
    /// Seventeenth: after proposal lifetime, tags strictly increase (I-7);
    /// placement follows the number, not its relation to `revoked`.
    pub const FROZEN: u16 = 17;
}

/// What the file specifies for the author's silence.
///
/// A separate enum rather than adjacent optional fields: "open,
/// but to whom is unknown" and "close, but with an heir" are states that cannot
/// occur, so there is no reason to make them representable. The same technique as on the server
/// (`cc_authority::AfterSilence`) and in the order (`order::HeirMode`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeirStanding {
    /// No heir appointed; silence does not close the file.
    Absent,
    /// After silence, bequests open for these devices.
    ///
    /// A list rather than a single device: there may be several heirs, each receiving THEIR OWN share,
    /// sealed to their key.
    Open { device_fprs: Vec<[u8; 32]>, silence_seconds: u64, released_at: Option<i64> },
    /// After silence, the file closes for everyone.
    Close { silence_seconds: u64, released_at: Option<i64> },
}

/// An approver's vote as seen by the author.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Vote {
    pub device_fpr: [u8; 32],
    pub voter: [u8; 32],
    pub approve: bool,
    pub at: i64,
}

/// A proposal awaiting signatures.
///
/// The first signer's body is carried as a TEMPLATE. The first revision omitted it:
/// "sign your own command, not someone else's bytes". That reasoning is valid: signing
/// someone else's body is wrong, and it is also stale. But a coauthor signing through the UI
/// must REPRODUCE the parameters, which the intent digest hides by construction.
/// The solution is a template: the client extracts parameters, inserts its own time and
/// signs with its own key. The same command, its own bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProposalStanding {
    /// INTENT digest: identifies the proposal.
    ///
    /// Intent, not body: coauthors sign the same command from their own
    /// machines with different issuance times (`order::intent_digest`).
    pub intent: [u8; 32],
    /// Order kind (`oc_protocol::order::Kind`).
    pub kind: u8,
    pub at: i64,
    pub need: u8,
    /// Who has already signed.
    pub signers: Vec<[u8; 32]>,
    /// The first signer's body: a reconstruction template.
    pub body: Vec<u8>,
}

/// The complete file standing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Standing {
    pub file_id: [u8; 16],
    pub revoked: bool,
    pub max_devices: Option<u32>,
    pub max_grants: Option<u32>,
    pub coauthors: Vec<[u8; 32]>,
    pub coauthor_threshold: u8,
    /// Proposal lifetime: assigned by the author or the server default.
    ///
    /// A resolved value rather than `Option`: the requester needs "how long",
    /// not "was it assigned?". Its origin matters to the server, not the person.
    pub proposal_ttl: i64,
    pub approvers: Vec<[u8; 32]>,
    pub approver_threshold: u8,
    pub heir: HeirStanding,
    /// When the server last saw the author. `None` means never.
    pub last_alive: Option<i64>,
    pub votes: Vec<Vote>,
    pub proposals: Vec<ProposalStanding>,
    /// Issuance stopped by the author's panic button for all their files at once.
    pub frozen: bool,
}

/// Encode the standing.
///
/// # Errors
/// [`FormatError`] if a field cannot be written.
pub fn encode(standing: &Standing) -> Result<Vec<u8>, FormatError> {
    let mut w = TlvWriter::new();
    w.put(tag::FILE_ID, &standing.file_id)?;
    w.put(tag::REVOKED, &[u8::from(standing.revoked)])?;
    if let Some(n) = standing.max_devices {
        w.put(tag::MAX_DEVICES, &n.to_le_bytes())?;
    }
    if let Some(n) = standing.max_grants {
        w.put(tag::MAX_GRANTS, &n.to_le_bytes())?;
    }
    if !standing.coauthors.is_empty() {
        w.put(tag::COAUTHORS, &flatten(&standing.coauthors))?;
    }
    if standing.coauthor_threshold != 0 {
        w.put(tag::COAUTHOR_THRESHOLD, &[standing.coauthor_threshold])?;
    }
    if !standing.approvers.is_empty() {
        w.put(tag::APPROVERS, &flatten(&standing.approvers))?;
    }
    if standing.approver_threshold != 0 {
        w.put(tag::APPROVER_THRESHOLD, &[standing.approver_threshold])?;
    }
    // Порядок полей задан возрастанием тега, а не удобством: `last_alive`
    // одиннадцатый и потому стоит между сроком и моментом события, хотя по
    // смыслу принадлежит не наследнику, а файлу.
    match &standing.heir {
        HeirStanding::Absent => {}
        HeirStanding::Open { silence_seconds, .. } => {
            w.put(tag::HEIR_MODE, &[1])?;
            w.put(tag::SILENCE_SECONDS, &silence_seconds.to_le_bytes())?;
        }
        HeirStanding::Close { silence_seconds, .. } => {
            w.put(tag::HEIR_MODE, &[2])?;
            w.put(tag::SILENCE_SECONDS, &silence_seconds.to_le_bytes())?;
        }
    }
    if let Some(at) = standing.last_alive {
        w.put(tag::LAST_ALIVE, &at.to_le_bytes())?;
    }
    let released = match &standing.heir {
        HeirStanding::Absent => None,
        HeirStanding::Open { released_at, .. } | HeirStanding::Close { released_at, .. } => {
            *released_at
        }
    };
    if let Some(at) = released {
        w.put(tag::HEIR_RELEASED_AT, &at.to_le_bytes())?;
    }
    if let HeirStanding::Open { device_fprs, .. } = &standing.heir {
        w.put(tag::HEIR_FPR, &flatten(device_fprs))?;
    }
    if !standing.votes.is_empty() {
        let mut flat = Vec::with_capacity(standing.votes.len().saturating_mul(VOTE_LEN));
        for v in &standing.votes {
            flat.extend_from_slice(&v.device_fpr);
            flat.extend_from_slice(&v.voter);
            flat.push(u8::from(v.approve));
            flat.extend_from_slice(&v.at.to_le_bytes());
        }
        w.put(tag::VOTES, &flat)?;
    }
    if !standing.proposals.is_empty() {
        let mut flat = Vec::new();
        for p in &standing.proposals {
            // Подписавших не больше шестнадцати — предел состава, поэтому счёт
            // помещается в байт, а тело идёт последним, до конца записи.
            let signers = u8::try_from(p.signers.len())
                .map_err(|_| FormatError::BadFieldLength { tag: tag::PROPOSALS, len: p.signers.len() })?;
            let mut one = Vec::with_capacity(
                43usize
                    .saturating_add(p.signers.len().saturating_mul(32))
                    .saturating_add(p.body.len()),
            );
            one.extend_from_slice(&p.intent);
            one.push(p.kind);
            one.extend_from_slice(&p.at.to_le_bytes());
            one.push(p.need);
            one.push(signers);
            one.extend_from_slice(&flatten(&p.signers));
            one.extend_from_slice(&p.body);
            let len = u32::try_from(one.len())
                .map_err(|_| FormatError::BadFieldLength { tag: tag::PROPOSALS, len: one.len() })?;
            flat.extend_from_slice(&len.to_le_bytes());
            flat.extend_from_slice(&one);
        }
        w.put(tag::PROPOSALS, &flat)?;
    }
    // ПОСЛЕ потоков: номер шестнадцатый, а теги обязаны строго возрастать (И-7).
    // Поле смысловое соседствует с порогом соавторов, но место в байтах ему
    // задаёт номер, а не смысл, — и первая редакция уронила на этом собственный
    // писатель.
    if standing.proposal_ttl != 0 {
        w.put(tag::PROPOSAL_TTL, &standing.proposal_ttl.to_le_bytes())?;
    }
    // ПОСЛЕДНИМ: семнадцатый. Пишется только когда заморожено — незамороженное
    // положение прежняя сборка читает как раньше.
    if standing.frozen {
        w.put(tag::FROZEN, &[1])?;
    }
    Ok(w.finish().to_vec())
}

/// Consecutive keys, no separators: element length is constant.
fn flatten(keys: &[[u8; 32]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(keys.len().saturating_mul(32));
    for k in keys {
        out.extend_from_slice(k);
    }
    out
}

/// Vote record length: fingerprint, voter, decision, time.
const VOTE_LEN: usize = 73;

/// Parse the standing strictly: exact lengths, mode consistent with fields, and
/// NO value has two representations.
///
/// # What has been rejected since 2026-09-20, and why
///
/// The writer [`encode`] omits everything meaning "nothing": an empty roster,
/// a zero threshold, zero proposal lifetime and unfrozen standing are never
/// written. Parsing formerly accepted both omission and explicit encoding of the same meaning,
/// so each quantity had TWO wire representations, while
/// canonicality (I-7) requires exactly one.
///
/// **Unfrozen standing remains valid**, and is the most common case,
/// but is expressed by ABSENCE of tag 17, not by `frozen = 0`. The same applies to
/// roster, threshold and lifetime: absence remains valid and reads as before;
/// only the second form, which no writer produces, is rejected.
///
/// Roster and threshold are also checked against each other under the same rule as
/// `oc_format::header::check_coauthors` and [`crate::order`]: the threshold must be
/// achievable by the roster. The server never returns otherwise (`check_roster` rejects
/// such an order, and `Coauthors` such a header), so the check excludes no
/// reachable standing while preventing a manually crafted "quorum
/// that nobody can ever reach".
///
/// # Errors
/// [`FormatError`] for an unknown tag, invalid length, a value the
/// writer never produces, or fields inconsistent with the mode.
pub fn decode(bytes: &[u8]) -> Result<Standing, FormatError> {
    let mut file_id = None;
    let mut revoked = None;
    let mut max_devices = None;
    let mut max_grants = None;
    let mut heir_mode = None;
    let mut silence_seconds = None;
    let mut last_alive = None;
    let mut released_at = None;
    let mut device_fprs = None;
    let mut coauthors = Vec::new();
    // `Option`, а не `0`: «тега не было» и «тег с нулём» обязаны различаться —
    // второе отвергается, первое законно и означает тот же ноль.
    let mut coauthor_threshold = None;
    let mut frozen = false;
    let mut approvers = Vec::new();
    let mut approver_threshold = None;
    let mut proposal_ttl = 0i64;
    let mut votes = Vec::new();
    let mut proposals = Vec::new();

    let mut reader = TlvReader::new(bytes);
    while let Some(f) = reader.next_field()? {
        match f.tag {
            tag::FILE_ID => file_id = Some(exact(f.tag, f.value)?),
            tag::FROZEN => {
                // Только единица: писатель ставит тег ИСКЛЮЧИТЕЛЬНО при
                // заморозке, и `frozen = 0` было бы вторым способом сказать то,
                // что уже говорит отсутствие тега.
                frozen = match f.value {
                    [1] => true,
                    other => {
                        return Err(FormatError::BadFieldLength {
                            tag: tag::FROZEN,
                            len: other.len(),
                        });
                    }
                };
            }
            tag::REVOKED => {
                revoked = Some(match f.value {
                    [0] => false,
                    [1] => true,
                    other => {
                        return Err(FormatError::BadFieldLength {
                            tag: tag::REVOKED,
                            len: other.len(),
                        });
                    }
                });
            }
            tag::MAX_DEVICES => max_devices = Some(u32_le(f.tag, f.value)?),
            tag::MAX_GRANTS => max_grants = Some(u32_le(f.tag, f.value)?),
            tag::HEIR_MODE => {
                heir_mode = Some(match f.value {
                    [b @ (1 | 2)] => *b,
                    other => {
                        return Err(FormatError::BadFieldLength {
                            tag: tag::HEIR_MODE,
                            len: other.len(),
                        });
                    }
                });
            }
            tag::SILENCE_SECONDS => silence_seconds = Some(u64_le(f.tag, f.value)?),
            tag::LAST_ALIVE => last_alive = Some(u64_le(f.tag, f.value)?.cast_signed()),
            tag::HEIR_RELEASED_AT => released_at = Some(u64_le(f.tag, f.value)?.cast_signed()),
            tag::HEIR_FPR => device_fprs = Some(nonempty_keys(f.tag, f.value)?),
            tag::COAUTHORS => coauthors = nonempty_keys(f.tag, f.value)?,
            tag::COAUTHOR_THRESHOLD => coauthor_threshold = Some(one_byte(f.tag, f.value)?),
            tag::APPROVERS => approvers = nonempty_keys(f.tag, f.value)?,
            tag::APPROVER_THRESHOLD => approver_threshold = Some(one_byte(f.tag, f.value)?),
            tag::PROPOSAL_TTL => {
                proposal_ttl = u64_le(f.tag, f.value)?.cast_signed();
                // Ноль писатель не ставит: он означает «умолчание сервера», а
                // умолчание выражается отсутствием тега. Тот же довод, что у
                // распоряжения `SetCoauthors` (`docs/protocol.md` §11.8): снять
                // срок нельзя, можно только сменить.
                if proposal_ttl == 0 {
                    return Err(FormatError::BadFieldLength {
                        tag: tag::PROPOSAL_TTL,
                        len: f.value.len(),
                    });
                }
            }
            tag::VOTES => {
                // Пустой поток отвергается наравне с обрезанным: писатель ставит
                // тег только при непустом списке. Дальше — точная длина записи.
                if f.value.is_empty() || !f.value.len().is_multiple_of(VOTE_LEN) {
                    return Err(FormatError::BadFieldLength {
                        tag: tag::VOTES,
                        len: f.value.len(),
                    });
                }
                for chunk in f.value.chunks(VOTE_LEN) {
                    votes.push(decode_vote(chunk)?);
                }
            }
            tag::PROPOSALS => {
                // Пустой поток — то же самое, что отсутствие тега, и писатель
                // пишет второе.
                if f.value.is_empty() {
                    return Err(FormatError::BadFieldLength { tag: tag::PROPOSALS, len: 0 });
                }
                proposals = split_proposals(f.value)?;
            }
            other => crate::unknown::refuse_if_critical(other)?,
        }
    }

    let coauthor_threshold =
        check_roster(tag::COAUTHORS, tag::COAUTHOR_THRESHOLD, &coauthors, coauthor_threshold)?;
    let approver_threshold =
        check_roster(tag::APPROVERS, tag::APPROVER_THRESHOLD, &approvers, approver_threshold)?;

    let heir = match (heir_mode, silence_seconds, device_fprs) {
        (None, None, None) => HeirStanding::Absent,
        (Some(1), Some(silence_seconds), Some(device_fprs)) if !device_fprs.is_empty() => {
            HeirStanding::Open { device_fprs, silence_seconds, released_at }
        }
        (Some(2), Some(silence_seconds), None) => {
            HeirStanding::Close { silence_seconds, released_at }
        }
        _ => return Err(FormatError::UnknownCriticalField { tag: tag::HEIR_MODE }),
    };
    if heir == HeirStanding::Absent && released_at.is_some() {
        return Err(FormatError::UnknownCriticalField { tag: tag::HEIR_RELEASED_AT });
    }

    Ok(Standing {
        file_id: file_id.ok_or(FormatError::MissingField { tag: tag::FILE_ID })?,
        revoked: revoked.ok_or(FormatError::MissingField { tag: tag::REVOKED })?,
        max_devices,
        max_grants,
        coauthors,
        coauthor_threshold,
        proposal_ttl,
        approvers,
        approver_threshold,
        heir,
        last_alive,
        votes,
        proposals,
        frozen,
    })
}

fn split_keys(tag: u16, value: &[u8]) -> Result<Vec<[u8; 32]>, FormatError> {
    if !value.len().is_multiple_of(32) {
        return Err(FormatError::BadFieldLength { tag, len: value.len() });
    }
    let mut out = Vec::with_capacity(value.len() / 32);
    for chunk in value.chunks(32) {
        out.push(exact32(tag, chunk)?);
    }
    Ok(out)
}

/// A roster whose tag is present must be nonempty.
///
/// An empty value and an absent tag both mean "no roster", but
/// the writer only emits the latter. Separate from [`split_keys`] because an empty
/// proposal signer list IS valid: a proposal without any signatures
/// is representable and must survive a round trip.
fn nonempty_keys(tag: u16, value: &[u8]) -> Result<Vec<[u8; 32]>, FormatError> {
    if value.is_empty() {
        return Err(FormatError::BadFieldLength { tag, len: 0 });
    }
    split_keys(tag, value)
}

fn one_byte(tag: u16, value: &[u8]) -> Result<u8, FormatError> {
    match value {
        [b] => Ok(*b),
        other => Err(FormatError::BadFieldLength { tag, len: other.len() }),
    }
}

/// Whether a threshold is achievable by its roster: the same rule as for orders
/// (`order::check_roster`) and headers (`header::check_coauthors`).
///
/// Returns the threshold as a number: externally the structure uses `0` for "no quorum";
/// `None` becomes zero here, after consistency has been
/// checked, not while reading the field.
///
/// The roster limit comes from [`crate::order::MAX_KEYS`], not a neighboring numeric
/// literal: two places naming one quantity diverge on the first change,
/// silently; one check would reject standing accepted by the other.
fn check_roster(
    keys_tag: u16,
    threshold_tag: u16,
    keys: &[[u8; 32]],
    threshold: Option<u8>,
) -> Result<u8, FormatError> {
    if keys.len() > crate::order::MAX_KEYS {
        return Err(FormatError::BadFieldLength { tag: keys_tag, len: keys.len() });
    }
    match (keys.is_empty(), threshold) {
        // Кворума нет: ни состава, ни порога.
        (true, None) => Ok(0),
        // Порог без состава набрать нечем, состав без порога ничего не требует —
        // обе половины бессмысленны поодиночке, и сервер ни ту ни другую не
        // отдаёт: `check_roster` распоряжения пропускает только пару.
        (true, Some(_)) => Err(FormatError::MissingField { tag: keys_tag }),
        (false, None) => Err(FormatError::MissingField { tag: threshold_tag }),
        (false, Some(threshold)) => {
            // Порог выше состава — правило, которого никто никогда не исполнит:
            // файл замирает навсегда, и заметить это можно только тем, что он
            // замер. Ноль при непустом составе — та же беда с другой стороны:
            // «кворум есть, но не требуется» означало бы состав, ничего не
            // держащий, и писатель такого не производит (тег он опускает).
            let wanted = usize::from(threshold);
            if wanted == 0 || wanted > keys.len() {
                return Err(FormatError::BadFieldLength { tag: threshold_tag, len: wanted });
            }
            Ok(threshold)
        }
    }
}

fn decode_vote(chunk: &[u8]) -> Result<Vote, FormatError> {
    let bad = || FormatError::BadFieldLength { tag: tag::VOTES, len: chunk.len() };
    Ok(Vote {
        device_fpr: exact32(tag::VOTES, chunk.get(..32).ok_or_else(bad)?)?,
        voter: exact32(tag::VOTES, chunk.get(32..64).ok_or_else(bad)?)?,
        approve: match chunk.get(64) {
            Some(0) => false,
            Some(1) => true,
            _ => return Err(bad()),
        },
        at: u64_le(tag::VOTES, chunk.get(65..73).ok_or_else(bad)?)?.cast_signed(),
    })
}

/// Proposals: each has its own length because signature counts differ.
fn split_proposals(mut rest: &[u8]) -> Result<Vec<ProposalStanding>, FormatError> {
    let bad = || FormatError::BadFieldLength { tag: tag::PROPOSALS, len: 0 };
    let mut out = Vec::new();
    while !rest.is_empty() {
        let head: [u8; 4] =
            rest.get(..4).and_then(|s| <[u8; 4]>::try_from(s).ok()).ok_or_else(bad)?;
        let len = usize::try_from(u32::from_le_bytes(head)).map_err(|_| bad())?;
        let body = rest.get(4..4usize.saturating_add(len)).ok_or_else(bad)?;
        rest = rest.get(4usize.saturating_add(len)..).ok_or_else(bad)?;

        let count = usize::from(*body.get(42).ok_or_else(bad)?);
        let signers_end = 43usize.saturating_add(count.saturating_mul(32));
        let signers = body.get(43..signers_end).ok_or_else(bad)?;
        let order_body = body.get(signers_end..).ok_or_else(bad)?;
        out.push(ProposalStanding {
            intent: exact32(tag::PROPOSALS, body.get(..32).ok_or_else(bad)?)?,
            kind: *body.get(32).ok_or_else(bad)?,
            at: u64_le(tag::PROPOSALS, body.get(33..41).ok_or_else(bad)?)?.cast_signed(),
            need: *body.get(41).ok_or_else(bad)?,
            signers: split_keys(tag::PROPOSALS, signers)?,
            body: order_body.to_vec(),
        });
    }
    Ok(out)
}

fn exact(tag: u16, value: &[u8]) -> Result<[u8; 16], FormatError> {
    value.try_into().map_err(|_| FormatError::BadFieldLength { tag, len: value.len() })
}

fn exact32(tag: u16, value: &[u8]) -> Result<[u8; 32], FormatError> {
    value.try_into().map_err(|_| FormatError::BadFieldLength { tag, len: value.len() })
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
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn bare() -> Standing {
        Standing {
            file_id: [0x5a; 16],
            revoked: false,
            max_devices: Some(3),
            max_grants: None,
            coauthors: Vec::new(),
            coauthor_threshold: 0,
            proposal_ttl: 0,
            approvers: Vec::new(),
            approver_threshold: 0,
            heir: HeirStanding::Absent,
            last_alive: None,
            votes: Vec::new(),
            proposals: Vec::new(),
            frozen: false,
        }
    }

    /// THE QUORUM IS SHOWN IN FULL AND ROUND-TRIPS UNCHANGED.
    ///
    /// Rosters, thresholds, votes and proposals: everything the author needs to
    /// understand why the file will not open and whose signature is awaited.
    #[test]
    fn a_quorum_survives_the_round_trip_whole() {
        let case = Standing {
            coauthors: vec![[1; 32], [2; 32]],
            coauthor_threshold: 2,
            proposal_ttl: 3 * 86_400,
            approvers: vec![[3; 32], [4; 32], [5; 32]],
            approver_threshold: 2,
            votes: vec![
                Vote { device_fpr: [7; 32], voter: [3; 32], approve: true, at: 1_756_000_000 },
                Vote { device_fpr: [7; 32], voter: [4; 32], approve: false, at: 1_756_000_100 },
            ],
            proposals: vec![
                ProposalStanding {
                    intent: [9; 32],
                    kind: 2,
                    at: 1_756_000_000,
                    need: 2,
                    signers: vec![[1; 32]],
                    body: vec![0xaa; 40],
                },
                // Предложение без подписей представимо и обязано пережить круг:
                // длина у записей разная, и нулевая — самая обидная граница.
                ProposalStanding {
                    intent: [10; 32],
                    kind: 3,
                    at: 1_756_000_050,
                    need: 2,
                    signers: Vec::new(),
                    body: Vec::new(),
                },
            ],
            ..bare()
        };
        assert_eq!(decode(&encode(&case).unwrap()).unwrap(), case, "кворум не пережил круг");
    }

    /// STREAM LENGTHS ARE EXACT (I-8).
    #[test]
    fn stream_lengths_are_exact() {
        let mut w = TlvWriter::new();
        w.put(tag::FILE_ID, &[0x5a; 16]).unwrap();
        w.put(tag::REVOKED, &[0]).unwrap();
        w.put(tag::VOTES, &[0u8; 72]).unwrap();
        assert!(decode(&w.finish()).is_err(), "голос в 72 байта принят");

        let mut w = TlvWriter::new();
        w.put(tag::FILE_ID, &[0x5a; 16]).unwrap();
        w.put(tag::REVOKED, &[0]).unwrap();
        w.put(tag::COAUTHORS, &[0u8; 33]).unwrap();
        assert!(decode(&w.finish()).is_err(), "тридцать три байта приняты за ключ");

        // Предложение, чья объявленная длина уходит за край.
        let mut flat = Vec::new();
        flat.extend_from_slice(&999u32.to_le_bytes());
        flat.extend_from_slice(&[0u8; 43]);
        let mut w = TlvWriter::new();
        w.put(tag::FILE_ID, &[0x5a; 16]).unwrap();
        w.put(tag::REVOKED, &[0]).unwrap();
        w.put(tag::PROPOSALS, &flat).unwrap();
        assert!(decode(&w.finish()).is_err(), "предложение длиннее своего потока принято");
    }

    /// ENCODING ROUND TRIP FOR ALL THREE HEIR STATES.
    #[test]
    fn every_standing_survives_the_round_trip() {
        let cases = [
            bare(),
            Standing { revoked: true, max_grants: Some(7), ..bare() },
            Standing {
                heir: HeirStanding::Open {
                    device_fprs: vec![[0x77; 32]],
                    silence_seconds: 2_592_000,
                    released_at: None,
                },
                last_alive: Some(1_756_000_000),
                ..bare()
            },
            Standing {
                heir: HeirStanding::Close {
                    silence_seconds: 86_400,
                    released_at: Some(1_756_100_000),
                },
                last_alive: Some(1_756_000_000),
                ..bare()
            },
        ];
        for case in cases {
            assert_eq!(decode(&encode(&case).unwrap()).unwrap(), case, "круг не сошёлся");
        }
    }

    /// THE MODE MUST MATCH THE FIELDS.
    ///
    /// Bytes arrive over the network, and an adversary can construct "open, but to whom is unknown"
    /// as easily as honest standing. Accepting it would mean
    /// showing the author a nonexistent heir.
    #[test]
    fn a_mode_that_does_not_match_its_fields_is_refused() {
        // Открытие без отпечатка.
        let mut w = TlvWriter::new();
        w.put(tag::FILE_ID, &[0x5a; 16]).unwrap();
        w.put(tag::REVOKED, &[0]).unwrap();
        w.put(tag::HEIR_MODE, &[1]).unwrap();
        w.put(tag::SILENCE_SECONDS, &86_400u64.to_le_bytes()).unwrap();
        assert!(decode(&w.finish()).is_err(), "открытие без отпечатка принято");

        // Закрытие с отпечатком.
        let mut w = TlvWriter::new();
        w.put(tag::FILE_ID, &[0x5a; 16]).unwrap();
        w.put(tag::REVOKED, &[0]).unwrap();
        w.put(tag::HEIR_MODE, &[2]).unwrap();
        w.put(tag::SILENCE_SECONDS, &86_400u64.to_le_bytes()).unwrap();
        w.put(tag::HEIR_FPR, &[0x77; 32]).unwrap();
        assert!(decode(&w.finish()).is_err(), "закрытие с отпечатком принято");

        // Срок без режима.
        let mut w = TlvWriter::new();
        w.put(tag::FILE_ID, &[0x5a; 16]).unwrap();
        w.put(tag::REVOKED, &[0]).unwrap();
        w.put(tag::SILENCE_SECONDS, &86_400u64.to_le_bytes()).unwrap();
        assert!(decode(&w.finish()).is_err(), "срок без режима принят");

        // Событие без наследника.
        let mut w = TlvWriter::new();
        w.put(tag::FILE_ID, &[0x5a; 16]).unwrap();
        w.put(tag::REVOKED, &[0]).unwrap();
        w.put(tag::HEIR_RELEASED_AT, &1i64.to_le_bytes()).unwrap();
        assert!(decode(&w.finish()).is_err(), "событие без наследника принято");
    }

    /// VALUES NEVER PRODUCED BY THE WRITER ARE REJECTED (2026-09-20).
    ///
    /// Each quantity had TWO wire representations: omission
    /// (no tag) and an explicit encoding of the same meaning. Nobody ever
    /// produces the latter, yet parsing accepted it: two different byte sequences
    /// meant the same thing, which I-7 forbids.
    ///
    /// The test enumerates them by name rather than checking that "something was rejected":
    /// removing ANY one check must fail the test, and the message must
    /// identify exactly which form passed.
    #[test]
    fn values_the_writer_never_writes_are_refused() {
        // Каждый случай — приписка к минимальному законному положению.
        let cases: [(&str, u16, Vec<u8>); 7] = [
            ("пустой состав соавторов", tag::COAUTHORS, Vec::new()),
            ("нулевой порог соавторов", tag::COAUTHOR_THRESHOLD, vec![0]),
            ("пустой состав одобряющих", tag::APPROVERS, Vec::new()),
            ("нулевой порог одобряющих", tag::APPROVER_THRESHOLD, vec![0]),
            ("нулевой срок предложения", tag::PROPOSAL_TTL, 0u64.to_le_bytes().to_vec()),
            ("незамороженное явной записью", tag::FROZEN, vec![0]),
            ("пустой поток голосов", tag::VOTES, Vec::new()),
        ];
        for (what, tag, value) in cases {
            let mut w = TlvWriter::new();
            w.put(tag::FILE_ID, &[0x5a; 16]).unwrap();
            w.put(tag::REVOKED, &[0]).unwrap();
            w.put(tag, &value).unwrap();
            assert!(decode(&w.finish()).is_err(), "принято: {what}");
        }

        // Пустой поток предложений — то же самое, но тег 15 обязан стоять до
        // шестнадцатого, поэтому он пишется отдельно.
        let mut w = TlvWriter::new();
        w.put(tag::FILE_ID, &[0x5a; 16]).unwrap();
        w.put(tag::REVOKED, &[0]).unwrap();
        w.put(tag::PROPOSALS, &[]).unwrap();
        assert!(decode(&w.finish()).is_err(), "принят пустой поток предложений");

        // ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: то же положение БЕЗ этих полей законно, и
        // именно оно приходит с сервера чаще всего.
        let mut w = TlvWriter::new();
        w.put(tag::FILE_ID, &[0x5a; 16]).unwrap();
        w.put(tag::REVOKED, &[0]).unwrap();
        let plain = decode(&w.finish()).expect("голое положение отвергнуто");
        assert_eq!(plain.coauthor_threshold, 0);
        assert!(!plain.frozen, "незамороженное — законное состояние");
        assert_eq!(plain.proposal_ttl, 0);
    }

    /// A THRESHOLD MUST BE ACHIEVABLE BY ITS ROSTER, AND A ROSTER MUST HAVE A THRESHOLD.
    ///
    /// One rule serves three places: the header (`header::check_coauthors`),
    /// the order (`order::check_roster`) and this module. The server does not return half-pairs,
    /// but standing bytes are constructed by whoever responds, so a "quorum
    /// that nobody can ever reach" is as easy to construct as honest
    /// standing.
    #[test]
    fn a_threshold_must_be_reachable_by_its_roster() {
        let roster = |keys: usize, threshold: Option<u8>| {
            let mut w = TlvWriter::new();
            w.put(tag::FILE_ID, &[0x5a; 16]).unwrap();
            w.put(tag::REVOKED, &[0]).unwrap();
            if keys > 0 {
                let flat: Vec<[u8; 32]> =
                    (0..keys).map(|n| [u8::try_from(n).unwrap(); 32]).collect();
                w.put(tag::COAUTHORS, &flatten(&flat)).unwrap();
            }
            if let Some(t) = threshold {
                w.put(tag::COAUTHOR_THRESHOLD, &[t]).unwrap();
            }
            decode(&w.finish())
        };

        assert!(roster(3, Some(4)).is_err(), "порог 4 из трёх принят");
        assert!(roster(3, Some(0)).is_err(), "нулевой порог при составе из трёх принят");
        assert!(roster(0, Some(1)).is_err(), "порог без состава принят");
        assert!(roster(0, Some(0)).is_err(), "нулевой порог явной записью принят");
        assert!(roster(2, None).is_err(), "состав без порога принят");
        assert!(roster(17, Some(1)).is_err(), "состав из семнадцати принят");

        // Положительный контроль: исполнимые пары проходят.
        assert_eq!(roster(3, Some(2)).unwrap().coauthor_threshold, 2);
        assert_eq!(roster(3, Some(3)).unwrap().coauthor_threshold, 3);
        assert_eq!(roster(0, None).unwrap().coauthor_threshold, 0);
    }

    /// SINGLE-BYTE FIELDS ARE READ WITH EXACT LENGTH (I-8), AND AN UNKNOWN TAG IS
    /// REJECTED (I-7).
    #[test]
    fn lengths_are_exact_and_unknown_tags_are_refused() {
        let mut w = TlvWriter::new();
        w.put(tag::FILE_ID, &[0x5a; 16]).unwrap();
        w.put(tag::REVOKED, &[1, 0, 0, 0]).unwrap();
        assert!(decode(&w.finish()).is_err(), "четырёхбайтовый `отозван` принят");

        let mut w = TlvWriter::new();
        w.put(tag::FILE_ID, &[0x5a; 16]).unwrap();
        w.put(tag::REVOKED, &[2]).unwrap();
        assert!(decode(&w.finish()).is_err(), "`отозван` со значением 2 принят");

        // Незнакомый тег отвергается, а не пропускается: теги этого документа
        // критичны все до одного.
        let mut w = TlvWriter::new();
        w.put(tag::FILE_ID, &[0x5a; 16]).unwrap();
        w.put(tag::REVOKED, &[0]).unwrap();
        w.put(200, &[1]).unwrap();
        assert!(decode(&w.finish()).is_err(), "незнакомый тег пропущен");
    }
}
