// SPDX-License-Identifier: MPL-2.0
//! File rule based on holder attributes: bytes (F-27, B4b).
//!
//! # Why the rule lives here rather than only on the server
//!
//! Before B4b, the rule was a type in `cc-authority` and a codec in its
//! store: only the operator set it, using a command on the server machine, and
//! its bytes never left the state file. With a signed author order
//! (`order::Kind::SetRule`), those same bytes travel over the wire under a signature;
//! a document signed and verified by different parties must have a single
//! definition, located alongside the other documents.
//!
//! The layout matches the store's pre-move output byte for byte:
//! old server state files remain readable unchanged, and the state
//! fingerprint does not change on upgrade. The store calls this same codec.
//!
//! # Layout
//!
//! TLV, tags in ascending order, all critical:
//!
//! | Tag | Field | Value |
//! |---|---|---|
//! | 1 | lease lifetime cap | `i64le` seconds, positive; optional |
//! | 2 | issuance conditions | condition stream; always written, even when empty |
//! | 3 | restrictions | stream of `[condition, profile]` pairs; only when present |
//!
//! A stream is consecutive `u32le length ‖ bytes`. A condition is `u8 mode ‖ stream [attribute,
//! value…]`. A profile uses the policy codec (`policy_codec`, container version).
//!
//! # What parsing rejects itself
//!
//! A name or value that is not an identifier; a condition without values; "at least" with
//! other than one value; an unknown mode; limits on conditions, values and
//! restrictions; a nonpositive lifetime cap; an empty restrictions stream:
//! the writer never produces one, so it cannot have come from the writer. The meaning of names
//! (whether an attribute exists in the dictionary) is checked by the server, which owns the dictionary.

use oc_policy::Policy;

use oc_format::FormatError;
use oc_format::tlv::{TlvReader, TlvWriter};

/// Maximum attribute name and value length, in bytes.
pub const MAX_NAME_BYTES: usize = 64;
/// Number of values per condition (and per dictionary attribute).
pub const MAX_VALUES: usize = 64;
/// Number of issuance conditions in a rule.
pub const MAX_CLAUSES: usize = 16;
/// Number of restrictions in a rule.
pub const MAX_TIGHTENINGS: usize = 8;

/// Rule tags. All critical (I-7).
pub mod tag {
    pub const MAX_LEASE: u16 = 1;
    pub const CLAUSES: u16 = 2;
    pub const TIGHTENINGS: u16 = 3;
}

/// How a condition interprets its values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode {
    /// At least one listed value.
    AnyOf = 1,
    /// All listed values.
    AllOf = 2,
    /// A value ranked at least as high as the specified one, by dictionary value order.
    /// The condition has exactly one value.
    AtLeast = 3,
}

impl Mode {
    /// Inverse of `as u8`. An unknown number gives `None` and is rejected by parsing.
    #[must_use]
    pub fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::AnyOf),
            2 => Some(Self::AllOf),
            3 => Some(Self::AtLeast),
            _ => None,
        }
    }
}

/// One rule condition: attribute, mode, values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Clause {
    pub attribute: String,
    pub mode: Mode,
    pub values: Vec<String>,
}

/// Holder-based restriction: anyone who does NOT satisfy `unless` gets no more than `profile`.
///
/// The profile is an ordinary policy composed by intersection (`docs/format.md`
/// §4.3), so a restriction can do only what the server's strict profile
/// can do, and cannot expand the author's permissions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tightening {
    /// Who is NOT subject to the restriction.
    pub unless: Clause,
    /// How the policy is restricted for everyone else.
    pub profile: Policy,
}

/// File rule: all conditions together (logical AND between conditions), a lease lifetime
/// cap and holder-based restrictions. An empty rule means no rule.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rule {
    pub clauses: Vec<Clause>,
    /// Maximum lease lifetime for a device that satisfies the rule.
    /// Tightens the author's lifetime rather than extending it: intersection takes the minimum.
    pub max_lease_seconds: Option<i64>,
    /// Holder-based ACTION restrictions. The gate (`clauses`) decides whether to issue;
    /// restrictions determine what is allowed within the issued lease.
    pub tightenings: Vec<Tightening>,
}

impl Rule {
    /// No rule: no conditions, lifetime cap or restrictions. A cap without
    /// conditions is a rule ("everyone, but for a week") and is stored as one.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.clauses.is_empty() && self.max_lease_seconds.is_none() && self.tightenings.is_empty()
    }
}

/// A string is an identifier: Latin letters, digits, `_ . : / -`, from 1 to
/// [`MAX_NAME_BYTES`] bytes.
///
/// The character set is deliberately narrow: names appear in the journal, rejection messages and
/// command lines; a space or quote would prevent the command
/// from being read back unambiguously.
#[must_use]
pub fn is_identifier(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_NAME_BYTES
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'/' | b'-'))
}

/// Command-line condition: `name=a|b` means any, `name=a&b` all, `name>=a` at least.
///
/// One parser serves both `cca` and `cc`: coauthors enter rules on their own machines,
/// and identical strings must yield identical conditions; otherwise signatures
/// would cover different intentions.
///
/// `>=` is checked first: a string containing it also contains `=`, so parsing on `=`
/// would read "name>" as the name. Values containing `|` and `&` cannot be identifiers,
/// so the separators are unambiguous. The codec validates names on encoding.
///
/// # Errors
/// A string without `=`, or one mixing `|` and `&`.
pub fn parse_clause(text: &str) -> Result<Clause, &'static str> {
    if let Some((attribute, value)) = text.split_once(">=") {
        return Ok(Clause {
            attribute: attribute.to_owned(),
            mode: Mode::AtLeast,
            values: vec![value.to_owned()],
        });
    }
    let (attribute, values) = text.split_once('=').ok_or("ожидалось имя=значение")?;
    if values.contains('|') && values.contains('&') {
        return Err("«любое из» и «все» в одном условии не смешиваются");
    }
    let (mode, split): (Mode, char) =
        if values.contains('&') { (Mode::AllOf, '&') } else { (Mode::AnyOf, '|') };
    Ok(Clause {
        attribute: attribute.to_owned(),
        mode,
        values: values.split(split).map(str::to_owned).collect(),
    })
}

/// Encode a rule.
///
/// # Errors
/// [`FormatError`] if the rule fails the same checks as decoding:
/// we do not issue documents that we would refuse to accept.
pub fn encode(rule: &Rule) -> Result<Vec<u8>, FormatError> {
    check(rule)?;
    let mut w = TlvWriter::new();
    if let Some(seconds) = rule.max_lease_seconds {
        w.put(tag::MAX_LEASE, &seconds.to_le_bytes())?;
    }
    let mut clauses = Vec::with_capacity(rule.clauses.len());
    for clause in &rule.clauses {
        clauses.push(encode_clause(clause)?);
    }
    w.put(tag::CLAUSES, &stream(tag::CLAUSES, &clauses)?)?;
    // Только когда есть: правило без ужесточений кодируется теми же байтами,
    // что до их появления.
    if !rule.tightenings.is_empty() {
        let mut items = Vec::with_capacity(rule.tightenings.len());
        for tightening in &rule.tightenings {
            let profile = oc_format::policy_codec::encode(
                oc_format::header::CONTAINER_VERSION,
                &tightening.profile,
            )?;
            items.push(stream(tag::TIGHTENINGS, &[encode_clause(&tightening.unless)?, profile])?);
        }
        w.put(tag::TIGHTENINGS, &stream(tag::TIGHTENINGS, &items)?)?;
    }
    Ok(w.finish().to_vec())
}

/// Decode a rule strictly.
///
/// # Errors
/// [`FormatError`] for an unknown tag, invalid length, unknown mode,
/// non-identifier name or exceeded limit.
pub fn decode(bytes: &[u8]) -> Result<Rule, FormatError> {
    let mut rule = Rule::default();
    let mut clauses_seen = false;
    let mut reader = TlvReader::new(bytes);
    while let Some(field) = reader.next_field()? {
        match field.tag {
            tag::MAX_LEASE => {
                let raw: [u8; 8] = field.value.try_into().map_err(|_| FormatError::BadFieldLength {
                    tag: tag::MAX_LEASE,
                    len: field.value.len(),
                })?;
                rule.max_lease_seconds = Some(i64::from_le_bytes(raw));
            }
            tag::CLAUSES => {
                clauses_seen = true;
                for item in unstream(tag::CLAUSES, field.value, MAX_CLAUSES)? {
                    rule.clauses.push(decode_clause(item)?);
                }
            }
            tag::TIGHTENINGS => {
                let items = unstream(tag::TIGHTENINGS, field.value, MAX_TIGHTENINGS)?;
                // Пустой поток писатель не производит никогда — значит, пришёл
                // не от писателя. Принять его значило бы принять «ужесточения
                // были и пропали».
                if items.is_empty() {
                    return Err(FormatError::BadFieldLength { tag: tag::TIGHTENINGS, len: 0 });
                }
                for item in items {
                    let parts = unstream(tag::TIGHTENINGS, item, 2)?;
                    let [unless, profile] = parts.as_slice() else {
                        return Err(FormatError::BadFieldLength {
                            tag: tag::TIGHTENINGS,
                            len: parts.len(),
                        });
                    };
                    rule.tightenings.push(Tightening {
                        unless: decode_clause(unless)?,
                        profile: oc_format::policy_codec::decode(
                            oc_format::header::SUPPORTED_READER_VERSION,
                            profile,
                        )?,
                    });
                }
            }
            other => crate::unknown::refuse_if_critical(other)?,
        }
    }
    // Поток условий писатель ставит всегда, и его отсутствие — не «условий
    // нет», а документ не от писателя.
    if !clauses_seen {
        return Err(FormatError::MissingField { tag: tag::CLAUSES });
    }
    check(&rule)?;
    Ok(rule)
}

/// Checks shared by encoding and decoding.
fn check(rule: &Rule) -> Result<(), FormatError> {
    if rule.clauses.len() > MAX_CLAUSES {
        return Err(FormatError::BadFieldLength { tag: tag::CLAUSES, len: rule.clauses.len() });
    }
    if rule.tightenings.len() > MAX_TIGHTENINGS {
        return Err(FormatError::BadFieldLength {
            tag: tag::TIGHTENINGS,
            len: rule.tightenings.len(),
        });
    }
    if rule.max_lease_seconds.is_some_and(|seconds| seconds <= 0) {
        return Err(FormatError::UnknownCriticalField { tag: tag::MAX_LEASE });
    }
    for clause in &rule.clauses {
        check_clause(clause, tag::CLAUSES)?;
    }
    for tightening in &rule.tightenings {
        check_clause(&tightening.unless, tag::TIGHTENINGS)?;
    }
    Ok(())
}

/// The condition is satisfiable: names are identifiers, the value count is nonzero and within
/// the limit, and "at least" has exactly one value.
///
/// A condition without values is an error, not "satisfied by everyone": the built-in
/// `all()` returns true for an empty list, so a rule that appeared closed
/// would be satisfied by anyone (I-10).
fn check_clause(clause: &Clause, at: u16) -> Result<(), FormatError> {
    if !is_identifier(&clause.attribute) || !clause.values.iter().all(|v| is_identifier(v)) {
        return Err(FormatError::UnknownCriticalField { tag: at });
    }
    if clause.values.is_empty() || clause.values.len() > MAX_VALUES {
        return Err(FormatError::BadFieldLength { tag: at, len: clause.values.len() });
    }
    if clause.mode == Mode::AtLeast && clause.values.len() != 1 {
        return Err(FormatError::BadFieldLength { tag: at, len: clause.values.len() });
    }
    Ok(())
}

fn encode_clause(clause: &Clause) -> Result<Vec<u8>, FormatError> {
    let mut parts: Vec<Vec<u8>> = Vec::with_capacity(clause.values.len().saturating_add(1));
    parts.push(clause.attribute.as_bytes().to_vec());
    parts.extend(clause.values.iter().map(|value| value.as_bytes().to_vec()));
    let mut item = vec![clause.mode as u8];
    item.extend_from_slice(&stream(tag::CLAUSES, &parts)?);
    Ok(item)
}

fn decode_clause(item: &[u8]) -> Result<Clause, FormatError> {
    let (mode, rest) =
        item.split_first().ok_or(FormatError::BadFieldLength { tag: tag::CLAUSES, len: 0 })?;
    let mode = Mode::from_u8(*mode).ok_or(FormatError::UnknownCriticalField { tag: tag::CLAUSES })?;
    // Атрибут и значения: не больше предела значений плюс одно имя.
    let parts = unstream(tag::CLAUSES, rest, MAX_VALUES.saturating_add(1))?;
    let (attribute, values) =
        parts.split_first().ok_or(FormatError::BadFieldLength { tag: tag::CLAUSES, len: 0 })?;
    Ok(Clause {
        attribute: text(attribute)?,
        mode,
        values: values.iter().map(|value| text(value)).collect::<Result<_, _>>()?,
    })
}

fn text(bytes: &[u8]) -> Result<String, FormatError> {
    core::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| FormatError::UnknownCriticalField { tag: tag::CLAUSES })
}

/// Stream: consecutive `u32le length ‖ bytes`.
fn stream<T: AsRef<[u8]>>(at: u16, items: &[T]) -> Result<Vec<u8>, FormatError> {
    let mut out = Vec::new();
    for item in items {
        let item = item.as_ref();
        let len = u32::try_from(item.len())
            .map_err(|_| FormatError::BadFieldLength { tag: at, len: item.len() })?;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(item);
    }
    Ok(out)
}

/// Decode a stream strictly, with at most `limit` entries.
///
/// The limit is checked BEFORE accumulating entries: otherwise a megabyte stream
/// would force allocation of thousands of entries only to reject them afterward. Truncation within
/// an entry and trailing bytes after the last entry are errors, not "almost correct".
fn unstream(at: u16, bytes: &[u8], limit: usize) -> Result<Vec<&[u8]>, FormatError> {
    let mut out = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        if out.len() >= limit {
            return Err(FormatError::BadFieldLength { tag: at, len: out.len().saturating_add(1) });
        }
        let (head, tail) = rest
            .split_at_checked(4)
            .ok_or(FormatError::BadFieldLength { tag: at, len: rest.len() })?;
        let len = u32::from_le_bytes(
            head.try_into().map_err(|_| FormatError::BadFieldLength { tag: at, len: head.len() })?,
        );
        let len = usize::try_from(len).map_err(|_| FormatError::BadFieldLength { tag: at, len: tail.len() })?;
        let (item, after) = tail
            .split_at_checked(len)
            .ok_or(FormatError::BadFieldLength { tag: at, len: tail.len() })?;
        out.push(item);
        rest = after;
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use oc_policy::Action;

    fn clause(attribute: &str, mode: Mode, values: &[&str]) -> Clause {
        Clause {
            attribute: attribute.to_string(),
            mode,
            values: values.iter().map(|v| (*v).to_string()).collect(),
        }
    }

    fn sample() -> Rule {
        Rule {
            clauses: vec![
                clause("dept", Mode::AnyOf, &["legal", "production"]),
                clause("contract", Mode::AtLeast, &["2026"]),
            ],
            max_lease_seconds: Some(86_400),
            tightenings: vec![Tightening {
                unless: clause("clearance", Mode::AllOf, &["secret"]),
                profile: Policy::deny_all().allow(Action::View),
            }],
        }
    }

    #[test]
    fn a_rule_survives_the_round_trip() {
        let bytes = encode(&sample()).unwrap();
        assert_eq!(decode(&bytes).unwrap(), sample());
        // Пустое правило — законный документ: «правила нет».
        let empty = encode(&Rule::default()).unwrap();
        assert!(decode(&empty).unwrap().is_empty());
    }

    /// WITHOUT RESTRICTIONS, THE OLD BYTES: tag 3 is not written at all.
    #[test]
    fn without_tightenings_the_third_tag_is_absent() {
        let plain = Rule { tightenings: Vec::new(), ..sample() };
        let bytes = encode(&plain).unwrap();
        let mut reader = TlvReader::new(&bytes);
        while let Some(field) = reader.next_field().unwrap() {
            assert_ne!(field.tag, tag::TIGHTENINGS, "пустые ужесточения записаны");
        }
    }

    #[test]
    fn a_hostile_rule_is_refused_on_parsing() {
        let bad = |rule: Rule, why: &str| {
            assert!(encode(&rule).is_err(), "записано: {why}");
        };
        bad(Rule { clauses: vec![clause("dept", Mode::AnyOf, &[])], ..Rule::default() }, "пустое условие");
        bad(Rule { clauses: vec![clause("dept", Mode::AtLeast, &["a", "b"])], ..Rule::default() }, "«не ниже» двух");
        bad(Rule { clauses: vec![clause("отдел", Mode::AnyOf, &["a"])], ..Rule::default() }, "не идентификатор");
        bad(Rule { clauses: vec![clause("dept", Mode::AnyOf, &["a b"])], ..Rule::default() }, "пробел в значении");
        bad(Rule { max_lease_seconds: Some(0), ..Rule::default() }, "нулевой потолок");
        bad(
            Rule { clauses: vec![clause("dept", Mode::AnyOf, &["a"]); MAX_CLAUSES + 1], ..Rule::default() },
            "условий сверх предела",
        );

        // Незнакомый режим — байтами, писатель его не произведёт.
        let mut bytes = encode(&Rule { clauses: vec![clause("dept", Mode::AnyOf, &["a"])], ..Rule::default() }).unwrap();
        let at = bytes.iter().position(|b| *b == Mode::AnyOf as u8).unwrap();
        bytes[at] = 9;
        assert!(decode(&bytes).is_err(), "незнакомый режим разобран");

        // Условие без значений — байтами: писатель его не произведёт, а разбор
        // обязан отвергнуть сам (правило, выглядящее закрытым, выполнялось бы
        // у кого угодно).
        let mut item = vec![Mode::AllOf as u8];
        item.extend_from_slice(&stream(tag::CLAUSES, &[b"dept".to_vec()]).unwrap());
        let mut w = TlvWriter::new();
        w.put(tag::CLAUSES, &stream(tag::CLAUSES, &[item]).unwrap()).unwrap();
        assert!(decode(&w.finish()).is_err(), "условие без значений разобрано");

        // Без потока условий — не документ писателя.
        let mut w = TlvWriter::new();
        w.put(tag::MAX_LEASE, &10i64.to_le_bytes()).unwrap();
        assert!(matches!(decode(&w.finish()), Err(FormatError::MissingField { .. })));

        // Пустой поток ужесточений.
        let mut w = TlvWriter::new();
        w.put(tag::CLAUSES, &[]).unwrap();
        w.put(tag::TIGHTENINGS, &[]).unwrap();
        assert!(decode(&w.finish()).is_err(), "пустой поток ужесточений разобран");

        // Незнакомый тег.
        let mut w = TlvWriter::new();
        w.put(tag::CLAUSES, &[]).unwrap();
        w.put(9, &[1]).unwrap();
        assert!(matches!(decode(&w.finish()), Err(FormatError::UnknownCriticalField { tag: 9 })));
    }

    #[test]
    fn a_clause_is_read_from_the_command_line_one_way() {
        assert_eq!(parse_clause("dept=legal|production").unwrap(), clause("dept", Mode::AnyOf, &["legal", "production"]));
        assert_eq!(parse_clause("dept=legal&production").unwrap(), clause("dept", Mode::AllOf, &["legal", "production"]));
        assert_eq!(parse_clause("contract>=2026").unwrap(), clause("contract", Mode::AtLeast, &["2026"]));
        assert_eq!(parse_clause("dept=legal").unwrap(), clause("dept", Mode::AnyOf, &["legal"]));
        assert!(parse_clause("dept").is_err());
        assert!(parse_clause("dept=a|b&c").is_err(), "смешанное условие разобрано");
    }

    /// PARSING ARBITRARY BYTES DOES NOT PANIC.
    #[test]
    fn decoding_arbitrary_bytes_never_panics() {
        let bytes = encode(&sample()).unwrap();
        for cut in 0..bytes.len() {
            let _ = decode(&bytes[..cut]);
        }
        for at in 0..bytes.len() {
            let mut damaged = bytes.clone();
            damaged[at] ^= 0xff;
            let _ = decode(&damaged);
        }
        // Поток, объявляющий огромную запись, — отказ, а не выделение.
        let mut w = TlvWriter::new();
        w.put(tag::CLAUSES, &u32::MAX.to_le_bytes()).unwrap();
        assert!(decode(&w.finish()).is_err());
    }
}
