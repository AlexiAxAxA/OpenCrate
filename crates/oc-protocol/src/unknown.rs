//! The crate's shared rule for unknown tags (I-7, decision of 2026-09-21).
//!
//! Tag decisions are made by `oc_format::tlv::unknown_tag_action`, the same
//! function the container uses. There is deliberately no second implementation here: two places
//! computing the critical-range boundary would silently diverge, and do so
//! in exactly the direction of "skipped what should have been rejected".
//!
//! # Why a helper rather than a line in every parser
//!
//! The crate has fourteen document parsers; three `match` lines repeated verbatim
//! fourteen times are a known repository problem: one path
//! gets fixed while its neighbor is forgotten. Here there is nothing to forget: one rule in
//! one place.
//!
//! # Why the second helper REMEMBERS skipped entries
//!
//! Some documents check themselves: the parsed structure
//! is re-encoded and must reproduce the ORIGINAL bytes (`control::Binding`,
//! `ControlRequest`, `Receipt`, `Transfer`, `directory::Record`). This check
//! is deliberate: it establishes canonicality. A body our encoder does not
//! reproduce lacks a unique representation, yet its exact bytes determine
//! the signature, countersignature and directory journal leaf.
//!
//! A skipped optional tag breaks this comparison: re-encoding loses it.
//! Thus the comparison uses the body WITHOUT skipped entries rather than the entire body:
//! canonicality of KNOWN fields remains guarded, while unknown optional fields
//! bypass that check. Entire entries (tag, length, value) are removed using the same
//! technique as I-3.

use core::ops::Range;
use oc_format::FormatError;
use oc_format::tlv::{FIELD_PREFIX_LEN, Field, UnknownTag, unknown_tag_action};

/// Decision for an unknown tag: reject critical, skip optional.
///
/// The error variant is the one the crate returned for EVERY unknown tag before
/// the decision of 2026-09-21: behavior for the critical range is entirely unchanged,
/// including the rejection text.
///
/// # Errors
/// [`FormatError::UnknownCriticalField`]: a tag from the critical range.
pub(crate) fn refuse_if_critical(tag: u16) -> Result<(), FormatError> {
    match unknown_tag_action(tag) {
        UnknownTag::Refuse => Err(FormatError::UnknownCriticalField { tag }),
        UnknownTag::Ignore => Ok(()),
    }
}

/// The same decision, but remembering which entries were skipped.
#[derive(Debug, Default)]
pub(crate) struct Skipped {
    /// Ranges of ENTRIES (tag, length, value) in the body passed to the parser.
    spans: Vec<Range<usize>>,
}

impl Skipped {
    /// Observe an unknown field: reject critical, remember optional.
    ///
    /// # Errors
    /// [`FormatError::UnknownCriticalField`]: a tag from the critical range.
    pub(crate) fn see(&mut self, field: &Field<'_>) -> Result<(), FormatError> {
        refuse_if_critical(field.tag)?;
        // Граница ЗАПИСИ, а не значения: длина префикса берётся у формата, а не
        // повторяется здесь числом — иначе смена ширины тега разъехалась бы с
        // вырезом молча (тот же довод, что у `FIELD_PREFIX_LEN`).
        let start = field.span.start.checked_sub(FIELD_PREFIX_LEN).ok_or(FormatError::OffsetOverflow)?;
        self.spans.push(start..field.span.end);
        Ok(())
    }

    /// The body without skipped entries, against which re-encoding is compared.
    ///
    /// Ranges ascend by construction: tags strictly increase (I-7),
    /// so offsets do too. Ordering is neither restored nor
    /// checked here: it is a property of traversal, not of this data.
    pub(crate) fn strip(&self, body: &[u8]) -> Vec<u8> {
        if self.spans.is_empty() {
            return body.to_vec();
        }
        let mut out = Vec::with_capacity(body.len());
        let mut cut = 0usize;
        for span in &self.spans {
            if let Some(keep) = body.get(cut..span.start) {
                out.extend_from_slice(keep);
            }
            cut = span.end;
        }
        if let Some(tail) = body.get(cut..) {
            out.extend_from_slice(tail);
        }
        out
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use oc_format::tlv::{CRIT_TAG_MAX, TlvReader, TlvWriter};

    #[test]
    fn the_critical_range_is_refused_and_the_optional_one_is_not() {
        assert!(refuse_if_critical(1).is_err());
        assert!(refuse_if_critical(CRIT_TAG_MAX).is_err());
        assert!(refuse_if_critical(CRIT_TAG_MAX + 1).is_ok());
        assert!(refuse_if_critical(u16::MAX).is_ok());
    }

    /// The trimmed body is exactly what the encoder would write without extra fields.
    #[test]
    fn stripping_gives_back_the_body_the_writer_would_have_written() {
        let mut w = TlvWriter::new();
        w.put(1, b"one").unwrap();
        w.put(0x8ABC, b"unknown").unwrap();
        w.put(0x8ABD, b"").unwrap();
        let with_extra = w.finish().to_vec();

        let mut w = TlvWriter::new();
        w.put(1, b"one").unwrap();
        let without = w.finish().to_vec();

        let mut skipped = Skipped::default();
        let mut reader = TlvReader::new(&with_extra);
        while let Some(field) = reader.next_field().unwrap() {
            if field.tag != 1 {
                skipped.see(&field).unwrap();
            }
        }
        assert_eq!(skipped.strip(&with_extra), without);
        // Ничего не пропущено — тело отдаётся как есть.
        assert_eq!(Skipped::default().strip(&without), without);
    }
}
