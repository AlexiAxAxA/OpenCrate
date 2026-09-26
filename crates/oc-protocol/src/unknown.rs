// SPDX-License-Identifier: MPL-2.0
//! Shared unknown-tag handling for protocol codecs (I-7).
//!
//! `oc_format::tlv::unknown_tag_action` decides whether to reject or skip a field.
//! Codecs that check canonical re-encoding must omit skipped entries from that
//! comparison, since their encoder cannot reproduce unknown fields. Signatures
//! still authenticate the original body, including those entries.

use core::ops::Range;
use oc_format::FormatError;
use oc_format::tlv::{FIELD_PREFIX_LEN, Field, UnknownTag, unknown_tag_action};

/// Reject an unknown critical tag; skip an optional one.
///
/// # Errors
/// [`FormatError::UnknownCriticalField`] for a critical tag.
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
