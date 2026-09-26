// SPDX-License-Identifier: MPL-2.0
//! TLV fields with strictly increasing numeric tags.
//!
//! Ordering rejects duplicates and reordered fields. Each codec separately checks
//! field lengths and canonical values. Tag ranges distinguish unknown critical
//! fields, which require rejection, from optional fields that can be skipped.
//! Slot parsing applies the same rule with slot-level rather than file-level rejection.

use crate::FormatError;
use core::ops::Range;
use zeroize::Zeroizing;

/// Tags no greater than this value are critical: an unknown one means rejection.
pub const CRIT_TAG_MAX: u16 = 0x7FFF;

/// Field header: tag (u16) and length (u32).
///
/// Public because excluding records from `core_hash` depends on it: that requires
/// the RECORD boundary, not the value boundary, computed by subtracting this length
/// from the value's start. A second source of truth for this number would mean
/// that changing the width of a tag or length silently breaks the core hash,
/// and only for some files.
pub const FIELD_PREFIX_LEN: usize = 6;

/// Parsed field with the exact range of its value in the original buffer.
///
/// The range is essential, not a convenience: policy and header core hashes use
/// original bytes rather than a re-encoding of the parsed structure, avoiding
/// the whole family of canonicalization bugs known from JWS and XML-DSig.
#[derive(Clone, PartialEq, Eq)]
pub struct Field<'a> {
    pub tag: u16,
    pub value: &'a [u8],
    /// Value range in the buffer passed to [`TlvReader::new`].
    pub span: Range<usize>,
}

impl core::fmt::Debug for Field<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Field").field("tag", &self.tag)
            .field("value_len", &self.value.len()).field("span", &self.span).finish()
    }
}

impl<'a> Field<'a> {
    /// Value as exactly one byte.
    pub fn u8(&self) -> Result<u8, FormatError> {
        match self.value {
            [b] => Ok(*b),
            _ => Err(FormatError::BadFieldLength { tag: self.tag, len: self.value.len() }),
        }
    }

    /// Value as a little-endian `u16`.
    pub fn u16(&self) -> Result<u16, FormatError> {
        self.array::<2>().map(u16::from_le_bytes)
    }

    /// Value as a little-endian `u32`.
    pub fn u32(&self) -> Result<u32, FormatError> {
        self.array::<4>().map(u32::from_le_bytes)
    }

    /// Value as a little-endian `u64`.
    pub fn u64(&self) -> Result<u64, FormatError> {
        self.array::<8>().map(u64::from_le_bytes)
    }

    /// Value as an array of an exact length.
    ///
    /// Length is checked, not adjusted: a short value is not padded with
    /// zeros and a long one is not truncated. Otherwise the attacker controls
    /// which bytes enter a key or fingerprint.
    pub fn array<const N: usize>(&self) -> Result<[u8; N], FormatError> {
        <[u8; N]>::try_from(self.value)
            .map_err(|_| FormatError::BadFieldLength { tag: self.tag, len: self.value.len() })
    }
}

/// Sequential field reading with increasing-tag validation.
pub struct TlvReader<'a> {
    buf: &'a [u8],
    pos: usize,
    last_tag: Option<u16>,
}

impl core::fmt::Debug for TlvReader<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TlvReader").field("len", &self.buf.len())
            .field("pos", &self.pos).field("last_tag", &self.last_tag).finish()
    }
}

impl<'a> TlvReader<'a> {
    /// Start reading. Parses nothing: parsing happens in [`TlvReader::next_field`].
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0, last_tag: None }
    }

    /// Whether the entire buffer has been read.
    pub fn is_exhausted(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// Next field, or `None` at the end of the buffer.
    ///
    /// Total: every buffer either parses or yields an error, never
    /// panicking or looping forever: the position strictly increases on every step.
    pub fn next_field(&mut self) -> Result<Option<Field<'a>>, FormatError> {
        if self.pos >= self.buf.len() {
            return Ok(None);
        }

        let header_end = self
            .pos
            .checked_add(FIELD_PREFIX_LEN)
            .ok_or(FormatError::OffsetOverflow)?;
        let prefix = self.buf.get(self.pos..header_end).ok_or(FormatError::Truncated {
            need: header_end as u64,
            have: self.buf.len() as u64,
        })?;

        let tag = prefix
            .get(0..2)
            .and_then(|s| <[u8; 2]>::try_from(s).ok())
            .map(u16::from_le_bytes)
            .ok_or(FormatError::OffsetOverflow)?;
        let len = prefix
            .get(2..6)
            .and_then(|s| <[u8; 4]>::try_from(s).ok())
            .map(u32::from_le_bytes)
            .ok_or(FormatError::OffsetOverflow)? as usize;

        // Возрастание тегов — единственное правило канонизации в этом формате.
        // Равенство запрещено тоже: два поля с одним тегом означали бы, что
        // читатель волен выбрать любое из них, а разные читатели выбрали бы разные.
        match self.last_tag {
            Some(prev) if tag <= prev => {
                return Err(FormatError::FieldsOutOfOrder { previous: prev, found: tag });
            }
            _ => {}
        }

        let value_end = header_end.checked_add(len).ok_or(FormatError::OffsetOverflow)?;
        let value = self.buf.get(header_end..value_end).ok_or(FormatError::Truncated {
            need: value_end as u64,
            have: self.buf.len() as u64,
        })?;

        self.last_tag = Some(tag);
        self.pos = value_end;
        Ok(Some(Field { tag, value, span: header_end..value_end }))
    }
}

/// Write fields while enforcing increasing tags, matching reader validation.
///
/// The self-wiping buffer also carries private metadata such as filenames.
/// Zeroizing wipes owned contents on drop; it does not make Vec growth safe for
/// secrets or prove erasure of copies made by callers.
#[derive(Default)]
pub struct TlvWriter {
    buf: Zeroizing<Vec<u8>>,
    last_tag: Option<u16>,
}

impl core::fmt::Debug for TlvWriter {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // TLV also carries key seeds and private metadata.
        f.debug_struct("TlvWriter").field("len", &self.buf.len())
            .field("last_tag", &self.last_tag).finish()
    }
}

impl TlvWriter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Writer with a known initial capacity.
    ///
    /// Buffer growth is safe (see `TlvWriter::reserve`) but not free:
    /// every reallocation copies and wipes everything accumulated. Where
    /// the final size is known beforehand, growth is best avoided altogether.
    pub fn with_capacity(capacity: usize) -> Self {
        Self { buf: Zeroizing::new(Vec::with_capacity(capacity)), last_tag: None }
    }

    /// Make room for `extra` bytes without scattering already-written data across the heap.
    ///
    /// Ordinary `Vec` growth returns the old block to the allocator untouched, so the filename
    /// would remain in freed heap memory once for every
    /// reallocation: a growing buffer here is worse than an unwiped one. A new buffer
    /// is explicitly allocated, the old one is moved to a local variable and wiped by its
    /// `Drop` **before** memory is returned to the allocator.
    fn reserve(&mut self, extra: usize) -> Result<(), FormatError> {
        let needed = self.buf.len().checked_add(extra).ok_or(FormatError::OffsetOverflow)?;
        if needed <= self.buf.capacity() {
            return Ok(());
        }
        // Удвоение, а не рост впритык: иначе каждое поле стоило бы копирования и
        // затирания всего буфера, и запись заголовка стала бы квадратичной.
        let target = needed.max(self.buf.capacity().saturating_mul(2));
        let mut previous = Zeroizing::new(Vec::with_capacity(target));
        previous.extend_from_slice(&self.buf);
        core::mem::swap(&mut self.buf, &mut previous);
        Ok(())
    }

    /// Write a field. Tags must be increasing.
    pub fn put(&mut self, tag: u16, value: &[u8]) -> Result<(), FormatError> {
        match self.last_tag {
            Some(prev) if tag <= prev => {
                return Err(FormatError::FieldsOutOfOrder { previous: prev, found: tag });
            }
            _ => {}
        }
        let len = u32::try_from(value.len())
            .map_err(|_| FormatError::BadFieldLength { tag, len: value.len() })?;
        // Место под заголовок поля и значение берётся одним куском заранее:
        // три `extend_from_slice` подряд по растущему буферу дали бы до трёх
        // перевыделений на поле, а значит и до трёх копий значения в куче.
        self.reserve(FIELD_PREFIX_LEN.saturating_add(value.len()))?;
        self.buf.extend_from_slice(&tag.to_le_bytes());
        self.buf.extend_from_slice(&len.to_le_bytes());
        self.buf.extend_from_slice(value);
        self.last_tag = Some(tag);
        Ok(())
    }

    /// Write an optional field: `None` takes no space.
    pub fn put_opt(&mut self, tag: u16, value: Option<&[u8]>) -> Result<(), FormatError> {
        match value {
            Some(v) => self.put(tag, v),
            None => Ok(()),
        }
    }

    /// Finished bytes in a zeroizing wrapper.
    ///
    /// The return type is part of the guarantee, not decoration: if this function returned
    /// an ordinary `Vec`, everything the writer carefully avoided scattering across the heap
    /// would be returned intact to the allocator by the caller's first `drop`. Callers needing
    /// specifically public bytes (header, policy, content description) explicitly copy them
    /// with `to_vec`, making that choice visible in code.
    pub fn finish(self) -> Zeroizing<Vec<u8>> {
        self.buf
    }

    /// Current length.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

/// How to handle a field whose tag the reader does not recognize.
///
/// Separation by tag range is the format's most valuable extension point. Without it,
/// every significant field in the next version becomes a rejection event.
pub fn unknown_tag_action(tag: u16) -> UnknownTag {
    if tag <= CRIT_TAG_MAX { UnknownTag::Refuse } else { UnknownTag::Ignore }
}

/// Decision for an unknown tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownTag {
    /// Critical range: the file uses semantics we do not understand.
    Refuse,
    /// Optional range: skip.
    Ignore,
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn encoded(fields: &[(u16, &[u8])]) -> Vec<u8> {
        let mut w = TlvWriter::new();
        for (tag, value) in fields {
            w.put(*tag, value).unwrap();
        }
        w.finish().to_vec()
    }

    fn read_all(buf: &[u8]) -> Result<Vec<(u16, Vec<u8>)>, FormatError> {
        let mut r = TlvReader::new(buf);
        let mut out = Vec::new();
        while let Some(f) = r.next_field()? {
            out.push((f.tag, f.value.to_vec()));
        }
        Ok(out)
    }

    #[test]
    fn round_trips_fields_in_order() {
        let buf = encoded(&[(1, b"a"), (5, b""), (9, b"hello")]);
        let got = read_all(&buf).unwrap();
        assert_eq!(got, vec![(1, b"a".to_vec()), (5, vec![]), (9, b"hello".to_vec())]);
    }

    #[test]
    fn duplicate_tags_are_impossible_to_write_and_to_read() {
        // Дубликат означал бы, что читатель волен выбрать любое из двух значений,
        // а разные читатели выбрали бы разные. Это классический источник
        // расхождения между тем, что проверила подпись, и тем, что применил код.
        let mut w = TlvWriter::new();
        w.put(3, b"first").unwrap();
        assert!(matches!(w.put(3, b"second"), Err(FormatError::FieldsOutOfOrder { .. })));

        // И на чтении тоже — на случай, если заголовок собран не нашим кодом.
        let mut hand_made = Vec::new();
        for value in [b"first".as_ref(), b"second".as_ref()] {
            hand_made.extend_from_slice(&3u16.to_le_bytes());
            hand_made.extend_from_slice(&(value.len() as u32).to_le_bytes());
            hand_made.extend_from_slice(value);
        }
        assert!(matches!(
            read_all(&hand_made),
            Err(FormatError::FieldsOutOfOrder { previous: 3, found: 3 })
        ));
    }

    #[test]
    fn reordered_fields_are_refused() {
        let mut hand_made = Vec::new();
        for tag in [9u16, 1u16] {
            hand_made.extend_from_slice(&tag.to_le_bytes());
            hand_made.extend_from_slice(&0u32.to_le_bytes());
        }
        assert!(matches!(
            read_all(&hand_made),
            Err(FormatError::FieldsOutOfOrder { previous: 9, found: 1 })
        ));
    }

    #[test]
    fn spans_point_at_the_original_bytes() {
        // Хеши считаются по диапазону исходных байтов, а не по повторной
        // кодировке: именно это закрывает семейство ошибок канонизации.
        let buf = encoded(&[(1, b"abc"), (2, b"defg")]);
        let mut r = TlvReader::new(&buf);
        let f1 = r.next_field().unwrap().unwrap();
        let f2 = r.next_field().unwrap().unwrap();
        assert_eq!(&buf[f1.span.clone()], b"abc");
        assert_eq!(&buf[f2.span.clone()], b"defg");
    }

    #[test]
    fn truncation_at_every_boundary_is_an_error_not_a_panic() {
        let buf = encoded(&[(1, b"abc"), (7, b"defgh")]);
        for cut in 0..buf.len() {
            match read_all(&buf[..cut]) {
                Ok(fields) => {
                    // Обрыв ровно на границе поля — допустимое короткое чтение.
                    assert!(fields.len() < 2, "обрезание на {cut} байтах прошло целиком");
                }
                Err(FormatError::Truncated { .. }) => {}
                Err(other) => panic!("обрезание на {cut} байтах дало {other:?}"),
            }
        }
    }

    #[test]
    fn a_declared_length_larger_than_the_buffer_is_refused() {
        // Классический вектор: объявить гигантскую длину и заставить читателя
        // выделить память или прочитать чужие байты.
        let mut hand_made = Vec::new();
        hand_made.extend_from_slice(&1u16.to_le_bytes());
        hand_made.extend_from_slice(&u32::MAX.to_le_bytes());
        hand_made.extend_from_slice(b"short");
        assert!(matches!(read_all(&hand_made), Err(FormatError::Truncated { .. })));
    }

    #[test]
    fn never_panics_on_arbitrary_bytes() {
        let mut soup: Vec<u8> = Vec::new();
        for i in 0..512u16 {
            soup.push((i % 256) as u8);
        }
        for cut in 0..soup.len() {
            let _ = read_all(&soup[..cut]);
        }
    }

    #[test]
    fn typed_accessors_check_length_exactly() {
        let buf = encoded(&[(1, &[7]), (2, &2000u16.to_le_bytes()), (3, b"xxx")]);
        let mut r = TlvReader::new(&buf);
        assert_eq!(r.next_field().unwrap().unwrap().u8().unwrap(), 7);
        assert_eq!(r.next_field().unwrap().unwrap().u16().unwrap(), 2000);
        // Три байта — это не u32 и не u16: длина проверяется, а не подгоняется.
        let f = r.next_field().unwrap().unwrap();
        assert!(matches!(f.u32(), Err(FormatError::BadFieldLength { tag: 3, len: 3 })));
        assert!(matches!(f.u16(), Err(FormatError::BadFieldLength { tag: 3, len: 3 })));
    }

    #[test]
    fn unknown_critical_tags_are_refused_and_optional_ones_ignored() {
        assert_eq!(unknown_tag_action(0), UnknownTag::Refuse);
        assert_eq!(unknown_tag_action(CRIT_TAG_MAX), UnknownTag::Refuse);
        assert_eq!(unknown_tag_action(CRIT_TAG_MAX + 1), UnknownTag::Ignore);
        assert_eq!(unknown_tag_action(u16::MAX), UnknownTag::Ignore);
    }

    #[test]
    fn empty_buffer_yields_no_fields() {
        assert_eq!(read_all(&[]).unwrap(), vec![]);
    }
}
