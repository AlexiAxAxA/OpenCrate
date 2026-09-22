//! Transcript: the only way to obtain bytes for a signature or MAC.
//!
//! This type exists for one invariant: **signing bytes without domain
//! separation is impossible**. Its constructor requires a label, and signing functions accept
//! only [`Transcript`], so a label cannot be forgotten: the code simply will
//! not compile.
//!
//! Otherwise, an author's signature made in one context (revocation record, activation
//! request, permission grant) becomes replayable in another if
//! encodings can collide. A silent error detectable only by an attack.

use crate::label::Label;

/// Bytes prepared for signing or MAC computation, with a mandatory domain label.
#[derive(Clone, PartialEq, Eq)]
pub struct Transcript {
    buf: Vec<u8>,
}

impl core::fmt::Debug for Transcript {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Transcript({} байт)", self.buf.len())
    }
}

impl Transcript {
    /// Begin a transcript with a domain label.
    ///
    /// The label has type [`Label`], not `&'static [u8]`, a substantive
    /// difference: a `Label` cannot be invented; only constants in
    /// [`crate::label`] supply it. When bytes were accepted, I-12 checks
    /// inspected the registry while a caller could bypass it with a string
    /// absent from the registry (for example an extension of an occupied label), invisible to
    /// every probe. That no longer compiles.
    #[must_use]
    pub fn new(label: Label) -> Self {
        let bytes = label.as_bytes();
        let mut buf = Vec::with_capacity(bytes.len().saturating_add(64));
        buf.extend_from_slice(bytes);
        buf.push(0x00);
        Self { buf }
    }

    /// Append one byte: algorithm identifier, version, tag.
    pub fn u8(&mut self, value: u8) -> &mut Self {
        self.buf.push(value);
        self
    }

    /// Append a little-endian `u32`. Order is specified by the format.
    pub fn u32le(&mut self, value: u32) -> &mut Self {
        self.buf.extend_from_slice(&value.to_le_bytes());
        self
    }

    /// Append a big-endian `u32`, used for chunk indices.
    pub fn u32be(&mut self, value: u32) -> &mut Self {
        self.buf.extend_from_slice(&value.to_be_bytes());
        self
    }

    /// Append a big-endian `u64`, used for lease sequences.
    pub fn u64be(&mut self, value: u64) -> &mut Self {
        self.buf.extend_from_slice(&value.to_be_bytes());
        self
    }

    /// Append fixed-length data: key, fingerprint, identifier.
    ///
    /// For **variable-length** fields use [`Transcript::field`], or
    /// two different field sequences can produce identical bytes and the signature
    /// ceases to identify contents unambiguously.
    pub fn fixed(&mut self, value: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(value);
        self
    }

    /// Append a variable-length field with a length prefix.
    pub fn field(&mut self, value: &[u8]) -> &mut Self {
        let len = u32::try_from(value.len()).unwrap_or(u32::MAX);
        self.buf.extend_from_slice(&len.to_le_bytes());
        self.buf.extend_from_slice(value);
        self
    }

    /// Append a final block without a length prefix.
    ///
    /// Permitted **only** when its length was already written into the transcript,
    /// as in a header signature, where `u32le(HeaderLen)` precedes
    /// the header itself.
    pub fn tail_after_declared_length(&mut self, value: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(value);
        self
    }

    /// Completed bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Byte length.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether the transcript is empty. A label is always present, so always `false`.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::label;

    #[test]
    fn every_transcript_starts_with_its_label() {
        let t = Transcript::new(label::LEASE);
        assert!(t.as_bytes().starts_with(label::LEASE.as_bytes()));
        assert_eq!(t.as_bytes().get(label::LEASE.len()), Some(&0x00));
    }

    #[test]
    fn prefix_labels_do_not_collide_even_though_the_set_is_prefix_free() {
        // Двойная страховка: набор меток беспрефиксный, и сверх того транскрипт
        // ставит нулевой байт после метки. Тест фиксирует вторую защиту, чтобы
        // её не убрали как «избыточную».
        let mut a = Transcript::new(label::LEASE);
        a.fixed(b"-cache-and-more");
        let mut b = Transcript::new(label::CACHED_LEASE);
        b.fixed(b"-and-more");
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn different_labels_never_collide() {
        // Смысл всего типа: одни и те же данные под разными метками дают разные
        // байты, поэтому подпись из одного контекста не проходит в другом.
        let mut a = Transcript::new(label::LEASE);
        a.fixed(&[1, 2, 3]);
        let mut b = Transcript::new(label::REVOCATION);
        b.fixed(&[1, 2, 3]);
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn variable_length_fields_are_unambiguous() {
        // Без префикса длины ("ab","c") и ("a","bc") дали бы одни байты.
        let mut a = Transcript::new(label::GRANT);
        a.field(b"ab").field(b"c");
        let mut b = Transcript::new(label::GRANT);
        b.field(b"a").field(b"bc");
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn fixed_length_fields_are_concatenated_verbatim() {
        let mut t = Transcript::new(label::CHUNK);
        t.fixed(&[0xaa; 16]).u32be(7).u8(1);
        let expected_len = label::CHUNK.len() + 1 + 16 + 4 + 1;
        assert_eq!(t.len(), expected_len);
        assert_eq!(t.as_bytes().get(t.len() - 5..t.len()), Some(&[0, 0, 0, 7, 1][..]));
    }

    #[test]
    fn endianness_is_explicit_and_distinct() {
        let mut le = Transcript::new(label::CHUNK);
        le.u32le(1);
        let mut be = Transcript::new(label::CHUNK);
        be.u32be(1);
        assert_ne!(le.as_bytes(), be.as_bytes(), "порядок байтов обязан быть явным");
    }
}
