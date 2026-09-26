// SPDX-License-Identifier: MPL-2.0
// Арифметика длин и смещений — это и есть границы формата, поэтому здесь она
// поднята с `warn` (уровень workspace) до `deny`. Атрибутом крейта, а не строкой
// в `Cargo.toml`: `[lints] workspace = true` не смешивается с локальными
// правилами, а отказываться от наследования всей таблицы ради одного лита
// значило бы потерять остальные.
//
// Точечные `#[allow]` допустимы там, где невозможность переполнения следует из
// типа (например, деление на `NonZeroU32`), и каждый обязан нести объяснение.
#![deny(clippy::arithmetic_side_effects)]

//! Parsing and assembling the `.cc` container.
//!
//! The host supplies bytes; this crate performs no I/O, clock reads, or random
//! generation. Authentication uses original byte slices, never reserialization
//! (`docs/format.md` §5). [`Prologue::split`] checks structural boundaries, and
//! [`verify::verify_and_parse`] verifies the header and reports signer trust.
//!
//! Client/server documents live in `oc-protocol`, which depends on this crate.
//! [`FormatError`] is shared with those codecs, so some variants describe protocol
//! errors rather than container errors.

pub mod content;
pub mod edit;
pub mod encoding;
pub mod footer;
pub mod frame;
pub mod header;
pub mod policy_codec;
pub mod text;
pub mod tlv;
pub mod verify;

use core::fmt;
use core::num::NonZeroU32;
use core::ops::Range;

/// Version 1 magic. A breaking format change changes it, causing old clients
/// to reject the file without attempting to parse its content.
pub const MAGIC: [u8; 8] = *b"CLOSECR1";

/// Ed25519 signature length.
pub const SIG_LEN: usize = 64;

/// Stored XChaCha20-Poly1305 nonce length.
pub const NONCE_LEN: u64 = 24;

/// Poly1305 tag length.
pub const TAG_LEN: u64 = 16;

/// Upper bound on header size. Checked before allocation so that
/// the declared length cannot become a memory-exhaustion vector.
pub const MAX_HEADER_LEN: u32 = 1 << 20;

/// Upper bound on the number of key slots.
pub const MAX_KEY_SLOTS: usize = 1024;

/// Allowed chunk size range. The lower bound is the page size; the upper bound
/// keeps read amplification tolerable (`docs/format.md` 6.2).
pub const MIN_CHUNK_SIZE: u32 = 4 * 1024;
/// Upper bound on chunk size.
pub const MAX_CHUNK_SIZE: u32 = 1024 * 1024;

/// The single definition of which chunk sizes are valid.
///
/// Deliberately public: the header assembler, the parser, and the code
/// accepting the user's command-line value must all check the size.
/// A condition written in three places diverges at the first boundary change,
/// and does so silently: a file accepted by one check ends up
/// rejected by another.
///
/// Input validation is protection, not convenience: the value reaches
/// `SecretBuf::with_capacity`, allocating and zeroing a buffer, even before
/// the header is assembled. Without this check, `--chunk-size 4000000000`
/// would attempt a four-gigabyte allocation, and allocation failure in Rust means
/// process `abort`, not an error that can be shown to the user.
pub fn check_chunk_size(size: u32) -> Result<u32, FormatError> {
    if (MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&size) && size.is_power_of_two() {
        Ok(size)
    } else {
        Err(FormatError::BadChunkSize { got: size })
    }
}

/// Offset of the header length field.
const HEADER_LEN_OFFSET: usize = MAGIC.len();
/// Offset of the header itself.
const HEADER_OFFSET: usize = HEADER_LEN_OFFSET + 4;

/// Protected file identity: 16 random bytes.
///
/// Deliberately not UUIDv7: it embeds creation time and would reveal the packaging
/// date to anyone holding a container even before they can open it.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileId(pub [u8; 16]);

impl fmt::Debug for FileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FileId(")?;
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ")")
    }
}

/// Structural parsing errors. All mean "this buffer is not our container",
/// and none carries data from the content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatError {
    /// The first eight bytes do not match [`MAGIC`].
    BadMagic,
    /// Declared header length exceeds [`MAX_HEADER_LEN`].
    HeaderTooLarge { declared: u32 },
    /// The buffer is shorter than the declared structure requires.
    Truncated { need: u64, have: u64 },
    /// Offsets do not fit in `usize` on this platform.
    OffsetOverflow,
    /// Chunk size is out of range or not a power of two.
    BadChunkSize { got: u32 },
    /// Chunk count does not match the total length.
    ChunkCountMismatch { expected: u32, got: u32 },
    /// Access to a chunk beyond the file.
    ChunkOutOfRange { index: u32, count: u32 },
    /// A field value's length does not match its type.
    BadFieldLength { tag: u16, len: usize },
    /// Field tags are not increasing: a duplicate or reordering.
    FieldsOutOfOrder { previous: u16, found: u16 },
    /// An unknown tag in the critical range was encountered: the file uses
    /// semantics this client does not understand and must not be opened.
    UnknownCriticalField { tag: u16 },
    /// A required header field is missing.
    MissingField { tag: u16 },
    /// A key field is present but consists entirely of zeros.
    ///
    /// Deliberately distinct from [`FormatError::MissingField`]: "field absent" and "field
    /// present but empty" are different events. The latter is more dangerous because it appears
    /// populated and passes all structural checks; that is precisely how the pinned
    /// lease signing key field ended up zero in every
    /// issued container.
    DegenerateKey { tag: u16 },
    /// The server address contains a byte outside printable US-ASCII.
    ///
    /// Deliberately distinct from [`FormatError::BadFieldLength`]: the length is correct
    /// but the CONTENT is invalid. The ban is not aesthetic: this address is displayed
    /// for a person to compare with their intended destination, and that comparison
    /// is meaningful only while the string cannot move the cursor,
    /// reverse character order, or masquerade as another letter.
    BadAddressByte { tag: u16, byte: u8 },
    /// The note contains a character that must not be displayed to a person.
    ///
    /// Distinct from [`FormatError::BadAddressByte`] although both concern content:
    /// the rules DIFFER. An address must be printable ASCII: that is its wire
    /// representation. A note is a phrase in any language; only control
    /// characters and bidirectional marks are forbidden. While both shared one error,
    /// a person with a Russian note would read "byte 0x00 in the address".
    ///
    /// The CODE is stored and printed, not the character itself: printing
    /// a rejected character in an error message would let it onto the screen
    /// through precisely the path the check closes.
    BadNoteChar { tag: u16, code: u32 },
    /// A field value is declared to be text but is not text.
    ///
    /// Distinct from [`FormatError::BadFieldLength`], fixing the same class of
    /// problem as [`FormatError::BadNoteChar`]. A `from_utf8` failure
    /// was reported as a LENGTH error even though the length was correct and the bytes invalid.
    /// The change introducing `BadNoteChar` removed one borrowed label
    /// while leaving a second beside it on the very same field.
    NotUtf8 { tag: u16 },
    /// The file requires a newer client version, as declared by the WRITER in
    /// `min_reader_version`.
    ReaderTooOld { need: u16, have: u16 },
    /// A protection class this build does not implement.
    ///
    /// Distinct from the format version: a class can be added without changing the version,
    /// and accepting an unknown class would mean reading under class-zero rules.
    UnsupportedClass { class: u8 },
    /// The FORMAT version itself is outside the range this code can read.
    ///
    /// Distinct from [`FormatError::ReaderTooOld`], not cosmetically. There the number
    /// means client version; here it means format version. Previously both values
    /// entered one structure, reporting "this file requires client version 999"
    /// for a file declaring `container_version = 999` and `min_reader_version = 1`.
    /// A format version in a field meaning client version is precisely the substitution
    /// of meanings this repository forbids in bytes and must also forbid
    /// in diagnostics.
    ///
    /// `first` and `max` bound the READABLE range, not the format's history.
    /// The name `first` dates from when the lower bound matched the first
    /// version ever created; decision R-1 (2026-09-19) separated them: versions 1–4
    /// are no longer readable, and the field carries
    /// `header::MIN_READABLE_CONTAINER_VERSION`, rather than
    /// `header::FIRST_CONTAINER_VERSION`.
    /// Renaming the field here would require edits unrelated to that decision;
    /// a false doc comment would cost more.
    UnsupportedContainerVersion { version: u16, first: u16, max: u16 },
    /// A lease document version this build does not recognize.
    ///
    /// Distinct from the container version: the documents are independent and evolve at different
    /// rates. A shared error would leave the user guessing which is
    /// newer: the file or its permission.
    UnsupportedLeaseVersion { version: u16 },
    /// The declared mutable region length exceeds
    /// [`content::MAX_CONTENT_DESC_LEN`]. Checked before any allocation.
    ContentDescTooLarge { declared: u32 },
    /// The mutable region MAC does not match: it was modified by someone other than the content
    /// key holder, or moved from another file. Details are deliberately absent:
    /// the attacker has no need to know precisely which check failed.
    BadContentMac,
    /// Header or signed-document signature mismatch.
    ///
    /// Shared with protocol codecs using the same verification error. Mutable-region
    /// MAC failures use [`FormatError::BadContentMac`] because they have a different
    /// authentication key and recovery path.
    BadHeaderSignature,
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadMagic => write!(f, "не контейнер Close Crate: магия не совпала"),
            Self::HeaderTooLarge { declared } => {
                write!(f, "заголовок объявлен как {declared} байт, предел {MAX_HEADER_LEN}")
            }
            Self::Truncated { need, have } => {
                write!(f, "файл обрезан: нужно {need} байт, есть {have}")
            }
            Self::OffsetOverflow => write!(f, "переполнение смещения"),
            Self::BadChunkSize { got } => {
                write!(f, "размер чанка {got} вне диапазона или не степень двойки")
            }
            Self::ChunkCountMismatch { expected, got } => {
                write!(f, "число чанков не сходится: ожидалось {expected}, объявлено {got}")
            }
            Self::ChunkOutOfRange { index, count } => {
                write!(f, "чанк {index} за пределами файла из {count} чанков")
            }
            Self::BadFieldLength { tag, len } => {
                write!(f, "поле {tag}: длина {len} не соответствует типу")
            }
            Self::FieldsOutOfOrder { previous, found } => {
                write!(f, "поля не по возрастанию: после {previous} встретилось {found}")
            }
            Self::UnknownCriticalField { tag } => {
                write!(f, "неизвестное критичное поле {tag}: нужна более новая версия клиента")
            }
            Self::MissingField { tag } => write!(f, "отсутствует обязательное поле {tag}"),
            Self::DegenerateKey { tag } => {
                write!(f, "поле {tag}: ключ состоит из нулей, то есть отсутствует по существу")
            }
            Self::BadAddressByte { tag, byte } => {
                write!(f, "поле {tag}: в адресе байт 0x{byte:02x} вне печатной части ASCII")
            }
            Self::BadNoteChar { tag, code } => {
                write!(f, "поле {tag}: символ U+{code:04X} не показывают человеку")
            }
            Self::NotUtf8 { tag } => write!(f, "поле {tag}: значение не UTF-8"),
            Self::ReaderTooOld { need, have } => {
                write!(f, "файлу нужен клиент версии {need}, эта версия {have}")
            }
            Self::UnsupportedClass { class } => {
                write!(f, "класс защиты {class} этой версией клиента не исполняется")
            }
            Self::UnsupportedLeaseVersion { version } => {
                write!(f, "лизинг версии {version}: нужен клиент новее")
            }
            Self::UnsupportedContainerVersion { version, first, max } => write!(
                f,
                "версия формата {version} вне читаемого диапазона {first}..={max}"
            ),
            Self::ContentDescTooLarge { declared } => write!(
                f,
                "изменяемая область объявлена как {declared} байт, предел {}",
                content::MAX_CONTENT_DESC_LEN
            ),
            Self::BadContentMac => write!(f, "MAC изменяемой области не сошёлся"),
            Self::BadHeaderSignature => write!(
                f,
                "подпись заголовка не сходится: файл изменён или подписан не тем ключом"
            ),
        }
    }
}

impl core::error::Error for FormatError {}

/// A split container prologue: borrows exactly the signed bytes.
///
/// Storing a slice rather than a parsed structure is a security requirement,
/// not an optimization: signatures are verified over original bytes because
/// reserializing a parsed header creates the entire family of
/// canonicalization bugs known from JWS and XML-DSig.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prologue<'a> {
    /// Header bytes, exactly `declared_len` of them.
    pub header: &'a [u8],
    /// Author signature over the transcript from
    /// [`crate::verify::header_signing_transcript`].
    pub signature: &'a [u8; SIG_LEN],
    /// Offset of the first byte after the signature.
    pub after_signature: u64,
    declared_len: u32,
}

impl<'a> Prologue<'a> {
    /// Structural splitting: magic, boundaries, length limit. No CBOR or
    /// cryptography. Total and cheap, so it is called first.
    pub fn split(buf: &'a [u8]) -> Result<Self, FormatError> {
        let have = buf.len() as u64;

        let magic = buf.get(0..HEADER_LEN_OFFSET).ok_or(FormatError::Truncated {
            need: HEADER_OFFSET as u64,
            have,
        })?;
        if magic != MAGIC {
            return Err(FormatError::BadMagic);
        }

        let len_bytes: [u8; 4] = buf
            .get(HEADER_LEN_OFFSET..HEADER_OFFSET)
            .and_then(|s| <[u8; 4]>::try_from(s).ok())
            .ok_or(FormatError::Truncated { need: HEADER_OFFSET as u64, have })?;
        let declared_len = u32::from_le_bytes(len_bytes);
        if declared_len > MAX_HEADER_LEN {
            return Err(FormatError::HeaderTooLarge { declared: declared_len });
        }

        let header_end = HEADER_OFFSET
            .checked_add(declared_len as usize)
            .ok_or(FormatError::OffsetOverflow)?;
        let sig_end = header_end.checked_add(SIG_LEN).ok_or(FormatError::OffsetOverflow)?;

        let header = buf
            .get(HEADER_OFFSET..header_end)
            .ok_or(FormatError::Truncated { need: sig_end as u64, have })?;
        let signature = buf
            .get(header_end..sig_end)
            .and_then(|s| <&[u8; SIG_LEN]>::try_from(s).ok())
            .ok_or(FormatError::Truncated { need: sig_end as u64, have })?;

        Ok(Self { header, signature, after_signature: sig_end as u64, declared_len })
    }

    /// Independent construction of the signing string, **only for the comparison test**.
    ///
    /// There is one production implementation: [`crate::verify::header_signing_transcript`].
    /// This one assembles the same bytes by hand with a hardcoded label literal instead of
    /// `label::HEADER_SIG`, which is the point: the test
    /// `both_ways_of_building_the_signing_string_agree` compares them and fails
    /// if someone changes the label or field order in one place and forgets
    /// the other.
    ///
    /// Gated by `cfg(test)`. When public, it was a second source of truth for
    /// signed bytes in the crate's production surface. If someone called it
    /// instead of the real implementation, divergence would become invisible because both
    /// sides would compute using the same copy.
    #[cfg(test)]
    pub(crate) fn signing_transcript(&self, suite_id: u8, out: &mut Vec<u8>) {
        out.clear();
        out.extend_from_slice(b"CC/v1/header-sig");
        out.push(0x00);
        out.push(suite_id);
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&self.declared_len.to_le_bytes());
        out.extend_from_slice(self.header);
    }
}

/// Mapping plaintext ranges to ciphertext ranges.
///
/// Pure arithmetic: called by the virtual filesystem when an
/// application reads four kilobytes from the middle of a document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    chunk_size: NonZeroU32,
    chunk_count: u32,
    total_len: u64,
    payload_offset: u64,
}

impl Layout {
    /// Check consistency and construct the mapping.
    ///
    /// An empty file has exactly one zero-length chunk. Every file therefore has
    /// at least one AEAD tag and at least one tree leaf, with neither
    /// requiring a special case.
    pub fn new(
        chunk_size: u32,
        chunk_count: u32,
        total_len: u64,
        payload_offset: u64,
    ) -> Result<Self, FormatError> {
        let chunk_size = check_chunk_size(chunk_size)?;
        let chunk_size = NonZeroU32::new(chunk_size).ok_or(FormatError::BadChunkSize { got: 0 })?;

        let expected = Self::required_chunks(total_len, chunk_size)?;
        if expected != chunk_count {
            return Err(FormatError::ChunkCountMismatch { expected, got: chunk_count });
        }

        Ok(Self { chunk_size, chunk_count, total_len, payload_offset })
    }

    // Делитель ненулевой по типу `NonZeroU32`, поэтому деление не может
    // паниковать; линтер об этом не знает.
    #[allow(clippy::arithmetic_side_effects)]
    fn required_chunks(total_len: u64, chunk_size: NonZeroU32) -> Result<u32, FormatError> {
        let size = u64::from(chunk_size.get());
        let full = total_len / size;
        let remainder = total_len % size;
        let count = if remainder == 0 { full } else { full.saturating_add(1) };
        let count = count.max(1);
        u32::try_from(count).map_err(|_| FormatError::OffsetOverflow)
    }

    /// Chunk size in plaintext bytes.
    pub fn chunk_size(&self) -> u32 {
        self.chunk_size.get()
    }

    /// Chunk count, always at least one.
    pub fn chunk_count(&self) -> u32 {
        self.chunk_count
    }

    /// Total plaintext length.
    pub fn total_len(&self) -> u64 {
        self.total_len
    }

    /// Index of the chunk containing the given plaintext offset.
    // Делитель ненулевой по типу `NonZeroU32`.
    #[allow(clippy::arithmetic_side_effects)]
    pub fn chunk_of(&self, plaintext_offset: u64) -> Result<u32, FormatError> {
        let index = plaintext_offset / u64::from(self.chunk_size.get());
        let index = u32::try_from(index).map_err(|_| FormatError::OffsetOverflow)?;
        if index >= self.chunk_count {
            return Err(FormatError::ChunkOutOfRange { index, count: self.chunk_count });
        }
        Ok(index)
    }

    /// Range of chunks covering a read. An empty read yields `None`.
    pub fn chunks_for(&self, offset: u64, len: u64) -> Result<Option<Range<u32>>, FormatError> {
        if len == 0 || offset >= self.total_len {
            return Ok(None);
        }
        let last_byte = offset
            .checked_add(len)
            .and_then(|end| end.checked_sub(1))
            .ok_or(FormatError::OffsetOverflow)?
            .min(self.total_len.saturating_sub(1));

        let first = self.chunk_of(offset)?;
        let last = self.chunk_of(last_byte)?;
        let end = last.checked_add(1).ok_or(FormatError::OffsetOverflow)?;
        Ok(Some(first..end))
    }

    /// Plaintext length of a particular chunk: the last chunk is shorter.
    pub fn plaintext_len_of(&self, index: u32) -> Result<u64, FormatError> {
        if index >= self.chunk_count {
            return Err(FormatError::ChunkOutOfRange { index, count: self.chunk_count });
        }
        let size = u64::from(self.chunk_size.get());
        let start = u64::from(index).checked_mul(size).ok_or(FormatError::OffsetOverflow)?;
        Ok(self.total_len.saturating_sub(start).min(size))
    }

    /// On-disk byte range of a chunk: `nonce ‖ ciphertext ‖ tag`.
    ///
    /// All chunks except the last are full, so the offset is computed by multiplication,
    /// rather than summing a table.
    pub fn ciphertext_span(&self, index: u32) -> Result<Range<u64>, FormatError> {
        let plaintext_len = self.plaintext_len_of(index)?;
        let framed_full = u64::from(self.chunk_size.get())
            .checked_add(NONCE_LEN)
            .and_then(|v| v.checked_add(TAG_LEN))
            .ok_or(FormatError::OffsetOverflow)?;
        let start = self
            .payload_offset
            .checked_add(u64::from(index).checked_mul(framed_full).ok_or(FormatError::OffsetOverflow)?)
            .ok_or(FormatError::OffsetOverflow)?;
        let end = start
            .checked_add(NONCE_LEN)
            .and_then(|v| v.checked_add(plaintext_len))
            .and_then(|v| v.checked_add(TAG_LEN))
            .ok_or(FormatError::OffsetOverflow)?;
        Ok(start..end)
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn container(header: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&MAGIC);
        buf.extend_from_slice(&(header.len() as u32).to_le_bytes());
        buf.extend_from_slice(header);
        buf.extend_from_slice(&[0x5a; SIG_LEN]);
        buf
    }

    #[test]
    fn splits_a_well_formed_prologue() {
        let buf = container(b"header-bytes");
        let p = Prologue::split(&buf).unwrap();
        assert_eq!(p.header, b"header-bytes");
        assert_eq!(p.signature, &[0x5a; SIG_LEN]);
        assert_eq!(p.after_signature, buf.len() as u64);
    }

    #[test]
    fn rejects_foreign_files() {
        assert_eq!(Prologue::split(b"%PDF-1.7 and then some"), Err(FormatError::BadMagic));
    }

    #[test]
    fn rejects_declared_length_beyond_the_cap() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&MAGIC);
        buf.extend_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            Prologue::split(&buf),
            Err(FormatError::HeaderTooLarge { declared: u32::MAX })
        );
    }

    #[test]
    fn rejects_truncation_at_every_boundary() {
        let full = container(b"header-bytes");
        for cut in 0..full.len() {
            let err = Prologue::split(&full[..cut]).unwrap_err();
            assert!(
                matches!(err, FormatError::Truncated { .. }),
                "обрезание на {cut} байтах дало {err:?}, а должно было дать Truncated"
            );
        }
        assert!(Prologue::split(&full).is_ok());
    }

    #[test]
    fn never_panics_on_arbitrary_input() {
        // Дешёвая замена фаззеру на этапе, когда фаззер ещё не подключён:
        // разбор обязан быть тотальным на любом префиксе любого мусора.
        let mut soup = Vec::new();
        soup.extend_from_slice(&MAGIC);
        soup.extend_from_slice(&[0xff; 256]);
        for cut in 0..soup.len() {
            let _ = Prologue::split(&soup[..cut]);
        }
        for byte in 0u16..=255 {
            let _ = Prologue::split(&[byte as u8; 13]);
        }
    }

    #[test]
    fn transcript_covers_magic_length_and_header() {
        let buf = container(b"abc");
        let p = Prologue::split(&buf).unwrap();
        let mut out = Vec::new();
        p.signing_transcript(7, &mut out);

        assert!(out.starts_with(b"CC/v1/header-sig"));
        assert!(out.ends_with(b"abc"));
        assert!(out.windows(8).any(|w| w == MAGIC), "магия обязана входить в транскрипт");
        // Метка домена, нулевой байт, идентификатор набора, магия, длина, заголовок.
        assert_eq!(out.len(), 16 + 1 + 1 + 8 + 4 + 3);
    }

    #[test]
    fn transcript_binds_the_suite_id() {
        let buf = container(b"abc");
        let p = Prologue::split(&buf).unwrap();
        let (mut a, mut b) = (Vec::new(), Vec::new());
        p.signing_transcript(1, &mut a);
        p.signing_transcript(2, &mut b);
        assert_ne!(a, b, "подпись обязана различать наборы алгоритмов");
    }

    #[test]
    fn empty_file_still_has_one_chunk() {
        let layout = Layout::new(65536, 1, 0, 100).unwrap();
        assert_eq!(layout.chunk_count(), 1);
        assert_eq!(layout.plaintext_len_of(0).unwrap(), 0);
        // Пустой чанк на диске — только nonce и тег.
        assert_eq!(layout.ciphertext_span(0).unwrap(), 100..(100 + NONCE_LEN + TAG_LEN));
    }

    #[test]
    fn rejects_inconsistent_chunk_count() {
        let err = Layout::new(65536, 9, 65536 * 3, 0).unwrap_err();
        assert_eq!(err, FormatError::ChunkCountMismatch { expected: 3, got: 9 });
    }

    #[test]
    fn rejects_chunk_sizes_outside_the_contract() {
        for bad in [0, 1, 2048, 65535, MAX_CHUNK_SIZE * 2] {
            assert!(
                matches!(Layout::new(bad, 1, 0, 0), Err(FormatError::BadChunkSize { .. })),
                "размер чанка {bad} должен быть отвергнут"
            );
        }
    }

    #[test]
    fn maps_a_small_read_to_exactly_one_chunk() {
        // Ровно тот случай, ради которого выбран размер чанка: приложение читает
        // четыре килобайта из середины большого файла.
        let chunk = 65536u32;
        let total = 4u64 * 1024 * 1024 * 1024;
        let count = (total / u64::from(chunk)) as u32;
        let layout = Layout::new(chunk, count, total, 4096).unwrap();

        let range = layout.chunks_for(1_000_000, 4096).unwrap().unwrap();
        assert_eq!(range.end - range.start, 1, "чтение внутри чанка не должно задевать соседей");
        assert_eq!(range.start, 1_000_000 / u64::from(chunk) as u32);
    }

    #[test]
    fn a_read_across_a_boundary_touches_both_chunks() {
        let layout = Layout::new(4096, 4, 16384, 0).unwrap();
        let range = layout.chunks_for(4090, 12).unwrap().unwrap();
        assert_eq!(range, 0..2);
    }

    #[test]
    fn a_read_past_the_end_is_clamped() {
        let layout = Layout::new(4096, 2, 5000, 0).unwrap();
        let range = layout.chunks_for(4000, 1_000_000).unwrap().unwrap();
        assert_eq!(range, 0..2);
        assert!(layout.chunks_for(5000, 10).unwrap().is_none());
        assert!(layout.chunks_for(0, 0).unwrap().is_none());
    }

    #[test]
    fn spans_are_contiguous_and_cover_the_payload() {
        let layout = Layout::new(4096, 3, 4096 * 2 + 17, 77).unwrap();
        let mut cursor = 77;
        for i in 0..layout.chunk_count() {
            let span = layout.ciphertext_span(i).unwrap();
            assert_eq!(span.start, cursor, "чанк {i} не примыкает к предыдущему");
            let framed = NONCE_LEN + layout.plaintext_len_of(i).unwrap() + TAG_LEN;
            assert_eq!(span.end - span.start, framed);
            cursor = span.start + NONCE_LEN + u64::from(layout.chunk_size()) + TAG_LEN;
        }
        assert_eq!(layout.plaintext_len_of(2).unwrap(), 17);
    }

    #[test]
    fn refuses_to_address_chunks_that_do_not_exist() {
        let layout = Layout::new(4096, 2, 5000, 0).unwrap();
        assert!(matches!(
            layout.ciphertext_span(2),
            Err(FormatError::ChunkOutOfRange { index: 2, count: 2 })
        ));
    }
}
