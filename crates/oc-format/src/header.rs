// SPDX-License-Identifier: MPL-2.0
//! Container header: the immutable region signed by the author.
//!
//! Encoding uses TLV from [`crate::tlv`]. Parsing returns both a structure and
//! field byte ranges: policy and header core hashes are computed over
//! original bytes, not a re-encoding of the parsed structure.

use crate::policy_codec;
use crate::tlv::{TlvReader, TlvWriter, UnknownTag, unknown_tag_action};
use crate::{FormatError, MAX_KEY_SLOTS};
use core::ops::Range;
use sha2::{Digest, Sha256};
use oc_crypto::{AeadAlg, KemAlg, SigAlg, TreeHashAlg, label};
use oc_policy::Policy;

/// Header field tags. Values are part of the signed bytes and must not be
/// reordered during refactoring: previously issued files would become unreadable.
pub mod tag {
    pub const CONTAINER_VERSION: u16 = 1;
    pub const MIN_READER_VERSION: u16 = 2;
    pub const FILE_ID: u16 = 3;
    pub const SUITE: u16 = 4;
    pub const AUTHOR_KEY: u16 = 5;
    pub const HEADER_SALT: u16 = 6;
    pub const CHUNK_SIZE: u16 = 7;
    pub const ORIGINAL_ROOT: u16 = 8;
    pub const POLICY: u16 = 9;
    pub const KEY_SLOTS: u16 = 10;
    pub const AUTHORITY: u16 = 11;
    pub const PRIVATE_META: u16 = 12;
    pub const PREV_HEADER_HASH: u16 = 13;
    pub const ORG_ID: u16 = 14;
    pub const CLASS: u16 = 15;
    /// Footer offset: **PERMANENTLY RETIRED by the decision moved to version 4**; do not use.
    ///
    /// Declared twice: here and in mutable-region tag 5. Tag 5 is authoritative,
    /// for mutability rather than security reasons: the footer follows the
    /// payload, edits change its length and move the footer, but only the absent
    /// author could sign a new offset. Discussion in
    /// `docs/format.md`, section "VERSION 3 IS OPEN", item 6.
    ///
    /// The field remains until version 4 is cut, deliberately: versions 1,
    /// 2, and 3 are frozen along with a second implementation's right to write this tag.
    /// Removing it earlier would reject a file conforming to the frozen
    /// specification.
    pub const FOOTER_OFFSET: u16 = 16;
    /// Wrapped content key.
    ///
    /// Lives in the header, not a slot: one file KEK means one wrapped CEK,
    /// regardless of slot count. Covered by the author signature as a normal
    /// field, but **excluded** from [`super::Header::core_hash`] to avoid a
    /// circular dependency: associated data binds the wrapper to the core hash.
    pub const WRAPPED_CEK: u16 = 17;
    /// Coauthor membership authorized to administer the file (version 4).
    ///
    /// Optional because it changes which orders the server accepts, not reader keys
    /// or access rules. Older readers can skip it without misinterpreting access.
    pub const COAUTHORS: u16 = 0x8001;
}

/// Tags inside the `SUITE` field.
mod suite_tag {
    pub const SIG: u16 = 1;
    pub const AEAD: u16 = 2;
    pub const TREE_HASH: u16 = 3;
}

/// Tags inside the `AUTHORITY` field.
mod authority_tag {
    pub const URLS: u16 = 1;
    pub const SEALING_KID: u16 = 2;
    pub const LEASE_VERIFY_KEY: u16 = 3;
}

/// Tags inside an individual slot record.
mod slot_tag {
    pub const KIND: u16 = 1;
    pub const KEM: u16 = 2;
    pub const ENC: u16 = 3;
    pub const CT: u16 = 4;
    pub const COMMITMENT: u16 = 5;
    pub const KEY_FPR: u16 = 6;
    /// Sealing AEAD nonce. Stored, not derived: see oc_crypto::seal::SealedBlob::nonce.
    pub const NONCE: u16 = 7;
    /// Claim-code commitment (K8). Only for a `RecipientClaim` slot.
    pub const CLAIM_COMMIT: u16 = 8;
}

/// The only protection class this version implements.
///
/// Zero means "local". Other §2 registry numbers are reserved but must not be
/// accepted when parsing: see the comment on the `tag::CLASS` branch.
const LOCAL_CLASS: u8 = 0;

/// The first format version ever created.
///
/// **NO LONGER the parsing lower bound**: since decision R-1 (2026-09-19),
/// [`MIN_READABLE_CONTAINER_VERSION`] serves that role. This constant records
/// format history: version numbering is NOT reset; it counts structure,
/// not names, and numbers 1–4 are not reused. Removing it would erase
/// the record that five is fifth, not first.
pub const FIRST_CONTAINER_VERSION: u16 = 1;

/// Format version produced by this code.
///
/// Five: hardware hybrid `kem_id = 5` (MLKEM768-P256), version 5 decision.
/// The reader learns a version before the writer so every intermediate release
/// understands its own files. Versions 1–4 are no longer produced and have no witness artifacts:
/// the 2026-09-08 rename changed the magic (`docs/format.md`).
pub const CONTAINER_VERSION: u16 = 5;
/// Maximum client version: version 3 always requires reader 3 (§2.1).
pub const SUPPORTED_READER_VERSION: u16 = 5;
/// Minimum readable container version.
///
/// Versions 1–4 were retired by decision R-1 (2026-09-19): no `CLOSECR1` containers
/// of those versions had been issued. Historical numbers remain reserved.
/// Future compatibility decisions belong in `docs/format.md`; do not change this
/// bound merely to make a fixture pass.
pub const MIN_READABLE_CONTAINER_VERSION: u16 = 5;
/// Maximum readable format version.
///
/// Separate from the writer version, a foundational distinction: the reader must
/// recognize new bytes BEFORE the writer starts producing them, or
/// switching the writer makes a fresh file unreadable to yesterday's build for
/// no reason.
///
/// Bump order is essential: raise this constant BEFORE the writer version,
/// or a freshly produced file will be rejected by its own reader. Conversely, raise
/// the lower bound [`MIN_READABLE_CONTAINER_VERSION`] AFTER
/// switching the writer: raising it earlier makes a build unable to
/// open the files it itself produces.
pub const MAX_READABLE_CONTAINER_VERSION: u16 = 5;
/// Wrapped content key length.
///
/// Re-exported, not separately defined: two definitions of one length
/// would diverge at the first change, causing the header to cut the wrapper at a
/// different boundary than the one used to assemble it.
pub use oc_crypto::wrap::WRAPPED_CEK_LEN;
/// Upper bound on an individual server address length.
const MAX_URL_LEN: usize = 2048;
/// Upper bound on the number of server addresses.
const MAX_URLS: usize = 16;

/// File algorithm suite. No `kem` here: it is defined **per slot**,
/// because a hybrid with ML-KEM will replace X25519, and slots with different KEMs must
/// coexist in one file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Suite {
    pub sig: SigAlg,
    pub aead: AeadAlg,
    pub tree_hash: TreeHashAlg,
}

/// Purpose of a key slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotKind {
    /// License server share.
    Server = 1,
    /// Recipient share sealed to their long-term key.
    RecipientIdentity = 2,
    /// Recipient share derived from a claim code. Only the commitment
    /// is stored; the code travels through a second channel.
    RecipientClaim = 3,
    /// Both shares sealed to the author's device. Always present: otherwise
    /// removing protection would require network access, and the product would risk losing
    /// the author's own files.
    AuthorDevice = 4,
}

impl SlotKind {
    pub fn from_u16(v: u16) -> Option<Self> {
        match v {
            1 => Some(Self::Server),
            2 => Some(Self::RecipientIdentity),
            3 => Some(Self::RecipientClaim),
            4 => Some(Self::AuthorDevice),
            _ => None,
        }
    }
}

/// Key slot.
///
/// An unknown slot kind is retained as [`KeySlot::Unknown`] and ignored:
/// the reading rule is to understand at least one usable slot and skip the rest.
/// Without this, adding a version 2 slot would make files unreadable to
/// released clients.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySlot {
    Known(KnownSlot),
    Unknown { kind: u16, raw: Vec<u8> },
}

/// Slot whose kind this client recognizes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownSlot {
    pub kind: SlotKind,
    pub kem: KemAlg,
    /// Sender's ephemeral public key. Unused and zeroed for a claim-code
    /// slot.
    ///
    /// Length depends on the pair (`container_version`, `kem_id`), not a constant:
    /// 32 bytes for X25519, 65 for P-256 (uncompressed SEC1 point). Before format
    /// version 2 this was a fixed-length array, not merely
    /// inconvenient but a hard limit: it could not fit 65 bytes, so a P-256
    /// slot could be neither written nor parsed.
    pub enc: Vec<u8>,
    /// Sealing AEAD nonce.
    ///
    /// Stored in the file, not derived from the shared secret: otherwise repeating
    /// the author's generator state would expose both slot plaintexts through
    /// XOR, and those are secret shares used to assemble the content key.
    pub nonce: [u8; 24],
    /// Sealed secret with tag.
    pub ct: Vec<u8>,
    /// Slot commitment, checked in constant time before opening AEAD.
    pub commitment: [u8; 32],
    /// The **public key** to which the secret is sealed, without hashing.
    ///
    /// Previously called "fingerprint", a word needing explanation rather than silent replacement:
    /// throughout this project, "fingerprint" means the 32-byte key itself, including
    /// fingerprints in `cc keygen` output and the `fingerprint` field in device
    /// facts. No hash is computed on either write or read; no such function
    /// or domain label exists. The distinction became visible in
    /// format version 2, where a P-256 key occupies 65 bytes.
    ///
    /// Included in author-signed bytes because the server issues keys and is thus
    /// a recipient key directory: without a pinned value it could
    /// substitute its own key for the recipient's and assemble both shares.
    pub key_fpr: Option<Vec<u8>>,
    /// Claim-code commitment K8, only for [`SlotKind::RecipientClaim`].
    ///
    /// A claim slot derives its share from the code, so it has no sealed ciphertext.
    /// [`encode`](Header::encode) and [`decode`](Header::decode) enforce the slot-kind
    /// field layout: claim slots carry this commitment; sealing slots carry ciphertext.
    pub claim_commit: Option<[u8; 32]>,
}

impl KnownSlot {
    /// Whether this slot kind seals a secret to someone's public key.
    ///
    /// The single definition of this distinction. Three of four kinds
    /// seal; the claim-code kind seals nothing.
    #[must_use]
    pub fn kind_seals(kind: SlotKind) -> bool {
        match kind {
            SlotKind::Server | SlotKind::RecipientIdentity | SlotKind::AuthorDevice => true,
            SlotKind::RecipientClaim => false,
        }
    }
}

/// License server coordinates.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Authority {
    /// Address list: rotation and self-hosted deployments are inevitable; a single
    /// hardcoded URL would eventually cause rejection.
    pub urls: Vec<String>,
    /// Identifier of the server key used when packing.
    ///
    /// This is a signed record, not proof of the identity of a contacted server.
    /// Opening the server slot requires the corresponding private key; transport
    /// identity and the lease-signing key are separate concerns.
    pub sealing_kid: [u8; 32],
    /// **Pinned** lease verification key.
    ///
    /// Pinning only a URL means trust on first use: without the key
    /// specified here, a fake server can issue its own leases.
    pub lease_verify_key: [u8; 32],
}

/// Parsed header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub container_version: u16,
    pub min_reader_version: u16,
    pub file_id: [u8; 16],
    pub suite: Suite,
    pub author_key: [u8; 32],
    pub header_salt: [u8; 32],
    pub chunk_size: u32,
    pub original_root: [u8; 32],
    pub policy: Policy,
    pub key_slots: Vec<KeySlot>,
    pub authority: Authority,
    /// AEAD block under K5: the real filename and informational size.
    ///
    /// Version 1 does not write MIME (§2.0); it must not be claimed here: tag 3 is
    /// merely reserved for it.
    pub private_meta: Vec<u8>,
    pub prev_header_hash: Option<[u8; 32]>,
    pub org_id: Vec<u8>,
    /// Protection class. 0 means local; reserved for future classes.
    pub class: u8,
    pub footer_offset: Option<u64>,
    /// Content key wrapped under the KEK.
    pub wrapped_cek: [u8; WRAPPED_CEK_LEN],
    /// Coauthor membership pinned by the author's signature. Version 4.
    ///
    /// An anchor for the server: membership currently lives only in server state,
    /// vouched for by state rather than the document. Whoever controls the server can
    /// rewrite membership; this tag prevents doing so silently.
    pub coauthors: Option<Coauthors>,
}

/// Membership limit: this many keys a person can still visually inspect.
///
/// The same number as server addresses and queued requests, for the same reason.
pub const MAX_COAUTHORS: usize = 16;

/// First format version supporting coauthor membership in the header.
pub const FIRST_COAUTHORS_VERSION: u16 = 4;

/// Tags inside the coauthor membership record.
pub mod coauthors_tag {
    pub const THRESHOLD: u16 = 1;
    pub const KEYS: u16 = 2;
}

/// Membership authorized to administer the file, and its signature threshold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coauthors {
    /// Number of member signatures required. Zero means "no quorum".
    pub threshold: u8,
    /// Member keys. Empty when `threshold = 0`.
    pub keys: Vec<[u8; 32]>,
}

impl Coauthors {
    /// Whether membership is enforceable: the same rule used by encoder and decoder.
    ///
    /// Exposed so the writer, command line, and SDK reject
    /// BEFORE irreversible packaging using the same rule, not their own copy:
    /// a copied rule diverges from its original with the first edit.
    ///
    /// # Errors
    /// Zero threshold with nonempty membership, empty or over-[`MAX_COAUTHORS`]
    /// membership with a nonzero threshold, impossible threshold, or duplicate key.
    pub fn validate(&self) -> Result<(), FormatError> {
        check_coauthors(self)
    }
}

/// Field byte ranges within the parsed buffer.
///
/// Exist solely to compute hashes over original bytes.
/// Recomputing over a re-encoding of the parsed structure causes the entire
/// family of canonicalization bugs known from JWS and XML-DSig.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderSpans {
    /// Policy field value, without tag or length.
    pub policy_value: Range<usize>,
    /// The **entire record** of key slots, including tag and length.
    ///
    /// The whole record, not the value: [`Header::core_hash`] excludes it from
    /// the hashed bytes, and leaving tag and length would permit changing slot
    /// contents without changing the core hash.
    pub key_slots_record: Range<usize>,
    /// Entire wrapped-content-key record. Excluded for the same reason.
    pub wrapped_cek_record: Range<usize>,
}

/// File protection strength, determined by the author slot.
///
/// The author route is sufficient to recover CEK, so it must be at least as strong
/// as every recipient route (`docs/format.md`, author-slot strength rule).
/// Ordering follows that rule, not KEM numbers: P-256 remains classical.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Strength {
    /// X25519, P-256, or RSA-OAEP: neither post-quantum protection nor a requirement on
    /// recipient hardware.
    Classical,
    /// X-Wing (`kem_id = 4`): software post-quantum hybrid.
    PostQuantum,
    /// MLKEM768-P256 (`kem_id = 5`): post-quantum hybrid with its classical
    /// half in the TPM.
    PostQuantumHardware,
}

impl Strength {
    /// Strength of one slot, by mechanism.
    #[must_use]
    pub fn of_kem(kem: u8) -> Self {
        match kem {
            5 => Self::PostQuantumHardware,
            4 => Self::PostQuantum,
            _ => Self::Classical,
        }
    }

    /// Storage number: variant order, starting at zero.
    #[must_use]
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Classical => 0,
            Self::PostQuantum => 1,
            Self::PostQuantumHardware => 2,
        }
    }

    /// Decode the number; an unknown number yields `None`, not classical strength (I-10).
    #[must_use]
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Classical),
            1 => Some(Self::PostQuantum),
            2 => Some(Self::PostQuantumHardware),
            _ => None,
        }
    }
}

/// Header together with its field ranges.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedHeader {
    pub header: Header,
    pub spans: HeaderSpans,
}

impl Header {
    /// File strength: strongest author slot ([`Strength`]).
    ///
    /// Without an author slot (a claim-code file without the author on this
    /// device), classical: no mechanism is weaker, so there is nothing
    /// to require of the requester.
    #[must_use]
    pub fn file_strength(&self) -> Strength {
        self.key_slots
            .iter()
            .filter_map(|slot| match slot {
                KeySlot::Known(known) if known.kind == SlotKind::AuthorDevice => {
                    Some(Strength::of_kem(known.kem as u8))
                }
                _ => None,
            })
            .max()
            .unwrap_or(Strength::Classical)
    }

    /// Parse a header from bytes.
    ///
    /// Total: every buffer either parses or yields an error, never
    /// panics. Called **before** signature verification because both the author key and
    /// algorithm suite are inside the header. This does not make input trusted;
    /// parsing must tolerate any input.
    pub fn decode(bytes: &[u8]) -> Result<ParsedHeader, FormatError> {
        let mut reader = TlvReader::new(bytes);

        let mut container_version = None;
        let mut min_reader_version = None;
        let mut file_id = None;
        let mut suite = None;
        let mut author_key = None;
        let mut header_salt = None;
        let mut chunk_size = None;
        let mut original_root = None;
        let mut policy = None;
        let mut policy_value = None;
        let mut key_slots = None;
        let mut key_slots_record = None;
        let mut authority = None;
        let mut private_meta = None;
        let mut prev_header_hash = None;
        let mut org_id = None;
        let mut class = None;
        let mut footer_offset = None;
        let mut wrapped_cek = None;
        let mut wrapped_cek_record = None;
        let mut coauthors = None;

        while let Some(field) = reader.next_field()? {
            // Запись целиком: значение плюс тег и длина перед ним. Длина берётся
            // из `FIELD_PREFIX_LEN`, а не литералом: это же число определяет
            // границы выреза из `core_hash`, и разойдись оно с кодировщиком —
            // хеш ядра сменился бы молча.
            let record_start = field
                .span
                .start
                .checked_sub(crate::tlv::FIELD_PREFIX_LEN)
                .ok_or(FormatError::OffsetOverflow)?;
            let record = record_start..field.span.end;

            match field.tag {
                tag::CONTAINER_VERSION => container_version = Some(field.u16()?),
                tag::MIN_READER_VERSION => min_reader_version = Some(field.u16()?),
                tag::FILE_ID => file_id = Some(field.array::<16>()?),
                tag::SUITE => suite = Some(decode_suite(field.value)?),
                tag::AUTHOR_KEY => author_key = Some(field.array::<32>()?),
                tag::HEADER_SALT => header_salt = Some(field.array::<32>()?),
                tag::CHUNK_SIZE => chunk_size = Some(check_chunk_size(field.u32()?)?),
                tag::ORIGINAL_ROOT => original_root = Some(field.array::<32>()?),
                tag::POLICY => {
                    // Версия к этому моменту уже прочитана: теги идут строго
                    // по возрастанию, а `container_version` — первый. Тот же
                    // приём, что у слотов ниже, и по той же причине: что поле
                    // вообще существует, решает версия, а не наше умение.
                    let version = container_version.ok_or(FormatError::MissingField {
                        tag: tag::CONTAINER_VERSION,
                    })?;
                    policy = Some(policy_codec::decode(version, field.value)?);
                    policy_value = Some(field.span.clone());
                }
                tag::KEY_SLOTS => {
                    // Версия к этому моменту уже разобрана, и это свойство
                    // достаётся бесплатно из И-7: теги идут строго по
                    // возрастанию, а `container_version` — тег 1 против тега 10
                    // у слотов. Порядок гарантирован разбором, а не соглашением.
                    //
                    // Отсутствие версии здесь означает файл, где слоты есть, а
                    // поля версии нет: разбирать слоты «по какой-нибудь» версии
                    // значит выбрать её за противника.
                    let version =
                        container_version.ok_or(FormatError::MissingField {
                            tag: tag::CONTAINER_VERSION,
                        })?;
                    key_slots = Some(decode_slots(version, field.value)?);
                    key_slots_record = Some(record);
                }
                tag::AUTHORITY => authority = Some(decode_authority(field.value)?),
                tag::PRIVATE_META => private_meta = Some(field.value.to_vec()),
                tag::PREV_HEADER_HASH => prev_header_hash = Some(field.array::<32>()?),
                tag::ORG_ID => org_id = Some(field.value.to_vec()),
                // Класс защиты: разобрать номер и суметь его исполнить — разные
                // вещи. Резерв в реестре (§2) не означает, что незнакомое значение
                // можно принять и читать файл по правилам нулевого класса: класс
                // задаёт, по каким правилам файл обрабатывается целиком. Тот же
                // рубеж, что у `aead_id` и `tree_hash_id`, и по той же причине.
                tag::CLASS => {
                    let value = field.u8()?;
                    if value != LOCAL_CLASS {
                        return Err(FormatError::UnsupportedClass { class: value });
                    }
                    class = Some(value);
                }
                tag::FOOTER_OFFSET => footer_offset = Some(field.u64()?),
                tag::WRAPPED_CEK => {
                    wrapped_cek = Some(field.array::<WRAPPED_CEK_LEN>()?);
                    wrapped_cek_record = Some(record);
                }
                // Состав соавторов знаком нам с версии 4. У версий 1–3 тег не
                // определён, и там он проходит общим путём ниже — то есть
                // ПРОПУСКАЕТСЯ как необязательный, а не отвергается. Это верно:
                // необязательный диапазон на то и заведён, чтобы старый читатель
                // открывал файл, не понимая поля, которое его не касается.
                tag::COAUTHORS if version_so_far(container_version) >= FIRST_COAUTHORS_VERSION => {
                    coauthors = Some(decode_coauthors(field.value)?);
                }
                other => match unknown_tag_action(other) {
                    // Файл использует семантику, которой этот клиент не знает.
                    // Открыть его значило бы исполнить не те правила, что
                    // подписал автор.
                    UnknownTag::Refuse => {
                        return Err(FormatError::UnknownCriticalField { tag: other });
                    }
                    UnknownTag::Ignore => {}
                },
            }
        }

        let header = Header {
            container_version: container_version
                .ok_or(FormatError::MissingField { tag: tag::CONTAINER_VERSION })?,
            min_reader_version: min_reader_version
                .ok_or(FormatError::MissingField { tag: tag::MIN_READER_VERSION })?,
            file_id: file_id.ok_or(FormatError::MissingField { tag: tag::FILE_ID })?,
            suite: suite.ok_or(FormatError::MissingField { tag: tag::SUITE })?,
            author_key: author_key.ok_or(FormatError::MissingField { tag: tag::AUTHOR_KEY })?,
            header_salt: header_salt.ok_or(FormatError::MissingField { tag: tag::HEADER_SALT })?,
            chunk_size: chunk_size.ok_or(FormatError::MissingField { tag: tag::CHUNK_SIZE })?,
            original_root: original_root
                .ok_or(FormatError::MissingField { tag: tag::ORIGINAL_ROOT })?,
            policy: policy.ok_or(FormatError::MissingField { tag: tag::POLICY })?,
            key_slots: key_slots.ok_or(FormatError::MissingField { tag: tag::KEY_SLOTS })?,
            authority: authority.ok_or(FormatError::MissingField { tag: tag::AUTHORITY })?,
            private_meta: private_meta
                .ok_or(FormatError::MissingField { tag: tag::PRIVATE_META })?,
            prev_header_hash,
            org_id: org_id.ok_or(FormatError::MissingField { tag: tag::ORG_ID })?,
            class: class.ok_or(FormatError::MissingField { tag: tag::CLASS })?,
            footer_offset,
            wrapped_cek: wrapped_cek.ok_or(FormatError::MissingField { tag: tag::WRAPPED_CEK })?,
            coauthors,
        };

        let spans = HeaderSpans {
            policy_value: policy_value.ok_or(FormatError::MissingField { tag: tag::POLICY })?,
            key_slots_record: key_slots_record
                .ok_or(FormatError::MissingField { tag: tag::KEY_SLOTS })?,
            wrapped_cek_record: wrapped_cek_record
                .ok_or(FormatError::MissingField { tag: tag::WRAPPED_CEK })?,
        };

        Ok(ParsedHeader { header, spans })
    }

    /// Encode the header. Tags are written in strictly increasing order.
    pub fn encode(&self) -> Result<Vec<u8>, FormatError> {
        check_chunk_size(self.chunk_size)?;
        if self.key_slots.len() > MAX_KEY_SLOTS {
            return Err(FormatError::BadFieldLength {
                tag: tag::KEY_SLOTS,
                len: self.key_slots.len(),
            });
        }

        let mut w = TlvWriter::new();
        w.put(tag::CONTAINER_VERSION, &self.container_version.to_le_bytes())?;
        w.put(tag::MIN_READER_VERSION, &self.min_reader_version.to_le_bytes())?;
        w.put(tag::FILE_ID, &self.file_id)?;
        w.put(tag::SUITE, &encode_suite(&self.suite)?)?;
        w.put(tag::AUTHOR_KEY, &self.author_key)?;
        w.put(tag::HEADER_SALT, &self.header_salt)?;
        w.put(tag::CHUNK_SIZE, &self.chunk_size.to_le_bytes())?;
        w.put(tag::ORIGINAL_ROOT, &self.original_root)?;
        w.put(tag::POLICY, &policy_codec::encode(self.container_version, &self.policy)?)?;
        w.put(tag::KEY_SLOTS, &encode_slots(self.container_version, &self.key_slots)?)?;
        w.put(tag::AUTHORITY, &encode_authority(&self.authority)?)?;
        w.put(tag::PRIVATE_META, &self.private_meta)?;
        w.put_opt(tag::PREV_HEADER_HASH, self.prev_header_hash.as_ref().map(|h| h.as_slice()))?;
        w.put(tag::ORG_ID, &self.org_id)?;
        w.put(tag::CLASS, &[self.class])?;
        let footer = self.footer_offset.map(u64::to_le_bytes);
        w.put_opt(tag::FOOTER_OFFSET, footer.as_ref().map(|b| b.as_slice()))?;
        w.put(tag::WRAPPED_CEK, &self.wrapped_cek)?;
        // Состав соавторов идёт последним: 0x8001 — наибольший тег, а порядок
        // строго возрастающий (И-7). Версия решает, существует ли поле вообще:
        // записать его в контейнер версии 3 значило бы дать этой версии
        // семантику, которой у неё не было.
        if self.container_version >= FIRST_COAUTHORS_VERSION
            && let Some(coauthors) = &self.coauthors
        {
            w.put(tag::COAUTHORS, &encode_coauthors(coauthors)?)?;
        }
        // Заголовок целиком уходит на диск и в подпись — это публичные байты, и
        // затирающая обёртка писателя им не нужна. Копия здесь явная именно
        // потому, что для приватных метаданных обёртку снимать нельзя.
        Ok(w.finish().to_vec())
    }

    /// Header core hash: everything except key material.
    ///
    /// Enters the associated data for CEK wrapping, preventing a wrapped key
    /// from being moved to a container with a different header.
    ///
    /// **Two** records are excluded from the hashed bytes: slots and wrapped CEK.
    /// Both contain material itself bound to this hash: including them would
    /// produce a value dependent on itself.
    pub fn core_hash(header_bytes: &[u8], spans: &HeaderSpans) -> Result<[u8; 32], FormatError> {
        let mut hasher = Sha256::new();
        hasher.update(label::CORE_HASH.as_bytes());
        hasher.update([0x00]);

        // Записи идут в порядке возрастания тегов, но полагаться на это нельзя:
        // сортировка здесь дешевле, чем молчаливо неверный хеш, если порядок
        // тегов когда-нибудь изменится.
        let mut cut = [spans.key_slots_record.clone(), spans.wrapped_cek_record.clone()];
        cut.sort_by_key(|r| r.start);

        let mut cursor = 0usize;
        for range in &cut {
            if range.start < cursor || range.end > header_bytes.len() {
                return Err(FormatError::OffsetOverflow);
            }
            let piece = header_bytes.get(cursor..range.start).ok_or(FormatError::OffsetOverflow)?;
            hasher.update(piece);
            cursor = range.end;
        }
        let tail = header_bytes.get(cursor..).ok_or(FormatError::OffsetOverflow)?;
        hasher.update(tail);

        Ok(hasher.finalize().into())
    }

    /// Policy hash over its byte range.
    ///
    /// The client compares it with lease `policy_hash`: the server must not
    /// issue a license for rules different from those the author signed.
    pub fn policy_hash(header_bytes: &[u8], spans: &HeaderSpans) -> Result<[u8; 32], FormatError> {
        let bytes = header_bytes
            .get(spans.policy_value.clone())
            .ok_or(FormatError::OffsetOverflow)?;
        let mut hasher = Sha256::new();
        hasher.update(label::POLICY_HASH.as_bytes());
        hasher.update([0x00]);
        hasher.update(bytes);
        Ok(hasher.finalize().into())
    }
}

fn check_chunk_size(size: u32) -> Result<u32, FormatError> {
    // Условие живёт в `crate::check_chunk_size` и только там: та же проверка
    // нужна разбору, сборке и разбору аргументов командной строки, а три копии
    // разъехались бы молча.
    crate::check_chunk_size(size)
}

fn encode_suite(suite: &Suite) -> Result<Vec<u8>, FormatError> {
    // Отказ на записи стоит там же, где отказ на чтении. Записав в подписанный
    // заголовок хеш дерева, которого эта сборка не считает, мы выпустили бы
    // файл, чьё дерево посчитано BLAKE3, а объявлено другим: наш читатель его
    // отверг бы, а честный чужой читатель посчитал бы дерево объявленным
    // алгоритмом и разошёлся бы с нами в том, какой файл подлинный.
    oc_crypto::merkle::ensure_supported(suite.tree_hash)
        .map_err(|_| unsupported(suite_tag::TREE_HASH))?;
    let mut w = TlvWriter::new();
    w.put(suite_tag::SIG, &[suite.sig as u8])?;
    w.put(suite_tag::AEAD, &[suite.aead as u8])?;
    w.put(suite_tag::TREE_HASH, &[suite.tree_hash as u8])?;
    Ok(w.finish().to_vec())
}

fn decode_suite(bytes: &[u8]) -> Result<Suite, FormatError> {
    let mut reader = TlvReader::new(bytes);
    let (mut sig, mut aead, mut tree_hash) = (None, None, None);
    while let Some(field) = reader.next_field()? {
        match field.tag {
            // Неизвестный идентификатор алгоритма — отказ, а не подстановка
            // умолчания: подставив «что-нибудь», клиент прочитал бы файл не тем
            // шифром и решил бы, что файл повреждён.
            suite_tag::SIG => {
                let parsed = SigAlg::from_u8(field.u8()?).map_err(|_| unsupported(field.tag))?;
                // The author's suite signature is Ed25519. RSA-PSS support applies only to
                // editing-device signatures; accepting it here would declare one algorithm
                // while header verification still uses another.
                if parsed != SigAlg::Ed25519 {
                    return Err(unsupported(field.tag));
                }
                sig = Some(parsed);
            }
            suite_tag::AEAD => {
                aead = Some(AeadAlg::from_u8(field.u8()?).map_err(|_| unsupported(field.tag))?);
            }
            suite_tag::TREE_HASH => {
                tree_hash =
                    Some(TreeHashAlg::from_u8(field.u8()?).map_err(|_| unsupported(field.tag))?);
            }
            // Nested maps follow the same unknown-tag range rule as the outer container.
            // Protocol codecs share that rule except access decisions, whose signature is
            // reconstructed from parsed fields and therefore cannot skip unknown bytes.
            other => match unknown_tag_action(other) {
                UnknownTag::Refuse => {
                    return Err(FormatError::UnknownCriticalField { tag: other });
                }
                UnknownTag::Ignore => {}
            },
        }
    }
    Ok(Suite {
        sig: sig.ok_or(FormatError::MissingField { tag: suite_tag::SIG })?,
        aead: aead.ok_or(FormatError::MissingField { tag: suite_tag::AEAD })?,
        tree_hash: tree_hash.ok_or(FormatError::MissingField { tag: suite_tag::TREE_HASH })?,
    })
}

/// An unknown algorithm is the same kind of event as an unknown critical field:
/// the client cannot execute the author's intention.
fn unsupported(tag: u16) -> FormatError {
    FormatError::UnknownCriticalField { tag }
}

/// Require printable ASCII without spaces: `0x21..=0x7E`.
///
/// Addresses are displayed for human comparison. This excludes terminal controls,
/// bidirectional marks, and Unicode lookalikes; international hostnames can use
/// punycode. Both writing and parsing enforce the same display constraint.
fn check_address_charset(url: &str) -> Result<(), FormatError> {
    for byte in url.as_bytes() {
        if !matches!(byte, 0x21..=0x7E) {
            return Err(FormatError::BadAddressByte { tag: authority_tag::URLS, byte: *byte });
        }
    }
    Ok(())
}

fn encode_authority(authority: &Authority) -> Result<Vec<u8>, FormatError> {
    if authority.urls.len() > MAX_URLS {
        return Err(FormatError::BadFieldLength {
            tag: authority_tag::URLS,
            len: authority.urls.len(),
        });
    }
    let mut urls = TlvWriter::new();
    for (index, url) in authority.urls.iter().enumerate() {
        if url.len() > MAX_URL_LEN {
            return Err(FormatError::BadFieldLength { tag: authority_tag::URLS, len: url.len() });
        }
        check_address_charset(url)?;
        let tag = u16::try_from(index).map_err(|_| FormatError::OffsetOverflow)?;
        urls.put(tag, url.as_bytes())?;
    }

    // Отказ стоит и на записи, и на разборе. На записи — чтобы контейнер с
    // отсутствующим по существу ключом нельзя было выпустить; на разборе — чтобы
    // уже выпущенный такой контейнер нельзя было принять.
    check_key_present(authority_tag::LEASE_VERIFY_KEY, &authority.lease_verify_key)?;
    check_key_present(authority_tag::SEALING_KID, &authority.sealing_kid)?;

    let mut w = TlvWriter::new();
    w.put(authority_tag::URLS, &urls.finish())?;
    w.put(authority_tag::SEALING_KID, &authority.sealing_kid)?;
    w.put(authority_tag::LEASE_VERIFY_KEY, &authority.lease_verify_key)?;
    Ok(w.finish().to_vec())
}

/// A key must be substantively present, not merely have the right length.
///
/// A zero key is not a "default value" but a missing key disguised
/// as a populated field. For `lease_verify_key` it directly defeats the field's
/// purpose (docs/format.md §2, tag 11): the author-pinned lease signing
/// key is the only thing preventing a fake server from issuing its own
/// leases. For `sealing_kid`, zero is a low-order X25519 point
/// that `seal` rejects anyway, but later and with a less clear reason.
///
/// Ordinary comparison: the value is public, appears in a signed header,
/// and is compared with a constant, not a secret.
fn check_key_present(tag: u16, key: &[u8; 32]) -> Result<(), FormatError> {
    if key.iter().all(|byte| *byte == 0) {
        return Err(FormatError::DegenerateKey { tag });
    }
    Ok(())
}

fn decode_authority(bytes: &[u8]) -> Result<Authority, FormatError> {
    let mut reader = TlvReader::new(bytes);
    let mut authority = Authority::default();
    let (mut seen_kid, mut seen_key) = (false, false);

    while let Some(field) = reader.next_field()? {
        match field.tag {
            authority_tag::URLS => {
                let mut urls = TlvReader::new(field.value);
                while let Some(url) = urls.next_field()? {
                    if authority.urls.len() >= MAX_URLS {
                        return Err(FormatError::BadFieldLength {
                            tag: authority_tag::URLS,
                            len: authority.urls.len(),
                        });
                    }
                    if url.value.len() > MAX_URL_LEN {
                        return Err(FormatError::BadFieldLength {
                            tag: authority_tag::URLS,
                            len: url.value.len(),
                        });
                    }
                    // Адрес обязан быть корректным UTF-8: строка из произвольных
                    // байтов позже пошла бы в сетевой запрос, и подобрать её
                    // содержимое смог бы тот, кто подделал заголовок.
                    let text = core::str::from_utf8(url.value).map_err(|_| {
                        FormatError::BadFieldLength {
                            tag: authority_tag::URLS,
                            len: url.value.len(),
                        }
                    })?;
                    // И печатным ASCII — см. `check_address_charset`. Проверка
                    // стоит ЗДЕСЬ, на разборе, а не у того, кто печатает: там она
                    // потребовалась бы в каждом месте вывода, и первое же забытое
                    // вернуло бы дыру целиком.
                    check_address_charset(text)?;
                    authority.urls.push(text.to_string());
                }
            }
            authority_tag::SEALING_KID => {
                authority.sealing_kid = field.array::<32>()?;
                seen_kid = true;
            }
            authority_tag::LEASE_VERIFY_KEY => {
                authority.lease_verify_key = field.array::<32>()?;
                seen_key = true;
            }
            // То же правило диапазона, что и в `suite`, и по той же причине.
            other => match unknown_tag_action(other) {
                UnknownTag::Refuse => {
                    return Err(FormatError::UnknownCriticalField { tag: other });
                }
                UnknownTag::Ignore => {}
            },
        }
    }

    if !seen_kid {
        return Err(FormatError::MissingField { tag: authority_tag::SEALING_KID });
    }
    if !seen_key {
        return Err(FormatError::MissingField { tag: authority_tag::LEASE_VERIFY_KEY });
    }
    check_key_present(authority_tag::SEALING_KID, &authority.sealing_kid)?;
    check_key_present(authority_tag::LEASE_VERIFY_KEY, &authority.lease_verify_key)?;
    Ok(authority)
}

/// Slots are numbered by position, not kind.
///
/// Kind is **inside** the record because tags must strictly increase: using slot
/// kind as the tag would make two recipients in one file impossible
/// to encode, precisely what slots exist for.
fn encode_slots(version: u16, slots: &[KeySlot]) -> Result<Vec<u8>, FormatError> {
    let mut w = TlvWriter::new();
    for (index, slot) in slots.iter().enumerate() {
        let tag = u16::try_from(index).map_err(|_| FormatError::OffsetOverflow)?;
        let body = match slot {
            KeySlot::Known(known) => encode_known_slot(version, known)?,
            KeySlot::Unknown { raw, .. } => raw.clone(),
        };
        w.put(tag, &body)?;
    }
    Ok(w.finish().to_vec())
}

fn encode_known_slot(version: u16, slot: &KnownSlot) -> Result<Vec<u8>, FormatError> {
    // Длины сверяются ТЕМИ ЖЕ таблицами, что и на разборе, и это не
    // перестраховка. Без проверки здесь наш писатель способен произвести слот,
    // который наш же читатель обязан отвергнуть, — а обнаружилось бы это у
    // получателя, как «файл повреждён». Ровно ради этого свойства рядом уже
    // стоит `check_slot_shape`: состав полей проверяется на записи, теперь и
    // длины тоже.
    //
    // Механизм, форму которого эта версия не задаёт, записать нельзя вовсе:
    // пропуск на чтении (§3.3) — милость к ЧУЖОМУ файлу, а не разрешение
    // выпускать свои с полями неизвестной формы.
    let enc_len = expected_enc_len(version, slot.kem)
        .ok_or(FormatError::BadFieldLength { tag: slot_tag::ENC, len: slot.enc.len() })?;
    if slot.enc.len() != enc_len {
        return Err(FormatError::BadFieldLength { tag: slot_tag::ENC, len: slot.enc.len() });
    }
    if let Some(fpr) = slot.key_fpr.as_deref() {
        let fpr_len = expected_key_fpr_len(version, slot.kem)
            .ok_or(FormatError::BadFieldLength { tag: slot_tag::KEY_FPR, len: fpr.len() })?;
        if fpr.len() != fpr_len {
            return Err(FormatError::BadFieldLength { tag: slot_tag::KEY_FPR, len: fpr.len() });
        }
    }

    // Состав полей проверяется на записи, а не только на чтении: наш писатель не
    // должен уметь произвести слот, который наш же читатель обязан отвергнуть.
    check_slot_shape(
        slot.kind,
        slot.kem,
        slot.claim_commit.is_some(),
        slot.ct.len(),
        slot.key_fpr.is_some(),
        &slot.enc,
        &slot.nonce,
    )?;

    let mut w = TlvWriter::new();
    w.put(slot_tag::KIND, &(slot.kind as u16).to_le_bytes())?;
    w.put(slot_tag::KEM, &[slot.kem as u8])?;
    w.put(slot_tag::ENC, &slot.enc)?;
    w.put(slot_tag::CT, &slot.ct)?;
    w.put(slot_tag::COMMITMENT, &slot.commitment)?;
    w.put_opt(slot_tag::KEY_FPR, slot.key_fpr.as_deref())?;
    w.put(slot_tag::NONCE, &slot.nonce)?;
    w.put_opt(slot_tag::CLAIM_COMMIT, slot.claim_commit.as_ref().map(|c| c.as_slice()))?;
    Ok(w.finish().to_vec())
}

/// Validate the slot-kind field layout (`docs/format.md` §2.0).
///
/// Sealing slots require ciphertext and forbid a claim commitment. Claim slots
/// require that commitment and forbid ciphertext, `key_fpr`, and nonzero `enc` or
/// `nonce`: those fields have no meaning without a recipient key. `key_fpr`
/// remains optional for sealing slots, as specified by tag 6.
fn check_slot_shape(
    kind: SlotKind,
    kem: KemAlg,
    has_claim_commit: bool,
    ct_len: usize,
    has_key_fpr: bool,
    enc: &[u8],
    nonce: &[u8],
) -> Result<(), FormatError> {
    let seals = KnownSlot::kind_seals(kind);
    if seals == has_claim_commit {
        return Err(FormatError::BadFieldLength {
            tag: slot_tag::CLAIM_COMMIT,
            len: usize::from(has_claim_commit),
        });
    }
    if seals != (ct_len > 0) {
        return Err(FormatError::BadFieldLength { tag: slot_tag::CT, len: ct_len });
    }
    if !seals && has_key_fpr {
        return Err(FormatError::BadFieldLength {
            tag: slot_tag::KEY_FPR,
            len: usize::from(has_key_fpr),
        });
    }
    if !seals {
        // Claim slots always use kem_id = 1 (format §2, item 5).
        // That fixes zero enc to 32 bytes and prevents two accepted encodings for the
        // same claim slot. Enforce the rule on both writing and reading.
        if kem != KemAlg::X25519HkdfSha256 {
            return Err(FormatError::BadFieldLength { tag: slot_tag::KEM, len: kem as usize });
        }
        // Сравнение обычное, не константного времени: значения публичны, лежат в
        // подписанном заголовке и сверяются с нулём, а не с секретом.
        if enc.iter().any(|byte| *byte != 0) {
            return Err(FormatError::BadFieldLength { tag: slot_tag::ENC, len: enc.len() });
        }
        if nonce.iter().any(|byte| *byte != 0) {
            return Err(FormatError::BadFieldLength { tag: slot_tag::NONCE, len: nonce.len() });
        }
    }
    Ok(())
}

fn decode_slots(version: u16, bytes: &[u8]) -> Result<Vec<KeySlot>, FormatError> {
    let mut reader = TlvReader::new(bytes);
    let mut slots = Vec::new();
    while let Some(field) = reader.next_field()? {
        if slots.len() >= MAX_KEY_SLOTS {
            return Err(FormatError::BadFieldLength { tag: tag::KEY_SLOTS, len: slots.len() });
        }
        slots.push(decode_slot(version, field.value)?);
    }
    Ok(slots)
}

/// Encapsulation length defined for a format-version/KEM pair.
///
/// `None` means this version does not define the mechanism's shape, so its slot
/// may be skipped rather than checked as X25519. The exhaustive match keeps new
/// mechanisms visible when the table changes.
fn expected_enc_len(version: u16, kem: KemAlg) -> Option<usize> {
    match (version, kem) {
        (_, KemAlg::X25519HkdfSha256) => Some(X25519_PUBLIC_LEN),
        // P-256 определён начиная с версии 2. Зависимость от ВЕРСИИ, а не от
        // одного механизма, — не педантизм: без неё контейнер версии 1 со слотом
        // на P-256 задним числом стал бы открываемым, то есть версия 1 обрела бы
        // семантику, которой у неё никогда не было. Заморожено и то, чего версия
        // не умеет.
        (v, KemAlg::P256HkdfSha256) if v >= 2 => Some(P256_PUBLIC_LEN),
        // Форм для RSA-OAEP не задаёт ни одна версия: номер в реестре занят,
        // механизм не исполняется, слот пропускается.
        // Гибрид X-Wing определён начиная с версии 4 — по той же причине, по
        // какой P-256 начинается со второй: длина есть функция ПАРЫ, и «версия 3
        // для номера 4 не определена» — это её значение, а не пробел.
        (v, KemAlg::XWing) if v >= FIRST_HYBRID_VERSION => Some(XWING_CIPHERTEXT_LEN),
        // Аппаратный гибрид определён с версии 5, и зависимость от версии здесь
        // та же и по той же причине, что у соседей выше.
        (v, KemAlg::MlKem768P256) if v >= FIRST_HARDWARE_HYBRID_VERSION => {
            Some(MLKEM_P256_CIPHERTEXT_LEN)
        }
        (
            _,
            KemAlg::P256HkdfSha256
            | KemAlg::RsaOaepSha256
            | KemAlg::XWing
            | KemAlg::MlKem768P256,
        ) => None,
    }
}

/// First format version supporting hybrid slots.
pub const FIRST_HYBRID_VERSION: u16 = 4;

/// Hybrid `enc` is X-Wing ciphertext: `ct_M(1088) ‖ ct_X(32)`.
const XWING_CIPHERTEXT_LEN: usize = oc_crypto::xwing::CIPHERTEXT_LEN;

/// First format version supporting the HARDWARE hybrid MLKEM768-P256.
///
/// A separate constant beside [`FIRST_HYBRID_VERSION`], not the same number:
/// mechanisms are introduced by different versions, and sharing a constant would bind their fates,
/// moving one boundary when the other changes.
pub const FIRST_HARDWARE_HYBRID_VERSION: u16 = 5;

/// Hardware hybrid `enc`: `ct_M(1088) ‖ eph_P256(65)`.
///
/// Re-exported from crypto, not a number: two length definitions would diverge
/// on the first edit, causing the header to cut the slot at a different boundary
/// than the one used to assemble it.
const MLKEM_P256_CIPHERTEXT_LEN: usize = oc_crypto::mlkem_p256::CIPHERTEXT_LEN;

/// Hardware hybrid `key_fpr`: `pk_M(1184) ‖ pk_P256(65)`.
///
/// This mechanism's `enc` and `key_fpr` lengths differ by ninety-six
/// bytes; both have four digits, making them easy to confuse, surfacing to the recipient
/// as "file damaged". This is why the tables are separate.
const MLKEM_P256_PUBLIC_LEN: usize = oc_crypto::mlkem_p256::PUBLIC_KEY_LEN;

/// Hybrid `key_fpr` is the public half of X-Wing: `pk_M(1184) ‖ pk_X(32)`.
///
/// Here `enc` and `key_fpr` lengths DIFFER, the first mechanism for which
/// separating the tables became necessary rather than merely prudent.
const XWING_PUBLIC_LEN: usize = oc_crypto::xwing::PUBLIC_KEY_LEN;

/// Uncompressed P-256 point length on the wire: `0x04 ‖ X(32) ‖ Y(32)`.
///
/// Compressed form (33 bytes) is not accepted, not to save code: PCP exports
/// a public key as `BCRYPT_ECCKEY_BLOB`, offering no compressed form.
/// Two valid forms of one key would give one recipient two
/// different slot records, hence divergent `core_hash` and signatures between two
/// conforming implementations.
pub const P256_PUBLIC_LEN: usize = 65;

/// X25519 public key length. Alias for readability in the tables above: beside
/// `P256_PUBLIC_LEN` it identifies a key length rather than a coincidentally equal number.
const X25519_PUBLIC_LEN: usize = oc_crypto::seal::PUBLIC_KEY_LEN;

/// Mechanism-specific `key_fpr` length: a SEPARATE function, not the same one.
///
/// For X25519 and P-256 the lengths coincide, making one table
/// tempting. The coincidence is incidental: both fields carry a curve point. For RSA-OAEP, `enc`
/// is encapsulation (hundreds of bytes) while `key_fpr` is a public key, and one measure for both
/// is wrong from its first use. Separation is introduced now, while free,
/// rather than when a third mechanism breaks against it.
///
/// Deliberately `match` without `_`: adding a [`KemAlg`] member must break
/// compilation here at the length table, not silently inherit a neighbor's behavior.
fn expected_key_fpr_len(version: u16, kem: KemAlg) -> Option<usize> {
    match (version, kem) {
        (_, KemAlg::X25519HkdfSha256) => Some(X25519_PUBLIC_LEN),
        (v, KemAlg::P256HkdfSha256) if v >= 2 => Some(P256_PUBLIC_LEN),
        (v, KemAlg::XWing) if v >= FIRST_HYBRID_VERSION => Some(XWING_PUBLIC_LEN),
        (v, KemAlg::MlKem768P256) if v >= FIRST_HARDWARE_HYBRID_VERSION => {
            Some(MLKEM_P256_PUBLIC_LEN)
        }
        (
            _,
            KemAlg::P256HkdfSha256
            | KemAlg::RsaOaepSha256
            | KemAlg::XWing
            | KemAlg::MlKem768P256,
        ) => None,
    }
}

/// Encode coauthor membership.
///
/// # Errors
/// Membership cannot be enforced: empty, over the limit, containing duplicate keys, or with a threshold
/// the members cannot meet.
/// Version read by this point in parsing.
///
/// A separate function for one reason: `None` means "the version field has not
/// appeared yet", while tags strictly increase and `container_version` comes first.
/// Thus `None` is possible only in a header entirely lacking a version, rejected
/// below. Zero is deliberately below every real version:
/// it sends the tag through the common path, where the optional range skips it.
fn version_so_far(container_version: Option<u16>) -> u16 {
    container_version.unwrap_or(0)
}

fn encode_coauthors(coauthors: &Coauthors) -> Result<Vec<u8>, FormatError> {
    check_coauthors(coauthors)?;
    let mut w = TlvWriter::new();
    w.put(coauthors_tag::THRESHOLD, &[coauthors.threshold])?;
    // При «кворума нет» поле ключей ОТСУТСТВУЕТ, а не пусто: пустое значение
    // означало бы состав из нуля ключей, то есть другое утверждение.
    if coauthors.threshold != 0 {
        let mut flat = Vec::with_capacity(coauthors.keys.len().saturating_mul(32));
        for key in &coauthors.keys {
            flat.extend_from_slice(key);
        }
        w.put(coauthors_tag::KEYS, &flat)?;
    }
    Ok(w.finish().to_vec())
}

/// Whether membership can be enforced.
///
/// A rule nobody can ever satisfy freezes a file forever, noticeable only
/// once it is frozen. Hence the check HERE, on both
/// sides: writing and parsing.
fn check_coauthors(coauthors: &Coauthors) -> Result<(), FormatError> {
    if coauthors.threshold == 0 {
        // «Кворума нет» — законное утверждение, но состава при нём не бывает.
        if coauthors.keys.is_empty() {
            return Ok(());
        }
        return Err(FormatError::BadFieldLength {
            tag: tag::COAUTHORS,
            len: coauthors.keys.len(),
        });
    }
    if coauthors.keys.is_empty() || coauthors.keys.len() > MAX_COAUTHORS {
        return Err(FormatError::BadFieldLength {
            tag: tag::COAUTHORS,
            len: coauthors.keys.len(),
        });
    }
    // Порог обязан быть исполним составом. `usize::from` вместо приведения:
    // арифметика со сторонними эффектами в этом крейте запрещена.
    if usize::from(coauthors.threshold) > coauthors.keys.len() {
        return Err(FormatError::BadFieldLength {
            tag: tag::COAUTHORS,
            len: usize::from(coauthors.threshold),
        });
    }
    // Повтор ключа запрещён: один голос считался бы за два, и «двое из трёх»
    // исполнялось бы одной подписью.
    for (i, key) in coauthors.keys.iter().enumerate() {
        if coauthors.keys.iter().skip(i.saturating_add(1)).any(|other| other == key) {
            return Err(FormatError::DegenerateKey { tag: tag::COAUTHORS });
        }
    }
    Ok(())
}

/// Parse coauthor membership.
fn decode_coauthors(bytes: &[u8]) -> Result<Coauthors, FormatError> {
    let mut reader = TlvReader::new(bytes);
    let mut threshold = None;
    let mut keys = Vec::new();
    while let Some(field) = reader.next_field()? {
        match field.tag {
            coauthors_tag::THRESHOLD => threshold = Some(field.u8()?),
            coauthors_tag::KEYS => {
                if field.value.is_empty() || field.value.len() % 32 != 0 {
                    return Err(FormatError::BadFieldLength {
                        tag: coauthors_tag::KEYS,
                        len: field.value.len(),
                    });
                }
                for chunk in field.value.chunks_exact(32) {
                    let key: [u8; 32] =
                        chunk.try_into().map_err(|_| FormatError::BadFieldLength {
                            tag: coauthors_tag::KEYS,
                            len: chunk.len(),
                        })?;
                    keys.push(key);
                }
            }
            // Теги ВНУТРИ состава критичны независимо от диапазона, как и внутри
            // политики: разобрать состав наполовину значит получить не тот
            // состав, который закрепил автор.
            other => return Err(FormatError::UnknownCriticalField { tag: other }),
        }
    }
    let coauthors = Coauthors {
        threshold: threshold.ok_or(FormatError::MissingField { tag: coauthors_tag::THRESHOLD })?,
        keys,
    };
    check_coauthors(&coauthors)?;
    Ok(coauthors)
}

fn decode_slot(version: u16, bytes: &[u8]) -> Result<KeySlot, FormatError> {
    // First collect fields and identify the slot's kind, mechanism and critical tags.
    // Apply exact lengths only after deciding the slot is supported. Checking them
    // earlier would reject a file whose unfamiliar slot should simply be skipped.
    let mut reader = TlvReader::new(bytes);
    let mut kind_raw = None;
    let mut kem = None;
    let mut enc: Option<&[u8]> = None;
    let mut ct: Option<&[u8]> = None;
    let mut commitment: Option<&[u8]> = None;
    let mut key_fpr: Option<&[u8]> = None;
    let mut nonce: Option<&[u8]> = None;
    let mut claim_commit: Option<&[u8]> = None;
    // Встретилось критичное поле, которого эта сборка не знает. Слот из-за него
    // становится непригодным, но файл — нет; подробности ниже.
    let mut unusable = false;

    while let Some(field) = reader.next_field()? {
        match field.tag {
            // Вид и механизм — единственные поля, чью длину приходится проверять в
            // первом проходе: именно по ним решается судьба слота, и прочитать их
            // как-то иначе, чем `u16` и `u8`, невозможно. Их ширина задана §2.0 и
            // менять её значило бы менять сам способ адресации слотов.
            slot_tag::KIND => kind_raw = Some(field.u16()?),
            slot_tag::KEM => kem = Some(field.u8()?),
            // Остальные — сырыми срезами, без проверки длины.
            slot_tag::ENC => enc = Some(field.value),
            slot_tag::CT => ct = Some(field.value),
            slot_tag::COMMITMENT => commitment = Some(field.value),
            slot_tag::KEY_FPR => key_fpr = Some(field.value),
            slot_tag::NONCE => nonce = Some(field.value),
            slot_tag::CLAIM_COMMIT => claim_commit = Some(field.value),
            // An unknown critical field makes this slot unusable, not the entire file.
            // Do not interpret a partially understood key slot; skip it and allow another
            // supported slot to serve the recipient. Optional fields follow the shared range rule.
            other => match unknown_tag_action(other) {
                UnknownTag::Refuse => unusable = true,
                UnknownTag::Ignore => {}
            },
        }
    }

    // Отсутствие вида слота — это повреждение, а не расширение: пропускать
    // нечего, потому что неизвестно даже, что пропускается.
    let kind_raw = kind_raw.ok_or(FormatError::MissingField { tag: slot_tag::KIND })?;
    if unusable {
        return Ok(KeySlot::Unknown { kind: kind_raw, raw: bytes.to_vec() });
    }
    let Some(kind) = SlotKind::from_u16(kind_raw) else {
        // Слот вида, которого клиент не знает. Сохраняется как есть: правило
        // чтения — понять хотя бы один пригодный слот, остальные пропустить.
        return Ok(KeySlot::Unknown { kind: kind_raw, raw: bytes.to_vec() });
    };

    let kem_raw = kem.ok_or(FormatError::MissingField { tag: slot_tag::KEM })?;
    let Ok(kem) = KemAlg::from_u8(kem_raw) else {
        // KEM, которого клиент не знает, — тоже повод пропустить слот, а не
        // отвергнуть файл: другой слот того же файла может быть открываем.
        return Ok(KeySlot::Unknown { kind: kind_raw, raw: bytes.to_vec() });
    };
    let Some(enc_len) = expected_enc_len(version, kem) else {
        // Механизм в реестре есть, но формы его полей эта версия не задаёт. Слот
        // сохраняется целиком и не используется — так же, как слот незнакомого
        // вида. Длины его полей не проверяются: проверять чужую форму по своей
        // мерке значит отвергать файл за то, что он новее.
        return Ok(KeySlot::Unknown { kind: kind_raw, raw: bytes.to_vec() });
    };

    // ВТОРОЙ ПРОХОД: слот наш, длины проверяются точно.
    let ct = ct.ok_or(FormatError::MissingField { tag: slot_tag::CT })?;

    // Тот же контроль состава, что на записи. Слот, не соответствующий своему
    // виду, — не расширение, а противоречие: пропустить его как `Unknown`
    // значило бы принять файл, в котором один и тот же вид слота устроен
    // двумя способами.
    let enc = exact(slot_tag::ENC, enc)?;
    if enc.len() != enc_len {
        return Err(FormatError::BadFieldLength { tag: slot_tag::ENC, len: enc.len() });
    }
    let nonce = exact(slot_tag::NONCE, nonce)?;

    // Длина `key_fpr` проверяется своей мерой и ТОЛЬКО когда поле есть: §2.0
    // называет его необязательным на разборе, и требовать его значило бы
    // отвергать файлы, которые открываются. Но раз уж оно есть — длина точная
    // (И-8): короткое не дополняется нулями, длинное не обрезается, иначе
    // противник управляет тем, какие байты сравниваются со своим ключом.
    if let Some(value) = key_fpr {
        let Some(fpr_len) = expected_key_fpr_len(version, kem) else {
            return Ok(KeySlot::Unknown { kind: kind_raw, raw: bytes.to_vec() });
        };
        if value.len() != fpr_len {
            return Err(FormatError::BadFieldLength {
                tag: slot_tag::KEY_FPR,
                len: value.len(),
            });
        }
    }

    check_slot_shape(
        kind,
        kem,
        claim_commit.is_some(),
        ct.len(),
        key_fpr.is_some(),
        enc,
        nonce,
    )?;

    Ok(KeySlot::Known(KnownSlot {
        kind,
        kem,
        enc: enc.to_vec(),
        nonce: to_array::<24>(slot_tag::NONCE, nonce)?,
        ct: ct.to_vec(),
        commitment: to_array::<32>(
            slot_tag::COMMITMENT,
            exact(slot_tag::COMMITMENT, commitment)?,
        )?,
        key_fpr: key_fpr.map(<[u8]>::to_vec),
        claim_commit: match claim_commit {
            Some(value) => Some(to_array::<32>(slot_tag::CLAIM_COMMIT, value)?),
            None => None,
        },
    }))
}

/// Required slot field: present, or an error naming its tag.
fn exact(tag: u16, value: Option<&[u8]>) -> Result<&[u8], FormatError> {
    value.ok_or(FormatError::MissingField { tag })
}

/// Slice to an exact-length array. Short values are not padded, long ones not truncated (I-8).
fn to_array<const N: usize>(tag: u16, value: &[u8]) -> Result<[u8; N], FormatError> {
    <[u8; N]>::try_from(value).map_err(|_| FormatError::BadFieldLength { tag, len: value.len() })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use oc_policy::{Action, Policy};

    /// Executable KEMs must have both length entries in at least one readable version.
    /// Versions define wire shapes; the build defines support. Enumerating registry
    /// identifiers catches a new implementation whose parser length table was omitted.
    #[test]
    fn the_length_tables_are_silent_exactly_about_the_unexecutable_mechanism() {
        let all: Vec<KemAlg> = (0u8..=255).filter_map(|v| KemAlg::from_u8(v).ok()).collect();
        assert_eq!(all.len(), 5, "реестр механизмов изменился — проверьте таблицы длин");
        for kem in all {
            let shaped = (MIN_READABLE_CONTAINER_VERSION..=CONTAINER_VERSION).any(|v| {
                expected_enc_len(v, kem).is_some() && expected_key_fpr_len(v, kem).is_some()
            });
            assert_eq!(
                shaped,
                kem.ensure_supported().is_ok(),
                "таблицы длин разошлись с исполнимостью на {kem:?}"
            );
        }
    }

    /// COAUTHOR MEMBERSHIP SURVIVES AN ENCODING ROUND TRIP.
    #[test]
    fn a_coauthor_roster_survives_the_encoding_round_trip() {
        let mut header = sample();
        header.coauthors = Some(Coauthors { threshold: 2, keys: vec![[1u8; 32], [2u8; 32], [3u8; 32]] });
        let bytes = header.encode().unwrap();
        let back = Header::decode(&bytes).unwrap().header;
        assert_eq!(back.coauthors, header.coauthors);
    }

    /// "NO QUORUM" IS A VALID STATEMENT AND IS WRITTEN.
    ///
    /// Zero with empty membership differs from an absent tag: the former is an
    /// author statement; the latter means the author said nothing about coauthors.
    #[test]
    fn no_quorum_is_a_statement_and_differs_from_saying_nothing() {
        let mut header = sample();
        header.coauthors = Some(Coauthors { threshold: 0, keys: Vec::new() });
        let bytes = header.encode().unwrap();
        let back = Header::decode(&bytes).unwrap().header;
        assert_eq!(back.coauthors, Some(Coauthors { threshold: 0, keys: Vec::new() }));

        let mut silent = sample();
        silent.coauthors = None;
        let back = Header::decode(&silent.encode().unwrap()).unwrap().header;
        assert_eq!(back.coauthors, None, "молчание превратилось в утверждение");
    }

    /// UNENFORCEABLE MEMBERSHIP IS REJECTED ON WRITE, RATHER THAN FREEZING THE FILE.
    ///
    /// A rule nobody can ever satisfy is noticed only when the
    /// file freezes. The check therefore exists on both sides; this tests the side
    /// where changing one's mind is still possible.
    #[test]
    fn an_unsatisfiable_roster_is_refused_before_it_freezes_the_file() {
        for roster in [
            // Порог больше состава: «трое из двух».
            Coauthors { threshold: 3, keys: vec![[1u8; 32], [2u8; 32]] },
            // Повтор ключа: один голос считался бы за два.
            Coauthors { threshold: 2, keys: vec![[1u8; 32], [1u8; 32]] },
            // Порог есть, состава нет.
            Coauthors { threshold: 1, keys: Vec::new() },
            // Состав есть, кворума нет — два несовместимых утверждения разом.
            Coauthors { threshold: 0, keys: vec![[1u8; 32]] },
            // Состав длиннее предела в шестнадцать.
            Coauthors { threshold: 1, keys: (0..17u8).map(|n| [n; 32]).collect() },
        ] {
            let mut header = sample();
            header.coauthors = Some(roster.clone());
            assert!(header.encode().is_err(), "неисполнимый состав записан: {roster:?}");
        }
    }

    /// A VERSION 3 READER SKIPS MEMBERSHIP RATHER THAN REJECTING THE FILE.
    ///
    /// That is why the tag is optional: coauthor membership changes neither
    /// keys nor access rules, so rejecting it would mean
    /// rejection without cause.
    #[test]
    fn an_older_reader_skips_the_roster_instead_of_refusing_the_file() {
        let mut header = sample();
        header.container_version = 3;
        header.min_reader_version = 3;
        let mut bytes = header.encode().unwrap();
        // Дописываем запись состава руками: писатель версии 3 её не создаёт.
        let mut w = TlvWriter::new();
        w.put(coauthors_tag::THRESHOLD, &[1]).unwrap();
        w.put(coauthors_tag::KEYS, &[7u8; 32]).unwrap();
        let record = w.finish().to_vec();
        let mut outer = TlvWriter::new();
        outer.put(tag::COAUTHORS, &record).unwrap();
        bytes.extend_from_slice(&outer.finish());

        let back = Header::decode(&bytes).expect("файл версии 3 отвергнут из-за состава").header;
        assert_eq!(back.coauthors, None, "версия 3 не должна понимать состав");
    }

    fn sample() -> Header {
        Header {
            container_version: CONTAINER_VERSION,
            min_reader_version: CONTAINER_VERSION,
            file_id: [0x11; 16],
            suite: Suite {
                sig: SigAlg::Ed25519,
                aead: AeadAlg::XChaCha20Poly1305,
                tree_hash: TreeHashAlg::Blake3,
            },
            author_key: [0x22; 32],
            header_salt: [0x33; 32],
            chunk_size: 65536,
            original_root: [0x44; 32],
            policy: Policy::deny_all().allow(Action::View),
            key_slots: vec![
                KeySlot::Known(KnownSlot {
                    kind: SlotKind::Server,
                    kem: KemAlg::X25519HkdfSha256,
                    enc: vec![0x55; 32],
                    nonce: [0x01; 24],
                    ct: vec![0x66; 48],
                    commitment: [0x77; 32],
                    key_fpr: None,
                    claim_commit: None,
                }),
                KeySlot::Known(KnownSlot {
                    kind: SlotKind::AuthorDevice,
                    kem: KemAlg::X25519HkdfSha256,
                    enc: vec![0x88; 32],
                    nonce: [0x01; 24],
                    ct: vec![0x99; 80],
                    commitment: [0x77; 32],
                    key_fpr: Some(vec![0xaa; 32]),
                    claim_commit: None,
                }),
            ],
            authority: Authority {
                urls: vec!["https://cc.example/api".to_string()],
                sealing_kid: [0xbb; 32],
                lease_verify_key: [0xcc; 32],
            },
            private_meta: vec![0xdd; 64],
            prev_header_hash: None,
            org_id: b"acme".to_vec(),
            class: 0,
            footer_offset: None,
            wrapped_cek: [0xee; WRAPPED_CEK_LEN],
            coauthors: None,
        }
    }

    #[test]
    fn a_header_round_trips_through_encode_and_decode() {
        let header = sample();
        let bytes = header.encode().unwrap();
        let parsed = Header::decode(&bytes).unwrap();
        assert_eq!(parsed.header, header);
    }

    /// Insert a SECOND record with the same tag immediately after the first.
    ///
    /// Using raw bytes, not [`TlvWriter`]: the writer rejects duplicates,
    /// as intended, while this tests the READER. Insertion must be
    /// ADJACENT: a copy appended at the end would have a tag smaller than the previous
    /// one and be caught as ordinary reordering, so the probe
    /// would not test its stated property.
    fn with_a_duplicate_record(bytes: &[u8], tag: u16, value: &[u8]) -> Vec<u8> {
        let mut reader = TlvReader::new(bytes);
        while let Some(field) = reader.next_field().unwrap() {
            if field.tag != tag {
                continue;
            }
            let mut out = bytes[..field.span.end].to_vec();
            out.extend_from_slice(&tag.to_le_bytes());
            out.extend_from_slice(&u32::try_from(value.len()).unwrap().to_le_bytes());
            out.extend_from_slice(value);
            out.extend_from_slice(&bytes[field.span.end..]);
            return out;
        }
        panic!("тега {tag} нет в заголовке — проба потеряла цель");
    }

    /// Reassemble a header, substituting one field value.
    fn with_field_value(bytes: &[u8], tag: u16, value: &[u8]) -> Vec<u8> {
        let mut reader = TlvReader::new(bytes);
        let mut w = TlvWriter::new();
        while let Some(field) = reader.next_field().unwrap() {
            let replacement = if field.tag == tag { value } else { field.value };
            w.put(field.tag, replacement).unwrap();
        }
        w.finish().to_vec()
    }

    /// I-7 ON THE PATH: parsing rejects a header with a DUPLICATE tag.
    ///
    /// Increasing tags had only one probe, directly against
    /// [`TlvReader`]. Primitive and path differ: between them lies
    /// [`Header::decode`], which would simply overwrite a variable
    /// with the duplicate's last value. Two different byte sequences
    /// would then mean one header, while `core_hash` and the author signature
    /// used one set of bytes and the decision another:
    /// precisely the divergence increasing tags were introduced
    /// to prevent.
    #[test]
    fn a_header_with_a_duplicated_tag_is_refused_by_the_reader() {
        let bytes = sample().encode().unwrap();
        assert!(Header::decode(&bytes).is_ok(), "предпосылка пробы неверна: честный заголовок не разобрался");

        // `map(|_| ())` — чтобы сообщение об ошибке не вываливало весь заголовок.
        let outcome = Header::decode(&with_a_duplicate_record(&bytes, tag::FILE_ID, &[0x99; 16]))
            .map(|_| ());
        assert!(
            matches!(outcome, Err(FormatError::FieldsOutOfOrder { previous, found })
                if previous == tag::FILE_ID && found == tag::FILE_ID),
            "заголовок с двумя записями FILE_ID разобран: {outcome:?}"
        );
    }

    /// I-8 ON THE PATH: a field one byte too long or too short is rejected.
    ///
    /// Exact length had one probe, calling primitive `Field::array`
    /// directly. A probe bypassing the tested path passes exactly when
    /// that path is broken: if [`Header::decode`] truncated a long value to
    /// sixteen bytes, `file_id` would come from attacker-chosen
    /// bytes, and the primitive's probe would miss it.
    ///
    /// Both sides in one probe because I-8 forbids both: short values are not
    /// zero-padded and long values are not truncated.
    #[test]
    fn a_header_field_of_the_wrong_length_is_refused_by_the_reader() {
        let bytes = sample().encode().unwrap();

        for (what, value) in [
            ("на байт длиннее", vec![0x11u8; 17]),
            ("на байт короче", vec![0x11u8; 15]),
        ] {
            let spoiled = with_field_value(&bytes, tag::FILE_ID, &value);
            let outcome = Header::decode(&spoiled).map(|_| ());
            assert!(
                matches!(outcome, Err(FormatError::BadFieldLength { tag, len })
                    if tag == tag::FILE_ID && len == value.len()),
                "FILE_ID {what} принят: {outcome:?}"
            );
        }
    }

    #[test]
    fn an_authority_with_a_zero_key_is_refused_both_ways() {
        // Нулевой ключ подписи лизинга проходил все структурные проверки: длина
        // верна, поле присутствует, — и все выпускаемые контейнеры несли именно
        // его. Между тем закреплённый автором ключ подписи лизинга — это то
        // единственное, что мешает поддельному серверу выпускать собственные
        // лизинги на чужой файл (docs/format.md §2, тег 11).
        for zeroed in [true, false] {
            let mut header = sample();
            if zeroed {
                header.authority.lease_verify_key = [0u8; 32];
            } else {
                header.authority.sealing_kid = [0u8; 32];
            }
            let tag = if zeroed {
                authority_tag::LEASE_VERIFY_KEY
            } else {
                authority_tag::SEALING_KID
            };
            assert_eq!(
                header.encode(),
                Err(FormatError::DegenerateKey { tag }),
                "сборка выпустила контейнер с нулевым ключом authority"
            );
        }

        // Разбор отвергает такой контейнер, даже если его собрали не нами: байты
        // подменяются прямо в закодированном заголовке, минуя `encode`.
        let header = sample();
        let bytes = header.encode().unwrap();
        let needle = [0xccu8; 32];
        let at = bytes
            .windows(needle.len())
            .position(|w| w == needle)
            .expect("ключ подписи лизинга обязан присутствовать в байтах");
        let mut tampered = bytes.clone();
        for byte in tampered[at..at + needle.len()].iter_mut() {
            *byte = 0;
        }
        assert_eq!(
            Header::decode(&tampered).map(|_| ()),
            Err(FormatError::DegenerateKey { tag: authority_tag::LEASE_VERIFY_KEY })
        );
    }

    #[test]
    fn a_header_declaring_a_tree_hash_this_build_cannot_compute_is_refused_both_ways() {
        // Оба направления: не выпустить такой файл и не принять его. Иначе
        // `tree_hash_id` не управляет ничем — дерево всё равно считается BLAKE3,
        // и файл, объявивший SHA-256, читается по другому хешу.
        let mut header = sample();
        header.suite.tree_hash = TreeHashAlg::Sha256;
        assert_eq!(
            header.encode(),
            Err(FormatError::UnknownCriticalField { tag: suite_tag::TREE_HASH }),
            "сборка выпустила файл с хешем дерева, которого сама не считает"
        );

        // Чужой файл собирается в обход нашего кодировщика, поэтому чтение
        // проверяется отдельно: подменяем один байт значения в готовом наборе.
        let mut suite = TlvWriter::new();
        suite.put(suite_tag::SIG, &[SigAlg::Ed25519 as u8]).unwrap();
        suite.put(suite_tag::AEAD, &[AeadAlg::XChaCha20Poly1305 as u8]).unwrap();
        suite.put(suite_tag::TREE_HASH, &[2]).unwrap();
        assert_eq!(
            decode_suite(&suite.finish()),
            Err(FormatError::UnknownCriticalField { tag: suite_tag::TREE_HASH })
        );
    }

    #[test]
    fn optional_fields_round_trip_when_present() {
        let mut header = sample();
        header.prev_header_hash = Some([0x0f; 32]);
        header.footer_offset = Some(1_234_567);
        let bytes = header.encode().unwrap();
        assert_eq!(Header::decode(&bytes).unwrap().header, header);
    }

    #[test]
    fn two_recipients_fit_in_one_file() {
        // Ради этого слоты и нумеруются позицией, а не видом: будь тегом вид,
        // двух получателей закодировать было бы нельзя, потому что теги обязаны
        // строго возрастать.
        let mut header = sample();
        let recipient = KnownSlot {
            kind: SlotKind::RecipientIdentity,
            kem: KemAlg::X25519HkdfSha256,
            enc: vec![0x01; 32],
            nonce: [0x01; 24],
            ct: vec![0x02; 48],
            commitment: [0x77; 32],
            key_fpr: Some(vec![0x03; 32]),
            claim_commit: None,
        };
        header.key_slots.push(KeySlot::Known(recipient.clone()));
        header.key_slots.push(KeySlot::Known(KnownSlot { enc: vec![0x04; 32], ..recipient }));

        let bytes = header.encode().unwrap();
        assert_eq!(Header::decode(&bytes).unwrap().header.key_slots.len(), 4);
    }

    #[test]
    fn a_slot_of_an_unknown_kind_is_kept_and_does_not_break_parsing() {
        let mut header = sample();
        let mut inner = TlvWriter::new();
        inner.put(slot_tag::KIND, &999u16.to_le_bytes()).unwrap();
        inner.put(slot_tag::CT, b"future").unwrap();
        let raw = inner.finish().to_vec();
        header.key_slots.push(KeySlot::Unknown { kind: 999, raw: raw.clone() });

        let bytes = header.encode().unwrap();
        let parsed = Header::decode(&bytes).unwrap();
        assert_eq!(parsed.header.key_slots.len(), 3);
        assert!(matches!(
            parsed.header.key_slots.get(2),
            Some(KeySlot::Unknown { kind: 999, .. })
        ));
    }

    #[test]
    fn an_unknown_critical_tag_is_refused_and_an_unknown_optional_tag_is_ignored() {
        let base = sample().encode().unwrap();

        for (tag, should_fail) in [(500u16, true), (0x9000u16, false)] {
            let mut w = TlvWriter::new();
            let mut reader = TlvReader::new(&base);
            let mut inserted = false;
            while let Some(field) = reader.next_field().unwrap() {
                if !inserted && field.tag > tag {
                    w.put(tag, b"unexpected").unwrap();
                    inserted = true;
                }
                w.put(field.tag, field.value).unwrap();
            }
            if !inserted {
                w.put(tag, b"unexpected").unwrap();
            }
            let result = Header::decode(&w.finish());
            assert_eq!(
                result.is_err(),
                should_fail,
                "тег {tag}: ожидался {}",
                if should_fail { "отказ" } else { "пропуск" }
            );
        }
    }

    #[test]
    fn a_missing_required_field_is_refused_rather_than_defaulted() {
        let base = sample().encode().unwrap();
        for missing in [tag::FILE_ID, tag::AUTHOR_KEY, tag::POLICY, tag::WRAPPED_CEK] {
            let mut w = TlvWriter::new();
            let mut reader = TlvReader::new(&base);
            while let Some(field) = reader.next_field().unwrap() {
                if field.tag != missing {
                    w.put(field.tag, field.value).unwrap();
                }
            }
            assert_eq!(
                Header::decode(&w.finish()).map(|_| ()),
                Err(FormatError::MissingField { tag: missing })
            );
        }
    }

    #[test]
    fn the_core_hash_ignores_the_key_material_but_notices_everything_else() {
        // Ровно то свойство, ради которого хеш вырезает две записи: слоты и
        // завёрнутый ключ связаны с этим хешем через связанные данные, и включи
        // мы их — значение зависело бы от самого себя.
        let header = sample();
        let bytes = header.encode().unwrap();
        let parsed = Header::decode(&bytes).unwrap();
        let base = Header::core_hash(&bytes, &parsed.spans).unwrap();

        let mut other_slots = header.clone();
        if let Some(KeySlot::Known(slot)) = other_slots.key_slots.get_mut(0) {
            slot.ct = vec![0x00; 48];
        }
        let other_bytes = other_slots.encode().unwrap();
        let other_parsed = Header::decode(&other_bytes).unwrap();
        assert_eq!(
            Header::core_hash(&other_bytes, &other_parsed.spans).unwrap(),
            base,
            "подмена содержимого слота не должна менять хеш ядра"
        );

        let mut other_cek = header.clone();
        other_cek.wrapped_cek = [0x00; WRAPPED_CEK_LEN];
        let cek_bytes = other_cek.encode().unwrap();
        let cek_parsed = Header::decode(&cek_bytes).unwrap();
        assert_eq!(
            Header::core_hash(&cek_bytes, &cek_parsed.spans).unwrap(),
            base,
            "подмена завёрнутого ключа не должна менять хеш ядра"
        );
    }

    /// Core hashing excludes each complete key-material record: tag, length and value.
    ///
    /// Changing only same-length values cannot detect accidental retention of tag/length.
    /// This independent construction concatenates header bytes around the full record
    /// ranges and compares `SHA-256("CC/v1/core-hash" ‖ 0x00 ‖ Header without these records)`.
    /// Record 17 has fixed length, so it especially needs this exclusion check.
    #[test]
    fn the_core_hash_cuts_whole_records_tag_and_length_included() {
        let bytes = sample().encode().unwrap();
        let parsed = Header::decode(&bytes).unwrap();
        let spans = &parsed.spans;

        let mut cut = [spans.key_slots_record.clone(), spans.wrapped_cek_record.clone()];
        cut.sort_by_key(|r| r.start);
        let mut without = Vec::with_capacity(bytes.len());
        let mut cursor = 0usize;
        for range in &cut {
            without.extend_from_slice(bytes.get(cursor..range.start).unwrap());
            cursor = range.end;
        }
        without.extend_from_slice(bytes.get(cursor..).unwrap());

        let mut hasher = Sha256::new();
        hasher.update(label::CORE_HASH.as_bytes());
        hasher.update([0x00]);
        hasher.update(&without);
        let expected: [u8; 32] = hasher.finalize().into();

        assert_eq!(
            Header::core_hash(&bytes, spans).unwrap(),
            expected,
            "хеш ядра посчитан не по заголовку без записей 10 и 17. \
             Вероятнее всего вырезано одно ЗНАЧЕНИЕ, а тег с длиной остались: \
             вырезано {} байт из {}, а записи занимают {} — оставленный тег с длиной \
             позволяет менять слоты, не меняя хеш (И-3)",
            bytes.len().saturating_sub(without.len()),
            bytes.len(),
            cut.iter().map(|r| r.len()).sum::<usize>()
        );
    }

    /// TWO HEADERS DIFFERING ONLY IN SLOT COUNT YIELD THE SAME CORE HASH.
    ///
    /// Behavioral counterpart to the probe above, and the only substitution
    /// caught WITHOUT a second hash calculation: different slot counts change the LENGTH
    /// of record 10, hence its length bytes. If code retained those in the hashed
    /// bytes, adding a recipient would change `core_hash`, along with CEK-wrapping AAD
    /// and the author signature. Adding a recipient would then require reissuing
    /// the file, precisely the property I-3 rules out.
    #[test]
    fn adding_a_recipient_slot_leaves_the_core_hash_alone() {
        let two = sample();
        let mut one = two.clone();
        one.key_slots.truncate(1);
        assert_eq!(one.key_slots.len(), 1, "срез слотов не сработал — проба бессмысленна");

        let two_bytes = two.encode().unwrap();
        let one_bytes = one.encode().unwrap();
        let two_parsed = Header::decode(&two_bytes).unwrap();
        let one_parsed = Header::decode(&one_bytes).unwrap();
        assert_ne!(
            two_parsed.spans.key_slots_record.len(),
            one_parsed.spans.key_slots_record.len(),
            "записи слотов вышли одной длины — положительного контроля нет, проба слепа"
        );

        assert_eq!(
            Header::core_hash(&one_bytes, &one_parsed.spans).unwrap(),
            Header::core_hash(&two_bytes, &two_parsed.spans).unwrap(),
            "число слотов изменило хеш ядра: из хешируемых байтов вырезано не всё, \
             а только значение записи 10 — тег и длина остались (И-3)"
        );
    }

    #[test]
    fn the_core_hash_changes_when_anything_signed_changes() {
        let header = sample();
        let bytes = header.encode().unwrap();
        let parsed = Header::decode(&bytes).unwrap();
        let base = Header::core_hash(&bytes, &parsed.spans).unwrap();

        let mut variants = Vec::new();
        let mut other = header.clone();
        other.file_id = [0x00; 16];
        variants.push(other);
        let mut other = header.clone();
        other.policy = Policy::deny_all().allow(Action::Export);
        variants.push(other);
        let mut other = header.clone();
        other.author_key = [0x00; 32];
        variants.push(other);
        let mut other = header.clone();
        other.org_id = b"other".to_vec();
        variants.push(other);

        for variant in variants {
            let vb = variant.encode().unwrap();
            let vp = Header::decode(&vb).unwrap();
            assert_ne!(
                Header::core_hash(&vb, &vp.spans).unwrap(),
                base,
                "изменение подписанного поля прошло мимо хеша ядра"
            );
        }
    }

    #[test]
    fn the_policy_hash_follows_the_policy_and_nothing_else() {
        let header = sample();
        let bytes = header.encode().unwrap();
        let parsed = Header::decode(&bytes).unwrap();
        let base = Header::policy_hash(&bytes, &parsed.spans).unwrap();

        let mut same_policy = header.clone();
        same_policy.org_id = b"different".to_vec();
        let sb = same_policy.encode().unwrap();
        let sp = Header::decode(&sb).unwrap();
        assert_eq!(Header::policy_hash(&sb, &sp.spans).unwrap(), base);

        let mut other_policy = header.clone();
        other_policy.policy = Policy::deny_all().allow(Action::Print);
        let ob = other_policy.encode().unwrap();
        let op = Header::decode(&ob).unwrap();
        assert_ne!(Header::policy_hash(&ob, &op.spans).unwrap(), base);
    }

    #[test]
    fn a_bad_chunk_size_is_refused_on_both_write_and_read() {
        for bad in [0u32, 1000, 65535, crate::MAX_CHUNK_SIZE * 2] {
            let mut header = sample();
            header.chunk_size = bad;
            assert!(matches!(header.encode(), Err(FormatError::BadChunkSize { .. })));
        }

        let base = sample().encode().unwrap();
        let mut w = TlvWriter::new();
        let mut reader = TlvReader::new(&base);
        while let Some(field) = reader.next_field().unwrap() {
            if field.tag == tag::CHUNK_SIZE {
                w.put(field.tag, &1000u32.to_le_bytes()).unwrap();
            } else {
                w.put(field.tag, field.value).unwrap();
            }
        }
        assert!(matches!(Header::decode(&w.finish()), Err(FormatError::BadChunkSize { .. })));
    }

    /// An `authority` record with one address and DELIBERATELY NONZERO keys.
    ///
    /// Nonzero is essential here. The earlier address probe used zero
    /// `sealing_kid` and `lease_verify_key`, but `check_key_present` rejects a zero key
    /// as `DegenerateKey`. Thus `is_err()` held for an unrelated
    /// reason and would still hold with address validation entirely removed.
    /// An address probe must distinguish address rejection from key
    /// rejection; the only way is to give the latter no reason to trigger.
    fn authority_with_url(url: &[u8]) -> Vec<u8> {
        let mut urls = TlvWriter::new();
        urls.put(0, url).unwrap();
        let mut inner = TlvWriter::new();
        inner.put(authority_tag::URLS, &urls.finish()).unwrap();
        inner.put(authority_tag::SEALING_KID, &[0x88u8; 32]).unwrap();
        inner.put(authority_tag::LEASE_VERIFY_KEY, &[0x99u8; 32]).unwrap();
        inner.finish().to_vec()
    }

    #[test]
    fn a_non_utf8_authority_url_is_refused() {
        // Контроль: та же запись с законным адресом принимается. Без него отказ
        // ниже неотличим от «такая запись `authority` не разбирается вовсе».
        decode_authority(&authority_with_url(b"https://cc.example/api"))
            .expect("законный адрес отвергнут: отказ ниже придёт не от адреса");

        // Адрес позже уйдёт в сетевой запрос; произвольные байты в нём — подарок
        // тому, кто подделал заголовок.
        match decode_authority(&authority_with_url(&[0xff, 0xfe])) {
            Err(FormatError::BadFieldLength { tag, len }) => {
                assert_eq!(tag, authority_tag::URLS, "отказ пришёл от чужого поля");
                assert_eq!(len, 2);
            }
            other => panic!("байты, не являющиеся UTF-8, приняты как адрес: {other:?}"),
        }
    }

    /// An address is PRINTABLE ASCII, not merely "valid UTF-8".
    ///
    /// All three cases below are valid UTF-8, passing
    /// `from_utf8`. `check_address_charset` rejects them, each taken from its
    /// doc comment: a control sequence colors the screen, RIGHT-TO-LEFT
    /// OVERRIDE reverses the displayed name, and Cyrillic `а` is indistinguishable from
    /// its Latin counterpart. Without a separate probe, nobody guarded this ban:
    /// `BadAddressByte` appeared in no test.
    #[test]
    fn an_authority_url_outside_printable_ascii_is_refused() {
        for (what, url) in [
            ("управляющая последовательность", "https://cc.example/\u{1b}[2K"),
            ("RIGHT-TO-LEFT OVERRIDE", "https://\u{202e}moc.dab/"),
            ("кириллическая а", "https://exа.example/"),
            ("пробел", "https://cc.example/ api"),
        ] {
            match decode_authority(&authority_with_url(url.as_bytes())) {
                Err(FormatError::BadAddressByte { tag, .. }) => {
                    assert_eq!(tag, authority_tag::URLS, "{what}: отказ пришёл от чужого поля");
                }
                other => panic!("{what}: принят или отвергнут не по набору символов: {other:?}"),
            }
        }
    }

    #[test]
    fn never_panics_on_arbitrary_bytes() {
        let valid = sample().encode().unwrap();
        for cut in 0..valid.len() {
            let _ = Header::decode(&valid[..cut]);
        }
        for position in (0..valid.len()).step_by(3) {
            let mut broken = valid.clone();
            broken[position] ^= 0xff;
            let _ = Header::decode(&broken);
        }
    }
}
