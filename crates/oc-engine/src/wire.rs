// SPDX-License-Identifier: MPL-2.0
//! Message codec between the host and packing engine.
//!
//! Messages carry packing requests, public keys, the payload key, stream results,
//! and the completed header. Document content and the CEK stay on their respective
//! sides of the boundary. Transport and process management belong to the host.
//!
//! Messages may contain secrets. Their size is computed before allocating
//! [`Message`], so its fixed-capacity, zeroizing buffer never leaves old copies
//! behind through reallocation. A size mismatch returns [`WireError::BadSize`].

use core::ops::Deref;

use oc_crypto::AeadAlg;
use oc_crypto::secret::{ClaimSecret, PayloadKey, SECRET_LEN, SecretBuf};
use oc_policy::Policy;

use crate::{Recipient, SealedInfo};

/// Maximum size of one message.
///
/// Not "just in case": the length comes from another process; without a ceiling
/// it becomes an instruction for how much memory to allocate. A megabyte leaves ample room:
/// the largest message carries a container header, itself bounded
/// by the format's own limit.
pub const MAX_MESSAGE: usize = 1 << 20;

/// Frame header for a body of length `len`.
///
/// A thin wrapper around [`oc_format::frame::header`], not a redundant layer:
/// implementation moved there when framing gained a THIRD consumer,
/// a socket-based server. Only error conversion remains here, so engine
/// callers need not know format errors.
///
/// # Errors
/// Returns [`WireError::TooLarge`] when the body exceeds `max`.
pub fn frame_header(len: usize, max: usize) -> Result<[u8; 4], WireError> {
    oc_format::frame::header(len, max).map_err(|_| WireError::TooLarge)
}

/// Body length from the frame header, with a ceiling.
///
/// # Errors
/// Returns [`WireError::TooLarge`] when the declared length exceeds `max`.
pub fn frame_len(head: [u8; 4], max: usize) -> Result<usize, WireError> {
    oc_format::frame::body_len(head, max).map_err(|_| WireError::TooLarge)
}

/// Wire-parsing failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// The message ended before parsing did.
    Truncated,
    /// Bytes remain after the parsed message.
    ///
    /// A distinct rejection, not silence: trailing bytes mean sender and
    /// receiver disagree on layout, so processing cannot continue.
    TrailingBytes,
    /// Unknown message kind.
    UnknownKind(u8),
    /// A field value is outside its declared set.
    BadValue(&'static str),
    /// Length exceeds [`MAX_MESSAGE`].
    TooLarge,
    /// Computed message size differs from the written size.
    ///
    /// Not externally observable with correct calculation, yet still rejection rather than a panic
    /// or extra writes. Lints forbid panics here, while "append as much as
    /// needed" would restore a growing buffer and heap copies of
    /// the key (I-11).
    BadSize,
}

impl core::fmt::Display for WireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Truncated => write!(f, "сообщение обрезано"),
            Self::TrailingBytes => write!(f, "после сообщения остались байты"),
            Self::UnknownKind(k) => write!(f, "неизвестный вид сообщения: {k}"),
            Self::BadValue(what) => write!(f, "недопустимое значение поля: {what}"),
            Self::TooLarge => write!(f, "сообщение длиннее допустимого"),
            Self::BadSize => write!(f, "размер сообщения посчитан неверно"),
        }
    }
}

impl std::error::Error for WireError {}

/// What to pack: everything the engine needs to know, owned.
///
/// A separate type, not a borrowing [`crate::PackRequest`]: borrowing across processes
/// is impossible. The methods below turn it into a "request plus public keys" pair,
/// preventing a second set of engine fields that would diverge from
/// the first.
#[derive(Debug, Clone)]
pub struct PlanArgs {
    pub original_name: String,
    pub policy: Policy,
    pub chunk_size: u32,
    pub org_id: Vec<u8>,
    pub authority_urls: Vec<String>,
    pub recipient: Recipient,
    pub author: [u8; 32],
    pub authority_sealing: [u8; 32],
    pub authority_lease_verify: [u8; 32],
    pub device: [u8; 32],
    /// Author hybrid public half, 1216 bytes. Present only for a
    /// hybrid recipient; otherwise the engine does not need it and it does not traverse the pipe.
    pub device_hybrid: Option<Vec<u8>>,
    /// Author hardware-hybrid half, 1249 bytes. The same rule applies.
    pub device_hardware_hybrid: Option<Vec<u8>>,
    pub device_tpm: Option<Vec<u8>>,
    /// Coauthor roster for tag `0x8001`. Travels as public signing keys,
    /// containing no secrets.
    pub coauthors: Option<oc_format::header::Coauthors>,
}

impl PlanArgs {
    /// Construct an owned request from borrowed halves.
    ///
    /// Needed by exactly one caller: the one sending a request to ANOTHER
    /// process. Filename and rules must cross that boundary anyway, making copying
    /// unavoidable; the in-process path should not pay that cost.
    ///
    /// Not a style issue. The copy contains the REAL FILENAME, placed in
    /// private metadata precisely to hide it; an extra string
    /// freed without wiping remains in the heap. The probe
    /// `security_probe_secret_hygiene_second_pass` caught this.
    #[must_use]
    pub fn from_parts(request: &crate::PackRequest<'_>, keys: &crate::PublicKeys<'_>) -> Self {
        Self {
            original_name: request.original_name.to_string(),
            policy: request.policy.clone(),
            chunk_size: request.chunk_size,
            org_id: request.org_id.clone(),
            authority_urls: request.authority_urls.clone(),
            recipient: request.recipient.clone(),
            author: keys.author,
            authority_sealing: keys.authority_sealing,
            authority_lease_verify: keys.authority_lease_verify,
            device_hybrid: keys.device_hybrid.map(<[u8]>::to_vec),
            device_hardware_hybrid: keys.device_hardware_hybrid.map(<[u8]>::to_vec),
            device: keys.device,
            device_tpm: keys.device_tpm.map(<[u8]>::to_vec),
            coauthors: request.coauthors.clone(),
        }
    }

    /// View these fields as a packing request.
    #[must_use]
    pub fn request(&self) -> crate::PackRequest<'_> {
        crate::PackRequest {
            original_name: &self.original_name,
            policy: self.policy.clone(),
            chunk_size: self.chunk_size,
            org_id: self.org_id.clone(),
            authority_urls: self.authority_urls.clone(),
            recipient: match &self.recipient {
                Recipient::None => Recipient::None,
                Recipient::Identity { public_key } => Recipient::Identity { public_key: *public_key },
                Recipient::Hybrid { public_key } => {
                    Recipient::Hybrid { public_key: public_key.clone() }
                }
                Recipient::HardwareHybrid { public_key } => {
                    Recipient::HardwareHybrid { public_key: public_key.clone() }
                }
                Recipient::Claim { secret } => Recipient::Claim { secret: secret.clone() },
            },
            coauthors: self.coauthors.clone(),
        }
    }

    /// View these fields as a public-key set.
    #[must_use]
    pub fn keys(&self) -> crate::PublicKeys<'_> {
        crate::PublicKeys {
            author: self.author,
            authority_sealing: self.authority_sealing,
            authority_lease_verify: self.authority_lease_verify,
            device: self.device,
            device_hybrid: self.device_hybrid.as_deref(),
            device_hardware_hybrid: self.device_hardware_hybrid.as_deref(),
            device_tpm: self.device_tpm.as_deref(),
        }
    }
}

/// Engine response to a planning request.
#[derive(Debug)]
pub struct Planned {
    pub file_id: [u8; 16],
    pub payload_key: PayloadKey,
    pub chunk_size: u32,
    pub aead: AeadAlg,
}

/// Engine response to an assembly request.
#[derive(Debug)]
pub struct Done {
    pub header: Vec<u8>,
    pub content_desc: Vec<u8>,
}

/// Device-to-engine message.
#[derive(Debug)]
pub enum Request {
    Plan(Box<PlanArgs>),
    Assemble(SealedInfo),
}

/// Engine-to-device message.
#[derive(Debug)]
pub enum Response {
    Planned(Planned),
    Done(Done),
    /// Failure already converted to text.
    ///
    /// Text rather than a code: the engine has its own error taxonomy; transporting it
    /// over the wire would create a second numeric registry that would diverge
    /// from the first. Humans need text; the machine has no decision here: any engine
    /// failure means "file not packed".
    Failed(String),
}

// Виды сообщений. Числа свои, провода — они не имеют отношения к номерам
// формата и не обязаны с ними совпадать.
const KIND_PLAN: u8 = 1;
const KIND_ASSEMBLE: u8 = 2;
const KIND_PLANNED: u8 = 3;
const KIND_DONE: u8 = 4;
const KIND_FAILED: u8 = 5;

// Виды получателя на проводе.
const RECIPIENT_NONE: u8 = 0;
const RECIPIENT_IDENTITY: u8 = 1;
const RECIPIENT_CLAIM: u8 = 2;
/// Recipient hybrid key: X-Wing, format version 4.
const RECIPIENT_HYBRID: u8 = 3;
/// Recipient hardware hybrid: MLKEM768-P256, version 5.
const RECIPIENT_HARDWARE_HYBRID: u8 = 4;

/// AEAD identifiers on the wire.
///
/// Match WITHOUT `_`: a new algorithm must break the build here rather than
/// silently become an unknown number. The format's identifier registries
/// use the same technique.
fn aead_to_wire(alg: AeadAlg) -> u8 {
    match alg {
        AeadAlg::XChaCha20Poly1305 => 1,
        AeadAlg::Aes256Gcm => 2,
        AeadAlg::Aes256GcmSiv => 3,
    }
}

fn aead_from_wire(value: u8) -> Result<AeadAlg, WireError> {
    match value {
        1 => Ok(AeadAlg::XChaCha20Poly1305),
        2 => Ok(AeadAlg::Aes256Gcm),
        3 => Ok(AeadAlg::Aes256GcmSiv),
        _ => Err(WireError::BadValue("aead")),
    }
}

/// One wire message's bytes in a fixed-capacity buffer.
///
/// Not introduced for taste. The payload key and claim code travel over this
/// wire, while an appended-to `Vec` returns its old block to the allocator
/// on every reallocation, with secrets inside and before any `Drop` (I-11).
/// Here capacity is set once and contents wiped on destruction:
/// this is [`SecretBuf`], whose guarantees cover the entire message,
/// not one "secret" field; the wire layout does not divide bytes into important
/// and unimportant ones.
///
/// One type for both sides, deliberately. Pipe reception is the same problem: frame
/// length is known in advance, and reading it into an ordinary vector would create
/// a second, unwiped copy of the same message.
///
/// [`Deref`] to `[u8]` deliberately exposes bytes: they are meant to enter
/// a pipe. The type promises not unreadability but a buffer that
/// never reallocates or outlives itself.
pub struct Message(SecretBuf);

impl Message {
    /// Storage for a message of known length.
    ///
    /// Length is declared immediately and equals capacity, so [`Message::as_mut_slice`]
    /// returns all storage without wiping existing data; no tail beyond
    /// meaningful bytes exists at all.
    #[must_use]
    pub fn with_len(len: usize) -> Self {
        let mut buf = SecretBuf::with_capacity(len);
        // Длина равна ёмкости, поэтому отказ невозможен. `let _` вместо
        // `unwrap`: паника в этом крейте запрещена литами, а обрабатывать
        // недостижимую ветвь отдельным отказом значило бы обещать её вызывающему.
        let _ = buf.declare_len(len);
        Self(buf)
    }

    /// Message bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// All message storage for writing, for pipe reception or assembly.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.0.as_declared_mut()
    }

    /// Capacity set at creation, also its length: the buffer never grows.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.0.capacity()
    }
}

impl Deref for Message {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsRef<[u8]> for Message {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl core::fmt::Debug for Message {
    /// Contents hidden: messages contain a key, and a secret in a log leaks just like
    /// one written to disk.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Message({} байт, содержимое скрыто)", self.capacity())
    }
}

/// Add sizes with rejection rather than overflow.
fn add(a: usize, b: usize) -> Result<usize, WireError> {
    a.checked_add(b).ok_or(WireError::TooLarge)
}

/// Size of a length-prefixed piece.
fn blob_size(len: usize) -> Result<usize, WireError> {
    add(4, len)
}

/// Message-byte assembler using a nongrowing buffer.
///
/// Capacity is calculated externally, the only way to avoid reallocating
/// the buffer in flight. [`Writer::finish`] catches discrepancies between
/// calculated and written sizes: there is nowhere to append silently.
struct Writer {
    message: Message,
    at: usize,
}

impl Writer {
    fn new(kind: u8, size: usize) -> Result<Self, WireError> {
        // Потолок стоит ДО выделения: размер считается по полям, часть которых
        // пришла из чужого процесса.
        if size > MAX_MESSAGE {
            return Err(WireError::TooLarge);
        }
        let mut writer = Self { message: Message::with_len(size), at: 0 };
        writer.u8(kind)?;
        Ok(writer)
    }
    fn raw(&mut self, v: &[u8]) -> Result<(), WireError> {
        let end = add(self.at, v.len())?;
        let room = self.message.as_mut_slice().get_mut(self.at..end).ok_or(WireError::BadSize)?;
        room.copy_from_slice(v);
        self.at = end;
        Ok(())
    }
    fn u8(&mut self, v: u8) -> Result<(), WireError> {
        self.raw(&[v])
    }
    fn u32(&mut self, v: u32) -> Result<(), WireError> {
        self.raw(&v.to_le_bytes())
    }
    fn u64(&mut self, v: u64) -> Result<(), WireError> {
        self.raw(&v.to_le_bytes())
    }
    /// A length-prefixed piece.
    fn blob(&mut self, v: &[u8]) -> Result<(), WireError> {
        let len = u32::try_from(v.len()).map_err(|_| WireError::TooLarge)?;
        self.u32(len)?;
        self.raw(v)
    }
    /// Message complete: exactly as many bytes written as calculation promised.
    fn finish(self) -> Result<Message, WireError> {
        if self.at == self.message.capacity() { Ok(self.message) } else { Err(WireError::BadSize) }
    }
}

/// Message-byte parser.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.at.checked_add(n).ok_or(WireError::Truncated)?;
        let out = self.bytes.get(self.at..end).ok_or(WireError::Truncated)?;
        self.at = end;
        Ok(out)
    }
    fn u8(&mut self) -> Result<u8, WireError> {
        self.take(1)?.first().copied().ok_or(WireError::Truncated)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N], WireError> {
        <[u8; N]>::try_from(self.take(N)?).map_err(|_| WireError::Truncated)
    }
    fn u32(&mut self) -> Result<u32, WireError> {
        Ok(u32::from_le_bytes(self.array::<4>()?))
    }
    fn u64(&mut self) -> Result<u64, WireError> {
        Ok(u64::from_le_bytes(self.array::<8>()?))
    }
    fn blob(&mut self) -> Result<&'a [u8], WireError> {
        let len = self.u32()? as usize;
        if len > MAX_MESSAGE {
            return Err(WireError::TooLarge);
        }
        self.take(len)
    }
    fn text(&mut self) -> Result<String, WireError> {
        let bytes = self.blob()?;
        String::from_utf8(bytes.to_vec()).map_err(|_| WireError::BadValue("не текст"))
    }
    /// Parsing finished with no bytes remaining.
    ///
    /// Trailing bytes mean rejection, not a minor detail: the parties disagree
    /// on layout. Silently swallowing them would allow the sender to
    /// append arbitrary data to the message.
    fn finish(self) -> Result<(), WireError> {
        if self.at == self.bytes.len() { Ok(()) } else { Err(WireError::TrailingBytes) }
    }
}

/// Assembly-request size: kind, length, chunk count, tree root.
const ASSEMBLE_SIZE: usize = 1 + 8 + 4 + 32;

/// Encode a device message.
///
/// A planning request carries the claim code, so it is assembled exactly like
/// the key-bearing response: exact size, nongrowing buffer, wiping on destruction.
///
/// # Errors
/// Returns [`WireError`] when a field exceeds its declared length, rules cannot
/// be encoded, or the whole message exceeds [`MAX_MESSAGE`].
pub fn encode_request(request: &Request) -> Result<Message, WireError> {
    match request {
        Request::Plan(args) => {
            // Правила кодируются ДО расчёта размера: их длина в него входит, а
            // посчитать её иначе нельзя.
            // Версия — та, что производит ЭТА сборка: труба не контейнер, и
            // обе её стороны собраны вместе. Брать сюда версию из данных
            // было бы неоткуда и незачем.
            let policy = oc_format::policy_codec::encode(
                oc_format::header::CONTAINER_VERSION,
                &args.policy,
            )
                .map_err(|_| WireError::BadValue("правила"))?;
            let count = u32::try_from(args.authority_urls.len()).map_err(|_| WireError::TooLarge)?;

            let mut size = 1; // вид сообщения
            size = add(size, blob_size(args.original_name.len())?)?;
            size = add(size, blob_size(policy.len())?)?;
            size = add(size, 4)?; // chunk_size
            size = add(size, blob_size(args.org_id.len())?)?;
            size = add(size, 4)?; // число адресов
            for url in &args.authority_urls {
                size = add(size, blob_size(url.len())?)?;
            }
            size = add(size, 1)?; // вид получателя
            size = add(
                size,
                match &args.recipient {
                    Recipient::None => 0,
                    // Открытый ключ и код-претензия одной длины, но это
                    // совпадение, а не правило: ветви разные намеренно.
                    Recipient::Identity { .. } => 32,
                    Recipient::Hybrid { .. } => oc_crypto::xwing::PUBLIC_KEY_LEN,
                    Recipient::HardwareHybrid { .. } => oc_crypto::mlkem_p256::PUBLIC_KEY_LEN,
                    Recipient::Claim { .. } => SECRET_LEN,
                },
            )?;
            size = add(size, 32 * 4)?; // автор, запечатывание, проверка лизинга, устройство
            size = add(size, 1)?; // есть ли гибридная половина автора
            if let Some(bytes) = &args.device_hybrid {
                size = add(size, blob_size(bytes.len())?)?;
            }
            size = add(size, 1)?; // есть ли аппаратная гибридная половина автора
            if let Some(bytes) = &args.device_hardware_hybrid {
                size = add(size, blob_size(bytes.len())?)?;
            }
            size = add(size, 1)?; // есть ли аппаратный ключ
            if let Some(bytes) = &args.device_tpm {
                size = add(size, blob_size(bytes.len())?)?;
            }
            size = add(size, 1)?; // есть ли состав соавторов
            if let Some(roster) = &args.coauthors {
                // Порог и число ключей — по байту: состав не длиннее
                // `MAX_COAUTHORS`, и проверяется это до записи, а не обрезкой.
                roster.validate().map_err(|_| WireError::BadValue("состав соавторов"))?;
                size = add(size, 2)?;
                size = add(size, roster.keys.len().checked_mul(32).ok_or(WireError::TooLarge)?)?;
            }

            let mut w = Writer::new(KIND_PLAN, size)?;
            w.blob(args.original_name.as_bytes())?;
            w.blob(&policy)?;
            w.u32(args.chunk_size)?;
            w.blob(&args.org_id)?;
            w.u32(count)?;
            for url in &args.authority_urls {
                w.blob(url.as_bytes())?;
            }
            match &args.recipient {
                Recipient::None => w.u8(RECIPIENT_NONE)?,
                Recipient::Identity { public_key } => {
                    w.u8(RECIPIENT_IDENTITY)?;
                    w.raw(public_key)?;
                }
                Recipient::Hybrid { public_key } => {
                    w.u8(RECIPIENT_HYBRID)?;
                    w.raw(public_key.as_slice())?;
                }
                Recipient::HardwareHybrid { public_key } => {
                    w.u8(RECIPIENT_HARDWARE_HYBRID)?;
                    w.raw(public_key.as_slice())?;
                }
                Recipient::Claim { secret } => {
                    w.u8(RECIPIENT_CLAIM)?;
                    w.raw(secret.expose())?;
                }
            }
            w.raw(&args.author)?;
            w.raw(&args.authority_sealing)?;
            w.raw(&args.authority_lease_verify)?;
            w.raw(&args.device)?;
            match &args.device_hybrid {
                None => w.u8(0)?,
                Some(bytes) => {
                    w.u8(1)?;
                    w.blob(bytes)?;
                }
            }
            match &args.device_hardware_hybrid {
                None => w.u8(0)?,
                Some(bytes) => {
                    w.u8(1)?;
                    w.blob(bytes)?;
                }
            }
            match &args.device_tpm {
                Some(bytes) => {
                    w.u8(1)?;
                    w.blob(bytes)?;
                }
                None => w.u8(0)?,
            }
            match &args.coauthors {
                None => w.u8(0)?,
                Some(roster) => {
                    let count =
                        u8::try_from(roster.keys.len()).map_err(|_| WireError::BadValue("состав соавторов"))?;
                    w.u8(1)?;
                    w.u8(roster.threshold)?;
                    w.u8(count)?;
                    for key in &roster.keys {
                        w.raw(key)?;
                    }
                }
            }
            w.finish()
        }
        Request::Assemble(sealed) => {
            let mut w = Writer::new(KIND_ASSEMBLE, ASSEMBLE_SIZE)?;
            w.u64(sealed.total_len)?;
            w.u32(sealed.chunk_count)?;
            w.raw(&sealed.tree_root)?;
            w.finish()
        }
    }
}

/// Parse a device message.
///
/// # Errors
/// Returns [`WireError`] for truncation, unknown kind, invalid
/// field values, or trailing bytes.
pub fn decode_request(bytes: &[u8]) -> Result<Request, WireError> {
    let mut r = Reader::new(bytes);
    let kind = r.u8()?;
    match kind {
        KIND_PLAN => {
            let original_name = r.text()?;
            let policy = oc_format::policy_codec::decode(
                oc_format::header::SUPPORTED_READER_VERSION,
                r.blob()?,
            )
                .map_err(|_| WireError::BadValue("правила"))?;
            let chunk_size = r.u32()?;
            let org_id = r.blob()?.to_vec();
            let count = r.u32()? as usize;
            // Потолок на счётчик стоит до цикла, а не внутри: без него число из
            // чужого сообщения задавало бы, сколько раз мы попробуем выделить.
            if count > MAX_MESSAGE {
                return Err(WireError::TooLarge);
            }
            let mut authority_urls = Vec::new();
            for _ in 0..count {
                authority_urls.push(r.text()?);
            }
            let recipient = match r.u8()? {
                RECIPIENT_NONE => Recipient::None,
                RECIPIENT_IDENTITY => Recipient::Identity { public_key: r.array::<32>()? },
                RECIPIENT_HYBRID => Recipient::Hybrid {
                    public_key: Box::new(r.array::<{ oc_crypto::xwing::PUBLIC_KEY_LEN }>()?),
                },
                RECIPIENT_HARDWARE_HYBRID => Recipient::HardwareHybrid {
                    public_key: Box::new(r.array::<{ oc_crypto::mlkem_p256::PUBLIC_KEY_LEN }>()?),
                },
                RECIPIENT_CLAIM => {
                    Recipient::Claim { secret: ClaimSecret::from_bytes(r.array::<32>()?) }
                }
                _ => return Err(WireError::BadValue("получатель")),
            };
            let author = r.array::<32>()?;
            let authority_sealing = r.array::<32>()?;
            let authority_lease_verify = r.array::<32>()?;
            let device = r.array::<32>()?;
            let device_hybrid = match r.u8()? {
                0 => None,
                1 => Some(r.blob()?.to_vec()),
                _ => return Err(WireError::BadValue("гибридный ключ автора")),
            };
            let device_hardware_hybrid = match r.u8()? {
                0 => None,
                1 => Some(r.blob()?.to_vec()),
                _ => return Err(WireError::BadValue("аппаратный гибридный ключ автора")),
            };
            let device_tpm = match r.u8()? {
                0 => None,
                1 => Some(r.blob()?.to_vec()),
                _ => return Err(WireError::BadValue("аппаратный ключ")),
            };
            let coauthors = match r.u8()? {
                0 => None,
                1 => {
                    let threshold = r.u8()?;
                    let count = usize::from(r.u8()?);
                    // Потолок до цикла: число ключей приходит из чужого процесса.
                    if count > oc_format::header::MAX_COAUTHORS {
                        return Err(WireError::BadValue("состав соавторов"));
                    }
                    let mut keys = Vec::with_capacity(count);
                    for _ in 0..count {
                        keys.push(r.array::<32>()?);
                    }
                    let roster = oc_format::header::Coauthors { threshold, keys };
                    // То же правило, что у кодировщика заголовка: неисполнимый
                    // состав отвергается на разборе, а не в сборке заголовка.
                    roster.validate().map_err(|_| WireError::BadValue("состав соавторов"))?;
                    Some(roster)
                }
                _ => return Err(WireError::BadValue("состав соавторов")),
            };
            r.finish()?;
            Ok(Request::Plan(Box::new(PlanArgs {
                original_name,
                policy,
                chunk_size,
                org_id,
                authority_urls,
                recipient,
                author,
                authority_sealing,
                authority_lease_verify,
                device,
                device_hybrid,
                device_hardware_hybrid,
                device_tpm,
                coauthors,
            })))
        }
        KIND_ASSEMBLE => {
            let total_len = r.u64()?;
            let chunk_count = r.u32()?;
            let tree_root = r.array::<32>()?;
            r.finish()?;
            Ok(Request::Assemble(SealedInfo { total_len, chunk_count, tree_root }))
        }
        other => Err(WireError::UnknownKind(other)),
    }
}

/// Plan-response size: kind, `file_id`, key, chunk size, AEAD number.
///
/// Fields are fixed, so size is fixed: there is no reason to compute it locally.
/// Written as an expression, not a number: adding a field would silently make a number diverge
/// from layout, while the expression must change alongside it.
const PLANNED_SIZE: usize = 1 + 16 + SECRET_LEN + 4 + 1;

/// Encode an engine response.
///
/// A plan response carries the payload key. Its buffer is allocated to exactly
/// the required size and wiped on destruction; see [`Message`].
///
/// # Errors
/// Returns [`WireError`] when a field exceeds its declared length or
/// the whole message exceeds [`MAX_MESSAGE`].
pub fn encode_response(response: &Response) -> Result<Message, WireError> {
    match response {
        Response::Planned(planned) => {
            let mut w = Writer::new(KIND_PLANNED, PLANNED_SIZE)?;
            w.raw(&planned.file_id)?;
            w.raw(planned.payload_key.expose())?;
            w.u32(planned.chunk_size)?;
            w.u8(aead_to_wire(planned.aead))?;
            w.finish()
        }
        Response::Done(done) => {
            let mut size = 1;
            size = add(size, blob_size(done.header.len())?)?;
            size = add(size, blob_size(done.content_desc.len())?)?;
            let mut w = Writer::new(KIND_DONE, size)?;
            w.blob(&done.header)?;
            w.blob(&done.content_desc)?;
            w.finish()
        }
        Response::Failed(text) => {
            let size = add(1, blob_size(text.len())?)?;
            let mut w = Writer::new(KIND_FAILED, size)?;
            w.blob(text.as_bytes())?;
            w.finish()
        }
    }
}

/// Parse an engine response.
///
/// # Errors
/// Returns [`WireError`] for truncation, unknown kind, invalid
/// field values, or trailing bytes.
pub fn decode_response(bytes: &[u8]) -> Result<Response, WireError> {
    let mut r = Reader::new(bytes);
    let kind = r.u8()?;
    match kind {
        KIND_PLANNED => {
            let file_id = r.array::<16>()?;
            let payload_key = PayloadKey::from_bytes(r.array::<32>()?);
            let chunk_size = r.u32()?;
            let aead = aead_from_wire(r.u8()?)?;
            r.finish()?;
            Ok(Response::Planned(Planned { file_id, payload_key, chunk_size, aead }))
        }
        KIND_DONE => {
            let header = r.blob()?.to_vec();
            let content_desc = r.blob()?.to_vec();
            r.finish()?;
            Ok(Response::Done(Done { header, content_desc }))
        }
        KIND_FAILED => {
            let text = r.text()?;
            r.finish()?;
            Ok(Response::Failed(text))
        }
        other => Err(WireError::UnknownKind(other)),
    }
}

#[cfg(test)]
// `arithmetic_side_effects` снят ради одного теста: ожидаемый размер сообщения
// там выписан слагаемыми ровно в порядке полей — так расхождение с раскладкой
// видно глазом. Переполнение на литералах здесь невозможно. `indexing_slicing` —
// ради пробы состава соавторов: она портит байты годного сообщения по известным
// смещениям, и выход за границу там — провал пробы, а не разбор ввода.
#[allow(clippy::unwrap_used, clippy::panic, clippy::arithmetic_side_effects, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn args() -> PlanArgs {
        PlanArgs {
            original_name: "contract.docx".to_string(),
            policy: Policy::deny_all(),
            chunk_size: 65536,
            org_id: b"org".to_vec(),
            authority_urls: vec!["https://a".to_string(), "https://b".to_string()],
            recipient: Recipient::Identity { public_key: [7u8; 32] },
            author: [1u8; 32],
            authority_sealing: [2u8; 32],
            authority_lease_verify: [3u8; 32],
            device: [4u8; 32],
            device_hybrid: None,
            device_hardware_hybrid: None,
            device_tpm: Some(vec![9u8; 65]),
            coauthors: None,
        }
    }

    /// Requests survive the wire losslessly for all three recipient kinds.
    #[test]
    fn a_request_survives_the_wire_in_every_recipient_mode() {
        for recipient in [
            Recipient::None,
            Recipient::Identity { public_key: [7u8; 32] },
            Recipient::Claim { secret: ClaimSecret::from_bytes([8u8; 32]) },
        ] {
            let mut a = args();
            a.recipient = recipient;
            let bytes = encode_request(&Request::Plan(Box::new(a))).unwrap();
            let Request::Plan(back) = decode_request(&bytes).unwrap() else {
                panic!("вид сообщения потерян");
            };
            assert_eq!(back.original_name, "contract.docx");
            assert_eq!(back.chunk_size, 65536);
            assert_eq!(back.authority_urls.len(), 2);
            assert_eq!(back.device_tpm.as_deref(), Some(&[9u8; 65][..]));
        }
    }

    /// COAUTHOR ROSTERS SURVIVE THE WIRE; UNEXECUTABLE ROSTERS FAIL AT PARSING.
    ///
    /// Silently losing a roster in the pipe would produce a container with flags
    /// but no tag; the server would not pin the roster, and the author would learn only
    /// when a unilateral change succeeded. Thus the roster travels in full,
    /// and a message with an unexecutable roster cannot parse at all.
    #[test]
    fn a_coauthor_roster_survives_the_wire_and_a_broken_one_is_refused() {
        let roster = oc_format::header::Coauthors { threshold: 2, keys: vec![[1u8; 32], [0x42; 32]] };
        let mut a = args();
        a.coauthors = Some(roster.clone());
        let bytes = encode_request(&Request::Plan(Box::new(a))).unwrap();
        let Request::Plan(back) = decode_request(&bytes).unwrap() else {
            panic!("вид сообщения потерян");
        };
        assert_eq!(back.coauthors, Some(roster), "состав потерян или искажён");
        assert_eq!(back.request().coauthors, back.coauthors, "взгляд запросом теряет состав");

        // «Кворума нет» — законное утверждение: порог ноль без ключей.
        let mut a = args();
        a.coauthors = Some(oc_format::header::Coauthors { threshold: 0, keys: Vec::new() });
        let bytes = encode_request(&Request::Plan(Box::new(a))).unwrap();
        let Request::Plan(back) = decode_request(&bytes).unwrap() else { panic!() };
        assert_eq!(back.coauthors.map(|c| c.threshold), Some(0));

        // Неисполнимый состав не уходит и с этой стороны.
        let mut a = args();
        a.coauthors = Some(oc_format::header::Coauthors { threshold: 3, keys: vec![[1u8; 32], [2u8; 32]] });
        assert!(encode_request(&Request::Plan(Box::new(a))).is_err(), "неисполнимый порог закодирован");

        // С той стороны: байты хорошего сообщения, в которых порог поднят выше
        // числа ключей и продублирован ключ, — отказ разбора, а не состав.
        let mut a = args();
        a.coauthors = Some(oc_format::header::Coauthors { threshold: 1, keys: vec![[1u8; 32], [2u8; 32]] });
        let good = encode_request(&Request::Plan(Box::new(a))).unwrap();
        let tail = good.len() - (2 + 64);
        let mut raised = good.to_vec();
        raised[tail] = 3;
        assert!(decode_request(&raised).is_err(), "порог выше состава разобран");
        let mut duplicated = good.to_vec();
        let second = tail + 2 + 32;
        duplicated.copy_within(tail + 2..tail + 2 + 32, second);
        assert!(decode_request(&duplicated).is_err(), "повтор ключа в составе разобран");
        let mut too_many = good.to_vec();
        too_many[tail + 1] = 17;
        assert!(decode_request(&too_many).is_err(), "счётчик состава сверх предела разобран");
        let truncated = &good[..good.len() - 1];
        assert!(decode_request(truncated).is_err(), "обрезанный состав разобран");
    }

    /// Sealed-stream information survives the wire.
    #[test]
    fn the_sealed_info_survives_the_wire() {
        let sealed = SealedInfo { total_len: 1 << 40, chunk_count: 7, tree_root: [5u8; 32] };
        let bytes = encode_request(&Request::Assemble(sealed)).unwrap();
        let Request::Assemble(back) = decode_request(&bytes).unwrap() else {
            panic!("вид сообщения потерян");
        };
        assert_eq!(back.total_len, sealed.total_len);
        assert_eq!(back.chunk_count, sealed.chunk_count);
        assert_eq!(back.tree_root, sealed.tree_root);
    }

    /// Responses survive the wire, including the payload key.
    #[test]
    fn the_responses_survive_the_wire() {
        let planned = Response::Planned(Planned {
            file_id: [6u8; 16],
            payload_key: PayloadKey::from_bytes([7u8; 32]),
            chunk_size: 4096,
            aead: AeadAlg::XChaCha20Poly1305,
        });
        let bytes = encode_response(&planned).unwrap();
        let Response::Planned(back) = decode_response(&bytes).unwrap() else {
            panic!("вид ответа потерян");
        };
        assert_eq!(back.file_id, [6u8; 16]);
        assert_eq!(back.payload_key.expose(), &[7u8; 32]);
        assert_eq!(back.chunk_size, 4096);

        let done = Response::Done(Done { header: vec![1, 2, 3], content_desc: vec![4, 5] });
        let bytes = encode_response(&done).unwrap();
        let Response::Done(back) = decode_response(&bytes).unwrap() else {
            panic!("вид ответа потерян");
        };
        assert_eq!(back.header, vec![1, 2, 3]);
        assert_eq!(back.content_desc, vec![4, 5]);
    }

    /// TRUNCATED, EXTRA, AND UNKNOWN DATA ARE REJECTED, NOT GUESSED.
    ///
    /// Messages arrive from another process, hence hostile-input
    /// parsing with all its consequences. Trailing bytes receive a separate check,
    /// for good reason: extra bytes mean the parties disagree on layout,
    /// and swallowing them silently would let the sender append
    /// arbitrary data to the message.
    #[test]
    fn a_damaged_message_is_refused_rather_than_guessed() {
        let bytes = encode_request(&Request::Plan(Box::new(args()))).unwrap();

        for cut in 0..bytes.len() {
            let piece = bytes.get(..cut).unwrap();
            assert!(decode_request(piece).is_err(), "обрезка на {cut} принята");
        }

        let mut longer = bytes.to_vec();
        longer.push(0);
        assert_eq!(decode_request(&longer).unwrap_err(), WireError::TrailingBytes);

        assert_eq!(decode_request(&[99]).unwrap_err(), WireError::UnknownKind(99));
        assert_eq!(decode_request(&[]).unwrap_err(), WireError::Truncated);
    }

    /// FRAME LIMITS ARE CHECKED IN BOTH DIRECTIONS BEFORE ALLOCATION.
    ///
    /// This rule lived in two copies, engine and client, each repeating it
    /// in words. A third consumer would add a third copy; divergence here
    /// means processes disagreeing on length.
    #[test]
    fn the_frame_ceiling_holds_in_both_directions() {
        assert_eq!(frame_header(3, 10).unwrap(), 3u32.to_le_bytes());
        assert_eq!(frame_header(10, 10).unwrap(), 10u32.to_le_bytes(), "ровно потолок законен");
        assert_eq!(frame_header(11, 10).unwrap_err(), WireError::TooLarge);

        assert_eq!(frame_len(3u32.to_le_bytes(), 10).unwrap(), 3);
        assert_eq!(frame_len(10u32.to_le_bytes(), 10).unwrap(), 10);
        assert_eq!(frame_len(11u32.to_le_bytes(), 10).unwrap_err(), WireError::TooLarge);

        // Четыре байта, обещающие четыре гигабайта, — тот самый случай, ради
        // которого потолок и стоит.
        assert_eq!(frame_len(u32::MAX.to_le_bytes(), MAX_MESSAGE).unwrap_err(), WireError::TooLarge);
    }

    /// SECRET-BEARING MESSAGES ARE ASSEMBLED IN EXACT-SIZE BUFFERS.
    ///
    /// Tests I-11, not "nice arithmetic": a buffer whose capacity
    /// equals length never reallocated in flight, hence never returned an intermediate
    /// copy of the payload key or claim code to the allocator before
    /// `Drop`. Either calculation error is visible here: underestimate and
    /// [`Writer::raw`] rejects; overestimate and `finish` fails. Both
    /// return [`WireError::BadSize`], not a grown buffer.
    #[test]
    fn a_message_carrying_a_secret_is_built_in_a_buffer_of_the_exact_size() {
        let planned = Response::Planned(Planned {
            file_id: [6u8; 16],
            payload_key: PayloadKey::from_bytes([7u8; 32]),
            chunk_size: 4096,
            aead: AeadAlg::XChaCha20Poly1305,
        });
        let message = encode_response(&planned).unwrap();
        assert_eq!(message.capacity(), 54, "раскладка ответа с ключом изменилась");
        assert_eq!(message.len(), message.capacity(), "буфер с ключом не должен иметь запаса");

        let mut a = args();
        a.recipient = Recipient::Claim { secret: ClaimSecret::from_bytes([8u8; 32]) };
        let expected = 1
            + (4 + "contract.docx".len())
            + (4 + oc_format::policy_codec::encode(oc_format::header::CONTAINER_VERSION, &Policy::deny_all()).unwrap().len())
            + 4
            + (4 + 3)
            + 4
            + (4 + "https://a".len())
            + (4 + "https://b".len())
            + 1
            + 32
            + 32 * 4
            // Признак «есть ли гибридная половина автора» — байт, даже когда её
            // нет: получатель здесь классический, и половина не едет.
            + 1
            // Тот же байт для АППАРАТНОЙ половины автора (`kem_id = 5`).
            + 1
            // Признак «есть ли аппаратный ключ» и сам ключ несжатой точкой.
            + 1
            + (4 + 65)
            // Признак «есть ли состав соавторов» — байт, даже когда состава нет.
            + 1;
        let message = encode_request(&Request::Plan(Box::new(a))).unwrap();
        assert_eq!(message.capacity(), expected, "раскладка запроса изменилась");
        assert_eq!(message.len(), message.capacity(), "буфер с кодом-претензией не должен расти");
    }

    /// Messages do not disclose their contents through `Debug`.
    ///
    /// They contain a payload key, and a secret in a log or panic report
    /// leaks exactly like one written to disk.
    #[test]
    fn a_message_never_prints_its_bytes() {
        let planned = Response::Planned(Planned {
            file_id: [6u8; 16],
            payload_key: PayloadKey::from_bytes([0xab; 32]),
            chunk_size: 4096,
            aead: AeadAlg::XChaCha20Poly1305,
        });
        let rendered = format!("{:?}", encode_response(&planned).unwrap());
        assert!(!rendered.contains("ab"), "Debug выдал байты сообщения: {rendered}");
        assert!(rendered.contains("скрыто"));
    }
}
