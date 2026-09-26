// SPDX-License-Identifier: MPL-2.0
//! Packing keys, recipient slots, and the container header.
//!
//! The host supplies randomness and processes document bytes. The engine has no
//! I/O or clocks, and retains the CEK while releasing only the derived payload key.
//!
//! ```text
//! plan()      -> session and payload key
//! seal_chunks -> ciphertext, length, and tree root (host)
//! assemble()  -> header and signing transcript
//! sign+write  -> author signature and container (host)
//! ```
//!
//! Assembly follows streaming because private metadata includes the final length.
//! The host signs the entire header with the author's key; the engine does not sign.

use rand_core::CryptoRng;
use oc_crypto::secret::{Cek, ClaimSecret, PayloadKey, SecretA, SecretB};
use oc_crypto::{AeadAlg, CryptoError, SigAlg, TreeHashAlg, kdf, label, seal, wrap};
use oc_format::FormatError;
use oc_format::content::ContentDesc;
use oc_format::header::{
    Authority, CONTAINER_VERSION, SUPPORTED_READER_VERSION, Header, KeySlot, KnownSlot, SlotKind, Suite, WRAPPED_CEK_LEN,
};
use oc_format::tlv::TlvWriter;
use oc_policy::Policy;
use zeroize::Zeroizing;

pub mod wire;
/// Edit writer (`docs/format.md`, "EDITING IS EXECUTABLE", item G).
pub mod edit;

/// Private-metadata tags.
///
/// Public because the engine writes them and the device reads them: maintaining two
/// definitions of identical numbers in two crates would create
/// divergence appearing only in someone else's file.
pub mod meta_tag {
    pub const NAME: u16 = 1;
    pub const SIZE: u16 = 2;
}

/// Length of the nonce encrypting private metadata.
pub const META_NONCE_LEN: usize = 24;

/// Engine failure.
#[derive(Debug)]
pub enum EngineError {
    Format(FormatError),
    Crypto(CryptoError),
    /// The assembled header is internally inconsistent.
    CoreHashMismatch,
    /// Assembly changed the planned chunk size or recipient.
    PlanMismatch,
    /// Hybrid recipient, but no author hybrid half was supplied.
    ///
    /// A distinct error, not a downgrade to a classical slot: downgrading
    /// would restore the very hole this branch closes, silently;
    /// the file would appear post-quantum without being so.
    MissingAuthorHybridKey,
}

impl From<FormatError> for EngineError {
    fn from(e: FormatError) -> Self {
        Self::Format(e)
    }
}

impl From<CryptoError> for EngineError {
    fn from(e: CryptoError) -> Self {
        Self::Crypto(e)
    }
}

impl core::fmt::Display for EngineError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Format(e) => write!(f, "{e}"),
            Self::Crypto(e) => write!(f, "{e}"),
            Self::PlanMismatch => f.write_str("assembly request differs from the encryption plan"),
            Self::CoreHashMismatch => {
                write!(f, "хеш ядра заголовка изменился после добавления слотов")
            }
            Self::MissingAuthorHybridKey => write!(
                f,
                "получатель гибридный, а гибридного ключа автора нет: классический авторский слот свёл бы постквантовую защиту на нет"
            ),
        }
    }
}

impl std::error::Error for EngineError {}

/// Algorithm suite used by this engine.
#[must_use]
pub fn suite() -> Suite {
    Suite {
        sig: SigAlg::Ed25519,
        aead: AeadAlg::XChaCha20Poly1305,
        tree_hash: TreeHashAlg::Blake3,
    }
}

/// Whom the file addresses besides the author's device.
///
/// The author slot is **always** present and not described here: without it,
/// removing protection would require networking, creating precisely the risk of losing
/// one's own files that the product should prevent.
///
/// `Clone` deserves explanation: the claim-code variant copies a
/// SECRET. This is deliberate: the packing request lives until header assembly,
/// with the entire document stream between planning and assembly. It is safe precisely because
/// `ClaimSecret` wipes itself on destruction. The copy disappears just like
/// the original.
#[derive(Debug, Clone)]
pub enum Recipient {
    /// Nobody: **only** the author opens the file.
    ///
    /// Not "seamless mode" from §3.4, although its flags resemble the
    /// default. In seamless mode the recipient share is available to anyone holding
    /// the file; here nobody but the author's device can access it.
    None,
    /// Recipient's long-term key ("partner key" mode, §3.4).
    Identity { public_key: [u8; 32] },
    /// Recipient hybrid key: `kem_id = 4`, X-Wing (format version 4).
    ///
    /// Boxed because 1216 bytes in an enum would inflate EVERY
    /// variant to that size, including `None`.
    Hybrid { public_key: Box<[u8; oc_crypto::xwing::PUBLIC_KEY_LEN]> },
    /// Recipient HARDWARE hybrid: `kem_id = 5`, MLKEM768-P256 (version 5).
    ///
    /// Differs from [`Self::Hybrid`] in where the recipient's classical half
    /// lives: software X25519 there, P-256 inside its TPM here.
    HardwareHybrid { public_key: Box<[u8; oc_crypto::mlkem_p256::PUBLIC_KEY_LEN]> },
    /// Claim code (§3.4): the share derives from the code; only the commitment
    /// enters the container.
    Claim { secret: ClaimSecret },
}

/// Recipient slot that will appear in the header.
///
/// Unlike [`Recipient`], the claim code has already become a
/// commitment. The type exists precisely to prevent the
/// state "claim-code mode without a commitment".
enum RecipientPlan {
    None,
    Identity([u8; 32]),
    Hybrid(Box<[u8; oc_crypto::xwing::PUBLIC_KEY_LEN]>),
    HardwareHybrid(Box<[u8; oc_crypto::mlkem_p256::PUBLIC_KEY_LEN]>),
    Claim([u8; 32]),
}

impl RecipientPlan {
    fn matches(&self, file_id: &[u8; 16], requested: &Recipient) -> bool {
        match (self, requested) {
            (Self::None, Recipient::None) => true,
            (Self::Identity(planned), Recipient::Identity { public_key }) =>
                oc_crypto::public_key_eq(planned, public_key),
            (Self::Hybrid(planned), Recipient::Hybrid { public_key }) =>
                oc_crypto::public_key_eq(planned.as_slice(), public_key.as_slice()),
            (Self::HardwareHybrid(planned), Recipient::HardwareHybrid { public_key }) =>
                oc_crypto::public_key_eq(planned.as_slice(), public_key.as_slice()),
            (Self::Claim(planned), Recipient::Claim { secret }) => {
                let (_, commitment) = kdf::secret_b_from_claim(file_id, secret);
                oc_crypto::digest_eq(planned, &commitment)
            }
            _ => false,
        }
    }
}

/// Public keys the engine places in the header and slots.
///
/// PUBLIC only. No device secret enters here, enforced
/// by types: the engine has nothing to sign with or decrypt others' data with.
#[derive(Debug)]
pub struct PublicKeys<'a> {
    /// Author verification key, stored in the header as `author_key`.
    pub author: [u8; 32],
    /// Server sealing key: both `sealing_kid` and the server-slot recipient.
    pub authority_sealing: [u8; 32],
    /// Pinned lease-verification key.
    pub authority_lease_verify: [u8; 32],
    /// Author-device software key.
    pub device: [u8; 32],
    /// Author-device hardware hybrid: MLKEM768-P256, 1249 bytes.
    ///
    /// Required if and only if the recipient uses mechanism five.
    pub device_hardware_hybrid: Option<&'a [u8]>,
    /// Author-device hybrid public half: X-Wing, 1216 bytes.
    ///
    /// Required if and only if the recipient is hybrid: the author slot
    /// must be no weaker than the recipient slot, or post-quantum protection
    /// is lost on the file itself; see `seal_slots`.
    pub device_hybrid: Option<&'a [u8]>,
    /// Hardware device key (P-256 from a TPM), if available.
    ///
    /// When present, the author slot addresses IT; no second slot for a software
    /// key is written beside it. Writing both would let an attacker who stole
    /// the key directory open new files too, making hardware binding
    /// provide nothing but a label.
    pub device_tpm: Option<&'a [u8]>,
}

/// What to pack and under which rules.
pub struct PackRequest<'a> {
    pub original_name: &'a str,
    pub policy: Policy,
    pub chunk_size: u32,
    pub org_id: Vec<u8>,
    pub authority_urls: Vec<String>,
    pub recipient: Recipient,
    /// Coauthor roster under the author signature: tag `0x8001` (version 4).
    ///
    /// `None` means no header tag and container bytes identical to before
    /// this field existed: golden artifacts without a roster remain unchanged. Checked using
    /// the encoder's rule (`Coauthors::validate`); the caller must
    /// reject earlier, before processing the stream.
    pub coauthors: Option<oc_format::header::Coauthors>,
}

/// What the engine gives the device to process the stream.
///
/// `payload_key`, not `CEK`: see module documentation.
#[derive(Debug)]
pub struct Plan {
    pub file_id: [u8; 16],
    pub payload_key: PayloadKey,
    pub chunk_size: u32,
    pub aead: AeadAlg,
}

/// What the device reports after processing the stream.
#[derive(Debug, Clone, Copy)]
pub struct SealedInfo {
    pub total_len: u64,
    pub chunk_count: u32,
    pub tree_root: [u8; 32],
}

impl core::fmt::Debug for PackRequest<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PackRequest")
            .field("original_name", &"<redacted>")
            .field("policy", &self.policy)
            .field("chunk_size", &self.chunk_size)
            .field("org_id", &self.org_id)
            .field("authority_urls", &self.authority_urls)
            .field("recipient", &self.recipient)
            .field("coauthors", &self.coauthors)
            .finish()
    }
}

/// What the engine returns after assembly.
///
/// # NO signing transcript here, deliberately
///
/// It existed and was removed when the engine began moving into a separate process. The reason
/// is not protocol convenience: the device must sign what ITSELF
/// derived from the header it intends to write, not what the engine
/// sent. Otherwise a hostile engine could pair one header's transcript
/// with another header's bytes, making the author's signature authenticate the wrong file.
///
/// Transcript derivation is a pure function of the header and suite
/// (`oc_format::verify::header_signing_transcript`), available to the device and
/// essentially free. Omitting it would exchange verifiable data for supplied data.
#[derive(Debug)]
pub struct Assembled {
    /// Entire header, ready to write.
    pub header: Vec<u8>,
    /// Mutable region with its MAC already applied.
    pub content_desc: Vec<u8>,
}

/// One file's secrets, living between the engine's two calls.
///
/// Deliberately neither `Clone` nor `Copy`: copying this structure copies the
/// content key, with no scenario requiring that.
#[derive(Debug)]
pub struct Session {
    file_id: [u8; 16],
    header_salt: [u8; 32],
    chunk_size: u32,
    cek: Cek,
    secret_a: SecretA,
    secret_b: SecretB,
    plan: RecipientPlan,
}

impl core::fmt::Debug for RecipientPlan {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Содержимое не печатается: обязательство кода-претензии выводится из
        // секрета, и хотя само по себе оно не секрет, привычка печатать поля
        // ключевых структур в отчёт о панике здесь не заводится.
        match self {
            Self::None => write!(f, "RecipientPlan::None"),
            Self::Identity(_) => write!(f, "RecipientPlan::Identity"),
            Self::Hybrid(_) => write!(f, "RecipientPlan::Hybrid"),
            Self::HardwareHybrid(_) => write!(f, "RecipientPlan::HardwareHybrid"),
            Self::Claim(_) => write!(f, "RecipientPlan::Claim"),
        }
    }
}

/// First call: generate secrets and release the payload key.
///
/// # RNG consumption order is frozen here
///
/// `file_id`, `header_salt`, `CEK`, share A, share B, precisely in that order. It
/// is not cosmetic: golden artifacts use a seeded RNG; any
/// reordering changes every file byte. For the same reason, a new RNG call cannot be
/// inserted "at the start", only at the end, and only alongside
/// a format-version decision.
pub fn plan<G: CryptoRng + ?Sized>(request: &PackRequest<'_>, rng: &mut G) -> (Session, Plan) {
    let mut file_id = [0u8; 16];
    let mut header_salt = [0u8; 32];
    rand_core::Rng::fill_bytes(rng, &mut file_id);
    rand_core::Rng::fill_bytes(rng, &mut header_salt);

    let cek = Cek::random(rng);
    let secret_a = SecretA::random(rng);

    // Доля получателя случайна во всех режимах, КРОМЕ кода-претензии: там она
    // выводится из кода (K7), потому что передаётся не файлом, а вторым каналом.
    // Порядок важен — доля должна существовать до вывода KEK.
    //
    // Вместе с долей решается и то, какой слот получателя появится. Одним
    // выражением, а не двумя: разними их, и возникло бы состояние «режим кода, а
    // обязательства нет» — недостижимое, но требующее ветки, которая ничего не
    // значит. Здесь его просто нет.
    let (secret_b, plan) = match &request.recipient {
        Recipient::None => (SecretB::random(rng), RecipientPlan::None),
        Recipient::Identity { public_key } => {
            (SecretB::random(rng), RecipientPlan::Identity(*public_key))
        }
        Recipient::Hybrid { public_key } => {
            (SecretB::random(rng), RecipientPlan::Hybrid(public_key.clone()))
        }
        Recipient::HardwareHybrid { public_key } => {
            (SecretB::random(rng), RecipientPlan::HardwareHybrid(public_key.clone()))
        }
        Recipient::Claim { secret } => {
            let (share, commit) = kdf::secret_b_from_claim(&file_id, secret);
            (share, RecipientPlan::Claim(commit))
        }
    };

    let payload_key =
        kdf::derive_payload_key(&cek, &header_salt, &file_id, request.chunk_size, suite().aead);

    (
        Session { file_id, header_salt, chunk_size: request.chunk_size, cek, secret_a, secret_b, plan },
        Plan { file_id, payload_key, chunk_size: request.chunk_size, aead: suite().aead },
    )
}

impl Session {
    /// Second call: assemble header and mutable region.
    ///
    /// The header is assembled TWICE, not wastefully: the core hash must
    /// exist before key material bound to it (I-3),
    /// while slots and the wrapped key are excluded from that hash. The first pass yields
    /// a skeleton without them; the second yields the actual header.
    ///
    /// # Errors
    /// Returns [`EngineError`] on encoding or sealing failure, or a
    /// recomputed core-hash mismatch. The chunk size and recipient must match
    /// the request used by [`plan`], otherwise [`EngineError::PlanMismatch`].
    pub fn assemble<G: CryptoRng + ?Sized>(
        self,
        request: &PackRequest<'_>,
        keys: &PublicKeys<'_>,
        sealed: SealedInfo,
        rng: &mut G,
    ) -> Result<Assembled, EngineError> {
        let Session { file_id, header_salt, chunk_size, cek, secret_a, secret_b, plan } = self;
        // Keep the K3 chunk size and recipient selected during planning.
        if request.chunk_size != chunk_size || !plan.matches(&file_id, &request.recipient) {
            return Err(EngineError::PlanMismatch);
        }

        let private_meta =
            seal_private_meta(&cek, &header_salt, &file_id, request, sealed.total_len, rng)?;

        let mut header = Header {
            container_version: CONTAINER_VERSION,
            // Версия 3 всегда требует читателя 3: состав слотов это не понижает (§2.1).
            min_reader_version: SUPPORTED_READER_VERSION,
            file_id,
            suite: suite(),
            author_key: keys.author,
            header_salt,
            chunk_size: request.chunk_size,
            original_root: sealed.tree_root,
            policy: request.policy.clone(),
            key_slots: Vec::new(),
            authority: Authority {
                urls: request.authority_urls.clone(),
                sealing_kid: keys.authority_sealing,
                lease_verify_key: keys.authority_lease_verify,
            },
            private_meta,
            prev_header_hash: None,
            org_id: request.org_id.clone(),
            class: 0,
            footer_offset: None,
            wrapped_cek: [0u8; WRAPPED_CEK_LEN],
            coauthors: request.coauthors.clone(),
        };

        let skeleton = header.encode()?;
        let parsed = Header::decode(&skeleton)?;
        let core_hash = Header::core_hash(&skeleton, &parsed.spans)?;
        let policy_hash = Header::policy_hash(&skeleton, &parsed.spans)?;

        let kek = kdf::derive_kek(&file_id, &request.org_id, &secret_a, &secret_b);
        let (wrapped_cek, commitment) = wrap::wrap_cek(&kek, &cek, &core_hash, rng)?;

        header.wrapped_cek = wrapped_cek;

        // Порядок слотов: сервер, получатель (если есть), устройство автора.
        // Держится ради воспроизводимости golden.
        let mut slots = vec![seal_slot(
            SlotKind::Server,
            &keys.authority_sealing,
            label::SLOT_SERVER,
            &file_id,
            &policy_hash,
            secret_a.expose(),
            commitment,
            rng,
        )?];

        // Признак снимается ДО разбора плана: ниже план частично перемещается.
        let hybrid_recipient = matches!(plan, RecipientPlan::Hybrid(_));
        let hardware_recipient = matches!(plan, RecipientPlan::HardwareHybrid(_));

        match plan {
            RecipientPlan::None => {}
            RecipientPlan::Identity(public_key) => {
                slots.push(seal_slot(
                    SlotKind::RecipientIdentity,
                    &public_key,
                    label::SLOT_RECIPIENT,
                    &file_id,
                    &policy_hash,
                    secret_b.expose(),
                    commitment,
                    rng,
                )?);
            }
            RecipientPlan::HardwareHybrid(public_key) => {
                slots.push(seal_slot_mlkem_p256(
                    SlotKind::RecipientIdentity,
                    public_key.as_slice(),
                    label::SLOT_RECIPIENT,
                    &file_id,
                    &policy_hash,
                    secret_b.expose(),
                    commitment,
                    rng,
                )?);
            }
            RecipientPlan::Hybrid(public_key) => {
                slots.push(seal_slot_xwing(
                    SlotKind::RecipientIdentity,
                    public_key.as_slice(),
                    label::SLOT_RECIPIENT,
                    &file_id,
                    &policy_hash,
                    secret_b.expose(),
                    commitment,
                    rng,
                )?);
            }
            // Запечатывать нечего: доля выводится из кода, который у получателя
            // уже есть. В слот идёт только обязательство.
            RecipientPlan::Claim(claim_commit) => slots.push(claim_slot(claim_commit, commitment)),
        }

        // АВТОРСКИЙ СЛОТ НЕ ВПРАВЕ БЫТЬ СЛАБЕЕ СЛОТА ПОЛУЧАТЕЛЯ.
        //
        // Здесь безусловно стоял классический слот — на ключ в TPM либо на
        // программный, — и он несёт ОБЕ доли разом (`both_shares`). Значит
        // гибридный слот получателя не давал контейнеру ничего: противник,
        // умеющий решать дискретный логарифм, брал авторский слот, получал A‖B,
        // выводил KEK и открывал файл, не притрагиваясь к ML-KEM. Стойкость
        // контейнера равна стойкости СЛАБЕЙШЕГО достаточного пути к CEK, а
        // авторский путь достаточен всегда.
        //
        // Поэтому при гибридном получателе авторский слот тоже гибридный.
        //
        // Цена названа вслух: X-Wing определён на X25519, а ключ в TPM — P-256,
        // поэтому на таком файле автор ТЕРЯЕТ аппаратную привязку. Это та же
        // взаимоисключимость, что записана для получателя (`docs/threat-model.md`
        // §2), только теперь и на стороне автора. Выбор между «постквантово» и
        // «ключ не покидает TPM» делает автор, называя получателя.
        let author_slot = match (hardware_recipient, keys.device_hardware_hybrid) {
            // Получатель на аппаратном гибриде — авторский слот тот же механизм.
            // Слабее нельзя: авторский слот несёт ОБЕ доли, и классический
            // рядом с постквантовым свёл бы защиту к классической.
            (true, Some(public)) => seal_slot_mlkem_p256(
                SlotKind::AuthorDevice,
                public,
                label::SLOT_AUTHOR_DEVICE,
                &file_id,
                &policy_hash,
                &both_shares(&secret_a, &secret_b),
                commitment,
                rng,
            )?,
            // Аппаратной половины автора нет — отказ, а не понижение. У этой
            // машины может не быть TPM вовсе; тогда пятый механизм ей недоступен,
            // и упаковать на него значило бы соврать про ступень.
            (true, None) => return Err(EngineError::MissingAuthorHybridKey),
            (false, _) => match (hybrid_recipient, keys.device_hybrid, keys.device_tpm) {
            (true, Some(hybrid_public), _) => seal_slot_xwing(
                SlotKind::AuthorDevice,
                hybrid_public,
                label::SLOT_AUTHOR_DEVICE,
                &file_id,
                &policy_hash,
                &both_shares(&secret_a, &secret_b),
                commitment,
                rng,
            )?,
            // Получатель гибридный, а гибридной половины автора нет. Это не
            // «упакуем классическим»: молчаливое понижение вернуло бы ровно ту
            // дыру, ради закрытия которой ветка и заведена. Отказ.
            (true, None, _) => return Err(EngineError::MissingAuthorHybridKey),
            (false, _, Some(tpm_public)) => seal_slot_p256(
                SlotKind::AuthorDevice,
                tpm_public,
                label::SLOT_AUTHOR_DEVICE,
                &file_id,
                &policy_hash,
                &both_shares(&secret_a, &secret_b),
                commitment,
                rng,
            )?,
            (false, _, None) => seal_slot(
                SlotKind::AuthorDevice,
                &keys.device,
                label::SLOT_AUTHOR_DEVICE,
                &file_id,
                &policy_hash,
                &both_shares(&secret_a, &secret_b),
                commitment,
                rng,
            )?,
            },
        };
        slots.push(author_slot);
        header.key_slots = slots;

        let final_bytes = header.encode()?;
        let final_parsed = Header::decode(&final_bytes)?;
        // Проверка предположения, на котором держится весь двухпроходный порядок.
        // Если хеш ядра всё-таки зависит от ключевого материала, файл получится
        // нечитаемым — и узнать об этом надо здесь, а не у получателя.
        let recomputed = Header::core_hash(&final_bytes, &final_parsed.spans)?;
        // Сравнение через `digest_eq`, хотя оракула здесь нет: обе величины наши,
        // обе на стороне ПИСАТЕЛЯ, противнику неоткуда мерить время. И-13 говорит
        // не «где опасно», а «доктрина сравнения дайджестов ЕДИНА для всего
        // репозитория», и в этом вся её ценность.
        if !oc_crypto::digest_eq(&recomputed, &core_hash) {
            return Err(EngineError::CoreHashMismatch);
        }

        let mac_key = kdf::derive_content_mac_key(&cek, &header_salt, &file_id);
        let content_desc = ContentDesc {
            total_len: sealed.total_len,
            chunk_count: sealed.chunk_count,
            tree_root: sealed.tree_root,
            version_counter: 0,
            // Свежеупакованный файл не правлен: подписи редактора у него нет и
            // быть не может. Она появляется только при первой правке.
            editor: None,
            footer_offset: None,
        }
        .encode(&mac_key, &file_id, header.container_version)?;

        Ok(Assembled { header: final_bytes, content_desc })
    }
}

fn both_shares(a: &SecretA, b: &SecretB) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(64));
    out.extend_from_slice(a.expose());
    out.extend_from_slice(b.expose());
    out
}

/// Seal a slot to a P-256 key, when the recipient is a TPM.
///
/// A separate function rather than a [`seal_slot`] flag, for the same reason
/// crypto separates `seal` and `seal_p256`: mechanisms consume the
/// RNG differently, and X25519's order is frozen by golden artifacts.
#[allow(clippy::too_many_arguments)]
fn seal_slot_p256<G: CryptoRng + ?Sized>(
    kind: SlotKind,
    recipient_public: &[u8],
    purpose: oc_crypto::Label,
    file_id: &[u8; 16],
    policy_hash: &[u8; 32],
    plaintext: &[u8],
    commitment: [u8; 32],
    rng: &mut G,
) -> Result<KeySlot, EngineError> {
    let kem = oc_crypto::KemAlg::P256HkdfSha256;
    let info = seal::slot_info(purpose, kem, file_id);

    let blob = seal::seal_p256(recipient_public, &info, policy_hash, plaintext, rng)?;
    Ok(KeySlot::Known(KnownSlot {
        kind,
        kem,
        enc: blob.enc,
        nonce: blob.nonce,
        ct: blob.ct,
        commitment,
        key_fpr: Some(recipient_public.to_vec()),
        claim_commit: None,
    }))
}

/// Seal a slot with the X-Wing HYBRID, `kem_id = 4`.
///
/// A separate function beside [`seal_slot`] and [`seal_slot_p256`] for the same
/// reason those are separate: each mechanism has its own RNG consumption
/// order, while X25519's is frozen by golden artifacts.
#[allow(clippy::too_many_arguments)]
fn seal_slot_xwing<G: CryptoRng + ?Sized>(
    kind: SlotKind,
    recipient_public: &[u8],
    purpose: oc_crypto::Label,
    file_id: &[u8; 16],
    policy_hash: &[u8; 32],
    plaintext: &[u8],
    commitment: [u8; 32],
    rng: &mut G,
) -> Result<KeySlot, EngineError> {
    let kem = oc_crypto::KemAlg::XWing;
    let info = seal::slot_info(purpose, kem, file_id);

    let blob = seal::seal_xwing(recipient_public, &info, policy_hash, plaintext, rng)?;
    Ok(KeySlot::Known(KnownSlot {
        kind,
        kem,
        enc: blob.enc,
        nonce: blob.nonce,
        ct: blob.ct,
        commitment,
        key_fpr: Some(recipient_public.to_vec()),
        claim_commit: None,
    }))
}

/// Seal a slot with a HARDWARE hybrid, `kem_id = 5`.
#[allow(clippy::too_many_arguments)]
fn seal_slot_mlkem_p256<G: CryptoRng + ?Sized>(
    kind: SlotKind,
    recipient_public: &[u8],
    purpose: oc_crypto::Label,
    file_id: &[u8; 16],
    policy_hash: &[u8; 32],
    plaintext: &[u8],
    commitment: [u8; 32],
    rng: &mut G,
) -> Result<KeySlot, EngineError> {
    let kem = oc_crypto::KemAlg::MlKem768P256;
    let info = seal::slot_info(purpose, kem, file_id);

    let blob = seal::seal_mlkem_p256(recipient_public, &info, policy_hash, plaintext, rng)?;
    Ok(KeySlot::Known(KnownSlot {
        kind,
        kem,
        enc: blob.enc,
        nonce: blob.nonce,
        ct: blob.ct,
        commitment,
        key_fpr: Some(recipient_public.to_vec()),
        claim_commit: None,
    }))
}

/// Seal one slot.
///
/// `info` distinguishes slot purpose; `aad` is the policy hash, preventing ciphertext from
/// moving to a container with different rules. Eight arguments are many,
/// and the linter is right, but each is mandatory and meaningful; gathering them into
/// a structure would introduce a type lasting exactly one call, hiding
/// what readers of that call need to see.
#[allow(clippy::too_many_arguments)]
fn seal_slot<G: CryptoRng + ?Sized>(
    kind: SlotKind,
    recipient_public: &[u8; 32],
    purpose: oc_crypto::Label,
    file_id: &[u8; 16],
    policy_hash: &[u8; 32],
    plaintext: &[u8],
    commitment: [u8; 32],
    rng: &mut G,
) -> Result<KeySlot, EngineError> {
    // Механизм называется один раз и тем же значением уходит и в info, и в поле
    // слота: разъединив их, легко получить слот, чей объявленный алгоритм не тот,
    // которым он на самом деле запечатан.
    let kem = seal::DEFAULT_SEALING_KEM;
    let info = seal::slot_info(purpose, kem, file_id);

    let blob = seal::seal(recipient_public, &info, policy_hash, plaintext, rng)?;
    Ok(KeySlot::Known(KnownSlot {
        kind,
        kem,
        enc: blob.enc,
        nonce: blob.nonce,
        ct: blob.ct,
        commitment,
        key_fpr: Some(recipient_public.to_vec()),
        claim_commit: None,
    }))
}

/// Claim-code slot: commitment and nothing more.
///
/// Sealing fields are zeroed and `ct` stays empty, not as placeholders
/// "to satisfy the structure": there is **nothing to seal**. The recipient
/// share derives from the code, which never enters the container.
fn claim_slot(claim_commit: [u8; 32], commitment: [u8; 32]) -> KeySlot {
    KeySlot::Known(KnownSlot {
        kind: SlotKind::RecipientClaim,
        kem: seal::DEFAULT_SEALING_KEM,
        // Нули длиной ровно 32: слот кода-претензии объявляет `kem_id = 1` всегда
        // (§2.0), и длина его неиспользуемых полей задана механизмом, а не
        // выбором по умолчанию. Пустой вектор прошёл бы проверку «все байты нули»
        // так же, как тридцать два нуля, — а байты в файле разные.
        enc: vec![0u8; 32],
        nonce: [0u8; 24],
        ct: Vec::new(),
        commitment,
        // Отпечатка ключа нет, потому что нет и ключа: получателя опознаёт код, а
        // не пара ключей.
        key_fpr: None,
        claim_commit: Some(claim_commit),
    })
}

/// Encrypt private metadata under its own key.
fn seal_private_meta<G: CryptoRng + ?Sized>(
    cek: &Cek,
    header_salt: &[u8; 32],
    file_id: &[u8; 16],
    request: &PackRequest<'_>,
    total_len: u64,
    rng: &mut G,
) -> Result<Vec<u8>, EngineError> {
    let mut meta = TlvWriter::new();
    meta.put(meta_tag::NAME, request.original_name.as_bytes())?;
    meta.put(meta_tag::SIZE, &total_len.to_le_bytes())?;

    let key = kdf::derive_private_meta_key(cek, header_salt, file_id);
    let body = meta.finish();
    // Nonce через засев (решение С-13, доведённое пунктом Р-2). Здесь повтор
    // состояния генератора обходился дороже всего: `CEK` и `header_salt` берутся
    // из того же генератора, поэтому при откате снапшота повторялись и ключ K5, и
    // nonce, — а открытые тексты различались, потому что это имя и размер другого
    // документа.
    //
    // Вывод стоит ВНУТРИ `seal_metadata_hedged`, а не здесь: пока он был шагом
    // движка, его можно было не сделать — функция принимала любые 24 байта и
    // молчала. Здесь остаётся только засев, который без генератора не добыть.
    let mut nonce_seed = Zeroizing::new([0u8; META_NONCE_LEN]);
    rand_core::Rng::fill_bytes(rng, nonce_seed.as_mut_slice());
    let (nonce, ct) = oc_crypto::aead::seal_metadata_hedged(&key, file_id, &nonce_seed, &body)?;

    // Nonce хранится вместе с шифротекстом: он не секрет, но без него блок не
    // расшифровать, а читатель его никогда не вычисляет (И-1).
    let mut out = Vec::with_capacity(META_NONCE_LEN.saturating_add(ct.len()));
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

#[cfg(test)]
mod tests {
    //! RNG consumption order is NAMED rather than implied.
    //!
    //! [`plan`]'s documentation freezes the order: `file_id`,
    //! `header_salt`, `CEK`, share A, share B. Until now only golden
    //! artifacts guarded it: those in `cc-cli` and adjacent `hardware_hybrid_golden.rs`. An artifact
    //! responds to swapped adjacent calls with "bytes differ at
    //! position N", insufficient to reconstruct order: all file bytes
    //! change together because everything else derives from these five
    //! values.
    //!
    //! Four of five requests are 32 bytes, so lengths alone CANNOT reveal
    //! neighbor swaps. Therefore we also check WHERE the bytes went: stream
    //! piece K must land in field X, and on a shift
    //! the probe names what took its place.
    //!
    //! This probe is inside the crate rather than `tests/`: [`Session`] fields are private;
    //! exposing them for comparison would widen the engine API for a test,
    //! releasing file secrets to anyone importing the crate.

    // Литы сняты для теста: `unwrap`/`panic` — словарь проверки, индексирование
    // и арифметика — нарезка потока заведомо известной длины.
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]

    use super::{PackRequest, Recipient, plan};
    use oc_policy::{Action, Policy};

    /// Bytes covered by location checks: 16 + 32 × 4.
    const WATCHED: usize = 144;

    /// Stream byte by index.
    ///
    /// A cheap custom sequence, not a hash: cryptographic quality
    /// is entirely unnecessary; pieces need only be distinguishable and
    /// reproducible, without another engine dependency.
    fn stream_byte(index: usize) -> u8 {
        (index as u8).wrapping_mul(31).wrapping_add(7)
    }

    /// RNG that REMEMBERS requested lengths in order.
    ///
    /// Emits a known stream, letting byte position identify which
    /// request received it.
    struct Recorder {
        next: usize,
        lengths: Vec<usize>,
    }

    impl rand_core::TryRng for Recorder {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            let mut b = [0u8; 4];
            self.try_fill_bytes(&mut b)?;
            Ok(u32::from_le_bytes(b))
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            let mut b = [0u8; 8];
            self.try_fill_bytes(&mut b)?;
            Ok(u64::from_le_bytes(b))
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            self.lengths.push(dst.len());
            for out in dst.iter_mut() {
                *out = stream_byte(self.next);
                self.next += 1;
            }
            Ok(())
        }
    }
    impl rand_core::TryCryptoRng for Recorder {}

    fn request() -> PackRequest<'static> {
        PackRequest {
            original_name: "порядок.pdf",
            policy: Policy::deny_all().allow(Action::View),
            chunk_size: 65536,
            org_id: b"order".to_vec(),
            authority_urls: vec!["https://cc.example/api".to_string()],
            recipient: Recipient::None,
            coauthors: None,
        }
    }

    /// FIVE RNG REQUESTS, IN THE NAMED ORDER AND INTO THE NAMED FIELDS.
    #[test]
    fn the_generator_is_drawn_from_in_the_frozen_order() {
        let mut rng = Recorder { next: 0, lengths: Vec::new() };
        let (session, _) = plan(&request(), &mut rng);

        let stream: Vec<u8> = (0..WATCHED).map(stream_byte).collect();
        // (имя величины — так её зовёт код `plan`, байты, которые ей достались)
        let fields: [(&str, &[u8]); 5] = [
            ("file_id", &session.file_id),
            ("header_salt", &session.header_salt),
            ("CEK", session.cek.expose()),
            ("secret_a (доля A)", session.secret_a.expose()),
            ("secret_b (доля B)", session.secret_b.expose()),
        ];
        let expected_lengths: Vec<usize> = fields.iter().map(|(_, bytes)| bytes.len()).collect();

        assert_eq!(
            rng.lengths,
            expected_lengths,
            "генератор спрошен не так, как обещает докстрока `plan`. Ожидались длины {}, \
             пришли {:?}. Новый запрос дописывается ТОЛЬКО в конец и только вместе с \
             решением о версии формата: любой другой сдвиг меняет каждый байт файла",
            fields
                .iter()
                .map(|(name, bytes)| format!("{name} {}", bytes.len()))
                .collect::<Vec<_>>()
                .join(", "),
            rng.lengths
        );

        let mut at = 0usize;
        for (position, (name, got)) in fields.iter().enumerate() {
            let want = &stream[at..at + got.len()];
            assert!(
                *got == want,
                "порядок расхода генератора сдвинут: на месте {position} ожидался {name}, \
                 пришёл {}",
                fields
                    .iter()
                    .find(|(_, other)| *other == want)
                    .map_or_else(
                        || "кусок потока, не попавший никуда".to_string(),
                        |(other, _)| (*other).to_string()
                    )
            );
            at += got.len();
        }
        assert_eq!(at, WATCHED, "сверено не всё, что обещано: {at} байт вместо {WATCHED}");
    }

    /// POSITIVE CONTROL: location checking detects swapping two neighbors.
    ///
    /// Without it, the probe above would pass even with an all-zero RNG,
    /// where all pieces are equal and every location "matches" every other.
    #[test]
    fn the_order_check_would_notice_two_neighbours_swapped() {
        let mut rng = Recorder { next: 0, lengths: Vec::new() };
        let (session, _) = plan(&request(), &mut rng);
        assert_ne!(
            session.cek.expose(),
            session.secret_a.expose(),
            "два соседних куска потока совпали — сверка адресов слепа"
        );
        assert_ne!(
            &session.header_salt,
            session.cek.expose(),
            "два соседних куска потока совпали — сверка адресов слепа"
        );
    }
}
