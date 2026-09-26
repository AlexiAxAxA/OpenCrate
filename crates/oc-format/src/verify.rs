// SPDX-License-Identifier: MPL-2.0
//! Container verification entry point.
//!
//! [`Prologue::split`] checks structure, then the header decoder obtains the author
//! key and algorithm suite needed to verify the original header bytes. Decoding
//! therefore precedes signature verification, unlike the idealized order in §5.1.
//! The decoder must safely handle unauthenticated and attacker-signed input.
//!
//! After signature verification, version checks and signer trust are evaluated.
//! A valid signature proves possession of its key, not trust in the author.
//! Because decoding runs first, its errors take precedence over signature errors.

use crate::header::{
    MAX_READABLE_CONTAINER_VERSION, MIN_READABLE_CONTAINER_VERSION, ParsedHeader,
    SUPPORTED_READER_VERSION, Suite,
};
use crate::{FormatError, MAGIC, MAX_HEADER_LEN, Prologue};
use oc_crypto::{Transcript, label, sign};

/// Header signature verification failure.
///
/// One variant for both "public key could not be parsed" and "signature mismatch".
/// There is no need to distinguish them externally: different answers would give the attacker
/// an extra bit about precisely which check failed.
const BAD_HEADER_SIGNATURE: FormatError = FormatError::BadHeaderSignature;

/// What is known about the signer.
///
/// A separate type, not a Boolean flag: the primary mistake in systems of this kind is
/// taking a public key **from the header itself**, verifying the signature with it,
/// and calling the result verified. That is self-signing, proving precisely
/// nothing. Distinct values prevent confusing "the signature matches" with "we
/// know who signed".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerTrust {
    /// The author key is pinned for this organization and matches.
    Pinned,
    /// The signature is valid, but this "organization, key" pair is new. The interface
    /// must state that explicitly rather than display a padlock.
    Unknown,
    /// **Known organization, different key.**
    ///
    /// The most important of the three values and the only one that must
    /// stop processing. This is exactly what substitution looks like: the file claims to be
    /// from the same sender as previously received files but is signed with
    /// a different key.
    ///
    /// Legitimate reasons also exist: the author changed keys. Nothing inside the file can
    /// distinguish them: the signature is valid in either case. Therefore
    /// the person decides, with **denial** as the default: a mistaken
    /// rejection costs one call to the sender; mistaken acceptance costs opening
    /// an attacker's file.
    Conflict,
}

/// Store of pinned author keys.
///
/// Returns the complete verdict rather than "is this key known": only the store's owner
/// can distinguish "first seen" from "a different key is known",
/// and this layer has no basis for deciding on its behalf.
///
/// `org_id` is required in the query as a consequence of the format. The author's
/// name is deliberately absent from the header (§2, tag 5): a name claimed in
/// the header proves no more than the header itself. The only anchor
/// for pinning is `org_id`, the tenant field. Hence the guarantee's
/// boundary: this catches key substitution **for a known organization**, but not
/// an attacker claiming to be a new organization; they simply become
/// unknown, which is the honest state.
pub trait TrustStore {
    /// What is known about the "organization, author key" pair.
    fn lookup(&self, org_id: &[u8], author_key: &[u8; 32]) -> SignerTrust;
}

/// A store that knows nobody.
///
/// Useful as both a default and an explicit "no trust" statement
/// in tests: every correctly signed container yields
/// [`SignerTrust::Unknown`].
#[derive(Debug, Clone, Copy, Default)]
pub struct EmptyTrustStore;

impl TrustStore for EmptyTrustStore {
    fn lookup(&self, _org_id: &[u8], _author_key: &[u8; 32]) -> SignerTrust {
        SignerTrust::Unknown
    }
}

/// Verified header together with the bytes from which it was parsed.
#[derive(Debug, Clone)]
pub struct VerifiedHeader<'a> {
    pub parsed: ParsedHeader,
    /// Original header bytes: all hashes are computed over these,
    /// not over a re-encoding.
    pub header_bytes: &'a [u8],
    /// Offset of the mutable region's first byte.
    pub content_desc_offset: u64,
    pub trust: SignerTrust,
}

/// Algorithm suite identifier included in the header signature (§5).
///
/// There is no separate scalar `suite_id` field in the header: the suite is defined by three
/// identifiers within `SUITE`. This value is therefore derived from the
/// parsed suite, specifically from the **signature algorithm**,
/// the sole algorithm on which the signature being verified depends. When [`SigAlg`]
/// gains a second value, this byte prevents presenting one scheme's signature as
/// another's if their encodings can be made to collide.
///
/// The AEAD and tree hash identifiers deliberately do not enter this byte: they are
/// within the header bytes, all covered by the signature. A second encoding
/// of the same thing is a second place that may diverge from the first,
/// causing silent rejection of a valid file.
///
/// [`SigAlg`]: oc_crypto::SigAlg
pub fn suite_id(suite: &Suite) -> u8 {
    suite.sig as u8
}

/// Exact byte string covered by the author's signature (§5).
///
/// ```text
/// "CC/v1/header-sig" ‖ 0x00 ‖ u8(suite_id) ‖ Magic ‖ u32le(HeaderLen) ‖ Header
/// ```
///
/// [`Transcript::new`] itself inserts the zero byte after the label, so it must not
/// be added here: a second zero would produce a string absent from
/// the specification, making files incompatible with any other implementation.
///
/// The header comes last without a length prefix: its length is already bound by
/// the preceding field. [`Transcript`] provides
/// [`Transcript::tail_after_declared_length`] for this case: it states that the missing
/// prefix is deliberate, not forgotten.
///
/// Public because the packer must sign exactly the same string.
/// Two independent constructions, one for writing and one for reading, could diverge and yield
/// a file our writer signs but our reader rejects, requiring byte comparison
/// to find the cause.
pub fn header_signing_transcript(
    header_bytes: &[u8],
    suite: &Suite,
) -> Result<Transcript, FormatError> {
    let declared = u32::try_from(header_bytes.len()).map_err(|_| FormatError::OffsetOverflow)?;
    // Тот же предел, что и на чтении. Писатель не должен уметь произвести
    // заголовок, который наш же читатель обязан отвергнуть по длине.
    if declared > MAX_HEADER_LEN {
        return Err(FormatError::HeaderTooLarge { declared });
    }

    let mut transcript = Transcript::new(label::HEADER_SIG);
    transcript
        .u8(suite_id(suite))
        .fixed(&MAGIC)
        .u32le(declared)
        .tail_after_declared_length(header_bytes);
    Ok(transcript)
}

/// Parse and verify the container prologue.
///
/// Sequence (see module documentation for its departure from §5.1):
/// 1. structural boundaries: magic, length limit, sufficient bytes;
/// 2. header decoding to obtain the author key and algorithm suite;
/// 3. Ed25519 signature verification over the domain-labeled transcript;
/// 4. version negotiation: `min_reader_version` and the `container_version` range;
/// 5. signer trust determination using the store.
///
/// Step 4 precedes **any** substantive use of fields: a file
/// requiring a newer client must be rejected even if everything else
/// parsed and its signature matched. The author key and suite are read earlier,
/// at step 2, but are not "applied": they only determine what to use and
/// what to compute the signature over.
///
/// Success means "the signature matches", **not** "the signer is trustworthy":
/// trust is returned separately in [`VerifiedHeader::trust`].
pub fn verify_and_parse<'a>(
    buf: &'a [u8],
    trust_store: &dyn TrustStore,
) -> Result<VerifiedHeader<'a>, FormatError> {
    // 1. Структура. Дёшево, тотально и без криптографии, поэтому первым: буфер,
    // который вообще не наш, отсеивается до единой операции с ключами.
    let prologue = Prologue::split(buf)?;

    // 2. Декодирование. Вынужденно идёт до проверки подписи: ключ автора и набор
    // алгоритмов лежат внутри заголовка. Безопасно ровно потому, что декодер
    // тотален; см. описание модуля.
    let parsed = crate::header::Header::decode(prologue.header)?;

    // 3. Подпись — по **сырым** байтам заголовка, а не по повторной кодировке
    // разобранной структуры. Повторная сериализация здесь воспроизвела бы всё
    // семейство ошибок канонизации, известное по JWS и XML-DSig: разобрали одно,
    // подписали другое.
    //
    // Ключ приходит из непроверенного заголовка, то есть от противника.
    // `sign::verify` внутри использует `verify_strict` и отвечает отказом, а не
    // паникой, на некорректную точку кривой.
    let transcript = header_signing_transcript(prologue.header, &parsed.header.suite)?;
    sign::verify(&parsed.header.author_key, &transcript, prologue.signature)
        .map_err(|_| BAD_HEADER_SIGNATURE)?;

    // 4. Согласование версий. Отказ обязателен, даже если подпись сошлась:
    // файл использует семантику, которой этот клиент не знает, и «понять
    // большинство полей» здесь означает применить чужие правила к чужому файлу.
    // Проверка стоит до сборки результата, чтобы наружу не ушла структура,
    // которую вызывающий имел бы право использовать.
    let min_reader_version = parsed.header.min_reader_version;
    if min_reader_version > SUPPORTED_READER_VERSION {
        return Err(FormatError::ReaderTooOld {
            need: min_reader_version,
            have: SUPPORTED_READER_VERSION,
        });
    }

    // `min_reader_version` — утверждение автора, а не описание формата.
    // Проверяем саму версию независимо: подписанный файл с версией 999 и
    // `min_reader_version = 1` не становится понятным этому читателю.
    // Диапазон исключает и будущие версии, и снятые версии 1–4 (решение Р-1).
    let container_version = parsed.header.container_version;
    // Обе границы нужны: версия 0 и снятые версии тоже недопустимы.
    if !(MIN_READABLE_CONTAINER_VERSION..=MAX_READABLE_CONTAINER_VERSION)
        .contains(&container_version)
    {
        return Err(FormatError::UnsupportedContainerVersion {
            version: container_version,
            first: MIN_READABLE_CONTAINER_VERSION,
            max: MAX_READABLE_CONTAINER_VERSION,
        });
    }

    // 5. Доверие — отдельным значением, а не флагом «проверено». Ключ спрашивается
    // именно тот, которым проверена подпись: спросить какой-нибудь другой значило
    // бы вернуть доверие к тому, кто файл не подписывал.
    let trust = trust_store.lookup(&parsed.header.org_id, &parsed.header.author_key);

    Ok(VerifiedHeader {
        parsed,
        header_bytes: prologue.header,
        // Изменяемая область начинается сразу за подписью. Смещение берётся из
        // пролога, а не пересчитывается по длине заголовка: два независимых
        // вычисления одного смещения рано или поздно разойдутся.
        content_desc_offset: prologue.after_signature,
        trust,
    })
}

/// Parse the prologue **without** signature verification.
///
/// Exists for exactly one use: decoder fuzzing, which needs
/// access to deep branches without dealing with signatures.
///
/// Gated by `cfg`, not merely an awkward name. A name and `#[doc(hidden)]` are
/// requests to a reviewer; bypassing signature verification is too costly to rely
/// on requests: a function available in a production build will eventually
/// be called there, from a debugging branch, a diagnostic utility, or
/// a "temporary look inside". Now the `cc-cli` build lacks this
/// symbol entirely, making it impossible to call even deliberately.
///
/// The fuzzer enables `fuzzing` explicitly: `--cfg fuzzing` (cargo-fuzz sets
/// it automatically).
#[doc(hidden)]
#[cfg(any(test, fuzzing))]
pub fn parse_without_verifying_signature_for_fuzzing_only(
    buf: &[u8],
) -> Result<ParsedHeader, FormatError> {
    let prologue = Prologue::split(buf)?;
    crate::header::Header::decode(prologue.header)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::header::{
        Authority, CONTAINER_VERSION, FIRST_CONTAINER_VERSION, Header, KeySlot, KnownSlot, SlotKind,
        tag,
    };
    use crate::tlv::TlvWriter;
    use oc_crypto::sign::{Ed25519Signer, SIGNATURE_LEN, Signer};
    use oc_crypto::{AeadAlg, KemAlg, SigAlg, TreeHashAlg};
    use oc_policy::{Action, Policy};

    /// Bytes immediately after the signature. There is no real mutable region here;
    /// only `content_desc_offset` pointing exactly to these bytes matters.
    const TRAILER: &[u8] = b"<content-desc goes here>";

    /// Marker used by the test to locate `original_root` within the encoded
    /// header and corrupt a value byte rather than a length byte: corrupting the length
    /// would break parsing before signature verification and test the wrong property.
    const ORIGINAL_ROOT: [u8; 32] = [0x33; 32];

    fn signer(seed: u8) -> Ed25519Signer {
        // Семя, а не генератор: тест обязан воспроизводиться байт в байт.
        Ed25519Signer::from_seed(&[seed; 32])
    }

    /// Algorithm suite for all test headers.
    fn sample_suite() -> Suite {
        Suite {
            sig: SigAlg::Ed25519,
            aead: AeadAlg::XChaCha20Poly1305,
            tree_hash: TreeHashAlg::Blake3,
        }
    }

    /// Store recognizing the listed keys regardless of organization.
    ///
    /// Deliberately ignores organization: these tests check that
    /// `verify_and_parse` queries the store with the key it used to verify
    /// the signature. Organization binding is a property of the store implementation,
    /// tested there (`cc_cli::trust`).
    #[derive(Debug, Default)]
    struct PinnedKeys(Vec<[u8; 32]>);

    impl TrustStore for PinnedKeys {
        fn lookup(&self, _org_id: &[u8], author_key: &[u8; 32]) -> SignerTrust {
            if self.0.contains(author_key) { SignerTrust::Pinned } else { SignerTrust::Unknown }
        }
    }

    /// Fully populated header: parsing must traverse every branch rather than
    /// a minimal field subset.
    fn sample_header(author_key: [u8; 32]) -> Header {
        Header {
            container_version: CONTAINER_VERSION,
            min_reader_version: SUPPORTED_READER_VERSION,
            file_id: [0x11; 16],
            suite: sample_suite(),
            author_key,
            header_salt: [0x22; 32],
            chunk_size: 65536,
            original_root: ORIGINAL_ROOT,
            policy: Policy::deny_all().allow(Action::View),
            key_slots: vec![KeySlot::Known(KnownSlot {
                kind: SlotKind::AuthorDevice,
                kem: KemAlg::X25519HkdfSha256,
                enc: vec![0x44; 32],
                nonce: [0x01; 24],
                ct: vec![0x55; 48],
                commitment: [0x66; 32],
                key_fpr: Some(vec![0x77; 32]),
                claim_commit: None,
            })],
            authority: Authority {
                urls: vec!["https://cc.example/api".to_string()],
                sealing_kid: [0x88; 32],
                lease_verify_key: [0x99; 32],
            },
            private_meta: vec![0xaa; 64],
            prev_header_hash: None,
            org_id: b"org".to_vec(),
            wrapped_cek: [0xbb; crate::header::WRAPPED_CEK_LEN],
            coauthors: None,
            class: 0,
            footer_offset: None,
        }
    }

    /// Assemble a container from prepared parts.
    ///
    /// Deliberately separate from signing: forgery tests must be able to insert
    /// someone else's signature without rebuilding the header.
    fn assemble(header_bytes: &[u8], signature: &[u8; SIGNATURE_LEN]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&u32::try_from(header_bytes.len()).unwrap().to_le_bytes());
        out.extend_from_slice(header_bytes);
        out.extend_from_slice(signature);
        out.extend_from_slice(TRAILER);
        out
    }

    /// A correctly signed container.
    ///
    /// `signer` and `header.author_key` are deliberately separate: only this allows a test
    /// to construct a header whose stated key differs from the actual signer.
    fn container(header: &Header, signer: &Ed25519Signer) -> Vec<u8> {
        let header_bytes = header.encode().unwrap();
        let transcript = header_signing_transcript(&header_bytes, &header.suite).unwrap();
        let signature = signer.sign(&transcript).unwrap();
        assemble(&header_bytes, &signature)
    }

    /// A container signed with its own key: an ordinary honest file.
    fn self_consistent(signer: &Ed25519Signer) -> Vec<u8> {
        container(&sample_header(signer.public_key()), signer)
    }

    #[test]
    fn a_well_formed_container_parses_and_exposes_the_bytes_it_was_parsed_from() {
        let author = signer(1);
        let buf = self_consistent(&author);

        let verified = verify_and_parse(&buf, &EmptyTrustStore).unwrap();

        assert_eq!(verified.parsed.header.author_key, author.public_key());
        assert_eq!(verified.parsed.header.chunk_size, 65536);
        assert_eq!(
            verified.header_bytes,
            sample_header(author.public_key()).encode().unwrap()
        );
        // Смещение обязано указывать ровно на первый байт за подписью: по нему
        // читатель изменяемой области начнёт разбор, и ошибка здесь сдвинула бы
        // всё, что дальше.
        let offset = usize::try_from(verified.content_desc_offset).unwrap();
        assert_eq!(buf.get(offset..), Some(TRAILER));
    }

    #[test]
    fn an_empty_trust_store_never_reports_a_pinned_signer() {
        // Значение по умолчанию обязано быть недоверием. Хранилище, которое
        // «на всякий случай» доверяет, — это отсутствие защиты с видом защиты.
        let buf = self_consistent(&signer(1));
        let verified = verify_and_parse(&buf, &EmptyTrustStore).unwrap();
        assert_eq!(verified.trust, SignerTrust::Unknown);
    }

    #[test]
    fn a_store_that_knows_the_key_reports_it_as_pinned() {
        let author = signer(1);
        let buf = self_consistent(&author);
        let store = PinnedKeys(vec![author.public_key()]);

        let verified = verify_and_parse(&buf, &store).unwrap();
        assert_eq!(verified.trust, SignerTrust::Pinned);
    }

    #[test]
    fn a_header_signed_by_a_stranger_verifies_but_is_never_trusted() {
        // ГЛАВНОЕ СВОЙСТВО ЭТОГО МОДУЛЯ.
        //
        // Противник строит заголовок, кладёт в поле автора СВОЙ публичный ключ и
        // подписывает СВОИМ приватным. Подпись сходится — иначе и быть не может,
        // ведь проверяется она названным в том же файле ключом. Самоподписанность
        // не доказывает ничего, и путать её с доверием — ровно та ошибка, ради
        // которой `SignerTrust` вообще существует отдельным типом.
        //
        // Хранилище при этом знает настоящего автора. Если бы `verify_and_parse`
        // отвечал «подписано, значит хорошо», файл противника выглядел бы для
        // пользователя так же, как файл автора.
        let author = signer(1);
        let stranger = signer(2);
        assert_ne!(author.public_key(), stranger.public_key());

        let forged = container(&sample_header(stranger.public_key()), &stranger);
        let store = PinnedKeys(vec![author.public_key()]);

        let verified = verify_and_parse(&forged, &store).unwrap();

        assert_eq!(
            verified.trust,
            SignerTrust::Unknown,
            "самоподписанный заголовок противника выдан за доверенный"
        );
        assert_eq!(
            verified.parsed.header.author_key,
            stranger.public_key(),
            "наружу обязан уходить тот ключ, которым проверена подпись"
        );

        // Контраст: то же хранилище на честном файле отвечает `Pinned`. Без этой
        // половины тест проходил бы и у реализации, которая не доверяет никому.
        let honest = self_consistent(&author);
        assert_eq!(
            verify_and_parse(&honest, &store).unwrap().trust,
            SignerTrust::Pinned
        );
    }

    #[test]
    fn a_signature_from_the_authors_key_over_a_foreign_header_is_refused() {
        // Обратная подстановка: заголовок называет автора, но подписал его не он.
        // Здесь подпись не сходится, и это уже отказ, а не вопрос доверия.
        let author = signer(1);
        let stranger = signer(2);
        let forged = container(&sample_header(author.public_key()), &stranger);

        assert_eq!(
            verify_and_parse(&forged, &PinnedKeys(vec![author.public_key()])).unwrap_err(),
            BAD_HEADER_SIGNATURE
        );
    }

    #[test]
    fn corrupting_a_single_header_byte_breaks_the_signature() {
        let author = signer(1);
        let header_bytes = sample_header(author.public_key()).encode().unwrap();
        let transcript = header_signing_transcript(&header_bytes, &sample_suite()).unwrap();
        let signature = author.sign(&transcript).unwrap();

        // Байт внутри ЗНАЧЕНИЯ поля: заголовок остаётся разбираемым, поэтому
        // отказ приходит именно от подписи, а не от декодера.
        let Some(at) = header_bytes
            .windows(ORIGINAL_ROOT.len())
            .position(|w| w == ORIGINAL_ROOT)
        else {
            panic!("original_root обязан лежать в закодированном заголовке");
        };
        let mut broken = header_bytes.clone();
        broken[at + 16] ^= 0x01;
        assert_eq!(
            verify_and_parse(&assemble(&broken, &signature), &EmptyTrustStore).unwrap_err(),
            BAD_HEADER_SIGNATURE
        );

        // И вообще любой перевёрнутый бит заголовка обязан дать отказ: подпись
        // покрывает байты целиком, поэтому «безобидных» мест в ней нет. Ошибка
        // при этом может прийти и от декодера — порча длины или тега ломает
        // разбор раньше, чем доходит до подписи.
        for position in 0..header_bytes.len() {
            for bit in [0x01u8, 0x80] {
                let mut broken = header_bytes.clone();
                broken[position] ^= bit;
                assert!(
                    verify_and_parse(&assemble(&broken, &signature), &EmptyTrustStore).is_err(),
                    "порча байта {position} битом {bit:#04x} прошла проверку"
                );
            }
        }
    }

    #[test]
    fn corrupting_a_single_signature_byte_breaks_verification() {
        let author = signer(1);
        let buf = self_consistent(&author);
        let header_bytes = sample_header(author.public_key()).encode().unwrap();
        let signature_at = crate::HEADER_OFFSET + header_bytes.len();

        for position in 0..SIGNATURE_LEN {
            for bit in [0x01u8, 0x80] {
                let mut broken = buf.clone();
                broken[signature_at + position] ^= bit;
                assert_eq!(
                    verify_and_parse(&broken, &EmptyTrustStore).unwrap_err(),
                    BAD_HEADER_SIGNATURE,
                    "испорченный байт подписи №{position} прошёл проверку"
                );
            }
        }
    }

    #[test]
    fn a_file_demanding_a_newer_reader_is_refused_even_with_a_valid_signature() {
        // Отказ по версии обязан пережить корректную подпись: файл использует
        // семантику, которой этот клиент не знает, и «разобралось большинство
        // полей» здесь означает применить не те правила к чужому файлу.
        let author = signer(1);
        let need = SUPPORTED_READER_VERSION + 1;
        let header = Header {
            min_reader_version: need,
            ..sample_header(author.public_key())
        };

        assert_eq!(
            verify_and_parse(
                &container(&header, &author),
                &PinnedKeys(vec![author.public_key()])
            )
            .unwrap_err(),
            FormatError::ReaderTooOld {
                need,
                have: SUPPORTED_READER_VERSION
            }
        );
    }

    #[test]
    fn a_correctly_signed_header_this_client_cannot_understand_is_still_refused() {
        // §5.2: подписать враждебный заголовок может кто угодно. Корректная
        // подпись не превращает неизвестное критичное поле в известное.
        let author = signer(1);
        let mut header_bytes = sample_header(author.public_key()).encode().unwrap();
        let mut extra = TlvWriter::new();
        extra
            .put(0x7FFE, b"semantics from a future version")
            .unwrap();
        header_bytes.extend_from_slice(&extra.finish());

        let transcript = header_signing_transcript(&header_bytes, &sample_suite()).unwrap();
        let signature = author.sign(&transcript).unwrap();

        assert_eq!(
            verify_and_parse(&assemble(&header_bytes, &signature), &EmptyTrustStore).unwrap_err(),
            FormatError::UnknownCriticalField { tag: 0x7FFE }
        );
    }

    #[test]
    fn a_signature_made_under_another_domain_label_is_refused() {
        // Без метки домена подпись автора, сделанная над записью отзыва или над
        // запросом активации, предъявлялась бы как подпись заголовка: данные те
        // же, контекст другой.
        let author = signer(1);
        let header = sample_header(author.public_key());
        let header_bytes = header.encode().unwrap();

        let mut wrong_domain = Transcript::new(label::REVOCATION);
        wrong_domain
            .u8(suite_id(&header.suite))
            .fixed(&MAGIC)
            .u32le(u32::try_from(header_bytes.len()).unwrap())
            .tail_after_declared_length(&header_bytes);
        let signature = author.sign(&wrong_domain).unwrap();

        assert_eq!(
            verify_and_parse(&assemble(&header_bytes, &signature), &EmptyTrustStore).unwrap_err(),
            BAD_HEADER_SIGNATURE
        );
    }

    #[test]
    fn the_signed_bytes_are_exactly_those_named_by_the_specification() {
        // §5: sig_input = "CC/v1/header-sig" ‖ 0x00 ‖ u8(suite_id) ‖ Magic ‖
        //                 u32le(HeaderLen) ‖ Header
        // Ровно один нулевой байт: его ставит `Transcript::new`, и добавлять
        // второй нельзя — получилась бы строка, которой нет в спецификации.
        let header_bytes = b"header bytes".as_slice();
        let suite = sample_suite();
        let transcript = header_signing_transcript(header_bytes, &suite).unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(label::HEADER_SIG.as_bytes());
        expected.push(0x00);
        expected.push(SigAlg::Ed25519 as u8);
        expected.extend_from_slice(&MAGIC);
        expected.extend_from_slice(&u32::try_from(header_bytes.len()).unwrap().to_le_bytes());
        expected.extend_from_slice(header_bytes);

        assert_eq!(transcript.as_bytes(), expected.as_slice());
    }

    #[test]
    fn the_transcript_agrees_with_the_prologues_own_encoding() {
        // Строку под подписью кодируют два независимых места. Разойдясь, они дали
        // бы файл, который наш писатель подписал, а наш читатель отверг, — и
        // причину пришлось бы искать сравнением байтов. Тест связывает их намертво.
        let author = signer(1);
        let header = sample_header(author.public_key());
        let buf = container(&header, &author);
        let prologue = Prologue::split(&buf).unwrap();

        let mut by_prologue = Vec::new();
        prologue.signing_transcript(suite_id(&header.suite), &mut by_prologue);
        let by_verify = header_signing_transcript(prologue.header, &header.suite).unwrap();

        assert_eq!(by_verify.as_bytes(), by_prologue.as_slice());
    }

    #[test]
    fn the_suite_identifier_is_the_signature_algorithm() {
        // Значение входит в подписанные байты, поэтому менять его при
        // рефакторинге нельзя: ранее выпущенные файлы перестанут проверяться.
        assert_eq!(suite_id(&sample_suite()), 1);
    }

    #[test]
    fn a_container_shorter_than_its_own_prologue_is_refused_before_any_crypto() {
        let buf = self_consistent(&signer(1));
        for cut in 0..buf.len().min(crate::HEADER_OFFSET + 8) {
            assert!(
                matches!(
                    verify_and_parse(&buf[..cut], &EmptyTrustStore).unwrap_err(),
                    FormatError::Truncated { .. }
                ),
                "обрезание до {cut} байт не дало Truncated"
            );
        }
    }

    #[test]
    fn the_fuzzing_entry_point_accepts_what_verification_refuses() {
        // Точка входа для фаззера намеренно пропускает подпись — иначе глубокие
        // ветви декодера недостижимы. Тест фиксирует, что она именно такова, и
        // заодно объясняет, почему её имя такое неудобное.
        let author = signer(1);
        let mut buf = self_consistent(&author);
        let signature_at =
            crate::HEADER_OFFSET + sample_header(author.public_key()).encode().unwrap().len();
        buf[signature_at] ^= 0xff;

        assert_eq!(
            verify_and_parse(&buf, &EmptyTrustStore).unwrap_err(),
            BAD_HEADER_SIGNATURE
        );
        assert!(parse_without_verifying_signature_for_fuzzing_only(&buf).is_ok());
    }

    #[test]
    fn never_panics_on_arbitrary_input() {
        // Разбор обязан быть тотальным: любой буфер либо даёт структуру, либо
        // ошибку. Дешёвая замена фаззеру, работающая на каждой сборке.
        let valid = self_consistent(&signer(1));

        for cut in 0..valid.len() {
            let _ = verify_and_parse(&valid[..cut], &EmptyTrustStore);
        }

        for byte in 0u16..=255 {
            let _ = verify_and_parse(&[byte as u8; 97], &EmptyTrustStore);
        }

        // С правильной магией: иначе разбор всегда отваливается на первом
        // сравнении и глубже не заходит.
        for declared in [
            0u32,
            1,
            12,
            200,
            MAX_HEADER_LEN,
            MAX_HEADER_LEN + 1,
            u32::MAX,
        ] {
            let mut buf = Vec::new();
            buf.extend_from_slice(&MAGIC);
            buf.extend_from_slice(&declared.to_le_bytes());
            buf.extend_from_slice(&[0xff; 200]);
            let _ = verify_and_parse(&buf, &EmptyTrustStore);
        }

        // Поле, объявляющее длину больше буфера, — классический вектор выделения
        // памяти по непроверенному числу.
        for len in [u32::MAX, u32::MAX / 2, 1 << 20] {
            let mut header = Vec::new();
            header.extend_from_slice(&tag::FILE_ID.to_le_bytes());
            header.extend_from_slice(&len.to_le_bytes());
            let _ = verify_and_parse(&assemble(&header, &[0x5a; SIGNATURE_LEN]), &EmptyTrustStore);
        }
    }

    /// The reader accepts exactly the readable range and rejects both adjacent values.
    ///
    /// Both boundaries, not just the upper one (§2.1 item 3). A version below the readable range is
    /// more dangerous than one above: it arouses no suspicion, "it is just an old file",
    /// although it means the same thing: semantics we do not support.
    ///
    /// FOUR IN THE REJECTION LIST IS A POSITIVE CONTROL FOR DECISION R-1,
    /// not just another round number. Zero and `MAX + 1` were rejected before the decision:
    /// testing them would also pass with the old boundary. What distinguishes the new behavior
    /// is precisely the lower neighbor: version 4, readable yesterday and permanently retired today.
    /// One appears for the same reason, but is weaker: it verifies that the lower
    /// bound moved away from [`FIRST_CONTAINER_VERSION`], retained as a historical record.
    ///
    /// Iterating the range, rather than only [`CONTAINER_VERSION`], maintains the second
    /// property this stage exists for: the reader learns a version BEFORE
    /// the writer starts producing it. Today the bounds coincide and the iteration
    /// has one step; it becomes substantive again when the reader version is bumped.
    #[test]
    fn the_reader_accepts_all_released_versions_and_refuses_the_neighbours() {
        let signer = signer(7);

        for version in MIN_READABLE_CONTAINER_VERSION..=MAX_READABLE_CONTAINER_VERSION {
            let mut header = sample_header(signer.public_key());
            header.container_version = version;
            header.min_reader_version = version;
            let bytes = container(&header, &signer);
            assert!(
                verify_and_parse(&bytes, &EmptyTrustStore).is_ok(),
                "версия {version} объявлена читаемой, но отвергнута"
            );
        }

        for version in [
            0,
            FIRST_CONTAINER_VERSION,
            MIN_READABLE_CONTAINER_VERSION - 1,
            MAX_READABLE_CONTAINER_VERSION + 1,
        ] {
            let mut header = sample_header(signer.public_key());
            header.container_version = version;
            // Требование к клиенту берётся ЧИТАЕМОЕ, иначе отказ пришёл бы из
            // проверки `min_reader_version` — и проба зеленела бы, ничего не
            // говоря о рубеже версии формата.
            header.min_reader_version = MIN_READABLE_CONTAINER_VERSION;
            let bytes = container(&header, &signer);
            assert!(
                matches!(
                    verify_and_parse(&bytes, &EmptyTrustStore),
                    Err(FormatError::UnsupportedContainerVersion { .. })
                ),
                "версия {version} вне читаемого диапазона, но принята"
            );
        }
    }

    /// The rejection names the boundary responsible for it.
    ///
    /// A separate probe, not a `matches!` in the neighboring one: "rejection occurred" and
    /// "rejection was explained correctly" are different claims; the first passes when the second
    /// is broken. If `first` still carried [`FIRST_CONTAINER_VERSION`],
    /// users would be told "readable range 1..=5" about a reader that rejects
    /// one: a falsehood presented as a diagnostic.
    #[test]
    fn the_refusal_names_the_readable_range_not_the_history() {
        let signer = signer(7);
        let mut header = sample_header(signer.public_key());
        header.container_version = MIN_READABLE_CONTAINER_VERSION - 1;
        header.min_reader_version = MIN_READABLE_CONTAINER_VERSION;
        let bytes = container(&header, &signer);

        assert_eq!(
            verify_and_parse(&bytes, &EmptyTrustStore).err(),
            Some(FormatError::UnsupportedContainerVersion {
                version: MIN_READABLE_CONTAINER_VERSION - 1,
                first: MIN_READABLE_CONTAINER_VERSION,
                max: MAX_READABLE_CONTAINER_VERSION,
            }),
            "отказ назвал не ту нижнюю границу"
        );
    }

    /// A reader requirement above our support is rejected with its own distinct error.
    ///
    /// A separate error variant keeps a FORMAT version number from being exposed
    /// in a field meaning CLIENT version: these are different spaces, and
    /// conflating them misleads the user about what to do.
    #[test]
    fn a_container_demanding_a_newer_client_is_refused_as_such() {
        let signer = signer(7);
        let mut header = sample_header(signer.public_key());
        // Версия формата берётся ЧИТАЕМАЯ: с рубежом Р-1 файл версии 1 отвергся
        // бы раньше, по диапазону, и проба перестала бы говорить о том, ради чего
        // заведена, — о том, что требование к КЛИЕНТУ даёт свой, отдельный отказ.
        header.container_version = MIN_READABLE_CONTAINER_VERSION;
        header.min_reader_version = SUPPORTED_READER_VERSION + 1;
        let bytes = container(&header, &signer);

        assert!(
            matches!(verify_and_parse(&bytes, &EmptyTrustStore), Err(FormatError::ReaderTooOld { .. })),
            "файл требует клиента новее, а отказ пришёл не тот"
        );
    }
}
