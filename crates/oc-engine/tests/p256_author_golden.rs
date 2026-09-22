//! P-256 AUTHOR-SLOT LAYOUT GOLDEN ARTIFACT (`kem_id = 2`), AT ENGINE LEVEL.
//!
//! # Why it exists
//!
//! This slot is written TODAY and BY DEFAULT on every machine where PCP supplies
//! a device key (`cc-cli/src/keys.rs`, sources `Auto` and `Hardware`), yet
//! nothing previously guarded its layout. Review
//! `docs/review/2026-09-21-p256-slot.md` found precisely this gap: all client probes
//! use `CC_DEVICE_BINDING=software`, so no test container
//! carries this slot. The ENDS are frozen (the primitive
//! `tests/kat/seal_p256.kat` and synthetic length-table probe slots),
//! but the middle, what the engine assembles from them, is not.
//!
//! The cost of blindness deserves repeating: the author slot is the only one
//! carrying BOTH shares together. If a reader stopped recognizing `kem_id = 2`, the author
//! would see "no key matched" for their own encrypted file while NOT ONE
//! probe failed. This file introduces that failure detection.
//!
//! # Why here rather than beside container artifacts
//!
//! For the same reason as neighboring `hardware_hybrid_golden.rs`: no container
//! artifact can be produced through `cc-cli`, which obtains its P-256 point only
//! from a TPM; every TPM has its own key, making "a byte-identical container on
//! another machine" cease to be meaningful
//! (`cc-cli/tests/golden.rs`, `fixed_keys`, field `device_tpm`).
//!
//! The engine neither has nor should have this limitation: pure, it accepts
//! the public point as a PARAMETER (`PublicKeys::device_tpm`), indifferent to
//! whether it came from a TPM or fixed scalar. It needs only 65
//! uncompressed-point bytes. This makes an artifact possible here and impossible
//! one layer above.
//!
//! # What is frozen
//!
//! `Assembled::header` bytes for two recipient kinds, chosen not for
//! exhaustive enumeration but because they are TODAY'S MAJORITY:
//!
//! * `p256-author.header`: a classical X25519 recipient. The ordinary path:
//!   with a nonhardware, nonhybrid recipient and an available TPM point, the engine
//!   writes an author slot with `kem_id = 2` (`oc-engine/src/lib.rs`, branch
//!   `(false, _, Some(tpm_public))`).
//! * `p256-author-none.header`: no recipient at all. Frozen because it is
//!   nearly free and covers a DIFFERENT layout: no recipient slot appears in the header,
//!   putting the author slot second rather than third. Record ordering and adjacency
//!   are as much format properties as their contents.
//!
//! Both follow one engine branch, without duplication: the branch is shared,
//! but the headers differ and can diverge independently.
//!
//! # What is NOT frozen, stated explicitly
//!
//! **No author signature here.** The engine deliberately has none (I-6): the author
//! key signs the entire header and the caller appends the signature
//! (`cc-cli/src/container.rs`, `write_all(output, &signature)` immediately after
//! the header). These frozen bytes therefore are NOT a container and do not
//! pass `verify::verify_and_parse`: `Header::decode` parses them, the same
//! `oc-format` parser without the signature boundary. The artifact freezes
//! layout, not signature presence.
//!
//! **`Assembled::content_desc` is excluded**, for the same reason as its neighbor:
//! it derives from `CEK` and `SealedInfo`, yielding identical bytes for every
//! recipient kind with the same seed; it cannot distinguish mechanism two from
//! any other.
//!
//! **`Plan::payload_key` is excluded.** Deterministic, but a KEY; secrets never
//! enter the repository in any form.
//!
//! **No live TPM here.** The scalar is software, explicitly: the artifact
//! speaks to slot LAYOUT, not actual key non-exportability.
//! The runs recorded in `CLAUDE.md` address live TPMs; this file does not.
//!
//! # Opening as well as comparing
//!
//! An artifact nobody can open freezes garbage, permanently.
//! Opening probes therefore accompany byte comparison: the author
//! slot opens using a SOFTWARE P-256 agreement party, through the same
//! `seal::open_with` and `KeyAgreement` trait the device will use
//! (`cc-cli/src/container.rs`, agreement-party iteration). The production
//! party is hardware; here it is software. Key derivation changes by
//! no bytes, since it depends on the shared secret rather than the key.
//!
//! # When version 6 is cut
//!
//! Like its neighbor, this artifact has NO witness: created for the current
//! writer, it will require the same decision as container artifacts when
//! version six is cut. This is recorded here, not performed.

// Литы отключены только здесь и только те, без которых тест нечитаем:
// `unwrap`/`expect`/`panic` — потому что провал пробы и есть паника, а
// `indexing_slicing`/`arithmetic_side_effects` — потому что срезы эталона
// режутся по заведомо известным границам, проверенным соседними `assert`.
//
// `disallowed_methods` — отдельный случай, и довод тот же, что у соседа
// (`hardware_hybrid_golden.rs`): `clippy.toml` запрещает движку `std::fs` и
// `std::env` под лозунгом «ввод-вывод живёт в cc-cli», и запрет этот про КРЕЙТ —
// пустым от машины обязан быть код, который поедет в анклав, то есть `src`.
// Эталон же по определению лежит файлом, и проба, которая его не читает, не
// проба. `include_bytes!` было бы хуже: отсутствующий эталон стал бы ошибкой
// СБОРКИ, и инструмент, которым его заводят, перестал бы собираться вместе с
// ним. Гейт чистоты это не задевает: под `wasm32-unknown-unknown` собирается
// библиотека, а не её пробы.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::disallowed_methods
)]

use std::path::PathBuf;

use oc_crypto::agreement::{KeyAgreement, P256Agreement};
use oc_crypto::seal::{self, SealedBlob, x25519_public};
use oc_crypto::secret::{SecretA, SecretB, X25519Secret};
use oc_crypto::sign::{Ed25519Signer, Signer};
use oc_crypto::{kdf, label, wrap};
use oc_engine::{META_NONCE_LEN, PackRequest, PublicKeys, Recipient, SealedInfo, meta_tag};
use oc_format::header::{Header, KeySlot, KnownSlot, P256_PUBLIC_LEN, SlotKind, Strength};
use oc_format::tlv::TlvReader;
use oc_policy::{Action, Policy};

/// Deterministic RNG. Not cryptographically strong and makes no such claim: its job is
/// to emit the same sequence on every machine.
///
/// Identical to its neighbor and the container-artifact RNG, NOT accidental
/// copy-paste: `hardware_hybrid_golden.rs` records the same argument:
/// artifacts must consume randomness IDENTICALLY, or differences
/// between their bytes mean nothing. Extracting shared `tests/common` code is
/// tempting, but would edit a file with an already frozen artifact for its neighbor's
/// convenience; duplication in probes costs less than risking another artifact's bytes.
struct SeedRng([u8; 32]);

impl SeedRng {
    fn seeded(seed: u8) -> Self {
        Self([seed; 32])
    }
}

impl rand_core::TryRng for SeedRng {
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
        // Именно `node_of`, а не `leaf_of`: у листа прообраз — величина формата,
        // и его правка меняла бы не только результат эталона, но и ВХОДЫ, то
        // есть расхождение стало бы нечитаемым.
        for out in dst.chunks_mut(32) {
            self.0 = oc_crypto::merkle::node_of(&self.0, &self.0);
            for (o, s) in out.iter_mut().zip(self.0.iter()) {
                *o = *s;
            }
        }
        Ok(())
    }
}

impl rand_core::TryCryptoRng for SeedRng {}

/// AUTHOR's P-256 scalar.
///
/// These bytes do not exist in production: the author's classical half lives in a TPM
/// without leaving. The engine is indifferent by construction: it sees 65
/// public bytes and never asks who holds the other half. This is why the
/// artifact is possible here, and precisely why it does NOT prove operation with a real
/// TPM.
///
/// Deliberately differs from `[0x5e; 32]` in `tests/kat/seal_p256.kat`:
/// if they matched, primitive divergence and assembly divergence would look
/// identical, and a failing probe could not identify which changed.
const AUTHOR_P256_SCALAR: [u8; 32] = [0x0a; 32];

/// RECIPIENT seed (X25519). Same value as container artifact
/// `recipient.cc` (`cc-cli/tests/golden.rs`, `fixed_recipient_public`): the pair
/// is identical there and here, linking two claims about one recipient.
const RECIPIENT_SEED: [u8; 32] = [0x05; 32];

/// Server sealing-key seed. Fully known to the probe, deliberately:
/// the testbed builds the artifact and plays both roles, or share A would be inaccessible.
const SERVER_SEED: [u8; 32] = [0x03; 32];

/// SOFTWARE device-key seed. Resides in `PublicKeys::device`; with a live
/// TPM point it never enters a slot. Precisely the property this artifact guards:
/// no second software-key slot is written beside the hardware slot,
/// or hardware binding would be merely a label.
const DEVICE_SOFTWARE_SEED: [u8; 32] = [0x02; 32];

/// RNG seed. Same number as its neighbor and container artifacts.
const RNG_SEED: u8 = 42;

/// What the device "measured" while processing the stream.
///
/// Values chosen manually rather than from an actual run, not a simplification: the engine
/// DOES NOT SEE the stream, accepting results as a parameter; an actual run
/// would yield precisely the same three numbers at greater cost.
fn sealed_info() -> SealedInfo {
    SealedInfo { total_len: 13_000, chunk_count: 4, tree_root: [0x3b; 32] }
}

/// Author's software agreement party. Derived by production `oc-crypto`
/// code, not stored as bytes: a hardcoded public point would become
/// a second source of truth for pair derivation and silently diverge from production.
fn author_p256() -> P256Agreement {
    P256Agreement::from_be_bytes(&AUTHOR_P256_SCALAR)
        .expect("фиксированный скаляр обязан быть годной стороной P-256")
}

fn recipient_secret() -> X25519Secret {
    X25519Secret::from_bytes(RECIPIENT_SEED)
}

fn request(recipient: Recipient) -> PackRequest<'static> {
    PackRequest {
        original_name: "отчёт.docx",
        policy: Policy::deny_all().allow(Action::View).allow(Action::Print),
        chunk_size: 4096,
        org_id: b"acme".to_vec(),
        authority_urls: vec!["https://cc.example/api".to_string()],
        recipient,
        coauthors: None,
    }
}

/// Classical recipient: the ordinary path where a TPM-backed author receives a
/// `kem_id = 2` slot.
fn recipient_identity() -> Recipient {
    Recipient::Identity { public_key: x25519_public(&recipient_secret()) }
}

/// Assemble a header with the engine. No I/O, no clocks, a seeded
/// RNG: everything needed for byte-for-byte reproducibility.
fn build_header(recipient: Recipient) -> Vec<u8> {
    let author_tpm = author_p256();
    let tpm_public = author_tpm.public_key();
    // Сверка здесь, а не только в пробе открытия: если сторона вдруг начнёт
    // отдавать сжатую точку, заголовок собрался бы иначе, а проба байтов
    // сообщила бы об этом как о безымянном расхождении на каком-то байте.
    assert_eq!(
        tpm_public.len(),
        P256_PUBLIC_LEN,
        "сторона P-256 отдала точку не в несжатой форме"
    );

    let request = request(recipient);
    let mut rng = SeedRng::seeded(RNG_SEED);
    let (session, _plan) = oc_engine::plan(&request, &mut rng);

    let keys = PublicKeys {
        author: Ed25519Signer::from_seed(&[0x01; 32]).public_key(),
        authority_sealing: x25519_public(&X25519Secret::from_bytes(SERVER_SEED)),
        authority_lease_verify: Ed25519Signer::from_seed(&[0x04; 32]).public_key(),
        device: x25519_public(&X25519Secret::from_bytes(DEVICE_SOFTWARE_SEED)),
        // Ни аппаратного гибрида, ни X-Wing: обе эти ветки СТАРШЕ ветки P-256, и
        // эталон обязан ходить именно по ней, а не по соседней.
        device_hardware_hybrid: None,
        device_hybrid: None,
        device_tpm: Some(tpm_public.as_slice()),
    };

    session
        .assemble(&request, &keys, sealed_info(), &mut rng)
        .expect("сборка заголовка с авторским слотом P-256 обязана проходить")
        .header
}

fn golden_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/golden/engine")
        .join(name)
}

const GOLDEN_WITH_RECIPIENT: &str = "p256-author.header";
const GOLDEN_WITHOUT_RECIPIENT: &str = "p256-author-none.header";

fn slot_of(header: &Header, kind: SlotKind) -> KnownSlot {
    header
        .key_slots
        .iter()
        .find_map(|slot| match slot {
            KeySlot::Known(known) if known.kind == kind => Some(known.clone()),
            _ => None,
        })
        .unwrap_or_else(|| {
            panic!(
                "\nСЛОТ {kind:?} НЕ ПРОЧИТАН ИЗ ЗАМОРОЖЕННОГО ЗАГОЛОВКА.\n\
                 Разбор прошёл, но слота такого рода среди РАЗОБРАННЫХ нет — значит\n\
                 читатель перестал признавать его механизм и отнёс запись к\n\
                 незнакомым (`KeySlot::Unknown`).\n\n\
                 Для слота автора это не мелочь: он единственный несёт ОБЕ доли\n\
                 сразу, и перестав его читать, продукт отвечает «ни один ключ не\n\
                 подошёл» на файле, который человек зашифровал сам. Проверь таблицы\n\
                 длин `expected_enc_len` / `expected_key_fpr_len` в\n\
                 oc-format/src/header.rs.\n"
            )
        })
}

fn blob_of(slot: &KnownSlot) -> SealedBlob {
    SealedBlob { enc: slot.enc.clone(), nonce: slot.nonce, ct: slot.ct.clone() }
}

fn read_golden(name: &str) -> Vec<u8> {
    let path = golden_path(name);
    std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "{}: {e}\nЭталон движка обязан лежать в репозитории. Создать его заново:\n  \
             CC_WRITE_NEW_GOLDEN=engine-p256-author cargo test -p oc-engine \
             --test p256_author_golden -- --ignored --nocapture",
            path.display()
        )
    })
}

fn compare(name: &str, produced: &[u8]) {
    let expected = read_golden(name);
    assert_eq!(
        produced.len(),
        expected.len(),
        "\n{name}: ДЛИНА ЗАГОЛОВКА ИЗМЕНИЛАСЬ: {} против {} байт.\n\
         Это изменение раскладки формата.\n",
        produced.len(),
        expected.len()
    );
    if produced != expected {
        let at = produced
            .iter()
            .zip(expected.iter())
            .position(|(a, b)| a != b)
            .unwrap_or(0);
        panic!(
            "\n{name}: ЭТАЛОН ДВИЖКА НЕ СОШЁЛСЯ, первое расхождение на байте {at}.\n\
             Получено 0x{:02x}, ожидалось 0x{:02x}.\n\n\
             Это изменение БАЙТОВ авторского слота P-256 — того самого, который\n\
             писатель печатает на каждой машине с TPM. Перевыпустить файл можно\n\
             ТОЛЬКО вместе с решением в docs/format.md и подъёмом версии формата\n\
             (И-14).\n",
            produced[at], expected[at]
        );
    }
}

/// A HEADER WITH A `kem_id = 2` AUTHOR SLOT MATCHES THE FROZEN BYTES EXACTLY.
///
/// Compares a freshly assembled header with a FILE, not with itself: this tests
/// determinism across PROCESSES, which cannot be faked inside
/// one run.
#[test]
fn the_p256_author_headers_are_byte_identical_to_the_frozen_goldens() {
    compare(GOLDEN_WITH_RECIPIENT, &build_header(recipient_identity()));
    compare(GOLDEN_WITHOUT_RECIPIENT, &build_header(Recipient::None));
}

/// TWO ASSEMBLY RUNS PRODUCE IDENTICAL BYTES.
///
/// Separate from file comparison, without duplication. File comparison does not explain
/// divergence: "mismatch" can mean either "layout shifted" or
/// "assembly is nondeterministic". This checks the latter,
/// cheaply, within one run, without a file.
#[test]
fn the_p256_author_header_is_the_same_bytes_twice() {
    assert_eq!(
        build_header(recipient_identity()),
        build_header(recipient_identity()),
        "сборка заголовка с авторским слотом P-256 недетерминирована"
    );
    assert_eq!(
        build_header(Recipient::None),
        build_header(Recipient::None),
        "сборка заголовка без получателя недетерминирована"
    );
}

/// Parse the artifact and confirm its author slot uses EXACTLY the expected mechanism
/// and shape. Shared part of both opening probes.
///
/// Lengths use `P256_PUBLIC_LEN` from `oc-format`, not the number 65:
/// a number in the probe would become a second layout authority and silently diverge.
fn parsed_author_slot(bytes: &[u8]) -> (oc_format::header::ParsedHeader, KnownSlot) {
    let parsed = Header::decode(bytes).expect("эталон обязан разбираться разборщиком oc-format");
    let slot = slot_of(&parsed.header, SlotKind::AuthorDevice);
    assert_eq!(
        slot.kem,
        oc_crypto::KemAlg::P256HkdfSha256,
        "авторский слот эталона объявлен не механизмом P-256"
    );
    assert_eq!(
        slot.enc.len(),
        P256_PUBLIC_LEN,
        "эфемерная точка в авторском слоте не той длины"
    );
    assert_eq!(
        slot.key_fpr.as_deref().map(<[u8]>::len),
        Some(P256_PUBLIC_LEN),
        "открытая точка автора в слоте не той длины"
    );
    // Слот назван той точкой, на которую запечатан. Сверка не косметическая:
    // `key_fpr` входит в подписанные байты именно затем, чтобы подмена ключа
    // была видна.
    assert_eq!(
        slot.key_fpr.as_deref(),
        Some(author_p256().public_key().as_slice()),
        "авторский слот называет не ту точку P-256"
    );
    // Читательская классификация — тоже свойство раскладки, и сказать её надо
    // вслух: аппаратная привязка НЕ делает файл постквантовым. Слот с ключом в
    // TPM остаётся классическим по стойкости, и продукт это знает.
    assert_eq!(
        parsed.header.file_strength(),
        Strength::Classical,
        "читатель классифицировал файл с авторским слотом P-256 не как классический"
    );
    (parsed, slot)
}

/// Open the author slot through to private-metadata PLAINTEXT.
///
/// Returns `CEK` for the caller to compare against the second path.
fn open_author_path(bytes: &[u8]) -> oc_crypto::secret::Cek {
    let (parsed, slot) = parsed_author_slot(bytes);
    let header = &parsed.header;
    let core_hash = Header::core_hash(bytes, &parsed.spans).unwrap();
    let policy_hash = Header::policy_hash(bytes, &parsed.spans).unwrap();

    // Тем же `open_with` и тем же трейтом, каким слот откроет устройство:
    // в поставке сторона аппаратная (TPM), здесь программная, а вывод ключа
    // одинаков — он считается по общему секрету, а не по ключу.
    let info = seal::slot_info(
        label::SLOT_AUTHOR_DEVICE,
        oc_crypto::KemAlg::P256HkdfSha256,
        &header.file_id,
    );
    let both = seal::open_with(&author_p256(), &blob_of(&slot), &info, &policy_hash)
        .expect("авторский слот обязан открываться стороной согласования P-256 автора");
    assert_eq!(both.len(), 64, "в авторском слоте лежит не пара долей");

    let a = SecretA::from_bytes(<[u8; 32]>::try_from(&both[0..32]).unwrap());
    let b = SecretB::from_bytes(<[u8; 32]>::try_from(&both[32..64]).unwrap());
    // `unwrap_cek` сверяет обязательство слота константным временем ДО открытия
    // AEAD (И-4) — то есть этот вызов проверяет не только ключ, но и рубеж.
    let kek = kdf::derive_kek(&header.file_id, &header.org_id, &a, &b);
    let cek = wrap::unwrap_cek(&kek, &header.wrapped_cek, &slot.commitment, &core_hash)
        .expect("авторский слот обязан разворачивать ключ содержимого эталона");

    // От ключа до открытого текста: приватные метаданные заголовка. Остановка на
    // `CEK` доказала бы, что сошлись доли, и промолчала бы о том, сходится ли с
    // ними зашифрованное. Дальше метаданных пути нет: содержимого файла движок не
    // видит, и это сказано прямо, а не скрыто за словом «полностью».
    let meta_key = kdf::derive_private_meta_key(&cek, &header.header_salt, &header.file_id);
    assert!(
        header.private_meta.len() > META_NONCE_LEN,
        "приватные метаданные короче собственного nonce"
    );
    let nonce: [u8; META_NONCE_LEN] = header.private_meta[..META_NONCE_LEN].try_into().unwrap();
    let plain = oc_crypto::aead::open_metadata(
        &meta_key,
        &header.file_id,
        &nonce,
        &header.private_meta[META_NONCE_LEN..],
    )
    .expect("приватные метаданные обязаны открываться ключом, собранным из долей автора");

    let mut reader = TlvReader::new(&plain);
    let mut name = None;
    let mut size = None;
    while let Some(field) = reader.next_field().expect("метаданные эталона обязаны разбираться") {
        match field.tag {
            meta_tag::NAME => name = Some(field.value.to_vec()),
            meta_tag::SIZE => size = Some(field.u64().unwrap()),
            _ => {}
        }
    }
    assert_eq!(name.as_deref(), Some("отчёт.docx".as_bytes()), "имя в метаданных не то");
    assert_eq!(size, Some(sealed_info().total_len), "размер в метаданных не тот");

    cek
}

/// THE P-256 AUTHOR SLOT OPENS; THE SECOND PATH REACHES THE SAME KEY.
///
/// A positive control without which byte comparison is blind: it proves
/// byte stability while saying nothing about usability. This checks the converse:
/// the frozen artifact is usable by BOTH paths.
///
/// Author path: both shares from one slot, no server required. Recipient
/// path: share B from its slot, share A from the server slot. Divergence would
/// make the file's two DIFFERENT opening paths reach different keys,
/// so "2 of 2" would cease to be that scheme.
#[test]
fn the_frozen_p256_author_slot_opens_and_agrees_with_the_recipient_path() {
    let bytes = read_golden(GOLDEN_WITH_RECIPIENT);
    let cek_author = open_author_path(&bytes);

    let parsed = Header::decode(&bytes).expect("эталон обязан разбираться");
    let header = &parsed.header;
    let core_hash = Header::core_hash(&bytes, &parsed.spans).unwrap();
    let policy_hash = Header::policy_hash(&bytes, &parsed.spans).unwrap();

    let recipient_slot = slot_of(header, SlotKind::RecipientIdentity);
    assert_eq!(
        recipient_slot.kem,
        oc_crypto::KemAlg::X25519HkdfSha256,
        "слот получателя эталона не классический — эталон собран не по той ветке"
    );
    let info = seal::slot_info(label::SLOT_RECIPIENT, seal::DEFAULT_SEALING_KEM, &header.file_id);
    let share_b = seal::open(&recipient_secret(), &blob_of(&recipient_slot), &info, &policy_hash)
        .expect("слот получателя эталона обязан открываться его ключом");
    assert_eq!(share_b.len(), 32, "в слоте получателя лежит не одна доля");
    let b = SecretB::from_bytes(<[u8; 32]>::try_from(&share_b[..]).unwrap());

    let server_slot = slot_of(header, SlotKind::Server);
    let info = seal::slot_info(label::SLOT_SERVER, seal::DEFAULT_SEALING_KEM, &header.file_id);
    let share_a = seal::open(
        &X25519Secret::from_bytes(SERVER_SEED),
        &blob_of(&server_slot),
        &info,
        &policy_hash,
    )
    .expect("слот сервера эталона обязан открываться ключом сервера");
    let a = SecretA::from_bytes(<[u8; 32]>::try_from(&share_a[..]).unwrap());

    let cek_recipient = wrap::unwrap_cek(
        &kdf::derive_kek(&header.file_id, &header.org_id, &a, &b),
        &header.wrapped_cek,
        &recipient_slot.commitment,
        &core_hash,
    )
    .expect("две доли обязаны разворачивать ключ содержимого эталона");

    assert_eq!(
        cek_author.expose(),
        cek_recipient.expose(),
        "путь автора и путь получателя дали разные ключи содержимого"
    );
}

/// WITH NO RECIPIENT, THE AUTHOR SLOT REMAINS THE ONLY PATH, AND IT WORKS.
///
/// There is no second path by construction, precisely why this probe is
/// separate: losing the author slot on such a file means losing the file
/// forever, without "at least the recipient can open it".
#[test]
fn the_frozen_recipientless_p256_author_slot_is_the_only_way_in_and_it_opens() {
    let bytes = read_golden(GOLDEN_WITHOUT_RECIPIENT);
    let parsed = Header::decode(&bytes).expect("эталон обязан разбираться");
    let recipient_slots = parsed
        .header
        .key_slots
        .iter()
        .filter(|slot| {
            matches!(slot, KeySlot::Known(known) if known.kind == SlotKind::RecipientIdentity)
        })
        .count();
    assert_eq!(recipient_slots, 0, "в эталоне без получателя нашёлся слот получателя");

    open_author_path(&bytes);
}

/// Add engine golden artifacts ONCE. Never overwrite existing files.
///
/// Same technique as its neighbor, for the same reason: reissuance and ADDITION
/// are different actions; I-14 forbids the former and permits the latter. A tool
/// that only adds cannot perform the forbidden action even by mistake. `#[ignore]`
/// alone is insufficient: it does not protect against
/// `cargo test --workspace -- --ignored`, so an environment variable is required
/// too, followed by refusal to write existing files.
#[test]
#[ignore = "инструмент добавления нового эталона, а не проверка"]
fn write_the_p256_author_engine_goldens_once() {
    if std::env::var("CC_WRITE_NEW_GOLDEN").as_deref() != Ok("engine-p256-author") {
        println!("эталоны движка НЕ записаны: CC_WRITE_NEW_GOLDEN=engine-p256-author не задана");
        return;
    }
    for (name, recipient) in
        [(GOLDEN_WITH_RECIPIENT, recipient_identity()), (GOLDEN_WITHOUT_RECIPIENT, Recipient::None)]
    {
        let path = golden_path(name);
        assert!(!path.exists(), "{} уже есть: эталоны не перезаписываются (И-14)", path.display());
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).unwrap();
        }
        let bytes = build_header(recipient);
        std::fs::write(&path, &bytes).unwrap();
        println!("записано {} байт в {}", bytes.len(), path.display());
    }
}
