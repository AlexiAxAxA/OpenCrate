// SPDX-License-Identifier: MPL-2.0
//! Frozen engine header with MLKEM768-P256 slots (`kem_id = 5`).
//!
//! Fixed software key material makes the layout reproducible without a live TPM.
//! The artifact covers the complete assembled header, including server, recipient,
//! and author slot order, 1153-byte encapsulations, and 1249-byte public keys.
//!
//! It is not a signed container and does not cover TPM isolation, the content
//! descriptor, or payload keys. Companion tests open both hybrid slots and reach
//! the private metadata. Changing the artifact requires a format decision;
//! its version-6 witness has not been created.

// Литы отключены только здесь и только те, без которых тест нечитаем:
// `unwrap`/`expect`/`panic` — потому что провал пробы и есть паника, а
// `indexing_slicing`/`arithmetic_side_effects` — потому что срезы эталона
// режутся по заведомо известным границам, проверенным соседними `assert`.
//
// `disallowed_methods` — отдельный случай, и он требует не отговорки, а довода.
// `clippy.toml` запрещает движку `std::fs` и `std::env` под лозунгом «ввод-вывод
// живёт в cc-cli», и запрет этот про КРЕЙТ: пустой от машины обязан быть тот
// код, который поедет в анклав, то есть `src`. Эталон же по определению лежит
// файлом, и проба, которая его не читает, не проба. Читать через `include_bytes!`
// было бы соблазнительно и хуже: отсутствующий эталон стал бы ошибкой СБОРКИ, и
// инструмент, которым его заводят, перестал бы собираться вместе с ним. То же
// послабление и по той же причине стоит у контейнерных эталонов
// (`cc-cli/tests/golden.rs`). Гейт чистоты это не задевает: под
// `wasm32-unknown-unknown` собирается библиотека, а не её пробы.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::disallowed_methods
)]

use std::path::PathBuf;

use oc_crypto::seal::{self, SealedBlob, x25519_public};
use oc_crypto::secret::{SecretA, SecretB, X25519Secret};
use oc_crypto::sign::{Ed25519Signer, Signer};
use oc_crypto::{kdf, label, mlkem_p256, wrap};
use oc_engine::{META_NONCE_LEN, PackRequest, PublicKeys, Recipient, SealedInfo, meta_tag};
use oc_format::header::{Header, KeySlot, KnownSlot, SlotKind, Strength};
use oc_format::tlv::TlvReader;
use oc_policy::{Action, Policy};

/// Deterministic RNG. Not cryptographically strong and makes no such claim: its job is
/// to emit the same sequence on every machine.
///
/// Identical to the container-artifact RNG (`cc-cli/tests/golden.rs`),
/// not accidental copy-paste: two artifacts must consume randomness
/// IDENTICALLY, or differences between their bytes would mean nothing.
/// Hashing uses `oc-crypto` rather than blake3 directly: the engine has no direct
/// blake3 dependency, and adding one for a test RNG would expand
/// the graph for a probe.
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

/// RECIPIENT seed. Same value as the rejection probe in `cc-cli`: the pair is
/// identical there and here, linking two claims about one mechanism.
const RECIPIENT_SEED: [u8; 32] = [0x08; 32];

/// Seed of the author's HARDWARE half.
///
/// These bytes do not exist in production: the author's classical half lives inside a TPM
/// without leaving; `keypair_from_seed` exists "only for vectors and
/// the software path", as its own documentation states. The engine is
/// indifferent by construction: it sees 1249 public bytes and does not ask who
/// holds the other half. This is why the artifact is possible here, and why
/// it does NOT prove real-TPM operation; that is addressed by the
/// 2026-09-15 run recorded in `CLAUDE.md`.
const AUTHOR_HYBRID_SEED: [u8; 32] = [0x09; 32];

/// Server sealing-key seed. Fully known to the probe, deliberately:
/// the testbed built this artifact and plays both roles, or share A would be inaccessible
/// and nothing could open it.
const SERVER_SEED: [u8; 32] = [0x03; 32];

/// RNG seed. Same number as the container artifacts.
const RNG_SEED: u8 = 42;

/// What the device "measured" while processing the stream.
///
/// Values chosen manually rather than from an actual run, not a simplification:
/// the engine DOES NOT SEE the stream, accepting its result as a parameter; an actual
/// run would give the same three numbers at greater cost. They matter only
/// because they enter the header and private metadata, both locations
/// checked by the artifact.
fn sealed_info() -> SealedInfo {
    SealedInfo { total_len: 13_000, chunk_count: 4, tree_root: [0x3b; 32] }
}

fn recipient_pair() -> mlkem_p256::Keypair {
    mlkem_p256::keypair_from_seed(&RECIPIENT_SEED)
        .expect("программная пара пятого механизма выводится из фиксированного семени")
}

fn author_pair() -> mlkem_p256::Keypair {
    mlkem_p256::keypair_from_seed(&AUTHOR_HYBRID_SEED)
        .expect("программная пара пятого механизма выводится из фиксированного семени")
}

fn request(public_key: Box<[u8; mlkem_p256::PUBLIC_KEY_LEN]>) -> PackRequest<'static> {
    PackRequest {
        original_name: "отчёт.docx",
        policy: Policy::deny_all().allow(Action::View).allow(Action::Print),
        chunk_size: 4096,
        org_id: b"acme".to_vec(),
        authority_urls: vec!["https://cc.example/api".to_string()],
        recipient: Recipient::HardwareHybrid { public_key },
        coauthors: None,
    }
}

/// Assemble a header with the engine. No I/O, no clocks, a seeded
/// RNG: everything needed for byte-for-byte reproducibility.
fn build_header() -> Vec<u8> {
    let recipient = recipient_pair();
    let author = author_pair();
    let request = request(Box::new(recipient.public_key));

    let mut rng = SeedRng::seeded(RNG_SEED);
    let (session, _plan) = oc_engine::plan(&request, &mut rng);

    let keys = PublicKeys {
        author: Ed25519Signer::from_seed(&[0x01; 32]).public_key(),
        authority_sealing: x25519_public(&X25519Secret::from_bytes(SERVER_SEED)),
        authority_lease_verify: Ed25519Signer::from_seed(&[0x04; 32]).public_key(),
        device: x25519_public(&X25519Secret::from_bytes([0x02; 32])),
        // Пятый механизм у получателя — значит и авторский слот пятого
        // механизма. Без этой половины движок обязан отказать, и отказывает:
        // `EngineError::MissingAuthorHybridKey`.
        device_hardware_hybrid: Some(author.public_key.as_slice()),
        // Ни X-Wing, ни TPM-точки: ветка аппаратного гибрида старше обеих, и
        // эталон обязан ходить именно по ней, а не по соседней.
        device_hybrid: None,
        device_tpm: None,
    };

    session
        .assemble(&request, &keys, sealed_info(), &mut rng)
        .expect("сборка заголовка на пятом механизме обязана проходить")
        .header
}

fn golden_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/golden/engine")
        .join("hardware-hybrid.header")
}

fn slot_of(header: &Header, kind: SlotKind) -> KnownSlot {
    header
        .key_slots
        .iter()
        .find_map(|slot| match slot {
            KeySlot::Known(known) if known.kind == kind => Some(known.clone()),
            _ => None,
        })
        .unwrap_or_else(|| panic!("слот {kind:?} отсутствует"))
}

fn blob_of(slot: &KnownSlot) -> SealedBlob {
    SealedBlob { enc: slot.enc.clone(), nonce: slot.nonce, ct: slot.ct.clone() }
}

/// A HEADER WITH TWO `kem_id = 5` SLOTS MATCHES THE FROZEN BYTES EXACTLY.
///
/// Compares a freshly assembled header with a file, not with itself: this is
/// determinism across PROCESSES, which cannot be faked inside
/// one run.
#[test]
fn the_hardware_hybrid_header_is_byte_identical_to_the_frozen_golden() {
    let produced = build_header();
    let path = golden_path();

    let expected = std::fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "{}: {e}\nЭталон движка обязан лежать в репозитории. Создать его заново:\n  \
             CC_WRITE_NEW_GOLDEN=engine-hardware-hybrid cargo test -p oc-engine \
             --test hardware_hybrid_golden -- --ignored --nocapture",
            path.display()
        )
    });

    assert_eq!(
        produced.len(),
        expected.len(),
        "\nДЛИНА ЗАГОЛОВКА ИЗМЕНИЛАСЬ: {} против {} байт.\n\
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
            "\nЭТАЛОН ДВИЖКА НЕ СОШЁЛСЯ, первое расхождение на байте {at}.\n\
             Получено 0x{:02x}, ожидалось 0x{:02x}.\n\n\
             Это изменение БАЙТОВ формата на единственном механизме, ради\n\
             которого нарезана версия 5. Перевыпустить файл можно ТОЛЬКО вместе\n\
             с решением в docs/format.md и подъёмом версии формата (И-14).\n",
            produced[at], expected[at]
        );
    }
}

/// BOTH GOLDEN HYBRID SLOTS OPEN WITH THEIR OWNERS' HALVES.
///
/// A positive control without which byte comparison is blind: it proves
/// byte stability while saying nothing about usability. This checks the converse:
/// the frozen artifact is usable by BOTH paths, author and recipient.
///
/// The recipient path is exactly the device path: `open_mlkem_p256` using both
/// halves, share A from the server slot, `derive_kek`, `unwrap_cek`, also checking
/// the slot commitment (I-4: `unwrap_cek` compares it in constant
/// time BEFORE opening AEAD). The author path differs because its slot carries
/// BOTH shares together and needs no server.
///
/// Continues through private-metadata PLAINTEXT rather than stopping at `CEK`:
/// stopping at the key would prove shares agree, but not that the data encrypted
/// with that key agrees. No file contents here, since the engine does not see
/// the stream, so the path ends at private metadata; this limit is stated
/// explicitly rather than hidden behind "fully".
#[test]
fn both_hardware_hybrid_slots_open_for_their_owners() {
    let bytes = std::fs::read(golden_path()).expect("эталон движка обязан лежать в репозитории");
    let parsed = Header::decode(&bytes).expect("эталон обязан разбираться разборщиком oc-format");
    let header = &parsed.header;
    let core_hash = Header::core_hash(&bytes, &parsed.spans).unwrap();
    let policy_hash = Header::policy_hash(&bytes, &parsed.spans).unwrap();

    // Сначала — что эталон действительно на ПЯТОМ механизме. Без этой сверки
    // проба прошла бы и на классическом заголовке, то есть не проверяла бы
    // того, ради чего заведена.
    let recipient_slot = slot_of(header, SlotKind::RecipientIdentity);
    let author_slot = slot_of(header, SlotKind::AuthorDevice);
    for (name, slot) in [("получателя", &recipient_slot), ("автора", &author_slot)] {
        assert_eq!(
            slot.kem,
            oc_crypto::KemAlg::MlKem768P256,
            "слот {name} объявлен не аппаратным гибридом"
        );
        // Длины — через константы механизма, а не числами: число в пробе стало
        // бы вторым источником истины о раскладке и разошлось бы молча.
        assert_eq!(
            slot.enc.len(),
            mlkem_p256::CIPHERTEXT_LEN,
            "шифротекст KEM в слоте {name} не той длины"
        );
        assert_eq!(
            slot.key_fpr.as_deref().map(<[u8]>::len),
            Some(mlkem_p256::PUBLIC_KEY_LEN),
            "открытая половина в слоте {name} не той длины"
        );
    }
    // Читательская классификация файла — тоже свойство раскладки, и держать её
    // отдельно дешевле, чем узнать о расхождении на чужой машине.
    assert_eq!(
        header.file_strength(),
        Strength::PostQuantumHardware,
        "читатель не считает эталон аппаратно-постквантовым"
    );

    // Слоты названы теми ключами, на которые запечатаны. Сверка не косметическая:
    // `key_fpr` входит в подписанные байты именно затем, чтобы сервер не мог
    // подменить ключ получателя своим.
    let recipient = recipient_pair();
    let author = author_pair();
    assert_eq!(
        recipient_slot.key_fpr.as_deref(),
        Some(recipient.public_key.as_slice()),
        "слот получателя называет не тот ключ"
    );
    assert_eq!(
        author_slot.key_fpr.as_deref(),
        Some(author.public_key.as_slice()),
        "слот автора называет не тот ключ"
    );

    // --- Путь ПОЛУЧАТЕЛЯ: доля B из своего слота, доля A из слота сервера.
    let info = seal::slot_info(
        label::SLOT_RECIPIENT,
        oc_crypto::KemAlg::MlKem768P256,
        &header.file_id,
    );
    let share_b = seal::open_mlkem_p256(
        &recipient.ml_kem_seed,
        &recipient.classical,
        &blob_of(&recipient_slot),
        &info,
        &policy_hash,
    )
    .expect("слот получателя обязан открываться обеими половинами его пары");
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

    let kek = kdf::derive_kek(&header.file_id, &header.org_id, &a, &b);
    let cek_recipient =
        wrap::unwrap_cek(&kek, &header.wrapped_cek, &recipient_slot.commitment, &core_hash)
            .expect("две доли обязаны разворачивать ключ содержимого эталона");

    // --- Путь АВТОРА: обе доли разом из одного слота, сервер не нужен.
    let info = seal::slot_info(
        label::SLOT_AUTHOR_DEVICE,
        oc_crypto::KemAlg::MlKem768P256,
        &header.file_id,
    );
    let both = seal::open_mlkem_p256(
        &author.ml_kem_seed,
        &author.classical,
        &blob_of(&author_slot),
        &info,
        &policy_hash,
    )
    .expect("слот автора обязан открываться аппаратной парой автора");
    assert_eq!(both.len(), 64, "в слоте автора лежит не пара долей");
    // Доля B из авторского слота обязана совпасть с долей из слота получателя:
    // разойдись они — файл открывался бы двумя РАЗНЫМИ путями к разным ключам,
    // и схема «2 из 2» перестала бы ею быть.
    assert_eq!(&both[32..64], share_b.as_slice(), "доли B у автора и получателя разошлись");
    let author_a = SecretA::from_bytes(<[u8; 32]>::try_from(&both[0..32]).unwrap());
    let author_b = SecretB::from_bytes(<[u8; 32]>::try_from(&both[32..64]).unwrap());
    let author_kek =
        kdf::derive_kek(&header.file_id, &header.org_id, &author_a, &author_b);
    let cek_author =
        wrap::unwrap_cek(&author_kek, &header.wrapped_cek, &author_slot.commitment, &core_hash)
            .expect("авторский слот обязан разворачивать ключ содержимого эталона");
    assert_eq!(
        cek_author.expose(),
        cek_recipient.expose(),
        "два пути дали разные ключи содержимого"
    );

    // --- От ключа до открытого текста: приватные метаданные заголовка.
    let meta_key =
        kdf::derive_private_meta_key(&cek_recipient, &header.header_salt, &header.file_id);
    assert!(
        header.private_meta.len() > META_NONCE_LEN,
        "приватные метаданные короче собственного nonce"
    );
    let nonce: [u8; META_NONCE_LEN] =
        header.private_meta[..META_NONCE_LEN].try_into().unwrap();
    let plain = oc_crypto::aead::open_metadata(
        &meta_key,
        &header.file_id,
        &nonce,
        &header.private_meta[META_NONCE_LEN..],
    )
    .expect("приватные метаданные обязаны открываться ключом, собранным из долей");

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
}

/// Add the engine golden artifact ONCE. Never overwrite an existing file.
///
/// Same technique as `write_the_hybrid_golden_once` in `cc-cli`, for the same
/// reason: reissuance and ADDITION are different actions; I-14 forbids the former and
/// permits the latter. An append-only tool cannot perform the
/// forbidden action even by mistake. `#[ignore]` alone is insufficient: it does not
/// protect against `cargo test --workspace -- --ignored`, so an environment
/// variable is required too, followed by refusal to write an existing file.
#[test]
#[ignore = "инструмент добавления нового эталона, а не проверка"]
fn write_the_hardware_hybrid_engine_golden_once() {
    if std::env::var("CC_WRITE_NEW_GOLDEN").as_deref() != Ok("engine-hardware-hybrid") {
        println!(
            "эталон движка НЕ записан: CC_WRITE_NEW_GOLDEN=engine-hardware-hybrid не задана"
        );
        return;
    }
    let path = golden_path();
    assert!(
        !path.exists(),
        "{} уже есть: эталоны не перезаписываются (И-14)",
        path.display()
    );
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).unwrap();
    }
    let bytes = build_header();
    std::fs::write(&path, &bytes).unwrap();
    println!("записано {} байт в {}", bytes.len(), path.display());
}
