//! ЭТАЛОН РАСКЛАДКИ СЛОТОВ АППАРАТНОГО ГИБРИДА (`kem_id = 5`) — НА УРОВНЕ ДВИЖКА.
//!
//! # Почему здесь, а не рядом с контейнерными эталонами
//!
//! Версия 5 формата нарезана ради ОДНОГО механизма — MLKEM768-P256, — и его
//! раскладка в файле не была закреплена ничем. Контейнерного эталона через
//! `cc-cli` не бывает в принципе, и причина записана у пробы
//! `a_hardware_hybrid_golden_is_not_producible_by_this_writer`
//! (`crates/cc-cli/tests/golden.rs`): слот АВТОРА при пятом механизме обязан
//! быть тем же механизмом, а открытую точку P-256 автора писатель берёт только
//! из TPM. У каждого TPM свой ключ, и «побайтово тот же контейнер на другой
//! машине» перестаёт существовать как понятие.
//!
//! Движок этого ограничения не имеет и иметь не должен: он чист и принимает
//! открытые ключи ПАРАМЕТРОМ (`PublicKeys::device_hardware_hybrid`), поэтому ему
//! всё равно, откуда пришла точка — из TPM или из фиксированного скаляра. Ровно
//! это и делает эталон возможным здесь и невозможным этажом выше.
//!
//! # Что заморожено
//!
//! Байты `Assembled::header` — заголовок целиком, готовый к записи, со слотами
//! сервера, получателя и автора. Это и есть то, ради чего проба заведена: обе
//! гибридные записи (1153 байта `enc`, 1249 байт `key_fpr`, nonce, шифротекст,
//! обязательство), их ПОРЯДОК и место среди прочих полей заголовка.
//!
//! # Что НЕ заморожено, и это честно сказать вслух
//!
//! **Подписи автора здесь нет.** В движке её нет намеренно (И-6): она ставится
//! ключом автора, покрывает заголовок целиком и приписывается вызывающим
//! (`cc-cli/src/container.rs`, `write_all(output, &signature)` сразу за
//! заголовком). Поэтому замороженные байты НЕ являются контейнером и не
//! проходят `verify::verify_and_parse` — разбирает их `Header::decode`, то есть
//! тот же разборщик `oc-format`, но без рубежа подписи. Эталон замораживает
//! раскладку, а не подписанность.
//!
//! **`Assembled::content_desc` не включён.** Он тоже байтовый и тоже
//! детерминированный, но к слотам отношения не имеет вовсе: он выводится из
//! `CEK` и `SealedInfo` и при любом виде получателя на том же семени генератора
//! получается один и тот же. Заморозив его здесь, мы получили бы артефакт,
//! который не отличает пятый механизм ни от какого другого, — то есть обещал бы
//! покрытие шире фактического.
//!
//! **`Plan::payload_key` не включён.** Он детерминирован, но это КЛЮЧ; секреты в
//! репозиторий не кладутся ни под каким видом.
//!
//! # Открывается, а не только сверяется
//!
//! Эталон, который никто не может открыть, замораживает мусор — и замораживает
//! навсегда. Поэтому рядом со сверкой байтов стоит
//! [`both_hardware_hybrid_slots_open_for_their_owners`]: оба слота открываются
//! программными половинами тем же кодом, каким их откроет устройство, и путь
//! доведён до открытого текста приватных метаданных.
//!
//! # Когда будет резаться версия 6
//!
//! У контейнерных эталонов есть свидетель `tests/golden/v5/`, снятый ДО
//! переключения писателя. У этого артефакта свидетеля НЕТ: он заведён под
//! текущего писателя и в день нарезки шестой версии потребует того же решения,
//! что и соседи. Здесь это записано, а не сделано: заводить каталог свидетеля,
//! в который сегодня нечего положить, кроме копии соседнего файла, значит
//! заводить копию без читателя.

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

/// Детерминированный генератор. Не криптостойкий и не претендует: его работа —
/// давать одну и ту же последовательность на любой машине.
///
/// Устроен дословно как у контейнерных эталонов (`cc-cli/tests/golden.rs`), и
/// это не копипаста по недосмотру: два эталона обязаны расходовать генератор
/// ОДИНАКОВО, иначе расхождение байтов между ними ничего не будет значить.
/// Хеш берётся через `oc-crypto`, а не напрямую из blake3: своего blake3 у
/// движка в зависимостях нет, и заводить его ради тестового генератора значило
/// бы расширять граф ради пробы.
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

/// Семя ПОЛУЧАТЕЛЯ. То же значение, что у пробы-отказа в `cc-cli`: пара там и
/// здесь одна и та же, и это связывает два утверждения об одном механизме.
const RECIPIENT_SEED: [u8; 32] = [0x08; 32];

/// Семя АППАРАТНОЙ половины автора.
///
/// В поставке этих байт не существует: классическая половина автора живёт в TPM
/// и наружу не выходит, а `keypair_from_seed` заведён «только для векторов и
/// программного пути» — так сказано в его собственной докстроке. Движку это
/// безразлично по построению: он видит 1249 открытых байт и не спрашивает, кто
/// держит вторую половину. Ровно поэтому эталон здесь возможен, и ровно поэтому
/// он НЕ доказывает работу с настоящим TPM — про живой TPM говорит прогон
/// 2026-09-15, записанный в `CLAUDE.md`.
const AUTHOR_HYBRID_SEED: [u8; 32] = [0x09; 32];

/// Семя ключа запечатывания сервера. Известно пробе целиком, и это осознанно:
/// эталон собран стендом, а стенд играет обе роли — иначе доля A недостижима и
/// открыть эталон нечем.
const SERVER_SEED: [u8; 32] = [0x03; 32];

/// Семя генератора. То же число, что у контейнерных эталонов.
const RNG_SEED: u8 = 42;

/// Что устройство «намерило», прогнав поток.
///
/// Величины взяты руками, а не из настоящего прогона, и это не упрощение:
/// движок потока НЕ ВИДИТ — он принимает итог параметром, — поэтому настоящий
/// прогон дал бы ровно те же три числа, только дороже. Содержательны они лишь
/// тем, что попадают в заголовок и в приватные метаданные, и оба эти места
/// эталон и сверяет.
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

/// Собрать заголовок движком. Никакого ввода-вывода, никаких часов, генератор
/// сидированный — всё, что нужно для побайтовой воспроизводимости.
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

/// ЗАГОЛОВОК С ДВУМЯ СЛОТАМИ `kem_id = 5` ПОБАЙТНО СОВПАДАЕТ С ЗАМОРОЖЕННЫМ.
///
/// Сверяется свежесобранный заголовок с файлом, а не сам с собой: это же и есть
/// проверка детерминизма между ПРОЦЕССАМИ, которую внутри одного прогона
/// подделать нечем.
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

/// ОБА ГИБРИДНЫХ СЛОТА ЭТАЛОНА ОТКРЫВАЮТСЯ СВОИМИ ПОЛОВИНАМИ.
///
/// Положительный контроль, без которого сверка байтов слепа: она доказывает
/// постоянство байтов и молчит об их пригодности. Здесь проверяется обратное —
/// что замороженное годно, и годно по ОБОИМ путям, авторскому и получательскому.
///
/// Путь получателя тот же, которым пойдёт устройство: `open_mlkem_p256` обеими
/// половинами, доля A из слота сервера, `derive_kek`, `unwrap_cek` — и в нём же
/// проверяется обязательство слота (И-4: `unwrap_cek` сверяет его константным
/// временем ДО открытия AEAD). Путь автора отличается тем, что его слот несёт
/// ОБЕ доли разом, и сервер ему не нужен.
///
/// Доведено до ОТКРЫТОГО ТЕКСТА приватных метаданных, а не до `CEK`: остановка
/// на ключе доказала бы, что сошлись доли, и промолчала бы о том, сходится ли с
/// ними то, что этим ключом зашифровано. Содержимого файла здесь нет — движок
/// потока не видит, — поэтому дальше приватных метаданных путь не идёт, и это
/// сказано прямо, а не скрыто за словом «полностью».
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

/// Дописать эталон движка ОДИН раз. Существующий файл не перезаписывается.
///
/// Тем же приёмом, что `write_the_hybrid_golden_once` в `cc-cli`, и по той же
/// причине: перевыпуск и ДОБАВЛЕНИЕ — разные действия, И-14 запрещает первое и
/// разрешает второе. Инструмент, умеющий только дописать, не может сделать
/// запрещённого даже по ошибке. Одного `#[ignore]` для этого мало: он не
/// защищает от `cargo test --workspace -- --ignored`, поэтому рядом стоит
/// переменная окружения, а поверх неё — отказ писать в существующий файл.
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
