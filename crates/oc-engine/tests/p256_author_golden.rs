//! ЭТАЛОН РАСКЛАДКИ АВТОРСКОГО СЛОТА P-256 (`kem_id = 2`) — НА УРОВНЕ ДВИЖКА.
//!
//! # Зачем заведён
//!
//! Этот слот печатается СЕГОДНЯ и ПО УМОЛЧАНИЮ — на каждой машине, где PCP отдал
//! ключ устройства (`cc-cli/src/keys.rs`, источник `Auto` и `Hardware`), — и до
//! сих пор его раскладку не стерегло ничто. Разбор
//! `docs/review/2026-09-21-p256-slot.md` показал ровно эту дыру: все пробы
//! клиента идут с `CC_DEVICE_BINDING=software`, то есть ни один тестовый
//! контейнер этого слота не несёт; заморожены КОНЦЫ (примитив
//! `tests/kat/seal_p256.kat` и синтетические слоты в пробах таблиц длин) и не
//! заморожена середина — то, что из них собирает движок.
//!
//! Цена слепоты названа там же и стоит повторения: авторский слот — единственный,
//! несущий ОБЕ доли разом. Перестань читатель признавать `kem_id = 2` — и автор
//! получит «ни один ключ не подошёл» на файле, который зашифровал сам, а НИ ОДНА
//! проба при этом не покраснеет. Красное здесь заводится этим файлом.
//!
//! # Почему здесь, а не рядом с контейнерными эталонами
//!
//! По той же причине, что у соседа `hardware_hybrid_golden.rs`: контейнерного
//! эталона через `cc-cli` не бывает, потому что точку P-256 клиент берёт только
//! из TPM, а у каждого TPM свой ключ — «побайтово тот же контейнер на другой
//! машине» перестаёт существовать как понятие
//! (`cc-cli/tests/golden.rs`, `fixed_keys`, поле `device_tpm`).
//!
//! Движок этого ограничения не имеет и иметь не должен: он чист и принимает
//! открытую точку ПАРАМЕТРОМ (`PublicKeys::device_tpm`), поэтому ему всё равно,
//! откуда она пришла — из TPM или из фиксированного скаляра. Ему достаточно 65
//! байт несжатой точки. Ровно это делает эталон возможным здесь и невозможным
//! этажом выше.
//!
//! # Что заморожено
//!
//! Байты `Assembled::header` при двух видах получателя, и оба вида выбраны не
//! ради полноты перебора, а потому, что они СЕГОДНЯШНЕЕ БОЛЬШИНСТВО:
//!
//! * `p256-author.header` — классический получатель X25519. Это обычный путь:
//!   при неаппаратном и негибридном получателе и при наличии точки TPM движок
//!   печатает авторский слот `kem_id = 2` (`oc-engine/src/lib.rs`, ветка
//!   `(false, _, Some(tpm_public))`).
//! * `p256-author-none.header` — получателя нет вовсе. Заморожен потому, что
//!   почти бесплатен и покрывает ДРУГУЮ раскладку: слота получателя в заголовке
//!   нет, и авторский слот оказывается вторым, а не третьим. Порядок и соседство
//!   записей — такое же свойство формата, как их содержимое.
//!
//! Оба идут по одной ветке движка, и это не дублирование: ветка одна, а
//! заголовки разные, и разойтись они могут независимо.
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
//! **`Assembled::content_desc` не включён** — по той же причине, что у соседа:
//! он выводится из `CEK` и `SealedInfo` и при любом виде получателя на том же
//! семени получается один и тот же, то есть не отличает второй механизм ни от
//! какого другого.
//!
//! **`Plan::payload_key` не включён.** Он детерминирован, но это КЛЮЧ; секреты в
//! репозиторий не кладутся ни под каким видом.
//!
//! **Живого TPM здесь нет.** Скаляр программный, и это сказано прямо: эталон
//! говорит о РАСКЛАДКЕ слота, а не о том, что ключ действительно неизвлекаем.
//! Про живой TPM говорят прогоны, записанные в `CLAUDE.md`, а не этот файл.
//!
//! # Открывается, а не только сверяется
//!
//! Эталон, который никто не может открыть, замораживает мусор — и замораживает
//! навсегда. Поэтому рядом со сверкой байтов стоят пробы открытия: авторский
//! слот открывается ПРОГРАММНОЙ стороной согласования P-256 — тем же
//! `seal::open_with` и тем же трейтом `KeyAgreement`, каким его откроет
//! устройство (`cc-cli/src/container.rs`, перебор сторон согласования). В
//! поставке сторона аппаратная, здесь программная; вывод ключа от этого не
//! меняется ни на байт, потому что считается по общему секрету, а не по ключу.
//!
//! # Когда будет резаться версия 6
//!
//! Свидетеля у этого артефакта, как и у соседнего, НЕТ: он заведён под текущего
//! писателя и в день нарезки шестой версии потребует того же решения, что и
//! контейнерные эталоны. Здесь это записано, а не сделано.

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

/// Детерминированный генератор. Не криптостойкий и не претендует: его работа —
/// давать одну и ту же последовательность на любой машине.
///
/// Устроен дословно как у соседа и у контейнерных эталонов, и это НЕ копипаста
/// по недосмотру — довод записан в `hardware_hybrid_golden.rs` и здесь он тот
/// же: эталоны обязаны расходовать генератор ОДИНАКОВО, иначе расхождение байтов
/// между ними ничего не будет значить. Вынести его в общий `tests/common` было
/// бы соблазнительно, но это означало бы править файл, чей эталон уже заморожен,
/// ради удобства соседа; дубль в пробах дешевле риска сдвинуть чужие байты.
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

/// Скаляр АВТОРСКОЙ стороны P-256.
///
/// В поставке этих байт не существует: классическая половина автора живёт в TPM
/// и наружу не выходит. Движку это безразлично по построению — он видит 65
/// открытых байт и не спрашивает, кто держит вторую половину. Ровно поэтому
/// эталон здесь возможен, и ровно поэтому он НЕ доказывает работу с настоящим
/// TPM.
///
/// Значение отличается от `[0x5e; 32]` из `tests/kat/seal_p256.kat` намеренно:
/// совпади они, расхождение примитива и расхождение сборки выглядели бы
/// одинаково, и по упавшей пробе нельзя было бы сказать, что именно сдвинулось.
const AUTHOR_P256_SCALAR: [u8; 32] = [0x0a; 32];

/// Семя ПОЛУЧАТЕЛЯ (X25519). То же значение, что у контейнерного эталона
/// `recipient.cc` (`cc-cli/tests/golden.rs`, `fixed_recipient_public`): пара там
/// и здесь одна и та же, и это связывает два утверждения об одном получателе.
const RECIPIENT_SEED: [u8; 32] = [0x05; 32];

/// Семя ключа запечатывания сервера. Известно пробе целиком, и это осознанно:
/// эталон собран стендом, а стенд играет обе роли — иначе доля A недостижима.
const SERVER_SEED: [u8; 32] = [0x03; 32];

/// Семя ПРОГРАММНОГО ключа устройства. Лежит в `PublicKeys::device` и при живой
/// точке TPM в слот не попадает вовсе — ровно это свойство эталон и стережёт:
/// второго слота на программный ключ рядом с аппаратным не пишется, иначе
/// аппаратная привязка осталась бы надписью.
const DEVICE_SOFTWARE_SEED: [u8; 32] = [0x02; 32];

/// Семя генератора. То же число, что у соседа и у контейнерных эталонов.
const RNG_SEED: u8 = 42;

/// Что устройство «намерило», прогнав поток.
///
/// Величины взяты руками, а не из настоящего прогона, и это не упрощение: движок
/// потока НЕ ВИДИТ — он принимает итог параметром, — поэтому настоящий прогон
/// дал бы ровно те же три числа, только дороже.
fn sealed_info() -> SealedInfo {
    SealedInfo { total_len: 13_000, chunk_count: 4, tree_root: [0x3b; 32] }
}

/// Программная сторона согласования автора. Выводится продуктовым кодом
/// `oc-crypto`, а не записана байтами: вписанная константой открытая точка стала
/// бы вторым источником истины о выводе пары и молча разошлась бы с продуктом.
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

/// Классический получатель — обычный путь, на котором автор с TPM получает слот
/// `kem_id = 2`.
fn recipient_identity() -> Recipient {
    Recipient::Identity { public_key: x25519_public(&recipient_secret()) }
}

/// Собрать заголовок движком. Никакого ввода-вывода, никаких часов, генератор
/// сидированный — всё, что нужно для побайтовой воспроизводимости.
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

/// ЗАГОЛОВОК С АВТОРСКИМ СЛОТОМ `kem_id = 2` ПОБАЙТНО СОВПАДАЕТ С ЗАМОРОЖЕННЫМ.
///
/// Сверяется свежесобранный заголовок с ФАЙЛОМ, а не сам с собой: это же и есть
/// проверка детерминизма между ПРОЦЕССАМИ, которую внутри одного прогона
/// подделать нечем.
#[test]
fn the_p256_author_headers_are_byte_identical_to_the_frozen_goldens() {
    compare(GOLDEN_WITH_RECIPIENT, &build_header(recipient_identity()));
    compare(GOLDEN_WITHOUT_RECIPIENT, &build_header(Recipient::None));
}

/// ДВА ПРОГОНА СБОРКИ ДАЮТ ОДНИ И ТЕ ЖЕ БАЙТЫ.
///
/// Отдельно от сверки с файлом, и это не дублирование. Сверка с файлом молчит о
/// причине расхождения: «не сошлось» одинаково значит «сдвинулась раскладка» и
/// «сборка вообще недетерминирована». Здесь проверяется второе, и проверяется
/// дёшево — внутри одного прогона, без файла.
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

/// Разобрать эталон и убедиться, что авторский слот — ТОТ САМЫЙ механизм и той
/// самой формы. Общая часть обеих проб открытия.
///
/// Длины сверяются через `P256_PUBLIC_LEN` из `oc-format`, а не числом 65: число
/// в пробе стало бы вторым источником истины о раскладке и разошлось бы молча.
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

/// Открыть авторский слот и дойти до ОТКРЫТОГО ТЕКСТА приватных метаданных.
///
/// Возвращает `CEK`, чтобы вызывающий мог сличить его со вторым путём.
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

/// АВТОРСКИЙ СЛОТ P-256 ОТКРЫВАЕТСЯ, И ВТОРОЙ ПУТЬ ВЕДЁТ К ТОМУ ЖЕ КЛЮЧУ.
///
/// Положительный контроль, без которого сверка байтов слепа: она доказывает
/// постоянство байтов и молчит об их пригодности. Здесь проверяется обратное —
/// что замороженное годно, и годно по ОБОИМ путям.
///
/// Путь автора: обе доли разом из одного слота, сервер не нужен. Путь
/// получателя: доля B из своего слота, доля A из слота сервера. Разойдись они —
/// файл открывался бы двумя РАЗНЫМИ путями к разным ключам, и схема «2 из 2»
/// перестала бы ею быть.
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

/// БЕЗ ПОЛУЧАТЕЛЯ АВТОРСКИЙ СЛОТ ОСТАЁТСЯ ЕДИНСТВЕННОЙ ДОРОГОЙ — И ОНА ЦЕЛА.
///
/// Здесь второго пути нет по построению, и именно поэтому проба заведена
/// отдельно: на таком файле потеря авторского слота означает потерю файла
/// навсегда, без всякого «зато откроет получатель».
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

/// Дописать эталоны движка ОДИН раз. Существующие файлы не перезаписываются.
///
/// Тем же приёмом, что у соседа, и по той же причине: перевыпуск и ДОБАВЛЕНИЕ —
/// разные действия, И-14 запрещает первое и разрешает второе. Инструмент,
/// умеющий только дописать, не может сделать запрещённого даже по ошибке. Одного
/// `#[ignore]` для этого мало: он не защищает от
/// `cargo test --workspace -- --ignored`, поэтому рядом стоит переменная
/// окружения, а поверх неё — отказ писать в существующий файл.
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
