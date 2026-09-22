//! Движок упаковки: всё, что РЕШАЕТ, и ничего, что считает по байтам.
//!
//! # Зачем этот крейт существует
//!
//! Продуктовый план делит работу так: на сервере — то, что решает (ключ
//! содержимого, доли, слоты, сборка и хеши заголовка), на устройстве — то, что
//! считает (прогон AEAD по байтам документа). Граница закладывается СЕЙЧАС,
//! чтобы позже компонент, держащий ключи, переехал в анклав сменой хостинга, а
//! не переписыванием.
//!
//! До этого крейта границы не было вовсе: `cc_cli::container::protect` делала
//! обе половины подряд, и «перенести движок в анклав» было беспредметным — в
//! репозитории отсутствовало то, что переносить.
//!
//! # Что здесь запрещено, и почему это проверяет сборка
//!
//! Ни ввода-вывода, ни часов, ни собственного генератора: генератор приходит
//! параметром. Крейт входит в тот же гейт чистоты, что `oc-format`,
//! `oc-protocol`, `oc-crypto` и `oc-policy`, — сборка под
//! `wasm32-unknown-unknown` и запрет `SystemTime` в `clippy.toml`.
//!
//! У четырёх остальных гейт держит детерминизм тестов. Здесь он держит саму
//! границу: анклав не примет компонент, успевший обзавестись зависимостью от
//! машины. Проверять это глазами ревьюера на каждом изменении — то же самое, что
//! не проверять.
//!
//! # Порядок вызовов и почему их два, а не один
//!
//! ```text
//!   plan()       → секреты, ключ полезной нагрузки          (движок)
//!   seal_chunks  → шифротекст, корень дерева, длина          (устройство)
//!   assemble()   → заголовок, транскрипт подписи, описание   (движок)
//!   sign+write   → подпись автора и запись файла             (устройство)
//! ```
//!
//! Средний шаг — `oc_crypto::stream::seal_chunks`. Он лежит в крипте, а не
//! здесь, и это не мелочь расположения: движок РЕШАЕТ, а тот цикл СЧИТАЕТ по
//! байтам, то есть принадлежит устройству. В крипту он переехал 2026-09-09 из
//! `cc_cli::payload`, когда устройств стало два — к машине получателя добавился
//! хост чужого языка через wasm, — и вторая реализация того же цикла разошлась
//! бы с первой молча (`oc_crypto::stream`, описание модуля).
//!
//! Разрезать иначе нельзя: приватные метаданные несут ДЛИНУ документа, а её
//! знает только тот, кто прогнал поток. Значит движок обязан отдать ключ, дождаться
//! ответа и лишь потом собрать заголовок.
//!
//! # Чего движок не делает — и это решение, а не упущение
//!
//! **Он не подписывает.** Подпись ставит ключ АВТОРА и покрывает заголовок
//! целиком, включая слоты (И-6); движок отдаёт транскрипт, подпись накладывает
//! устройство. Буквальное следование продуктовому плану — «сервер подписывает
//! политику» — потребовало бы второй подписи в заголовке, то есть новой версии
//! формата, посреди разреза, который обязан оставить байты неизменными.
//!
//! **CEK движок не отдаёт.** Наружу уходит только `payload_key`, выведенный из
//! него под конкретный размер чанка и алгоритм. Отдай движок CEK — и анклав
//! доказывал бы целостность образа, не давая ничего сверх неё: ключ, которым
//! разворачивается всё остальное, лежал бы снаружи.

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
/// Писатель правки (`docs/format.md`, «ПРАВКА ИСПОЛНИМА», п. G).
pub mod edit;

/// Теги приватных метаданных.
///
/// Публичны, потому что пишет их движок, а читает устройство: держать два
/// определения одних и тех же номеров в двух крейтах значило бы завести
/// расхождение, которое проявится только на чужом файле.
pub mod meta_tag {
    pub const NAME: u16 = 1;
    pub const SIZE: u16 = 2;
}

/// Длина nonce, которым зашифрованы приватные метаданные.
pub const META_NONCE_LEN: usize = 24;

/// Отказ движка.
#[derive(Debug)]
pub enum EngineError {
    Format(FormatError),
    Crypto(CryptoError),
    /// Собранный заголовок не сошёлся сам с собой.
    CoreHashMismatch,
    /// Получатель гибридный, а гибридной половины автора не дали.
    ///
    /// Отдельная ошибка, а не понижение до классического слота: понижение
    /// вернуло бы дыру, ради закрытия которой ветка и заведена, и вернуло бы
    /// молча — файл выглядел бы постквантовым, не будучи им.
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

/// Набор алгоритмов, которым пользуется этот движок.
#[must_use]
pub fn suite() -> Suite {
    Suite {
        sig: SigAlg::Ed25519,
        aead: AeadAlg::XChaCha20Poly1305,
        tree_hash: TreeHashAlg::Blake3,
    }
}

/// Кому адресован файл, помимо устройства автора.
///
/// Слот автора присутствует **всегда** и здесь не описывается: без него снятие
/// защиты требовало бы сети, и продукт создавал бы ровно тот риск потери
/// собственных файлов, от которого должен спасать.
///
/// `Clone` есть и стоит объяснения: у варианта с кодом-претензией копируется
/// СЕКРЕТ. Это осознанно — запрос упаковки живёт до сборки заголовка, а между
/// планом и сборкой лежит весь поток документа, — и безопасно ровно потому, что
/// `ClaimSecret` затирает себя при уничтожении. Копия исчезает так же, как
/// оригинал.
#[derive(Debug, Clone)]
pub enum Recipient {
    /// Никого: файл открывает **только** автор.
    ///
    /// Это не «бесшовный режим» из §3.4, хотя по флагам выглядит как значение по
    /// умолчанию. В бесшовном режиме доля получателя доступна всякому, у кого
    /// есть файл, — здесь она не доступна никому, кроме устройства автора.
    None,
    /// Долговременный ключ получателя (режим «ключ партнёра», §3.4).
    Identity { public_key: [u8; 32] },
    /// Гибридный ключ получателя — `kem_id = 4`, X-Wing (версия 4 формата).
    ///
    /// В коробке потому, что 1216 байт в перечислении раздули бы КАЖДЫЙ его
    /// вариант до этого размера, включая `None`.
    Hybrid { public_key: Box<[u8; oc_crypto::xwing::PUBLIC_KEY_LEN]> },
    /// АППАРАТНЫЙ гибрид получателя — `kem_id = 5`, MLKEM768-P256 (версия 5).
    ///
    /// Отличается от [`Self::Hybrid`] тем, где живёт классическая половина
    /// получателя: там программный X25519, здесь P-256 внутри его TPM.
    HardwareHybrid { public_key: Box<[u8; oc_crypto::mlkem_p256::PUBLIC_KEY_LEN]> },
    /// Код-претензия (§3.4): доля выводится из кода, в контейнер идёт только
    /// обязательство.
    Claim { secret: ClaimSecret },
}

/// Слот получателя, который появится в заголовке.
///
/// Отличается от [`Recipient`] тем, что код-претензия здесь уже превращена в
/// обязательство. Тип нужен именно ради этого: он не даёт существовать
/// состоянию «режим кода, а обязательства нет».
enum RecipientPlan {
    None,
    Identity([u8; 32]),
    Hybrid(Box<[u8; oc_crypto::xwing::PUBLIC_KEY_LEN]>),
    HardwareHybrid(Box<[u8; oc_crypto::mlkem_p256::PUBLIC_KEY_LEN]>),
    Claim([u8; 32]),
}

/// Открытые ключи, которые движок кладёт в заголовок и в слоты.
///
/// Только ОТКРЫТЫЕ. Ни одного секрета устройства сюда не приходит, и это
/// проверяется типом: движку нечем подписать и нечем расшифровать чужое.
#[derive(Debug)]
pub struct PublicKeys<'a> {
    /// Ключ проверки подписи автора — идёт в заголовок как `author_key`.
    pub author: [u8; 32],
    /// Ключ запечатывания сервера: и `sealing_kid`, и получатель слота сервера.
    pub authority_sealing: [u8; 32],
    /// Закреплённый ключ проверки лизинга.
    pub authority_lease_verify: [u8; 32],
    /// Программный ключ устройства автора.
    pub device: [u8; 32],
    /// Аппаратный гибрид устройства автора — MLKEM768-P256, 1249 байт.
    ///
    /// Нужен тогда и только тогда, когда получатель на пятом механизме.
    pub device_hardware_hybrid: Option<&'a [u8]>,
    /// Гибридная открытая половина устройства автора — X-Wing, 1216 байт.
    ///
    /// Нужна тогда и только тогда, когда получатель гибридный: авторский слот
    /// обязан быть не слабее слота получателя, иначе постквантовая защита
    /// теряется на самом файле — см. `seal_slots`.
    pub device_hybrid: Option<&'a [u8]>,
    /// Аппаратный ключ устройства (P-256 из TPM), если он есть.
    ///
    /// Когда он есть, слот автора адресуется ЕМУ, и второго слота на программный
    /// ключ рядом не пишется: написав оба, мы дали бы противнику, укравшему
    /// каталог ключей, открыть и новые файлы — то есть аппаратная привязка не
    /// давала бы ничего, оставаясь надписью.
    pub device_tpm: Option<&'a [u8]>,
}

/// Что упаковать и по каким правилам.
#[derive(Debug)]
pub struct PackRequest<'a> {
    pub original_name: &'a str,
    pub policy: Policy,
    pub chunk_size: u32,
    pub org_id: Vec<u8>,
    pub authority_urls: Vec<String>,
    pub recipient: Recipient,
    /// Состав соавторов под подписью автора — тег `0x8001` (версия 4).
    ///
    /// `None` — тега в заголовке нет, и байты контейнера такие же, как до
    /// появления поля: эталоны без состава не двигаются. Проверяется тем же
    /// правилом, что в кодировщике (`Coauthors::validate`), — вызывающий обязан
    /// отказать раньше, до прогона потока.
    pub coauthors: Option<oc_format::header::Coauthors>,
}

/// Что движок отдаёт устройству, чтобы то прогнало поток.
///
/// `payload_key`, а не `CEK`: см. модульную докстроку.
#[derive(Debug)]
pub struct Plan {
    pub file_id: [u8; 16],
    pub payload_key: PayloadKey,
    pub chunk_size: u32,
    pub aead: AeadAlg,
}

/// Что устройство сообщает движку, прогнав поток.
#[derive(Debug, Clone, Copy)]
pub struct SealedInfo {
    pub total_len: u64,
    pub chunk_count: u32,
    pub tree_root: [u8; 32],
}

/// Что движок отдаёт после сборки.
///
/// # Транскрипта подписи здесь НЕТ, и это решение
///
/// Он был — и убран, когда движок начали выносить в отдельный процесс. Причина
/// не в удобстве протокола: устройство обязано подписывать то, что оно САМО
/// вывело из заголовка, который собирается записать, а не то, что ему прислал
/// движок. Иначе движок, оказавшись враждебным, подсовывал бы транскрипт одного
/// заголовка к байтам другого, и подпись автора удостоверяла бы не тот файл.
///
/// Вывод транскрипта — чистая функция от заголовка и набора алгоритмов
/// (`oc_format::verify::header_signing_transcript`), устройству она доступна, и
/// стоит ничего. Экономить на ней значило бы менять проверяемое на присланное.
#[derive(Debug)]
pub struct Assembled {
    /// Заголовок целиком, готовый к записи.
    pub header: Vec<u8>,
    /// Изменяемая область с уже наложенным MAC.
    pub content_desc: Vec<u8>,
}

/// Секреты одного файла, живущие между двумя вызовами движка.
///
/// Не `Clone` и не `Copy` намеренно: копия этой структуры — копия ключа
/// содержимого, и заводить её незачем ни в одном сценарии.
#[derive(Debug)]
pub struct Session {
    file_id: [u8; 16],
    header_salt: [u8; 32],
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

/// Первый вызов: породить секреты и отдать ключ полезной нагрузки.
///
/// # Порядок расхода генератора здесь заморожен
///
/// `file_id`, `header_salt`, `CEK`, доля A, доля B — ровно в этом порядке. Он
/// не косметический: golden-эталоны сняты сидированным генератором, и любая
/// перестановка меняет каждый байт файла. Тот же довод запрещает добавлять сюда
/// новый вызов генератора «в начало» — только в конец, и только вместе с
/// решением о версии формата.
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
        Session { file_id, header_salt, cek, secret_a, secret_b, plan },
        Plan { file_id, payload_key, chunk_size: request.chunk_size, aead: suite().aead },
    )
}

impl Session {
    /// Второй вызов: собрать заголовок и изменяемую область.
    ///
    /// Заголовок собирается ДВАЖДЫ, и это не расточительство: хеш ядра обязан
    /// существовать раньше ключевого материала, который к нему привязан (И-3),
    /// а слоты и завёрнутый ключ из этого хеша вырезаны. Первый проход даёт
    /// каркас без них, второй — настоящий заголовок.
    ///
    /// # Errors
    /// Отдаёт [`EngineError`] при отказе кодирования, запечатывания или при
    /// расхождении пересчитанного хеша ядра.
    pub fn assemble<G: CryptoRng + ?Sized>(
        self,
        request: &PackRequest<'_>,
        keys: &PublicKeys<'_>,
        sealed: SealedInfo,
        rng: &mut G,
    ) -> Result<Assembled, EngineError> {
        let Session { file_id, header_salt, cek, secret_a, secret_b, plan } = self;

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

/// Запечатать слот на ключ P-256 — тот случай, когда получатель это TPM.
///
/// Отдельная функция, а не флаг у [`seal_slot`], по той же причине, по которой
/// разведены `seal` и `seal_p256` в крипте: у механизмов разный порядок расхода
/// генератора, а у X25519 он заморожен golden-эталонами.
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

/// Запечатать слот ГИБРИДОМ X-Wing — `kem_id = 4`.
///
/// Отдельная функция рядом с [`seal_slot`] и [`seal_slot_p256`] по той же
/// причине, что и они друг рядом с другом: у механизма свой порядок расхода
/// генератора, а у X25519 он заморожен эталонами.
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

/// Запечатать слот АППАРАТНЫМ гибридом — `kem_id = 5`.
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

/// Запечатать один слот.
///
/// `info` различает назначение слота, `aad` — хеш политики: шифротекст нельзя
/// перенести в контейнер с другими правилами. Восемь аргументов — много, и
/// линтер прав; но каждый здесь обязателен и содержателен, а собрать их в
/// структуру значило бы завести тип, живущий ровно один вызов, и спрятать за ним
/// то, что при чтении вызова как раз надо видеть.
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

/// Слот кода-претензии: обязательство и ничего больше.
///
/// Поля запечатывания заполняются нулями, а `ct` остаётся пустым, и это не
/// заглушки «чтобы прошло по структуре»: запечатывать здесь **нечего**. Доля
/// получателя выводится из кода, а код в контейнер не попадает.
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

/// Зашифровать приватные метаданные под собственным ключом.
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
    //! Порядок расхода генератора — НАЗВАННЫЙ, а не подразумеваемый.
    //!
    //! Докстрока [`plan`] объявляет порядок замороженным: `file_id`,
    //! `header_salt`, `CEK`, доля A, доля B. Держали его до сих пор только
    //! эталоны — golden в `cc-cli` и `hardware_hybrid_golden.rs` рядом. Эталон
    //! на перестановку двух соседних вызовов ответит «байты не сошлись на
    //! позиции N», и по такому ответу порядок не восстановить: сходятся все
    //! байты файла сразу, потому что из этих пяти величин выведено всё
    //! остальное.
    //!
    //! Четыре запроса из пяти — по 32 байта, и по одним длинам перестановка
    //! соседей НЕ видна. Поэтому сверяется ещё и то, КУДА легли байты: кусок
    //! потока под номером K обязан оказаться в поле с именем X, и при сдвиге
    //! проба называет, кто пришёл на его место.
    //!
    //! Проба живёт внутри крейта, а не в `tests/`: поля [`Session`] приватны, и
    //! открывать их наружу ради сверки значило бы расширить интерфейс движка
    //! ради теста — то есть отдать секреты файла всякому, кто подключит крейт.

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

    /// Сколько байт покрывает сверка адресов: 16 + 32 × 4.
    const WATCHED: usize = 144;

    /// Байт потока по его номеру.
    ///
    /// Своя дешёвая последовательность, а не хеш: криптографическое качество
    /// здесь не нужно ни на грош — нужно лишь, чтобы куски были различимы и
    /// воспроизводимы, а зависимости у движка не прибавилось.
    fn stream_byte(index: usize) -> u8 {
        (index as u8).wrapping_mul(31).wrapping_add(7)
    }

    /// Генератор, который ЗАПОМИНАЕТ длины запросов по порядку.
    ///
    /// Выдаёт заранее известный поток, поэтому по адресу байта видно, какой
    /// запрос его получил.
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

    /// ПЯТЬ ЗАПРОСОВ К ГЕНЕРАТОРУ, В НАЗВАННОМ ПОРЯДКЕ И В НАЗВАННЫЕ ПОЛЯ.
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

    /// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: сверка адресов ловит перестановку двух соседей.
    ///
    /// Без него проба выше зеленела бы и на генераторе, отдающем одни нули, —
    /// там все куски равны, и любой адрес «совпадает» с любым.
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
