//! Заголовок контейнера: неизменяемая область, подписанная автором.
//!
//! Кодирование — TLV из [`crate::tlv`]. Разбор возвращает не только структуру, но
//! и байтовые диапазоны полей: хеши политики и ядра заголовка считаются по
//! исходным байтам, а не по повторной кодировке разобранной структуры.

use crate::policy_codec;
use crate::tlv::{TlvReader, TlvWriter, UnknownTag, unknown_tag_action};
use crate::{FormatError, MAX_KEY_SLOTS};
use core::ops::Range;
use sha2::{Digest, Sha256};
use oc_crypto::{AeadAlg, KemAlg, SigAlg, TreeHashAlg, label};
use oc_policy::Policy;

/// Теги полей заголовка. Значения входят в подписанные байты, поэтому их нельзя
/// менять местами при рефакторинге: ранее выпущенные файлы перестанут читаться.
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
    /// Смещение футера — **СОЖЖЁН решением, перенесённым в версию 4**, не используйте.
    ///
    /// Величина объявлена дважды: здесь и тегом 5 изменяемой области. Главный —
    /// тег 5, и решает это не безопасность, а изменяемость: футер лежит за
    /// нагрузкой, правка меняет её длину, футер съезжает, а подписать новое
    /// смещение может только автор, которого при правке нет. Разбор — в
    /// `docs/format.md`, раздел «ВЕРСИЯ 3 ОТКРЫТА», пункт 6.
    ///
    /// Поле остаётся здесь до нарезки версии 4, и это не забывчивость: версии 1
    /// 2 и 3 заморожены вместе с правом второй реализации этот тег записать.
    /// Снять его раньше значило бы отвергать файл, который замороженной спеке
    /// соответствует.
    pub const FOOTER_OFFSET: u16 = 16;
    /// Завёрнутый ключ содержимого.
    ///
    /// Лежит в заголовке, а не в слоте: KEK у файла один, значит и завёрнутый CEK
    /// один, сколько бы слотов ни было. Подписью автора он покрыт как обычное
    /// поле, но из [`super::Header::core_hash`] **исключён** — иначе получилась бы
    /// круговая зависимость: обёртка связана с хешем ядра через связанные данные.
    pub const WRAPPED_CEK: u16 = 17;
    /// Состав тех, кто вправе администрировать файл. **Начиная с версии 4.**
    ///
    /// Первый НЕОБЯЗАТЕЛЬНЫЙ тег подписанного заголовка, и это решение, а не
    /// оплошность. Общее правило — «поле, ужесточающее требование, обязано быть
    /// критичным» — здесь не действует, потому что для ЧИТАТЕЛЯ поле не
    /// ужесточает ничего: состав соавторов не меняет ни ключей, ни правил
    /// доступа, он меняет лишь то, чьи распоряжения станет исполнять СЕРВЕР.
    /// Клиент, пропустивший тег, открывает файл совершенно верно.
    ///
    /// Критичный тег означал бы здесь, что старый просмотрщик отказывается
    /// открывать файл, у которого два администратора вместо одного, — отказ без
    /// причины, ровно та цена, ради избежания которой необязательный диапазон и
    /// заведён.
    pub const COAUTHORS: u16 = 0x8001;
}

/// Теги внутри поля `SUITE`.
mod suite_tag {
    pub const SIG: u16 = 1;
    pub const AEAD: u16 = 2;
    pub const TREE_HASH: u16 = 3;
}

/// Теги внутри поля `AUTHORITY`.
mod authority_tag {
    pub const URLS: u16 = 1;
    pub const SEALING_KID: u16 = 2;
    pub const LEASE_VERIFY_KEY: u16 = 3;
}

/// Теги внутри записи одного слота.
mod slot_tag {
    pub const KIND: u16 = 1;
    pub const KEM: u16 = 2;
    pub const ENC: u16 = 3;
    pub const CT: u16 = 4;
    pub const COMMITMENT: u16 = 5;
    pub const KEY_FPR: u16 = 6;
    /// Nonce AEAD запечатывания. Хранится, а не выводится — см. oc_crypto::seal::SealedBlob::nonce.
    pub const NONCE: u16 = 7;
    /// Обязательство кода-претензии (K8). Только у слота вида `RecipientClaim`.
    pub const CLAIM_COMMIT: u16 = 8;
}

/// Единственный класс защиты, который эта версия исполняет.
///
/// Ноль — «локальный». Прочие номера в реестре §2 зарезервированы, но приниматься
/// на разборе не должны: см. комментарий у ветки `tag::CLASS`.
const LOCAL_CLASS: u8 = 0;

/// Первая существовавшая версия формата.
///
/// **Нижней границей разбора БОЛЬШЕ НЕ ЯВЛЯЕТСЯ** — с решением Р-1 (2026-09-19)
/// её держит [`MIN_READABLE_CONTAINER_VERSION`]. Константа остаётся записью
/// истории устройства: нумерация версий НЕ сброшена, версия считает устройство,
/// а не имя, и номера 1–4 не переиспользуются. Убрать её значило бы стереть
/// след того, что пятёрка — пятая, а не первая.
pub const FIRST_CONTAINER_VERSION: u16 = 1;

/// Версия формата, которую производит этот код.
///
/// Пятёрка: аппаратный гибрид `kem_id = 5` (MLKEM768-P256), решение версии 5.
/// Читатель узнаёт версию раньше писателя, чтобы каждый промежуточный выпуск
/// понимал собственные файлы. Версии 1–4 больше не производятся, и свидетелей у
/// них нет: переименование 2026-09-08 сменило magic (`docs/format.md`).
pub const CONTAINER_VERSION: u16 = 5;
/// Наибольшая версия клиента: версия 3 всегда требует читателя 3 (§2.1).
pub const SUPPORTED_READER_VERSION: u16 = 5;
/// Наименьшая читаемая версия формата — НИЖНЯЯ граница разбора.
///
/// Пятёрка, а не единица, и это решение Р-1 от 2026-09-19, а не ужесточение
/// попутно. Версии 1–4 СОЖЖЕНЫ для чтения: ни один контейнер этих версий с
/// magic `CLOSECR1` никогда не выпускался — переименование 2026-09-08 сменило
/// magic и все метки домена в тот же день, когда нарезалась версия 5
/// (`docs/format.md`, раздел «ПЕРЕИМЕНОВАНИЕ 2026-09-08»). Обещание «версии
/// 1–4 читаемы» относилось к ПУСТОМУ МНОЖЕСТВУ и проверялось только перебором
/// номера в диапазоне, а не единым открытым файлом.
///
/// Правило, из которого это следует, шире самого случая (Р-3): **до первого
/// файла, ушедшего наружу, читатель держит только версию писателя.** Чтение
/// версии 5 снимется так же, как сегодня снимается чтение 1–4, — в день, когда
/// нарежется версия 6 и писатель уйдёт на неё. Правило перестанет действовать
/// в день первого внешнего файла, и этот день обязан быть записан в
/// `docs/format.md`.
///
/// Нумерация при этом НЕ сбрасывается: [`FIRST_CONTAINER_VERSION`] остаётся
/// записью истории, номера 1–4 не переиспользуются, байты версии 5 не меняются.
pub const MIN_READABLE_CONTAINER_VERSION: u16 = 5;
/// Наибольшая читаемая версия формата.
///
/// Отделена от версии писателя, и разделение это несущее: читатель обязан
/// узнавать новые байты РАНЬШЕ, чем писатель начнёт их выпускать, иначе
/// переключение писателя делает свежий файл нечитаемым для вчерашней сборки без
/// всякой на то причины.
///
/// Порядок при бампе несущий: эта константа поднимается РАНЬШЕ версии писателя,
/// иначе свежевыпущенный файл отвергнется собственным же читателем. Нижняя
/// граница [`MIN_READABLE_CONTAINER_VERSION`], наоборот, поднимается ПОЗЖЕ —
/// после того, как писатель переключён: подними её раньше, и сборка перестанет
/// открывать файлы, которые сама же и производит.
pub const MAX_READABLE_CONTAINER_VERSION: u16 = 5;
/// Длина завёрнутого ключа содержимого.
///
/// Переэкспорт, а не собственная константа: два определения одной длины
/// разошлись бы при первой же правке, и заголовок начал бы резать обёртку не по
/// той границе, по которой её собрали.
pub use oc_crypto::wrap::WRAPPED_CEK_LEN;
/// Верхняя граница длины одного адреса сервера.
const MAX_URL_LEN: usize = 2048;
/// Верхняя граница числа адресов сервера.
const MAX_URLS: usize = 16;

/// Набор алгоритмов файла. `kem` здесь нет: он задаётся **на каждый слот**,
/// потому что X25519 сменится гибридом с ML-KEM, и слоты с разными KEM обязаны
/// сосуществовать в одном файле.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Suite {
    pub sig: SigAlg,
    pub aead: AeadAlg,
    pub tree_hash: TreeHashAlg,
}

/// Назначение слота ключа.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotKind {
    /// Доля сервера лицензий.
    Server = 1,
    /// Доля получателя, запечатанная на его долговременный ключ.
    RecipientIdentity = 2,
    /// Доля получателя, выводимая из кода-претензии. Хранится только
    /// обязательство, сам код идёт вторым каналом.
    RecipientClaim = 3,
    /// Обе доли, запечатанные на устройство автора. Присутствует всегда: без него
    /// снятие защиты требовало бы сети, и продукт создавал бы риск потери
    /// собственных файлов.
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

/// Слот ключа.
///
/// Неизвестный вид слота сохраняется как [`KeySlot::Unknown`] и игнорируется:
/// правило чтения — понять хотя бы один пригодный слот, остальные пропустить.
/// Без этого добавление слота в версии 2 сделало бы файлы нечитаемыми для
/// выпущенных клиентов.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeySlot {
    Known(KnownSlot),
    Unknown { kind: u16, raw: Vec<u8> },
}

/// Слот, вид которого этому клиенту известен.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownSlot {
    pub kind: SlotKind,
    pub kem: KemAlg,
    /// Эфемерный публичный ключ отправителя. Для слота с кодом-претензией не
    /// используется и равен нулям.
    ///
    /// Длина — функция пары (`container_version`, `kem_id`), а не константа:
    /// у X25519 это 32 байта, у P-256 — 65 (несжатая точка SEC1). Массив
    /// фиксированной длины стоял здесь до версии 2 формата и был не просто
    /// неудобством, а потолком: 65 байт в него не помещались, поэтому слот на
    /// P-256 нельзя было ни записать, ни разобрать.
    pub enc: Vec<u8>,
    /// Nonce AEAD запечатывания.
    ///
    /// Хранится в файле, а не выводится из общего секрета: иначе повтор
    /// состояния генератора у автора отдавал бы открытые тексты обоих слотов
    /// через XOR, а это доли секрета, из которых собирается ключ содержимого.
    pub nonce: [u8; 24],
    /// Запечатанный секрет с тегом.
    pub ct: Vec<u8>,
    /// Обязательство слота, проверяемое в постоянном времени до открытия AEAD.
    pub commitment: [u8; 32],
    /// **Публичный ключ**, на который запечатан секрет, — без хеширования.
    ///
    /// Поле называлось «отпечаток», и слово стоит пояснить, а не заменить молча: в
    /// этом проекте «отпечаток» повсеместно означает сам 32-байтовый ключ (так же
    /// названы отпечатки в выводе `cc keygen` и поле `fingerprint` в фактах об
    /// устройстве). Хеша здесь нет ни на записи, ни на чтении, функции для него не
    /// существует, метки домена под неё не заведено. Разница стала видимой в
    /// версии 2 формата, где ключ P-256 занимает 65 байт.
    ///
    /// Входит в подписанные автором байты, потому что сервер выдаёт ключи и тем
    /// самым является каталогом ключей получателей: без закреплённого значения он
    /// мог бы подменить ключ получателя своим и собрать обе доли.
    pub key_fpr: Option<Vec<u8>>,
    /// Обязательство кода-претензии (K8). Только для [`SlotKind::RecipientClaim`].
    ///
    /// Отдельное поле, а не переиспользованный `ct`, и это стоит объяснить.
    /// В слоте с кодом-претензией **нечего запечатывать**: доля получателя
    /// выводится из кода, который у получателя уже есть. Контейнеру нужно другое —
    /// дать получателю проверить, что он набрал верный код, до того как начнётся
    /// дорогая работа. Это и есть K8.
    ///
    /// Положить его в `ct` было бы соблазнительно и неверно: `ct` по всему
    /// формату означает «запечатанный секрет с тегом», и поле, значащее в одном
    /// виде слота одно, а в другом другое, — это ровно тот класс перегрузки,
    /// который потом читают неправильно.
    ///
    /// Состав полей зависит от вида слота, и это проверяется в обе стороны
    /// (`encode`/`decode`): для видов, которые запечатывают, обязательство кода
    /// **запрещено**, а `enc`, `nonce` и `ct` обязательны; для кода-претензии
    /// наоборот.
    pub claim_commit: Option<[u8; 32]>,
}

impl KnownSlot {
    /// Запечатывает ли этот вид слота секрет на чей-то публичный ключ.
    ///
    /// Единственное место, где записано это различие. Три вида из четырёх
    /// запечатывают; код-претензия не запечатывает ничего.
    #[must_use]
    pub fn kind_seals(kind: SlotKind) -> bool {
        match kind {
            SlotKind::Server | SlotKind::RecipientIdentity | SlotKind::AuthorDevice => true,
            SlotKind::RecipientClaim => false,
        }
    }
}

/// Координаты сервера лицензий.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Authority {
    /// Список адресов: ротация и self-hosted развёртывания неизбежны, один
    /// зашитый URL стал бы днём отказа.
    pub urls: Vec<String>,
    /// Идентификатор ключа запечатывания сервера.
    ///
    /// ЭТО ЗАПИСЬ, А НЕ ПРОВЕРКА, и путать легко. Значение равно тому ключу, на
    /// который писатель запечатал слот `Server` (`oc_engine`: `sealing_kid` и
    /// получатель слота — одна и та же величина), но НИКТО его ни с чем не
    /// сверяет: во всём `cc-cli` и `cc-viewer` нет ни одного сравнения. Привязка
    /// к ключу сервера держится тем, что чужим ключом слот попросту не
    /// открывается.
    ///
    /// Почему сверки нет и заводить её не надо. Обе копии — это поле и `key_fpr`
    /// слота `Server` — лежат под подписью автора, покрывающей заголовок целиком
    /// (И-6), поэтому рассинхронизировать их может только свой же писатель;
    /// проверка ловила бы собственную ошибку, а не противника. Хуже того, строка
    /// «`sealing_kid` сверен» читалась бы как «мы удостоверились, что говорим с
    /// тем сервером», — а поле вообще не покидает машину автора и серверу не
    /// показывается: в `ActivateReq` его нет.
    ///
    /// Жёсткое равенство на разборе стоило бы ещё дороже: оно впаяло бы «слот
    /// сервера всегда 32-байтовый X25519» в тип `[u8; 32]`, тогда как `key_fpr` —
    /// функция `kem_id` и у пятого механизма занимает 1249 байт. Снимать это
    /// потом пришлось бы версией формата.
    pub sealing_kid: [u8; 32],
    /// **Закреплённый** ключ проверки лизинга.
    ///
    /// Закрепление по одному URL — это доверие при первом использовании: без
    /// названного здесь ключа поддельный сервер выпускает собственные лизинги.
    pub lease_verify_key: [u8; 32],
}

/// Разобранный заголовок.
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
    /// AEAD-блок под ключом K5: настоящее имя файла и справочный размер.
    ///
    /// MIME в версии 1 не пишется (§2.0), и упоминать его здесь нельзя: номер 3 под
    /// него лишь зарезервирован.
    pub private_meta: Vec<u8>,
    pub prev_header_hash: Option<[u8; 32]>,
    pub org_id: Vec<u8>,
    /// Класс защиты. 0 — локальный; резерв под будущие классы.
    pub class: u8,
    pub footer_offset: Option<u64>,
    /// Завёрнутый под KEK ключ содержимого.
    pub wrapped_cek: [u8; WRAPPED_CEK_LEN],
    /// Состав соавторов, закреплённый подписью автора. Версия 4.
    ///
    /// Якорь для сервера: сегодня состав живёт только в его состоянии, и за него
    /// ручается состояние, а не документ. Тот, кто держит сервер, может состав
    /// переписать; с этим тегом — не может молча.
    pub coauthors: Option<Coauthors>,
}

/// Предел состава: столько ключей человек ещё способен просмотреть глазами.
///
/// То же число, что у адресов сервера и у очереди просьб, и по той же причине.
pub const MAX_COAUTHORS: usize = 16;

/// Первая версия формата, знающая состав соавторов в заголовке.
pub const FIRST_COAUTHORS_VERSION: u16 = 4;

/// Теги внутри записи состава соавторов.
pub mod coauthors_tag {
    pub const THRESHOLD: u16 = 1;
    pub const KEYS: u16 = 2;
}

/// Состав тех, кто вправе администрировать файл, и порог их подписей.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Coauthors {
    /// Сколько подписей из состава требуется. Ноль означает «кворума нет».
    pub threshold: u8,
    /// Ключи состава. При `threshold = 0` пуст.
    pub keys: Vec<[u8; 32]>,
}

impl Coauthors {
    /// Исполним ли состав — то же правило, что стоит в кодировщике и разборщике.
    ///
    /// Наружу оно выставлено затем, чтобы писатель, командная строка и SDK
    /// отказывали ДО необратимой упаковки и тем же правилом, а не своей копией:
    /// копия правил расходится с оригиналом первой же правкой.
    ///
    /// # Errors
    /// Порог ноль при непустом составе, пустой или больше [`MAX_COAUTHORS`]
    /// состав при ненулевом пороге, неисполнимый порог, повтор ключа.
    pub fn validate(&self) -> Result<(), FormatError> {
        check_coauthors(self)
    }
}

/// Байтовые диапазоны полей внутри разобранного буфера.
///
/// Существуют только для того, чтобы хеши считались по исходным байтам.
/// Пересчёт по повторной кодировке разобранной структуры — источник всего
/// семейства ошибок канонизации, известного по JWS и XML-DSig.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderSpans {
    /// Значение поля политики, без тега и длины.
    pub policy_value: Range<usize>,
    /// **Вся запись** слотов ключа, включая тег и длину.
    ///
    /// Именно запись целиком, а не значение: [`Header::core_hash`] вырезает её из
    /// хешируемых байтов, и оставленные тег с длиной позволили бы менять содержимое
    /// слотов, не меняя хеш ядра.
    pub key_slots_record: Range<usize>,
    /// Вся запись завёрнутого ключа содержимого. Вырезается по той же причине.
    pub wrapped_cek_record: Range<usize>,
}

/// Сила, которой защищён файл, — по АВТОРСКОМУ слоту.
///
/// Стойкость контейнера равна стойкости слабейшего достаточного пути к CEK, а
/// авторский путь достаточен всегда; поэтому спека требует, чтобы авторский
/// слот был не слабее любого слота получателя (`docs/format.md`, «АВТОРСКИЙ
/// СЛОТ ОБЯЗАН БЫТЬ НЕ СЛАБЕЕ СЛОТА ПОЛУЧАТЕЛЯ»). Значит сила файла — это сила
/// авторского слота, и чужой слот получателя для неё не нужен: получатель, не
/// названный в заголовке, и наследник узнают её оттуда же.
///
/// Порядок вариантов — та самая таблица требований из спеки: «пятёрка требует
/// пятёрки, четвёрка — четвёрки или пятёрки, классика не требует ничего».
/// Это НЕ номер механизма как шкала: P-256 (`kem_id = 2`) классический, хотя
/// его номер больше единицы, а `RsaOaep` (3) не исполняется вовсе.
///
/// Живёт в разборщике, а не у клиента (E2, B8): то же правило применяет
/// сервер к просьбе о доступе, и две копии одного правила разошлись бы молча.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Strength {
    /// X25519, P-256 или RSA-OAEP: ни постквантовой защиты, ни требования к
    /// железу получателя.
    Classical,
    /// X-Wing (`kem_id = 4`): постквантовый гибрид, программный.
    PostQuantum,
    /// MLKEM768-P256 (`kem_id = 5`): постквантовый гибрид с классической
    /// половиной в TPM.
    PostQuantumHardware,
}

impl Strength {
    /// Сила одного слота по его механизму.
    #[must_use]
    pub fn of_kem(kem: u8) -> Self {
        match kem {
            5 => Self::PostQuantumHardware,
            4 => Self::PostQuantum,
            _ => Self::Classical,
        }
    }

    /// Номер для хранения: порядок вариантов, начиная с нуля.
    #[must_use]
    pub fn to_u8(self) -> u8 {
        match self {
            Self::Classical => 0,
            Self::PostQuantum => 1,
            Self::PostQuantumHardware => 2,
        }
    }

    /// Обратно из номера; незнакомый номер — `None`, а не классика (И-10).
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

/// Заголовок вместе с диапазонами его полей.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedHeader {
    pub header: Header,
    pub spans: HeaderSpans,
}

impl Header {
    /// Сила файла: сильнейший из авторских слотов ([`Strength`]).
    ///
    /// Без авторского слота (файл по коду-претензии без автора на этом
    /// устройстве) — классика: слабее её механизмов не бывает, и требовать от
    /// просителя нечего.
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

    /// Разобрать заголовок из байтов.
    ///
    /// Тотальна: любой буфер либо разбирается, либо даёт ошибку, но никогда не
    /// паникует. Вызывается **до** проверки подписи, потому что и ключ автора, и
    /// набор алгоритмов лежат внутри заголовка; это не делает вход доверенным, и
    /// разбор обязан выдерживать любой ввод.
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

    /// Закодировать заголовок. Теги пишутся строго по возрастанию.
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

    /// Хеш ядра заголовка: всё, кроме ключевого материала.
    ///
    /// Идёт в связанные данные заворачивания CEK, поэтому завёрнутый ключ нельзя
    /// перенести в контейнер с другим заголовком.
    ///
    /// Из хешируемых байтов вырезаны **две** записи — слоты и завёрнутый CEK.
    /// Обе содержат материал, который сам связан с этим хешем: включив их, мы
    /// получили бы значение, зависящее от самого себя.
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

    /// Хеш политики по её байтовому диапазону.
    ///
    /// Клиент сверяет его с `policy_hash` из лизинга: сервер не должен иметь
    /// возможности выдать лицензию под другие правила, чем подписал автор.
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
                // ЗДЕСЬ ГОДИТСЯ ТОЛЬКО Ed25519, и проверка нужна с тех пор, как
                // `SigAlg` перестал быть одноместным.
                //
                // Номер 2 (RSA-PSS) сборка теперь ИСПОЛНЯЕТ — им подписывает
                // правку редактировавшее устройство, — поэтому `from_u8` его
                // пропускает. Но `suite.sig_alg` описывает подпись АВТОРА, и она
                // заморожена версией 1: проверяется она `verify_strict` над
                // Ed25519 безусловно.
                //
                // Без этой строки заголовок мог бы объявить RSA-PSS, а проверен
                // был бы по Ed25519 — то есть объявление алгоритма снова стало бы
                // украшением. Ровно тот дефект, ради которого заведён
                // `ensure_supported`, только на уровень выше: там «умеем ли», а
                // здесь «в этом ли месте».
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
            // Правило диапазона действует и внутри вложенных map, а не только на
            // верхнем уровне заголовка: иначе оно перестаёт быть свойством
            // КОНТЕЙНЕРА и становится свойством конкретного декодера, а их в
            // крейте несколько — `header`, `content`, `edit`, `footer`, — и все
            // их пришлось бы помнить. Раньше здесь стоял безусловный отказ, то
            // есть необязательного диапазона внутри `suite` не существовало
            // вовсе.
            //
            // «Свойство контейнера», а не «свойство формата», и это уточнение
            // стоило правки: разборщиков в самом крейте несколько, и правило
            // обязано быть одним на всех.
            //
            // Документы протокола (`oc-protocol`) с 2026-09-21 подчиняются ТОМУ
            // ЖЕ правилу и зовут ту же `unknown_tag_action` (`docs/protocol.md`
            // §0.1). До того дня они отвергали любой незнакомый тег, в каком бы
            // диапазоне тот ни стоял, и исключением был один лизинг; вопрос,
            // оставленный решением Р-2 открытым, закрыт тем, что стороны после
            // выпуска обновляются в разное время. Исключение теперь одно и
            // обратное по смыслу: решение автора (`oc_protocol::access`)
            // остаётся строгим, потому что его подпись покрывает не сырые
            // байты, а пересобранное тело.
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

/// Неизвестный алгоритм — тот же класс события, что неизвестное критичное поле:
/// клиент не в состоянии исполнить то, что задумал автор.
fn unsupported(tag: u16) -> FormatError {
    FormatError::UnknownCriticalField { tag }
}

/// Набор символов, допустимый в адресе сервера.
///
/// Печатная часть US-ASCII без пробела: `0x21..=0x7E`. Правило узкое намеренно, и
/// узость его — не про эстетику URL.
///
/// # Зачем ограничивать то, что мы всё равно не разбираем
///
/// Единственное, что делает продукт с этим полем сегодня, — ПЕЧАТАЕТ его человеку
/// (`cc activate`, `cc inspect`), чтобы тот сравнил названные автором адреса с
/// тем, куда собирается идти сам. Согласие человека и есть здесь защитный
/// механизм — а сравнение имеет смысл ровно до тех пор, пока строка не умеет:
///
/// * **двигать курсор и красить экран** — `ESC` (0x1B) открывает управляющую
///   последовательность, и адрес, напечатанный ниже, способен затереть строку,
///   напечатанную выше. Строка «идём туда-то» перестаёт быть правдой, оставаясь
///   на экране;
/// * **переворачивать порядок символов** — U+202E RIGHT-TO-LEFT OVERRIDE
///   показывает `moc.dab` как `bad.com`;
/// * **притворяться другой буквой** — кириллическая `а` (U+0430) и латинская `a`
///   в любом шрифте выглядят одинаково.
///
/// Все три — про ОТОБРАЖЕНИЕ, и все три закрываются одним запретом на источник:
/// печатный ASCII не содержит ни управляющих байтов, ни двунаправленных меток, ни
/// вторых начертаний одной буквы.
///
/// # Почему это не отсекает нелатинские имена
///
/// Потому что у них есть проводная форма: punycode (`xn--…`), которую требует сам
/// DNS. Ограничение совпадает с тем, что и так уходит в сеть, а отсечённое —
/// ровно та U-форма, чьё отображение и есть атака.
///
/// # Почему на записи тоже
///
/// По той же причине, что и нулевой ключ: на записи — чтобы такой контейнер
/// нельзя было выпустить, на разборе — чтобы уже выпущенный нельзя было принять.
/// Односторонняя проверка оставила бы второе.
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

/// Ключ обязан присутствовать по существу, а не только по длине.
///
/// Нулевой ключ — не «значение по умолчанию», а отсутствие ключа, замаскированное
/// под заполненное поле. Для `lease_verify_key` это прямо ломает то, ради чего
/// поле заведено (docs/format.md §2, тег 11): закреплённый автором ключ подписи
/// лизинга — единственное, что мешает поддельному серверу выпускать собственные
/// лизинги. Для `sealing_kid` нулевое значение — точка малого порядка X25519,
/// которую `seal` и так отвергнет, но отвергнет позже и с менее внятной причиной.
///
/// Сравнение обычное: значение публично, лежит в подписанном заголовке и
/// сравнивается с константой, а не с секретом.
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

/// Слоты нумеруются позицией, а не видом.
///
/// Вид лежит **внутри** записи, потому что теги обязаны строго возрастать: будь
/// тегом вид слота, двух получателей в одном файле стало бы невозможно
/// закодировать — а ради этого слоты и заводились.
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

/// Состав полей слота обязан соответствовать его виду.
///
/// Проверка нужна потому, что иначе поля становятся необязательными «в среднем»:
/// слот, запечатывающий секрет и при этом несущий обязательство кода, не
/// означает ничего осмысленного, но структурно корректен — и читатель,
/// столкнувшись с ним, выберет одну из двух трактовок молча.
///
/// Проверяются **все** различия таблицы §2.0, а не только наличие обязательства,
/// и с ними — механизм слота кода-претензии (§2 п.5).
///
/// Запечатывающий слот обязан нести непустой шифртекст: пустой означал бы, что
/// секрета в нём нет, и слот выглядел бы пригодным, ничего не выдавая. Слот
/// кода-претензии обязан нести пустой: непустой `ct` там — байты, за которые
/// никто не отвечает, поскольку читатель их не открывает (доля выводится из
/// кода), и место для скрытого канала внутри подписанного автором заголовка.
///
/// Два оставшихся столбца добавлены пунктом Р-4, и добавлены по тому же аргументу,
/// которым спека запрещает непустой `ct`. Проверялись только `ct` и
/// `claim_commit` — то есть слот кода-претензии мог нести 32 байта `key_fpr` и
/// произвольные 56 байт в `enc` и `nonce`, пройти обе проверки и жить внутри
/// подписанного автором заголовка, не будучи прочитанным никем. Ровно то же
/// «место для скрытого канала», от которого таблица и защищает; спека объявляла
/// таблицу исполняемой целиком, а код исполнял две трети.
///
/// `key_fpr` у кода-претензии запрещён потому, что подтверждать ему нечего: этот
/// слот не запечатывает ни на какой ключ, получателя опознаёт код. Нулевые `enc` и
/// `nonce` — не заглушки «чтобы прошло по структуре», а единственное значение,
/// которое там осмысленно; любое другое означало бы, что читатель чего-то не знает
/// об этом слоте.
///
/// Проверка `key_fpr` **односторонняя**, и это осознанно. Запрет у кода-претензии —
/// да; обязательность у запечатывающих слотов — нет, потому что §2 (тег 6) называет
/// поле необязательным, и требовать его значило бы отвергать файлы, которые
/// открываются. Смысл столбца таблицы — «когда поле есть, оно означает ключ, на
/// который запечатано», а не «оно обязано быть». Первая редакция этой проверки была
/// двусторонней и упала на собственных тестах формата — там слоты без `key_fpr`
/// законны; это ровно тот случай, когда падение теста означало неверную правку, а не
/// устаревший тест.
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
        // МЕХАНИЗМ У СЛОТА КОДА-ПРЕТЕНЗИИ ПРИБИТ К ЕДИНИЦЕ, и это требование §2
        // п.5, записанное там дословно: «объявляет `kem_id = 1` всегда».
        //
        // Причина в спеке названа, и она про БАЙТЫ, а не про стройность: длина
        // нулевого `enc` берётся из механизма, и слот, объявивший P-256, несёт
        // 65 нулей вместо 32. Оба числа проходят проверку «все нули», обе длины
        // законны каждая для своего механизма — то есть `claim.cc` мог быть
        // выпущен в двух разных байтовых видах, оба принимаемые. Для формата,
        // объявленного замороженным, это и есть «байты поехали молча».
        //
        // Проверка стоит и на записи, и на чтении. Опытная проба показала, что
        // до неё слот с `kem_id = 2` и 65 нулями принимали ОБЕ стороны: писатель
        // производил то, что читатель обязан был отвергнуть.
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

/// Длина `enc`, которую эта версия формата умеет проверять, — по механизму.
///
/// `None` означает не «ошибка», а «слот такого механизма эта версия не разбирает,
/// и трогать длины его полей она не вправе».
///
/// Нужна потому, что 32 байта в `enc` — это форма **X25519**, а не форма слота
/// вообще: публичный ключ P-256 занимает 33 или 65 байт, инкапсуляция RSA-OAEP —
/// сотни, гибрид с ML-KEM — больше тысячи. Пока таблица §3.3 задавала `bytes[32]`
/// безусловно, слот на любом другом механизме был не «незнакомым», а **невозможным**:
/// проверка длины стояла в цикле разбора полей и уносила ошибку наружу, отвергая
/// весь контейнер — даже когда рядом лежал собственный, полностью открываемый слот.
/// Обещание §3.3 «слот с незнакомым `kem_id` пропускается, а не отвергает файл»
/// выполнить было нельзя в принципе.
///
/// `match` без `_`: добавление механизма в [`KemAlg`] обязано ломать сборку здесь,
/// рядом с таблицей длин, а не проходить молча и не приниматься под чужую форму.
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

/// Первая версия формата, знающая гибридный слот.
pub const FIRST_HYBRID_VERSION: u16 = 4;

/// `enc` гибрида — шифротекст X-Wing: `ct_M(1088) ‖ ct_X(32)`.
const XWING_CIPHERTEXT_LEN: usize = oc_crypto::xwing::CIPHERTEXT_LEN;

/// Первая версия формата, знающая АППАРАТНЫЙ гибрид MLKEM768-P256.
///
/// Отдельная константа рядом с [`FIRST_HYBRID_VERSION`], а не то же число:
/// механизмы вводятся разными версиями, и общая константа связала бы их судьбы
/// — правка одного двигала бы границу другому.
pub const FIRST_HARDWARE_HYBRID_VERSION: u16 = 5;

/// `enc` аппаратного гибрида: `ct_M(1088) ‖ eph_P256(65)`.
///
/// Переэкспортом из крипты, а не числом: два определения одной длины разошлись
/// бы при первой правке, и заголовок начал бы резать слот не по той границе, по
/// которой его собрали.
const MLKEM_P256_CIPHERTEXT_LEN: usize = oc_crypto::mlkem_p256::CIPHERTEXT_LEN;

/// `key_fpr` аппаратного гибрида: `pk_M(1184) ‖ pk_P256(65)`.
///
/// У этого механизма длины `enc` и `key_fpr` различаются на девяносто шесть
/// байт и обе четырёхзначны — перепутать их легко, а вылезет это у получателя
/// как «файл повреждён». Ради этого таблицы и разведены.
const MLKEM_P256_PUBLIC_LEN: usize = oc_crypto::mlkem_p256::PUBLIC_KEY_LEN;

/// `key_fpr` гибрида — открытая половина X-Wing: `pk_M(1184) ‖ pk_X(32)`.
///
/// Здесь длины `enc` и `key_fpr` РАЗНЫЕ, и это первый механизм, на котором
/// разделение двух таблиц перестало быть предусмотрительностью и стало нужным.
const XWING_PUBLIC_LEN: usize = oc_crypto::xwing::PUBLIC_KEY_LEN;

/// Длина несжатой точки P-256 на проводе: `0x04 ‖ X(32) ‖ Y(32)`.
///
/// Сжатая форма (33 байта) не принимается. Причина не в экономии кода: PCP отдаёт
/// публичный ключ структурой `BCRYPT_ECCKEY_BLOB` и сжатой формы не предлагает
/// вовсе, а две допустимые формы одного ключа дали бы для одного получателя две
/// разные записи слота — и, значит, разошедшиеся `core_hash` и подпись у двух
/// добросовестных реализаций.
pub const P256_PUBLIC_LEN: usize = 65;

/// Длина публичного ключа X25519. Псевдоним ради читаемости таблиц выше: рядом с
/// `P256_PUBLIC_LEN` он говорит, что это длина ключа, а не совпавшее число.
const X25519_PUBLIC_LEN: usize = oc_crypto::seal::PUBLIC_KEY_LEN;

/// Длина `key_fpr` для механизма — ОТДЕЛЬНАЯ функция, а не та же самая.
///
/// У X25519 и P-256 обе длины совпадают, и соблазн обойтись одной таблицей
/// велик. Совпадение случайно: оба поля несут точку кривой. У RSA-OAEP `enc` —
/// инкапсуляция (сотни байт), а `key_fpr` — публичный ключ, и одна мерка для них
/// неверна с первого же применения. Разделение вводится сейчас, пока стоит
/// ничего, а не тогда, когда третий механизм об него сломается.
///
/// `match` без `_` намеренно: добавление члена в [`KemAlg`] обязано ломать
/// сборку здесь, у таблицы длин, а не молча получать поведение соседа.
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

/// Закодировать состав соавторов.
///
/// # Errors
/// Состав не исполним: пуст, длиннее предела, с повтором ключа либо с порогом,
/// которого составом не набрать.
/// Версия, прочитанная к этому моменту разбора.
///
/// Отдельной функцией ради одного: `None` здесь означает «поля версии ещё не
/// было», а теги идут строго по возрастанию и `container_version` — первый.
/// Значит `None` возможен только у заголовка без версии вовсе, и такой заголовок
/// отвергнется ниже. Ноль выбран как заведомо меньший любой настоящей версии:
/// он отправит тег в общий путь, где необязательный диапазон его пропустит.
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

/// Исполним ли состав.
///
/// Правило, которого никто никогда не исполнит, замораживает файл навсегда, и
/// заметить это можно только тем, что он замер. Поэтому проверяется ЗДЕСЬ, на
/// обеих сторонах: и при записи, и при разборе.
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

/// Разобрать состав соавторов.
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
    // Разбор в ДВА прохода, и это не стиль.
    //
    // Первый проход только раскладывает поля по срезам и выясняет, наш ли это слот:
    // вид, механизм, нет ли незнакомого критичного тега. Второй — уже зная, что
    // слот наш, — применяет точные длины.
    //
    // Раньше проход был один, и длина `enc` проверялась в нём же, до того как
    // становилось известно, чей это слот. Из-за этого слот на чужом механизме
    // отвергал весь файл (см. [`expected_enc_len`]), а ветка «незнакомый механизм →
    // пропустить слот» была недостижима: она стоит после цикла.
    //
    // И-8 при этом не ослаблен. Для слота, который эта версия разбирает, длина
    // по-прежнему проверяется на точное соответствие, и несоответствие по-прежнему
    // фатально: короткое не дополняется нулями, длинное не обрезается.
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
            // Неизвестный тег ВНУТРИ слота разбирается тем же правилом диапазона,
            // что и снаружи, но последствие у критичного тега другое: непригоден
            // СЛОТ, а не файл.
            //
            // Молча пропустить критичное поле нельзя. Слот — не пассивный мешок
            // байтов: из него достаётся ключевой материал, и поле, добавленное
            // будущей версией в критичном диапазоне, меняет то, КАК его
            // доставать. Пропустив, клиент открыл бы слот не по тем правилам и
            // решил бы, что всё в порядке.
            //
            // Но и отвергать весь файл нельзя — а раньше делалось именно это, и
            // получалось, что точка расширения, ради которой слоты и заведены,
            // закрыта: любой будущий вид слота с новым критичным полем делал файл
            // нечитаемым для клиентов версии 1, даже когда у них есть собственный
            // вполне открываемый слот. Правило чтения §3.3 звучит иначе: понять
            // хотя бы один пригодный слот, остальные игнорировать. Незнакомый вид
            // слота и незнакомый `kem_id` уже пропускаются именно так —
            // незнакомое критичное поле обязано вести себя так же.
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

/// Обязательное поле слота: есть или ошибка с его тегом.
fn exact(tag: u16, value: Option<&[u8]>) -> Result<&[u8], FormatError> {
    value.ok_or(FormatError::MissingField { tag })
}

/// Срез в массив точной длины. Короткое не дополняется, длинное не обрезается (И-8).
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

    /// ТАБЛИЦЫ ДЛИН МОЛЧАТ РОВНО О ТОМ МЕХАНИЗМЕ, КОТОРОГО СБОРКА НЕ ИСПОЛНЯЕТ.
    ///
    /// Длина и исполнимость — РАЗНЫЕ вопросы, и сводить их в один нельзя: длина
    /// есть функция пары «версия × механизм» (P-256 неизвестен версии 1, гибрид
    /// — версиям до четвёртой), а исполнимость — свойство сборки. Проверяется
    /// поэтому не равенство таблиц, а одно следствие: механизм исполним тогда и
    /// только тогда, когда ХОТЬ ОДНА читаемая версия задаёт ему ОБЕ длины.
    ///
    /// Без этой пробы согласие держалось на памяти: добавить механизм в
    /// [`oc_crypto::seal::supports_kem`] и забыть про таблицу здесь значит
    /// получить слот, который сборка умеет открыть, а разбор молча пропускает
    /// как чужой. Обратная забывчивость хуже: форма без исполнения.
    ///
    /// Члены берутся из разбора, а не списком по памяти, — новый номер реестра
    /// попадёт сюда сам.
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

    /// СОСТАВ СОАВТОРОВ ПЕРЕЖИВАЕТ КРУГ КОДИРОВАНИЯ.
    #[test]
    fn a_coauthor_roster_survives_the_encoding_round_trip() {
        let mut header = sample();
        header.coauthors = Some(Coauthors { threshold: 2, keys: vec![[1u8; 32], [2u8; 32], [3u8; 32]] });
        let bytes = header.encode().unwrap();
        let back = Header::decode(&bytes).unwrap().header;
        assert_eq!(back.coauthors, header.coauthors);
    }

    /// «КВОРУМА НЕТ» — ЗАКОННОЕ УТВЕРЖДЕНИЕ, И ОНО ЗАПИСЫВАЕТСЯ.
    ///
    /// Ноль с пустым составом отличается от отсутствия тега: первое сказал
    /// автор, второе означает, что он про соавторов не говорил вовсе.
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

    /// НЕИСПОЛНИМЫЙ СОСТАВ ОТВЕРГАЕТСЯ ПРИ ЗАПИСИ, А НЕ ЗАМОРАЖИВАЕТ ФАЙЛ.
    ///
    /// Правило, которого никто никогда не исполнит, замечается только тем, что
    /// файл замер. Поэтому проверка стоит на обеих сторонах, и здесь — на той,
    /// где ещё можно передумать.
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

    /// ЧИТАТЕЛЬ ВЕРСИИ 3 СОСТАВ ПРОПУСКАЕТ, А НЕ ОТВЕРГАЕТ ФАЙЛ.
    ///
    /// Ради этого тег и стоит в необязательном диапазоне: состав соавторов не
    /// меняет ни ключей, ни правил доступа, и отказывать из-за него значило бы
    /// отказывать без причины.
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

    /// Вставить ВТОРУЮ запись с тем же тегом сразу за первой.
    ///
    /// Сырыми байтами, а не через [`TlvWriter`]: писатель дубликат не пропустит
    /// — в том и смысл, — а проверяется здесь ЧИТАТЕЛЬ. И вставлять надо именно
    /// ВПЛОТНУЮ: дописанная в конец копия отличалась бы от предыдущего тега в
    /// меньшую сторону и ловилась бы как обычная перестановка, то есть проба
    /// проверяла бы не то, что заявляет.
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

    /// Пересобрать заголовок, подменив значение одного поля.
    fn with_field_value(bytes: &[u8], tag: u16, value: &[u8]) -> Vec<u8> {
        let mut reader = TlvReader::new(bytes);
        let mut w = TlvWriter::new();
        while let Some(field) = reader.next_field().unwrap() {
            let replacement = if field.tag == tag { value } else { field.value };
            w.put(field.tag, replacement).unwrap();
        }
        w.finish().to_vec()
    }

    /// И-7 НА ПУТИ: заголовок с ДУБЛИРОВАННЫМ тегом отвергается разбором.
    ///
    /// Возрастание тегов ловила одна-единственная проба, и та — на самом
    /// [`TlvReader`]. Примитив и путь — разные вещи: между ними лежит
    /// [`Header::decode`], который на дубликате просто перезаписывал бы
    /// переменную последним значением. Тогда две разные последовательности
    /// байтов означали бы один заголовок, а `core_hash` и подпись автора
    /// считались бы по одним байтам, тогда как решение принималось бы по
    /// другим — ровно то расхождение, ради запрета которого возрастание и
    /// введено.
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

    /// И-8 НА ПУТИ: поле на байт длиннее (и на байт короче) положенного — отказ.
    ///
    /// Точную длину ловила одна проба, и та звала примитив `Field::array`
    /// напрямую. Проба, обходящая проверяемый путь, зеленеет именно тогда,
    /// когда путь сломан: обрежь [`Header::decode`] длинное значение до
    /// шестнадцати байт — и `file_id` возьмётся из тех байтов, которые выбрал
    /// противник, а проба примитива этого не увидит.
    ///
    /// Обе стороны в одной пробе, потому что И-8 запрещает обе: короткое не
    /// дополняется нулями, длинное не обрезается.
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

    /// ВЫРЕЗАНА ЗАПИСЬ ЦЕЛИКОМ — ТЕГ, ДЛИНА И ЗНАЧЕНИЕ, — А НЕ ОДНО ЗНАЧЕНИЕ.
    ///
    /// Сосед выше (`..._ignores_the_key_material_but_notices_everything_else`)
    /// этого НЕ стережёт, и стоит сказать почему: он подменяет содержимое слота
    /// и завёрнутый ключ, НЕ МЕНЯЯ ИХ ДЛИНЫ — `ct` там как был 48 байт, так и
    /// остаётся, а `wrapped_cek` пришпилен к 72 байтам инвариантом И-2. Вырежи
    /// код одно значение, оставив тег с длиной, — оставленные байты у обоих
    /// заголовков совпадут байт в байт, хеши сойдутся, и проба промолчит.
    /// Ловили это до сих пор ТОЛЬКО замороженные векторы, а они говорят «байты
    /// не сошлись на позиции N», и по такому сообщению виновника не найти.
    ///
    /// Здесь ожидаемое значение считается ЗАНОВО и независимо: байты заголовка
    /// склеиваются в обход обоих диапазонов записей. Это вторая запись правила
    /// И-3 — «`SHA-256("CC/v1/core-hash" ‖ 0x00 ‖ Header без этих записей)`», —
    /// и расхождение с первой означает, что вырез сдвинулся. Запись 17 закрыта
    /// только так: длина у неё постоянная, поэтому поведенческого близнеца,
    /// вроде пробы ниже, для неё не существует в принципе.
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

    /// ДВА ЗАГОЛОВКА, РАЗЛИЧНЫЕ ТОЛЬКО ЧИСЛОМ СЛОТОВ, ДАЮТ ОДИН ХЕШ ЯДРА.
    ///
    /// Поведенческий близнец пробы выше — и единственный вид подмены, который
    /// ловится БЕЗ второго счёта хеша: разное число слотов даёт разную ДЛИНУ
    /// записи 10, то есть разные байты длины. Оставь их код в хешируемых
    /// байтах — и добавление получателя меняло бы `core_hash`, а с ним AAD
    /// заворачивания CEK и подпись автора. То есть добавить получателя стало бы
    /// нельзя, не перевыпустив файл, — ровно свойство, которое И-3 отрицает.
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

    /// Запись `authority` с одним адресом и ЗАВЕДОМО НЕНУЛЕВЫМИ ключами.
    ///
    /// Ненулевые здесь — не украшение. Прежняя редакция пробы про адрес ставила
    /// нулевые `sealing_kid` и `lease_verify_key`, а нулевой ключ отвергается
    /// `check_key_present` как `DegenerateKey` — значит `is_err()` держался
    /// посторонней причиной и оставался бы верен при полностью снятой проверке
    /// адреса. Проба про адрес обязана отличать отказ по адресу от отказа по
    /// ключу, и единственный способ — не давать второму повода сработать.
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

    /// Адрес — ПЕЧАТНЫЙ ASCII, и это не то же самое, что «корректный UTF-8».
    ///
    /// Все три случая ниже — законный UTF-8, то есть проверку `from_utf8` они
    /// проходят. Отвергает их `check_address_charset`, и каждый взят из её
    /// докстроки: управляющая последовательность красит экран, RIGHT-TO-LEFT
    /// OVERRIDE переворачивает показанное имя, кириллическая `а` неотличима от
    /// латинской. Без отдельной пробы этот запрет не сторожил никто:
    /// `BadAddressByte` не встречался ни в одном тесте.
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
