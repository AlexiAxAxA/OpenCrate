//! Документы ДВЕРИ ДЕЙСТВИЙ: грант действий, просьба об исполнении и лиза.
//!
//! # Что это за разговор и чем он отличается от гранта агента
//!
//! Грант агента ([`crate::agent::AgentGrant`]) отвечает на вопрос «этой двери на
//! это поддерево и до этого часа», то есть раздаёт ЧТЕНИЕ. Здесь другой вопрос —
//! «этой двери толкнуть эту ветку этого remote», — и свести его к первому
//! нельзя: у чтения предмет файл, а у действия предмет АРГУМЕНТЫ, которых в
//! момент выдачи ещё нет. Поэтому грант действий называет не действия, а
//! ОГРАНИЧИТЕЛИ на них, а совпадение аргументов с ограничителями проверяется
//! дважды: дверью до сети ([`crate::action::args_within`]) и сервером перед выдачей лизы.
//!
//! # Почему capability, а не правило
//!
//! Агент в клетке не имеет средств действия — ни сети, ни ключа, ни записи в
//! дерево. Отказ здесь держится не на том, что кто-то сказал «нельзя», а на
//! отсутствии средства: выписать себе лизу модели нечем, а аргументы вне
//! ограничителей сервер не подпишет. Инъекция вправе уговорить модель попросить;
//! просьба — это всё, чего она добьётся.
//!
//! # Три документа и три разных доверия
//!
//! * [`crate::action::ActionGrant`] подписан ключом АВТОРА — тем же, что заголовок контейнера
//!   и грант агента. Раскладка `подпись(64) ‖ тело`, проверка `verify_strict` по
//!   сырым байтам ДО разбора (И-5, И-6).
//! * [`crate::action::ActionRequest`] НЕ ПОДПИСАН вовсе, как [`crate::access::AskAccess`]: ключ
//!   двери согласовательный, подписывать им нечем. Имя просителя не берётся из
//!   документа — сервер сверяет `door_fpr` с отпечатком, доказанным в
//!   рукопожатии, константным временем.
//! * [`crate::action::ActionLease`] подписана СЕРВЕРОМ, ключом подписи лизингов
//!   (`authority.lease_verify_key` из заголовка, закреплённый подписью автора).
//!   Метка своя ([`oc_crypto::label::ACTION_LEASE`]): ключ один и тот же, и без
//!   разных доменов разрешение открыть файл годилось бы разрешением толкнуть
//!   ветку.
//!
//! # Почему `force` невыразим, а не запрещён
//!
//! У [`crate::action::Args::GitPush`] нет поля под него — ни обязательного, ни необязательного.
//! Запрет, записанный правилом, требует места, где правило исполняется, и такого
//! места у нас два (дверь и сервер): один путь чинят, соседний забывают.
//! Отсутствие поля исполняется разборщиком: аргумент с лишним критичным тегом
//! отвергается на разборе, а необязательный тег до исполнителя не доходит — он
//! читает структуру, а не байты.

use oc_format::FormatError;
use oc_format::tlv::{TlvReader, TlvWriter};

/// Длина подписи впереди документа — как у гранта агента и у лизинга.
pub const SIGNATURE_LEN: usize = 64;

/// Сколько живёт лиза действия, в секундах.
///
/// Тридцать: столько, чтобы дверь успела исполнить одно действие, и не столько,
/// чтобы лиза пережила отзыв гранта сколько-нибудь заметно. Кеша лиз действий
/// нет вовсе — они одноразовые, и переживать им нечего.
pub const ACTION_LEASE_SECONDS: i64 = 30;

/// Сколько правил помещается в один грант действий.
///
/// Предел нужен по той же причине, что [`crate::agent::MAX_GRANT_FILES`]: длину
/// списка называет чужая сторона. Тридцать два — набор, который человек ещё в
/// состоянии охватить одним решением; дверь, которой нужно больше, получает
/// второй грант, и это честнее одного, о составе которого автор уже не судит.
pub const MAX_ACTION_RULES: usize = 32;

/// Наибольшая длина короткого имени: `remote`, `branch`, `host`, `secret_ref`.
pub const MAX_ACTION_NAME: usize = 128;

/// Наибольшая длина пути и префикса пути.
pub const MAX_ACTION_PATH: usize = 512;

/// Наибольшее тело HTTP-запроса — 1 МиБ (спека этапа 2, §3).
///
/// Величина проверяется на РАЗБОРЕ и ещё раз в [`crate::action::args_within`]: первое закрывает
/// документ, второе — исполнение. Поток наружу этап 2 не делает вовсе, и тело
/// больше мегабайта означало бы, что дверь копит его в памяти.
pub const MAX_BODY_LEN: u32 = 1024 * 1024;

/// Реестр видов действий. Номера нормативны: они попадают в подписанное тело.
///
/// Расширять, не переименовывать, сожжённые не переиспользовать (CLAUDE.md,
/// «Как менять формат», правило 3). Незнакомый номер отвергается НА РАЗБОРЕ, а
/// не на первой попытке исполнить: вид, которого дверь не умеет, — это правило,
/// которое никогда не сработает, и узнать об этом лучше здесь (правило 4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ActionKind {
    /// `git push <remote> HEAD:<branch>` из контейнера двери.
    GitPush = 1,
    /// Удаление файла внутри дерева.
    TreeRemove = 2,
    /// Переименование внутри дерева.
    TreeRename = 3,
    /// Запрос `https` наружу.
    HttpRequest = 4,
}

impl ActionKind {
    /// Номер вида на проводе.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    /// Вид по номеру с провода.
    ///
    /// # Errors
    /// [`FormatError::BadFieldLength`] с переданным тегом — номер вне реестра.
    pub const fn from_u16(value: u16, tag: u16) -> Result<Self, FormatError> {
        match value {
            1 => Ok(Self::GitPush),
            2 => Ok(Self::TreeRemove),
            3 => Ok(Self::TreeRename),
            4 => Ok(Self::HttpRequest),
            _ => Err(FormatError::BadFieldLength { tag, len: 2 }),
        }
    }
}

/// Метод HTTP. Реестр, а не строка, и это не экономия байтов.
///
/// Строка на проводе означала бы, что множество методов бесконечно, а
/// «`method ∈ methods`» — сравнение текста, выбранного чужой стороной. С
/// реестром незнакомый метод отвергается на разборе, и метода, которого нет в
/// этом списке, дверь не исполнит никогда.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Method {
    Get = 1,
    Head = 2,
    Post = 3,
    Put = 4,
    Patch = 5,
    Delete = 6,
}

impl Method {
    /// Номер метода на проводе.
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    /// Метод по номеру с провода.
    ///
    /// # Errors
    /// [`FormatError::BadFieldLength`] с переданным тегом — номер вне реестра.
    pub const fn from_u8(value: u8, tag: u16) -> Result<Self, FormatError> {
        match value {
            1 => Ok(Self::Get),
            2 => Ok(Self::Head),
            3 => Ok(Self::Post),
            4 => Ok(Self::Put),
            5 => Ok(Self::Patch),
            6 => Ok(Self::Delete),
            _ => Err(FormatError::BadFieldLength { tag, len: 1 }),
        }
    }
}

/// Ограничитель: что именно дверь вправе просить у сервера по этому виду.
///
/// Вариант несёт вид: поле `kind` у [`ActionRule`] от него ПРОИЗВОДНО и сверяется
/// на записи и на чтении. Держать номер отдельно всё же нужно — он идёт на
/// провод первым и по нему разборщик выбирает, какие теги ждать; без него
/// разбор ограничителя был бы угадыванием по составу полей.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Constraint {
    GitPush {
        remote: String,
        branch: String,
    },
    TreeRemove {
        prefix: String,
    },
    TreeRename {
        from_prefix: String,
        to_prefix: String,
    },
    HttpRequest {
        host: String,
        /// Строго по возрастанию, без повторов: из возрастания бесплатно
        /// следует, что один набор методов — одна последовательность байтов.
        methods: Vec<Method>,
        path_prefix: String,
        /// Имя ссылки на секрет в окружении ДВЕРИ. Агент называет ссылку, а не
        /// значение; значения он не видит никогда.
        secret_ref: Option<String>,
    },
}

impl Constraint {
    /// Вид, которому принадлежит ограничитель.
    #[must_use]
    pub const fn kind(&self) -> ActionKind {
        match self {
            Self::GitPush { .. } => ActionKind::GitPush,
            Self::TreeRemove { .. } => ActionKind::TreeRemove,
            Self::TreeRename { .. } => ActionKind::TreeRename,
            Self::HttpRequest { .. } => ActionKind::HttpRequest,
        }
    }
}

/// Одно правило гранта: вид, ограничитель, предел числа исполнений и два флага.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionRule {
    pub kind: ActionKind,
    pub constraint: Constraint,
    /// Сколько раз действие можно исполнить. `0` — без предела.
    ///
    /// Счёт ведёт сервер и ПО ЦЕПОЧКЕ: исполнение потомка списывается и с
    /// предка, иначе делегирование умножало бы предел.
    pub max_uses: u32,
    /// Требуется живое «да» владельца на КАЖДОЕ исполнение.
    pub confirm: bool,
    /// Можно ли передать это правило потомку. Умолчание — `false`.
    pub delegable: bool,
}

/// Грант действий — подписан автором, привязан к файловому гранту.
///
/// Якорь здесь `grant_id`, а не файл: у действия нет контейнера с заголовком, из
/// которого берётся `author_key`. Ключ проверки — тот, что сервер записал при
/// регистрации файлового гранта; держатель, потолок срока и погашение — оттуда
/// же. Цепочка одна, второй сущности отзыва не появляется.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionGrant {
    pub grant_id: [u8; 16],
    pub rules: Vec<ActionRule>,
    pub issued_at: i64,
    pub expires_at: i64,
    pub author_key: [u8; 32],
    pub signature: [u8; SIGNATURE_LEN],
}

/// Аргументы одного исполнения.
///
/// Поля ровно те, что ограничитель умеет проверить, и ни одного сверх. `force`
/// здесь нет — см. докстроку модуля.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Args {
    GitPush {
        remote: String,
        branch: String,
    },
    TreeRemove {
        path: String,
    },
    TreeRename {
        from: String,
        to: String,
    },
    HttpRequest {
        /// Есть и здесь, хотя план его не выписал: лиза обязана нести аргументы
        /// ДОСЛОВНО (спека §4.3), а дверь исполняет то, что в лизе. Возьми она
        /// хост из гранта, а остальное из лизы — исполняемый адрес собирался бы
        /// из двух документов, и «аргументы лизы равны запрошенным» перестало бы
        /// значить «адрес тот же».
        host: String,
        method: Method,
        path: String,
        /// Хеш тела. Само тело на сервер не уходит: серверу незачем видеть, что
        /// дверь посылает наружу, а привязать лизу к телу хешем достаточно.
        body_digest: [u8; 32],
        body_len: u32,
    },
}

impl Args {
    /// Вид, к которому относятся аргументы.
    #[must_use]
    pub const fn kind(&self) -> ActionKind {
        match self {
            Self::GitPush { .. } => ActionKind::GitPush,
            Self::TreeRemove { .. } => ActionKind::TreeRemove,
            Self::TreeRename { .. } => ActionKind::TreeRename,
            Self::HttpRequest { .. } => ActionKind::HttpRequest,
        }
    }
}

/// Просьба двери об исполнении. НЕ ПОДПИСАНА — см. докстроку модуля.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionRequest {
    pub grant_id: [u8; 16],
    /// Имя просителя. Сервер сверяет его с доказанным в рукопожатии отпечатком
    /// константным временем; из документа оно НЕ принимается на веру.
    pub door_fpr: [u8; 32],
    pub kind: ActionKind,
    pub args: Args,
    /// Случайное значение двери: им сервер отличает повтор от нового исполнения.
    pub nonce: [u8; 16],
    /// Записка — правило то же, что у просьбы о доступе.
    pub note: String,
}

/// Лиза действия — подписана сервером ключом подписи лизингов.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionLease {
    pub grant_id: [u8; 16],
    pub door_fpr: [u8; 32],
    pub kind: ActionKind,
    /// Аргументы ДОСЛОВНО: дверь исполняет то, что в лизе, а не то, что просила.
    pub args: Args,
    pub nonce: [u8; 16],
    pub issued_at: i64,
    pub expires_at: i64,
    pub seq: u64,
    pub signature: [u8; SIGNATURE_LEN],
}

/// Реестр тегов гранта действий. Возрастание строгое, критичность по диапазону.
pub mod grant_tag {
    /// Файловый грант, к которому привязан. `bytes[16]`.
    pub const GRANT_ID: u16 = 1;
    /// Список правил: вложенный TLV с нумерацией позицией.
    pub const RULES: u16 = 2;
    /// Момент выдачи. `i64le`, секунды.
    pub const ISSUED_AT: u16 = 3;
    /// Момент истечения. `i64le`, секунды.
    pub const EXPIRES_AT: u16 = 4;
    /// Ключ автора, которым грант подписан. `bytes[32]`.
    pub const AUTHOR_KEY: u16 = 5;
}

/// Теги ОДНОГО правила внутри списка.
pub mod rule_tag {
    /// Вид действия. `u16le`.
    pub const KIND: u16 = 1;
    /// Ограничитель: вложенный TLV, состав тегов зависит от вида.
    pub const CONSTRAINT: u16 = 2;
    /// Предел числа исполнений, `u32le`; `0` — без предела.
    pub const MAX_USES: u16 = 3;
    /// Требуется ли одобрение владельца на каждое исполнение. `u8`, 0 или 1.
    pub const CONFIRM: u16 = 4;
    /// Можно ли делегировать. `u8`, 0 или 1.
    pub const DELEGABLE: u16 = 5;
}

/// Теги ограничителей И аргументов — реестр ОДИН на оба.
///
/// Один, а не два, намеренно: спека требует, чтобы аргументы шли «теми же
/// тегами, что ограничители» (§4.2). Два реестра с одинаковым смыслом и разными
/// номерами — это приглашение проверить `remote` из одного против `branch` из
/// другого, и ошибка эта не поймалась бы ничем, кроме глаз.
///
/// Виды пользуются НЕПЕРЕСЕКАЮЩИМИСЯ подмножествами, и каждое возрастает: то,
/// что не ждёт разборщик этого вида, отвергается как незнакомый критичный тег.
pub mod field_tag {
    /// `git.push`: имя remote. Текст.
    pub const REMOTE: u16 = 1;
    /// `git.push`: имя ветки. Текст.
    pub const BRANCH: u16 = 2;
    /// `tree.remove`: префикс (в ограничителе) или путь (в аргументах).
    pub const PATH: u16 = 3;
    /// `tree.rename`: откуда.
    pub const FROM: u16 = 4;
    /// `tree.rename`: куда.
    pub const TO: u16 = 5;
    /// `http.request`: хост, точно, без масок.
    pub const HOST: u16 = 6;
    /// `http.request`: методы — по байту на метод, строго по возрастанию. В
    /// аргументах список длины один: метод у исполнения ровно один.
    pub const METHODS: u16 = 7;
    /// `http.request`: префикс пути (в ограничителе) или путь (в аргументах).
    pub const PATH_PREFIX: u16 = 8;
    /// `http.request`: имя ссылки на секрет в окружении двери. Только в
    /// ограничителе; в аргументах его нет — секрет выбирает грант, не агент.
    pub const SECRET_REF: u16 = 9;
    /// `http.request`: хеш тела. Только в аргументах. `bytes[32]`.
    pub const BODY_DIGEST: u16 = 10;
    /// `http.request`: длина тела. Только в аргументах. `u32le`.
    pub const BODY_LEN: u16 = 11;
}

/// Реестр тегов просьбы.
pub mod request_tag {
    pub const GRANT_ID: u16 = 1;
    pub const DOOR_FPR: u16 = 2;
    pub const KIND: u16 = 3;
    pub const ARGS: u16 = 4;
    pub const NONCE: u16 = 5;
    pub const NOTE: u16 = 6;
}

/// Реестр тегов лизы.
pub mod lease_tag {
    pub const GRANT_ID: u16 = 1;
    pub const DOOR_FPR: u16 = 2;
    pub const KIND: u16 = 3;
    pub const ARGS: u16 = 4;
    pub const NONCE: u16 = 5;
    pub const ISSUED_AT: u16 = 6;
    pub const EXPIRES_AT: u16 = 7;
    pub const SEQ: u16 = 8;
}

// ----------------------------------------------------------------------------
// Отказ проверок аргументов и сужения.
// ----------------------------------------------------------------------------

/// Почему аргументы не приняты или сужение не состоялось.
///
/// Свой род ошибки, а не вариант [`FormatError`], и довод тот же, что у
/// [`crate::agent::ChainRefusal`]: «аргумент вне ограничителя» — событие
/// ОТНОШЕНИЯ между двумя документами, а не поля TLV, и номера тега у него нет.
///
/// Ограничитель назван ПОИМЁННО: спека требует отказывать «с названием
/// ограничителя» (§7), а «аргументы вне гранта» без имени не говорит человеку
/// ничего и не даёт агенту исправить просьбу.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionRefusal {
    /// Аргументы не того вида, что правило.
    WrongKind,
    /// Значение обязано совпадать с названным в гранте, и не совпало.
    NotEqual { limiter: &'static str },
    /// Путь не лежит под префиксом гранта — сравнение ПО КОМПОНЕНТАМ.
    OutsidePrefix { limiter: &'static str },
    /// Путь не той формы: `..`, абсолютный, пустой компонент, чужой символ.
    BadPath { limiter: &'static str },
    /// Метода нет в списке разрешённых.
    MethodNotAllowed,
    /// Тело длиннее [`MAX_BODY_LEN`].
    BodyTooLarge { len: u32 },
    /// Правило требует одобрения владельца и потому не делегируется.
    ConfirmNotDelegable,
    /// Правило не помечено `delegable`.
    NotDelegable,
    /// Потомку выписано больше исполнений, чем есть у родителя.
    MoreUses,
    /// Ограничитель потомка ШИРЕ родительского.
    WiderLimiter { limiter: &'static str },
    /// Потомок назвал другую ссылку на секрет или добавил её там, где её нет.
    SecretRefChanged,
}

impl core::fmt::Display for ActionRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::WrongKind => f.write_str("аргументы не того вида действия, что правило гранта"),
            Self::NotEqual { limiter } => {
                write!(f, "значение не совпадает с названным в гранте ограничителем «{limiter}»")
            }
            Self::OutsidePrefix { limiter } => {
                write!(f, "путь лежит вне префикса «{limiter}», названного в гранте")
            }
            Self::BadPath { limiter } => {
                write!(f, "путь у ограничителя «{limiter}» не той формы: разрешён относительный путь без «..»")
            }
            Self::MethodNotAllowed => {
                f.write_str("метода нет в списке разрешённых этим грантом")
            }
            Self::BodyTooLarge { len } => {
                write!(f, "тело длиной {len} байт больше разрешённого мегабайта")
            }
            Self::ConfirmNotDelegable => f.write_str(
                "правило требует одобрения владельца на каждое исполнение и потому не делегируется",
            ),
            Self::NotDelegable => {
                f.write_str("правило не помечено как делегируемое: потомку его передать нельзя")
            }
            Self::MoreUses => {
                f.write_str("потомку выписано больше исполнений, чем разрешено родителю")
            }
            Self::WiderLimiter { limiter } => {
                write!(f, "ограничитель «{limiter}» у потомка шире родительского")
            }
            Self::SecretRefChanged => f.write_str(
                "потомок назвал другую ссылку на секрет: добавить или сменить её делегирование не вправе",
            ),
        }
    }
}

// ----------------------------------------------------------------------------
// Проверка аргументов против ограничителя и сужения при делегировании.
// ----------------------------------------------------------------------------

/// Аргументы лежат в ограничителях правила?
///
/// Чистая: ни часов, ни состояния. Зовётся ДВАЖДЫ — дверью до сети (чтобы отказ
/// пришёл словами и не стоил разговора) и сервером перед выдачей лизы (потому
/// что дверь — чужая сторона, и её проверка сервера не касается).
///
/// # Errors
/// [`ActionRefusal`] с именем ограничителя, на котором проверка разошлась.
pub fn args_within(rule: &ActionRule, args: &Args) -> Result<(), ActionRefusal> {
    // Вид сверяется ПЕРВЫМ: без этого дальнейший `match` выбирал бы ветвь по
    // аргументам, а ограничитель брал бы из правила другого вида.
    if rule.kind != args.kind() || rule.constraint.kind() != args.kind() {
        return Err(ActionRefusal::WrongKind);
    }
    match (&rule.constraint, args) {
        (
            Constraint::GitPush { remote, branch },
            Args::GitPush { remote: want_remote, branch: want_branch },
        ) => {
            // Равенство, а не вложенность: ветка `agent/work-2` не «под»
            // `agent/work`, она другая ветка, и толкать в неё грант не давал.
            if remote != want_remote {
                return Err(ActionRefusal::NotEqual { limiter: "remote" });
            }
            if branch != want_branch {
                return Err(ActionRefusal::NotEqual { limiter: "branch" });
            }
            Ok(())
        }
        (Constraint::TreeRemove { prefix }, Args::TreeRemove { path }) => {
            under_tree_prefix(prefix, path, "prefix")
        }
        (
            Constraint::TreeRename { from_prefix, to_prefix },
            Args::TreeRename { from, to },
        ) => {
            under_tree_prefix(from_prefix, from, "from_prefix")?;
            under_tree_prefix(to_prefix, to, "to_prefix")
        }
        (
            Constraint::HttpRequest { host, methods, path_prefix, secret_ref: _ },
            Args::HttpRequest { host: want_host, method, path, body_digest: _, body_len },
        ) => {
            if host != want_host {
                return Err(ActionRefusal::NotEqual { limiter: "host" });
            }
            if !methods.contains(method) {
                return Err(ActionRefusal::MethodNotAllowed);
            }
            // Форма пути проверяется ЗДЕСЬ, а не только на разборе документа:
            // `args_within` зовут и на структуре, собранной в памяти двери, — до
            // того как из неё получится хоть один байт на провод.
            if check_http_path(path, field_tag::PATH_PREFIX).is_err()
                || check_http_path(path_prefix, field_tag::PATH_PREFIX).is_err()
            {
                return Err(ActionRefusal::BadPath { limiter: "path_prefix" });
            }
            if !path_under(path_prefix, path) {
                return Err(ActionRefusal::OutsidePrefix { limiter: "path_prefix" });
            }
            if *body_len > MAX_BODY_LEN {
                return Err(ActionRefusal::BodyTooLarge { len: *body_len });
            }
            Ok(())
        }
        // Недостижимо: вид сверен выше, и каждый вид имеет ровно один вариант
        // ограничителя и ровно один вариант аргументов. Ветвь стоит потому, что
        // `match` обязан быть полным, и отвечает она ЗАПРЕТОМ (И-10): неясность
        // — это отказ, а не «наверное, можно».
        _ => Err(ActionRefusal::WrongKind),
    }
}

/// Путь внутри дерева: сначала форма, потом префикс.
///
/// Порядок именно такой: `"src/../../etc"` формально начинается с компонента
/// `src`, то есть проверку префикса прошёл бы. Форма обязана идти первой.
fn under_tree_prefix(
    prefix: &str,
    path: &str,
    limiter: &'static str,
) -> Result<(), ActionRefusal> {
    if check_tree_path(path, field_tag::PATH).is_err()
        || check_tree_path(prefix, field_tag::PATH).is_err()
    {
        return Err(ActionRefusal::BadPath { limiter });
    }
    if path_under(prefix, path) {
        Ok(())
    } else {
        Err(ActionRefusal::OutsidePrefix { limiter })
    }
}

/// Правило потомка не шире родительского?
///
/// # Errors
/// [`ActionRefusal`] с именем ограничителя, на котором потомок расширил родителя.
pub fn narrower(child: &ActionRule, parent: &ActionRule) -> Result<(), ActionRefusal> {
    if child.kind != parent.kind {
        return Err(ActionRefusal::WrongKind);
    }
    // `confirm` проверяется ПЕРЕД `delegable`, и это не вкусовщина: живое «да»
    // владельца выписано на КОНКРЕТНУЮ дверь, и передать его потомку нельзя
    // никаким флагом. Правило, требующее одобрения, не делегируется, даже если
    // автор по недосмотру пометил его делегируемым, — и человек, читающий
    // отказ, узнаёт настоящую причину, а не «не помечено».
    if parent.confirm {
        return Err(ActionRefusal::ConfirmNotDelegable);
    }
    // «`delegable` только снимается» исполняется так: у родителя он обязан быть
    // поднят, иначе передавать нечего. Потомок вправе оставить его или снять —
    // поднять из снятого он не может, потому что снятое правило сюда не дойдёт.
    if !parent.delegable {
        return Err(ActionRefusal::NotDelegable);
    }
    if !uses_within(child.max_uses, parent.max_uses) {
        return Err(ActionRefusal::MoreUses);
    }
    match (&child.constraint, &parent.constraint) {
        (
            Constraint::GitPush { remote, branch },
            Constraint::GitPush { remote: parent_remote, branch: parent_branch },
        ) => {
            if remote != parent_remote {
                return Err(ActionRefusal::WiderLimiter { limiter: "remote" });
            }
            if branch != parent_branch {
                return Err(ActionRefusal::WiderLimiter { limiter: "branch" });
            }
            Ok(())
        }
        (
            Constraint::TreeRemove { prefix },
            Constraint::TreeRemove { prefix: parent_prefix },
        ) => narrower_prefix(parent_prefix, prefix, "prefix"),
        (
            Constraint::TreeRename { from_prefix, to_prefix },
            Constraint::TreeRename {
                from_prefix: parent_from,
                to_prefix: parent_to,
            },
        ) => {
            narrower_prefix(parent_from, from_prefix, "from_prefix")?;
            narrower_prefix(parent_to, to_prefix, "to_prefix")
        }
        (
            Constraint::HttpRequest { host, methods, path_prefix, secret_ref },
            Constraint::HttpRequest {
                host: parent_host,
                methods: parent_methods,
                path_prefix: parent_prefix,
                secret_ref: parent_secret,
            },
        ) => {
            if host != parent_host {
                return Err(ActionRefusal::WiderLimiter { limiter: "host" });
            }
            if !methods.iter().all(|m| parent_methods.contains(m)) {
                return Err(ActionRefusal::WiderLimiter { limiter: "methods" });
            }
            narrower_prefix(parent_prefix, path_prefix, "path_prefix")?;
            // Ссылку на секрет потомок вправе СНЯТЬ и не вправе ни сменить, ни
            // придумать: имя ссылки выбирает автор, и потомок, назвавший другое,
            // получил бы заголовок `Authorization` с чужим секретом двери.
            match (secret_ref, parent_secret) {
                (None, _) => Ok(()),
                (Some(mine), Some(theirs)) if mine == theirs => Ok(()),
                _ => Err(ActionRefusal::SecretRefChanged),
            }
        }
        // Недостижимо: виды сверены выше. Ответ — запрет (И-10).
        _ => Err(ActionRefusal::WrongKind),
    }
}

/// Предел потомка не шире родительского, где `0` означает «без предела».
///
/// Число `0` МЕНЬШЕ любого предела как число и БОЛЬШЕ любого как смысл. Ровно
/// здесь и жила бы дыра, если сравнивать их напрямую: потомок с `max_uses = 0`
/// получил бы бесконечность от родителя, у которого её нет.
const fn uses_within(child: u32, parent: u32) -> bool {
    if parent == 0 {
        return true;
    }
    child != 0 && child <= parent
}

/// Префикс потомка лежит под родительским — по компонентам.
fn narrower_prefix(
    parent: &str,
    child: &str,
    limiter: &'static str,
) -> Result<(), ActionRefusal> {
    if path_under(parent, child) {
        Ok(())
    } else {
        Err(ActionRefusal::WiderLimiter { limiter })
    }
}

// ----------------------------------------------------------------------------
// Форма текстовых полей.
// ----------------------------------------------------------------------------

/// Символы, из которых состоит имя remote: буквы, цифры, `-`, `_`, `.`.
fn name_char_ok(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.')
}

/// Короткое имя с проводной формой: `remote`, и по тем же правилам — часть
/// прочих.
///
/// Отказ — [`FormatError::BadAddressByte`], а не [`FormatError::BadNoteChar`], и
/// это выбор, а не случайность: записка — фраза на любом языке, и запрещены в
/// ней только опасные категории, а здесь поле имеет ПРОВОДНУЮ ФОРМУ и обязано
/// быть печатным ASCII. Ровно так спека и описывает разницу двух отказов.
fn check_name(text: &str, tag: u16) -> Result<(), FormatError> {
    if text.is_empty() || text.len() > MAX_ACTION_NAME {
        return Err(FormatError::BadFieldLength { tag, len: text.len() });
    }
    if let Some(byte) = text.bytes().find(|b| !name_char_ok(*b)) {
        return Err(FormatError::BadAddressByte { tag, byte });
    }
    // Имя, начинающееся с дефиса, командная строка прочтёт как ДОВОД. Дверь
    // зовёт `git` списком аргументов, а не строкой, и потому не обязана этого
    // бояться, — но правило стоит здесь, а не в двери, потому что здесь оно
    // одно на всех исполнителей, а там их будет по одному на вид действия.
    if text.starts_with('-') {
        return Err(FormatError::BadAddressByte { tag, byte: b'-' });
    }
    Ok(())
}

/// Имя хоста: строчные буквы, цифры, `-`, точки между метками.
///
/// Маска здесь невыразима по построению: `*` не входит в набор, поэтому
/// «поддомены» не запрещены правилом, а просто не записываются.
fn check_host(text: &str, tag: u16) -> Result<(), FormatError> {
    if text.is_empty() || text.len() > MAX_ACTION_NAME {
        return Err(FormatError::BadFieldLength { tag, len: text.len() });
    }
    if let Some(byte) =
        text.bytes().find(|b| !(b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-' || *b == b'.'))
    {
        return Err(FormatError::BadAddressByte { tag, byte });
    }
    // Метки непусты и не начинаются с дефиса: пустая метка означает `..` в
    // имени, а ведущий дефис — довод для программы, которая имя получит.
    for label in text.split('.') {
        if label.is_empty() || label.starts_with('-') || label.ends_with('-') {
            return Err(FormatError::BadAddressByte { tag, byte: b'.' });
        }
    }
    Ok(())
}

/// Имя ссылки на секрет: прописные буквы, цифры, `_`.
///
/// Набор узкий потому, что имя идёт в имя переменной окружения двери
/// (`CC_DOOR_SECRET_<REF>`): всё, что туда не годится, лучше отвергнуть здесь,
/// чем узнать на исполнении.
fn check_secret_ref(text: &str, tag: u16) -> Result<(), FormatError> {
    if text.is_empty() || text.len() > MAX_ACTION_NAME {
        return Err(FormatError::BadFieldLength { tag, len: text.len() });
    }
    if let Some(byte) =
        text.bytes().find(|b| !(b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_'))
    {
        return Err(FormatError::BadAddressByte { tag, byte });
    }
    Ok(())
}

/// Компоненты пути: куски между `/`, пустые отброшены.
fn components(path: &str) -> impl Iterator<Item = &str> {
    path.split('/').filter(|part| !part.is_empty())
}

/// Путь внутри дерева: относительный, без `..`, без `.`, без пустых компонентов.
///
/// # Почему набор символов такой узкий
///
/// Потому что путь отсюда попадает в файловую систему, и всё, что в нём
/// невыразимо, дверь не сделает никогда. Обратного ската нет: путь, который
/// грант записать не может, — это путь, по которому действие не исполнится.
/// Запрет обратной косой и двоеточия снимает разом диски Windows, потоки NTFS и
/// UNC-пути; запрет `..` — выход из дерева.
fn check_tree_path(text: &str, tag: u16) -> Result<(), FormatError> {
    if text.is_empty() || text.len() > MAX_ACTION_PATH {
        return Err(FormatError::BadFieldLength { tag, len: text.len() });
    }
    if let Some(byte) = text.bytes().find(|b| !(name_char_ok(*b) || *b == b'/')) {
        return Err(FormatError::BadAddressByte { tag, byte });
    }
    if text.starts_with('/') {
        return Err(FormatError::BadAddressByte { tag, byte: b'/' });
    }
    check_path_parts(text, tag)
}

/// Путь HTTP: начинается с `/`, дальше те же правила о компонентах.
///
/// Запроса и якоря в нём нет вовсе: `?` и `#` не входят в набор. Разреши мы их —
/// «путь под префиксом» перестало бы значить «адрес под префиксом»: всё, что
/// после `?`, к префиксу не относится, а на сервере назначения значит не меньше
/// самого пути.
fn check_http_path(text: &str, tag: u16) -> Result<(), FormatError> {
    if text.is_empty() || text.len() > MAX_ACTION_PATH {
        return Err(FormatError::BadFieldLength { tag, len: text.len() });
    }
    if let Some(byte) =
        text.bytes().find(|b| !(name_char_ok(*b) || matches!(b, b'/' | b'~' | b'%')))
    {
        return Err(FormatError::BadAddressByte { tag, byte });
    }
    let Some(rest) = text.strip_prefix('/') else {
        return Err(FormatError::BadAddressByte { tag, byte: b'/' });
    };
    if rest.is_empty() {
        // Ровно «/» — корень: под ним лежит всё, и компонентов у него нет.
        return Ok(());
    }
    check_path_parts(rest, tag)
}

/// Общее правило компонентов: непустые, не `.`, не `..`.
fn check_path_parts(text: &str, tag: u16) -> Result<(), FormatError> {
    for part in text.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return Err(FormatError::BadAddressByte { tag, byte: b'.' });
        }
    }
    Ok(())
}

/// Лежит ли `path` под `prefix` — ПО КОМПОНЕНТАМ, а не по строке.
///
/// По строке `"src2/x"` начинался бы с `"src"`, и грант на `src` отдавал бы
/// соседний каталог. Сравнение компонентами этого не допускает: `src2` не равно
/// `src` целиком.
///
/// Равенство считается «под»: грант на `docs/notes.md` разрешает действие ровно
/// над ним самим, и требовать строгого вложения значило бы запретить
/// однофайловый грант.
fn path_under(prefix: &str, path: &str) -> bool {
    let mut got = components(path);
    for want in components(prefix) {
        match got.next() {
            Some(part) if part == want => {}
            _ => return false,
        }
    }
    true
}

// ----------------------------------------------------------------------------
// Кодек ограничителя и аргументов.
// ----------------------------------------------------------------------------

fn encode_constraint(limit: &Constraint) -> Result<Vec<u8>, FormatError> {
    let mut w = TlvWriter::new();
    match limit {
        Constraint::GitPush { remote, branch } => {
            check_name(remote, field_tag::REMOTE)?;
            check_tree_path(branch, field_tag::BRANCH)?;
            w.put(field_tag::REMOTE, remote.as_bytes())?;
            w.put(field_tag::BRANCH, branch.as_bytes())?;
        }
        Constraint::TreeRemove { prefix } => {
            check_tree_path(prefix, field_tag::PATH)?;
            w.put(field_tag::PATH, prefix.as_bytes())?;
        }
        Constraint::TreeRename { from_prefix, to_prefix } => {
            check_tree_path(from_prefix, field_tag::FROM)?;
            check_tree_path(to_prefix, field_tag::TO)?;
            w.put(field_tag::FROM, from_prefix.as_bytes())?;
            w.put(field_tag::TO, to_prefix.as_bytes())?;
        }
        Constraint::HttpRequest { host, methods, path_prefix, secret_ref } => {
            check_host(host, field_tag::HOST)?;
            check_methods(methods, field_tag::METHODS)?;
            check_http_path(path_prefix, field_tag::PATH_PREFIX)?;
            if let Some(reference) = secret_ref {
                check_secret_ref(reference, field_tag::SECRET_REF)?;
            }
            w.put(field_tag::HOST, host.as_bytes())?;
            w.put(field_tag::METHODS, &encode_methods(methods))?;
            w.put(field_tag::PATH_PREFIX, path_prefix.as_bytes())?;
            if let Some(reference) = secret_ref {
                w.put(field_tag::SECRET_REF, reference.as_bytes())?;
            }
        }
    }
    Ok(w.finish().to_vec())
}

/// Список методов непуст и строго возрастает.
fn check_methods(methods: &[Method], tag: u16) -> Result<(), FormatError> {
    if methods.is_empty() {
        return Err(FormatError::BadFieldLength { tag, len: 0 });
    }
    for pair in methods.windows(2) {
        let (Some(a), Some(b)) = (pair.first(), pair.get(1)) else { continue };
        if a >= b {
            // Возрастание даёт то же, что И-7 даёт тегам: повтор невозможен,
            // перестановка невозможна, один набор — одна последовательность
            // байтов. Вариант ошибки тот же, каким о порядке сообщает TLV.
            return Err(FormatError::FieldsOutOfOrder {
                previous: u16::from(a.as_u8()),
                found: u16::from(b.as_u8()),
            });
        }
    }
    Ok(())
}

fn encode_methods(methods: &[Method]) -> Vec<u8> {
    methods.iter().map(|m| m.as_u8()).collect()
}

fn decode_methods(bytes: &[u8], tag: u16) -> Result<Vec<Method>, FormatError> {
    let methods = bytes
        .iter()
        .map(|b| Method::from_u8(*b, tag))
        .collect::<Result<Vec<Method>, FormatError>>()?;
    check_methods(&methods, tag)?;
    Ok(methods)
}

fn decode_constraint(bytes: &[u8], kind: ActionKind) -> Result<Constraint, FormatError> {
    let mut reader = TlvReader::new(bytes);
    let (mut remote, mut branch, mut path, mut from, mut to) = (None, None, None, None, None);
    let (mut host, mut methods, mut path_prefix, mut secret_ref) = (None, None, None, None);
    while let Some(f) = reader.next_field()? {
        // Теги разбираются ПО ВИДУ: то, чего этот вид не ждёт, — незнакомый тег,
        // даже если соседний вид его знает. Иначе ограничитель `git.push` с
        // дописанным `host` разобрался бы, и вид перестал бы определять состав.
        match (kind, f.tag) {
            (ActionKind::GitPush, field_tag::REMOTE) => remote = Some(text(&f, field_tag::REMOTE)?),
            (ActionKind::GitPush, field_tag::BRANCH) => branch = Some(text(&f, field_tag::BRANCH)?),
            (ActionKind::TreeRemove, field_tag::PATH) => path = Some(text(&f, field_tag::PATH)?),
            (ActionKind::TreeRename, field_tag::FROM) => from = Some(text(&f, field_tag::FROM)?),
            (ActionKind::TreeRename, field_tag::TO) => to = Some(text(&f, field_tag::TO)?),
            (ActionKind::HttpRequest, field_tag::HOST) => host = Some(text(&f, field_tag::HOST)?),
            (ActionKind::HttpRequest, field_tag::METHODS) => {
                methods = Some(decode_methods(f.value, field_tag::METHODS)?);
            }
            (ActionKind::HttpRequest, field_tag::PATH_PREFIX) => {
                path_prefix = Some(text(&f, field_tag::PATH_PREFIX)?);
            }
            (ActionKind::HttpRequest, field_tag::SECRET_REF) => {
                secret_ref = Some(text(&f, field_tag::SECRET_REF)?);
            }
            (_, other) => crate::unknown::refuse_if_critical(other)?,
        }
    }
    let limit = match kind {
        ActionKind::GitPush => Constraint::GitPush {
            remote: remote.ok_or(FormatError::MissingField { tag: field_tag::REMOTE })?,
            branch: branch.ok_or(FormatError::MissingField { tag: field_tag::BRANCH })?,
        },
        ActionKind::TreeRemove => Constraint::TreeRemove {
            prefix: path.ok_or(FormatError::MissingField { tag: field_tag::PATH })?,
        },
        ActionKind::TreeRename => Constraint::TreeRename {
            from_prefix: from.ok_or(FormatError::MissingField { tag: field_tag::FROM })?,
            to_prefix: to.ok_or(FormatError::MissingField { tag: field_tag::TO })?,
        },
        ActionKind::HttpRequest => Constraint::HttpRequest {
            host: host.ok_or(FormatError::MissingField { tag: field_tag::HOST })?,
            methods: methods.ok_or(FormatError::MissingField { tag: field_tag::METHODS })?,
            path_prefix: path_prefix
                .ok_or(FormatError::MissingField { tag: field_tag::PATH_PREFIX })?,
            secret_ref,
        },
    };
    // Форма проверяется и на чтении: наш писатель отказывается произвести такой
    // ограничитель, и наш читатель обязан отказаться его принять (И-9).
    check_constraint_shape(&limit)?;
    Ok(limit)
}

fn check_constraint_shape(limit: &Constraint) -> Result<(), FormatError> {
    match limit {
        Constraint::GitPush { remote, branch } => {
            check_name(remote, field_tag::REMOTE)?;
            check_tree_path(branch, field_tag::BRANCH)
        }
        Constraint::TreeRemove { prefix } => check_tree_path(prefix, field_tag::PATH),
        Constraint::TreeRename { from_prefix, to_prefix } => {
            check_tree_path(from_prefix, field_tag::FROM)?;
            check_tree_path(to_prefix, field_tag::TO)
        }
        Constraint::HttpRequest { host, methods, path_prefix, secret_ref } => {
            check_host(host, field_tag::HOST)?;
            check_methods(methods, field_tag::METHODS)?;
            check_http_path(path_prefix, field_tag::PATH_PREFIX)?;
            match secret_ref {
                Some(reference) => check_secret_ref(reference, field_tag::SECRET_REF),
                None => Ok(()),
            }
        }
    }
}

fn encode_args(args: &Args) -> Result<Vec<u8>, FormatError> {
    check_args_shape(args)?;
    let mut w = TlvWriter::new();
    match args {
        Args::GitPush { remote, branch } => {
            w.put(field_tag::REMOTE, remote.as_bytes())?;
            w.put(field_tag::BRANCH, branch.as_bytes())?;
        }
        Args::TreeRemove { path } => {
            w.put(field_tag::PATH, path.as_bytes())?;
        }
        Args::TreeRename { from, to } => {
            w.put(field_tag::FROM, from.as_bytes())?;
            w.put(field_tag::TO, to.as_bytes())?;
        }
        Args::HttpRequest { host, method, path, body_digest, body_len } => {
            w.put(field_tag::HOST, host.as_bytes())?;
            w.put(field_tag::METHODS, &[method.as_u8()])?;
            w.put(field_tag::PATH_PREFIX, path.as_bytes())?;
            w.put(field_tag::BODY_DIGEST, body_digest)?;
            w.put(field_tag::BODY_LEN, &body_len.to_le_bytes())?;
        }
    }
    Ok(w.finish().to_vec())
}

fn decode_args(bytes: &[u8], kind: ActionKind) -> Result<Args, FormatError> {
    let mut reader = TlvReader::new(bytes);
    let (mut remote, mut branch, mut path, mut from, mut to) = (None, None, None, None, None);
    let (mut host, mut method, mut http_path, mut digest, mut len) = (None, None, None, None, None);
    while let Some(f) = reader.next_field()? {
        match (kind, f.tag) {
            (ActionKind::GitPush, field_tag::REMOTE) => remote = Some(text(&f, field_tag::REMOTE)?),
            (ActionKind::GitPush, field_tag::BRANCH) => branch = Some(text(&f, field_tag::BRANCH)?),
            (ActionKind::TreeRemove, field_tag::PATH) => path = Some(text(&f, field_tag::PATH)?),
            (ActionKind::TreeRename, field_tag::FROM) => from = Some(text(&f, field_tag::FROM)?),
            (ActionKind::TreeRename, field_tag::TO) => to = Some(text(&f, field_tag::TO)?),
            (ActionKind::HttpRequest, field_tag::HOST) => host = Some(text(&f, field_tag::HOST)?),
            (ActionKind::HttpRequest, field_tag::METHODS) => {
                // Ровно один байт: у ИСПОЛНЕНИЯ метод один. Список длины два
                // означал бы просьбу «исполни одним из двух», и выбирать
                // пришлось бы двери — то есть не автору и не серверу.
                let one = f.array::<1>()?;
                let Some(byte) = one.first() else {
                    return Err(FormatError::BadFieldLength { tag: field_tag::METHODS, len: 0 });
                };
                method = Some(Method::from_u8(*byte, field_tag::METHODS)?);
            }
            (ActionKind::HttpRequest, field_tag::PATH_PREFIX) => {
                http_path = Some(text(&f, field_tag::PATH_PREFIX)?);
            }
            (ActionKind::HttpRequest, field_tag::BODY_DIGEST) => digest = Some(f.array::<32>()?),
            (ActionKind::HttpRequest, field_tag::BODY_LEN) => {
                len = Some(u32::from_le_bytes(f.array::<4>()?));
            }
            (_, other) => crate::unknown::refuse_if_critical(other)?,
        }
    }
    let args = match kind {
        ActionKind::GitPush => Args::GitPush {
            remote: remote.ok_or(FormatError::MissingField { tag: field_tag::REMOTE })?,
            branch: branch.ok_or(FormatError::MissingField { tag: field_tag::BRANCH })?,
        },
        ActionKind::TreeRemove => Args::TreeRemove {
            path: path.ok_or(FormatError::MissingField { tag: field_tag::PATH })?,
        },
        ActionKind::TreeRename => Args::TreeRename {
            from: from.ok_or(FormatError::MissingField { tag: field_tag::FROM })?,
            to: to.ok_or(FormatError::MissingField { tag: field_tag::TO })?,
        },
        ActionKind::HttpRequest => Args::HttpRequest {
            host: host.ok_or(FormatError::MissingField { tag: field_tag::HOST })?,
            method: method.ok_or(FormatError::MissingField { tag: field_tag::METHODS })?,
            path: http_path.ok_or(FormatError::MissingField { tag: field_tag::PATH_PREFIX })?,
            body_digest: digest.ok_or(FormatError::MissingField { tag: field_tag::BODY_DIGEST })?,
            body_len: len.ok_or(FormatError::MissingField { tag: field_tag::BODY_LEN })?,
        },
    };
    check_args_shape(&args)?;
    Ok(args)
}

fn check_args_shape(args: &Args) -> Result<(), FormatError> {
    match args {
        Args::GitPush { remote, branch } => {
            check_name(remote, field_tag::REMOTE)?;
            check_tree_path(branch, field_tag::BRANCH)
        }
        Args::TreeRemove { path } => check_tree_path(path, field_tag::PATH),
        Args::TreeRename { from, to } => {
            check_tree_path(from, field_tag::FROM)?;
            check_tree_path(to, field_tag::TO)
        }
        Args::HttpRequest { host, method: _, path, body_digest: _, body_len } => {
            check_host(host, field_tag::HOST)?;
            check_http_path(path, field_tag::PATH_PREFIX)?;
            if *body_len > MAX_BODY_LEN {
                // Потолок стоит и на РАЗБОРЕ, не только в `args_within`: длину
                // называет чужая сторона, и документ, объявляющий гигабайт, не
                // должен доживать до места, где его читают как число.
                return Err(FormatError::BadFieldLength {
                    tag: field_tag::BODY_LEN,
                    len: *body_len as usize,
                });
            }
            Ok(())
        }
    }
}

/// Значение поля текстом.
fn text(field: &oc_format::tlv::Field<'_>, tag: u16) -> Result<String, FormatError> {
    let value = core::str::from_utf8(field.value).map_err(|_| FormatError::NotUtf8 { tag })?;
    Ok(value.to_string())
}

// ----------------------------------------------------------------------------
// Кодек правила и списка правил.
// ----------------------------------------------------------------------------

fn encode_rule(rule: &ActionRule) -> Result<Vec<u8>, FormatError> {
    check_rule_shape(rule)?;
    let mut w = TlvWriter::new();
    w.put(rule_tag::KIND, &rule.kind.as_u16().to_le_bytes())?;
    w.put(rule_tag::CONSTRAINT, &encode_constraint(&rule.constraint)?)?;
    w.put(rule_tag::MAX_USES, &rule.max_uses.to_le_bytes())?;
    w.put(rule_tag::CONFIRM, &[u8::from(rule.confirm)])?;
    w.put(rule_tag::DELEGABLE, &[u8::from(rule.delegable)])?;
    Ok(w.finish().to_vec())
}

fn decode_rule(bytes: &[u8]) -> Result<ActionRule, FormatError> {
    let mut reader = TlvReader::new(bytes);
    let (mut kind, mut raw_limit, mut max_uses, mut confirm, mut delegable) =
        (None, None, None, None, None);
    while let Some(f) = reader.next_field()? {
        match f.tag {
            rule_tag::KIND => {
                kind = Some(ActionKind::from_u16(f.u16()?, rule_tag::KIND)?);
            }
            // Ограничитель откладывается СЫРЫМ: разобрать его нельзя, не зная
            // вида, а вид лежит в теге 1. Возрастание тегов гарантирует, что к
            // этому моменту вид уже прочитан, — но полагаться на порядок значило
            // бы завести второй источник истины о нём.
            rule_tag::CONSTRAINT => raw_limit = Some(f.value.to_vec()),
            rule_tag::MAX_USES => max_uses = Some(u32::from_le_bytes(f.array::<4>()?)),
            rule_tag::CONFIRM => confirm = Some(flag(f.u8()?, rule_tag::CONFIRM)?),
            rule_tag::DELEGABLE => delegable = Some(flag(f.u8()?, rule_tag::DELEGABLE)?),
            other => crate::unknown::refuse_if_critical(other)?,
        }
    }
    let kind = kind.ok_or(FormatError::MissingField { tag: rule_tag::KIND })?;
    let raw_limit = raw_limit.ok_or(FormatError::MissingField { tag: rule_tag::CONSTRAINT })?;
    let rule = ActionRule {
        kind,
        constraint: decode_constraint(&raw_limit, kind)?,
        max_uses: max_uses.ok_or(FormatError::MissingField { tag: rule_tag::MAX_USES })?,
        confirm: confirm.ok_or(FormatError::MissingField { tag: rule_tag::CONFIRM })?,
        delegable: delegable.ok_or(FormatError::MissingField { tag: rule_tag::DELEGABLE })?,
    };
    check_rule_shape(&rule)?;
    Ok(rule)
}

/// Признак — РОВНО 0 или 1.
///
/// «Всё, что не ноль, истина» здесь недопустимо: у одного смысла было бы 255
/// представлений, и два документа с разными байтами значили бы одно. То же
/// правило, по которому теги идут по возрастанию (И-7).
fn flag(value: u8, tag: u16) -> Result<bool, FormatError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(FormatError::BadFieldLength { tag, len: 1 }),
    }
}

pub(crate) fn check_rule_shape(rule: &ActionRule) -> Result<(), FormatError> {
    if rule.kind != rule.constraint.kind() {
        // Номер вида и ограничитель — два утверждения об одном, и разойтись они
        // не вправе: по номеру разборщик выбирает состав тегов, а исполнитель
        // читает вариант. Документ, где они разные, означал бы разное для двух
        // читателей.
        return Err(FormatError::BadFieldLength { tag: rule_tag::KIND, len: 2 });
    }
    check_constraint_shape(&rule.constraint)
}

/// Список правил — вложенный TLV с нумерацией ПОЗИЦИЕЙ.
///
/// Тот же приём, каким кодируются слоты заголовка и список файлов гранта агента:
/// своего счётчика нет, потому что он был бы вторым источником истины о длине.
pub(crate) fn encode_rules(rules: &[ActionRule]) -> Result<Vec<u8>, FormatError> {
    if rules.len() > MAX_ACTION_RULES {
        return Err(FormatError::BadFieldLength { tag: grant_tag::RULES, len: rules.len() });
    }
    let mut w = TlvWriter::new();
    for (index, rule) in rules.iter().enumerate() {
        let tag = u16::try_from(index).map_err(|_| FormatError::OffsetOverflow)?;
        w.put(tag, &encode_rule(rule)?)?;
    }
    Ok(w.finish().to_vec())
}

pub(crate) fn decode_rules(bytes: &[u8]) -> Result<Vec<ActionRule>, FormatError> {
    let mut reader = TlvReader::new(bytes);
    let mut out: Vec<ActionRule> = Vec::new();
    while let Some(field) = reader.next_field()? {
        // Потолок — ВНУТРИ цикла: длину списка называет чужая сторона.
        if out.len() >= MAX_ACTION_RULES {
            return Err(FormatError::BadFieldLength { tag: grant_tag::RULES, len: out.len() });
        }
        out.push(decode_rule(field.value)?);
    }
    Ok(out)
}

// ----------------------------------------------------------------------------
// Грант действий.
// ----------------------------------------------------------------------------

/// Байты гранта действий БЕЗ подписи — то, что подписывается и проверяется.
///
/// # Errors
/// [`FormatError`], если грант не той формы, которую примет наш же читатель.
pub fn grant_body(grant: &ActionGrant) -> Result<Vec<u8>, FormatError> {
    check_grant_shape(grant)?;
    let mut w = TlvWriter::new();
    w.put(grant_tag::GRANT_ID, &grant.grant_id)?;
    w.put(grant_tag::RULES, &encode_rules(&grant.rules)?)?;
    w.put(grant_tag::ISSUED_AT, &grant.issued_at.to_le_bytes())?;
    w.put(grant_tag::EXPIRES_AT, &grant.expires_at.to_le_bytes())?;
    w.put(grant_tag::AUTHOR_KEY, &grant.author_key)?;
    Ok(w.finish().to_vec())
}

/// Транскрипт подписи гранта действий.
#[must_use]
pub fn grant_transcript(body: &[u8]) -> oc_crypto::Transcript {
    let mut t = oc_crypto::Transcript::new(oc_crypto::label::ACTION_GRANT);
    t.field(body);
    t
}

/// Закодировать грант целиком: `подпись(64) ‖ тело`.
///
/// # Errors
/// [`FormatError`], если тело не собирается — см. [`grant_body`].
pub fn encode_grant(grant: &ActionGrant) -> Result<Vec<u8>, FormatError> {
    let body = grant_body(grant)?;
    let mut out = Vec::with_capacity(SIGNATURE_LEN.saturating_add(body.len()));
    out.extend_from_slice(&grant.signature);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Проверить подпись автора, потом разобрать — в этом порядке, и только в нём.
///
/// `author_key` передаёт ВЫЗЫВАЮЩИЙ — из записи сервера о файловом гранте, а не
/// из принесённого документа. Ключ внутри сверяется с переданным константным
/// временем (И-13): он часть подписанного тела, то есть утверждение «грант
/// выпущен этим автором», а не источник истины.
///
/// # Errors
/// [`FormatError::BadHeaderSignature`] при коротком документе и при несошедшейся
/// подписи; иначе — ошибки разбора и проверки формы.
pub fn decode_grant(bytes: &[u8], author_key: &[u8; 32]) -> Result<ActionGrant, FormatError> {
    let (signature, body) = split_signature(bytes)?;
    oc_crypto::sign::verify(author_key, &grant_transcript(body), &signature)
        .map_err(|_| FormatError::BadHeaderSignature)?;
    let mut grant = decode_grant_body(body)?;
    if !oc_crypto::digest_eq(&grant.author_key, author_key) {
        return Err(FormatError::BadFieldLength { tag: grant_tag::AUTHOR_KEY, len: 32 });
    }
    grant.signature = signature;
    Ok(grant)
}

/// Тело гранта действий БЕЗ проверки подписи.
///
/// Тот же довод, что у [`crate::agent::peek_grant`]: ключ проверки сервер ищет
/// ПО СОДЕРЖИМОМУ — по `grant_id`, у записи которого записан ключ автора, — а
/// прочесть `grant_id`, не разобрав тело, нечем. Исполнять по этому значению
/// нельзя ничего: подпись не проверена.
///
/// Форма проверяется полностью: И-9 запрещает выпускать из крейта байты,
/// которых мы не проверили.
///
/// # Errors
/// [`FormatError`], если байты короче подписи или тело не разбирается.
pub fn peek_grant(bytes: &[u8]) -> Result<ActionGrant, FormatError> {
    let (signature, body) = split_signature(bytes)?;
    let mut grant = decode_grant_body(body)?;
    grant.signature = signature;
    Ok(grant)
}

fn decode_grant_body(body: &[u8]) -> Result<ActionGrant, FormatError> {
    let mut reader = TlvReader::new(body);
    let (mut grant_id, mut rules, mut issued_at, mut expires_at, mut author_key) =
        (None, None, None, None, None);
    while let Some(f) = reader.next_field()? {
        match f.tag {
            grant_tag::GRANT_ID => grant_id = Some(f.array::<16>()?),
            grant_tag::RULES => rules = Some(decode_rules(f.value)?),
            grant_tag::ISSUED_AT => issued_at = Some(i64::from_le_bytes(f.array::<8>()?)),
            grant_tag::EXPIRES_AT => expires_at = Some(i64::from_le_bytes(f.array::<8>()?)),
            grant_tag::AUTHOR_KEY => author_key = Some(f.array::<32>()?),
            other => crate::unknown::refuse_if_critical(other)?,
        }
    }
    let grant = ActionGrant {
        grant_id: grant_id.ok_or(FormatError::MissingField { tag: grant_tag::GRANT_ID })?,
        rules: rules.ok_or(FormatError::MissingField { tag: grant_tag::RULES })?,
        issued_at: issued_at.ok_or(FormatError::MissingField { tag: grant_tag::ISSUED_AT })?,
        expires_at: expires_at.ok_or(FormatError::MissingField { tag: grant_tag::EXPIRES_AT })?,
        author_key: author_key.ok_or(FormatError::MissingField { tag: grant_tag::AUTHOR_KEY })?,
        signature: [0; SIGNATURE_LEN],
    };
    check_grant_shape(&grant)?;
    Ok(grant)
}

fn check_grant_shape(grant: &ActionGrant) -> Result<(), FormatError> {
    if grant.rules.len() > MAX_ACTION_RULES {
        return Err(FormatError::BadFieldLength { tag: grant_tag::RULES, len: grant.rules.len() });
    }
    for rule in &grant.rules {
        check_rule_shape(rule)?;
    }
    if grant.expires_at < grant.issued_at {
        // Срок, кончающийся раньше начала, не «уже истёк»: это документ, о
        // котором нельзя сказать, что он когда-либо действовал.
        return Err(FormatError::BadFieldLength { tag: grant_tag::EXPIRES_AT, len: 8 });
    }
    Ok(())
}

// ----------------------------------------------------------------------------
// Просьба.
// ----------------------------------------------------------------------------

/// Закодировать просьбу. Подписи у неё нет — см. докстроку модуля.
///
/// # Errors
/// [`FormatError`], если аргументы или записка не той формы.
pub fn encode_request(ask: &ActionRequest) -> Result<Vec<u8>, FormatError> {
    check_request_shape(ask)?;
    let mut w = TlvWriter::new();
    w.put(request_tag::GRANT_ID, &ask.grant_id)?;
    w.put(request_tag::DOOR_FPR, &ask.door_fpr)?;
    w.put(request_tag::KIND, &ask.kind.as_u16().to_le_bytes())?;
    w.put(request_tag::ARGS, &encode_args(&ask.args)?)?;
    w.put(request_tag::NONCE, &ask.nonce)?;
    w.put(request_tag::NOTE, ask.note.as_bytes())?;
    Ok(w.finish().to_vec())
}

/// Разобрать просьбу.
///
/// # Errors
/// [`FormatError`] при нехватке полей, неверных длинах, незнакомом виде или
/// негодной записке.
pub fn decode_request(bytes: &[u8]) -> Result<ActionRequest, FormatError> {
    let mut reader = TlvReader::new(bytes);
    let (mut grant_id, mut door_fpr, mut kind, mut raw_args) = (None, None, None, None);
    let (mut nonce, mut note) = (None, None);
    while let Some(f) = reader.next_field()? {
        match f.tag {
            request_tag::GRANT_ID => grant_id = Some(f.array::<16>()?),
            request_tag::DOOR_FPR => door_fpr = Some(f.array::<32>()?),
            request_tag::KIND => kind = Some(ActionKind::from_u16(f.u16()?, request_tag::KIND)?),
            request_tag::ARGS => raw_args = Some(f.value.to_vec()),
            request_tag::NONCE => nonce = Some(f.array::<16>()?),
            request_tag::NOTE => {
                let value = text(&f, request_tag::NOTE)?;
                crate::access::check_note(&value, request_tag::NOTE)?;
                note = Some(value);
            }
            other => crate::unknown::refuse_if_critical(other)?,
        }
    }
    let kind = kind.ok_or(FormatError::MissingField { tag: request_tag::KIND })?;
    let raw_args = raw_args.ok_or(FormatError::MissingField { tag: request_tag::ARGS })?;
    let ask = ActionRequest {
        grant_id: grant_id.ok_or(FormatError::MissingField { tag: request_tag::GRANT_ID })?,
        door_fpr: door_fpr.ok_or(FormatError::MissingField { tag: request_tag::DOOR_FPR })?,
        kind,
        args: decode_args(&raw_args, kind)?,
        nonce: nonce.ok_or(FormatError::MissingField { tag: request_tag::NONCE })?,
        note: note.ok_or(FormatError::MissingField { tag: request_tag::NOTE })?,
    };
    check_request_shape(&ask)?;
    Ok(ask)
}

fn check_request_shape(ask: &ActionRequest) -> Result<(), FormatError> {
    if ask.kind != ask.args.kind() {
        return Err(FormatError::BadFieldLength { tag: request_tag::KIND, len: 2 });
    }
    crate::access::check_note(&ask.note, request_tag::NOTE)?;
    check_args_shape(&ask.args)
}

// ----------------------------------------------------------------------------
// Лиза.
// ----------------------------------------------------------------------------

/// Байты лизы БЕЗ подписи — то, что подписывается и проверяется.
///
/// # Errors
/// [`FormatError`], если лиза не той формы, которую примет наш же читатель.
pub fn lease_body(lease: &ActionLease) -> Result<Vec<u8>, FormatError> {
    check_lease_shape(lease)?;
    let mut w = TlvWriter::new();
    w.put(lease_tag::GRANT_ID, &lease.grant_id)?;
    w.put(lease_tag::DOOR_FPR, &lease.door_fpr)?;
    w.put(lease_tag::KIND, &lease.kind.as_u16().to_le_bytes())?;
    w.put(lease_tag::ARGS, &encode_args(&lease.args)?)?;
    w.put(lease_tag::NONCE, &lease.nonce)?;
    w.put(lease_tag::ISSUED_AT, &lease.issued_at.to_le_bytes())?;
    w.put(lease_tag::EXPIRES_AT, &lease.expires_at.to_le_bytes())?;
    w.put(lease_tag::SEQ, &lease.seq.to_le_bytes())?;
    Ok(w.finish().to_vec())
}

/// Транскрипт подписи лизы действия.
///
/// Метка своя, а не [`oc_crypto::label::LEASE`]: ключ подписи у сервера один и
/// тот же, и без разных доменов разрешение ОТКРЫТЬ файл годилось бы разрешением
/// ИСПОЛНИТЬ действие.
#[must_use]
pub fn lease_transcript(body: &[u8]) -> oc_crypto::Transcript {
    let mut t = oc_crypto::Transcript::new(oc_crypto::label::ACTION_LEASE);
    t.field(body);
    t
}

/// Закодировать лизу целиком: `подпись(64) ‖ тело`.
///
/// # Errors
/// [`FormatError`], если тело не собирается — см. [`lease_body`].
pub fn encode_lease(lease: &ActionLease) -> Result<Vec<u8>, FormatError> {
    let body = lease_body(lease)?;
    let mut out = Vec::with_capacity(SIGNATURE_LEN.saturating_add(body.len()));
    out.extend_from_slice(&lease.signature);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Проверить подпись сервера, потом разобрать — в этом порядке, и только в нём.
///
/// `lease_verify_key` — `authority.lease_verify_key`, закреплённый автором в
/// заголовке любого файла гранта; для двери без файлов сервер отдаёт его в
/// ответе `FetchChain`. Из самой лизы ключ не берётся никогда.
///
/// # Errors
/// [`FormatError::BadHeaderSignature`] при коротком документе и при несошедшейся
/// подписи; иначе — ошибки разбора и проверки формы.
pub fn decode_lease(
    bytes: &[u8],
    lease_verify_key: &[u8; 32],
) -> Result<ActionLease, FormatError> {
    let (signature, body) = split_signature(bytes)?;
    oc_crypto::sign::verify(lease_verify_key, &lease_transcript(body), &signature)
        .map_err(|_| FormatError::BadHeaderSignature)?;
    let mut lease = decode_lease_body(body)?;
    lease.signature = signature;
    Ok(lease)
}

fn decode_lease_body(body: &[u8]) -> Result<ActionLease, FormatError> {
    let mut reader = TlvReader::new(body);
    let (mut grant_id, mut door_fpr, mut kind, mut raw_args) = (None, None, None, None);
    let (mut nonce, mut issued_at, mut expires_at, mut seq) = (None, None, None, None);
    while let Some(f) = reader.next_field()? {
        match f.tag {
            lease_tag::GRANT_ID => grant_id = Some(f.array::<16>()?),
            lease_tag::DOOR_FPR => door_fpr = Some(f.array::<32>()?),
            lease_tag::KIND => kind = Some(ActionKind::from_u16(f.u16()?, lease_tag::KIND)?),
            lease_tag::ARGS => raw_args = Some(f.value.to_vec()),
            lease_tag::NONCE => nonce = Some(f.array::<16>()?),
            lease_tag::ISSUED_AT => issued_at = Some(i64::from_le_bytes(f.array::<8>()?)),
            lease_tag::EXPIRES_AT => expires_at = Some(i64::from_le_bytes(f.array::<8>()?)),
            lease_tag::SEQ => seq = Some(f.u64()?),
            other => crate::unknown::refuse_if_critical(other)?,
        }
    }
    let kind = kind.ok_or(FormatError::MissingField { tag: lease_tag::KIND })?;
    let raw_args = raw_args.ok_or(FormatError::MissingField { tag: lease_tag::ARGS })?;
    let lease = ActionLease {
        grant_id: grant_id.ok_or(FormatError::MissingField { tag: lease_tag::GRANT_ID })?,
        door_fpr: door_fpr.ok_or(FormatError::MissingField { tag: lease_tag::DOOR_FPR })?,
        kind,
        args: decode_args(&raw_args, kind)?,
        nonce: nonce.ok_or(FormatError::MissingField { tag: lease_tag::NONCE })?,
        issued_at: issued_at.ok_or(FormatError::MissingField { tag: lease_tag::ISSUED_AT })?,
        expires_at: expires_at.ok_or(FormatError::MissingField { tag: lease_tag::EXPIRES_AT })?,
        seq: seq.ok_or(FormatError::MissingField { tag: lease_tag::SEQ })?,
        signature: [0; SIGNATURE_LEN],
    };
    check_lease_shape(&lease)?;
    Ok(lease)
}

fn check_lease_shape(lease: &ActionLease) -> Result<(), FormatError> {
    if lease.kind != lease.args.kind() {
        return Err(FormatError::BadFieldLength { tag: lease_tag::KIND, len: 2 });
    }
    if lease.expires_at < lease.issued_at {
        return Err(FormatError::BadFieldLength { tag: lease_tag::EXPIRES_AT, len: 8 });
    }
    // Окно проверяется НА РАЗБОРЕ, а не только дверью: лиза действия
    // одноразовая и живёт тридцать секунд, а документ, объявивший неделю, — это
    // либо чужая реализация с другим числом, либо подмена. Отказ на границе
    // крейта дешевле обоих случаев, и он же делает [`ACTION_LEASE_SECONDS`]
    // величиной ПРОВОДА, а не соглашением двух программ.
    if lease.expires_at > lease.issued_at.saturating_add(ACTION_LEASE_SECONDS) {
        return Err(FormatError::BadFieldLength { tag: lease_tag::EXPIRES_AT, len: 8 });
    }
    check_args_shape(&lease.args)
}

// ----------------------------------------------------------------------------
// Очередь `confirm` и решение владельца.
// ----------------------------------------------------------------------------

/// Сколько записей очереди `confirm` сервер отдаёт владельцу за раз — ОКНО.
///
/// Величина провода: ответ на `ActionRequests` несёт не больше стольких
/// записей, и клиент больший ответ отвергает — длину называет чужая сторона.
///
/// Шестнадцать, столько же, сколько у окна просьб о доступе
/// ([`crate::access::MAX_PENDING_PER_FILE`]), и по той же причине: столько
/// человек в состоянии просмотреть глазами за один раз. Решённые уходят из
/// окна, и в него встают следующие по номеру.
pub const MAX_PENDING_ACTION_WINDOW: usize = 16;

/// Наибольшая длина причины отказа на проводе.
///
/// Длиннее записки ([`crate::access::MAX_NOTE`]) намеренно: записку пишет
/// человек фразой, а причину отказа составляет программа из названия
/// ограничителя, имени вида и величин, и урезать её до фразы значило бы терять
/// ровно то, ради чего отказ и несёт слова.
pub const MAX_REFUSAL: usize = 1024;

/// Одна просьба, ждущая живого «да» владельца. Так он её видит.
///
/// Поля те же, что у просьбы, плюс номер и время приёма по часам СЕРВЕРА:
/// время, названное просителем, ничем не подтверждено, а владельцу оно нужно,
/// чтобы отличить «просят прямо сейчас» от «просили неделю назад».
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingAction {
    pub seq: u64,
    pub grant_id: [u8; 16],
    pub door_fpr: [u8; 32],
    pub kind: ActionKind,
    pub args: Args,
    pub nonce: [u8; 16],
    pub note: String,
    pub at: i64,
}

/// Решение владельца по одной просьбе об исполнении.
///
/// Подписано ключом АВТОРА файлового гранта — тем, что лежит в заголовке файла
/// и записан сервером при регистрации. Подпись покрывает `seq`, `grant_id` и
/// `door_fpr` вместе: одобрение, выписанное одной двери, нельзя переадресовать
/// другой, а одобрение одной просьбы — предъявить за другую.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActionDecision {
    pub seq: u64,
    pub grant_id: [u8; 16],
    /// Кому. Дублирует то, что лежит в очереди, и это не избыточность: подпись
    /// покрывает отпечаток, поэтому одобрение не переадресуется.
    pub door_fpr: [u8; 32],
    pub approve: bool,
    /// Записка владельца. При отказе она и есть причина, которую увидит агент,
    /// — правило записки то же, что у просьбы.
    pub note: String,
    pub author_key: [u8; 32],
    pub signature: [u8; SIGNATURE_LEN],
}

/// Теги записи очереди `confirm`.
pub mod pending_tag {
    pub const SEQ: u16 = 1;
    pub const GRANT_ID: u16 = 2;
    pub const DOOR_FPR: u16 = 3;
    pub const KIND: u16 = 4;
    pub const ARGS: u16 = 5;
    pub const NONCE: u16 = 6;
    pub const NOTE: u16 = 7;
    pub const AT: u16 = 8;
}

/// Теги решения владельца.
pub mod decision_tag {
    pub const GRANT_ID: u16 = 1;
    pub const DOOR_FPR: u16 = 2;
    pub const SEQ: u16 = 3;
    pub const APPROVE: u16 = 4;
    pub const NOTE: u16 = 5;
    pub const AUTHOR_KEY: u16 = 6;
}

/// Ключ правила для счёта исполнений: вид и ограничитель БАЙТАМИ.
///
/// Счёт `max_uses` сервер ведёт по паре «держатель — правило», и «то же
/// правило» обязано значить «те же байты ограничителя», а не «похоже
/// выглядит»: два правила `tree.remove` на два поддерева — обычный грант, и
/// спутав их, сервер списывал бы исполнение не с того предела.
///
/// Байты те же, что уходят в подписанное тело гранта, — отдельной сборки здесь
/// нет намеренно: вторая разошлась бы с первой на ближайшей правке кодека.
///
/// # Errors
/// [`FormatError`], если ограничитель не той формы, которую примет наш читатель.
pub fn limiter_key(rule: &ActionRule) -> Result<Vec<u8>, FormatError> {
    let constraint = encode_constraint(&rule.constraint)?;
    let mut out = Vec::with_capacity(2usize.saturating_add(constraint.len()));
    out.extend_from_slice(&rule.kind.as_u16().to_le_bytes());
    out.extend_from_slice(&constraint);
    Ok(out)
}

/// Закодировать запись очереди.
///
/// # Errors
/// [`FormatError`], если аргументы или записка не той формы.
pub fn encode_pending(p: &PendingAction) -> Result<Vec<u8>, FormatError> {
    check_pending_shape(p)?;
    let mut w = TlvWriter::new();
    w.put(pending_tag::SEQ, &p.seq.to_le_bytes())?;
    w.put(pending_tag::GRANT_ID, &p.grant_id)?;
    w.put(pending_tag::DOOR_FPR, &p.door_fpr)?;
    w.put(pending_tag::KIND, &p.kind.as_u16().to_le_bytes())?;
    w.put(pending_tag::ARGS, &encode_args(&p.args)?)?;
    w.put(pending_tag::NONCE, &p.nonce)?;
    w.put(pending_tag::NOTE, p.note.as_bytes())?;
    w.put(pending_tag::AT, &p.at.to_le_bytes())?;
    Ok(w.finish().to_vec())
}

/// Разобрать запись очереди.
///
/// # Errors
/// [`FormatError`] при нехватке полей, неверных длинах, незнакомом виде или
/// негодной записке.
pub fn decode_pending(bytes: &[u8]) -> Result<PendingAction, FormatError> {
    let mut reader = TlvReader::new(bytes);
    let (mut seq, mut grant_id, mut door_fpr, mut kind) = (None, None, None, None);
    let (mut raw_args, mut nonce, mut note, mut at) = (None, None, None, None);
    while let Some(f) = reader.next_field()? {
        match f.tag {
            pending_tag::SEQ => seq = Some(f.u64()?),
            pending_tag::GRANT_ID => grant_id = Some(f.array::<16>()?),
            pending_tag::DOOR_FPR => door_fpr = Some(f.array::<32>()?),
            pending_tag::KIND => kind = Some(ActionKind::from_u16(f.u16()?, pending_tag::KIND)?),
            pending_tag::ARGS => raw_args = Some(f.value.to_vec()),
            pending_tag::NONCE => nonce = Some(f.array::<16>()?),
            pending_tag::NOTE => {
                let value = text(&f, pending_tag::NOTE)?;
                crate::access::check_note(&value, pending_tag::NOTE)?;
                note = Some(value);
            }
            pending_tag::AT => at = Some(i64::from_le_bytes(f.array::<8>()?)),
            other => crate::unknown::refuse_if_critical(other)?,
        }
    }
    let kind = kind.ok_or(FormatError::MissingField { tag: pending_tag::KIND })?;
    let raw_args = raw_args.ok_or(FormatError::MissingField { tag: pending_tag::ARGS })?;
    let pending = PendingAction {
        seq: seq.ok_or(FormatError::MissingField { tag: pending_tag::SEQ })?,
        grant_id: grant_id.ok_or(FormatError::MissingField { tag: pending_tag::GRANT_ID })?,
        door_fpr: door_fpr.ok_or(FormatError::MissingField { tag: pending_tag::DOOR_FPR })?,
        kind,
        args: decode_args(&raw_args, kind)?,
        nonce: nonce.ok_or(FormatError::MissingField { tag: pending_tag::NONCE })?,
        note: note.ok_or(FormatError::MissingField { tag: pending_tag::NOTE })?,
        at: at.ok_or(FormatError::MissingField { tag: pending_tag::AT })?,
    };
    check_pending_shape(&pending)?;
    Ok(pending)
}

fn check_pending_shape(p: &PendingAction) -> Result<(), FormatError> {
    if p.kind != p.args.kind() {
        return Err(FormatError::BadFieldLength { tag: pending_tag::KIND, len: 2 });
    }
    crate::access::check_note(&p.note, pending_tag::NOTE)?;
    check_args_shape(&p.args)
}

/// Разобрать очередь: записи подряд, каждая со своей длиной.
///
/// Длина у каждой записи, а не одна на всё тело, потому что записи разной
/// длины: записка и аргументы переменные. Общего счётчика записей нет
/// намеренно — он был бы вторым источником истины о том, сколько их, и
/// разошёлся бы с телом.
///
/// # Errors
/// [`crate::access::QueueError`], если тело оборвано, запись не разбирается или
/// записей больше окна [`MAX_PENDING_ACTION_WINDOW`].
pub fn split_action_queue(
    mut rest: &[u8],
) -> Result<Vec<PendingAction>, crate::access::QueueError> {
    use crate::access::QueueError;
    let mut out: Vec<PendingAction> = Vec::new();
    while !rest.is_empty() {
        let head: [u8; 4] = rest
            .get(..4)
            .and_then(|s| <[u8; 4]>::try_from(s).ok())
            .ok_or(QueueError::Torn("очередь действий оборвана на длине записи"))?;
        let len = u32::from_le_bytes(head) as usize;
        let body = rest
            .get(4..)
            .and_then(|s| s.get(..len))
            .ok_or(QueueError::Torn("запись очереди действий короче объявленной длины"))?;
        out.push(decode_pending(body).map_err(QueueError::Record)?);
        rest = rest.get(4usize.saturating_add(len)..).unwrap_or_default();
        // Окно то же, что у сервера: длину очереди называет чужая сторона, и
        // без предела «покажи очередь» означало бы «выдели столько, сколько
        // скажет собеседник».
        if out.len() > MAX_PENDING_ACTION_WINDOW {
            return Err(QueueError::TooMany);
        }
    }
    Ok(out)
}

/// Байты решения БЕЗ подписи — то, что подписывается и проверяется.
///
/// # Errors
/// [`FormatError`], если записка не той формы.
pub fn decision_body(d: &ActionDecision) -> Result<Vec<u8>, FormatError> {
    crate::access::check_note(&d.note, decision_tag::NOTE)?;
    let mut w = TlvWriter::new();
    w.put(decision_tag::GRANT_ID, &d.grant_id)?;
    w.put(decision_tag::DOOR_FPR, &d.door_fpr)?;
    w.put(decision_tag::SEQ, &d.seq.to_le_bytes())?;
    w.put(decision_tag::APPROVE, &[u8::from(d.approve)])?;
    w.put(decision_tag::NOTE, d.note.as_bytes())?;
    w.put(decision_tag::AUTHOR_KEY, &d.author_key)?;
    Ok(w.finish().to_vec())
}

/// Транскрипт подписи решения владельца.
///
/// Метка своя ([`oc_crypto::label::ACTION_DECISION`]), а не
/// [`oc_crypto::label::GRANT`], которой подписано решение по просьбе о доступе:
/// ключ у обоих один, и домены разводит только метка.
#[must_use]
pub fn decision_transcript(body: &[u8]) -> oc_crypto::Transcript {
    let mut t = oc_crypto::Transcript::new(oc_crypto::label::ACTION_DECISION);
    t.field(body);
    t
}

/// Закодировать решение целиком: `подпись(64) ‖ тело`.
///
/// Раскладка та же, что у гранта и лизы этого модуля, — в отличие от решения о
/// доступе, где подпись идёт ХВОСТОВЫМ тегом. Разная раскладка у соседей стоила
/// бы второго правила «где искать подпись», а правило здесь одно: первые
/// шестьдесят четыре байта.
///
/// # Errors
/// [`FormatError`], если тело не собирается.
pub fn encode_decision(d: &ActionDecision) -> Result<Vec<u8>, FormatError> {
    let body = decision_body(d)?;
    let mut out = Vec::with_capacity(SIGNATURE_LEN.saturating_add(body.len()));
    out.extend_from_slice(&d.signature);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Проверить подпись автора, потом разобрать — в этом порядке, и только в нём.
///
/// `author_key` передаёт ВЫЗЫВАЮЩИЙ — из записи сервера о файловом гранте, а не
/// из принесённого документа; ключ внутри сверяется с переданным константным
/// временем (И-13).
///
/// # Errors
/// [`FormatError::BadHeaderSignature`] при коротком документе и при
/// несошедшейся подписи; иначе — ошибки разбора.
pub fn decode_decision(
    bytes: &[u8],
    author_key: &[u8; 32],
) -> Result<ActionDecision, FormatError> {
    let (signature, body) = split_signature(bytes)?;
    oc_crypto::sign::verify(author_key, &decision_transcript(body), &signature)
        .map_err(|_| FormatError::BadHeaderSignature)?;
    let mut decision = decode_decision_body(body)?;
    if !oc_crypto::digest_eq(&decision.author_key, author_key) {
        return Err(FormatError::BadFieldLength { tag: decision_tag::AUTHOR_KEY, len: 32 });
    }
    decision.signature = signature;
    Ok(decision)
}

/// Тело решения БЕЗ проверки подписи — чтобы найти, чьим ключом его проверять.
///
/// Тот же довод, что у [`peek_grant`]: ключ проверки сервер ищет по `grant_id`,
/// а прочесть `grant_id`, не разобрав тело, нечем. Исполнять по результату
/// нельзя ничего.
///
/// # Errors
/// [`FormatError`], если байты короче подписи или тело не разбирается.
pub fn peek_decision(bytes: &[u8]) -> Result<ActionDecision, FormatError> {
    let (signature, body) = split_signature(bytes)?;
    let mut decision = decode_decision_body(body)?;
    decision.signature = signature;
    Ok(decision)
}

fn decode_decision_body(body: &[u8]) -> Result<ActionDecision, FormatError> {
    let mut reader = TlvReader::new(body);
    let (mut grant_id, mut door_fpr, mut seq) = (None, None, None);
    let (mut approve, mut note, mut author_key) = (None, None, None);
    while let Some(f) = reader.next_field()? {
        match f.tag {
            decision_tag::GRANT_ID => grant_id = Some(f.array::<16>()?),
            decision_tag::DOOR_FPR => door_fpr = Some(f.array::<32>()?),
            decision_tag::SEQ => seq = Some(f.u64()?),
            // СТРОГО 0 ИЛИ 1, а не «байт не ноль»: иначе у одного решения было
            // бы двести пятьдесят пять представлений, а подпись покрывает
            // байты — каноничность записи потерялась бы вместе с ними (И-7).
            decision_tag::APPROVE => {
                approve = Some(match f.value {
                    [0] => false,
                    [1] => true,
                    other => {
                        return Err(FormatError::BadFieldLength {
                            tag: decision_tag::APPROVE,
                            len: other.len(),
                        });
                    }
                });
            }
            decision_tag::NOTE => {
                let value = text(&f, decision_tag::NOTE)?;
                crate::access::check_note(&value, decision_tag::NOTE)?;
                note = Some(value);
            }
            decision_tag::AUTHOR_KEY => author_key = Some(f.array::<32>()?),
            other => crate::unknown::refuse_if_critical(other)?,
        }
    }
    Ok(ActionDecision {
        seq: seq.ok_or(FormatError::MissingField { tag: decision_tag::SEQ })?,
        grant_id: grant_id.ok_or(FormatError::MissingField { tag: decision_tag::GRANT_ID })?,
        door_fpr: door_fpr.ok_or(FormatError::MissingField { tag: decision_tag::DOOR_FPR })?,
        approve: approve.ok_or(FormatError::MissingField { tag: decision_tag::APPROVE })?,
        note: note.ok_or(FormatError::MissingField { tag: decision_tag::NOTE })?,
        author_key: author_key
            .ok_or(FormatError::MissingField { tag: decision_tag::AUTHOR_KEY })?,
        signature: [0; SIGNATURE_LEN],
    })
}

fn split_signature(bytes: &[u8]) -> Result<([u8; SIGNATURE_LEN], &[u8]), FormatError> {
    let (signature, body) =
        bytes.split_at_checked(SIGNATURE_LEN).ok_or(FormatError::BadHeaderSignature)?;
    let signature: [u8; SIGNATURE_LEN] =
        signature.try_into().map_err(|_| FormatError::BadHeaderSignature)?;
    Ok((signature, body))
}

#[cfg(test)]
// Тестам позволено разворачивать `Option`, падать с сообщением, индексировать и
// считать без проверки переполнения: проверяемый код на этих путях не
// исполняется, а выход за границы уронил бы тест, и уронил бы громко.
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use oc_crypto::sign::{Ed25519Signer, Signer as _};

    fn author() -> Ed25519Signer {
        Ed25519Signer::from_seed(&[0xa1; 32])
    }

    fn stranger() -> Ed25519Signer {
        Ed25519Signer::from_seed(&[0x77; 32])
    }

    /// Ключ подписи лиз — им сервер заверяет и лизинги файлов, и лизы действий.
    fn server() -> Ed25519Signer {
        Ed25519Signer::from_seed(&[0x5e; 32])
    }

    fn push_rule() -> ActionRule {
        ActionRule {
            kind: ActionKind::GitPush,
            constraint: Constraint::GitPush {
                remote: "origin".to_string(),
                branch: "agent/work".to_string(),
            },
            max_uses: 10,
            confirm: false,
            delegable: true,
        }
    }

    fn remove_rule() -> ActionRule {
        ActionRule {
            kind: ActionKind::TreeRemove,
            constraint: Constraint::TreeRemove { prefix: "src".to_string() },
            max_uses: 0,
            confirm: false,
            delegable: true,
        }
    }

    fn rename_rule() -> ActionRule {
        ActionRule {
            kind: ActionKind::TreeRename,
            constraint: Constraint::TreeRename {
                from_prefix: "src".to_string(),
                to_prefix: "attic".to_string(),
            },
            max_uses: 3,
            confirm: false,
            delegable: false,
        }
    }

    fn http_rule() -> ActionRule {
        ActionRule {
            kind: ActionKind::HttpRequest,
            constraint: Constraint::HttpRequest {
                host: "api.example.com".to_string(),
                methods: vec![Method::Get, Method::Post],
                path_prefix: "/v1/issues".to_string(),
                secret_ref: Some("FORGE_TOKEN".to_string()),
            },
            max_uses: 100,
            confirm: false,
            delegable: true,
        }
    }

    fn grant() -> ActionGrant {
        let mut g = ActionGrant {
            grant_id: [0x67; 16],
            rules: vec![push_rule(), remove_rule(), rename_rule(), http_rule()],
            issued_at: 1_700_000_000,
            expires_at: 1_700_086_400,
            author_key: author().public_key(),
            signature: [0; SIGNATURE_LEN],
        };
        sign_grant(&mut g, &author());
        g
    }

    fn sign_grant(g: &mut ActionGrant, signer: &Ed25519Signer) {
        let body = grant_body(g).expect("тело гранта собирается");
        g.signature = signer.sign(&grant_transcript(&body)).unwrap();
    }

    fn push_args() -> Args {
        Args::GitPush { remote: "origin".to_string(), branch: "agent/work".to_string() }
    }

    fn http_args() -> Args {
        Args::HttpRequest {
            host: "api.example.com".to_string(),
            method: Method::Post,
            path: "/v1/issues/42".to_string(),
            body_digest: [0x33; 32],
            body_len: 512,
        }
    }

    fn lease() -> ActionLease {
        let mut l = ActionLease {
            grant_id: [0x67; 16],
            door_fpr: [0xd1; 32],
            kind: ActionKind::GitPush,
            args: push_args(),
            nonce: [0x5a; 16],
            issued_at: 1_700_010_000,
            expires_at: 1_700_010_030,
            seq: 7,
            signature: [0; SIGNATURE_LEN],
        };
        sign_lease(&mut l, &server());
        l
    }

    fn sign_lease(l: &mut ActionLease, signer: &Ed25519Signer) {
        let body = lease_body(l).expect("тело лизы собирается");
        l.signature = signer.sign(&lease_transcript(&body)).unwrap();
    }

    fn request() -> ActionRequest {
        ActionRequest {
            grant_id: [0x67; 16],
            door_fpr: [0xd1; 32],
            kind: ActionKind::GitPush,
            args: push_args(),
            nonce: [0x5a; 16],
            note: "выкладываю ветку агента".to_string(),
        }
    }

    /// Поля тела — парами «тег, значение», для пересборки руками.
    fn fields_of(body: &[u8]) -> Vec<(u16, Vec<u8>)> {
        let mut reader = TlvReader::new(body);
        let mut out = Vec::new();
        while let Some(f) = reader.next_field().unwrap() {
            out.push((f.tag, f.value.to_vec()));
        }
        out
    }

    fn rebuild_with(body: &[u8], tag: u16, value: &[u8]) -> Vec<u8> {
        let mut w = TlvWriter::new();
        for (t, v) in fields_of(body) {
            if t == tag {
                w.put(t, value).unwrap();
            } else {
                w.put(t, &v).unwrap();
            }
        }
        w.finish().to_vec()
    }

    fn rebuild_plus(body: &[u8], tag: u16, value: &[u8]) -> Vec<u8> {
        let mut w = TlvWriter::new();
        for (t, v) in fields_of(body) {
            w.put(t, &v).unwrap();
        }
        w.put(tag, value).unwrap();
        w.finish().to_vec()
    }

    fn signed(body: &[u8], signer: &Ed25519Signer) -> Vec<u8> {
        let sig = signer.sign(&grant_transcript(body)).unwrap();
        let mut out = sig.to_vec();
        out.extend_from_slice(body);
        out
    }

    // --------------------------------------------------------------------
    // Кодеки.
    // --------------------------------------------------------------------

    #[test]
    fn the_grant_round_trips_with_every_kind_of_rule() {
        let g = grant();
        let bytes = encode_grant(&g).unwrap();
        assert_eq!(decode_grant(&bytes, &author().public_key()).unwrap(), g);
    }

    #[test]
    fn the_request_round_trips() {
        let r = request();
        let bytes = encode_request(&r).unwrap();
        assert_eq!(decode_request(&bytes).unwrap(), r);
    }

    #[test]
    fn the_lease_round_trips() {
        let l = lease();
        let bytes = encode_lease(&l).unwrap();
        assert_eq!(decode_lease(&bytes, &server().public_key()).unwrap(), l);
    }

    /// ПОДПИСЬ ГРАНТА ПРОВЕРЯЕТСЯ ДО РАЗБОРА ТЕЛА.
    ///
    /// Тело здесь заведомо неразбираемо, и проба различает порядок двумя
    /// прогонами: со своей подписью ответ обязан быть РАЗБОРНЫМ, с чужой —
    /// ПОДПИСНЫМ. Один прогон этого не показал бы: `is_err()` истинно у обоих
    /// порядков.
    #[test]
    fn a_broken_grant_body_fails_the_signature_before_parsing() {
        let good = grant_body(&grant()).unwrap();
        let unknown_critical = rebuild_plus(&good, 0x7FFF, &[0xab; 4]);
        let bad_clock =
            rebuild_with(&good, grant_tag::EXPIRES_AT, &(-1_i64).to_le_bytes());

        for (what, body) in
            [("чужой критичный тег", unknown_critical), ("срок раньше выдачи", bad_clock)]
        {
            let own = signed(&body, &author());
            let parsed = decode_grant(&own, &author().public_key());
            assert!(
                matches!(
                    parsed,
                    Err(FormatError::BadFieldLength { .. }
                        | FormatError::UnknownCriticalField { .. })
                ),
                "{what}: предпосылка неверна, тело разбирается: {parsed:?}"
            );

            let forged = signed(&body, &stranger());
            let outcome = decode_grant(&forged, &author().public_key());
            assert!(
                matches!(outcome, Err(FormatError::BadHeaderSignature)),
                "{what}: разбор произошёл до проверки подписи, ответ {outcome:?}"
            );
        }
    }

    /// ТО ЖЕ ДЛЯ ЛИЗЫ: подпись сервера — раньше разбора.
    #[test]
    fn a_broken_lease_body_fails_the_signature_before_parsing() {
        let good = lease_body(&lease()).unwrap();
        let body = rebuild_plus(&good, 0x7FFF, &[0xab; 4]);

        let own = {
            let sig = server().sign(&lease_transcript(&body)).unwrap();
            let mut out = sig.to_vec();
            out.extend_from_slice(&body);
            out
        };
        assert!(
            matches!(
                decode_lease(&own, &server().public_key()),
                Err(FormatError::UnknownCriticalField { .. })
            ),
            "предпосылка неверна: тело разбирается"
        );

        let forged = {
            let sig = stranger().sign(&lease_transcript(&body)).unwrap();
            let mut out = sig.to_vec();
            out.extend_from_slice(&body);
            out
        };
        let outcome = decode_lease(&forged, &server().public_key());
        assert!(
            matches!(outcome, Err(FormatError::BadHeaderSignature)),
            "разбор произошёл до проверки подписи: {outcome:?}"
        );
    }

    /// Подпись гранта не годится подписью лизы, и наоборот: домены разные.
    #[test]
    fn the_two_documents_do_not_share_a_signing_domain() {
        let body = lease_body(&lease()).unwrap();
        let wrong_domain = server().sign(&grant_transcript(&body)).unwrap();
        let mut document = wrong_domain.to_vec();
        document.extend_from_slice(&body);
        assert!(
            matches!(
                decode_lease(&document, &server().public_key()),
                Err(FormatError::BadHeaderSignature)
            ),
            "подпись в домене гранта принята лизой"
        );
    }

    #[test]
    fn a_grant_signed_by_another_author_is_refused() {
        let mut g = grant();
        sign_grant(&mut g, &stranger());
        let bytes = encode_grant(&g).unwrap();
        assert!(matches!(
            decode_grant(&bytes, &author().public_key()),
            Err(FormatError::BadHeaderSignature)
        ));
    }

    /// Подпись СХОДИТСЯ, а имя автора внутри другое — грант всё равно отвергнут.
    #[test]
    fn the_author_key_inside_must_match_the_one_supplied() {
        let mut g = grant();
        g.author_key = [0x99; 32];
        sign_grant(&mut g, &author());
        let bytes = encode_grant(&g).unwrap();
        match decode_grant(&bytes, &author().public_key()) {
            Err(FormatError::BadFieldLength { tag, .. }) => {
                assert_eq!(tag, grant_tag::AUTHOR_KEY);
            }
            other => panic!("грант с чужим именем автора принят: {other:?}"),
        }
    }

    /// ВЗГЛЯД БЕЗ ПОДПИСИ ОТДАЁТ ТО ЖЕ ТЕЛО — И НЕ ЗАМЕНЯЕТ ПРОВЕРКИ.
    #[test]
    fn peeking_reads_the_same_body_but_never_stands_in_for_the_signature() {
        let g = grant();
        let bytes = encode_grant(&g).unwrap();
        assert_eq!(peek_grant(&bytes).unwrap(), g);

        let body = grant_body(&g).unwrap();
        let forged = signed(&body, &stranger());
        assert!(peek_grant(&forged).is_ok(), "взгляд обязан проходить и без своей подписи");
        assert!(
            matches!(
                decode_grant(&forged, &author().public_key()),
                Err(FormatError::BadHeaderSignature)
            ),
            "чужая подпись принята"
        );
    }

    #[test]
    fn an_unknown_optional_tag_is_skipped_and_a_critical_one_is_refused() {
        let good = grant_body(&grant()).unwrap();

        let skipped = rebuild_plus(&good, 0x8000, &[1, 2, 3]);
        let back = decode_grant(&signed(&skipped, &author()), &author().public_key()).unwrap();
        let mut expected = grant();
        expected.signature = back.signature;
        assert_eq!(back, expected, "необязательный тег не проехал мимо");

        let refused = rebuild_plus(&good, 0x7FFF, &[1, 2, 3]);
        assert!(
            matches!(
                decode_grant(&signed(&refused, &author()), &author().public_key()),
                Err(FormatError::UnknownCriticalField { tag: 0x7FFF })
            ),
            "критичный тег из будущей версии пропущен молча"
        );
    }

    /// НЕЗНАКОМЫЙ ВИД ДЕЙСТВИЯ ОТВЕРГАЕТСЯ НА РАЗБОРЕ.
    #[test]
    fn an_unknown_action_kind_is_refused_on_parse() {
        let bytes = encode_request(&request()).unwrap();
        let broken = rebuild_with(&bytes, request_tag::KIND, &99_u16.to_le_bytes());
        assert!(
            matches!(
                decode_request(&broken),
                Err(FormatError::BadFieldLength { tag: request_tag::KIND, .. })
            ),
            "вид вне реестра принят"
        );
    }

    /// `force` НЕВЫРАЗИМ: лишний критичный тег в аргументах — отказ.
    ///
    /// Проба стережёт не строку кода, а СВОЙСТВО: поля под `--force` нет, и
    /// дописать его в подписанные аргументы не выйдет — разбор отвергнет тег до
    /// того, как исполнитель увидит структуру.
    #[test]
    fn an_extra_critical_tag_in_the_arguments_is_refused() {
        let ask = request();
        let args = encode_args(&ask.args).unwrap();
        // Тег 12 в реестре аргументов не занят и лежит в критичном диапазоне —
        // ровно так выглядел бы дописанный `force`.
        let with_force = rebuild_plus(&args, 12, &[1]);
        assert!(
            matches!(
                decode_args(&with_force, ActionKind::GitPush),
                Err(FormatError::UnknownCriticalField { tag: 12 })
            ),
            "лишний критичный тег в аргументах принят"
        );

        // И чужой ЗНАКОМЫЙ тег — тоже отказ: `host` принадлежит другому виду.
        let with_host = rebuild_plus(&args, field_tag::HOST, b"example.com");
        assert!(
            matches!(
                decode_args(&with_host, ActionKind::GitPush),
                Err(FormatError::UnknownCriticalField { tag: field_tag::HOST })
            ),
            "тег чужого вида принят в аргументах git.push"
        );
    }

    /// Вид и вариант аргументов — два утверждения об одном, и расходиться им
    /// нельзя.
    #[test]
    fn the_kind_must_agree_with_the_arguments() {
        let mut ask = request();
        ask.kind = ActionKind::TreeRemove;
        assert!(encode_request(&ask).is_err(), "писатель выпустил просьбу с чужим видом");
    }

    #[test]
    fn the_flags_are_exactly_zero_or_one() {
        let g = grant();
        let body = grant_body(&g).unwrap();
        let rules = fields_of(&body)
            .into_iter()
            .find(|(t, _)| *t == grant_tag::RULES)
            .map(|(_, v)| v)
            .unwrap();
        // Первое правило — запись с тегом 0.
        let first = fields_of(&rules).into_iter().find(|(t, _)| *t == 0).map(|(_, v)| v).unwrap();
        let broken = rebuild_with(&first, rule_tag::CONFIRM, &[2]);
        assert!(
            matches!(
                decode_rule(&broken),
                Err(FormatError::BadFieldLength { tag: rule_tag::CONFIRM, .. })
            ),
            "признак принял значение, которого у истины нет"
        );
    }

    #[test]
    fn a_lease_longer_than_its_window_is_refused() {
        let mut l = lease();
        l.expires_at = l.issued_at + ACTION_LEASE_SECONDS + 1;
        assert!(lease_body(&l).is_err(), "писатель выпустил лизу шире окна");

        let good = lease_body(&lease()).unwrap();
        let body = rebuild_with(
            &good,
            lease_tag::EXPIRES_AT,
            &(1_700_010_000_i64 + ACTION_LEASE_SECONDS + 1).to_le_bytes(),
        );
        let sig = server().sign(&lease_transcript(&body)).unwrap();
        let mut document = sig.to_vec();
        document.extend_from_slice(&body);
        assert!(
            matches!(
                decode_lease(&document, &server().public_key()),
                Err(FormatError::BadFieldLength { tag: lease_tag::EXPIRES_AT, .. })
            ),
            "лиза шире обещанного окна принята"
        );
    }

    #[test]
    fn more_rules_than_the_ceiling_is_refused() {
        let mut g = grant();
        g.rules = (0..=MAX_ACTION_RULES).map(|_| push_rule()).collect();
        assert!(grant_body(&g).is_err(), "писатель выпустил грант длиннее потолка");
    }

    #[test]
    fn methods_out_of_order_or_repeated_are_refused() {
        for (what, methods) in [
            ("перестановка", vec![Method::Post, Method::Get]),
            ("повтор", vec![Method::Get, Method::Get]),
            ("пустой список", vec![]),
        ] {
            let mut rule = http_rule();
            rule.constraint = Constraint::HttpRequest {
                host: "api.example.com".to_string(),
                methods,
                path_prefix: "/v1".to_string(),
                secret_ref: None,
            };
            assert!(encode_rule(&rule).is_err(), "{what}: писатель принял список методов");
        }
    }

    /// ФОРМА ПУТИ: `..`, абсолютный путь и чужие символы отвергаются.
    #[test]
    fn a_path_that_escapes_the_tree_is_refused_by_the_codec() {
        for bad in ["../etc/passwd", "/etc/passwd", "src/../../x", "C:/windows", "src\\x", "src//x", "src/./x", ""]
        {
            let mut rule = remove_rule();
            rule.constraint = Constraint::TreeRemove { prefix: bad.to_string() };
            assert!(encode_rule(&rule).is_err(), "путь {bad:?} принят писателем");
        }
        // Положительный контроль: правило не запрещает вообще всё.
        let mut rule = remove_rule();
        rule.constraint = Constraint::TreeRemove { prefix: "src/deep/leaf.rs".to_string() };
        assert!(encode_rule(&rule).is_ok(), "честный путь отвергнут — правило слишком строго");
    }

    #[test]
    fn a_host_mask_is_inexpressible() {
        for bad in ["*.example.com", "API.example.com", "", ".example.com", "ex..com", "-ex.com"] {
            let mut rule = http_rule();
            rule.constraint = Constraint::HttpRequest {
                host: bad.to_string(),
                methods: vec![Method::Get],
                path_prefix: "/".to_string(),
                secret_ref: None,
            };
            assert!(encode_rule(&rule).is_err(), "хост {bad:?} принят писателем");
        }
        let mut rule = http_rule();
        rule.constraint = Constraint::HttpRequest {
            host: "api.example.com".to_string(),
            methods: vec![Method::Get],
            path_prefix: "/".to_string(),
            secret_ref: None,
        };
        assert!(encode_rule(&rule).is_ok(), "честный хост отвергнут");
    }

    #[test]
    fn an_http_path_with_a_query_is_refused() {
        for bad in ["/v1?x=1", "v1/issues", "/v1/../admin", "/v1/", "#frag"] {
            let mut rule = http_rule();
            rule.constraint = Constraint::HttpRequest {
                host: "api.example.com".to_string(),
                methods: vec![Method::Get],
                path_prefix: bad.to_string(),
                secret_ref: None,
            };
            assert!(encode_rule(&rule).is_err(), "префикс пути {bad:?} принят");
        }
        let mut rule = http_rule();
        rule.constraint = Constraint::HttpRequest {
            host: "api.example.com".to_string(),
            methods: vec![Method::Get],
            path_prefix: "/".to_string(),
            secret_ref: None,
        };
        assert!(encode_rule(&rule).is_ok(), "корень отвергнут как префикс");
    }

    #[test]
    fn a_body_longer_than_a_megabyte_is_refused_on_parse() {
        let args = Args::HttpRequest {
            host: "api.example.com".to_string(),
            method: Method::Post,
            path: "/v1/issues".to_string(),
            body_digest: [0; 32],
            body_len: MAX_BODY_LEN + 1,
        };
        assert!(encode_args(&args).is_err(), "писатель принял тело больше мегабайта");
    }

    // --------------------------------------------------------------------
    // `args_within`.
    // --------------------------------------------------------------------

    #[test]
    fn honest_arguments_pass_every_kind() {
        args_within(&push_rule(), &push_args()).expect("push в разрешённую ветку");
        args_within(&remove_rule(), &Args::TreeRemove { path: "src/main.rs".to_string() })
            .expect("удаление под префиксом");
        args_within(
            &rename_rule(),
            &Args::TreeRename { from: "src/old.rs".to_string(), to: "attic/old.rs".to_string() },
        )
        .expect("переименование под обоими префиксами");
        args_within(&http_rule(), &http_args()).expect("запрос под префиксом пути");
    }

    #[test]
    fn arguments_of_another_kind_are_refused() {
        assert_eq!(
            args_within(&push_rule(), &Args::TreeRemove { path: "src/x".to_string() }),
            Err(ActionRefusal::WrongKind)
        );
    }

    /// ПРАВИЛО, ЧЕЙ НОМЕР ВИДА ЛЖЁТ ОБ ОГРАНИЧИТЕЛЕ, НЕ ИСПОЛНЯЕТСЯ.
    ///
    /// Заведена по итогу мутации: снятие сверки видов в начале [`crate::action::args_within`]
    /// не покраснило НИ ОДНОЙ пробы — отказ приходил от последней ветви `match`,
    /// и выглядело это как сторож. Сторожем оно не было: `match` смотрит на
    /// ВАРИАНТ ограничителя, а не на объявленный номер вида, и правило, где эти
    /// двое расходятся, исполнялось бы по ограничителю.
    ///
    /// Документ такой формы наш разбор не выпустит (`check_rule_shape`), и
    /// именно поэтому проба нужна здесь: [`crate::action::args_within`] — функция ЧИСТАЯ, её
    /// зовут на структуре, собранной в памяти двери, а не только на разобранной.
    #[test]
    fn a_rule_whose_kind_contradicts_its_limiter_is_refused() {
        let mut liar = remove_rule();
        liar.kind = ActionKind::GitPush;
        assert!(check_rule_shape(&liar).is_err(), "предпосылка: такой документ не выпускается");

        assert_eq!(
            args_within(&liar, &Args::TreeRemove { path: "src/main.rs".to_string() }),
            Err(ActionRefusal::WrongKind),
            "действие исполнено по ограничителю, хотя правило называет другой вид"
        );
        assert_eq!(args_within(&liar, &push_args()), Err(ActionRefusal::WrongKind));
    }

    #[test]
    fn another_remote_or_branch_is_refused_by_name() {
        assert_eq!(
            args_within(
                &push_rule(),
                &Args::GitPush { remote: "upstream".to_string(), branch: "agent/work".to_string() }
            ),
            Err(ActionRefusal::NotEqual { limiter: "remote" })
        );
        assert_eq!(
            args_within(
                &push_rule(),
                &Args::GitPush { remote: "origin".to_string(), branch: "main".to_string() }
            ),
            Err(ActionRefusal::NotEqual { limiter: "branch" })
        );
    }

    /// `src2` НЕ ПОД `src` — сравнение по компонентам, а не по строке.
    ///
    /// Проба за правилом, ради которого сравнение и написано компонентами: по
    /// строке `"src2/x"` начинается с `"src"`, и грант на один каталог отдавал
    /// бы соседний.
    #[test]
    fn a_sibling_directory_is_not_under_the_prefix() {
        assert_eq!(
            args_within(&remove_rule(), &Args::TreeRemove { path: "src2/main.rs".to_string() }),
            Err(ActionRefusal::OutsidePrefix { limiter: "prefix" })
        );
        // Положительный контроль: настоящий потомок проходит, иначе проба выше
        // зеленела бы и при правиле «запрещено всё».
        assert!(
            args_within(&remove_rule(), &Args::TreeRemove { path: "src/main.rs".to_string() })
                .is_ok()
        );
        // И сам префикс — тоже «под»: однофайловый грант обязан работать.
        assert!(
            args_within(&remove_rule(), &Args::TreeRemove { path: "src".to_string() }).is_ok()
        );
    }

    #[test]
    fn a_path_leaving_the_tree_is_refused_before_the_prefix_is_even_checked() {
        assert_eq!(
            args_within(&remove_rule(), &Args::TreeRemove { path: "src/../../etc".to_string() }),
            Err(ActionRefusal::BadPath { limiter: "prefix" })
        );
        assert_eq!(
            args_within(&remove_rule(), &Args::TreeRemove { path: "/etc/passwd".to_string() }),
            Err(ActionRefusal::BadPath { limiter: "prefix" })
        );
    }

    #[test]
    fn both_halves_of_a_rename_are_checked() {
        let rule = rename_rule();
        assert_eq!(
            args_within(
                &rule,
                &Args::TreeRename { from: "docs/x".to_string(), to: "attic/x".to_string() }
            ),
            Err(ActionRefusal::OutsidePrefix { limiter: "from_prefix" })
        );
        assert_eq!(
            args_within(
                &rule,
                &Args::TreeRename { from: "src/x".to_string(), to: "docs/x".to_string() }
            ),
            Err(ActionRefusal::OutsidePrefix { limiter: "to_prefix" })
        );
    }

    #[test]
    fn the_http_limiters_are_all_checked() {
        let rule = http_rule();

        let mut args = http_args();
        if let Args::HttpRequest { host, .. } = &mut args {
            *host = "evil.example.com".to_string();
        }
        assert_eq!(args_within(&rule, &args), Err(ActionRefusal::NotEqual { limiter: "host" }));

        let mut args = http_args();
        if let Args::HttpRequest { method, .. } = &mut args {
            *method = Method::Delete;
        }
        assert_eq!(args_within(&rule, &args), Err(ActionRefusal::MethodNotAllowed));

        let mut args = http_args();
        if let Args::HttpRequest { path, .. } = &mut args {
            *path = "/v1/issues2/42".to_string();
        }
        assert_eq!(
            args_within(&rule, &args),
            Err(ActionRefusal::OutsidePrefix { limiter: "path_prefix" })
        );

        let mut args = http_args();
        if let Args::HttpRequest { body_len, .. } = &mut args {
            *body_len = MAX_BODY_LEN + 1;
        }
        assert_eq!(
            args_within(&rule, &args),
            Err(ActionRefusal::BodyTooLarge { len: MAX_BODY_LEN + 1 })
        );

        // Контроль: ровно мегабайт ещё проходит — иначе проба выше зеленела бы
        // и при правиле «тело всегда велико».
        let mut args = http_args();
        if let Args::HttpRequest { body_len, .. } = &mut args {
            *body_len = MAX_BODY_LEN;
        }
        assert!(args_within(&rule, &args).is_ok());
    }

    // --------------------------------------------------------------------
    // `narrower`.
    // --------------------------------------------------------------------

    #[test]
    fn a_narrowing_child_rule_passes() {
        let parent = remove_rule();
        let mut child = remove_rule();
        child.constraint = Constraint::TreeRemove { prefix: "src/agent".to_string() };
        child.max_uses = 5;
        child.delegable = false;
        narrower(&child, &parent).expect("сужение обязано проходить");
    }

    #[test]
    fn a_child_of_another_kind_is_refused() {
        assert_eq!(narrower(&remove_rule(), &push_rule()), Err(ActionRefusal::WrongKind));
    }

    #[test]
    fn a_confirm_rule_is_never_delegated() {
        let mut parent = push_rule();
        parent.confirm = true;
        let child = push_rule();
        assert_eq!(narrower(&child, &parent), Err(ActionRefusal::ConfirmNotDelegable));
    }

    #[test]
    fn a_rule_not_marked_delegable_is_not_delegated() {
        let parent = rename_rule();
        assert!(!parent.delegable, "предпосылка: правило не делегируемо");
        assert_eq!(narrower(&rename_rule(), &parent), Err(ActionRefusal::NotDelegable));
    }

    /// `delegable` ТОЛЬКО СНИМАЕТСЯ: поднять его потомок не вправе.
    #[test]
    fn delegable_can_only_be_dropped() {
        let mut parent = remove_rule();
        parent.delegable = false;
        let mut child = remove_rule();
        child.delegable = true;
        assert_eq!(narrower(&child, &parent), Err(ActionRefusal::NotDelegable));

        // Контроль: при делегируемом родителе снятие проходит.
        let parent = remove_rule();
        let mut child = remove_rule();
        child.delegable = false;
        assert!(narrower(&child, &parent).is_ok());
    }

    #[test]
    fn a_child_cannot_widen_the_use_count() {
        let parent = push_rule();
        assert_eq!(parent.max_uses, 10, "предпосылка");

        let mut child = push_rule();
        child.max_uses = 11;
        assert_eq!(narrower(&child, &parent), Err(ActionRefusal::MoreUses));

        // «Без предела» у потомка при пределе у родителя — тоже расширение, и
        // именно так выглядела бы дыра: `0` меньше десяти как число.
        let mut child = push_rule();
        child.max_uses = 0;
        assert_eq!(narrower(&child, &parent), Err(ActionRefusal::MoreUses));

        // Контроль: у родителя без предела потомок берёт сколько угодно.
        let mut boundless = push_rule();
        boundless.max_uses = 0;
        let mut child = push_rule();
        child.max_uses = 1_000;
        assert!(narrower(&child, &boundless).is_ok());
    }

    #[test]
    fn a_child_cannot_widen_a_limiter() {
        // git.push: remote и branch — равенство.
        let mut child = push_rule();
        child.constraint = Constraint::GitPush {
            remote: "upstream".to_string(),
            branch: "agent/work".to_string(),
        };
        assert_eq!(
            narrower(&child, &push_rule()),
            Err(ActionRefusal::WiderLimiter { limiter: "remote" })
        );

        // tree.remove: префикс вверх по дереву.
        let mut child = remove_rule();
        child.constraint = Constraint::TreeRemove { prefix: "src2".to_string() };
        assert_eq!(
            narrower(&child, &remove_rule()),
            Err(ActionRefusal::WiderLimiter { limiter: "prefix" })
        );

        // tree.rename: обе половины.
        let mut parent = rename_rule();
        parent.delegable = true;
        let mut child = parent.clone();
        child.constraint = Constraint::TreeRename {
            from_prefix: "docs".to_string(),
            to_prefix: "attic".to_string(),
        };
        assert_eq!(
            narrower(&child, &parent),
            Err(ActionRefusal::WiderLimiter { limiter: "from_prefix" })
        );
        let mut child = parent.clone();
        child.constraint = Constraint::TreeRename {
            from_prefix: "src".to_string(),
            to_prefix: "docs".to_string(),
        };
        assert_eq!(
            narrower(&child, &parent),
            Err(ActionRefusal::WiderLimiter { limiter: "to_prefix" })
        );
    }

    #[test]
    fn the_http_child_narrows_host_methods_path_and_secret() {
        let parent = http_rule();

        let widen = |limit: Constraint| {
            let mut child = http_rule();
            child.constraint = limit;
            narrower(&child, &parent)
        };

        assert_eq!(
            widen(Constraint::HttpRequest {
                host: "other.example.com".to_string(),
                methods: vec![Method::Get],
                path_prefix: "/v1/issues".to_string(),
                secret_ref: Some("FORGE_TOKEN".to_string()),
            }),
            Err(ActionRefusal::WiderLimiter { limiter: "host" })
        );

        assert_eq!(
            widen(Constraint::HttpRequest {
                host: "api.example.com".to_string(),
                methods: vec![Method::Get, Method::Post, Method::Delete],
                path_prefix: "/v1/issues".to_string(),
                secret_ref: Some("FORGE_TOKEN".to_string()),
            }),
            Err(ActionRefusal::WiderLimiter { limiter: "methods" })
        );

        assert_eq!(
            widen(Constraint::HttpRequest {
                host: "api.example.com".to_string(),
                methods: vec![Method::Get],
                path_prefix: "/v1".to_string(),
                secret_ref: Some("FORGE_TOKEN".to_string()),
            }),
            Err(ActionRefusal::WiderLimiter { limiter: "path_prefix" })
        );

        assert_eq!(
            widen(Constraint::HttpRequest {
                host: "api.example.com".to_string(),
                methods: vec![Method::Get],
                path_prefix: "/v1/issues".to_string(),
                secret_ref: Some("ADMIN_TOKEN".to_string()),
            }),
            Err(ActionRefusal::SecretRefChanged)
        );

        // Контроль: сузить всё разом — можно, и ссылку на секрет можно СНЯТЬ.
        assert!(
            widen(Constraint::HttpRequest {
                host: "api.example.com".to_string(),
                methods: vec![Method::Get],
                path_prefix: "/v1/issues/42".to_string(),
                secret_ref: None,
            })
            .is_ok()
        );
    }

    /// Ссылку на секрет нельзя ДОБАВИТЬ там, где родитель её не назвал.
    #[test]
    fn a_child_cannot_invent_a_secret_reference() {
        let mut parent = http_rule();
        parent.constraint = Constraint::HttpRequest {
            host: "api.example.com".to_string(),
            methods: vec![Method::Get],
            path_prefix: "/v1".to_string(),
            secret_ref: None,
        };
        let mut child = parent.clone();
        child.constraint = Constraint::HttpRequest {
            host: "api.example.com".to_string(),
            methods: vec![Method::Get],
            path_prefix: "/v1".to_string(),
            secret_ref: Some("FORGE_TOKEN".to_string()),
        };
        assert_eq!(narrower(&child, &parent), Err(ActionRefusal::SecretRefChanged));
    }

    /// У КАЖДОГО ОТКАЗА ЕСТЬ ПРИЧИНА СЛОВАМИ.
    ///
    /// Проба против мутации «причина → пустая строка»: отказ без объяснения
    /// проходит любую проверку вида «отказ случился», и ловится он только так.
    #[test]
    fn every_refusal_names_a_reason() {
        for refusal in [
            ActionRefusal::WrongKind,
            ActionRefusal::NotEqual { limiter: "remote" },
            ActionRefusal::OutsidePrefix { limiter: "prefix" },
            ActionRefusal::BadPath { limiter: "prefix" },
            ActionRefusal::MethodNotAllowed,
            ActionRefusal::BodyTooLarge { len: 5 },
            ActionRefusal::ConfirmNotDelegable,
            ActionRefusal::NotDelegable,
            ActionRefusal::MoreUses,
            ActionRefusal::WiderLimiter { limiter: "host" },
            ActionRefusal::SecretRefChanged,
        ] {
            let text = format!("{refusal}");
            assert!(text.len() > 10, "отказ {refusal:?} не объяснён: {text:?}");
        }
    }

    /// Разбор произвольных байтов не паникует: всё это приходит с провода.
    #[test]
    fn decoding_arbitrary_bytes_never_panics() {
        let key = author().public_key();
        let documents =
            [encode_grant(&grant()).unwrap(), encode_lease(&lease()).unwrap(), encode_request(&request()).unwrap()];
        for bytes in &documents {
            for cut in 0..bytes.len() {
                let _ = decode_grant(&bytes[..cut], &key);
                let _ = decode_lease(&bytes[..cut], &key);
                let _ = decode_request(&bytes[..cut]);
            }
        }
        let mut seed = 0x5eed_u64;
        for _ in 0..10_000 {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let len = (seed >> 33) as usize % 128;
            let mut junk = vec![0u8; len];
            for (i, b) in junk.iter_mut().enumerate() {
                *b = (seed >> (i % 8 * 8)) as u8;
            }
            let _ = decode_grant(&junk, &key);
            let _ = decode_lease(&junk, &key);
            let _ = decode_request(&junk);
            let _ = decode_decision(&junk, &key);
            let _ = peek_decision(&junk);
            let _ = decode_pending(&junk);
            let _ = split_action_queue(&junk);
        }
    }

    fn decision() -> ActionDecision {
        let mut d = ActionDecision {
            seq: 11,
            grant_id: [0x67; 16],
            door_fpr: [0xd1; 32],
            approve: true,
            note: "да, эту ветку можно".to_string(),
            author_key: author().public_key(),
            signature: [0; SIGNATURE_LEN],
        };
        let body = decision_body(&d).expect("тело решения собирается");
        d.signature = author().sign(&decision_transcript(&body)).unwrap();
        d
    }

    fn pending() -> PendingAction {
        PendingAction {
            seq: 11,
            grant_id: [0x67; 16],
            door_fpr: [0xd1; 32],
            kind: ActionKind::GitPush,
            args: push_args(),
            nonce: [0x5a; 16],
            note: "выкладываю ветку агента".to_string(),
            at: 1_700_010_000,
        }
    }

    /// РЕШЕНИЕ ВЛАДЕЛЬЦА ПРОВЕРЯЕТСЯ ПОДПИСЬЮ ДО РАЗБОРА И ТОЛЬКО ЕГО КЛЮЧОМ.
    ///
    /// Три половины: круговой проход; чужой ключ — отказ; правка любого байта
    /// тела — отказ. Взгляд без подписи при этом тело читает: по нему сервер и
    /// ищет, чьим ключом проверять.
    #[test]
    fn an_owner_decision_verifies_with_the_author_key_and_nothing_else_passes() {
        let d = decision();
        let bytes = encode_decision(&d).unwrap();
        assert_eq!(decode_decision(&bytes, &author().public_key()).unwrap(), d);
        assert!(
            decode_decision(&bytes, &stranger().public_key()).is_err(),
            "решение принято чужим ключом"
        );
        // Взгляд читает то же тело, но исполнять по нему нельзя ничего.
        assert_eq!(peek_decision(&bytes).unwrap(), d);

        for index in 0..bytes.len() {
            let mut broken = bytes.clone();
            broken[index] ^= 0x01;
            assert!(
                decode_decision(&broken, &author().public_key()).is_err(),
                "правка байта {index} прошла проверку"
            );
        }
    }

    /// ПОЛЕ `author_key` В РЕШЕНИИ СВЕРЯЕТСЯ С ПЕРЕДАННЫМ КЛЮЧОМ.
    ///
    /// Оно есть в подписанном теле, и потому это утверждение «решение выпущено
    /// этим автором», а не источник истины: ключ проверки приходит из записи
    /// сервера. Подписав тело с чужим ключом внутри СВОИМ ключом, автор получил
    /// бы документ, который сходится подписью и лжёт полем.
    #[test]
    fn the_author_key_inside_the_decision_is_checked_against_the_one_passed_in() {
        let mut d = decision();
        d.author_key = stranger().public_key();
        let body = decision_body(&d).unwrap();
        d.signature = author().sign(&decision_transcript(&body)).unwrap();
        let bytes = encode_decision(&d).unwrap();
        assert!(
            decode_decision(&bytes, &author().public_key()).is_err(),
            "решение с чужим ключом в теле принято"
        );
    }

    /// ДОМЕНЫ РЕШЕНИЙ РАЗВЕДЕНЫ: ПОДПИСЬ ПО ДОСТУПУ НЕ ГОДИТСЯ ДЛЯ ДЕЙСТВИЯ.
    ///
    /// Ключ у обоих один — автора, — и без разных меток одно подписанное «да»
    /// годилось бы вместо другого. Проверяется прямо: подпись по транскрипту
    /// решения о ДОСТУПЕ над тем же телом этим разбором не принимается.
    #[test]
    fn a_decision_signature_from_the_access_domain_does_not_pass_here() {
        let d = decision();
        let body = decision_body(&d).unwrap();
        let foreign = author().sign(&crate::access::decision_transcript(&body)).unwrap();
        let mut bytes = foreign.to_vec();
        bytes.extend_from_slice(&body);
        assert!(
            decode_decision(&bytes, &author().public_key()).is_err(),
            "подпись из домена доступа принята за решение по действию"
        );
    }

    /// ЗАПИСЬ ОЧЕРЕДИ И САМА ОЧЕРЕДЬ: КРУГОВОЙ ПРОХОД, ОКНО, ОБРЫВ.
    ///
    /// Положительный контроль первым: очередь ровно в окно ПРИНИМАЕТСЯ. Без
    /// него отказ выше окна зеленел бы и на разборщике, который не принимает
    /// ничего.
    #[test]
    fn the_confirm_queue_round_trips_and_refuses_more_than_its_window() {
        let p = pending();
        assert_eq!(decode_pending(&encode_pending(&p).unwrap()).unwrap(), p);

        let one = encode_pending(&p).unwrap();
        let mut body = Vec::new();
        for _ in 0..MAX_PENDING_ACTION_WINDOW {
            body.extend_from_slice(&(one.len() as u32).to_le_bytes());
            body.extend_from_slice(&one);
        }
        assert_eq!(split_action_queue(&body).unwrap().len(), MAX_PENDING_ACTION_WINDOW);

        let mut over = body.clone();
        over.extend_from_slice(&(one.len() as u32).to_le_bytes());
        over.extend_from_slice(&one);
        assert!(split_action_queue(&over).is_err(), "очередь выше окна принята");

        // Обрыв на длине и внутри записи — отказ, а не «почти правильно».
        for cut in [1usize, 3, body.len() - 1] {
            assert!(split_action_queue(&body[..cut]).is_err(), "обрубок длиной {cut} принят");
        }
        // Пустая очередь законна: «никто не просит» — не отказ.
        assert!(split_action_queue(&[]).unwrap().is_empty());
    }

    /// КЛЮЧ ПРАВИЛА РАЗЛИЧАЕТ ДВА ПРАВИЛА ОДНОГО ВИДА.
    ///
    /// Счёт исполнений сервер ведёт по паре «держатель — правило», и два
    /// `tree.remove` на два поддерева — обычный грант. Спутай их ключ — и
    /// исполнение списывалось бы не с того предела.
    ///
    /// Предел и флаги в ключ НЕ входят намеренно: правило, у которого сменили
    /// `max_uses`, остаётся тем же правилом, и счёт по нему не должен
    /// обнуляться.
    #[test]
    fn a_rule_key_tells_two_rules_of_one_kind_apart() {
        let mut a = remove_rule();
        let mut b = remove_rule();
        assert_eq!(limiter_key(&a).unwrap(), limiter_key(&b).unwrap());

        b.constraint = Constraint::TreeRemove { prefix: "docs".to_string() };
        assert_ne!(
            limiter_key(&a).unwrap(),
            limiter_key(&b).unwrap(),
            "два поддерева получили один ключ"
        );
        // Вид входит в ключ: ограничители разных видов пользуются своими
        // тегами, но полагаться на это значило бы полагаться на совпадение.
        assert_ne!(limiter_key(&remove_rule()).unwrap(), limiter_key(&push_rule()).unwrap());

        // Предел и флаги ключа не меняют.
        let key = limiter_key(&a).unwrap();
        a.max_uses = 0;
        a.confirm = !a.confirm;
        a.delegable = !a.delegable;
        assert_eq!(limiter_key(&a).unwrap(), key, "смена предела сменила ключ правила");
    }
}
