//! Распоряжение автора серверу: что сделать с файлом.
//!
//! До 2026-09-03 регистрация и отзыв были операторскими командами `cca` на
//! машине сервера, и «кто для сервера автор» решалось тем, у кого есть доступ к
//! этой машине. По проводу так нельзя: `file_id` лежит в заголовке открытым, и
//! без подписи любой, кому файл переслали, зарегистрировал бы его на своих
//! условиях или отозвал у всех (`docs/protocol.md` §9.3).
//!
//! Распоряжение — TLV-документ за подписью КЛЮЧА АВТОРА, того самого, что
//! подписал заголовок контейнера. Регистрация несёт рядом заголовок целиком:
//! сервер проверяет подпись заголовка, берёт из него ключ автора и им
//! проверяет распоряжение — ключ автора сервер узнаёт не со слов просителя, а
//! из документа, который получатель изменить не может. Отзыв проверяется
//! ключом, запомненным при регистрации.
//!
//! Раскладка та же, что у отзывной и у лизинга: `подпись(64) ‖ тело`. Подпись
//! идёт первой, чтобы обрубок документа не разбирался «почти успешно».
//!
//! Момент выписки — часть тела и часть подписи: сервер принимает только
//! свежее распоряжение (допуск перекоса часов), так что документ, пролежавший
//! где-то и всплывший, не исполняется.
//!
//! Свежести мало, и здесь стояло, что её и довольно: «обе операции идемпотентны,
//! повтор ничего не даёт». Написано это было о двух видах — регистрации и
//! отзыве; видов теперь восемь, и повтор голоса, состава или оттепели меняет
//! состояние. Порядок МЕЖДУ распоряжениями держит сервер барьером по виду
//! (`docs/protocol.md` §11.11), а не эта проверка.

//! Видов распоряжений больше двух: к регистрации и отзыву добавились признак
//! жизни автора и назначение наследника (`docs/protocol.md` §11). Раскладка,
//! подпись и правило свежести у всех общие — различается только состав полей.
//! Состав проверяется по виду в ОБЕ стороны, одной функцией `check`: разойдись
//! проверка записи с проверкой разбора хоть на одно поле — и распоряжение,
//! которое мы отказываемся выписать, мы всё же исполнили бы, придя оно со
//! стороны.

use oc_crypto::CryptoError;

use oc_format::FormatError;
use oc_format::tlv::{TlvReader, TlvWriter};

/// Версия тела распоряжения.
pub const ORDER_VERSION: u16 = 1;

/// Длина подписи Ed25519 перед телом.
pub const SIGNATURE_LEN: usize = 64;

/// Сколько наследников принимает одно распоряжение.
///
/// Шестнадцать — тот же предел, что у состава, и по той же причине: список
/// читает человек, и тот, в котором он не находит нужное глазами, ничем не лучше
/// отсутствующего. Предел стоит и до выделения памяти: поток в мегабайт иначе
/// заставил бы собрать тысячи решений, чтобы затем их отвергнуть.
pub const MAX_HEIRS: usize = 16;

/// Сколько ключей принимает один состав — соавторов или одобряющих.
///
/// Шестнадцать: столько же, сколько адресов сервера в заголовке и запросов в
/// очереди, и по той же причине — величина, которую человек в состоянии
/// просмотреть глазами. Предел делят обе стороны: он часть формата документа, а
/// не вкус сервера.
pub const MAX_KEYS: usize = 16;

/// Сколько имён одного устройства называет замена.
///
/// Четыре — столько механизмов у устройства бывает сразу: X25519, X-Wing, P-256
/// в TPM и аппаратный гибрид. Больше означало бы уже не одно устройство.
pub const MAX_DEVICE_NAMES: usize = 4;

/// Теги тела. Все критичные: незнакомый тег — отказ (И-7).
pub mod tag {
    pub const VERSION: u16 = 1;
    pub const FILE_ID: u16 = 2;
    pub const KIND: u16 = 3;
    pub const AT: u16 = 4;
    /// Только для регистрации: предел устройств.
    pub const MAX_DEVICES: u16 = 5;
    /// Только для регистрации: предел выдач.
    pub const MAX_GRANTS: u16 = 6;
    /// Только у `SetCoauthors`/`SetApprovers`: ключи подряд по 32 байта.
    ///
    /// Потоком без нумерации, а не тегом на ключ: номер тегом упирается в
    /// потолок 65536 (И-7), а здесь он не нужен вовсе — длина элемента
    /// постоянна, и порядок задаётся положением.
    pub const KEYS: u16 = 7;
    /// Только у `SetCoauthors`/`SetApprovers`: сколько подписей из состава
    /// требуется. Ноль при пустом составе означает «кворума нет».
    pub const THRESHOLD: u16 = 8;
    /// Только у `ApproveDevice`: за какое устройство голос.
    pub const DEVICE_FPR: u16 = 9;
    /// Только у `ApproveDevice`: за или против.
    pub const APPROVE: u16 = 10;
    /// Только у `SetHeir{Open|Close}`: сколько секунд молчания автора считать
    /// событием.
    pub const SILENCE_SECONDS: u16 = 11;
    /// Только у `SetHeir`: что делать после тишины.
    pub const HEIR_MODE: u16 = 12;
    /// Только у `SetHeir{Open}`: готовые решения автора наследникам, потоком.
    ///
    /// # Почему поток, и почему номер не сожжён
    ///
    /// Заводился тег под ОДНО решение. Наследников оказалось несколько (решение
    /// заказчика 2026-09-05), и содержимое расширено до потока
    /// `u32le длина ‖ Decision`, повторяющегося до `MAX_HEIRS` раз.
    ///
    /// Номер при этом не переиспользован под другой смысл, а тот же смысл выражен
    /// точнее: «кому и что достаётся после тишины». И-7 запрещает первое, но не
    /// второе. Сжигать номер было бы не осторожностью, а суеверием: ни один
    /// сервер с назначенным наследником не выпущен, а документы протокола, кроме
    /// лизинга, не заморожены (`docs/protocol.md` §0). Один наследник —
    /// по-прежнему законный случай: поток из одной записи.
    pub const BEQUEST: u16 = 13;
    /// Чей ключ проверяет подпись, когда взять его по файлу нельзя.
    ///
    /// # Почему имя сменилось, а номер нет
    ///
    /// Тег заводился как `AUTHOR_KEY` — «чьё присутствие отмечено» у признака
    /// жизни за все файлы сразу. С голосом одобряющего выяснилось, что смысл у
    /// поля ШИРЕ: подписывает не автор, а член состава, и его ключ по файлу тоже
    /// не найти — сервер помнит у файла ключ АВТОРА. Имя `author_key` при этом
    /// стало бы ложью с видом истины: под ним лежал бы ключ постороннего.
    ///
    /// Номер остался прежним намеренно. И-7 запрещает переиспользовать номера
    /// под ДРУГИМ смыслом, а смысл здесь тот же самый и всегда был им: «ключ,
    /// которым проверять этот документ». Менять номер значило бы сжечь его ради
    /// уточнения формулировки.
    ///
    /// Обязателен у `Alive` с нулевым `file_id` и у `ApproveDevice`; запрещён
    /// везде ещё.
    pub const SIGNER_KEY: u16 = 14;
    /// Только у `SetCoauthors`: сколько живёт предложение, не набравшее подписей.
    ///
    /// Необязателен: отсутствие означает «умолчание сервера», а не «ноль». Файл,
    /// у которого срок не назван, ведёт себя как вёл.
    pub const PROPOSAL_TTL: u16 = 15;
    /// Только у `Freeze`: 1 — заморозить выдачи по всем файлам ключа, 0 — снять.
    ///
    /// Направление — часть подписанного распоряжения, как режим у наследника:
    /// «остановить всё» и «пустить всё» — противоположные веления, и выбирать
    /// между ними обязан автор, а не тот, у кого есть доступ к серверу.
    pub const FROZEN: u16 = 16;
    /// Только у `ReplaceDevice`: имена ПРЕЖНЕГО устройства (K27) подряд по 32 байта,
    /// от одного до [`super::MAX_DEVICE_NAMES`]. Имён несколько, потому что у
    /// одного устройства их несколько — классическое, X-Wing, аппаратные.
    pub const OLD_DEVICES: u16 = 17;
    /// Только у `ReplaceDevice`: имена НОВОГО устройства (K27), тем же потоком.
    pub const NEW_DEVICES: u16 = 18;
    /// Только у `SetRule` и обязателен в нём: правило файла по атрибутам,
    /// кодек [`crate::attribute_rule`]. Пустое правило законно и снимает прежнее.
    pub const RULE: u16 = 19;
    /// Только у `WatchAuthor` и обязателен в нём: ключ подписи лизингов сервера,
    /// которому адресовано доказательство. Привязывает его к серверу и к
    /// арендатору: у размещённого профиля ключ свой у каждого.
    pub const AUTHORITY_KEY: u16 = 20;
    /// Только у `RevokeGrant` и обязателен в нём: имя гранта агента, который
    /// гасится (`crate::agent::AgentGrant::grant_id`).
    ///
    /// Гранта, а не файла: грант выдан на ПОДДЕРЕВО, и погасить его — одно
    /// веление, а не N велений по числу файлов. Отзыв по файлу оставил бы
    /// цепочку наполовину живой ровно тогда, когда автор хочет её погасить.
    pub const GRANT_ID: u16 = 21;
}

/// Что велено сделать.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    /// Зарегистрировать файл с названными пределами.
    Register = 1,
    /// Отозвать доступ к файлу.
    Revoke = 2,
    /// Сменить пределы устройств и выдач у уже занятого файла.
    SetLimits = 3,
    /// Назначить состав соавторов и порог их подписей.
    SetCoauthors = 4,
    /// Назначить состав одобряющих открытие и порог их голосов.
    SetApprovers = 5,
    /// Голос одобряющего за конкретное устройство.
    ApproveDevice = 6,
    /// Автор здесь: отодвинуть срок тишины.
    Alive = 7,
    /// Назначить наследника, закрыть по тишине или снять и то и другое.
    SetHeir = 8,
    /// Кнопка паники: остановить выдачи по ВСЕМ файлам ключа — либо пустить их.
    ///
    /// За все файлы сразу и без файла вовсе, как признак жизни: утечка ключа
    /// или инцидент — свойство автора, а не документа, и останавливать
    /// документы по одному значило бы дать противнику время, которого у него не
    /// должно быть.
    Freeze = 9,
    /// Заменить потерянное устройство новым: освободить имена прежнего и
    /// занять место за именами нового одной записью (Ф-26, B3b).
    ///
    /// Подписывает автор — дверью распоряжений §9.3, под кворумом соавторов,
    /// если он назначен. Код доступа и код-претензия права замены не дают:
    /// кто держит код, тот держит ОДНУ выдачу, а не право вытеснить чужое место.
    ReplaceDevice = 10,
    /// Задать правило файла по атрибутам держателя: ворота выдачи, потолок
    /// срока, ужесточения действий (Ф-27, B4b).
    ///
    /// Правило — про ФАЙЛ, и задаёт его хозяин файла: подписью автора или
    /// кворумом соавторов, той же дверью, что пределы. Словарь и держания — про
    /// организацию, и их этой дверью не задать: подпись одного автора, меняющая
    /// держания, меняла бы доступ к файлам других авторов.
    SetRule = 11,
    /// Доказательство владения ключом автора для подписки на события ВСЕХ его
    /// файлов (`docs/protocol.md` §9.9, B5).
    ///
    /// Не веление: дверь распоряжений его не исполняет, а подписка не
    /// принимает другие виды. Документ тот же, что у распоряжений, — второй
    /// формат со своей меткой завёл бы второе определение того, «что автор
    /// подписал»; домены разводит этот байт вида внутри подписанного тела.
    WatchAuthor = 12,
    /// Погасить грант агента: сервер перестаёт выписывать лизы всей цепочке
    /// (Agent Protocol, этап 1, §4 шаг 6).
    ///
    /// Без файла и МИМО КВОРУМА — как кнопка паники, и по тому же доводу:
    /// погашение есть безопасное направление (И-10), а грант выдан на поддерево,
    /// то есть ни одному файлу в отдельности не принадлежит. Кворум соавторов
    /// здесь и вовсе не при чём: грант выпущен подписью автора единолично, и
    /// гасит его тот же ключ.
    RevokeGrant = 13,
}

impl Kind {
    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Register),
            2 => Some(Self::Revoke),
            3 => Some(Self::SetLimits),
            4 => Some(Self::SetCoauthors),
            5 => Some(Self::SetApprovers),
            6 => Some(Self::ApproveDevice),
            7 => Some(Self::Alive),
            8 => Some(Self::SetHeir),
            9 => Some(Self::Freeze),
            10 => Some(Self::ReplaceDevice),
            11 => Some(Self::SetRule),
            12 => Some(Self::WatchAuthor),
            13 => Some(Self::RevokeGrant),
            _ => None,
        }
    }
}

/// Что делать, когда автор замолчал дольше срока.
///
/// Режим — часть подписанного распоряжения, а не состояние сервера: «открыть
/// наследнику» и «закрыть всем» — противоположные судьбы документа, и выбирать
/// между ними обязан автор. Живи режим только на сервере, судьбу выбирал бы
/// тот, у кого есть доступ к серверу.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum HeirMode {
    /// Снять наследника и срок вовсе.
    ///
    /// Отдельным ЗНАЧЕНИЕМ, а не отсутствием поля: «снять» — распоряжение,
    /// которое сервер обязан исполнить и записать в журнал, и отличить его от
    /// «поле забыли» надо на разборе, а не догадкой.
    Off = 0,
    /// Открыть наследнику завещание.
    Open = 1,
    /// Закрыть файл всем.
    Close = 2,
}

impl HeirMode {
    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Off),
            1 => Some(Self::Open),
            2 => Some(Self::Close),
            _ => None,
        }
    }
}

/// Распоряжение, как его видят обе стороны.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Order {
    pub file_id: [u8; 16],
    pub kind: Kind,
    /// Момент выписки по часам автора, секунды UTC.
    pub at: i64,
    /// Пределы — у регистрации и у смены пределов; у прочих видов их быть не
    /// должно.
    pub max_devices: Option<u32>,
    pub max_grants: Option<u32>,
    /// Состав — у назначения соавторов и одобряющих.
    ///
    /// Порядок ключей значения не имеет и на исполнение не влияет; сохраняется
    /// он затем, чтобы круг кодирования сходился побайтно, а подпись покрывала
    /// ровно то, что автор видел.
    pub keys: Option<Vec<[u8; 32]>>,
    /// Порог — вместе с составом и только с ним.
    pub threshold: Option<u8>,
    /// За какое устройство голос — только у `ApproveDevice`.
    pub device_fpr: Option<[u8; 32]>,
    /// За или против — только у `ApproveDevice`.
    pub approve: Option<bool>,
    /// Срок тишины — у назначения наследника и у закрытия по тишине.
    pub silence_seconds: Option<u64>,
    /// Что делать после тишины — только у `SetHeir`.
    pub heir_mode: Option<HeirMode>,
    /// Завещания: готовые решения автора наследникам, каждое целиком.
    ///
    /// Байтами, а не разобранными структурами, и это не лень: сервер отдаёт их
    /// наследникам КАК ЕСТЬ, а всякая пересборка разошлась бы с подписью автора,
    /// которая покрывает решение целиком.
    ///
    /// Несколько, потому что наследников бывает несколько; один — поток из одной
    /// записи, и никакого особого случая для него нет.
    pub bequests: Option<Vec<Vec<u8>>>,
    /// Чей ключ проверяет подпись — у `Alive` за все файлы и у голоса.
    pub signer_key: Option<[u8; 32]>,
    /// Сколько живёт предложение — у назначения соавторов.
    pub proposal_ttl: Option<u64>,
    /// Заморозить (`true`) или пустить (`false`) выдачи — только у `Freeze`.
    pub frozen: Option<bool>,
    /// Имена прежнего устройства — только у `ReplaceDevice`.
    pub old_devices: Option<Vec<[u8; 32]>>,
    /// Имена нового устройства — только у `ReplaceDevice`.
    pub new_devices: Option<Vec<[u8; 32]>>,
    /// Правило файла по атрибутам — только у `SetRule`.
    pub rule: Option<crate::attribute_rule::Rule>,
    /// Кому адресовано доказательство подписки — только у `WatchAuthor`.
    pub authority_key: Option<[u8; 32]>,
    /// Какой грант агента гасится — только у `RevokeGrant`.
    pub grant_id: Option<[u8; 16]>,
}

impl Order {
    /// Распоряжение без необязательных полей.
    ///
    /// Полей у распоряжения больше, чем нужно любому одному виду, и заполнять
    /// нулями всё лишнее на каждой стороне значило бы переписывать этот список
    /// при каждом новом виде.
    #[must_use]
    pub fn new(file_id: [u8; 16], kind: Kind, at: i64) -> Self {
        Self {
            file_id,
            kind,
            at,
            max_devices: None,
            max_grants: None,
            keys: None,
            threshold: None,
            device_fpr: None,
            approve: None,
            silence_seconds: None,
            heir_mode: None,
            bequests: None,
            signer_key: None,
            proposal_ttl: None,
            frozen: None,
            old_devices: None,
            new_devices: None,
            rule: None,
            authority_key: None,
            grant_id: None,
        }
    }
}

/// Поле, обязательное ровно при одном условии и запретное при обратном.
fn required(present: bool, wanted: bool, tag: u16) -> Result<(), FormatError> {
    match (present, wanted) {
        (false, true) => Err(FormatError::MissingField { tag }),
        (true, false) => Err(FormatError::UnknownCriticalField { tag }),
        _ => Ok(()),
    }
}

/// Поле, допустимое лишь у некоторых видов, но и у них необязательное.
fn only_if(present: bool, allowed: bool, tag: u16) -> Result<(), FormatError> {
    if present && !allowed { Err(FormatError::UnknownCriticalField { tag }) } else { Ok(()) }
}

/// Согласованность состава полей с видом — одним местом для обеих сторон.
///
/// # Errors
/// [`FormatError`], если поле стоит не у своего вида, отсутствует у своего или
/// завещание не годится этому файлу.
fn check(order: &Order) -> Result<(), FormatError> {
    let register = order.kind == Kind::Register;
    let set_limits = order.kind == Kind::SetLimits;
    only_if(order.max_devices.is_some(), register || set_limits, tag::MAX_DEVICES)?;
    only_if(order.max_grants.is_some(), register || set_limits, tag::MAX_GRANTS)?;
    // Смена пределов, не меняющая ни одного предела, — распоряжение, которое
    // ничего не велит. Принять его значило бы записать в журнал событие,
    // которого не было.
    if set_limits && order.max_devices.is_none() && order.max_grants.is_none() {
        return Err(FormatError::MissingField { tag: tag::MAX_DEVICES });
    }

    let roster = matches!(order.kind, Kind::SetCoauthors | Kind::SetApprovers);
    required(order.keys.is_some(), roster, tag::KEYS)?;
    required(order.threshold.is_some(), roster, tag::THRESHOLD)?;
    if let (Some(keys), Some(threshold)) = (&order.keys, order.threshold) {
        check_roster(keys, threshold)?;
    }

    let vote = order.kind == Kind::ApproveDevice;
    required(order.device_fpr.is_some(), vote, tag::DEVICE_FPR)?;
    required(order.approve.is_some(), vote, tag::APPROVE)?;

    required(order.heir_mode.is_some(), order.kind == Kind::SetHeir, tag::HEIR_MODE)?;
    required(
        order.silence_seconds.is_some(),
        matches!(order.heir_mode, Some(HeirMode::Open | HeirMode::Close)),
        tag::SILENCE_SECONDS,
    )?;
    required(order.bequests.is_some(), order.heir_mode == Some(HeirMode::Open), tag::BEQUEST)?;

    // Срок предложения — только у состава СОАВТОРОВ: у одобряющих предложений
    // нет вовсе, им нечему протухать. Ноль запрещён: снять срок нельзя, можно
    // лишь сменить, а предложение без срока копилось бы вечно.
    only_if(order.proposal_ttl.is_some(), order.kind == Kind::SetCoauthors, tag::PROPOSAL_TTL)?;
    if order.proposal_ttl == Some(0) {
        return Err(FormatError::BadFieldLength { tag: tag::PROPOSAL_TTL, len: 0 });
    }

    // Кнопка паники — всегда за все файлы ключа: файла у неё нет, а направление
    // обязательно. Файл здесь не «необязателен», он ЗАПРЕЩЁН: заморозка одного
    // файла есть отзыв, и у него свой вид.
    let freeze = order.kind == Kind::Freeze;
    required(order.frozen.is_some(), freeze, tag::FROZEN)?;
    if freeze && order.file_id != [0u8; 16] {
        return Err(FormatError::UnknownCriticalField { tag: tag::FILE_ID });
    }

    // Ключ называется ровно там, где по файлу его не взять: у признака жизни за
    // все файлы сразу файла нет вовсе, у кнопки паники — тоже, а у голоса
    // подписывает не автор, и ключ автора, записанный у файла, здесь ни при чём.
    // Доказательство подписки: за все файлы ключа — файла нет, ключ назван,
    // адресат назван.
    let watch = order.kind == Kind::WatchAuthor;
    required(order.authority_key.is_some(), watch, tag::AUTHORITY_KEY)?;
    if watch && order.file_id != [0u8; 16] {
        return Err(FormatError::UnknownCriticalField { tag: tag::FILE_ID });
    }

    // ПОГАШЕНИЕ ГРАНТА: имя гранта обязательно, файла нет вовсе. Файл здесь не
    // «необязателен», он ЗАПРЕЩЁН: грант выдан на поддерево, и веление, названное
    // одним его файлом, означало бы погашение то ли гранта, то ли файла — двух
    // разных судеб под одним документом.
    let revoke_grant = order.kind == Kind::RevokeGrant;
    required(order.grant_id.is_some(), revoke_grant, tag::GRANT_ID)?;
    if revoke_grant && order.file_id != [0u8; 16] {
        return Err(FormatError::UnknownCriticalField { tag: tag::FILE_ID });
    }

    required(
        order.signer_key.is_some(),
        (order.kind == Kind::Alive && order.file_id == [0u8; 16])
            || vote
            || freeze
            || watch
            || revoke_grant,
        tag::SIGNER_KEY,
    )?;

    if let Some(all) = &order.bequests {
        check_bequests(all, order.file_id)?;
    }

    // ЗАМЕНА УСТРОЙСТВА: у своего файла, имена по ОДНОМУ устройству с каждой
    // стороны, и ни одно имя не стоит сразу в обеих. «Заменить устройство им же»
    // — распоряжение, которое ничего не велит, а исполнить его значило бы
    // вычеркнуть устройство и тут же зарезервировать ему место заново.
    let replace = order.kind == Kind::ReplaceDevice;
    required(order.old_devices.is_some(), replace, tag::OLD_DEVICES)?;
    required(order.new_devices.is_some(), replace, tag::NEW_DEVICES)?;
    if replace && order.file_id == [0u8; 16] {
        return Err(FormatError::MissingField { tag: tag::FILE_ID });
    }
    if let (Some(old), Some(new)) = (&order.old_devices, &order.new_devices) {
        check_names(old, tag::OLD_DEVICES)?;
        check_names(new, tag::NEW_DEVICES)?;
        if old.iter().any(|name| new.contains(name)) {
            return Err(FormatError::UnknownCriticalField { tag: tag::NEW_DEVICES });
        }
    }

    // ПРАВИЛО ФАЙЛА: у своего файла и только у своего вида. Само правило
    // проверяется своим кодеком при записи — здесь достаточно присутствия.
    let set_rule = order.kind == Kind::SetRule;
    required(order.rule.is_some(), set_rule, tag::RULE)?;
    if set_rule && order.file_id == [0u8; 16] {
        return Err(FormatError::MissingField { tag: tag::FILE_ID });
    }
    Ok(())
}

/// Имена устройства: от одного до [`MAX_DEVICE_NAMES`], без повторов и без нулевого.
fn check_names(names: &[[u8; 32]], tag: u16) -> Result<(), FormatError> {
    if names.is_empty() || names.len() > MAX_DEVICE_NAMES {
        return Err(FormatError::BadFieldLength { tag, len: names.len() });
    }
    for (at, name) in names.iter().enumerate() {
        if *name == [0u8; 32] || names.get(at.saturating_add(1)..).is_some_and(|rest| rest.contains(name)) {
            return Err(FormatError::UnknownCriticalField { tag });
        }
    }
    Ok(())
}

/// Состав исполним, и в нём нет одного человека дважды.
///
/// Порог выше числа ключей — правило, которого никто никогда не исполнит: файл
/// замирает навсегда, и заметить это можно только тем, что он замер. Повтор
/// ключа — та же беда с другой стороны: один голос считался бы за два, и порог
/// «двое из трёх» исполнялся бы одной подписью.
///
/// Пустой состав с нулевым порогом законен и означает «кворума нет»: снять
/// кворум надо чем-то, и отдельного вида для этого заводить незачем.
fn check_roster(keys: &[[u8; 32]], threshold: u8) -> Result<(), FormatError> {
    if keys.len() > MAX_KEYS {
        return Err(FormatError::BadFieldLength { tag: tag::KEYS, len: keys.len() });
    }
    for (at, key) in keys.iter().enumerate() {
        if keys.get(at.saturating_add(1)..).is_some_and(|rest| rest.contains(key)) {
            return Err(FormatError::UnknownCriticalField { tag: tag::KEYS });
        }
    }
    let wanted = usize::from(threshold);
    let ok = if keys.is_empty() { wanted == 0 } else { wanted >= 1 && wanted <= keys.len() };
    if ok { Ok(()) } else { Err(FormatError::UnknownCriticalField { tag: tag::THRESHOLD }) }
}

/// Завещания — годные решения автора ИМЕННО ОБ ЭТОМ файле, и все разным людям.
///
/// Разбираются здесь, а не только на сервере, по И-9: крейт не выпускает наружу
/// байты, которых не проверил. Сверяется содержимое, а не подпись: подпись автора
/// покрывает решение целиком, поэтому его же решение о ДРУГОМ файле подписано
/// верно и от нужного по подписи неотличимо.
///
/// Пустой список отвергается: «открыть завещание» без завещания есть
/// распоряжение, которое нечем исполнить. Повтор отпечатка — тоже: два решения
/// одному устройству означали бы, что сервер должен выбрать между ними, а
/// выбирать ему нечем.
fn check_bequests(all: &[Vec<u8>], file_id: [u8; 16]) -> Result<(), FormatError> {
    if all.is_empty() || all.len() > MAX_HEIRS {
        return Err(FormatError::BadFieldLength { tag: tag::BEQUEST, len: all.len() });
    }
    let mut seen: Vec<[u8; 32]> = Vec::with_capacity(all.len());
    for bytes in all {
        let decision = crate::access::decode_decision(bytes)?;
        let fits = decision.file_id == file_id
            && decision.seq == crate::access::HEIR_SEQ
            && decision.approve
            && decision.share_b.is_some();
        if !fits {
            return Err(FormatError::UnknownCriticalField { tag: tag::BEQUEST });
        }
        if seen.contains(&decision.device_fpr) {
            return Err(FormatError::UnknownCriticalField { tag: tag::BEQUEST });
        }
        seen.push(decision.device_fpr);
    }
    Ok(())
}

/// Транскрипт подписи: метка домена и тело как одно поле.
#[must_use]
pub fn signing_transcript(body: &[u8]) -> oc_crypto::Transcript {
    let mut t = oc_crypto::Transcript::new(oc_crypto::label::AUTHOR_ORDER);
    t.field(body);
    t
}

/// Закодировать тело.
///
/// # Errors
/// [`FormatError`], если состав полей не сходится с видом (`check`): такой
/// документ не имеет смысла, и выписать его значило бы завести вторую трактовку
/// одного тела.
pub fn encode(order: &Order) -> Result<Vec<u8>, FormatError> {
    check(order)?;
    let mut w = TlvWriter::new();
    w.put(tag::VERSION, &ORDER_VERSION.to_le_bytes())?;
    w.put(tag::FILE_ID, &order.file_id)?;
    w.put(tag::KIND, &[order.kind as u8])?;
    w.put(tag::AT, &order.at.to_le_bytes())?;
    if let Some(n) = order.max_devices {
        w.put(tag::MAX_DEVICES, &n.to_le_bytes())?;
    }
    if let Some(n) = order.max_grants {
        w.put(tag::MAX_GRANTS, &n.to_le_bytes())?;
    }
    if let Some(keys) = &order.keys {
        let mut flat = Vec::with_capacity(keys.len().saturating_mul(32));
        for key in keys {
            flat.extend_from_slice(key);
        }
        w.put(tag::KEYS, &flat)?;
    }
    if let Some(threshold) = order.threshold {
        w.put(tag::THRESHOLD, &[threshold])?;
    }
    if let Some(fpr) = &order.device_fpr {
        w.put(tag::DEVICE_FPR, fpr)?;
    }
    if let Some(approve) = order.approve {
        w.put(tag::APPROVE, &[u8::from(approve)])?;
    }
    if let Some(n) = order.silence_seconds {
        w.put(tag::SILENCE_SECONDS, &n.to_le_bytes())?;
    }
    if let Some(mode) = order.heir_mode {
        w.put(tag::HEIR_MODE, &[mode as u8])?;
    }
    if let Some(all) = &order.bequests {
        let mut flat = Vec::new();
        for bytes in all {
            let len = u32::try_from(bytes.len())
                .map_err(|_| FormatError::BadFieldLength { tag: tag::BEQUEST, len: bytes.len() })?;
            flat.extend_from_slice(&len.to_le_bytes());
            flat.extend_from_slice(bytes);
        }
        w.put(tag::BEQUEST, &flat)?;
    }
    if let Some(key) = &order.signer_key {
        w.put(tag::SIGNER_KEY, key)?;
    }
    if let Some(n) = order.proposal_ttl {
        w.put(tag::PROPOSAL_TTL, &n.to_le_bytes())?;
    }
    if let Some(frozen) = order.frozen {
        w.put(tag::FROZEN, &[u8::from(frozen)])?;
    }
    for (names, name_tag) in [(&order.old_devices, tag::OLD_DEVICES), (&order.new_devices, tag::NEW_DEVICES)] {
        if let Some(names) = names {
            let flat: Vec<u8> = names.iter().flatten().copied().collect();
            w.put(name_tag, &flat)?;
        }
    }
    if let Some(rule) = &order.rule {
        w.put(tag::RULE, &crate::attribute_rule::encode(rule)?)?;
    }
    if let Some(key) = &order.authority_key {
        w.put(tag::AUTHORITY_KEY, key)?;
    }
    if let Some(grant_id) = &order.grant_id {
        w.put(tag::GRANT_ID, grant_id)?;
    }
    Ok(w.finish().to_vec())
}

/// Разобрать тело — строго: длины точные, версия одна, состав полей по виду.
///
/// # Errors
/// [`FormatError`] при незнакомом теге, неверной длине, чужой версии,
/// неизвестном виде или составе полей не по виду (`check`).
pub fn decode(body: &[u8]) -> Result<Order, FormatError> {
    let mut reader = TlvReader::new(body);
    let mut version = None;
    let mut file_id = None;
    let mut kind = None;
    let mut at = None;
    let mut max_devices = None;
    let mut max_grants = None;
    let mut keys = None;
    let mut threshold = None;
    let mut device_fpr = None;
    let mut approve = None;
    let mut silence_seconds = None;
    let mut heir_mode = None;
    let mut bequests = None;
    let mut signer_key = None;
    let mut proposal_ttl = None;
    let mut frozen = None;
    let mut old_devices = None;
    let mut new_devices = None;
    let mut rule = None;
    let mut authority_key = None;
    let mut grant_id = None;
    while let Some(field) = reader.next_field()? {
        match field.tag {
            tag::VERSION => version = Some(u16_le(field.tag, field.value)?),
            tag::FILE_ID => file_id = Some(exact16(field.tag, field.value)?),
            tag::KIND => {
                let byte = one_byte(tag::KIND, field.value)?;
                kind = Some(
                    Kind::from_byte(byte).ok_or(FormatError::UnknownCriticalField { tag: tag::KIND })?,
                );
            }
            tag::AT => at = Some(u64_le(field.tag, field.value)?.cast_signed()),
            tag::MAX_DEVICES => max_devices = Some(u32_le(field.tag, field.value)?),
            tag::MAX_GRANTS => max_grants = Some(u32_le(field.tag, field.value)?),
            tag::KEYS => keys = Some(split_keys(field.value)?),
            tag::THRESHOLD => threshold = Some(one_byte(tag::THRESHOLD, field.value)?),
            tag::DEVICE_FPR => device_fpr = Some(exact32(field.tag, field.value)?),
            tag::APPROVE => {
                approve = Some(match field.value {
                    [0] => false,
                    [1] => true,
                    other => {
                        return Err(FormatError::BadFieldLength {
                            tag: tag::APPROVE,
                            len: other.len(),
                        });
                    }
                });
            }
            tag::SILENCE_SECONDS => silence_seconds = Some(u64_le(field.tag, field.value)?),
            tag::HEIR_MODE => {
                let byte = one_byte(tag::HEIR_MODE, field.value)?;
                heir_mode = Some(
                    HeirMode::from_byte(byte)
                        .ok_or(FormatError::UnknownCriticalField { tag: tag::HEIR_MODE })?,
                );
            }
            tag::BEQUEST => bequests = Some(split_bequests(field.value)?),
            tag::SIGNER_KEY => signer_key = Some(exact32(field.tag, field.value)?),
            tag::PROPOSAL_TTL => proposal_ttl = Some(u64_le(field.tag, field.value)?),
            tag::FROZEN => {
                frozen = Some(match field.value {
                    [0] => false,
                    [1] => true,
                    other => {
                        return Err(FormatError::BadFieldLength {
                            tag: tag::FROZEN,
                            len: other.len(),
                        });
                    }
                });
            }
            tag::OLD_DEVICES => old_devices = Some(split_names(tag::OLD_DEVICES, field.value)?),
            tag::NEW_DEVICES => new_devices = Some(split_names(tag::NEW_DEVICES, field.value)?),
            tag::RULE => rule = Some(crate::attribute_rule::decode(field.value)?),
            tag::AUTHORITY_KEY => authority_key = Some(exact32(field.tag, field.value)?),
            tag::GRANT_ID => grant_id = Some(exact16(field.tag, field.value)?),
            other => crate::unknown::refuse_if_critical(other)?,
        }
    }
    if version.ok_or(FormatError::MissingField { tag: tag::VERSION })? != ORDER_VERSION {
        return Err(FormatError::UnknownCriticalField { tag: tag::VERSION });
    }
    let order = Order {
        file_id: file_id.ok_or(FormatError::MissingField { tag: tag::FILE_ID })?,
        kind: kind.ok_or(FormatError::MissingField { tag: tag::KIND })?,
        at: at.ok_or(FormatError::MissingField { tag: tag::AT })?,
        max_devices,
        max_grants,
        keys,
        threshold,
        device_fpr,
        approve,
        silence_seconds,
        heir_mode,
        bequests,
        signer_key,
        proposal_ttl,
        frozen,
        old_devices,
        new_devices,
        rule,
        authority_key,
        grant_id,
    };
    check(&order)?;
    Ok(order)
}

/// Тело распоряжения из подписанных байтов — БЕЗ проверки подписи.
///
/// Нужно серверу, чтобы по `file_id` найти, чьим ключом проверять: ключ
/// автора он помнит по файлу. Всё, что отсюда возвращается, годится только
/// для поиска ключа; исполнять распоряжение можно после [`verify_signed`].
///
/// # Errors
/// [`FormatError`], если байты короче подписи или тело не разбирается.
pub fn peek(bytes: &[u8]) -> Result<Order, FormatError> {
    let (_, body) = bytes.split_at_checked(SIGNATURE_LEN).ok_or(FormatError::BadHeaderSignature)?;
    decode(body)
}

/// Отпечаток НАМЕРЕНИЯ: что велено, без «когда выписано» и «кем подписано».
///
/// # Зачем он существует
///
/// Кворум соавторов собирается из подписей РАЗНЫХ людей на РАЗНЫХ машинах, и
/// каждый подписывает своё: набирает ту же команду, его клиент ставит свой
/// момент выписки, свой ключ. Опознавай сервер предложение по хешу тела — два
/// соавтора, набравшие одну и ту же команду в разные секунды, оказались бы
/// авторами двух разных предложений, и кворум не собрался бы НИКОГДА.
///
/// Отсюда правило: предложение опознаётся тем, ЧТО велено, а не тем, когда об
/// этом сказали. Совпасть обязаны файл, вид и все параметры; момент выписки и
/// ключ подписавшего в отпечаток не входят — они принадлежат подписи, а не
/// намерению.
///
/// Считается он тем же самым кодировщиком, что и тело: второй сериализатор ради
/// хеша был бы вторым определением того, что такое «то же распоряжение», и
/// разошёлся бы с первым на первой же новой строке.
///
/// # Errors
/// [`FormatError`], если распоряжение не кодируется.
pub fn intent_digest(order: &Order) -> Result<[u8; 32], FormatError> {
    let canonical = Order { at: 0, signer_key: None, ..order.clone() };
    Ok(oc_crypto::sha256(&encode(&canonical)?))
}

/// Вид распоряжения из ГОЛОГО ТЕЛА, без подписи впереди.
///
/// Разбор строгий, как везде: незнакомый вид не угадывается.
///
/// # Кто это зовёт
///
/// Сегодня — никто, и сказать это здесь честнее, чем промолчать. Писалась
/// функция для списка предложений соавторов, где вид доставали из ХРАНИМОГО
/// тела; с Ф-20 п.15 (2026-09-04) тела на сервере не хранятся вовсе —
/// предложение опознаётся велением (`intent_digest`), а вид лежит полем
/// записи. Прежняя редакция этой докстроки пережила ту смену устройства и
/// продолжала обещать хранимые тела.
///
/// # Errors
/// [`FormatError`], если тело не разбирается.
pub fn peek_kind(body: &[u8]) -> Result<u8, FormatError> {
    Ok(decode(body)?.kind as u8)
}

/// Проверить подпись над телом ключом автора.
///
/// # Errors
/// [`CryptoError`], если подпись не сходится.
pub fn verify(
    body: &[u8],
    signature: &[u8; SIGNATURE_LEN],
    author_key: &[u8; 32],
) -> Result<(), CryptoError> {
    oc_crypto::sign::verify(author_key, &signing_transcript(body), signature)
}

/// Проверить подписанный документ целиком и разобрать его.
///
/// # Errors
/// [`FormatError::BadHeaderSignature`] при короткой или несходящейся подписи;
/// ошибки разбора тела — как у [`decode`].
pub fn verify_signed(bytes: &[u8], author_key: &[u8; 32]) -> Result<Order, FormatError> {
    let (signature, body) =
        bytes.split_at_checked(SIGNATURE_LEN).ok_or(FormatError::BadHeaderSignature)?;
    let signature: [u8; SIGNATURE_LEN] =
        signature.try_into().map_err(|_| FormatError::BadHeaderSignature)?;
    verify(body, &signature, author_key).map_err(|_| FormatError::BadHeaderSignature)?;
    decode(body)
}

fn exact16(tag: u16, value: &[u8]) -> Result<[u8; 16], FormatError> {
    value.try_into().map_err(|_| FormatError::BadFieldLength { tag, len: value.len() })
}

/// Завещания потоком: у каждого своя длина, потому что решения разной длины —
/// доля запечатана на разные ключи, а `enc` у механизмов разный.
fn split_bequests(mut rest: &[u8]) -> Result<Vec<Vec<u8>>, FormatError> {
    let bad = |len: usize| FormatError::BadFieldLength { tag: tag::BEQUEST, len };
    let mut out = Vec::new();
    while !rest.is_empty() {
        // Предел проверяется В ЦИКЛЕ, до выделения следующей записи: поток в
        // мегабайт иначе заставил бы собрать тысячи решений, чтобы затем их
        // отвергнуть.
        if out.len() >= MAX_HEIRS {
            return Err(bad(out.len().saturating_add(1)));
        }
        let head: [u8; 4] =
            rest.get(..4).and_then(|s| <[u8; 4]>::try_from(s).ok()).ok_or_else(|| bad(rest.len()))?;
        let len = usize::try_from(u32::from_le_bytes(head)).map_err(|_| bad(0))?;
        let end = 4usize.saturating_add(len);
        out.push(rest.get(4..end).ok_or_else(|| bad(len))?.to_vec());
        rest = rest.get(end..).ok_or_else(|| bad(len))?;
    }
    Ok(out)
}

/// Ключи подряд по тридцать два байта.
///
/// Длина проверяется ТОЧНО (И-8): хвост не той длины означает, что противник
/// управляет тем, какие байты станут ключом. Предел на число ключей стоит здесь
/// же, до всякого выделения памяти, — иначе поле в мегабайт заставило бы нас
/// собрать тридцать тысяч ключей, чтобы затем их отвергнуть.
/// Имена устройства потоком по 32 байта. Предел — до выделения памяти.
fn split_names(tag: u16, value: &[u8]) -> Result<Vec<[u8; 32]>, FormatError> {
    if value.is_empty() || !value.len().is_multiple_of(32) || value.len() > MAX_DEVICE_NAMES.saturating_mul(32) {
        return Err(FormatError::BadFieldLength { tag, len: value.len() });
    }
    value
        .chunks(32)
        .map(|chunk| <[u8; 32]>::try_from(chunk).map_err(|_| FormatError::BadFieldLength { tag, len: chunk.len() }))
        .collect()
}

fn split_keys(value: &[u8]) -> Result<Vec<[u8; 32]>, FormatError> {
    if !value.len().is_multiple_of(32) || value.len() > MAX_KEYS.saturating_mul(32) {
        return Err(FormatError::BadFieldLength { tag: tag::KEYS, len: value.len() });
    }
    let mut out = Vec::with_capacity(value.len() / 32);
    for chunk in value.chunks(32) {
        out.push(
            <[u8; 32]>::try_from(chunk)
                .map_err(|_| FormatError::BadFieldLength { tag: tag::KEYS, len: chunk.len() })?,
        );
    }
    Ok(out)
}

fn exact32(tag: u16, value: &[u8]) -> Result<[u8; 32], FormatError> {
    value.try_into().map_err(|_| FormatError::BadFieldLength { tag, len: value.len() })
}

fn one_byte(tag: u16, value: &[u8]) -> Result<u8, FormatError> {
    match value {
        [b] => Ok(*b),
        other => Err(FormatError::BadFieldLength { tag, len: other.len() }),
    }
}

fn u16_le(tag: u16, value: &[u8]) -> Result<u16, FormatError> {
    let bytes: [u8; 2] =
        value.try_into().map_err(|_| FormatError::BadFieldLength { tag, len: value.len() })?;
    Ok(u16::from_le_bytes(bytes))
}

fn u32_le(tag: u16, value: &[u8]) -> Result<u32, FormatError> {
    let bytes: [u8; 4] =
        value.try_into().map_err(|_| FormatError::BadFieldLength { tag, len: value.len() })?;
    Ok(u32::from_le_bytes(bytes))
}

fn u64_le(tag: u16, value: &[u8]) -> Result<u64, FormatError> {
    let bytes: [u8; 8] =
        value.try_into().map_err(|_| FormatError::BadFieldLength { tag, len: value.len() })?;
    Ok(u64::from_le_bytes(bytes))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use oc_crypto::sign::{Ed25519Signer, Signer};

    fn signed(order: &Order, signer: &Ed25519Signer) -> Vec<u8> {
        let body = encode(order).unwrap();
        let sig = signer.sign(&signing_transcript(&body)).unwrap();
        let mut out = sig.to_vec();
        out.extend_from_slice(&body);
        out
    }

    fn register() -> Order {
        Order { max_devices: Some(3), ..Order::new([0x5a; 16], Kind::Register, 1_756_000_000) }
    }

    /// Подпись автора сходится с его ключом и ни с чьим другим; повреждение
    /// подписи, тела и обрубок отвергаются.
    #[test]
    fn a_signed_order_verifies_with_the_author_key_and_nothing_else_passes() {
        let author = Ed25519Signer::from_seed(&[0x41; 32]);
        let stranger = Ed25519Signer::from_seed(&[0x42; 32]);
        let order = register();
        let bytes = signed(&order, &author);

        assert_eq!(verify_signed(&bytes, &author.public_key()).unwrap(), order);
        assert_eq!(peek(&bytes).unwrap(), order, "заглянуть в тело можно и без ключа");
        assert!(verify_signed(&bytes, &stranger.public_key()).is_err(), "чужой ключ принят");

        let mut bad_sig = bytes.clone();
        bad_sig[10] ^= 1;
        assert!(verify_signed(&bad_sig, &author.public_key()).is_err(), "битая подпись принята");

        let mut bad_body = bytes.clone();
        let last = bad_body.len() - 1;
        bad_body[last] ^= 1;
        assert!(verify_signed(&bad_body, &author.public_key()).is_err(), "битое тело принято");

        assert!(verify_signed(&bytes[..40], &author.public_key()).is_err(), "обрубок принят");
        assert!(peek(&bytes[..40]).is_err(), "обрубок разобран");
    }

    /// ПОДПИСЬ ПРОВЕРЯЕТСЯ ДО РАЗБОРА ТЕЛА — сторож на порядок двух строк.
    ///
    /// Проба выше подаёт разбираемое тело, пробы на разбор зовут [`decode`]
    /// напрямую, и перестановка `decode` перед `verify` внутри [`verify_signed`]
    /// не роняла ни одной из них. Здесь тело заведомо неразбираемо, а подпись
    /// заведомо чужая: правильный ответ ровно один — `BadHeaderSignature`. Код
    /// разбора означал бы, что незаверенные байты уже прочитаны и о них
    /// отвечают различимо (И-5 для документов).
    #[test]
    fn the_signature_is_checked_before_the_body_is_parsed() {
        let author = Ed25519Signer::from_seed(&[0x41; 32]);
        let stranger = Ed25519Signer::from_seed(&[0x42; 32]);

        let empty = TlvWriter::new().finish().to_vec();
        let mut w = TlvWriter::new();
        w.put(0x7FFF, &[0xab; 4]).unwrap();
        let unknown_critical = w.finish().to_vec();

        for (what, body) in [("пустое тело", empty), ("чужой критичный тег", unknown_critical)] {
            assert!(decode(&body).is_err(), "{what}: предпосылка пробы неверна, тело разбирается");
            let sig = stranger.sign(&signing_transcript(&body)).unwrap();
            let mut bytes = sig.to_vec();
            bytes.extend_from_slice(&body);
            let outcome = verify_signed(&bytes, &author.public_key());
            assert!(
                matches!(outcome, Err(FormatError::BadHeaderSignature)),
                "{what}: разбор произошёл до проверки подписи, ответ {outcome:?}"
            );
        }
    }

    /// Отзыв без пределов проходит; отзыв с пределами — ни закодировать, ни
    /// разобрать: у одного тела не должно быть двух трактовок.
    #[test]
    fn a_revocation_carries_no_limits() {
        let revoke = Order::new([1; 16], Kind::Revoke, 7);
        assert_eq!(decode(&encode(&revoke).unwrap()).unwrap(), revoke);

        let with_limits = Order { max_grants: Some(1), ..revoke };
        assert!(encode(&with_limits).is_err(), "отзыв с пределом закодирован");

        let mut w = TlvWriter::new();
        w.put(tag::VERSION, &ORDER_VERSION.to_le_bytes()).unwrap();
        w.put(tag::FILE_ID, &[1; 16]).unwrap();
        w.put(tag::KIND, &[Kind::Revoke as u8]).unwrap();
        w.put(tag::AT, &7i64.to_le_bytes()).unwrap();
        w.put(tag::MAX_GRANTS, &1u32.to_le_bytes()).unwrap();
        assert!(decode(&w.finish()).is_err(), "отзыв с пределом разобран");
    }

    /// Тело разбирается строго: короткий идентификатор, чужая версия и
    /// неизвестный вид отвергаются.
    #[test]
    fn the_body_is_parsed_strictly() {
        let order = register();
        assert_eq!(decode(&encode(&order).unwrap()).unwrap(), order);

        let mut w = TlvWriter::new();
        w.put(tag::VERSION, &ORDER_VERSION.to_le_bytes()).unwrap();
        w.put(tag::FILE_ID, &[1; 15]).unwrap();
        w.put(tag::KIND, &[1]).unwrap();
        w.put(tag::AT, &0i64.to_le_bytes()).unwrap();
        assert!(decode(&w.finish()).is_err(), "короткий идентификатор дополнен");

        let mut w = TlvWriter::new();
        w.put(tag::VERSION, &2u16.to_le_bytes()).unwrap();
        w.put(tag::FILE_ID, &[1; 16]).unwrap();
        w.put(tag::KIND, &[1]).unwrap();
        w.put(tag::AT, &0i64.to_le_bytes()).unwrap();
        assert!(decode(&w.finish()).is_err(), "чужая версия принята");

        let mut w = TlvWriter::new();
        w.put(tag::VERSION, &ORDER_VERSION.to_le_bytes()).unwrap();
        w.put(tag::FILE_ID, &[1; 16]).unwrap();
        w.put(tag::KIND, &[9]).unwrap();
        w.put(tag::AT, &0i64.to_le_bytes()).unwrap();
        assert!(decode(&w.finish()).is_err(), "неизвестный вид принят");
    }

    /// Тело в обход проверок — чтобы `decode` было что отвергать.
    ///
    /// Без него запретное тело неоткуда взять: `encode` отказывается его
    /// выписывать, а проверять надо именно РАЗБОР — приди такое тело со стороны,
    /// от собеседника, который наш писатель не звал.
    fn hand_written(order: &Order) -> Vec<u8> {
        let mut w = TlvWriter::new();
        w.put(tag::VERSION, &ORDER_VERSION.to_le_bytes()).unwrap();
        w.put(tag::FILE_ID, &order.file_id).unwrap();
        w.put(tag::KIND, &[order.kind as u8]).unwrap();
        w.put(tag::AT, &order.at.to_le_bytes()).unwrap();
        if let Some(n) = order.max_devices {
            w.put(tag::MAX_DEVICES, &n.to_le_bytes()).unwrap();
        }
        if let Some(n) = order.max_grants {
            w.put(tag::MAX_GRANTS, &n.to_le_bytes()).unwrap();
        }
        if let Some(keys) = &order.keys {
            let mut flat = Vec::new();
            for k in keys {
                flat.extend_from_slice(k);
            }
            w.put(tag::KEYS, &flat).unwrap();
        }
        if let Some(t) = order.threshold {
            w.put(tag::THRESHOLD, &[t]).unwrap();
        }
        if let Some(f) = &order.device_fpr {
            w.put(tag::DEVICE_FPR, f).unwrap();
        }
        if let Some(a) = order.approve {
            w.put(tag::APPROVE, &[u8::from(a)]).unwrap();
        }
        if let Some(n) = order.silence_seconds {
            w.put(tag::SILENCE_SECONDS, &n.to_le_bytes()).unwrap();
        }
        if let Some(m) = order.heir_mode {
            w.put(tag::HEIR_MODE, &[m as u8]).unwrap();
        }
        if let Some(all) = &order.bequests {
            let mut flat = Vec::new();
            for b in all {
                flat.extend_from_slice(&u32::try_from(b.len()).unwrap().to_le_bytes());
                flat.extend_from_slice(b);
            }
            w.put(tag::BEQUEST, &flat).unwrap();
        }
        if let Some(k) = &order.signer_key {
            w.put(tag::SIGNER_KEY, k).unwrap();
        }
        if let Some(n) = order.proposal_ttl {
            w.put(tag::PROPOSAL_TTL, &n.to_le_bytes()).unwrap();
        }
        w.finish().to_vec()
    }

    /// Завещание — обычное решение автора с зарезервированным номером.
    fn bequest_for(file_id: [u8; 16], device_fpr: [u8; 32]) -> Vec<u8> {
        crate::access::encode_decision(&crate::access::Decision {
            seq: crate::access::HEIR_SEQ,
            file_id,
            device_fpr,
            approve: true,
            share_b: Some(crate::access::Blob {
                enc: vec![0x11; 32],
                nonce: [0x22; 24],
                ct: vec![0x33; 48],
            }),
            author_key: [0x44; 32],
            signature: [0x55; 64],
        })
        .unwrap()
    }

    fn set_heir(file_id: [u8; 16], mode: HeirMode) -> Order {
        Order {
            heir_mode: Some(mode),
            // Тридцать суток.
            silence_seconds: match mode {
                HeirMode::Off => None,
                _ => Some(2_592_000),
            },
            bequests: match mode {
                HeirMode::Open => Some(vec![bequest_for(file_id, [0x77; 32])]),
                _ => None,
            },
            ..Order::new(file_id, Kind::SetHeir, 1_756_000_000)
        }
    }

    /// ЗАВЕЩАНИЕ ЕДЕТ ОДНИМ ЗНАЧЕНИЕМ И ВОЗВРАЩАЕТСЯ ТЕМ ЖЕ.
    ///
    /// Круг кодирования проверяет здесь не «сериализация работает», а то, что
    /// решение автора не расползлось по полям распоряжения: сервер обязан
    /// отдать наследнику ГОТОВЫЕ байты, а не собирать решение заново — собранное
    /// заново не сойдётся с подписью автора, которая покрывает решение целиком.
    #[test]
    fn a_bequest_travels_whole_inside_the_order() {
        let author = Ed25519Signer::from_seed(&[0x41; 32]);
        for mode in [HeirMode::Open, HeirMode::Close, HeirMode::Off] {
            let order = set_heir([0x5a; 16], mode);
            let bytes = signed(&order, &author);
            assert_eq!(
                verify_signed(&bytes, &author.public_key()).unwrap(),
                order,
                "распоряжение о наследнике не пережило круг: {mode:?}"
            );
        }
    }

    /// ЗАВЕЩАНИЕ ПРИНАДЛЕЖИТ ТОЛЬКО ОТКРЫВАЮЩЕМУ РЕЖИМУ.
    ///
    /// Открытие без завещания — распоряжение, которое нечем исполнить; закрытие
    /// с завещанием — тело с двумя трактовками сразу («закрыть всем» и «открыть
    /// наследнику»). Оба отвергаются в обе стороны: то, что мы отказываемся
    /// выписать, мы обязаны отказаться и исполнить.
    #[test]
    fn a_bequest_belongs_to_an_opening_heir_and_nowhere_else() {
        let file_id = [0x5a; 16];

        let mut naked = set_heir(file_id, HeirMode::Open);
        naked.bequests = None;
        assert!(encode(&naked).is_err(), "открытие без завещания закодировано");
        assert!(decode(&hand_written(&naked)).is_err(), "открытие без завещания разобрано");

        let mut extra = set_heir(file_id, HeirMode::Close);
        extra.bequests = Some(vec![bequest_for(file_id, [0x77; 32])]);
        assert!(encode(&extra).is_err(), "закрытие с завещанием закодировано");
        assert!(decode(&hand_written(&extra)).is_err(), "закрытие с завещанием разобрано");

        let mut off = set_heir(file_id, HeirMode::Off);
        off.silence_seconds = Some(86_400);
        assert!(encode(&off).is_err(), "снятие со сроком закодировано");
        assert!(decode(&hand_written(&off)).is_err(), "снятие со сроком разобрано");

        // Завещание О ДРУГОМ ФАЙЛЕ отвергается ЗДЕСЬ, а не на сервере: подпись
        // автора покрывает решение целиком, поэтому чужое решение о чужом файле
        // подписано верно и от своего по подписи неотличимо.
        let mut alien = set_heir(file_id, HeirMode::Open);
        alien.bequests = Some(vec![bequest_for([0x99; 16], [0x77; 32])]);
        assert!(encode(&alien).is_err(), "завещание о другом файле закодировано");
        assert!(decode(&hand_written(&alien)).is_err(), "завещание о другом файле разобрано");

        // Номер очереди у завещания зарезервирован: с обычным номером оно встало
        // бы в очередь решений и заняло чужое место в ней.
        let mut numbered = set_heir(file_id, HeirMode::Open);
        numbered.bequests = Some(vec![
            crate::access::encode_decision(&crate::access::Decision {
                seq: 3,
                ..crate::access::decode_decision(&bequest_for(file_id, [0x77; 32])).unwrap()
            })
            .unwrap(),
        ]);
        assert!(encode(&numbered).is_err(), "завещание с очередным номером закодировано");
        assert!(decode(&hand_written(&numbered)).is_err(), "оно же разобрано");

        // Отказ вместо одобрения — распоряжение, которое нечего открывать.
        let mut refusal = set_heir(file_id, HeirMode::Open);
        refusal.bequests = Some(vec![
            crate::access::encode_decision(&crate::access::Decision {
                approve: false,
                share_b: None,
                ..crate::access::decode_decision(&bequest_for(file_id, [0x77; 32])).unwrap()
            })
            .unwrap(),
        ]);
        assert!(encode(&refusal).is_err(), "завещание с отказом закодировано");
        assert!(decode(&hand_written(&refusal)).is_err(), "оно же разобрано");
    }

    /// ПРИЗНАК ЖИЗНИ ЗА ВСЕ ФАЙЛЫ СРАЗУ ОБЯЗАН НАЗВАТЬ КЛЮЧ.
    ///
    /// Нулевой `file_id` означает «все файлы этого ключа», и без ключа в теле
    /// сервер не знает, чьё присутствие отмечено: подпись он проверяет ключом,
    /// который берёт ПО ФАЙЛУ, а файла здесь нет. Обратное тоже запрещено —
    /// ключ при названном файле был бы вторым способом сказать то же самое.
    #[test]
    fn a_sign_of_life_for_every_file_names_the_key() {
        let alive_all = Order { signer_key: Some([0x41; 32]), ..Order::new([0; 16], Kind::Alive, 9) };
        assert_eq!(decode(&encode(&alive_all).unwrap()).unwrap(), alive_all);

        let mut nameless = alive_all.clone();
        nameless.signer_key = None;
        assert!(encode(&nameless).is_err(), "признак жизни за все файлы без ключа закодирован");
        assert!(decode(&hand_written(&nameless)).is_err(), "он же разобран");

        let one = Order::new([0x5a; 16], Kind::Alive, 9);
        assert_eq!(decode(&encode(&one).unwrap()).unwrap(), one);

        let both = Order { signer_key: Some([0x41; 32]), ..one };
        assert!(encode(&both).is_err(), "названы и файл, и ключ");
        assert!(decode(&hand_written(&both)).is_err(), "они же разобраны");

        // Ключ автора — только у признака жизни: у отзыва он был бы третьим
        // мнением о том, кто автор, рядом с записью файла и подписью.
        let revoke = Order { signer_key: Some([0x41; 32]), ..Order::new([0; 16], Kind::Revoke, 9) };
        assert!(encode(&revoke).is_err(), "ключ автора принят в отзыве");
        assert!(decode(&hand_written(&revoke)).is_err(), "он же разобран");
    }

    fn keys_of(n: u8) -> Vec<[u8; 32]> {
        (0..n).map(|i| [i.saturating_add(1); 32]).collect()
    }

    fn set_keys(kind: Kind, n: u8, threshold: u8) -> Order {
        Order {
            keys: Some(keys_of(n)),
            threshold: Some(threshold),
            ..Order::new([0x5a; 16], kind, 1_756_000_000)
        }
    }

    /// СОСТАВ И ПОРОГ ЕЗДЯТ ВМЕСТЕ И ВОЗВРАЩАЮТСЯ ТЕМИ ЖЕ.
    #[test]
    fn a_roster_and_its_threshold_survive_the_round_trip() {
        let author = Ed25519Signer::from_seed(&[0x41; 32]);
        for kind in [Kind::SetCoauthors, Kind::SetApprovers] {
            for (n, threshold) in [(1u8, 1u8), (3, 2), (16, 16), (0, 0)] {
                let order = set_keys(kind, n, threshold);
                let bytes = signed(&order, &author);
                assert_eq!(
                    verify_signed(&bytes, &author.public_key()).unwrap(),
                    order,
                    "состав {n} с порогом {threshold} не пережил круг"
                );
            }
        }
    }

    /// ПОРОГ ОБЯЗАН БЫТЬ ИСПОЛНИМ СОСТАВОМ.
    ///
    /// Порог выше числа ключей — правило, которого никто никогда не исполнит:
    /// файл замирает навсегда, и заметить это можно только тем, что он замер.
    /// Отвергается в ОБЕ стороны — то, что мы отказываемся выписать, обязаны
    /// отказаться и исполнить.
    #[test]
    fn a_threshold_must_be_reachable_by_its_roster() {
        assert!(encode(&set_keys(Kind::SetCoauthors, 3, 4)).is_err(), "порог 4 из 3 закодирован");
        assert!(
            decode(&hand_written(&set_keys(Kind::SetCoauthors, 3, 4))).is_err(),
            "порог 4 из 3 разобран"
        );
        assert!(encode(&set_keys(Kind::SetCoauthors, 3, 0)).is_err(), "нулевой порог при составе");
        assert!(encode(&set_keys(Kind::SetCoauthors, 0, 1)).is_err(), "порог 1 при пустом составе");

        // Пустой состав с нулевым порогом — законное «снять кворум».
        assert!(encode(&set_keys(Kind::SetApprovers, 0, 0)).is_ok(), "снятие кворума отвергнуто");

        // Больше шестнадцати ключей не берётся: столько же, сколько адресов
        // сервера в заголовке, и по той же причине — величина, которую человек
        // в состоянии просмотреть глазами.
        let too_many = Order {
            keys: Some((0..17u8).map(|i| [i.saturating_add(1); 32]).collect()),
            threshold: Some(1),
            ..Order::new([0x5a; 16], Kind::SetCoauthors, 9)
        };
        assert!(encode(&too_many).is_err(), "семнадцать ключей закодированы");
        assert_eq!(MAX_KEYS, 16);

        // ПОВТОР КЛЮЧА — отказ. Иначе один человек считался бы за двоих, и порог
        // «двое из трёх» исполнялся бы одной подписью.
        let twice = Order {
            keys: Some(vec![[7u8; 32], [7u8; 32], [9u8; 32]]),
            threshold: Some(2),
            ..Order::new([0x5a; 16], Kind::SetCoauthors, 9)
        };
        assert!(encode(&twice).is_err(), "повторённый ключ закодирован");
        assert!(decode(&hand_written(&twice)).is_err(), "повторённый ключ разобран");
    }

    /// ГОЛОС ЗА УСТРОЙСТВО НЕСЁТ ОТПЕЧАТОК И РЕШЕНИЕ, И БОЛЬШЕ НИЧЕГО.
    #[test]
    fn a_vote_carries_a_fingerprint_and_a_verdict() {
        let author = Ed25519Signer::from_seed(&[0x41; 32]);
        for approve in [true, false] {
            let order = Order {
                device_fpr: Some([0x77; 32]),
                approve: Some(approve),
                signer_key: Some(author.public_key()),
                ..Order::new([0x5a; 16], Kind::ApproveDevice, 1_756_000_000)
            };
            let bytes = signed(&order, &author);
            assert_eq!(verify_signed(&bytes, &author.public_key()).unwrap(), order);
        }

        // ГОЛОС ОБЯЗАН НАЗВАТЬ СВОЙ КЛЮЧ. Подписывает не автор, а член состава, и
        // по файлу его ключ не найти: сервер помнит у файла ключ АВТОРА.
        let unsigned = Order {
            device_fpr: Some([0x77; 32]),
            approve: Some(true),
            ..Order::new([0x5a; 16], Kind::ApproveDevice, 9)
        };
        assert!(encode(&unsigned).is_err(), "голос без имени голосующего закодирован");
        assert!(decode(&hand_written(&unsigned)).is_err(), "он же разобран");

        // Без отпечатка голосовать не за что.
        let naked = Order {
            signer_key: Some([0x41; 32]),
            ..Order::new([0x5a; 16], Kind::ApproveDevice, 9)
        };
        assert!(encode(&naked).is_err(), "голос без отпечатка закодирован");
        assert!(decode(&hand_written(&naked)).is_err(), "голос без отпечатка разобран");

        // Отпечаток у чужого вида — запрещён: два способа сказать одно.
        let stray = Order {
            device_fpr: Some([0x77; 32]),
            approve: Some(true),
            ..Order::new([0x5a; 16], Kind::Revoke, 9)
        };
        assert!(encode(&stray).is_err(), "голос приделан к отзыву");
        assert!(decode(&hand_written(&stray)).is_err(), "он же разобран");
    }

    /// ПРЕДЕЛЫ ЖИВУТ У РЕГИСТРАЦИИ И У СМЕНЫ ПРЕДЕЛОВ, И БОЛЬШЕ НИГДЕ.
    ///
    /// Смена пределов без единого предела — распоряжение, которое ничего не
    /// велит: исполнить его нельзя, а принять значило бы записать в журнал
    /// событие, которого не было.
    #[test]
    fn limits_belong_to_registration_and_to_the_order_that_changes_them() {
        let change = Order {
            max_devices: Some(5),
            ..Order::new([0x5a; 16], Kind::SetLimits, 1_756_000_000)
        };
        assert_eq!(decode(&encode(&change).unwrap()).unwrap(), change);

        let both = Order { max_grants: Some(2), ..change.clone() };
        assert_eq!(decode(&encode(&both).unwrap()).unwrap(), both);

        let empty = Order::new([0x5a; 16], Kind::SetLimits, 9);
        assert!(encode(&empty).is_err(), "смена пределов без пределов закодирована");
        assert!(decode(&hand_written(&empty)).is_err(), "она же разобрана");

        let on_alive = Order {
            max_devices: Some(1),
            signer_key: Some([0x41; 32]),
            ..Order::new([0; 16], Kind::Alive, 9)
        };
        assert!(encode(&on_alive).is_err(), "предел приделан к признаку жизни");
    }

    /// СОСТАВ НЕ ПРИДЕЛЫВАЕТСЯ К ЧУЖОМУ ВИДУ, И ДЛИНА КЛЮЧЕЙ ТОЧНАЯ.
    #[test]
    fn a_roster_belongs_only_to_the_orders_that_set_one() {
        let stray = Order {
            keys: Some(keys_of(2)),
            threshold: Some(1),
            ..Order::new([0x5a; 16], Kind::Revoke, 9)
        };
        assert!(encode(&stray).is_err(), "состав приделан к отзыву");
        assert!(decode(&hand_written(&stray)).is_err(), "он же разобран");

        // Ключи идут подряд по тридцать два байта; хвост не той длины означает,
        // что противник управляет тем, какие байты станут ключом (И-8).
        let mut w = TlvWriter::new();
        w.put(tag::VERSION, &ORDER_VERSION.to_le_bytes()).unwrap();
        w.put(tag::FILE_ID, &[0x5a; 16]).unwrap();
        w.put(tag::KIND, &[Kind::SetCoauthors as u8]).unwrap();
        w.put(tag::AT, &9i64.to_le_bytes()).unwrap();
        w.put(tag::KEYS, &[7u8; 33]).unwrap();
        w.put(tag::THRESHOLD, &[1]).unwrap();
        assert!(decode(&w.finish()).is_err(), "тридцать три байта приняты за ключ");

        // Порог — ровно один байт.
        let mut w = TlvWriter::new();
        w.put(tag::VERSION, &ORDER_VERSION.to_le_bytes()).unwrap();
        w.put(tag::FILE_ID, &[0x5a; 16]).unwrap();
        w.put(tag::KIND, &[Kind::SetCoauthors as u8]).unwrap();
        w.put(tag::AT, &9i64.to_le_bytes()).unwrap();
        w.put(tag::KEYS, &[7u8; 32]).unwrap();
        w.put(tag::THRESHOLD, &[1, 0]).unwrap();
        assert!(decode(&w.finish()).is_err(), "двухбайтовый порог принят");
    }

    /// КНОПКА ПАНИКИ — РАСПОРЯЖЕНИЕ ЗА ВСЕ ФАЙЛЫ КЛЮЧА, КАК ПРИЗНАК ЖИЗНИ.
    ///
    /// Нулевой `file_id` и ключ подписавшего обязательны: заморозка — свойство
    /// автора, а не файла, и файла у неё нет. Поле `frozen` — только у этого вида.
    #[test]
    fn a_freeze_covers_every_file_of_the_key_and_carries_its_direction() {
        let freeze = Order {
            signer_key: Some([0x41; 32]),
            frozen: Some(true),
            ..Order::new([0; 16], Kind::Freeze, 9)
        };
        let bytes = encode(&freeze).unwrap();
        assert_eq!(decode(&bytes).unwrap(), freeze);
        let thaw = Order { frozen: Some(false), ..freeze.clone() };
        assert_eq!(decode(&encode(&thaw).unwrap()).unwrap(), thaw);

        // Без направления — распоряжение, которое ничего не велит.
        let blank = Order { frozen: None, ..freeze.clone() };
        assert!(encode(&blank).is_err(), "заморозка без направления закодирована");
        // Без ключа — проверять подпись нечем: файла нет.
        let nameless = Order { signer_key: None, ..freeze.clone() };
        assert!(encode(&nameless).is_err(), "заморозка без ключа закодирована");
        // На один файл — не этот вид: файл отзывают, автора замораживают.
        let one = Order { ..Order::new([0x5a; 16], Kind::Freeze, 9) };
        let one = Order { signer_key: Some([0x41; 32]), frozen: Some(true), ..one };
        assert!(encode(&one).is_err(), "заморозка одного файла закодирована");
        // Направление у чужого вида — отказ.
        let stray = Order { frozen: Some(true), ..Order::new([0x5a; 16], Kind::Revoke, 9) };
        assert!(encode(&stray).is_err(), "frozen у отзыва закодирован");
    }

    /// СРОК ПРЕДЛОЖЕНИЯ — НАСТРОЙКА ФАЙЛА, А НЕ КОНСТАНТА ПРОДУКТА.
    ///
    /// Решение заказчика 2026-09-05: трое суток умолчанием, автор ставит любой.
    /// Отсутствие тега означает «умолчание сервера», а не «ноль»: файл, у
    /// которого срок не назван, ведёт себя как вёл, и старая запись состояния
    /// читается новой сборкой без оговорок.
    ///
    /// Ноль отвергается: снять срок нельзя, можно лишь сменить. Предложение без
    /// срока копилось бы на сервере вечно и всплывало через месяц уже неуместным
    /// — ровно та беда, от которой срок и заведён.
    #[test]
    fn a_proposal_ttl_belongs_to_the_roster_and_cannot_be_zero() {
        let author = Ed25519Signer::from_seed(&[0x41; 32]);
        let with = Order {
            proposal_ttl: Some(5 * 86_400),
            ..set_keys(Kind::SetCoauthors, 2, 2)
        };
        let bytes = signed(&with, &author);
        assert_eq!(verify_signed(&bytes, &author.public_key()).unwrap(), with, "срок не пережил круг");

        // Без срока — законно и означает «как у сервера».
        let without = set_keys(Kind::SetCoauthors, 2, 2);
        assert_eq!(decode(&encode(&without).unwrap()).unwrap(), without);

        let zero = Order { proposal_ttl: Some(0), ..set_keys(Kind::SetCoauthors, 2, 2) };
        assert!(encode(&zero).is_err(), "нулевой срок закодирован");
        assert!(decode(&hand_written(&zero)).is_err(), "нулевой срок разобран");

        // Срок — только у состава СОАВТОРОВ: у одобряющих предложений нет вовсе,
        // им нечему протухать.
        let approvers = Order {
            proposal_ttl: Some(86_400),
            ..set_keys(Kind::SetApprovers, 2, 2)
        };
        assert!(encode(&approvers).is_err(), "срок приделан к составу одобряющих");
        assert!(decode(&hand_written(&approvers)).is_err(), "он же разобран");

        let stray = Order { proposal_ttl: Some(86_400), ..Order::new([0x5a; 16], Kind::Revoke, 9) };
        assert!(encode(&stray).is_err(), "срок приделан к отзыву");
        assert!(decode(&hand_written(&stray)).is_err(), "он же разобран");
    }

    /// НАСЛЕДНИКОВ БЫВАЕТ НЕСКОЛЬКО, И ВСЕ ОНИ РАЗНЫЕ.
    ///
    /// Решение заказчика 2026-09-05. Один наследник — не особый случай, а поток
    /// из одной записи; это и проверяется рядом, чтобы расширение не оказалось
    /// новым видом документа для старого случая.
    ///
    /// Повтор отпечатка отвергается: два решения одному устройству означали бы,
    /// что сервер должен выбрать между ними, а выбирать ему нечем. Пустой список
    /// — тоже: «открыть завещание» без завещания нечем исполнить.
    #[test]
    fn several_heirs_travel_together_and_all_of_them_differ() {
        let author = Ed25519Signer::from_seed(&[0x41; 32]);
        let file_id = [0x5a; 16];

        let three = Order {
            bequests: Some(
                (1..=3u8).map(|n| bequest_for(file_id, [n; 32])).collect(),
            ),
            ..set_heir(file_id, HeirMode::Open)
        };
        let bytes = signed(&three, &author);
        assert_eq!(
            verify_signed(&bytes, &author.public_key()).unwrap(),
            three,
            "трое наследников не пережили круг"
        );

        // Один — тот же путь, а не особый случай.
        let one = set_heir(file_id, HeirMode::Open);
        assert_eq!(decode(&encode(&one).unwrap()).unwrap(), one);

        let twice = Order {
            bequests: Some(vec![
                bequest_for(file_id, [7; 32]),
                bequest_for(file_id, [7; 32]),
            ]),
            ..set_heir(file_id, HeirMode::Open)
        };
        assert!(encode(&twice).is_err(), "два завещания одному устройству закодированы");
        assert!(decode(&hand_written(&twice)).is_err(), "они же разобраны");

        let none = Order { bequests: Some(Vec::new()), ..set_heir(file_id, HeirMode::Open) };
        assert!(encode(&none).is_err(), "пустой список завещаний закодирован");
        assert!(decode(&hand_written(&none)).is_err(), "он же разобран");

        // Семнадцатый отвергается, шестнадцать проходят: предел тот же, что у
        // состава, и по той же причине — список читает человек.
        let many = |n: u8| Order {
            bequests: Some((1..=n).map(|k| bequest_for(file_id, [k; 32])).collect()),
            ..set_heir(file_id, HeirMode::Open)
        };
        assert!(encode(&many(16)).is_ok(), "шестнадцать наследников отвергнуты");
        assert!(encode(&many(17)).is_err(), "семнадцать наследников приняты");
        assert_eq!(MAX_HEIRS, 16);

        // ОДНО НЕГОДНОЕ ЗАВЕЩАНИЕ ПОРТИТ ВЕСЬ СПИСОК, и это верно: принять его
        // частью значило бы исполнить распоряжение не так, как автор подписал.
        let mixed = Order {
            bequests: Some(vec![
                bequest_for(file_id, [1; 32]),
                bequest_for([0x99; 16], [2; 32]),
            ]),
            ..set_heir(file_id, HeirMode::Open)
        };
        assert!(encode(&mixed).is_err(), "чужой файл в списке принят");
        assert!(decode(&hand_written(&mixed)).is_err(), "он же разобран");
    }

    /// ЗАМЕНА УСТРОЙСТВА: КРУГ КОДИРОВАНИЯ И СОСТАВ ПОЛЕЙ ПО ВИДУ.
    #[test]
    fn an_author_scope_proof_names_its_server_and_no_file() {
        let proof = Order {
            signer_key: Some([0x0a; 32]),
            authority_key: Some([0x0b; 32]),
            ..Order::new([0u8; 16], Kind::WatchAuthor, 1_758_000_000)
        };
        let bytes = encode(&proof).unwrap();
        assert_eq!(decode(&bytes).unwrap(), proof);

        let bad = |order: Order, why: &str| assert!(encode(&order).is_err(), "записано: {why}");
        bad(Order { authority_key: None, ..proof.clone() }, "без адресата");
        bad(Order { signer_key: None, ..proof.clone() }, "без ключа автора");
        bad(Order { file_id: [1; 16], ..proof.clone() }, "с файлом");
        // Адресат — только у доказательства подписки.
        bad(
            Order { authority_key: Some([0x0b; 32]), ..Order::new([1; 16], Kind::Revoke, 1) },
            "адресат у отзыва",
        );
    }

    #[test]
    fn a_device_replacement_order_round_trips_and_its_names_are_checked() {
        let file_id = [0x6b; 16];
        let at = 1_760_000_000;
        let good = Order {
            old_devices: Some(vec![[0x01; 32], [0x02; 32]]),
            new_devices: Some(vec![[0x03; 32]]),
            ..Order::new(file_id, Kind::ReplaceDevice, at)
        };
        let author = Ed25519Signer::from_seed(&[0x41; 32]);
        let bytes = signed(&good, &author);
        assert_eq!(verify_signed(&bytes, &author.public_key()).unwrap(), good, "замена не пережила круг");

        let bad = |order: Order, why: &str| assert!(encode(&order).is_err(), "принята замена: {why}");
        bad(Order { new_devices: Some(vec![[0x03; 32]]), ..Order::new(file_id, Kind::ReplaceDevice, at) }, "без прежних");
        bad(Order { old_devices: Some(vec![[0x01; 32]]), ..Order::new(file_id, Kind::ReplaceDevice, at) }, "без новых");
        bad(Order { old_devices: Some(vec![]), new_devices: Some(vec![[0x03; 32]]), ..Order::new(file_id, Kind::ReplaceDevice, at) }, "пустые прежние");
        bad(Order { old_devices: Some(vec![[0x01; 32]; 2]), new_devices: Some(vec![[0x03; 32]]), ..Order::new(file_id, Kind::ReplaceDevice, at) }, "повтор имени");
        bad(Order { old_devices: Some(vec![[0x01; 32]]), new_devices: Some(vec![[0x01; 32]]), ..Order::new(file_id, Kind::ReplaceDevice, at) }, "устройство заменено им же");
        bad(Order { old_devices: Some(vec![[0u8; 32]]), new_devices: Some(vec![[0x03; 32]]), ..Order::new(file_id, Kind::ReplaceDevice, at) }, "нулевое имя");
        bad(
            Order { old_devices: Some((1..=5u8).map(|b| [b; 32]).collect()), new_devices: Some(vec![[0x09; 32]]), ..Order::new(file_id, Kind::ReplaceDevice, at) },
            "больше четырёх имён",
        );
        bad(Order { old_devices: Some(vec![[0x01; 32]]), new_devices: Some(vec![[0x03; 32]]), ..Order::new([0u8; 16], Kind::ReplaceDevice, at) }, "без файла");
        bad(Order { old_devices: Some(vec![[0x01; 32]]), ..Order::new(file_id, Kind::Revoke, at) }, "имена у чужого вида");

        // Имена у чужого вида не проходят и разбором — тело, собранное руками.
        let mut w = TlvWriter::new();
        w.put(tag::VERSION, &ORDER_VERSION.to_le_bytes()).unwrap();
        w.put(tag::FILE_ID, &file_id).unwrap();
        w.put(tag::KIND, &[Kind::Revoke as u8]).unwrap();
        w.put(tag::AT, &at.to_le_bytes()).unwrap();
        w.put(tag::OLD_DEVICES, &[0x01; 32]).unwrap();
        assert!(decode(&w.finish()).is_err(), "имена устройства у отзыва разобраны");
    }

    /// ПОГАШЕНИЕ ГРАНТА АГЕНТА: имя гранта обязательно, файла нет, ключ назван.
    ///
    /// Состав полей проверяется в ОБЕ стороны — писателем и разборщиком:
    /// веление, которое мы отказываемся выписать, мы не должны и исполнять,
    /// придя оно со стороны.
    #[test]
    fn a_grant_revocation_round_trips_and_its_fields_are_checked_by_kind() {
        let at = 1_760_000_000;
        let author = Ed25519Signer::from_seed(&[0x41; 32]);
        let good = Order {
            grant_id: Some([0x67; 16]),
            signer_key: Some(author.public_key()),
            ..Order::new([0u8; 16], Kind::RevokeGrant, at)
        };
        let bytes = signed(&good, &author);
        assert_eq!(
            verify_signed(&bytes, &author.public_key()).unwrap(),
            good,
            "погашение гранта не пережило круг"
        );

        let bad = |order: Order, why: &str| assert!(encode(&order).is_err(), "принято: {why}");
        bad(
            Order { signer_key: Some(author.public_key()), ..Order::new([0u8; 16], Kind::RevokeGrant, at) },
            "погашение без имени гранта",
        );
        bad(
            Order { grant_id: Some([0x67; 16]), ..Order::new([0u8; 16], Kind::RevokeGrant, at) },
            "погашение без ключа подписавшего",
        );
        bad(
            Order {
                grant_id: Some([0x67; 16]),
                signer_key: Some(author.public_key()),
                ..Order::new([0x5a; 16], Kind::RevokeGrant, at)
            },
            "погашение с файлом",
        );
        bad(
            Order { grant_id: Some([0x67; 16]), ..Order::new([0x5a; 16], Kind::Revoke, at) },
            "имя гранта у чужого вида",
        );

        // Имя гранта у чужого вида не проходит и разбором — тело руками.
        let mut w = TlvWriter::new();
        w.put(tag::VERSION, &ORDER_VERSION.to_le_bytes()).unwrap();
        w.put(tag::FILE_ID, &[0x5a; 16]).unwrap();
        w.put(tag::KIND, &[Kind::Revoke as u8]).unwrap();
        w.put(tag::AT, &at.to_le_bytes()).unwrap();
        w.put(tag::GRANT_ID, &[0x67; 16]).unwrap();
        assert!(decode(&w.finish()).is_err(), "имя гранта у отзыва файла разобрано");

        // Длина имени гранта — точная (И-8).
        for len in [0usize, 15, 17] {
            let mut w = TlvWriter::new();
            w.put(tag::VERSION, &ORDER_VERSION.to_le_bytes()).unwrap();
            w.put(tag::FILE_ID, &[0u8; 16]).unwrap();
            w.put(tag::KIND, &[Kind::RevokeGrant as u8]).unwrap();
            w.put(tag::AT, &at.to_le_bytes()).unwrap();
            w.put(tag::SIGNER_KEY, &author.public_key()).unwrap();
            w.put(tag::GRANT_ID, &vec![0x67; len]).unwrap();
            assert!(decode(&w.finish()).is_err(), "имя гранта длиной {len} принято");
        }
    }
}
