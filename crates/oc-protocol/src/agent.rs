//! Документы AGENT PROTOCOL: грант агента и делегирование потомку.
//!
//! # Что это за разговор и чем он отличается от одобрения
//!
//! Одобрение ([`crate::access::Decision`]) отвечает на вопрос «этот человек из
//! числа тех, кому предназначен ЭТОТ файл»: один `file_id`, одна подпись, ни
//! слова о сроке. Грант агента отвечает на другой — «этой двери на это ПОДДЕРЕВО
//! и до этого часа», — и свести его к пачке одобрений нельзя: пачка была бы N
//! решениями человека, N подписями и ни одним местом для ключа подписи двери,
//! срока и глубины делегирования.
//!
//! # Почему у двери ДВЕ пары ключей
//!
//! Устройство в протоколе — согласовательный ключ (`activation.rs`), и
//! подписывать им нечем. Дверь же обязана подписывать делегирования потомкам,
//! иначе заверить их нечем вовсе. Поэтому у двери вторая пара, Ed25519, и автор
//! называет её открытую половину в гранте: `door_verify`. Ключ этот попадает
//! под подпись автора — значит подменить его посредник не может, не сломав
//! подпись.
//!
//! # Что подписывается
//!
//! **Сырые байты тела, а не пересобранная структура**, и подпись лежит ВПЕРЕДИ
//! тела — та же раскладка, что у лиза, отзывной и распоряжения
//! (`подпись(64) ‖ тело`). Проверяется она ДО разбора TLV (И-5, И-6): разбор
//! незаверенных байтов сам по себе оракул — различимые коды ошибок сообщают о
//! том, чего никто не подписывал.
//!
//! # Чей ключ проверяет грант
//!
//! `author_key` берётся ВЫЗЫВАЮЩИМ — из заголовка контейнера или из записи
//! сервера о файле, — а не из принесённого документа. Ключ, лежащий внутри
//! документа, сверяется с переданным константным временем и служит ровно одному:
//! сделать «кому адресован этот грант» частью подписанного тела. Тот же приём,
//! которым закреплён ключ подписи лиза: истина о том, кто вправе решать,
//! приходит из подписанного заголовка, а не из слов собеседника.

use oc_format::FormatError;
use oc_format::tlv::{TlvReader, TlvWriter};
use oc_policy::Policy;

use crate::access::Blob;

/// Длина подписи в начале документа — как у лиза ([`crate::lease::SIGNATURE_LEN`]).
///
/// Подпись впереди тела намеренно: её длина фиксирована, и читатель добирается до
/// неё, не разобрав ни байта тела.
pub const SIGNATURE_LEN: usize = 64;

/// Сколько файлов помещается в один грант.
///
/// Предел нужен потому, что длину списка называет ЧУЖАЯ сторона: без него
/// «разбери грант» означало бы «выдели столько записей, сколько скажет
/// собеседник». Двести пятьдесят шесть — поддерево, которое человек в состоянии
/// выдать одним решением; дерево крупнее режется на несколько грантов, и это
/// честнее одного гранта, о составе которого автор судить уже не может.
pub const MAX_GRANT_FILES: usize = 256;

/// Наибольшая глубина делегирования, какую грант вправе разрешить.
///
/// Потолок стоит в ФОРМАТЕ, а не только в сервере, и это не дублирование: длина
/// цепочки — это длина списка, который проверяющий обязан обойти, а обход этот
/// делает и клиент. Четыре звена — предел, за которым человек, выдавший грант,
/// уже не представляет, у кого оказался доступ.
pub const MAX_GRANT_DEPTH: u8 = 4;

/// Единственный механизм согласования, который этап 1 ИСПОЛНЯЕТ у двери.
///
/// Ключи двери эфемерны и живут в памяти процесса; TPM здесь не участвует, а
/// постквантовой половины у двери нет. Разобрать номер и суметь его исполнить —
/// разные вещи (CLAUDE.md, «Как менять формат», правило 4), поэтому иной номер
/// отвергается НА РАЗБОРЕ, а не на первой попытке распечатать долю.
const DOOR_KEM_X25519: u8 = 1;

/// Реестр тегов гранта. Возрастание строгое, критичность по диапазону (И-7).
///
/// Номера нормативны: тело подписывается сырыми байтами, поэтому реализация,
/// пронумеровавшая поля иначе, соберёт другую подпись и молча разойдётся.
pub mod tag {
    /// Имя гранта: на него ссылаются отзыв и делегирования. `bytes[16]`.
    pub const GRANT_ID: u16 = 1;
    /// Отпечаток согласовательного ключа двери. `bytes[32]`.
    pub const DOOR_FPR: u16 = 2;
    /// Механизм согласования двери. `u8`.
    pub const DOOR_KEM: u16 = 3;
    /// Согласовательный ключ двери: на него запечатаны доли B.
    pub const DOOR_PUBLIC: u16 = 4;
    /// Ключ Ed25519 двери — им дверь подписывает делегирования. `bytes[32]`.
    pub const DOOR_VERIFY: u16 = 5;
    /// Список `(file_id, доля B)`, вложенный TLV с нумерацией позицией.
    pub const ENTRIES: u16 = 6;
    /// Момент выдачи. `i64le`, секунды.
    pub const ISSUED_AT: u16 = 7;
    /// Момент истечения. `i64le`, секунды.
    pub const EXPIRES_AT: u16 = 8;
    /// Ужесточение политики, кодек `policy_codec`. Необязательно: нет поля —
    /// грант не ужесточает ничего.
    pub const TIGHTENING: u16 = 9;
    /// Предел глубины делегирования. `u8`; 0 — делегировать нельзя.
    pub const MAX_DEPTH: u16 = 10;
    /// Ключ автора, которым подписан грант. `bytes[32]`.
    pub const AUTHOR_KEY: u16 = 11;
}

/// Реестр тегов делегирования. Свой, а не общий с грантом.
///
/// Общий реестр сэкономил бы десяток строк и стоил бы дорого: у двух документов
/// разный состав полей, и тег, означающий в одном «ключ автора», а в другом
/// «глубина», — это приглашение перепутать их при чтении.
pub mod link_tag {
    /// Корень цепочки. `bytes[16]`.
    pub const GRANT_ID: u16 = 1;
    /// Кто делегирует. `bytes[32]`.
    pub const PARENT_FPR: u16 = 2;
    /// Отпечаток двери потомка. `bytes[32]`.
    pub const CHILD_FPR: u16 = 3;
    /// Механизм согласования потомка. `u8`.
    pub const CHILD_KEM: u16 = 4;
    /// Согласовательный ключ потомка.
    pub const CHILD_PUBLIC: u16 = 5;
    /// Ключ Ed25519 потомка. `bytes[32]`.
    pub const CHILD_VERIFY: u16 = 6;
    /// Подмножество списка родителя, доли перепечатаны на ключ потомка.
    pub const ENTRIES: u16 = 7;
    /// Момент истечения. `i64le`, секунды.
    pub const EXPIRES_AT: u16 = 8;
    /// Ужесточение политики, тот же кодек.
    pub const TIGHTENING: u16 = 9;
    /// Сколько ещё звеньев разрешено НИЖЕ этого. `u8`.
    pub const DEPTH: u16 = 10;
    /// Список действий потомка — ПОДМНОЖЕСТВО родительских правил
    /// (`oc_protocol::action::ActionRule`, Agent Protocol, этап 2).
    ///
    /// Тег НЕОБЯЗАТЕЛЬНЫЙ (> `0x7FFF`), и это условие задачи, а не украшение:
    /// читатель первого этапа обязан пропустить его мимо и проверить цепочку
    /// ФАЙЛОВ ровно как прежде (И-7). Отсутствие поля и пустой список значат
    /// одно — «действий потомку не передано», — и умолчание это ЗАПРЕТ (И-10).
    ///
    /// Кодек тот же, что у списка правил гранта действий (`action::encode_rules`):
    /// второе представление того же смысла разошлось бы с первым на первой же
    /// новой строке.
    pub const ACTIONS: u16 = 0x8001;
}

/// Теги ОДНОЙ записи списка файлов.
mod entry_tag {
    pub const FILE_ID: u16 = 1;
    pub const ENC: u16 = 2;
    pub const NONCE: u16 = 3;
    pub const CT: u16 = 4;
}

/// Один файл гранта: его имя и доля B, запечатанная на ключ держателя.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub file_id: [u8; 16],
    /// Та же форма запечатанного блока, что у слота и у доли сервера.
    pub share_b: Blob,
}

/// Грант агента — подписан автором.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentGrant {
    pub grant_id: [u8; 16],
    /// `fpr == device_fpr(kem, public)` сверяется константным временем на
    /// разборе (K27): тройка `(fpr, kem, public)` приходит от чужой стороны, и
    /// посредник, приславший чужой отпечаток со своим ключом, получил бы долю на
    /// свой ключ под чужим именем.
    pub door_fpr: [u8; 32],
    pub door_kem: u8,
    pub door_public: Vec<u8>,
    pub door_verify: [u8; 32],
    /// По возрастанию `file_id`, без повторов. Порядок нормативен: он делает
    /// «тот же набор файлов» одной последовательностью байтов, а не многими.
    pub entries: Vec<Entry>,
    pub issued_at: i64,
    pub expires_at: i64,
    /// Ужесточение политики; `None` — «не ужесточает ничего».
    ///
    /// Кодек ТОТ ЖЕ, что у политики сервера в лизе и у политики автора в
    /// заголовке (`oc_format::policy_codec`): второе представление того же
    /// смысла разошлось бы с первым на первой же новой строке.
    pub tightening: Option<Policy>,
    pub max_depth: u8,
    pub author_key: [u8; 32],
    pub signature: [u8; SIGNATURE_LEN],
}

/// Байты гранта БЕЗ подписи — то, что подписывается и проверяется.
///
/// Отдельной функцией, потому что подписывающий и проверяющий обязаны собрать
/// одни и те же байты. Две сборки разошлись бы молча, и подпись перестала бы
/// значить то, что обещает.
///
/// # Errors
/// [`FormatError`], если грант не той формы, которую наш же читатель примет:
/// имя двери не называет её ключ, механизм не исполняется, список не по
/// возрастанию или длиннее [`MAX_GRANT_FILES`], глубина выше
/// [`MAX_GRANT_DEPTH`], срок кончается раньше начала.
pub fn grant_body(grant: &AgentGrant) -> Result<Vec<u8>, FormatError> {
    // Форма проверяется НА ЗАПИСИ, а не только на чтении: наш писатель не должен
    // уметь произвести документ, который наш же читатель обязан отвергнуть, —
    // обнаружилось бы это у получателя, как «грант повреждён». Тот же приём, что
    // у `encode_known_slot` в заголовке.
    check_grant_shape(grant)?;

    // Порядок полей — ПО ВОЗРАСТАНИЮ ТЕГА, как требует И-7; `TlvWriter`
    // проверяет это сам.
    let mut w = TlvWriter::new();
    w.put(tag::GRANT_ID, &grant.grant_id)?;
    w.put(tag::DOOR_FPR, &grant.door_fpr)?;
    w.put(tag::DOOR_KEM, &[grant.door_kem])?;
    w.put(tag::DOOR_PUBLIC, &grant.door_public)?;
    w.put(tag::DOOR_VERIFY, &grant.door_verify)?;
    w.put(tag::ENTRIES, &encode_entries(&grant.entries)?)?;
    w.put(tag::ISSUED_AT, &grant.issued_at.to_le_bytes())?;
    w.put(tag::EXPIRES_AT, &grant.expires_at.to_le_bytes())?;
    if let Some(policy) = &grant.tightening {
        w.put(tag::TIGHTENING, &encode_tightening(policy)?)?;
    }
    w.put(tag::MAX_DEPTH, &[grant.max_depth])?;
    w.put(tag::AUTHOR_KEY, &grant.author_key)?;
    Ok(w.finish().to_vec())
}

/// Транскрипт подписи гранта.
///
/// Через [`oc_crypto::Transcript`], а не ручной сборкой: его конструктор ТРЕБУЕТ
/// метку и сам ставит разделитель. Собери мы байты руками — метку можно было бы
/// забыть, и подпись гранта столкнулась бы с подписью заголовка в одном домене.
#[must_use]
pub fn grant_transcript(body: &[u8]) -> oc_crypto::Transcript {
    let mut t = oc_crypto::Transcript::new(oc_crypto::label::AGENT_GRANT);
    t.field(body);
    t
}

/// Закодировать грант целиком: `подпись(64) ‖ тело`.
///
/// # Errors
/// [`FormatError`], если тело не собирается — см. [`grant_body`].
pub fn encode_grant(grant: &AgentGrant) -> Result<Vec<u8>, FormatError> {
    let body = grant_body(grant)?;
    let mut out = Vec::with_capacity(SIGNATURE_LEN.saturating_add(body.len()));
    out.extend_from_slice(&grant.signature);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Проверить подпись автора, потом разобрать — в этом порядке, и только в этом.
///
/// `bytes` — документ целиком: `подпись(64) ‖ тело`. `author_key` передаёт
/// ВЫЗЫВАЮЩИЙ: ключ берётся из заголовка контейнера или из записи сервера о
/// файле, а не из принесённого документа. Ключ внутри документа сверяется с
/// переданным константным временем (И-13) — он часть подписанного тела, то есть
/// утверждение «грант выпущен для этого автора», а не источник истины.
///
/// # Errors
/// [`FormatError::BadHeaderSignature`] при коротком документе и при
/// несошедшейся подписи; иначе — ошибки разбора и проверки формы.
pub fn decode_grant(bytes: &[u8], author_key: &[u8; 32]) -> Result<AgentGrant, FormatError> {
    let (signature, body) = split_signature(bytes)?;
    oc_crypto::sign::verify(author_key, &grant_transcript(body), &signature)
        .map_err(|_| FormatError::BadHeaderSignature)?;
    let mut grant = decode_grant_body(body)?;
    if !oc_crypto::digest_eq(&grant.author_key, author_key) {
        // Подпись СОШЛАСЬ, а имя автора внутри другое. Значит документ подписан
        // тем, кого он сам автором не называет: либо ключ подменён, либо грант
        // адресован другому дереву. Вариант ошибки тот, которым весь крейт
        // сообщает «значение вне области».
        return Err(FormatError::BadFieldLength { tag: tag::AUTHOR_KEY, len: 32 });
    }
    grant.signature = signature;
    Ok(grant)
}

/// Тело гранта из подписанных байтов — БЕЗ проверки подписи.
///
/// # Кому это нужно и почему это не дыра
///
/// Серверу, и ровно затем же, зачем ему [`crate::order::peek`]: ключ проверки он
/// ищет ПО СОДЕРЖИМОМУ документа — по списку файлов, у записей которых записан
/// ключ автора, — а искать его, не прочитав список, нечем. Курица и яйцо
/// разрешаются тем же приёмом, что у распоряжений: здесь разбирают, чтобы
/// НАЙТИ ключ, и только [`decode_grant`] — чтобы поверить.
///
/// Всё, что отсюда возвращается, годится ровно для поиска ключа. Исполнять по
/// этому значению нельзя ничего: подпись не проверена, и любое поле выбрал тот,
/// кто документ прислал.
///
/// Форма при этом проверяется полностью (`check_grant_shape`): И-9 запрещает
/// выпускать из крейта байты, которых мы не проверили, и «почти разобранный»
/// грант наружу не уходит.
///
/// # Errors
/// [`FormatError`], если байты короче подписи или тело не разбирается.
pub fn peek_grant(bytes: &[u8]) -> Result<AgentGrant, FormatError> {
    let (signature, body) = split_signature(bytes)?;
    let mut grant = decode_grant_body(body)?;
    grant.signature = signature;
    Ok(grant)
}

/// Тело звена из подписанных байтов — БЕЗ проверки подписи.
///
/// Тот же довод, что у [`peek_grant`], и он здесь даже прямее: ключ проверки
/// звена — `verify` РОДИТЕЛЯ, а кто родитель, сказано внутри самого звена
/// (`parent_fpr`). Прочесть это поле, не разобрав тело, нельзя.
///
/// # Errors
/// [`FormatError`], если байты короче подписи или тело не разбирается.
pub fn peek_delegation(bytes: &[u8]) -> Result<Delegation, FormatError> {
    let (signature, body) = split_signature(bytes)?;
    let mut link = decode_delegation_body(body)?;
    link.signature = signature;
    Ok(link)
}

fn decode_grant_body(body: &[u8]) -> Result<AgentGrant, FormatError> {
    let mut reader = TlvReader::new(body);
    let (mut grant_id, mut door_fpr, mut door_kem, mut door_public) = (None, None, None, None);
    let (mut door_verify, mut entries, mut issued_at, mut expires_at) = (None, None, None, None);
    let (mut tightening, mut max_depth, mut author_key) = (None, None, None);
    while let Some(f) = reader.next_field()? {
        match f.tag {
            tag::GRANT_ID => grant_id = Some(f.array::<16>()?),
            tag::DOOR_FPR => door_fpr = Some(f.array::<32>()?),
            tag::DOOR_KEM => door_kem = Some(f.u8()?),
            tag::DOOR_PUBLIC => door_public = Some(f.value.to_vec()),
            tag::DOOR_VERIFY => door_verify = Some(f.array::<32>()?),
            tag::ENTRIES => entries = Some(decode_entries(f.value, tag::ENTRIES)?),
            tag::ISSUED_AT => issued_at = Some(i64::from_le_bytes(f.array::<8>()?)),
            tag::EXPIRES_AT => expires_at = Some(i64::from_le_bytes(f.array::<8>()?)),
            tag::TIGHTENING => tightening = Some(decode_tightening(f.value)?),
            tag::MAX_DEPTH => max_depth = Some(f.u8()?),
            tag::AUTHOR_KEY => author_key = Some(f.array::<32>()?),
            // Общее правило крейта (И-7): критичный незнакомый тег — отказ,
            // необязательный — пропуск. Пропуск безопасен потому, что подпись
            // покрывает СЫРЫЕ байты тела: дописать тег по дороге третья сторона
            // не может, подпись перестанет сходиться.
            other => crate::unknown::refuse_if_critical(other)?,
        }
    }
    let grant = AgentGrant {
        grant_id: grant_id.ok_or(FormatError::MissingField { tag: tag::GRANT_ID })?,
        door_fpr: door_fpr.ok_or(FormatError::MissingField { tag: tag::DOOR_FPR })?,
        door_kem: door_kem.ok_or(FormatError::MissingField { tag: tag::DOOR_KEM })?,
        door_public: door_public.ok_or(FormatError::MissingField { tag: tag::DOOR_PUBLIC })?,
        door_verify: door_verify.ok_or(FormatError::MissingField { tag: tag::DOOR_VERIFY })?,
        entries: entries.ok_or(FormatError::MissingField { tag: tag::ENTRIES })?,
        issued_at: issued_at.ok_or(FormatError::MissingField { tag: tag::ISSUED_AT })?,
        expires_at: expires_at.ok_or(FormatError::MissingField { tag: tag::EXPIRES_AT })?,
        tightening,
        max_depth: max_depth.ok_or(FormatError::MissingField { tag: tag::MAX_DEPTH })?,
        author_key: author_key.ok_or(FormatError::MissingField { tag: tag::AUTHOR_KEY })?,
        // Подпись кладёт `decode_grant`: она лежит вне тела.
        signature: [0; SIGNATURE_LEN],
    };
    check_grant_shape(&grant)?;
    Ok(grant)
}

/// Проверки формы, общие для записи и чтения.
///
/// Одной функцией, а не двумя списками: разойдись они — и появился бы документ,
/// который мы пишем и не читаем, либо читаем и не пишем.
fn check_grant_shape(grant: &AgentGrant) -> Result<(), FormatError> {
    check_holder_name(
        &grant.door_fpr,
        grant.door_kem,
        &grant.door_public,
        tag::DOOR_KEM,
        tag::DOOR_FPR,
    )?;
    check_entries(&grant.entries, tag::ENTRIES)?;
    if grant.max_depth > MAX_GRANT_DEPTH {
        return Err(FormatError::BadFieldLength {
            tag: tag::MAX_DEPTH,
            len: grant.max_depth as usize,
        });
    }
    if grant.expires_at < grant.issued_at {
        // Срок, кончающийся раньше начала, не «уже истёк»: это документ, о
        // котором нельзя сказать, что он вообще когда-либо действовал, и
        // принимать его значит отдавать решение о сроке чужим часам.
        return Err(FormatError::BadFieldLength { tag: tag::EXPIRES_AT, len: 8 });
    }
    Ok(())
}

/// Имя держателя называет предъявленный ключ — правило K27, для любого
/// механизма и ДО всякого использования тройки `(fpr, kem, public)`.
fn check_holder_name(
    fpr: &[u8; 32],
    kem: u8,
    public: &[u8],
    kem_tag: u16,
    fpr_tag: u16,
) -> Result<(), FormatError> {
    if kem != DOOR_KEM_X25519 {
        // Отказ НА РАЗБОРЕ, а не при первой попытке распечатать долю: механизм,
        // которого дверь не исполняет, — это грант, который никогда не сработает,
        // и узнать об этом лучше здесь, чем посреди сессии агента.
        return Err(FormatError::BadFieldLength { tag: kem_tag, len: 1 });
    }
    let alg = oc_crypto::KemAlg::from_u8(kem)
        .map_err(|_| FormatError::BadFieldLength { tag: kem_tag, len: 1 })?;
    // Длина ключа проверяется по механизму ВНУТРИ `device_fpr` (И-8), поэтому
    // отдельной проверки длины здесь нет.
    let named = oc_crypto::kdf::device_fpr(alg, public)
        .map_err(|_| FormatError::BadFieldLength { tag: fpr_tag, len: public.len() })?;
    if !oc_crypto::digest_eq(fpr, &named) {
        return Err(FormatError::BadFieldLength { tag: fpr_tag, len: 32 });
    }
    Ok(())
}

/// Список файлов: не длиннее потолка, строго по возрастанию `file_id`.
fn check_entries(entries: &[Entry], list_tag: u16) -> Result<(), FormatError> {
    if entries.len() > MAX_GRANT_FILES {
        return Err(FormatError::BadFieldLength { tag: list_tag, len: entries.len() });
    }
    for (index, pair) in entries.windows(2).enumerate() {
        let (Some(a), Some(b)) = (pair.first(), pair.get(1)) else { continue };
        if a.file_id >= b.file_id {
            // Возрастание даёт бесплатно то же, что И-7 даёт тегам: дубликаты
            // невозможны, перестановка невозможна, и один набор файлов — одна
            // последовательность байтов. Номера записей здесь и есть их теги во
            // вложенном TLV, поэтому вариант ошибки тот же, каким сообщает о
            // порядке разборщик TLV.
            let previous = u16::try_from(index).unwrap_or(u16::MAX);
            let found = previous.saturating_add(1);
            return Err(FormatError::FieldsOutOfOrder { previous, found });
        }
    }
    Ok(())
}

/// Записи списка: вложенный TLV, тег = номер записи.
///
/// Нумерация ПОЗИЦИЕЙ — тот же приём, которым заголовок кодирует слоты
/// (`oc-format`, запись 10). Своего счётчика записей нет намеренно: он был бы
/// вторым источником истины о том, сколько их, и разошёлся бы с телом.
fn encode_entries(entries: &[Entry]) -> Result<Vec<u8>, FormatError> {
    let mut w = TlvWriter::new();
    for (index, entry) in entries.iter().enumerate() {
        let tag = u16::try_from(index).map_err(|_| FormatError::OffsetOverflow)?;
        let mut inner = TlvWriter::new();
        inner.put(entry_tag::FILE_ID, &entry.file_id)?;
        inner.put(entry_tag::ENC, &entry.share_b.enc)?;
        inner.put(entry_tag::NONCE, &entry.share_b.nonce)?;
        inner.put(entry_tag::CT, &entry.share_b.ct)?;
        let body = inner.finish().to_vec();
        w.put(tag, &body)?;
    }
    Ok(w.finish().to_vec())
}

fn decode_entries(bytes: &[u8], list_tag: u16) -> Result<Vec<Entry>, FormatError> {
    let mut reader = TlvReader::new(bytes);
    let mut out: Vec<Entry> = Vec::new();
    while let Some(field) = reader.next_field()? {
        // Потолок проверяется ВНУТРИ цикла, а не после него: длину списка
        // называет чужая сторона, и «разобрать всё, потом посчитать» означало бы
        // выделить столько, сколько скажет собеседник.
        if out.len() >= MAX_GRANT_FILES {
            return Err(FormatError::BadFieldLength { tag: list_tag, len: out.len() });
        }
        out.push(decode_entry(field.value)?);
    }
    check_entries(&out, list_tag)?;
    Ok(out)
}

fn decode_entry(bytes: &[u8]) -> Result<Entry, FormatError> {
    let mut reader = TlvReader::new(bytes);
    let (mut file_id, mut enc, mut nonce, mut ct) = (None, None, None, None);
    while let Some(f) = reader.next_field()? {
        match f.tag {
            entry_tag::FILE_ID => file_id = Some(f.array::<16>()?),
            entry_tag::ENC => enc = Some(f.value.to_vec()),
            entry_tag::NONCE => nonce = Some(f.array::<24>()?),
            entry_tag::CT => ct = Some(f.value.to_vec()),
            other => crate::unknown::refuse_if_critical(other)?,
        }
    }
    Ok(Entry {
        file_id: file_id.ok_or(FormatError::MissingField { tag: entry_tag::FILE_ID })?,
        share_b: Blob {
            enc: enc.ok_or(FormatError::MissingField { tag: entry_tag::ENC })?,
            nonce: nonce.ok_or(FormatError::MissingField { tag: entry_tag::NONCE })?,
            ct: ct.ok_or(FormatError::MissingField { tag: entry_tag::CT })?,
        },
    })
}

/// Ужесточение — ТЕМ ЖЕ кодеком, каким кодируется политика сервера в лизе.
///
/// Второй формы политики на проводе быть не должно: она разошлась бы с первой на
/// первой же новой строке, а хеш политики — межреализационная поверхность.
fn encode_tightening(policy: &Policy) -> Result<Vec<u8>, FormatError> {
    oc_format::policy_codec::encode(oc_format::header::CONTAINER_VERSION, policy)
}

fn decode_tightening(bytes: &[u8]) -> Result<Policy, FormatError> {
    oc_format::policy_codec::decode(oc_format::header::SUPPORTED_READER_VERSION, bytes)
}

/// Делегирование — подписано ключом `door_verify` РОДИТЕЛЯ.
///
/// Родитель не вправе выдать потомку больше, чем имеет сам, и проверяет это не
/// он, а [`verify_grant_chain`]: список файлов — подмножество, срок не растёт,
/// глубина убывает. Здесь, в документе, лежит только то, что родитель УТВЕРЖДАЕТ;
/// сопоставление с родительским утверждением — работа цепочки.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delegation {
    pub grant_id: [u8; 16],
    pub parent_fpr: [u8; 32],
    pub child_fpr: [u8; 32],
    pub child_kem: u8,
    pub child_public: Vec<u8>,
    pub child_verify: [u8; 32],
    /// Подмножество родительского списка; доли перепечатаны на ключ потомка.
    pub entries: Vec<Entry>,
    pub expires_at: i64,
    pub tightening: Option<Policy>,
    /// Сколько ещё звеньев разрешено НИЖЕ этого.
    pub depth: u8,
    /// Действия, передаваемые потомку. Пустой список — «никаких», и это
    /// умолчание: тег необязателен, а отсутствующее правило означает ЗАПРЕТ.
    ///
    /// Здесь, как и у списка файлов, лежит лишь то, что родитель УТВЕРЖДАЕТ;
    /// сопоставление с родительским правилом — работа [`verify_grant_chain_with_actions`].
    pub actions: Vec<crate::action::ActionRule>,
    pub signature: [u8; SIGNATURE_LEN],
}

/// Байты делегирования БЕЗ подписи — то, что подписывается и проверяется.
///
/// # Errors
/// [`FormatError`], если звено не той формы, которую наш же читатель примет.
pub fn delegation_body(link: &Delegation) -> Result<Vec<u8>, FormatError> {
    check_delegation_shape(link)?;

    let mut w = TlvWriter::new();
    w.put(link_tag::GRANT_ID, &link.grant_id)?;
    w.put(link_tag::PARENT_FPR, &link.parent_fpr)?;
    w.put(link_tag::CHILD_FPR, &link.child_fpr)?;
    w.put(link_tag::CHILD_KEM, &[link.child_kem])?;
    w.put(link_tag::CHILD_PUBLIC, &link.child_public)?;
    w.put(link_tag::CHILD_VERIFY, &link.child_verify)?;
    w.put(link_tag::ENTRIES, &encode_entries(&link.entries)?)?;
    w.put(link_tag::EXPIRES_AT, &link.expires_at.to_le_bytes())?;
    if let Some(policy) = &link.tightening {
        w.put(link_tag::TIGHTENING, &encode_tightening(policy)?)?;
    }
    w.put(link_tag::DEPTH, &[link.depth])?;
    // ПОСЛЕ глубины и только при непустом списке: теги идут строго по
    // возрастанию (И-7), а пустое значение и отсутствие поля здесь означают
    // одно и то же — писать его значило бы завести два представления одного
    // смысла, то есть две последовательности байтов на одно звено.
    if !link.actions.is_empty() {
        w.put(link_tag::ACTIONS, &crate::action::encode_rules(&link.actions)?)?;
    }
    Ok(w.finish().to_vec())
}

/// Транскрипт подписи делегирования.
///
/// Метка своя, а не [`oc_crypto::label::AGENT_GRANT`]: грант подписывает автор,
/// делегирование — дверь своим эфемерным ключом. Совпади домены — дверь,
/// получившая грант, выписала бы себе новый, то есть новую глубину и новый срок.
#[must_use]
pub fn delegation_transcript(body: &[u8]) -> oc_crypto::Transcript {
    let mut t = oc_crypto::Transcript::new(oc_crypto::label::DELEGATION);
    t.field(body);
    t
}

/// Закодировать делегирование целиком: `подпись(64) ‖ тело`.
///
/// # Errors
/// [`FormatError`], если тело не собирается — см. [`delegation_body`].
pub fn encode_delegation(link: &Delegation) -> Result<Vec<u8>, FormatError> {
    let body = delegation_body(link)?;
    let mut out = Vec::with_capacity(SIGNATURE_LEN.saturating_add(body.len()));
    out.extend_from_slice(&link.signature);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Проверить подпись родителя, потом разобрать — в этом порядке, и только в нём.
///
/// `parent_verify` — ключ `verify` РОДИТЕЛЯ, переданный вызывающим: у первого
/// звена это `door_verify` гранта, у прочих — `child_verify` предыдущего. Внутри
/// документа этого ключа нет и быть не должно — иначе звено само называло бы,
/// чем его проверять.
///
/// # Errors
/// [`FormatError::BadHeaderSignature`] при коротком документе и при
/// несошедшейся подписи; иначе — ошибки разбора и проверки формы.
pub fn decode_delegation(
    bytes: &[u8],
    parent_verify: &[u8; 32],
) -> Result<Delegation, FormatError> {
    let (signature, body) = split_signature(bytes)?;
    oc_crypto::sign::verify(parent_verify, &delegation_transcript(body), &signature)
        .map_err(|_| FormatError::BadHeaderSignature)?;
    let mut link = decode_delegation_body(body)?;
    link.signature = signature;
    Ok(link)
}

fn decode_delegation_body(body: &[u8]) -> Result<Delegation, FormatError> {
    let mut reader = TlvReader::new(body);
    let (mut grant_id, mut parent_fpr, mut child_fpr, mut child_kem) = (None, None, None, None);
    let (mut child_public, mut child_verify, mut entries) = (None, None, None);
    let (mut expires_at, mut tightening, mut depth) = (None, None, None);
    let mut actions = Vec::new();
    while let Some(f) = reader.next_field()? {
        match f.tag {
            link_tag::GRANT_ID => grant_id = Some(f.array::<16>()?),
            link_tag::PARENT_FPR => parent_fpr = Some(f.array::<32>()?),
            link_tag::CHILD_FPR => child_fpr = Some(f.array::<32>()?),
            link_tag::CHILD_KEM => child_kem = Some(f.u8()?),
            link_tag::CHILD_PUBLIC => child_public = Some(f.value.to_vec()),
            link_tag::CHILD_VERIFY => child_verify = Some(f.array::<32>()?),
            link_tag::ENTRIES => entries = Some(decode_entries(f.value, link_tag::ENTRIES)?),
            link_tag::EXPIRES_AT => expires_at = Some(i64::from_le_bytes(f.array::<8>()?)),
            link_tag::TIGHTENING => tightening = Some(decode_tightening(f.value)?),
            link_tag::DEPTH => depth = Some(f.u8()?),
            // Тег необязательный, но ЗНАКОМЫЙ: раз мы его знаем — разбираем, и
            // мусор в нём отвергаем здесь, а не у сервера, где поздно. Читатель
            // первого этапа его не знает и пропускает (И-7), и цепочка файлов
            // от этого не меняется ничем.
            link_tag::ACTIONS => actions = crate::action::decode_rules(f.value)?,
            other => crate::unknown::refuse_if_critical(other)?,
        }
    }
    let link = Delegation {
        grant_id: grant_id.ok_or(FormatError::MissingField { tag: link_tag::GRANT_ID })?,
        parent_fpr: parent_fpr.ok_or(FormatError::MissingField { tag: link_tag::PARENT_FPR })?,
        child_fpr: child_fpr.ok_or(FormatError::MissingField { tag: link_tag::CHILD_FPR })?,
        child_kem: child_kem.ok_or(FormatError::MissingField { tag: link_tag::CHILD_KEM })?,
        child_public: child_public
            .ok_or(FormatError::MissingField { tag: link_tag::CHILD_PUBLIC })?,
        child_verify: child_verify
            .ok_or(FormatError::MissingField { tag: link_tag::CHILD_VERIFY })?,
        entries: entries.ok_or(FormatError::MissingField { tag: link_tag::ENTRIES })?,
        expires_at: expires_at.ok_or(FormatError::MissingField { tag: link_tag::EXPIRES_AT })?,
        tightening,
        depth: depth.ok_or(FormatError::MissingField { tag: link_tag::DEPTH })?,
        actions,
        signature: [0; SIGNATURE_LEN],
    };
    check_delegation_shape(&link)?;
    Ok(link)
}

fn check_delegation_shape(link: &Delegation) -> Result<(), FormatError> {
    check_holder_name(
        &link.child_fpr,
        link.child_kem,
        &link.child_public,
        link_tag::CHILD_KEM,
        link_tag::CHILD_FPR,
    )?;
    check_entries(&link.entries, link_tag::ENTRIES)?;
    if link.depth > MAX_GRANT_DEPTH {
        return Err(FormatError::BadFieldLength {
            tag: link_tag::DEPTH,
            len: link.depth as usize,
        });
    }
    if link.actions.len() > crate::action::MAX_ACTION_RULES {
        return Err(FormatError::BadFieldLength {
            tag: link_tag::ACTIONS,
            len: link.actions.len(),
        });
    }
    for rule in &link.actions {
        // Форма правила проверяется и здесь: наш писатель не должен уметь
        // произвести звено, которое наш же читатель обязан отвергнуть.
        crate::action::check_rule_shape(rule)?;
    }
    Ok(())
}

/// Итог проверки цепочки: на что и до когда вправе ПОСЛЕДНЕЕ звено.
///
/// # Почему ужесточения отдаются ВСЕ, а не сравниваются между собой
///
/// Потому что отношения порядка на политиках не существует и заводить его ради
/// одной проверки нельзя. Вместо «звено не ослабило родителя» цепочка отдаёт
/// весь список, а решатель пересекает его целиком: `oc_policy::intersect`
/// монотонна только в сторону ужесточения, поэтому лишнее звено способно
/// УЖЕСТОЧИТЬ и неспособно ослабить — что бы в нём ни лежало. Проверка,
/// которой нет, не может быть обойдена.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainFacts {
    pub grant_id: [u8; 16],
    pub holder_fpr: [u8; 32],
    pub holder_verify: [u8; 32],
    pub files: Vec<[u8; 16]>,
    pub expires_at: i64,
    /// Все ужесточения цепочки, от корня. Пересекает их вызывающий.
    pub tightening: Vec<Policy>,
    pub depth_left: u8,
    /// Действия, на которые вправе ПОСЛЕДНЕЕ звено.
    ///
    /// Пусто, если грант действий вызывающий не передал: правило, которое не с
    /// чем сверить, не действует (И-10). Поэтому старый вызов
    /// [`verify_grant_chain`] отдаёт здесь пустой список даже на цепочке, звенья
    /// которой несут тег действий, — и это не потеря, а умолчание «запрет».
    pub actions: Vec<crate::action::ActionRule>,
}

/// Почему цепочка не принята.
///
/// Свой род ошибки, а не вариант [`FormatError`]: разрыв цепочки — событие
/// ОТНОШЕНИЯ между звеньями, а не поля TLV, и номера тега у него нет. Номер
/// звена назван, потому что обе стороны показывают причину человеку, а «цепочка
/// не сошлась» без места разрыва не говорит ничего.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainRefusal {
    /// Грант не разобрался, не подписан этим автором или не той формы.
    BadGrant,
    /// Звено не разобралось или подписано не ключом родителя.
    BadLink { index: usize },
    /// Звено называет файл, которого у родителя нет.
    NotASubset { index: usize },
    /// Звено живёт дольше родителя.
    OutlivesParent { index: usize },
    /// Делегировать ниже уже нельзя: глубина исчерпана.
    DepthExhausted { index: usize },
    /// Звено называет другого родителя или другой корень.
    WrongParent { index: usize },
    /// Срок кончился по переданным часам.
    Expired,
    /// Срок ещё не начался по переданным часам.
    NotYetValid,
    /// Грант ДЕЙСТВИЙ не разобрался, не подписан этим автором или не той формы.
    BadActionGrant,
    /// Грант действий привязан к другому файловому гранту.
    ActionsWrongGrant,
    /// Грант действий живёт дольше файлового гранта, к которому привязан.
    ActionsOutliveGrant,
    /// Звено взяло вид действия, которого у родителя нет вовсе.
    ActionNotGranted { index: usize },
    /// Звено расширило родительское правило. Причина — от `action`.
    ActionWidens { index: usize, why: crate::action::ActionRefusal },
}

impl core::fmt::Display for ChainRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BadGrant => f.write_str("грант не принят: подпись автора не сошлась или документ не той формы"),
            Self::BadLink { index } => {
                write!(f, "звено {index} не принято: подпись родителя не сошлась или документ не той формы")
            }
            Self::NotASubset { index } => {
                write!(f, "звено {index} называет файл, которого нет у родителя")
            }
            Self::OutlivesParent { index } => write!(f, "звено {index} живёт дольше родителя"),
            Self::DepthExhausted { index } => {
                write!(f, "звено {index} лишнее: глубина делегирования исчерпана")
            }
            Self::WrongParent { index } => {
                write!(f, "звено {index} называет другого родителя или другой грант")
            }
            Self::Expired => f.write_str("срок гранта или звена уже истёк"),
            Self::NotYetValid => f.write_str("срок гранта ещё не начался"),
            Self::BadActionGrant => f.write_str(
                "грант действий не принят: подпись автора не сошлась или документ не той формы",
            ),
            Self::ActionsWrongGrant => {
                f.write_str("грант действий привязан к другому файловому гранту")
            }
            Self::ActionsOutliveGrant => {
                f.write_str("грант действий живёт дольше файлового гранта, к которому привязан")
            }
            Self::ActionNotGranted { index } => {
                write!(f, "звено {index} берёт вид действия, которого нет у родителя")
            }
            Self::ActionWidens { index, why } => {
                write!(f, "звено {index} расширяет правило действия: {why}")
            }
        }
    }
}

/// Проверить цепочку: грант, затем звенья по порядку. Часы — ПАРАМЕТРОМ.
///
/// `grant` и `links` — СЫРЫЕ байты: подписи проверяются здесь же, каждая до
/// разбора своего тела. Ключ проверки очередного звена берётся из предыдущего
/// звена, а самого первого — из гранта; ключ гранта приходит снаружи, из
/// заголовка контейнера.
///
/// Часы параметром, а не из системы: проба на истечение и на путешествие во
/// времени обязана быть ДАННЫМИ, иначе она проверяет часы машины, а не правило.
///
/// # Errors
/// [`ChainRefusal`] с номером звена, на котором цепочка разорвалась.
pub fn verify_grant_chain(
    author_key: &[u8; 32],
    grant: &[u8],
    links: &[&[u8]],
    now: i64,
) -> Result<ChainFacts, ChainRefusal> {
    verify_grant_chain_with_actions(author_key, grant, links, None, now)
}

/// То же, плюс ГРАНТ ДЕЙСТВИЙ (Agent Protocol, этап 2).
///
/// # Почему отдельная функция, а не пятый довод у прежней
///
/// Потому что прежний вызов обязан работать БЕЗ ПРАВОК — у него есть
/// вызывающие на сервере, в двери и в пробах первого этапа, и правка каждого
/// ради значения `None` была бы шумом, в котором теряется то единственное место,
/// где действительно что-то изменилось. Прежняя функция осталась ровно тем, чем
/// была, и делегирует сюда: две дороги к одной проверке, а не две проверки.
///
/// `actions` — СЫРЫЕ байты [`crate::action::ActionGrant`], подписанные ТЕМ ЖЕ
/// ключом автора: у действия нет контейнера с заголовком, поэтому якорь —
/// файловый грант, а ключ приходит снаружи, как и для него.
///
/// `None` означает «о действиях ничего не известно», и факты тогда несут пустой
/// список — в том числе когда звенья цепочки тег действий НЕСУТ. Проверить их
/// не с чем, а непроверенное правило не действует (И-10); заодно это и есть
/// обещание, что читатель первого этапа видит прежнюю цепочку.
///
/// # Errors
/// [`ChainRefusal`] с номером звена, на котором цепочка разорвалась.
pub fn verify_grant_chain_with_actions(
    author_key: &[u8; 32],
    grant: &[u8],
    links: &[&[u8]],
    actions: Option<&[u8]>,
    now: i64,
) -> Result<ChainFacts, ChainRefusal> {
    let grant = decode_grant(grant, author_key).map_err(|_| ChainRefusal::BadGrant)?;
    if now < grant.issued_at {
        return Err(ChainRefusal::NotYetValid);
    }
    if now > grant.expires_at {
        return Err(ChainRefusal::Expired);
    }

    // Грант действий разбирается ЗДЕСЬ, до обхода звеньев: его правила — корень
    // сужения, и звено, проверенное против пустого корня, прошло бы всё.
    let root_actions = match actions {
        None => Vec::new(),
        Some(bytes) => {
            let signed = crate::action::decode_grant(bytes, author_key)
                .map_err(|_| ChainRefusal::BadActionGrant)?;
            if signed.grant_id != grant.grant_id {
                // Привязка к ФАЙЛОВОМУ гранту и есть якорь: держатель, потолок
                // срока и погашение берутся оттуда. Грант действий с чужим
                // корнем — это права, выписанные другой двери.
                return Err(ChainRefusal::ActionsWrongGrant);
            }
            if signed.expires_at > grant.expires_at {
                // Проверка стоит здесь, а не только на сервере при
                // `PutActionGrant`: эта функция — единственное место, которое
                // видит ОБА документа сразу, и правило «срок не длиннее»
                // исполнимо только там, где есть с чем сравнивать.
                return Err(ChainRefusal::ActionsOutliveGrant);
            }
            if now < signed.issued_at {
                return Err(ChainRefusal::NotYetValid);
            }
            if now > signed.expires_at {
                return Err(ChainRefusal::Expired);
            }
            signed.rules
        }
    };

    let mut facts = ChainFacts {
        grant_id: grant.grant_id,
        holder_fpr: grant.door_fpr,
        holder_verify: grant.door_verify,
        files: grant.entries.iter().map(|entry| entry.file_id).collect(),
        expires_at: grant.expires_at,
        tightening: grant.tightening.into_iter().collect(),
        depth_left: grant.max_depth,
        actions: root_actions,
    };

    for (index, raw) in links.iter().enumerate() {
        // Подпись — ключом ПРЕДЫДУЩЕГО держателя, и проверяется она внутри
        // `decode_delegation`, то есть до разбора тела звена.
        let link = decode_delegation(raw, &facts.holder_verify)
            .map_err(|_| ChainRefusal::BadLink { index })?;

        // Звено обязано быть звеном ЭТОЙ цепочки: тот же корень и тот родитель,
        // чьим ключом оно подписано. Второе не следует из первого — ключ подписи
        // и согласовательный ключ у двери разные, и без сверки отпечатка звено
        // могло бы называть родителем кого угодно, оставаясь подписанным верно.
        if link.grant_id != facts.grant_id
            || !oc_crypto::digest_eq(&link.parent_fpr, &facts.holder_fpr)
        {
            return Err(ChainRefusal::WrongParent { index });
        }

        // Глубина: у родителя должно остаться хотя бы одно звено, и потомку
        // достаётся строго меньше. «Не больше» здесь недостаточно — цепочка
        // из звеньев одной глубины не кончалась бы никогда.
        if facts.depth_left == 0 || link.depth >= facts.depth_left {
            return Err(ChainRefusal::DepthExhausted { index });
        }

        if !link.entries.iter().all(|entry| facts.files.contains(&entry.file_id)) {
            return Err(ChainRefusal::NotASubset { index });
        }

        if link.expires_at > facts.expires_at {
            return Err(ChainRefusal::OutlivesParent { index });
        }
        if now > link.expires_at {
            return Err(ChainRefusal::Expired);
        }

        // Действия сужаются ровно как файлы: каждое правило потомка обязано
        // найти у родителя правило ТОГО ЖЕ ВИДА, которое оно не расширяет.
        // Считается это ДО присвоения новых фактов — иначе потомок сверялся бы
        // сам с собой.
        //
        // Когда грант действий не передан, список родителя пуст, и звено с
        // непустым тегом действий сюда не доходит вовсе: `narrow_actions`
        // зовётся только при известном корне. Так читатель первого этапа и
        // получает прежние факты на цепочке с тегом.
        facts.actions = if actions.is_some() {
            narrow_actions(&facts.actions, &link.actions, index)?
        } else {
            Vec::new()
        };

        facts.holder_fpr = link.child_fpr;
        facts.holder_verify = link.child_verify;
        facts.files = link.entries.iter().map(|entry| entry.file_id).collect();
        facts.expires_at = link.expires_at;
        facts.depth_left = link.depth;
        if let Some(policy) = link.tightening {
            facts.tightening.push(policy);
        }
    }

    Ok(facts)
}

/// Правила потомка против правил родителя: каждое обязано быть не шире.
///
/// # Почему «любое родительское того же вида», а не «первое»
///
/// Потому что правил одного вида у родителя бывает несколько: два `tree.remove`
/// на два разных поддерева — обычный грант, а не странность. Требовать
/// совпадения ПОРЯДКА значило бы делать проверку зависимой от того, как автор
/// перечислил правила, то есть отказывать в честном сужении по случайной
/// причине.
///
/// Причина отказа берётся от ПЕРВОГО родительского правила того же вида: отказ
/// без объяснения проходит любую пробу вида «отказ случился», а человеку нужен
/// ограничитель по имени. Когда такого вида у родителя нет вовсе, причина
/// другая и точнее — [`ChainRefusal::ActionNotGranted`].
fn narrow_actions(
    parents: &[crate::action::ActionRule],
    children: &[crate::action::ActionRule],
    index: usize,
) -> Result<Vec<crate::action::ActionRule>, ChainRefusal> {
    for child in children {
        let mut same_kind = parents.iter().filter(|p| p.kind == child.kind).peekable();
        if same_kind.peek().is_none() {
            return Err(ChainRefusal::ActionNotGranted { index });
        }
        let mut first_reason = None;
        let mut accepted = false;
        for parent in same_kind {
            match crate::action::narrower(child, parent) {
                Ok(()) => {
                    accepted = true;
                    break;
                }
                Err(why) => {
                    if first_reason.is_none() {
                        first_reason = Some(why);
                    }
                }
            }
        }
        if !accepted {
            let why = first_reason.unwrap_or(crate::action::ActionRefusal::WrongKind);
            return Err(ChainRefusal::ActionWidens { index, why });
        }
    }
    Ok(children.to_vec())
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

    /// Ключ ПОДПИСИ двери: им дверь заверяет делегирования.
    fn door() -> Ed25519Signer {
        Ed25519Signer::from_seed(&[0xd0; 32])
    }

    /// Согласовательный ключ двери. У X25519 отпечаток И ЕСТЬ ключ (K27),
    /// поэтому `door_fpr` совпадает с ним байт в байт.
    const DOOR_PUBLIC: [u8; 32] = [0xd1; 32];

    fn blob(seed: u8) -> Blob {
        Blob { enc: vec![seed; 32], nonce: [seed; 24], ct: vec![seed; 48] }
    }

    fn file_id(n: u16) -> [u8; 16] {
        let mut id = [0u8; 16];
        id[0] = (n >> 8) as u8;
        id[1] = n as u8;
        id
    }

    fn grant() -> AgentGrant {
        let mut g = AgentGrant {
            grant_id: [0x67; 16],
            door_fpr: DOOR_PUBLIC,
            door_kem: 1,
            door_public: DOOR_PUBLIC.to_vec(),
            door_verify: door().public_key(),
            entries: vec![
                Entry { file_id: file_id(1), share_b: blob(0x11) },
                Entry { file_id: file_id(2), share_b: blob(0x22) },
            ],
            issued_at: 1_700_000_000,
            expires_at: 1_700_086_400,
            tightening: None,
            max_depth: 2,
            author_key: author().public_key(),
            signature: [0; SIGNATURE_LEN],
        };
        sign_grant(&mut g, &author());
        g
    }

    fn sign_grant(g: &mut AgentGrant, signer: &Ed25519Signer) {
        let body = grant_body(g).expect("тело гранта собирается");
        g.signature = signer.sign(&grant_transcript(&body)).unwrap();
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

    /// Пересобрать тело, заменив значение одного тега. Нужно затем, чтобы
    /// получить документ, который наш писатель произвести отказывается: иначе
    /// проверки чтения остались бы непроверенными.
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

    /// Пересобрать тело, ДОБАВИВ тег (в конец, чтобы возрастание не нарушилось).
    fn rebuild_plus(body: &[u8], tag: u16, value: &[u8]) -> Vec<u8> {
        let mut w = TlvWriter::new();
        for (t, v) in fields_of(body) {
            w.put(t, &v).unwrap();
        }
        w.put(tag, value).unwrap();
        w.finish().to_vec()
    }

    /// Документ из готового тела, подписанный названным ключом.
    fn signed(body: &[u8], signer: &Ed25519Signer) -> Vec<u8> {
        let sig = signer.sign(&grant_transcript(body)).unwrap();
        let mut out = sig.to_vec();
        out.extend_from_slice(body);
        out
    }

    #[test]
    fn grant_round_trips() {
        let g = grant();
        let bytes = encode_grant(&g).unwrap();
        assert_eq!(decode_grant(&bytes, &author().public_key()).unwrap(), g);
    }

    /// Ужесточение ходит ТЕМ ЖЕ кодеком, что политика сервера в лизе.
    ///
    /// Проба заведена вместе с решением держать в структуре `Policy`, а не
    /// непрозрачные байты: байты не проверяются ничем, и грант с мусором в этом
    /// поле дожил бы до сервера, где ужесточение уже поздно отвергать.
    #[test]
    fn a_tightening_policy_round_trips_through_the_same_codec() {
        let mut g = grant();
        let mut policy = Policy::no_tightening();
        policy.max_opens = Some(3);
        g.tightening = Some(policy.clone());
        sign_grant(&mut g, &author());

        let bytes = encode_grant(&g).unwrap();
        let back = decode_grant(&bytes, &author().public_key()).unwrap();
        assert_eq!(back.tightening, Some(policy));
        assert_eq!(back, g);
    }

    /// ПОДПИСЬ ПРОВЕРЯЕТСЯ ДО РАЗБОРА ТЕЛА.
    ///
    /// Тело здесь заведомо НЕРАЗБИРАЕМО, и проба различает порядок двумя
    /// прогонами: с ЧУЖОЙ подписью ответ обязан быть подписным, со СВОЕЙ —
    /// разборным. Один прогон этого не показал бы: `is_err()` истинно у обоих
    /// порядков.
    #[test]
    fn a_flipped_body_byte_fails_the_signature_before_parsing() {
        let good = grant_body(&grant()).unwrap();

        // Портится байт ВНУТРИ TLV так, чтобы разбор тоже упал: номер механизма
        // становится неисполнимым.
        let broken_kem = rebuild_with(&good, tag::DOOR_KEM, &[0x63]);
        // И второй способ быть неразбираемым — незнакомый критичный тег.
        let unknown_critical = rebuild_plus(&good, 0x7FFF, &[0xab; 4]);

        for (what, body) in
            [("неисполнимый механизм", broken_kem), ("чужой критичный тег", unknown_critical)]
        {
            // Предпосылка: своя подпись — и ответ РАЗБОРНЫЙ.
            let own = signed(&body, &author());
            let parsed = decode_grant(&own, &author().public_key());
            assert!(
                matches!(parsed, Err(FormatError::BadFieldLength { .. } | FormatError::UnknownCriticalField { .. })),
                "{what}: предпосылка неверна, тело разбирается: {parsed:?}"
            );

            // А теперь подпись настоящая, но ЧУЖАЯ: подделать документ противник
            // умеет, подписать ключом автора — нет.
            let forged = signed(&body, &stranger());
            let outcome = decode_grant(&forged, &author().public_key());
            assert!(
                matches!(outcome, Err(FormatError::BadHeaderSignature)),
                "{what}: разбор произошёл до проверки подписи, ответ {outcome:?}"
            );
        }
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

    /// КЛЮЧ ВНУТРИ ОБЯЗАН СОВПАСТЬ С ПЕРЕДАННЫМ.
    ///
    /// Подпись здесь СХОДИТСЯ: документ подписан настоящим автором, но называет
    /// автором другого. Без сверки грант, выпущенный для одного дерева, был бы
    /// принят как выпущенный для другого — и поймать это `is_err()` на чужой
    /// подписи нельзя, потому что подпись не чужая.
    #[test]
    fn the_author_key_inside_must_match_the_one_supplied() {
        let mut g = grant();
        g.author_key = [0x99; 32];
        sign_grant(&mut g, &author());
        let bytes = encode_grant(&g).unwrap();
        match decode_grant(&bytes, &author().public_key()) {
            Err(FormatError::BadFieldLength { tag, .. }) => assert_eq!(tag, tag::AUTHOR_KEY),
            other => panic!("грант с чужим именем автора принят: {other:?}"),
        }
    }

    #[test]
    fn entries_out_of_order_or_repeated_are_refused() {
        let ordered = grant();

        for (what, entries) in [
            (
                "перестановка",
                vec![
                    Entry { file_id: file_id(2), share_b: blob(0x22) },
                    Entry { file_id: file_id(1), share_b: blob(0x11) },
                ],
            ),
            (
                "повтор",
                vec![
                    Entry { file_id: file_id(1), share_b: blob(0x11) },
                    Entry { file_id: file_id(1), share_b: blob(0x22) },
                ],
            ),
        ] {
            // Писатель отказывается сам.
            let mut g = ordered.clone();
            g.entries = entries.clone();
            assert!(grant_body(&g).is_err(), "{what}: писатель произвёл такой грант");

            // И читатель — по документу, собранному в обход писателя.
            let body = rebuild_with(
                &grant_body(&ordered).unwrap(),
                tag::ENTRIES,
                &encode_entries(&entries).unwrap(),
            );
            let outcome = decode_grant(&signed(&body, &author()), &author().public_key());
            assert!(
                matches!(outcome, Err(FormatError::FieldsOutOfOrder { .. })),
                "{what}: читатель принял, ответ {outcome:?}"
            );
        }
    }

    #[test]
    fn more_than_max_files_is_refused() {
        let ordered = grant();
        let many: Vec<Entry> = (0..=MAX_GRANT_FILES)
            .map(|n| Entry {
                file_id: file_id(u16::try_from(n).unwrap()),
                share_b: blob(0x33),
            })
            .collect();
        assert_eq!(many.len(), MAX_GRANT_FILES + 1);

        let mut g = ordered.clone();
        g.entries = many.clone();
        assert!(grant_body(&g).is_err(), "писатель выпустил грант длиннее потолка");

        let body = rebuild_with(
            &grant_body(&ordered).unwrap(),
            tag::ENTRIES,
            &encode_entries(&many).unwrap(),
        );
        let outcome = decode_grant(&signed(&body, &author()), &author().public_key());
        assert!(
            matches!(outcome, Err(FormatError::BadFieldLength { tag: tag::ENTRIES, .. })),
            "список длиннее потолка принят: {outcome:?}"
        );
    }

    #[test]
    fn depth_above_max_is_refused() {
        let ordered = grant();
        let mut g = ordered.clone();
        g.max_depth = MAX_GRANT_DEPTH + 1;
        assert!(grant_body(&g).is_err(), "писатель выпустил грант с глубиной выше потолка");

        let body = rebuild_with(
            &grant_body(&ordered).unwrap(),
            tag::MAX_DEPTH,
            &[MAX_GRANT_DEPTH + 1],
        );
        let outcome = decode_grant(&signed(&body, &author()), &author().public_key());
        assert!(
            matches!(outcome, Err(FormatError::BadFieldLength { tag: tag::MAX_DEPTH, .. })),
            "глубина выше потолка принята: {outcome:?}"
        );
    }

    /// ОТПЕЧАТОК ОБЯЗАН НАЗЫВАТЬ ПРЕДЪЯВЛЕННЫЙ КЛЮЧ (K27).
    ///
    /// Иначе посредник присылает чужой отпечаток со своим ключом и получает доли
    /// на свой ключ под чужим именем — находка Н-1/Н-4 криптообзора.
    #[test]
    fn a_door_fingerprint_that_is_not_the_name_of_its_key_is_refused() {
        let ordered = grant();
        let mut g = ordered.clone();
        g.door_fpr = [0xee; 32];
        assert!(grant_body(&g).is_err(), "писатель выпустил грант с чужим именем двери");

        let body = rebuild_with(&grant_body(&ordered).unwrap(), tag::DOOR_FPR, &[0xee; 32]);
        let outcome = decode_grant(&signed(&body, &author()), &author().public_key());
        assert!(
            matches!(outcome, Err(FormatError::BadFieldLength { tag: tag::DOOR_FPR, .. })),
            "имя, не называющее ключ, принято: {outcome:?}"
        );
    }

    /// МЕХАНИЗМ, КОТОРОГО ЭТАП 1 НЕ ИСПОЛНЯЕТ, ОТВЕРГАЕТСЯ НА РАЗБОРЕ.
    ///
    /// Первый случай тем и ценен, что отпечаток в нём ЧЕСТНЫЙ: ключ P-256 назван
    /// своим именем по K27, и отказ приходит не от сверки имени, а от того, что
    /// дверь такого механизма не умеет (правило 4 «Как менять формат»).
    #[test]
    fn an_unexecuted_kem_is_refused_on_parse() {
        let ordered = grant();
        let body = grant_body(&ordered).unwrap();

        let p256_public = {
            let mut key = vec![0x04u8; 65];
            key[1] = 0x11;
            key
        };
        let p256_fpr =
            oc_crypto::kdf::device_fpr(oc_crypto::KemAlg::P256HkdfSha256, &p256_public).unwrap();
        let honest_p256 = {
            let with_kem = rebuild_with(&body, tag::DOOR_KEM, &[2]);
            let with_key = rebuild_with(&with_kem, tag::DOOR_PUBLIC, &p256_public);
            rebuild_with(&with_key, tag::DOOR_FPR, &p256_fpr)
        };

        for (what, doc) in [
            ("честный P-256", honest_p256),
            ("номер вне реестра", rebuild_with(&body, tag::DOOR_KEM, &[0x63])),
        ] {
            let outcome = decode_grant(&signed(&doc, &author()), &author().public_key());
            assert!(
                matches!(outcome, Err(FormatError::BadFieldLength { tag: tag::DOOR_KEM, .. })),
                "{what}: механизм принят, ответ {outcome:?}"
            );
        }
    }

    #[test]
    fn unknown_optional_tag_is_skipped() {
        let body = rebuild_plus(&grant_body(&grant()).unwrap(), 0x8000, &[1, 2, 3]);
        let bytes = signed(&body, &author());
        let back = decode_grant(&bytes, &author().public_key()).unwrap();
        // Всё, кроме подписи, совпало: необязательное поле проехало мимо.
        let mut expected = grant();
        expected.signature = back.signature;
        assert_eq!(back, expected);
    }

    #[test]
    fn unknown_critical_tag_is_refused() {
        let body = rebuild_plus(&grant_body(&grant()).unwrap(), 0x7FFF, &[1, 2, 3]);
        let outcome = decode_grant(&signed(&body, &author()), &author().public_key());
        assert!(
            matches!(outcome, Err(FormatError::UnknownCriticalField { tag: 0x7FFF })),
            "критичный тег из будущей версии пропущен молча: {outcome:?}"
        );
    }

    #[test]
    fn expires_before_issued_is_refused() {
        let ordered = grant();
        let mut g = ordered.clone();
        g.expires_at = g.issued_at - 1;
        assert!(grant_body(&g).is_err(), "писатель выпустил грант с сроком раньше выдачи");

        let body = rebuild_with(
            &grant_body(&ordered).unwrap(),
            tag::EXPIRES_AT,
            &(ordered.issued_at - 1).to_le_bytes(),
        );
        let outcome = decode_grant(&signed(&body, &author()), &author().public_key());
        assert!(
            matches!(outcome, Err(FormatError::BadFieldLength { tag: tag::EXPIRES_AT, .. })),
            "срок раньше выдачи принят: {outcome:?}"
        );
    }

    // ------------------------------------------------------------------
    // Делегирование и цепочка.
    // ------------------------------------------------------------------

    /// Ключ ПОДПИСИ первого потомка.
    fn child_a() -> Ed25519Signer {
        Ed25519Signer::from_seed(&[0xc0; 32])
    }

    /// Согласовательный ключ первого потомка; он же его отпечаток (K27, X25519).
    const CHILD_A_PUBLIC: [u8; 32] = [0xc1; 32];

    fn child_b() -> Ed25519Signer {
        Ed25519Signer::from_seed(&[0xb0; 32])
    }

    const CHILD_B_PUBLIC: [u8; 32] = [0xb1; 32];

    fn child_c() -> Ed25519Signer {
        Ed25519Signer::from_seed(&[0xe0; 32])
    }

    const CHILD_C_PUBLIC: [u8; 32] = [0xe1; 32];

    /// Момент, в который цепочка проверяется. Данными, а не системными часами:
    /// иначе проба на истечение проверяла бы часы машины, а не правило.
    const NOW: i64 = 1_700_010_000;

    fn sign_link(d: &mut Delegation, signer: &Ed25519Signer) {
        let body = delegation_body(d).expect("тело звена собирается");
        d.signature = signer.sign(&delegation_transcript(&body)).unwrap();
    }

    /// Первое звено: дверь → потомок A, один файл из двух, срок короче гранта.
    fn link_one() -> Delegation {
        let mut d = Delegation {
            grant_id: [0x67; 16],
            parent_fpr: DOOR_PUBLIC,
            child_fpr: CHILD_A_PUBLIC,
            child_kem: 1,
            child_public: CHILD_A_PUBLIC.to_vec(),
            child_verify: child_a().public_key(),
            entries: vec![Entry { file_id: file_id(1), share_b: blob(0x44) }],
            expires_at: 1_700_050_000,
            tightening: None,
            depth: 1,
            actions: Vec::new(),
            signature: [0; SIGNATURE_LEN],
        };
        sign_link(&mut d, &door());
        d
    }

    /// Второе звено: потомок A → потомок B.
    fn link_two() -> Delegation {
        let mut d = Delegation {
            grant_id: [0x67; 16],
            parent_fpr: CHILD_A_PUBLIC,
            child_fpr: CHILD_B_PUBLIC,
            child_kem: 1,
            child_public: CHILD_B_PUBLIC.to_vec(),
            child_verify: child_b().public_key(),
            entries: vec![Entry { file_id: file_id(1), share_b: blob(0x55) }],
            expires_at: 1_700_040_000,
            tightening: None,
            depth: 0,
            actions: Vec::new(),
            signature: [0; SIGNATURE_LEN],
        };
        sign_link(&mut d, &child_a());
        d
    }

    fn chain(grant: &AgentGrant, links: &[Delegation], now: i64) -> Result<ChainFacts, ChainRefusal> {
        let grant_bytes = encode_grant(grant).unwrap();
        let raw: Vec<Vec<u8>> = links.iter().map(|l| encode_delegation(l).unwrap()).collect();
        let refs: Vec<&[u8]> = raw.iter().map(Vec::as_slice).collect();
        verify_grant_chain(&author().public_key(), &grant_bytes, &refs, now)
    }

    #[test]
    fn delegation_round_trips() {
        let d = link_one();
        let bytes = encode_delegation(&d).unwrap();
        assert_eq!(decode_delegation(&bytes, &door().public_key()).unwrap(), d);
    }

    /// ПОДПИСЬ ЗВЕНА ПРОВЕРЯЕТСЯ ДО РАЗБОРА ТЕЛА — тот же порядок, что у гранта.
    #[test]
    fn the_delegation_signature_is_checked_before_the_body_is_parsed() {
        let good = delegation_body(&link_one()).unwrap();
        let mut w = TlvWriter::new();
        for (t, v) in fields_of(&good) {
            w.put(t, &v).unwrap();
        }
        w.put(0x7FFF, &[0xab; 4]).unwrap();
        let body = w.finish().to_vec();

        // Своя подпись — ответ разборный.
        let own = {
            let sig = door().sign(&delegation_transcript(&body)).unwrap();
            let mut out = sig.to_vec();
            out.extend_from_slice(&body);
            out
        };
        assert!(
            matches!(
                decode_delegation(&own, &door().public_key()),
                Err(FormatError::UnknownCriticalField { .. })
            ),
            "предпосылка неверна: тело разбирается"
        );

        // Чужая подпись — ответ подписной, и только он.
        let forged = {
            let sig = stranger().sign(&delegation_transcript(&body)).unwrap();
            let mut out = sig.to_vec();
            out.extend_from_slice(&body);
            out
        };
        let outcome = decode_delegation(&forged, &door().public_key());
        assert!(
            matches!(outcome, Err(FormatError::BadHeaderSignature)),
            "разбор произошёл до проверки подписи: {outcome:?}"
        );
    }

    /// Имя потомка обязано называть его ключ — то же правило K27, что у двери.
    #[test]
    fn a_child_fingerprint_that_is_not_the_name_of_its_key_is_refused() {
        let mut d = link_one();
        d.child_fpr = [0xee; 32];
        assert!(delegation_body(&d).is_err(), "писатель выпустил звено с чужим именем потомка");
    }

    #[test]
    fn a_two_link_chain_verifies() {
        let facts = chain(&grant(), &[link_one(), link_two()], NOW).expect("честная цепочка");
        assert_eq!(facts.grant_id, [0x67; 16]);
    }

    #[test]
    fn facts_name_the_last_holder() {
        let facts = chain(&grant(), &[link_one(), link_two()], NOW).unwrap();
        assert_eq!(facts.holder_fpr, CHILD_B_PUBLIC, "держателем назван не последний");
        assert_eq!(facts.holder_verify, child_b().public_key());
        assert_eq!(facts.files, vec![file_id(1)], "файлы взяты не у последнего звена");
        assert_eq!(facts.expires_at, 1_700_040_000, "срок взят не самый короткий");
        assert_eq!(facts.depth_left, 0);
        assert!(facts.tightening.is_empty());
    }

    #[test]
    fn a_link_adding_a_file_is_refused() {
        let mut d = link_one();
        d.entries.push(Entry { file_id: file_id(9), share_b: blob(0x66) });
        sign_link(&mut d, &door());
        assert_eq!(chain(&grant(), &[d], NOW), Err(ChainRefusal::NotASubset { index: 0 }));
    }

    #[test]
    fn a_link_outliving_its_parent_is_refused() {
        let g = grant();
        let mut d = link_one();
        d.expires_at = g.expires_at.saturating_add(1);
        sign_link(&mut d, &door());
        assert_eq!(chain(&g, &[d], NOW), Err(ChainRefusal::OutlivesParent { index: 0 }));
    }

    /// Третье звено при глубине 2 лишнее: у второго не осталось ни одного.
    #[test]
    fn a_link_below_zero_depth_is_refused() {
        let mut third = Delegation {
            grant_id: [0x67; 16],
            parent_fpr: CHILD_B_PUBLIC,
            child_fpr: CHILD_C_PUBLIC,
            child_kem: 1,
            child_public: CHILD_C_PUBLIC.to_vec(),
            child_verify: child_c().public_key(),
            entries: vec![Entry { file_id: file_id(1), share_b: blob(0x77) }],
            expires_at: 1_700_030_000,
            tightening: None,
            depth: 0,
            actions: Vec::new(),
            signature: [0; SIGNATURE_LEN],
        };
        sign_link(&mut third, &child_b());
        assert_eq!(
            chain(&grant(), &[link_one(), link_two(), third], NOW),
            Err(ChainRefusal::DepthExhausted { index: 2 })
        );
    }

    #[test]
    fn max_depth_zero_forbids_any_link() {
        let mut g = grant();
        g.max_depth = 0;
        sign_grant(&mut g, &author());
        // Звено приходится переподписать: `door_verify` в гранте тот же, но
        // подпись звена от гранта не зависит — переподписывать нечего, и это
        // само по себе важно: глубину стережёт цепочка, а не подпись.
        assert_eq!(chain(&g, &[link_one()], NOW), Err(ChainRefusal::DepthExhausted { index: 0 }));
    }

    #[test]
    fn a_link_signed_by_a_stranger_is_refused() {
        let mut d = link_one();
        sign_link(&mut d, &stranger());
        assert_eq!(chain(&grant(), &[d], NOW), Err(ChainRefusal::BadLink { index: 0 }));
    }

    /// ЗВЕНО, НАЗЫВАЮЩЕЕ ЧУЖОГО РОДИТЕЛЯ, ОТВЕРГАЕТСЯ, ХОТЯ ПОДПИСЬ СХОДИТСЯ.
    ///
    /// Подпись здесь настоящая — звено подписано дверью. Сверять отпечаток всё
    /// равно обязательно: ключ подписи и согласовательный ключ у двери разные, и
    /// без сверки доли перепечатывались бы на ключ, которого в цепочке нет.
    #[test]
    fn a_link_naming_the_wrong_parent_is_refused() {
        let mut d = link_one();
        d.parent_fpr = [0xbb; 32];
        sign_link(&mut d, &door());
        assert_eq!(chain(&grant(), &[d], NOW), Err(ChainRefusal::WrongParent { index: 0 }));
    }

    #[test]
    fn links_from_another_grant_are_refused() {
        let mut d = link_one();
        d.grant_id = [0x68; 16];
        sign_link(&mut d, &door());
        assert_eq!(chain(&grant(), &[d], NOW), Err(ChainRefusal::WrongParent { index: 0 }));
    }

    /// ВРЕМЯ — ДАННЫМИ, и оба края проверяются отдельно.
    #[test]
    fn an_expired_grant_is_refused_by_the_clock_given() {
        let g = grant();
        assert_eq!(chain(&g, &[], g.expires_at.saturating_add(1)), Err(ChainRefusal::Expired));
        assert_eq!(chain(&g, &[], g.issued_at.saturating_sub(1)), Err(ChainRefusal::NotYetValid));
        // Контроль: на краях срок ещё действует — иначе проба выше зеленела бы
        // и при правиле «истекло всегда».
        assert!(chain(&g, &[], g.issued_at).is_ok());
        assert!(chain(&g, &[], g.expires_at).is_ok());
    }

    /// Истёкшее ЗВЕНО гасит цепочку, даже когда грант ещё жив.
    #[test]
    fn an_expired_link_is_refused_though_the_grant_lives() {
        let g = grant();
        let d = link_one();
        assert!(d.expires_at < g.expires_at, "предпосылка: звено короче гранта");
        assert_eq!(chain(&g, std::slice::from_ref(&d), d.expires_at.saturating_add(1)), Err(ChainRefusal::Expired));
    }

    /// У КАЖДОГО ОТКАЗА ЕСТЬ ПРИЧИНА СЛОВАМИ.
    ///
    /// Проба против мутации «причина → пустая строка»: отказ без объяснения
    /// проходит любую проверку вида «отказ случился», и ловится он только так.
    #[test]
    fn every_refusal_names_a_reason() {
        for refusal in [
            ChainRefusal::BadGrant,
            ChainRefusal::BadLink { index: 1 },
            ChainRefusal::NotASubset { index: 1 },
            ChainRefusal::OutlivesParent { index: 1 },
            ChainRefusal::DepthExhausted { index: 1 },
            ChainRefusal::WrongParent { index: 1 },
            ChainRefusal::Expired,
            ChainRefusal::NotYetValid,
        ] {
            let text = format!("{refusal}");
            assert!(text.len() > 10, "отказ {refusal:?} не объяснён: {text:?}");
        }
    }

    /// ВЗГЛЯД БЕЗ ПРОВЕРКИ ПОДПИСИ ОТДАЁТ ТО ЖЕ ТЕЛО — И НЕ ЗАМЕНЯЕТ ПРОВЕРКИ.
    ///
    /// Две половины: на честном документе `peek` и `decode` дают одно и то же
    /// (иначе сервер искал бы ключ по одним полям, а верил другим), а на
    /// документе с ЧУЖОЙ подписью `peek` проходит, `decode` — нет. Вторая
    /// половина и есть то, ради чего проба написана: `peek`, случайно ставший
    /// проверяющим, зеленил бы любую пробу вида «сервер принял грант».
    #[test]
    fn peeking_reads_the_same_body_but_never_stands_in_for_the_signature() {
        let g = grant();
        let bytes = encode_grant(&g).unwrap();
        assert_eq!(peek_grant(&bytes).unwrap(), g);
        assert_eq!(peek_grant(&bytes).unwrap(), decode_grant(&bytes, &author().public_key()).unwrap());

        let body = grant_body(&g).unwrap();
        let forged = signed(&body, &stranger());
        assert!(peek_grant(&forged).is_ok(), "взгляд обязан проходить и без своей подписи");
        assert!(
            matches!(decode_grant(&forged, &author().public_key()), Err(FormatError::BadHeaderSignature)),
            "чужая подпись принята"
        );

        let link = link_one();
        let raw = encode_delegation(&link).unwrap();
        assert_eq!(peek_delegation(&raw).unwrap(), link);
        let link_body = delegation_body(&link).unwrap();
        let sig = stranger().sign(&delegation_transcript(&link_body)).unwrap();
        let mut forged_link = sig.to_vec();
        forged_link.extend_from_slice(&link_body);
        assert!(peek_delegation(&forged_link).is_ok());
        assert!(
            matches!(
                decode_delegation(&forged_link, &door().public_key()),
                Err(FormatError::BadHeaderSignature)
            ),
            "звено с чужой подписью принято"
        );

        // Форма проверяется и здесь: незаверенный документ не той формы наружу
        // не уходит (И-9).
        let broken = rebuild_with(&body, tag::DOOR_KEM, &[0x63]);
        let mut document = [0u8; SIGNATURE_LEN].to_vec();
        document.extend_from_slice(&broken);
        assert!(peek_grant(&document).is_err(), "взгляд выпустил грант не той формы");
    }

    // ------------------------------------------------------------------
    // Делегирование ДЕЙСТВИЙ (этап 2).
    // ------------------------------------------------------------------

    use crate::action::{
        ActionGrant, ActionKind, ActionRefusal, ActionRule, Constraint, Method,
        grant_body as action_grant_body, grant_transcript as action_grant_transcript,
    };

    fn push_rule(branch: &str, max_uses: u32, delegable: bool) -> ActionRule {
        ActionRule {
            kind: ActionKind::GitPush,
            constraint: Constraint::GitPush {
                remote: "origin".to_string(),
                branch: branch.to_string(),
            },
            max_uses,
            confirm: false,
            delegable,
        }
    }

    fn remove_rule(prefix: &str) -> ActionRule {
        ActionRule {
            kind: ActionKind::TreeRemove,
            constraint: Constraint::TreeRemove { prefix: prefix.to_string() },
            max_uses: 0,
            confirm: false,
            delegable: true,
        }
    }

    fn http_rule() -> ActionRule {
        ActionRule {
            kind: ActionKind::HttpRequest,
            constraint: Constraint::HttpRequest {
                host: "api.example.com".to_string(),
                methods: vec![Method::Get, Method::Post],
                path_prefix: "/v1".to_string(),
                secret_ref: None,
            },
            max_uses: 100,
            confirm: false,
            delegable: true,
        }
    }

    /// Грант действий на тот же корень, подписанный тем же автором.
    fn action_grant(rules: Vec<ActionRule>) -> Vec<u8> {
        let mut g = ActionGrant {
            grant_id: [0x67; 16],
            rules,
            issued_at: 1_700_000_000,
            expires_at: 1_700_086_400,
            author_key: author().public_key(),
            signature: [0; SIGNATURE_LEN],
        };
        let body = action_grant_body(&g).expect("тело гранта действий собирается");
        g.signature = author().sign(&action_grant_transcript(&body)).unwrap();
        crate::action::encode_grant(&g).unwrap()
    }

    /// Звено первого уровня с названными действиями.
    fn link_with(actions: Vec<ActionRule>) -> Delegation {
        let mut d = link_one();
        d.actions = actions;
        sign_link(&mut d, &door());
        d
    }

    fn chain_acting(
        links: &[Delegation],
        actions: Option<&[u8]>,
        now: i64,
    ) -> Result<ChainFacts, ChainRefusal> {
        let grant_bytes = encode_grant(&grant()).unwrap();
        let raw: Vec<Vec<u8>> = links.iter().map(|l| encode_delegation(l).unwrap()).collect();
        let refs: Vec<&[u8]> = raw.iter().map(Vec::as_slice).collect();
        verify_grant_chain_with_actions(
            &author().public_key(),
            &grant_bytes,
            &refs,
            actions,
            now,
        )
    }

    #[test]
    fn a_delegation_with_actions_round_trips() {
        let d = link_with(vec![push_rule("agent/work", 5, false), remove_rule("src/agent")]);
        let bytes = encode_delegation(&d).unwrap();
        assert_eq!(decode_delegation(&bytes, &door().public_key()).unwrap(), d);
    }

    /// БЕЗ ТЕГА И С ПУСТЫМ СПИСКОМ — ОДНИ И ТЕ ЖЕ БАЙТЫ.
    ///
    /// Два представления одного смысла дали бы два звена на одно утверждение, а
    /// подпись считается по СЫРЫМ байтам: «то же звено» перестало бы быть одной
    /// последовательностью.
    #[test]
    fn an_empty_action_list_writes_no_tag_at_all() {
        let plain = delegation_body(&link_one()).unwrap();
        let mut empty = link_one();
        empty.actions = Vec::new();
        assert_eq!(delegation_body(&empty).unwrap(), plain);
        assert!(
            !fields_of(&plain).iter().any(|(t, _)| *t == link_tag::ACTIONS),
            "пустой список всё же записал тег"
        );
    }

    /// ЧИТАТЕЛЬ ПЕРВОГО ЭТАПА ВИДИТ ПРЕЖНЮЮ ЦЕПОЧКУ.
    ///
    /// Условие задачи и обещание И-7 разом: тег действий необязателен, старый
    /// вызов [`verify_grant_chain`] обязан пройти по цепочке С ТЕГОМ и отдать
    /// те же факты о файлах, что и по цепочке без него. Список действий при
    /// этом ПУСТ — непроверенное правило не действует (И-10).
    #[test]
    fn the_stage_one_reader_sees_the_same_chain_through_the_action_tag() {
        let with_tag = link_with(vec![push_rule("agent/work", 5, false)]);
        let plain = link_one();

        let a = chain(&grant(), std::slice::from_ref(&with_tag), NOW).expect("цепочка с тегом");
        let b = chain(&grant(), std::slice::from_ref(&plain), NOW).expect("цепочка без тега");

        assert_eq!(a.files, b.files, "тег действий изменил список файлов");
        assert_eq!(a.expires_at, b.expires_at);
        assert_eq!(a.holder_fpr, b.holder_fpr);
        assert_eq!(a.depth_left, b.depth_left);
        assert!(a.actions.is_empty(), "старый вызов отдал действия, которых не проверял");
    }

    /// Сужение проходит, и факты называют правила ПОСЛЕДНЕГО держателя.
    #[test]
    fn a_narrowing_child_gets_the_actions_it_asked_for() {
        let raw = action_grant(vec![push_rule("agent/work", 10, true), http_rule()]);
        let child = push_rule("agent/work", 4, false);
        let link = link_with(vec![child.clone()]);

        let facts = chain_acting(std::slice::from_ref(&link), Some(&raw), NOW)
            .expect("честное сужение действий");
        assert_eq!(facts.actions, vec![child], "факты назвали не правила потомка");
    }

    /// Без гранта действий факты пусты — даже когда звено просит.
    #[test]
    fn actions_unknown_to_the_verifier_never_take_effect() {
        let link = link_with(vec![push_rule("agent/work", 4, false)]);
        let facts = chain_acting(std::slice::from_ref(&link), None, NOW).unwrap();
        assert!(facts.actions.is_empty());
    }

    /// Корень цепочки получает правила гранта действий целиком.
    #[test]
    fn with_no_links_the_door_itself_holds_the_granted_actions() {
        let rules = vec![push_rule("agent/work", 10, true), http_rule()];
        let raw = action_grant(rules.clone());
        let facts = chain_acting(&[], Some(&raw), NOW).unwrap();
        assert_eq!(facts.actions, rules);
    }

    /// ДВЕРЬ «ТОЛЬКО ДЕЙСТВИЯ»: ФАЙЛОВЫЙ ГРАНТ С ПУСТЫМ СПИСКОМ ФАЙЛОВ ЖИВ.
    ///
    /// Спека этапа 2 (§4.1) на это рассчитывает и просит подтвердить пробой:
    /// двери, которой нужны только действия, файлы не нужны вовсе, а якорем
    /// остаётся всё равно файловый грант — у действия нет контейнера, из
    /// заголовка которого берётся ключ автора.
    ///
    /// Проверялось это до сих пор ТОЛЬКО чтением кода (`check_entries` смотрит
    /// верхний предел и молчит о нижнем), а «сегодня принимает» и «обещано
    /// принимать» — разные утверждения: первое чинится случайной правкой.
    #[test]
    fn a_file_grant_with_no_files_still_anchors_its_actions() {
        let mut g = grant();
        g.entries.clear();
        sign_grant(&mut g, &author());
        let bytes = encode_grant(&g).unwrap();
        assert!(
            decode_grant(&bytes, &author().public_key()).is_ok(),
            "грант без файлов отвергнут — двери «только действия» не существовать"
        );

        let rules = vec![push_rule("agent/work", 10, true)];
        let raw = action_grant(rules.clone());
        let facts = verify_grant_chain_with_actions(
            &author().public_key(),
            &bytes,
            &[],
            Some(&raw),
            NOW,
        )
        .expect("цепочка без файлов не принята");
        assert!(facts.files.is_empty(), "предпосылка: файлов у гранта нет");
        assert_eq!(facts.actions, rules, "действия не достались двери без файлов");
    }

    /// РАСШИРЕНИЕ ПО КАЖДОМУ ПОЛЮ — СВОЙ ОТКАЗ.
    #[test]
    fn every_way_of_widening_an_action_has_its_own_refusal() {
        let raw = action_grant(vec![push_rule("agent/work", 10, true), remove_rule("src")]);

        // Вид, которого у родителя нет вовсе.
        let link = link_with(vec![http_rule()]);
        assert_eq!(
            chain_acting(std::slice::from_ref(&link), Some(&raw), NOW),
            Err(ChainRefusal::ActionNotGranted { index: 0 })
        );

        // Другая ветка — равенство, а не вложенность.
        let link = link_with(vec![push_rule("main", 10, false)]);
        assert_eq!(
            chain_acting(std::slice::from_ref(&link), Some(&raw), NOW),
            Err(ChainRefusal::ActionWidens {
                index: 0,
                why: ActionRefusal::WiderLimiter { limiter: "branch" },
            })
        );

        // Больше исполнений, чем у родителя.
        let link = link_with(vec![push_rule("agent/work", 11, false)]);
        assert_eq!(
            chain_acting(std::slice::from_ref(&link), Some(&raw), NOW),
            Err(ChainRefusal::ActionWidens { index: 0, why: ActionRefusal::MoreUses })
        );

        // Соседний каталог: `src2` не под `src`, и по строке прошёл бы.
        let link = link_with(vec![remove_rule("src2")]);
        assert_eq!(
            chain_acting(std::slice::from_ref(&link), Some(&raw), NOW),
            Err(ChainRefusal::ActionWidens {
                index: 0,
                why: ActionRefusal::WiderLimiter { limiter: "prefix" },
            })
        );
    }

    /// `confirm`-правило не делегируется никогда: живое «да» владельца выписано
    /// на конкретную дверь.
    #[test]
    fn a_confirm_rule_does_not_travel_down_the_chain() {
        let mut parent = push_rule("agent/work", 10, true);
        parent.confirm = true;
        let raw = action_grant(vec![parent]);
        let link = link_with(vec![push_rule("agent/work", 1, false)]);
        assert_eq!(
            chain_acting(std::slice::from_ref(&link), Some(&raw), NOW),
            Err(ChainRefusal::ActionWidens {
                index: 0,
                why: ActionRefusal::ConfirmNotDelegable,
            })
        );
    }

    /// `delegable` ТОЛЬКО СНИМАЕТСЯ: у родителя снят — потомку не достаётся.
    #[test]
    fn a_rule_not_marked_delegable_stops_at_its_holder() {
        let raw = action_grant(vec![push_rule("agent/work", 10, false)]);
        let link = link_with(vec![push_rule("agent/work", 1, false)]);
        assert_eq!(
            chain_acting(std::slice::from_ref(&link), Some(&raw), NOW),
            Err(ChainRefusal::ActionWidens { index: 0, why: ActionRefusal::NotDelegable })
        );
    }

    /// Сужение считается ПО ЦЕПОЧКЕ, а не против корня.
    ///
    /// Второе звено сверяется с правилами ПЕРВОГО, а не гранта: иначе внук
    /// восстанавливал бы то, что сын отдал уже; проверка против корня зеленела
    /// бы на цепочке «10 → 4 → 8».
    #[test]
    fn the_second_link_narrows_the_first_and_not_the_root() {
        let raw = action_grant(vec![push_rule("agent/work", 10, true)]);
        let first = link_with(vec![push_rule("agent/work", 4, true)]);

        let widen = {
            let mut d = link_two();
            d.actions = vec![push_rule("agent/work", 8, false)];
            sign_link(&mut d, &child_a());
            d
        };
        assert_eq!(
            chain_acting(&[first.clone(), widen], Some(&raw), NOW),
            Err(ChainRefusal::ActionWidens { index: 1, why: ActionRefusal::MoreUses })
        );

        // Контроль: сужение на втором звене проходит.
        let narrow = {
            let mut d = link_two();
            d.actions = vec![push_rule("agent/work", 2, false)];
            sign_link(&mut d, &child_a());
            d
        };
        let facts = chain_acting(&[first, narrow], Some(&raw), NOW).unwrap();
        assert_eq!(facts.actions, vec![push_rule("agent/work", 2, false)]);
    }

    /// Звено, не назвавшее действий, ГАСИТ их для всех, кто ниже.
    #[test]
    fn a_link_that_names_no_actions_passes_none_down() {
        let raw = action_grant(vec![push_rule("agent/work", 10, true)]);
        let facts = chain_acting(std::slice::from_ref(&link_one()), Some(&raw), NOW).unwrap();
        assert!(facts.actions.is_empty(), "действия просочились через звено, их не назвавшее");
    }

    /// ГРАНТ ДЕЙСТВИЙ ОТ ЧУЖОГО КОРНЯ, ОТ ЧУЖОГО АВТОРА И ПЕРЕЖИВШИЙ ФАЙЛОВЫЙ.
    #[test]
    fn the_action_grant_is_anchored_to_this_file_grant_and_this_author() {
        // Чужой корень: подпись сходится, привязка нет.
        let mut g = ActionGrant {
            grant_id: [0x68; 16],
            rules: vec![push_rule("agent/work", 10, true)],
            issued_at: 1_700_000_000,
            expires_at: 1_700_086_400,
            author_key: author().public_key(),
            signature: [0; SIGNATURE_LEN],
        };
        let body = action_grant_body(&g).unwrap();
        g.signature = author().sign(&action_grant_transcript(&body)).unwrap();
        let raw = crate::action::encode_grant(&g).unwrap();
        assert_eq!(chain_acting(&[], Some(&raw), NOW), Err(ChainRefusal::ActionsWrongGrant));

        // Чужой автор.
        let mut g = ActionGrant {
            grant_id: [0x67; 16],
            rules: vec![push_rule("agent/work", 10, true)],
            issued_at: 1_700_000_000,
            expires_at: 1_700_086_400,
            author_key: stranger().public_key(),
            signature: [0; SIGNATURE_LEN],
        };
        let body = action_grant_body(&g).unwrap();
        g.signature = stranger().sign(&action_grant_transcript(&body)).unwrap();
        let raw = crate::action::encode_grant(&g).unwrap();
        assert_eq!(chain_acting(&[], Some(&raw), NOW), Err(ChainRefusal::BadActionGrant));

        // Срок длиннее файлового гранта.
        let mut g = ActionGrant {
            grant_id: [0x67; 16],
            rules: vec![push_rule("agent/work", 10, true)],
            issued_at: 1_700_000_000,
            expires_at: 1_700_086_401,
            author_key: author().public_key(),
            signature: [0; SIGNATURE_LEN],
        };
        let body = action_grant_body(&g).unwrap();
        g.signature = author().sign(&action_grant_transcript(&body)).unwrap();
        let raw = crate::action::encode_grant(&g).unwrap();
        assert_eq!(chain_acting(&[], Some(&raw), NOW), Err(ChainRefusal::ActionsOutliveGrant));
    }

    /// Истёкший грант действий гасит действия, даже когда файловый жив.
    #[test]
    fn an_expired_action_grant_is_refused_by_the_clock_given() {
        let mut g = ActionGrant {
            grant_id: [0x67; 16],
            rules: vec![push_rule("agent/work", 10, true)],
            issued_at: 1_700_000_000,
            expires_at: 1_700_005_000,
            author_key: author().public_key(),
            signature: [0; SIGNATURE_LEN],
        };
        let body = action_grant_body(&g).unwrap();
        g.signature = author().sign(&action_grant_transcript(&body)).unwrap();
        let raw = crate::action::encode_grant(&g).unwrap();

        assert_eq!(chain_acting(&[], Some(&raw), NOW), Err(ChainRefusal::Expired));
        // Контроль: до истечения тот же грант принимается, иначе проба выше
        // зеленела бы и при правиле «истекло всегда».
        assert!(chain_acting(&[], Some(&raw), 1_700_004_999).is_ok());
    }

    /// Мусор в необязательном теге отвергается НА РАЗБОРЕ, а не у сервера.
    #[test]
    fn junk_in_the_action_tag_is_refused_when_the_link_is_parsed() {
        let good = delegation_body(&link_one()).unwrap();
        let body = rebuild_plus(&good, link_tag::ACTIONS, &[0xab; 7]);
        let sig = door().sign(&delegation_transcript(&body)).unwrap();
        let mut document = sig.to_vec();
        document.extend_from_slice(&body);
        assert!(
            decode_delegation(&document, &door().public_key()).is_err(),
            "мусор в теге действий проехал мимо разбора"
        );
    }

    /// И у НОВЫХ отказов есть причина словами.
    #[test]
    fn every_action_refusal_of_the_chain_names_a_reason() {
        for refusal in [
            ChainRefusal::BadActionGrant,
            ChainRefusal::ActionsWrongGrant,
            ChainRefusal::ActionsOutliveGrant,
            ChainRefusal::ActionNotGranted { index: 1 },
            ChainRefusal::ActionWidens { index: 1, why: ActionRefusal::MoreUses },
        ] {
            let text = format!("{refusal}");
            assert!(text.len() > 10, "отказ {refusal:?} не объяснён: {text:?}");
        }
    }

    /// Разбор произвольных байтов не паникует: грант приходит с провода.
    #[test]
    fn decoding_arbitrary_bytes_never_panics() {
        let key = author().public_key();
        let bytes = encode_grant(&grant()).unwrap();
        for cut in 0..bytes.len() {
            let _ = decode_grant(&bytes[..cut], &key);
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
        }
    }
}
