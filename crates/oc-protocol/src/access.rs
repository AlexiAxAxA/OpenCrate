//! Документы ЗАПРОСА ДОСТУПА: получатель просит, автор одобряет.
//!
//! # Что это за разговор и чем он отличается от активации
//!
//! Активация отвечает на вопрос «можно ли ЭТОМУ устройству открыть файл СЕЙЧАС»
//! и решается сервером по правилам, которые автор записал заранее. Запрос
//! доступа отвечает на другой вопрос — «а этот человек вообще из числа тех, кому
//! файл предназначен», — и решить его сервер не может ни при каких правилах:
//! получателя при упаковке не называли.
//!
//! Решает автор. Сервер здесь **слепой посредник**: он хранит очередь, показывает
//! её автору и доставляет ответ. Ни доли B, ни содержимого он не видит — ответ
//! запечатан на ключ устройства, а не на его.
//!
//! # Почему это не стоило формату ни байта
//!
//! Слот `AuthorDevice` несёт ОБЕ доли (`docs/format.md` §3.3), поэтому автор
//! вправе отдать долю B кому угодно, не трогая контейнер и не переподписывая
//! заголовок. Выданная доля живёт отдельным запечатанным блоком той же формы,
//! что уже отдаёт сервер, — получатель хранит её рядом с лизингом.
//!
//! # Кто такой «автор» с точки зрения сервера
//!
//! Учётных записей у сервера нет и заводить их не пришлось. Заголовок контейнера
//! несёт `author_key` (тег 5) и подписан ИМ ЖЕ, строгой проверкой (И-6). Значит
//! сервер узнаёт ключ автора при регистрации файла — из самого файла, — и
//! одобрение принимает только подписанное этим ключом.
//!
//! Приём тот же, которым закреплён ключ подписи лизинга: истина о том, кто вправе
//! решать, приходит из подписанного заголовка, а не из слов собеседника.

use oc_format::tlv::{TlvReader, TlvWriter};
use oc_format::{FormatError, MAX_HEADER_LEN};

/// Наибольший размер документа этого разговора.
///
/// Тот же потолок, что у документов активации, и по той же причине: самое
/// крупное здесь — запечатанный блок доли, а он по форме слот и больше
/// предельного заголовка быть не может.
pub const MAX_DOCUMENT: usize = MAX_HEADER_LEN as usize;

/// Сколько ожидающих просьб сервер отдаёт автору за раз — ОКНО очереди.
///
/// Величина провода: ответ на `Requests` несёт не больше стольких записей, и
/// клиент больший ответ отвергает — длина приходит от чужой стороны.
///
/// Шестнадцать: столько же, сколько адресов сервера в заголовке, и по сходной
/// причине — величина, которую человек в состоянии просмотреть глазами. Решённые
/// уходят из окна, и в него встают следующие по номеру (C4): так сто просьб
/// разбираются окнами по шестнадцать, а не упираются в потолок.
pub const MAX_PENDING_PER_FILE: usize = 16;

/// Сколько нерешённых просьб сервер согласен ПОМНИТЬ на один файл — потолок.
///
/// Предел нужен, потому что просьба принимается ДО всякого одобрения: кто
/// угодно, добравшийся до сервера, вправе попросить. Без потолка это очередь,
/// которую набивают бесплатно.
///
/// Прежде потолок совпадал с окном (16), и на рассылке ста критикам
/// восемьдесят четыре получали «очередь полна» (`docs/plan.md`, Ф-22 п. 3).
/// Двести пятьдесят шесть — с запасом на такую рассылку; цена названа: до
/// ~400 КиБ состояния на файл при гибридных ключах (1216 байт ключа и 256 байт
/// записки на запись). Величина только серверная: на провод не выходит.
pub const MAX_WAITING_PER_FILE: usize = 256;

/// Номер решения, зарезервированный за завещанием.
///
/// Завещание — обычное подписанное решение автора, лежащее на сервере до тишины
/// (`docs/protocol.md` §11). Сквозная очередь решений начинается с нуля и растёт,
/// поэтому наибольшее возможное число ей недостижимо: занять его завещанием
/// значит не отнять у очереди ни одного номера.
///
/// Резервируется он затем, чтобы завещание нельзя было выдать за очередное
/// решение и наоборот. Сторона приёма номер не сверяет вовсе
/// (`cc_cli::granted::accept_against`) — и это не упущение, а причина, по которой
/// завещание вообще возможно без правки получателя: сверяет номер сервер, и по
/// нему отличает одно от другого, не заводя второго вида документа.
pub const HEIR_SEQ: u64 = u64::MAX;

mod tag {
    pub const FILE_ID: u16 = 1;
    pub const DEVICE_FPR: u16 = 2;
    pub const DEVICE_PUBLIC: u16 = 3;
    pub const DEVICE_KEM: u16 = 4;
    pub const NOTE: u16 = 5;
    pub const SEQ: u16 = 6;
    pub const AT: u16 = 7;
    pub const APPROVE: u16 = 8;
    pub const ENC: u16 = 9;
    pub const NONCE: u16 = 10;
    pub const CT: u16 = 11;
    pub const AUTHOR_KEY: u16 = 12;
    pub const SIGNATURE: u16 = 13;
}

/// Просьба о доступе, отправленная устройством.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AskAccess {
    pub file_id: [u8; 16],
    pub device_fpr: [u8; 32],
    pub device_public: Vec<u8>,
    pub device_kem: u8,
    /// Записка от человека к человеку: «это Пётр из бухгалтерии».
    ///
    /// Чистый UTF-8 на ЛЮБОМ языке: записку показывают человеку, и пишет её
    /// тоже человек. Отсекаются не буквы, а категории — управляющие символы и
    /// двунаправленные метки, потому что текст выбирает посторонний, а печатают
    /// его рядом со строками, которым автор верит. Правило — `note_char_is_safe`.
    pub note: String,
}

/// Запрос, ждущий решения. Так его видит автор.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pending {
    /// Номер в очереди сервера. Им автор и называет запрос, одобряя.
    pub seq: u64,
    pub file_id: [u8; 16],
    pub device_fpr: [u8; 32],
    pub device_public: Vec<u8>,
    pub device_kem: u8,
    pub note: String,
    /// Когда запрос принят — по часам СЕРВЕРА.
    ///
    /// Именно сервера: время, названное просителем, ничем не подтверждено, а
    /// автору оно нужно, чтобы отличить «просят прямо сейчас» от «просили
    /// месяц назад».
    pub at: i64,
}

/// Решение автора.
///
/// Подписывается ключом автора (`author_key` из заголовка), и подпись покрывает
/// ВСЁ решение целиком, включая запечатанную долю: иначе посредник мог бы
/// подменить долю, оставив одобрение.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    pub seq: u64,
    pub file_id: [u8; 16],
    /// Кому. Дублирует то, что лежит в очереди, и это не избыточность: подпись
    /// покрывает отпечаток, поэтому одобрение нельзя переадресовать.
    pub device_fpr: [u8; 32],
    pub approve: bool,
    /// Доля B, запечатанная на ключ устройства. `None` при отказе.
    pub share_b: Option<Blob>,
    pub author_key: [u8; 32],
    pub signature: [u8; 64],
}

/// Запечатанный блок: та же форма, что у слота и у доли сервера.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blob {
    pub enc: Vec<u8>,
    pub nonce: [u8; 24],
    pub ct: Vec<u8>,
}

/// Байты решения БЕЗ подписи — то, что подписывается и проверяется.
///
/// Отдельной функцией, потому что подписывающий и проверяющий обязаны собрать
/// одни и те же байты. Две сборки разошлись бы молча, и подпись перестала бы
/// значить то, что обещает.
///
/// # Errors
/// Отдаёт [`FormatError`], если тело не кодируется.
pub fn decision_body(decision: &Decision) -> Result<Vec<u8>, FormatError> {
    // Порядок полей — ПО ВОЗРАСТАНИЮ ТЕГА, как требует И-7. Записать их в
    // порядке чтения было бы естественнее для глаза, и первая редакция так и
    // сделала: `TlvWriter` отверг её сам, потому что возрастание он проверяет.
    let mut w = TlvWriter::new();
    w.put(tag::FILE_ID, &decision.file_id)?;
    w.put(tag::DEVICE_FPR, &decision.device_fpr)?;
    w.put(tag::SEQ, &decision.seq.to_le_bytes())?;
    w.put(tag::APPROVE, &[u8::from(decision.approve)])?;
    if let Some(blob) = &decision.share_b {
        w.put(tag::ENC, &blob.enc)?;
        w.put(tag::NONCE, &blob.nonce)?;
        w.put(tag::CT, &blob.ct)?;
    }
    w.put(tag::AUTHOR_KEY, &decision.author_key)?;
    Ok(w.finish().to_vec())
}

/// Транскрипт подписи решения.
///
/// Через [`oc_crypto::Transcript`], а не ручной сборкой: его конструктор ТРЕБУЕТ
/// метку и сам ставит разделитель. Собери мы байты руками — метку можно было бы
/// забыть, и подпись решения столкнулась бы с подписью заголовка в одном домене.
#[must_use]
pub fn decision_transcript(body: &[u8]) -> oc_crypto::Transcript {
    let mut t = oc_crypto::Transcript::new(oc_crypto::label::GRANT);
    t.field(body);
    t
}

/// Годится ли символ для записки.
///
/// # Почему НЕ печатный ASCII, хотя у адресов сервера именно он
///
/// Первая редакция сузила записку до печатного ASCII — тем же правилом, что
/// закрывает подделку отображения у адресов сервера. Правило верное, перенос
/// неверный, и поймал это не тест, а живой прогон между двумя машинами:
/// записка «проба с ноутбука HUAWEI» была отвергнута сервером.
///
/// Вещи разные. У адреса сервера есть ПРОВОДНАЯ форма, и она ASCII по
/// построению: нелатинские имена ходят в сеть как punycode, так что сужение не
/// отсекает там ничего живого. У записки проводной формы нет — это фраза от
/// человека человеку, и люди пишут на своём языке. Пример в докстроке
/// [`AskAccess::note`] («это Пётр из бухгалтерии») сам не прошёл бы проверку:
/// код запрещал ровно то, что документация приводила образцом.
///
/// # Что отсекается
///
/// То же, что у имён файлов (находка В-8), и по той же причине — опасны не
/// буквы, а КАТЕГОРИИ. Состав множества и обоснование каждой категории —
/// [`oc_format::text`]; здесь только РЕАКЦИЯ: отвергнуть.
///
/// Первая редакция несла свою копию списка — четвёртую в репозитории — и была
/// неполна ровно там же, где остальные три: девять кодовых точек Trojan Source
/// без самих меток направления (ALM, LRM, RLM). Копия убрана, список общий.
///
/// # Почему перевода строки БОЛЬШЕ НЕТ
///
/// Первая редакция его разрешала: «фраза бывает в две строки, а сдвинуть им
/// вывод нельзя — он добавляет строку, а не переписывает соседнюю». Довод верен
/// про ЗАТИРАНИЕ и упускает ПОДДЕЛКУ ПЕРЕЧНЯ. Записка печатается пунктом списка
/// просьб, и перевод строки выводит текст из этого пункта наружу: записка,
/// внутри которой стоят «№ 2» и «устройство:», дорисовывает в очередь просьбу,
/// которой нет.
///
/// Довесок: единственный потребитель записки всё равно заменял `\n` точкой,
/// то есть двухстрочная записка НИКОГДА не показывалась в две строки. Формат
/// разрешал то, чего показ не умел.
fn note_char_is_safe(c: char) -> bool {
    !oc_format::text::is_display_unsafe(c)
}

/// Наибольшая длина записки. Фраза, а не письмо.
pub const MAX_NOTE: usize = 256;

/// Правило записки, общее на весь крейт.
///
/// # Почему номер тега — параметр, а не константа внутри
///
/// Потому что записка есть не только здесь: её несёт и просьба об ИСПОЛНЕНИИ
/// действия ([`crate::action::ActionRequest`], этап 2), и там у поля свой номер
/// в своём реестре. Копия этих десяти строк во втором месте — ровно та болезнь,
/// которую репозиторий знает поимённо: один путь чинят, соседний забывают, и
/// набор отсекаемых категорий разошёлся бы на первой же правке
/// [`oc_format::text`]. Параметр стоит дешевле копии, а отказ при этом называет
/// ТОТ тег, в котором записка лежала, — иначе человек читал бы номер поля из
/// чужого документа.
///
/// # Errors
/// [`FormatError::BadFieldLength`] — записка длиннее [`MAX_NOTE`];
/// [`FormatError::BadNoteChar`] — в ней символ из отсекаемых категорий.
pub(crate) fn check_note(note: &str, tag: u16) -> Result<(), FormatError> {
    if note.len() > MAX_NOTE {
        return Err(FormatError::BadFieldLength { tag, len: note.len() });
    }
    if let Some(bad) = note.chars().find(|c| !note_char_is_safe(*c)) {
        // Отдельно от адресов сервера, а не тем же отказом. Прежняя редакция
        // возвращала `BadAddressByte { byte: 0 }`, и человек читал «в адресе
        // байт 0x00» — неверно дважды: поле не адрес, а нулевого байта в его
        // записке не было вовсе.
        return Err(FormatError::BadNoteChar { tag, code: u32::from(bad) });
    }
    Ok(())
}

/// Закодировать просьбу.
///
/// # Errors
/// Отдаёт [`FormatError`], если записка длиннее допустимого или содержит
/// небезопасные символы.
pub fn encode_ask(ask: &AskAccess) -> Result<Vec<u8>, FormatError> {
    check_note(&ask.note, tag::NOTE)?;
    let mut w = TlvWriter::new();
    w.put(tag::FILE_ID, &ask.file_id)?;
    w.put(tag::DEVICE_FPR, &ask.device_fpr)?;
    w.put(tag::DEVICE_PUBLIC, &ask.device_public)?;
    w.put(tag::DEVICE_KEM, &[ask.device_kem])?;
    w.put(tag::NOTE, ask.note.as_bytes())?;
    Ok(w.finish().to_vec())
}

/// Разобрать просьбу.
///
/// # Errors
/// Отдаёт [`FormatError`] при нехватке полей, неверных длинах или небезопасной
/// записке.
pub fn decode_ask(bytes: &[u8]) -> Result<AskAccess, FormatError> {
    let mut reader = TlvReader::new(bytes);
    let (mut file_id, mut fpr, mut public, mut kem, mut note) = (None, None, None, None, None);
    while let Some(f) = reader.next_field()? {
        match f.tag {
            tag::FILE_ID => file_id = Some(f.array::<16>()?),
            tag::DEVICE_FPR => fpr = Some(f.array::<32>()?),
            tag::DEVICE_PUBLIC => public = Some(f.value.to_vec()),
            tag::DEVICE_KEM => kem = Some(one_byte(f.value, tag::DEVICE_KEM)?),
            tag::NOTE => {
                let text = core::str::from_utf8(f.value)
                    .map_err(|_| FormatError::NotUtf8 { tag: tag::NOTE })?;
                check_note(text, tag::NOTE)?;
                note = Some(text.to_string());
            }
            other => crate::unknown::refuse_if_critical(other)?,
        }
    }
    Ok(AskAccess {
        file_id: file_id.ok_or(FormatError::MissingField { tag: tag::FILE_ID })?,
        device_fpr: fpr.ok_or(FormatError::MissingField { tag: tag::DEVICE_FPR })?,
        device_public: public.ok_or(FormatError::MissingField { tag: tag::DEVICE_PUBLIC })?,
        device_kem: kem.ok_or(FormatError::MissingField { tag: tag::DEVICE_KEM })?,
        note: note.ok_or(FormatError::MissingField { tag: tag::NOTE })?,
    })
}

/// Закодировать запись очереди.
///
/// # Errors
/// Отдаёт [`FormatError`], если тело не кодируется.
pub fn encode_pending(p: &Pending) -> Result<Vec<u8>, FormatError> {
    check_note(&p.note, tag::NOTE)?;
    let mut w = TlvWriter::new();
    w.put(tag::FILE_ID, &p.file_id)?;
    w.put(tag::DEVICE_FPR, &p.device_fpr)?;
    w.put(tag::DEVICE_PUBLIC, &p.device_public)?;
    w.put(tag::DEVICE_KEM, &[p.device_kem])?;
    w.put(tag::NOTE, p.note.as_bytes())?;
    w.put(tag::SEQ, &p.seq.to_le_bytes())?;
    w.put(tag::AT, &p.at.to_le_bytes())?;
    Ok(w.finish().to_vec())
}

/// Разобрать запись очереди.
///
/// # Errors
/// Отдаёт [`FormatError`] при нехватке полей или неверных длинах.
pub fn decode_pending(bytes: &[u8]) -> Result<Pending, FormatError> {
    let mut reader = TlvReader::new(bytes);
    let (mut file_id, mut fpr, mut public, mut kem, mut note) = (None, None, None, None, None);
    let (mut seq, mut at) = (None, None);
    while let Some(f) = reader.next_field()? {
        match f.tag {
            tag::FILE_ID => file_id = Some(f.array::<16>()?),
            tag::DEVICE_FPR => fpr = Some(f.array::<32>()?),
            tag::DEVICE_PUBLIC => public = Some(f.value.to_vec()),
            tag::DEVICE_KEM => kem = Some(one_byte(f.value, tag::DEVICE_KEM)?),
            tag::NOTE => {
                let text = core::str::from_utf8(f.value)
                    .map_err(|_| FormatError::NotUtf8 { tag: tag::NOTE })?;
                check_note(text, tag::NOTE)?;
                note = Some(text.to_string());
            }
            tag::SEQ => seq = Some(u64::from_le_bytes(f.array::<8>()?)),
            tag::AT => at = Some(i64::from_le_bytes(f.array::<8>()?)),
            other => crate::unknown::refuse_if_critical(other)?,
        }
    }
    Ok(Pending {
        seq: seq.ok_or(FormatError::MissingField { tag: tag::SEQ })?,
        file_id: file_id.ok_or(FormatError::MissingField { tag: tag::FILE_ID })?,
        device_fpr: fpr.ok_or(FormatError::MissingField { tag: tag::DEVICE_FPR })?,
        device_public: public.ok_or(FormatError::MissingField { tag: tag::DEVICE_PUBLIC })?,
        device_kem: kem.ok_or(FormatError::MissingField { tag: tag::DEVICE_KEM })?,
        note: note.ok_or(FormatError::MissingField { tag: tag::NOTE })?,
        at: at.ok_or(FormatError::MissingField { tag: tag::AT })?,
    })
}

/// Почему очередь не разобралась.
///
/// Свой род ошибки, а не вариант [`FormatError`]: обрыв на границе записи и
/// лишняя запись — события КОНВЕРТА очереди, а не поля TLV, и номера тега у них
/// нет. Причина названа словом, потому что оба хоста показывают её человеку.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueueError {
    /// Тело кончилось посреди записи: на длине либо раньше объявленной длины.
    Torn(&'static str),
    /// Запись выделена, но не разбирается.
    Record(FormatError),
    /// Записей больше окна [`MAX_PENDING_PER_FILE`].
    TooMany,
}

impl core::fmt::Display for QueueError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Torn(what) => f.write_str(what),
            Self::Record(e) => write!(f, "запись очереди не разбирается: {e}"),
            Self::TooMany => {
                f.write_str("сервер прислал больше запросов, чем помещается в очередь")
            }
        }
    }
}

/// Разобрать очередь: записи идут подряд, каждая со своей длиной.
///
/// Длина у каждой записи, а не одна на всё тело, потому что записи разной длины:
/// записка и публичный ключ переменные. Общего счётчика записей нет намеренно —
/// он был бы вторым источником истины о том, сколько их, и разошёлся бы с телом.
///
/// Живёт здесь, а не у вызывающего, потому что хостов у разбора два — `cc-cli` и
/// `cc-wasm`, — и вторая реализация одной раскладки разошлась бы молча. До
/// переноса она была одна и лежала в `cc_cli::decide`, куда модулю под `wasm32`
/// дороги нет.
///
/// # Errors
/// [`QueueError`], если тело оборвано, запись не разбирается или записей больше
/// окна.
pub fn split_queue(mut rest: &[u8]) -> Result<Vec<Pending>, QueueError> {
    let mut out: Vec<Pending> = Vec::new();
    while !rest.is_empty() {
        let head: [u8; 4] = rest
            .get(..4)
            .and_then(|s| <[u8; 4]>::try_from(s).ok())
            .ok_or(QueueError::Torn("очередь оборвана на длине записи"))?;
        let len = u32::from_le_bytes(head) as usize;
        let body = rest
            .get(4..)
            .and_then(|s| s.get(..len))
            .ok_or(QueueError::Torn("запись очереди короче объявленной длины"))?;
        out.push(decode_pending(body).map_err(QueueError::Record)?);
        rest = rest.get(4usize.saturating_add(len)..).unwrap_or_default();

        // Окно то же, что у сервера (он помнит больше, но отдаёт не больше
        // окна). Предел здесь не украшение: длина очереди приходит от чужой
        // стороны, и без него «покажи очередь» означало бы «выдели столько,
        // сколько скажет собеседник».
        if out.len() > MAX_PENDING_PER_FILE {
            return Err(QueueError::TooMany);
        }
    }
    Ok(out)
}

/// Закодировать решение вместе с подписью.
///
/// # Errors
/// Отдаёт [`FormatError`], если тело не кодируется.
pub fn encode_decision(d: &Decision) -> Result<Vec<u8>, FormatError> {
    let mut out = decision_body(d)?;
    let mut w = TlvWriter::new();
    w.put(tag::SIGNATURE, &d.signature)?;
    out.extend_from_slice(&w.finish());
    Ok(out)
}

/// Разобрать решение.
///
/// Подпись здесь НЕ проверяется — проверять её обязан тот, у кого есть ключ
/// автора, и делать это он обязан ДО всякого использования полей. Разбор и
/// проверка разведены намеренно: смешав их, мы получили бы функцию, чей отказ
/// не отличает «байты не те» от «подпись не сошлась».
///
/// # Errors
/// Отдаёт [`FormatError`] при нехватке полей или неверных длинах.
pub fn decode_decision(bytes: &[u8]) -> Result<Decision, FormatError> {
    let mut reader = TlvReader::new(bytes);
    let (mut seq, mut file_id, mut fpr, mut approve) = (None, None, None, None);
    let (mut enc, mut nonce, mut ct) = (None, None, None);
    let (mut author_key, mut signature) = (None, None);
    while let Some(f) = reader.next_field()? {
        match f.tag {
            tag::SEQ => seq = Some(u64::from_le_bytes(f.array::<8>()?)),
            tag::FILE_ID => file_id = Some(f.array::<16>()?),
            tag::DEVICE_FPR => fpr = Some(f.array::<32>()?),
            // СТРОГО 0 ИЛИ 1, а не «байт не ноль». Прежняя редакция читала любой
            // ненулевой байт как одобрение, и значение 5 разбиралось в `true`,
            // кодируясь обратно единицей: две разные последовательности байтов
            // означали одно и то же — ровно то, что запрещает И-7. Одобрение при
            // этом самое дорогое поле разговора: им выдаётся доля B.
            //
            // `BadFieldLength` — тот вариант, которым весь крейт сообщает
            // «значение вне области» (`standing::decode`, `order::decode`,
            // `lease::decode`); заводить ради этого новый значило бы разводить
            // одну доктрину на два кода.
            tag::APPROVE => {
                approve = Some(match one_byte(f.value, tag::APPROVE)? {
                    0 => false,
                    1 => true,
                    _ => return Err(FormatError::BadFieldLength { tag: tag::APPROVE, len: 1 }),
                });
            }
            tag::ENC => enc = Some(f.value.to_vec()),
            tag::NONCE => nonce = Some(f.array::<24>()?),
            tag::CT => ct = Some(f.value.to_vec()),
            tag::AUTHOR_KEY => author_key = Some(f.array::<32>()?),
            tag::SIGNATURE => signature = Some(f.array::<64>()?),
            // ЕДИНСТВЕННЫЙ РАЗБОРЩИК КРЕЙТА, ОСТАВШИЙСЯ СТРОГИМ (решение
            // 2026-09-21). Необязательного диапазона у решения автора нет, и
            // это не недосмотр.
            //
            // Подпись решения проверяется НЕ по сырым байтам, а по телу,
            // собранному заново из разобранной структуры ([`decision_body`],
            // зовётся в `cc_authority::Authority::decide_access` и в
            // `cc_cli::granted::verified_decision`). Пропущенный тег из такой
            // сборки выпадает — значит посторонний дописал бы его к уже
            // подписанному решению, и подпись СОШЛАСЬ БЫ. У всех остальных
            // документов крейта подпись покрывает сырые байты, и потому там
            // дописать нельзя; здесь можно, и цена этому — самое дорогое поле
            // разговора, доля B.
            //
            // Расширения необязательный диапазон здесь не даёт и в обмен: поле,
            // которое новая сборка внесёт в `decision_body`, старая всё равно
            // отвергнет по подписи. То есть выбор стоял между «ничего не
            // приобрели» и «ничего не приобрели, но подписанный документ стал
            // ковким», а И-6 держит ровно обратное — одна подпись, один
            // документ.
            other => return Err(FormatError::UnknownCriticalField { tag: other }),
        }
    }
    let approve = approve.ok_or(FormatError::MissingField { tag: tag::APPROVE })?;
    // Доля обязана быть при одобрении и обязана отсутствовать при отказе.
    // Одобрение без доли — обещание без исполнения; отказ с долей — выдача,
    // замаскированная под отказ.
    let share_b = match (approve, enc, nonce, ct) {
        (true, Some(enc), Some(nonce), Some(ct)) => Some(Blob { enc, nonce, ct }),
        (true, ..) => return Err(FormatError::MissingField { tag: tag::CT }),
        (false, None, None, None) => None,
        (false, ..) => return Err(FormatError::BadFieldLength { tag: tag::CT, len: 0 }),
    };
    Ok(Decision {
        seq: seq.ok_or(FormatError::MissingField { tag: tag::SEQ })?,
        file_id: file_id.ok_or(FormatError::MissingField { tag: tag::FILE_ID })?,
        device_fpr: fpr.ok_or(FormatError::MissingField { tag: tag::DEVICE_FPR })?,
        approve,
        share_b,
        author_key: author_key.ok_or(FormatError::MissingField { tag: tag::AUTHOR_KEY })?,
        signature: signature.ok_or(FormatError::MissingField { tag: tag::SIGNATURE })?,
    })
}

fn one_byte(value: &[u8], tag: u16) -> Result<u8, FormatError> {
    match value {
        [b] => Ok(*b),
        _ => Err(FormatError::BadFieldLength { tag, len: value.len() }),
    }
}

#[cfg(test)]
// Тестам позволено разворачивать `Option` и падать с сообщением: проверяемый код
// на этих путях не исполняется.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn ask() -> AskAccess {
        AskAccess {
            file_id: [0x11; 16],
            device_fpr: [0x22; 32],
            device_public: vec![0x33; 32],
            device_kem: 1,
            note: "Petr from accounting".to_string(),
        }
    }

    #[test]
    fn an_ask_round_trips() {
        let a = ask();
        assert_eq!(decode_ask(&encode_ask(&a).unwrap()).unwrap(), a);
    }

    /// ЗАПИСКУ ПОКАЖУТ ЧЕЛОВЕКУ, ПОЭТОМУ ОНА НЕ ВПРАВЕ ДВИГАТЬ КУРСОР.
    ///
    /// Тот же класс, что у адресов сервера и у имён файлов: текст сочиняет
    /// посторонний, а печатается он рядом со строками, которым человек верит.
    #[test]
    fn a_note_that_could_repaint_the_screen_is_refused() {
        for bad in [
            "ok\u{1b}[2K\u{1b}[Aevil",
            "\u{202e}gnp.exe",
            "carriage\rreturn",
            "nul\u{0}byte",
            // Метки направления, которых в списке из девяти не было. Каждая
            // переставляет текст при показе так же, как перечисленные девять.
            "alm\u{61c}mark",
            "lrm\u{200e}mark",
            "rlm\u{200f}mark",
            // Невидимки: две разные записки печатаются неотличимо.
            "buh\u{200b}galteria",
            "soft\u{ad}hyphen",
            "word\u{2060}joiner",
            "bom\u{feff}inside",
            // Разделители строки и абзаца: категории Zl и Zp, а не Cc.
            "line\u{2028}separator",
            "para\u{2029}separator",
            // Теговые символы — невидимая копия ASCII.
            "tag\u{e0041}smuggle",
            // Перевод строки: выводит текст из пункта перечня наружу и
            // дорисовывает в очередь просьбу, которой нет.
            "Petr\n\n  N 2\n     ustroystvo: 00",
        ] {
            let mut a = ask();
            a.note = bad.to_string();
            assert!(encode_ask(&a).is_err(), "записка принята: {bad:?}");
        }

        // Контроль: обычная фраза проходит.
        let mut a = ask();
        a.note = "Petr from accounting, phone 123".to_string();
        assert!(encode_ask(&a).is_ok());
    }

    /// Отказ называет ПОЛЕ и КОД — не чужую беду и не сам символ.
    ///
    /// Проба закрепляет то, ради чего заведён [`FormatError::BadNoteChar`]:
    /// прежняя редакция возвращала `BadAddressByte { byte: 0 }`, и человек с
    /// русской запиской читал «в адресе байт 0x00». Без этой пробы возврат к
    /// прежнему варианту прошёл бы зелёным — `is_err()` истинно у обоих.
    #[test]
    fn a_refused_note_names_the_field_and_the_code() {
        let mut a = ask();
        a.note = "moc.dab\u{202e}".to_string();
        match encode_ask(&a) {
            Err(FormatError::BadNoteChar { tag, code }) => {
                assert_eq!(tag, tag::NOTE);
                assert_eq!(code, 0x202e);
                // Сам символ в текст ошибки попасть не смеет: напечатать его
                // значило бы пропустить на экран тем самым путём, который
                // проверка и закрывает.
                let text = format!("{}", FormatError::BadNoteChar { tag, code });
                assert!(text.contains("U+202E"), "нет кода: {text}");
                assert!(!text.contains('\u{202e}'), "символ просочился: {text}");
            }
            other => panic!("ожидался BadNoteChar, получено {other:?}"),
        }
    }

    /// Не-UTF-8 в записке сообщается как не-UTF-8, а не как ошибка длины.
    #[test]
    fn a_note_that_is_not_utf8_says_so() {
        let mut a = ask();
        a.note = "okay".to_string();
        let mut bytes = encode_ask(&a).unwrap();
        let at = bytes.windows(4).position(|w| w == b"okay").expect("записка на месте");
        // `get_mut`, а не индексация: `indexing_slicing` запрещён во всём
        // workspace, и тесты не исключение. Поймал это гейт CI
        // `cargo clippy --workspace --all-targets`, который прогоняется по
        // ВСЕМ целям, — обычный `cargo test` до тестового кода литами не
        // добирается.
        *bytes.get_mut(at).expect("смещение внутри документа") = 0xff;
        match decode_ask(&bytes) {
            Err(FormatError::NotUtf8 { tag }) => assert_eq!(tag, tag::NOTE),
            other => panic!("ожидался NotUtf8, получено {other:?}"),
        }
    }

    /// Записка на своём языке — законная записка.
    ///
    /// Проба заведена по следу: первая редакция сужала набор до печатного
    /// ASCII, и НИ ОДИН тест этого не заметил, потому что все они были
    /// написаны латиницей. Нашёл живой прогон между двумя машинами.
    #[test]
    fn a_note_in_any_script_is_accepted() {
        for good in [
            "это Пётр из бухгалтерии",
            "проба с ноутбука HUAWEI",
            "会计部的彼得",
            "Pëtr, buhgalterija",
            "פטר מהנהלת חשבונות",
        ] {
            let mut a = ask();
            a.note = good.to_string();
            let bytes = encode_ask(&a).expect("законная записка отвергнута");
            assert_eq!(decode_ask(&bytes).unwrap().note, good);
        }
    }

    #[test]
    fn a_note_longer_than_allowed_is_refused() {
        let mut a = ask();
        a.note = "x".repeat(MAX_NOTE.saturating_add(1));
        assert!(encode_ask(&a).is_err());
    }

    fn decision(approve: bool) -> Decision {
        Decision {
            seq: 7,
            file_id: [0x11; 16],
            device_fpr: [0x22; 32],
            approve,
            share_b: approve.then(|| Blob {
                enc: vec![0x44; 32],
                nonce: [0x55; 24],
                ct: vec![0x66; 48],
            }),
            author_key: [0x77; 32],
            signature: [0x88; 64],
        }
    }

    #[test]
    fn a_decision_round_trips_both_ways() {
        for approve in [true, false] {
            let d = decision(approve);
            assert_eq!(decode_decision(&encode_decision(&d).unwrap()).unwrap(), d);
        }
    }

    /// ОДОБРЕНИЕ БЕЗ ДОЛИ И ОТКАЗ С ДОЛЕЙ — ОБА ОТВЕРГАЮТСЯ.
    ///
    /// Первое — обещание без исполнения: получатель увидел бы «одобрено» и не
    /// смог открыть файл. Второе опаснее: выдача, замаскированная под отказ, —
    /// автор думает, что отказал, а доля ушла.
    #[test]
    fn approval_without_a_share_and_refusal_with_one_are_both_refused() {
        let mut d = decision(true);
        d.share_b = None;
        assert!(decode_decision(&encode_decision(&d).unwrap()).is_err(), "одобрение без доли");

        let mut d = decision(false);
        d.share_b = Some(Blob { enc: vec![1; 32], nonce: [2; 24], ct: vec![3; 48] });
        assert!(decode_decision(&encode_decision(&d).unwrap()).is_err(), "отказ с долей");
    }

    /// ПРИЗНАК ОДОБРЕНИЯ — РОВНО 0 ИЛИ 1, И НИЧЕГО МЕЖДУ.
    ///
    /// До 2026-09-20 он читался как «байт не ноль», и решение с байтом 5
    /// разбиралось в одобрение, а кодировалось обратно единицей: две разные
    /// последовательности байтов означали одно и то же (И-7). Проба ловит именно
    /// возврат к такому чтению — `is_err()` здесь недостаточно, поэтому
    /// проверяется и КОД отказа.
    #[test]
    fn the_approval_flag_is_exactly_zero_or_one() {
        // Смещение байта одобрения ищется по заголовку поля: тег 8, длина 1.
        // Считать его руками нельзя — перед ним стоят поля переменной длины.
        let head = {
            let mut h = Vec::with_capacity(6);
            h.extend_from_slice(&tag::APPROVE.to_le_bytes());
            h.extend_from_slice(&1u32.to_le_bytes());
            h
        };
        let bytes = encode_decision(&decision(true)).unwrap();
        let at = bytes
            .windows(head.len())
            .position(|w| w == head.as_slice())
            .and_then(|p| p.checked_add(head.len()))
            .expect("поле одобрения на месте");

        for good in [0u8, 1] {
            let mut forged = bytes.clone();
            *forged.get_mut(at).expect("смещение внутри документа") = good;
            let parsed = decode_decision(&forged);
            // Ноль здесь — отказ с долей, и он отвергается ДРУГОЙ проверкой:
            // важно, что не проверкой области значения.
            match (good, parsed) {
                (1, Ok(d)) => assert!(d.approve, "единица прочитана не как одобрение"),
                (0, Err(FormatError::BadFieldLength { tag: tag::CT, .. })) => {}
                (_, other) => panic!("законный байт {good} дал {other:?}"),
            }
        }

        for bad in [2u8, 5, 255] {
            let mut forged = bytes.clone();
            *forged.get_mut(at).expect("смещение внутри документа") = bad;
            match decode_decision(&forged) {
                Err(FormatError::BadFieldLength { tag, len }) => {
                    assert_eq!(tag, tag::APPROVE, "отказ назвал не то поле");
                    assert_eq!(len, 1);
                }
                other => panic!("байт одобрения {bad} принят: {other:?}"),
            }
        }
    }

    /// ПОДПИСЬ ПОКРЫВАЕТ ДОЛЮ, А НЕ ТОЛЬКО СЛОВО «ОДОБРЕНО».
    ///
    /// Иначе посредник подменил бы долю, оставив одобрение, и получатель открыл
    /// бы не тот файл — или не открыл вовсе, виня автора.
    #[test]
    fn the_signed_body_changes_when_the_share_changes() {
        let a = decision(true);
        let mut b = a.clone();
        b.share_b = Some(Blob { enc: vec![0x99; 32], nonce: [0x55; 24], ct: vec![0x66; 48] });
        assert_ne!(decision_body(&a).unwrap(), decision_body(&b).unwrap());

        // И на отпечаток устройства тоже: одобрение нельзя переадресовать.
        let mut c = a.clone();
        c.device_fpr = [0x23; 32];
        assert_ne!(decision_body(&a).unwrap(), decision_body(&c).unwrap());
    }
}
