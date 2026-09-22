// Арифметика длин и смещений — это и есть границы формата, поэтому здесь она
// поднята с `warn` (уровень workspace) до `deny`. Атрибутом крейта, а не строкой
// в `Cargo.toml`: `[lints] workspace = true` не смешивается с локальными
// правилами, а отказываться от наследования всей таблицы ради одного лита
// значило бы потерять остальные.
//
// Точечные `#[allow]` допустимы там, где невозможность переполнения следует из
// типа (например, деление на `NonZeroU32`), и каждый обязан нести объяснение.
#![deny(clippy::arithmetic_side_effects)]

//! Разбор и сборка контейнера `.cc`.
//!
//! Крейт режет байты и считает смещения. В нём нет **ввода-вывода, часов и
//! генератора случайных чисел** — именно поэтому его можно проверять чистыми
//! данными и собирать под `wasm32`.
//!
//! Точная граница, потому что прежняя формулировка («ничего не знает ни о
//! криптографии…») расходилась с `Cargo.toml`: крейт зависит от `oc-crypto` и
//! `oc-policy` **по типам** — идентификаторы алгоритмов, структура политики, типы
//! ключей. Зависимость осознанная: без неё разбор возвращал бы сырые `u8` вместо
//! проверенных перечислений, и проверка «умеет ли сборка исполнить объявленный
//! алгоритм» переехала бы к вызывающему, то есть повторялась бы в каждом. Чего
//! крейт действительно не делает — так это криптографических операций: он не
//! шифрует, не подписывает и не выводит ключи.
//!
//! Всё, что он возвращает, — заимствованные срезы исходного буфера, потому что
//! подпись проверяется по сырым байтам, а не по результату повторной
//! сериализации (см. `docs/format.md`, раздел 5).
//!
//! Точка входа — [`Prologue::split`]. Она тотальна: любой буфер либо разбирается,
//! либо даёт ошибку, но никогда не паникует.
//!
//! # Что здесь НЕ живёт: протокол продукта
//!
//! Документы, ходящие между клиентом, сервером и свидетелем — активация,
//! распоряжение автора, положение файла, запрос доступа, лиз, отзывная,
//! аттестация, журнал, каталог, правило по атрибутам, управляющие операции и
//! реплика, — вынесены в `oc-protocol` решением Р-2 (`docs/plan.md`,
//! «Д-ядро-к-заморозке»). Это был ПЕРЕНОС: байты на проводе не изменились.
//!
//! Граница проведена по темпу изменения, и это единственный довод, который её
//! держит. Формат контейнера ЗАМИРАЕТ: после первого файла, ушедшего наружу,
//! каждый байт заголовка обещан навсегда, и менять его можно только новой
//! версией формата вместе с записанным решением (И-14). Протокол продукта
//! РАСТЁТ вместе с сервером — новый вид запроса появляется тогда же, когда
//! появляется механизм. Пока оба рода лежали в одном крейте, снаружи они были
//! неразличимы, и обещание «этот крейт заморожен и открыт» относилось заодно к
//! восьми с половиной тысячам строк, меняющихся каждую неделю.
//!
//! Стрелка зависимости одна: `oc-protocol` → `oc-format`. Обратной нет —
//! ни один разборщик контейнера не зовёт ни один документ протокола. Общим
//! остаётся [`FormatError`]: делить тип ошибки решение Р-2 не требовало, и
//! несколько его вариантов (`UnsupportedLeaseVersion` и соседи) сегодня
//! означают события чисто протокольные.
//!
//! Деление оценено 2026-09-20 и ОТКЛОНЕНО — числа и довод в докстроке
//! [`FormatError::BadHeaderSignature`]. Коротко: чисто протокольных вариантов
//! три (`UnsupportedLeaseVersion`, `BadNoteChar`, `NotUtf8`), и ни один из них
//! `oc-format` изнутри не возвращает, но четвёртый — `BadHeaderSignature` —
//! общий по существу, и увести его нельзя, не сменив тип ошибки у всего
//! `oc-protocol` и не задев тексты отказов и коды возврата `cc-cli`.

pub mod content;
pub mod edit;
pub mod encoding;
pub mod footer;
pub mod frame;
pub mod header;
pub mod policy_codec;
pub mod text;
pub mod tlv;
pub mod verify;

use core::fmt;
use core::num::NonZeroU32;
use core::ops::Range;

/// Магия версии 1. Ломающее изменение формата меняет её, и старый клиент
/// отказывает, не пытаясь разобрать содержимое.
pub const MAGIC: [u8; 8] = *b"CLOSECR1";

/// Длина подписи Ed25519.
pub const SIG_LEN: usize = 64;

/// Длина хранимого nonce XChaCha20-Poly1305.
pub const NONCE_LEN: u64 = 24;

/// Длина тега Poly1305.
pub const TAG_LEN: u64 = 16;

/// Верхняя граница заголовка. Проверяется до выделения памяти, поэтому
/// объявленная длина не может стать вектором исчерпания памяти.
pub const MAX_HEADER_LEN: u32 = 1 << 20;

/// Верхняя граница числа слотов ключа.
pub const MAX_KEY_SLOTS: usize = 1024;

/// Допустимый диапазон размера чанка. Нижняя граница — размер страницы, верхняя
/// выбрана так, чтобы усиление чтения оставалось терпимым (`docs/format.md` 6.2).
pub const MIN_CHUNK_SIZE: u32 = 4 * 1024;
/// Верхняя граница размера чанка.
pub const MAX_CHUNK_SIZE: u32 = 1024 * 1024;

/// Единственное место, где записано, какой размер чанка допустим.
///
/// Публичная намеренно: проверять размер обязан и тот, кто собирает заголовок, и
/// тот, кто его разбирает, и тот, кто принимает его от пользователя в командной
/// строке. Условие, записанное в трёх местах, разъезжается при первой же правке
/// границ, и разъедется оно молча — файл, принятый одной проверкой, окажется
/// отвергнут другой.
///
/// Проверка на стороне ввода — не удобство, а защита: значение попадает в
/// `SecretBuf::with_capacity`, то есть в выделение и обнуление буфера, ещё до
/// того, как заголовок будет собран. `--chunk-size 4000000000` без этой проверки
/// означал бы попытку выделить четыре гигабайта, а отказ выделения в Rust — это
/// `abort` процесса, а не ошибка, которую можно показать пользователю.
pub fn check_chunk_size(size: u32) -> Result<u32, FormatError> {
    if (MIN_CHUNK_SIZE..=MAX_CHUNK_SIZE).contains(&size) && size.is_power_of_two() {
        Ok(size)
    } else {
        Err(FormatError::BadChunkSize { got: size })
    }
}

/// Смещение поля длины заголовка.
const HEADER_LEN_OFFSET: usize = MAGIC.len();
/// Смещение самого заголовка.
const HEADER_OFFSET: usize = HEADER_LEN_OFFSET + 4;

/// Идентичность защищённого файла: 16 случайных байт.
///
/// Намеренно не UUIDv7 — тот вкладывает в себя время создания и раскрыл бы дату
/// упаковки любому, кто держит контейнер, но ещё не может его открыть.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileId(pub [u8; 16]);

impl fmt::Debug for FileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FileId(")?;
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        write!(f, ")")
    }
}

/// Ошибки структурного разбора. Все они означают «этот буфер не наш контейнер»
/// и ни одна не несёт данных из содержимого.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatError {
    /// Первые восемь байт не совпали с [`MAGIC`].
    BadMagic,
    /// Объявленная длина заголовка превышает [`MAX_HEADER_LEN`].
    HeaderTooLarge { declared: u32 },
    /// Буфер короче, чем требует объявленная структура.
    Truncated { need: u64, have: u64 },
    /// Смещения не помещаются в `usize` на этой платформе.
    OffsetOverflow,
    /// Размер чанка вне диапазона или не степень двойки.
    BadChunkSize { got: u32 },
    /// Число чанков не соответствует общей длине.
    ChunkCountMismatch { expected: u32, got: u32 },
    /// Обращение к чанку за пределами файла.
    ChunkOutOfRange { index: u32, count: u32 },
    /// Длина значения поля не соответствует его типу.
    BadFieldLength { tag: u16, len: usize },
    /// Теги полей идут не по возрастанию: дубликат или перестановка.
    FieldsOutOfOrder { previous: u16, found: u16 },
    /// Встречен неизвестный тег из критичного диапазона: файл использует
    /// семантику, которой этот клиент не знает, и открывать его нельзя.
    UnknownCriticalField { tag: u16 },
    /// Обязательное поле заголовка отсутствует.
    MissingField { tag: u16 },
    /// Ключ в поле присутствует, но состоит из нулей.
    ///
    /// Отдельно от [`FormatError::MissingField`] намеренно: «поля нет» и «поле
    /// есть, но пустое» — разные события. Второе опаснее, потому что выглядит
    /// заполненным и проходит все структурные проверки; именно так поле
    /// закреплённого ключа подписи лизинга и оказалось нулевым во всех
    /// выпущенных контейнерах.
    DegenerateKey { tag: u16 },
    /// Адрес сервера содержит байт вне печатной части US-ASCII.
    ///
    /// Отдельно от [`FormatError::BadFieldLength`] намеренно: длина здесь верна,
    /// а негодно СОДЕРЖИМОЕ. Причина запрета — не эстетика: этот адрес печатается
    /// человеку, чтобы он сравнил его с тем, куда собирается идти, и сравнение
    /// имеет смысл ровно до тех пор, пока строка не умеет двигать курсор,
    /// переворачивать порядок символов и притворяться другой буквой.
    BadAddressByte { tag: u16, byte: u8 },
    /// Записка содержит символ, который нельзя показывать человеку.
    ///
    /// Отдельно от [`FormatError::BadAddressByte`], хотя обе про содержимое:
    /// правила РАЗНЫЕ. Адрес обязан быть печатным ASCII — у него есть проводная
    /// форма, и она такова. Записка — фраза на любом языке, и запрещены в ней
    /// только управляющие символы и двунаправленные метки. Пока отказ был один
    /// на двоих, человек с русской запиской читал «в адресе байт 0x00».
    ///
    /// Хранится КОД, а не сам символ, и печатается тоже код: вывести
    /// отвергнутый символ в текст ошибки значило бы пропустить его на экран
    /// ровно тем путём, который проверка и закрывает.
    BadNoteChar { tag: u16, code: u32 },
    /// Значение поля объявлено текстом, но текстом не является.
    ///
    /// Отдельно от [`FormatError::BadFieldLength`], и это исправление того же
    /// класса, что и [`FormatError::BadNoteChar`]. Неудача `from_utf8`
    /// сообщалась как ошибка ДЛИНЫ, хотя длина была верна, а негодны байты.
    /// Правка, заводившая `BadNoteChar`, сняла одну заимствованную этикетку и
    /// оставила рядом вторую — на том же самом поле.
    NotUtf8 { tag: u16 },
    /// Файл требует более новую версию клиента: так заявил ПИСАТЕЛЬ в
    /// `min_reader_version`.
    ReaderTooOld { need: u16, have: u16 },
    /// Класс защиты, которого эта сборка не исполняет.
    ///
    /// Отдельно от версии формата: класс может быть добавлен и без смены версии, и
    /// принять незнакомый класс значило бы читать файл по правилам нулевого.
    UnsupportedClass { class: u8 },
    /// Версия самого ФОРМАТА вне того диапазона, который этот код умеет читать.
    ///
    /// Отдельно от [`FormatError::ReaderTooOld`], и это не косметика. Там номер
    /// означает версию клиента, здесь — версию формата, и раньше обе величины
    /// уходили в одну структуру: наружу приходило «файлу нужен клиент версии 999»
    /// для файла, объявившего `container_version = 999` и `min_reader_version = 1`.
    /// Номер версии формата в поле, означающем версию клиента, — ровно та подмена
    /// смыслов, которую этот репозиторий не допускает в байтах и не должен допускать
    /// в диагностике.
    ///
    /// `first` и `max` — границы ЧИТАЕМОГО диапазона, а не история формата.
    /// Имя `first` осталось с тех пор, когда нижняя граница совпадала с первой
    /// существовавшей версией; решение Р-1 (2026-09-19) их развело — версии 1–4
    /// больше не читаются, — и поле несёт
    /// `header::MIN_READABLE_CONTAINER_VERSION`, а не
    /// `header::FIRST_CONTAINER_VERSION`. Переименование поля здесь стоило бы
    /// правок в местах, не имеющих к решению отношения; неправда в докстроке
    /// стоила бы дороже.
    UnsupportedContainerVersion { version: u16, first: u16, max: u16 },
    /// Версия документа лизинга, которой эта сборка не знает.
    ///
    /// Отдельно от версии контейнера: документы независимы и меняются в разном
    /// темпе, а один код ошибки на оба заставил бы пользователя гадать, что
    /// именно новее — файл или разрешение к нему.
    UnsupportedLeaseVersion { version: u16 },
    /// Объявленная длина изменяемой области превышает
    /// [`content::MAX_CONTENT_DESC_LEN`]. Проверяется до любого выделения памяти.
    ContentDescTooLarge { declared: u32 },
    /// MAC изменяемой области не сошёлся: её правил не владелец ключа
    /// содержимого, либо она перенесена из другого файла. Деталей нет намеренно —
    /// какая именно проверка не прошла, противнику знать незачем.
    BadContentMac,
    /// Подпись заголовка не сходится.
    ///
    /// Отдельный вариант от [`FormatError::BadContentMac`], хотя оба означают
    /// «подлинность не подтверждена»: заголовок и изменяемая область заверены
    /// разными ключами и разными сторонами, и пользователю это надо сказать
    /// по-разному. «Файл подписан не тем, кем должен» и «файл правил не владелец
    /// ключа содержимого» — разные события и разные действия в ответ.
    ///
    /// # Имя ШИРЕ смысла, и это осознано
    ///
    /// `oc-protocol` возвращает этот же вариант, когда не сходится подпись
    /// СВОЕГО документа — лизинга, распоряжения, отзывной, толчка реплики,
    /// управляющей операции, — а заголовка там нет вовсе. Имя осталось от того
    /// времени, когда все эти документы жили в `oc-format` рядом с заголовком.
    ///
    /// Оценено 2026-09-20 и оставлено как есть. Завести
    /// `oc_protocol::ProtocolError::BadSignature` значило бы сменить тип ошибки
    /// у 108 публичных функций `oc-protocol` (672 упоминания `FormatError`
    /// внутри крейта) и переписать разбор отказа у каждого потребителя, который
    /// сегодня матчит именно этот вариант: `cc_cli::lease` (→ `BadSignature`),
    /// `cc_cli::binding` (→ `NotAnchored`), `cc_viewer::session` (→ стирание
    /// сессии), `cc_cli::exit`. Первые три задают ТЕКСТ отказа человеку,
    /// четвёртый — КОД возврата, и оба обещаны неизменными. Цена — правка сотен
    /// мест ради точности имени; выгода — точность имени. Полусделанное
    /// разделение хуже общего перечисления, а сделанное целиком здесь дороже
    /// неточности, названной вслух.
    BadHeaderSignature,
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadMagic => write!(f, "не контейнер Close Crate: магия не совпала"),
            Self::HeaderTooLarge { declared } => {
                write!(f, "заголовок объявлен как {declared} байт, предел {MAX_HEADER_LEN}")
            }
            Self::Truncated { need, have } => {
                write!(f, "файл обрезан: нужно {need} байт, есть {have}")
            }
            Self::OffsetOverflow => write!(f, "переполнение смещения"),
            Self::BadChunkSize { got } => {
                write!(f, "размер чанка {got} вне диапазона или не степень двойки")
            }
            Self::ChunkCountMismatch { expected, got } => {
                write!(f, "число чанков не сходится: ожидалось {expected}, объявлено {got}")
            }
            Self::ChunkOutOfRange { index, count } => {
                write!(f, "чанк {index} за пределами файла из {count} чанков")
            }
            Self::BadFieldLength { tag, len } => {
                write!(f, "поле {tag}: длина {len} не соответствует типу")
            }
            Self::FieldsOutOfOrder { previous, found } => {
                write!(f, "поля не по возрастанию: после {previous} встретилось {found}")
            }
            Self::UnknownCriticalField { tag } => {
                write!(f, "неизвестное критичное поле {tag}: нужна более новая версия клиента")
            }
            Self::MissingField { tag } => write!(f, "отсутствует обязательное поле {tag}"),
            Self::DegenerateKey { tag } => {
                write!(f, "поле {tag}: ключ состоит из нулей, то есть отсутствует по существу")
            }
            Self::BadAddressByte { tag, byte } => {
                write!(f, "поле {tag}: в адресе байт 0x{byte:02x} вне печатной части ASCII")
            }
            Self::BadNoteChar { tag, code } => {
                write!(f, "поле {tag}: символ U+{code:04X} не показывают человеку")
            }
            Self::NotUtf8 { tag } => write!(f, "поле {tag}: значение не UTF-8"),
            Self::ReaderTooOld { need, have } => {
                write!(f, "файлу нужен клиент версии {need}, эта версия {have}")
            }
            Self::UnsupportedClass { class } => {
                write!(f, "класс защиты {class} этой версией клиента не исполняется")
            }
            Self::UnsupportedLeaseVersion { version } => {
                write!(f, "лизинг версии {version}: нужен клиент новее")
            }
            Self::UnsupportedContainerVersion { version, first, max } => write!(
                f,
                "версия формата {version} вне читаемого диапазона {first}..={max}"
            ),
            Self::ContentDescTooLarge { declared } => write!(
                f,
                "изменяемая область объявлена как {declared} байт, предел {}",
                content::MAX_CONTENT_DESC_LEN
            ),
            Self::BadContentMac => write!(f, "MAC изменяемой области не сошёлся"),
            Self::BadHeaderSignature => write!(
                f,
                "подпись заголовка не сходится: файл изменён или подписан не тем ключом"
            ),
        }
    }
}

impl core::error::Error for FormatError {}

/// Разрезанный пролог контейнера: заимствует ровно те байты, которые подписаны.
///
/// Хранение среза, а не разобранной структуры, — не оптимизация, а требование
/// безопасности: подпись проверяется по исходным байтам, потому что повторная
/// сериализация разобранного заголовка порождает всё семейство ошибок
/// канонизации, известное по JWS и XML-DSig.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Prologue<'a> {
    /// Байты заголовка, ровно `declared_len` штук.
    pub header: &'a [u8],
    /// Подпись автора над транскриптом из
    /// [`crate::verify::header_signing_transcript`].
    pub signature: &'a [u8; SIG_LEN],
    /// Смещение первого байта после подписи.
    pub after_signature: u64,
    declared_len: u32,
}

impl<'a> Prologue<'a> {
    /// Структурное разрезание: магия, границы, предел длины. Ни CBOR, ни
    /// криптографии. Тотальна и дёшева, поэтому вызывается первой.
    pub fn split(buf: &'a [u8]) -> Result<Self, FormatError> {
        let have = buf.len() as u64;

        let magic = buf.get(0..HEADER_LEN_OFFSET).ok_or(FormatError::Truncated {
            need: HEADER_OFFSET as u64,
            have,
        })?;
        if magic != MAGIC {
            return Err(FormatError::BadMagic);
        }

        let len_bytes: [u8; 4] = buf
            .get(HEADER_LEN_OFFSET..HEADER_OFFSET)
            .and_then(|s| <[u8; 4]>::try_from(s).ok())
            .ok_or(FormatError::Truncated { need: HEADER_OFFSET as u64, have })?;
        let declared_len = u32::from_le_bytes(len_bytes);
        if declared_len > MAX_HEADER_LEN {
            return Err(FormatError::HeaderTooLarge { declared: declared_len });
        }

        let header_end = HEADER_OFFSET
            .checked_add(declared_len as usize)
            .ok_or(FormatError::OffsetOverflow)?;
        let sig_end = header_end.checked_add(SIG_LEN).ok_or(FormatError::OffsetOverflow)?;

        let header = buf
            .get(HEADER_OFFSET..header_end)
            .ok_or(FormatError::Truncated { need: sig_end as u64, have })?;
        let signature = buf
            .get(header_end..sig_end)
            .and_then(|s| <&[u8; SIG_LEN]>::try_from(s).ok())
            .ok_or(FormatError::Truncated { need: sig_end as u64, have })?;

        Ok(Self { header, signature, after_signature: sig_end as u64, declared_len })
    }

    /// Независимая сборка подписываемой строки — **только для теста-сверки**.
    ///
    /// Рабочая реализация одна: [`crate::verify::header_signing_transcript`].
    /// Эта собирает те же байты вручную и с зашитым литералом метки вместо
    /// `label::HEADER_SIG` — в этом весь смысл: тест
    /// `both_ways_of_building_the_signing_string_agree` сверяет их и падает,
    /// если кто-то поменяет метку или порядок полей в одном месте и забудет в
    /// другом.
    ///
    /// Закрыта `cfg(test)`. Публичной она была вторым источником истины о
    /// подписанных байтах в рабочей поверхности крейта: вызови её кто-нибудь
    /// вместо настоящей — расхождение перестало бы быть заметным, потому что обе
    /// стороны считали бы по одной и той же копии.
    #[cfg(test)]
    pub(crate) fn signing_transcript(&self, suite_id: u8, out: &mut Vec<u8>) {
        out.clear();
        out.extend_from_slice(b"CC/v1/header-sig");
        out.push(0x00);
        out.push(suite_id);
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&self.declared_len.to_le_bytes());
        out.extend_from_slice(self.header);
    }
}

/// Отображение диапазонов открытого текста в диапазоны шифротекста.
///
/// Чистая арифметика: именно её вызывает виртуальная файловая система, когда
/// приложение читает четыре килобайта из середины документа.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Layout {
    chunk_size: NonZeroU32,
    chunk_count: u32,
    total_len: u64,
    payload_offset: u64,
}

impl Layout {
    /// Проверяет согласованность и строит отображение.
    ///
    /// Пустой файл имеет ровно один чанк нулевой длины. Так у каждого файла есть
    /// хотя бы один тег AEAD и хотя бы один лист дерева, и ни то ни другое не
    /// требует особого случая.
    pub fn new(
        chunk_size: u32,
        chunk_count: u32,
        total_len: u64,
        payload_offset: u64,
    ) -> Result<Self, FormatError> {
        let chunk_size = check_chunk_size(chunk_size)?;
        let chunk_size = NonZeroU32::new(chunk_size).ok_or(FormatError::BadChunkSize { got: 0 })?;

        let expected = Self::required_chunks(total_len, chunk_size)?;
        if expected != chunk_count {
            return Err(FormatError::ChunkCountMismatch { expected, got: chunk_count });
        }

        Ok(Self { chunk_size, chunk_count, total_len, payload_offset })
    }

    // Делитель ненулевой по типу `NonZeroU32`, поэтому деление не может
    // паниковать; линтер об этом не знает.
    #[allow(clippy::arithmetic_side_effects)]
    fn required_chunks(total_len: u64, chunk_size: NonZeroU32) -> Result<u32, FormatError> {
        let size = u64::from(chunk_size.get());
        let full = total_len / size;
        let remainder = total_len % size;
        let count = if remainder == 0 { full } else { full.saturating_add(1) };
        let count = count.max(1);
        u32::try_from(count).map_err(|_| FormatError::OffsetOverflow)
    }

    /// Размер чанка в байтах открытого текста.
    pub fn chunk_size(&self) -> u32 {
        self.chunk_size.get()
    }

    /// Число чанков, всегда не меньше единицы.
    pub fn chunk_count(&self) -> u32 {
        self.chunk_count
    }

    /// Длина открытого текста целиком.
    pub fn total_len(&self) -> u64 {
        self.total_len
    }

    /// Номер чанка, содержащего заданное смещение открытого текста.
    // Делитель ненулевой по типу `NonZeroU32`.
    #[allow(clippy::arithmetic_side_effects)]
    pub fn chunk_of(&self, plaintext_offset: u64) -> Result<u32, FormatError> {
        let index = plaintext_offset / u64::from(self.chunk_size.get());
        let index = u32::try_from(index).map_err(|_| FormatError::OffsetOverflow)?;
        if index >= self.chunk_count {
            return Err(FormatError::ChunkOutOfRange { index, count: self.chunk_count });
        }
        Ok(index)
    }

    /// Диапазон чанков, покрывающих чтение. Пустое чтение даёт `None`.
    pub fn chunks_for(&self, offset: u64, len: u64) -> Result<Option<Range<u32>>, FormatError> {
        if len == 0 || offset >= self.total_len {
            return Ok(None);
        }
        let last_byte = offset
            .checked_add(len)
            .and_then(|end| end.checked_sub(1))
            .ok_or(FormatError::OffsetOverflow)?
            .min(self.total_len.saturating_sub(1));

        let first = self.chunk_of(offset)?;
        let last = self.chunk_of(last_byte)?;
        let end = last.checked_add(1).ok_or(FormatError::OffsetOverflow)?;
        Ok(Some(first..end))
    }

    /// Длина открытого текста конкретного чанка: последний чанк короче.
    pub fn plaintext_len_of(&self, index: u32) -> Result<u64, FormatError> {
        if index >= self.chunk_count {
            return Err(FormatError::ChunkOutOfRange { index, count: self.chunk_count });
        }
        let size = u64::from(self.chunk_size.get());
        let start = u64::from(index).checked_mul(size).ok_or(FormatError::OffsetOverflow)?;
        Ok(self.total_len.saturating_sub(start).min(size))
    }

    /// Диапазон байтов чанка на диске: `nonce ‖ шифротекст ‖ тег`.
    ///
    /// Все чанки, кроме последнего, полны, поэтому смещение считается умножением,
    /// а не суммированием таблицы.
    pub fn ciphertext_span(&self, index: u32) -> Result<Range<u64>, FormatError> {
        let plaintext_len = self.plaintext_len_of(index)?;
        let framed_full = u64::from(self.chunk_size.get())
            .checked_add(NONCE_LEN)
            .and_then(|v| v.checked_add(TAG_LEN))
            .ok_or(FormatError::OffsetOverflow)?;
        let start = self
            .payload_offset
            .checked_add(u64::from(index).checked_mul(framed_full).ok_or(FormatError::OffsetOverflow)?)
            .ok_or(FormatError::OffsetOverflow)?;
        let end = start
            .checked_add(NONCE_LEN)
            .and_then(|v| v.checked_add(plaintext_len))
            .and_then(|v| v.checked_add(TAG_LEN))
            .ok_or(FormatError::OffsetOverflow)?;
        Ok(start..end)
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn container(header: &[u8]) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&MAGIC);
        buf.extend_from_slice(&(header.len() as u32).to_le_bytes());
        buf.extend_from_slice(header);
        buf.extend_from_slice(&[0x5a; SIG_LEN]);
        buf
    }

    #[test]
    fn splits_a_well_formed_prologue() {
        let buf = container(b"header-bytes");
        let p = Prologue::split(&buf).unwrap();
        assert_eq!(p.header, b"header-bytes");
        assert_eq!(p.signature, &[0x5a; SIG_LEN]);
        assert_eq!(p.after_signature, buf.len() as u64);
    }

    #[test]
    fn rejects_foreign_files() {
        assert_eq!(Prologue::split(b"%PDF-1.7 and then some"), Err(FormatError::BadMagic));
    }

    #[test]
    fn rejects_declared_length_beyond_the_cap() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&MAGIC);
        buf.extend_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(
            Prologue::split(&buf),
            Err(FormatError::HeaderTooLarge { declared: u32::MAX })
        );
    }

    #[test]
    fn rejects_truncation_at_every_boundary() {
        let full = container(b"header-bytes");
        for cut in 0..full.len() {
            let err = Prologue::split(&full[..cut]).unwrap_err();
            assert!(
                matches!(err, FormatError::Truncated { .. }),
                "обрезание на {cut} байтах дало {err:?}, а должно было дать Truncated"
            );
        }
        assert!(Prologue::split(&full).is_ok());
    }

    #[test]
    fn never_panics_on_arbitrary_input() {
        // Дешёвая замена фаззеру на этапе, когда фаззер ещё не подключён:
        // разбор обязан быть тотальным на любом префиксе любого мусора.
        let mut soup = Vec::new();
        soup.extend_from_slice(&MAGIC);
        soup.extend_from_slice(&[0xff; 256]);
        for cut in 0..soup.len() {
            let _ = Prologue::split(&soup[..cut]);
        }
        for byte in 0u16..=255 {
            let _ = Prologue::split(&[byte as u8; 13]);
        }
    }

    #[test]
    fn transcript_covers_magic_length_and_header() {
        let buf = container(b"abc");
        let p = Prologue::split(&buf).unwrap();
        let mut out = Vec::new();
        p.signing_transcript(7, &mut out);

        assert!(out.starts_with(b"CC/v1/header-sig"));
        assert!(out.ends_with(b"abc"));
        assert!(out.windows(8).any(|w| w == MAGIC), "магия обязана входить в транскрипт");
        // Метка домена, нулевой байт, идентификатор набора, магия, длина, заголовок.
        assert_eq!(out.len(), 16 + 1 + 1 + 8 + 4 + 3);
    }

    #[test]
    fn transcript_binds_the_suite_id() {
        let buf = container(b"abc");
        let p = Prologue::split(&buf).unwrap();
        let (mut a, mut b) = (Vec::new(), Vec::new());
        p.signing_transcript(1, &mut a);
        p.signing_transcript(2, &mut b);
        assert_ne!(a, b, "подпись обязана различать наборы алгоритмов");
    }

    #[test]
    fn empty_file_still_has_one_chunk() {
        let layout = Layout::new(65536, 1, 0, 100).unwrap();
        assert_eq!(layout.chunk_count(), 1);
        assert_eq!(layout.plaintext_len_of(0).unwrap(), 0);
        // Пустой чанк на диске — только nonce и тег.
        assert_eq!(layout.ciphertext_span(0).unwrap(), 100..(100 + NONCE_LEN + TAG_LEN));
    }

    #[test]
    fn rejects_inconsistent_chunk_count() {
        let err = Layout::new(65536, 9, 65536 * 3, 0).unwrap_err();
        assert_eq!(err, FormatError::ChunkCountMismatch { expected: 3, got: 9 });
    }

    #[test]
    fn rejects_chunk_sizes_outside_the_contract() {
        for bad in [0, 1, 2048, 65535, MAX_CHUNK_SIZE * 2] {
            assert!(
                matches!(Layout::new(bad, 1, 0, 0), Err(FormatError::BadChunkSize { .. })),
                "размер чанка {bad} должен быть отвергнут"
            );
        }
    }

    #[test]
    fn maps_a_small_read_to_exactly_one_chunk() {
        // Ровно тот случай, ради которого выбран размер чанка: приложение читает
        // четыре килобайта из середины большого файла.
        let chunk = 65536u32;
        let total = 4u64 * 1024 * 1024 * 1024;
        let count = (total / u64::from(chunk)) as u32;
        let layout = Layout::new(chunk, count, total, 4096).unwrap();

        let range = layout.chunks_for(1_000_000, 4096).unwrap().unwrap();
        assert_eq!(range.end - range.start, 1, "чтение внутри чанка не должно задевать соседей");
        assert_eq!(range.start, 1_000_000 / u64::from(chunk) as u32);
    }

    #[test]
    fn a_read_across_a_boundary_touches_both_chunks() {
        let layout = Layout::new(4096, 4, 16384, 0).unwrap();
        let range = layout.chunks_for(4090, 12).unwrap().unwrap();
        assert_eq!(range, 0..2);
    }

    #[test]
    fn a_read_past_the_end_is_clamped() {
        let layout = Layout::new(4096, 2, 5000, 0).unwrap();
        let range = layout.chunks_for(4000, 1_000_000).unwrap().unwrap();
        assert_eq!(range, 0..2);
        assert!(layout.chunks_for(5000, 10).unwrap().is_none());
        assert!(layout.chunks_for(0, 0).unwrap().is_none());
    }

    #[test]
    fn spans_are_contiguous_and_cover_the_payload() {
        let layout = Layout::new(4096, 3, 4096 * 2 + 17, 77).unwrap();
        let mut cursor = 77;
        for i in 0..layout.chunk_count() {
            let span = layout.ciphertext_span(i).unwrap();
            assert_eq!(span.start, cursor, "чанк {i} не примыкает к предыдущему");
            let framed = NONCE_LEN + layout.plaintext_len_of(i).unwrap() + TAG_LEN;
            assert_eq!(span.end - span.start, framed);
            cursor = span.start + NONCE_LEN + u64::from(layout.chunk_size()) + TAG_LEN;
        }
        assert_eq!(layout.plaintext_len_of(2).unwrap(), 17);
    }

    #[test]
    fn refuses_to_address_chunks_that_do_not_exist() {
        let layout = Layout::new(4096, 2, 5000, 0).unwrap();
        assert!(matches!(
            layout.ciphertext_span(2),
            Err(FormatError::ChunkOutOfRange { index: 2, count: 2 })
        ));
    }
}
