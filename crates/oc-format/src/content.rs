//! Изменяемая область контейнера.
//!
//! Автора нет рядом, когда файл правят, поэтому подписать изменённое содержимое
//! он не может. Эта область заверена не подписью, а MAC на ключе, производном от
//! ключа содержимого: пересчитать её может тот, кто владеет CEK, и никто другой.
//!
//! Здесь же живут `total_len` и `chunk_count`. Это единственное место, где
//! записана длина файла, и записана она **под MAC**. Отсюда обрезание файла
//! обнаруживается сразу при открытии, а не когда чтение дойдёт до хвоста — до
//! которого виртуальная файловая система может не дойти никогда.

use crate::tlv::{TlvReader, TlvWriter, UnknownTag, unknown_tag_action};
use crate::{FormatError, Layout};
use oc_crypto::mac::{self, MAC_LEN};
use oc_crypto::{MacKey, SigAlg, Transcript, label};

/// Теги полей изменяемой области.
pub mod tag {
    pub const TOTAL_LEN: u16 = 1;
    pub const CHUNK_COUNT: u16 = 2;
    pub const TREE_ROOT: u16 = 3;
    pub const VERSION_COUNTER: u16 = 4;
    /// Смещение футера. **Главный источник этой величины** — решение, перенесённое в версию 4.
    ///
    /// Тег 16 подписанного заголовка объявляет то же самое и сожжён: футер лежит
    /// за нагрузкой, правка меняет её длину, и смещение обязано жить там, где
    /// оно может измениться без автора — рядом с `total_len` и `chunk_count`,
    /// описывающими то же «как файл выглядит сейчас».
    ///
    /// Смещение стоит под MAC, а не под подписью, поэтому держатель `CEK` его
    /// подменить может. Отсюда условие, без которого решение неверно: **футер
    /// вправе нести только самозаверяющееся содержимое** — токен службы времени,
    /// встречную подпись. Таблица тегов себя не заверяет, и класть её сюда
    /// нельзя, не пересмотрев решение. Разбор — в `docs/format.md`, раздел
    /// «ВЕРСИЯ 3 ОТКРЫТА», пункт 6.
    pub const FOOTER_OFFSET: u16 = 5;
    /// Подпись редактировавшего устройства. **Начиная с версии 4.**
    ///
    /// Диапазон критичный: клиент, не знающий про редактирование, обязан
    /// ОТКАЗАТЬСЯ открывать правленый файл, а не открыть и промолчать.
    /// Необязательный тег сделал бы правку незаметной ровно для того, кто не
    /// умеет её проверить.
    pub const EDITOR: u16 = 6;
}

/// Теги внутри записи подписи редактора (тег 6).
///
/// Вложенный TLV, а не склейка по фиксированным смещениям: величин пять, и
/// вторая система кодирования рядом с существующей — это второе место, которое
/// однажды разойдётся с первым.
pub mod editor_tag {
    pub const SIG_ALG: u16 = 1;
    pub const SESSION_HEAD: u16 = 2;
    pub const JOURNAL_HEAD: u16 = 3;
    pub const CERTIFIED_BY: u16 = 4;
    pub const SIGNATURE: u16 = 5;
}

/// Первая версия формата, знающая подпись редактора.
pub const FIRST_EDITING_VERSION: u16 = 4;

/// Длина подписи RSA-PSS над модулем RSA-2048.
pub const EDITOR_SIGNATURE_LEN: usize = oc_crypto::rsa::MODULUS_LEN;

/// Длина головы журнала: `u64le(size)` и корень в 32 байта.
pub const JOURNAL_HEAD_LEN: usize = 40;

/// Верхняя граница сертификата ключа подписи.
///
/// Изменяемая область целиком ограничена 64 КиБ, и без собственного предела
/// сертификат съел бы её всю, вытеснив поля, ради которых она существует.
pub const MAX_CERTIFIED_BY_LEN: usize = 8 * 1024;

/// Голова журнала сервера, последняя виденная подписывающим.
///
/// Носится в подписи ради сцепления в духе gossip: контейнеры ходят между
/// людьми, поэтому любые два обменивающихся клиента невольно сверяют свои
/// представления об истории. Сервер, показавший двоим разные ветви, ловится
/// первым же файлом, пересёкшим границу между ними, — а не только тем клиентом,
/// который аккуратно вёл закрепление головы.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalHead {
    /// Число записей. Нужно для доказательства непротиворечивости.
    pub size: u64,
    /// Корень над записями.
    pub root: [u8; 32],
}

/// Подпись редактировавшего устройства и всё, что она заверяет.
///
/// Пять величин, а не одна подпись, и каждая нужна:
///
/// * `sig_alg` — иначе схема подписи не выражена, а это `alg: none` из JWS;
/// * `session_head` — голова хеш-цепочки СОХРАНЕНИЙ. Подпись покрывает сеанс, а
///   не каждое сохранение: Word сохраняет по нескольку раз в минуту, а область
///   ограничена 64 КиБ;
/// * `journal_head` — см. [`JournalHead`];
/// * `certified_by` — сертификат ключа подписи. Без него ротация ключа
///   потребовала бы повторной сверки отпечатка вторым каналом со всеми;
/// * `signature` — собственно подпись.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditorSignature {
    pub sig_alg: SigAlg,
    pub session_head: [u8; 32],
    /// `None` кодируется ПУСТЫМ значением, а не отсутствием записи.
    ///
    /// Отсутствие записи означало бы, что подпись не покрывает факт «сервера
    /// редактор не видел», и устройство, никогда не отправлявшее правок, стало
    /// бы неотличимо от устройства, скрывшего свою голову.
    pub journal_head: Option<JournalHead>,
    pub certified_by: Vec<u8>,
    pub signature: Vec<u8>,
}

impl EditorSignature {
    /// Тело записи: вложенный TLV, теги строго по возрастанию.
    fn encode(&self) -> Result<Vec<u8>, FormatError> {
        if self.signature.len() != EDITOR_SIGNATURE_LEN {
            return Err(FormatError::BadFieldLength {
                tag: editor_tag::SIGNATURE,
                len: self.signature.len(),
            });
        }
        if self.certified_by.len() > MAX_CERTIFIED_BY_LEN {
            return Err(FormatError::BadFieldLength {
                tag: editor_tag::CERTIFIED_BY,
                len: self.certified_by.len(),
            });
        }

        let mut w = TlvWriter::new();
        w.put(editor_tag::SIG_ALG, &[self.sig_alg as u8])?;
        w.put(editor_tag::SESSION_HEAD, &self.session_head)?;
        // Голова пишется ВСЕГДА; «не виделась» — пустое значение.
        let head = self.journal_head.map(|h| {
            let mut bytes = [0u8; JOURNAL_HEAD_LEN];
            let (size, root) = bytes.split_at_mut(8);
            size.copy_from_slice(&h.size.to_le_bytes());
            root.copy_from_slice(&h.root);
            bytes
        });
        let head_value: &[u8] = match head.as_ref() {
            Some(bytes) => bytes.as_slice(),
            None => &[],
        };
        w.put(editor_tag::JOURNAL_HEAD, head_value)?;
        w.put(editor_tag::CERTIFIED_BY, &self.certified_by)?;
        w.put(editor_tag::SIGNATURE, &self.signature)?;
        Ok(w.finish().to_vec())
    }

    /// Разбор тела записи. Тотален: любой буфер либо даёт структуру, либо ошибку.
    fn decode(value: &[u8]) -> Result<Self, FormatError> {
        let mut reader = TlvReader::new(value);
        let mut sig_alg = None;
        let mut session_head = None;
        let mut journal_head = None;
        let mut certified_by = None;
        let mut signature = None;

        while let Some(field) = reader.next_field()? {
            match field.tag {
                editor_tag::SIG_ALG => {
                    let parsed = SigAlg::from_u8(field.u8()?)
                        .map_err(|_| FormatError::BadFieldLength { tag: field.tag, len: 1 })?;
                    // ЗДЕСЬ ГОДИТСЯ ТОЛЬКО RSA-PSS — зеркало проверки в разборе
                    // заголовка, где годится только Ed25519. `ensure_supported`
                    // отвечает «умеем ли исполнить», а место решается у места.
                    if parsed != SigAlg::RsaPssSha256 {
                        return Err(FormatError::BadFieldLength { tag: field.tag, len: 1 });
                    }
                    sig_alg = Some(parsed);
                }
                editor_tag::SESSION_HEAD => session_head = Some(field.array::<32>()?),
                editor_tag::JOURNAL_HEAD => {
                    journal_head = Some(match field.value.len() {
                        0 => None,
                        JOURNAL_HEAD_LEN => {
                            let bytes = field.array::<JOURNAL_HEAD_LEN>()?;
                            let (size, root) = bytes.split_at(8);
                            let size = <[u8; 8]>::try_from(size).map_err(|_| {
                                FormatError::BadFieldLength { tag: field.tag, len: bytes.len() }
                            })?;
                            let root = <[u8; 32]>::try_from(root).map_err(|_| {
                                FormatError::BadFieldLength { tag: field.tag, len: bytes.len() }
                            })?;
                            Some(JournalHead { size: u64::from_le_bytes(size), root })
                        }
                        other => {
                            return Err(FormatError::BadFieldLength { tag: field.tag, len: other });
                        }
                    });
                }
                editor_tag::CERTIFIED_BY => {
                    if field.value.len() > MAX_CERTIFIED_BY_LEN {
                        return Err(FormatError::BadFieldLength {
                            tag: field.tag,
                            len: field.value.len(),
                        });
                    }
                    certified_by = Some(field.value.to_vec());
                }
                editor_tag::SIGNATURE => {
                    if field.value.len() != EDITOR_SIGNATURE_LEN {
                        return Err(FormatError::BadFieldLength {
                            tag: field.tag,
                            len: field.value.len(),
                        });
                    }
                    signature = Some(field.value.to_vec());
                }
                // Все пять тегов критичны: необязательный `sig_alg` позволил бы
                // принять подпись, не зная её схемы.
                other => match unknown_tag_action(other) {
                    UnknownTag::Refuse => {
                        return Err(FormatError::UnknownCriticalField { tag: other });
                    }
                    UnknownTag::Ignore => {}
                },
            }
        }

        Ok(Self {
            sig_alg: sig_alg.ok_or(FormatError::MissingField { tag: editor_tag::SIG_ALG })?,
            session_head: session_head
                .ok_or(FormatError::MissingField { tag: editor_tag::SESSION_HEAD })?,
            journal_head: journal_head
                .ok_or(FormatError::MissingField { tag: editor_tag::JOURNAL_HEAD })?,
            certified_by: certified_by
                .ok_or(FormatError::MissingField { tag: editor_tag::CERTIFIED_BY })?,
            signature: signature.ok_or(FormatError::MissingField { tag: editor_tag::SIGNATURE })?,
        })
    }
}

/// Верхняя граница изменяемой области.
pub const MAX_CONTENT_DESC_LEN: u32 = 64 * 1024;

/// Длина префикса `ContentDescLen`.
const LEN_PREFIX: usize = 4;

/// Описание содержимого: то, что меняется при правке файла.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContentDesc {
    /// Длина открытого текста целиком.
    pub total_len: u64,
    /// Число чанков. Всегда не меньше единицы: пустой файл имеет один чанк
    /// нулевой длины, поэтому у любого файла есть хотя бы один тег AEAD и хотя бы
    /// один лист дерева.
    pub chunk_count: u32,
    /// Текущий корень дерева целостности.
    pub tree_root: [u8; 32],
    /// Растёт при каждой правке. Не даёт подсунуть более старую, но корректно
    /// заверенную версию содержимого.
    pub version_counter: u64,
    /// Смещение футера, если он есть. Зарезервировано под таблицу тегов, токен
    /// RFC 3161 и встречную подпись сервера.
    pub footer_offset: Option<u64>,
    /// Подпись редактировавшего устройства. Есть только у правленого файла и
    /// только начиная с версии 4.
    pub editor: Option<EditorSignature>,
}

impl ContentDesc {
    /// Закодировать и заверить MAC.
    ///
    /// Возвращает `ContentDescLen(u32le) ‖ тело ‖ mac(32)`.
    /// `version` — версия контейнера, а не украшение сигнатуры: раскладка этой
    /// области зависит от неё, и писатель не должен уметь произвести область,
    /// которую наш же читатель отвергнет как «тег из будущего».
    pub fn encode(
        &self,
        key: &MacKey,
        file_id: &[u8; 16],
        version: u16,
    ) -> Result<Vec<u8>, FormatError> {
        // Ноль чанков не бывает даже у пустого файла: у него один чанк нулевой
        // длины. Отказ именно на записи, а не только на чтении, — чтобы наш код
        // физически не мог произвести область, которую наш же читатель отвергнет.
        if self.chunk_count == 0 {
            return Err(FormatError::ChunkCountMismatch { expected: 1, got: 0 });
        }

        let body = self.encode_body(version)?;
        let body_len = u32::try_from(body.len()).map_err(|_| FormatError::OffsetOverflow)?;
        // Недостижимо при нынешнем наборе полей — тело меньше сотни байт. Проверка
        // стоит здесь ради симметрии с читателем: писатель не должен уметь выдать
        // область, которую читатель обязан отвергнуть по пределу длины.
        if body_len > MAX_CONTENT_DESC_LEN {
            return Err(FormatError::ContentDescTooLarge { declared: body_len });
        }

        // Отказ здесь недостижим: длина ключа задана типом `MacKey`. Но паника в
        // этом крейте запрещена, поэтому «недостижимо» выражается ветвью, а не
        // комментарием.
        let tag = mac::compute(key, &Self::mac_transcript(file_id, &body))
            .map_err(|_| FormatError::BadContentMac)?;

        let mut out = Vec::with_capacity(
            LEN_PREFIX.saturating_add(body.len()).saturating_add(MAC_LEN),
        );
        out.extend_from_slice(&body_len.to_le_bytes());
        out.extend_from_slice(&body);
        out.extend_from_slice(&tag);
        Ok(out)
    }

    /// Разобрать и проверить MAC.
    ///
    /// Возвращает описание и число прочитанных байтов. Структура **не** отдаётся
    /// вызывающему до проверки MAC: иначе `total_len` из непроверенной области
    /// определял бы, сколько памяти мы выделим.
    pub fn decode_verified(
        bytes: &[u8],
        key: &MacKey,
        file_id: &[u8; 16],
        version: u16,
    ) -> Result<(Self, usize), FormatError> {
        Self::decode_verified_with_body(bytes, key, file_id, version).map(|(desc, _, read)| (desc, read))
    }

    /// То же, что [`Self::decode_verified`], и вдобавок ЗАВЕРЕННЫЕ байты тела.
    ///
    /// Нужны подписи редактора (`crate::edit`): она ставится над сырыми байтами
    /// тела, а не над повторной кодировкой разобранного, — по той же причине,
    /// что и MAC.
    pub fn decode_verified_with_body<'b>(
        bytes: &'b [u8],
        key: &MacKey,
        file_id: &[u8; 16],
        version: u16,
    ) -> Result<(Self, &'b [u8], usize), FormatError> {
        let have = bytes.len() as u64;

        let declared = bytes
            .get(0..LEN_PREFIX)
            .and_then(|s| <[u8; LEN_PREFIX]>::try_from(s).ok())
            .map(u32::from_le_bytes)
            .ok_or(FormatError::Truncated { need: LEN_PREFIX as u64, have })?;

        // Предел проверяется до того, как объявленная длина участвует хоть в одном
        // вычислении смещения и хоть в одном выделении памяти. Иначе четыре байта
        // от противника управляли бы тем, сколько мы попробуем выделить и
        // прочитать, — это исчерпание памяти без единого байта полезных данных.
        if declared > MAX_CONTENT_DESC_LEN {
            return Err(FormatError::ContentDescTooLarge { declared });
        }

        let declared = usize::try_from(declared).map_err(|_| FormatError::OffsetOverflow)?;
        let body_end = LEN_PREFIX.checked_add(declared).ok_or(FormatError::OffsetOverflow)?;
        let read = body_end.checked_add(MAC_LEN).ok_or(FormatError::OffsetOverflow)?;

        let body = bytes
            .get(LEN_PREFIX..body_end)
            .ok_or(FormatError::Truncated { need: read as u64, have })?;
        let tag = bytes
            .get(body_end..read)
            .and_then(|s| <[u8; MAC_LEN]>::try_from(s).ok())
            .ok_or(FormatError::Truncated { need: read as u64, have })?;

        // Порядок обязателен: границы → MAC → разбор тела.
        //
        // MAC идёт ДО разбора. Иначе различимые коды ошибок (нет обязательного
        // поля, неверная длина, неизвестный тег) сообщались бы для незаверенных
        // байтов. Практическое следствие важнее теоретического: повреждение
        // изменяемой области выглядело бы для пользователя как обрезание файла, а
        // не как то, чем оно является, — подделка.
        //
        // Сравнение в постоянном времени: иначе по времени ответа тег подбирается
        // побайтово, за 32×256 попыток вместо 2^256.
        mac::verify(key, &Self::mac_transcript(file_id, body), &tag)
            .map_err(|_| FormatError::BadContentMac)?;

        let desc = Self::decode_body(body, version)?;

        Ok((desc, body, read))
    }

    /// Байты тела — те, что лягут под MAC. Писателю правки: транскрипт подписи
    /// редактора считается по ним до того, как подпись известна.
    pub fn body_bytes(&self, version: u16) -> Result<Vec<u8>, FormatError> {
        self.encode_body(version)
    }

    /// Согласовано ли описание с размером чанка из заголовка.
    ///
    /// Размер чанка подписан автором и живёт в заголовке, а число чанков — здесь,
    /// под MAC владельца CEK. Две области заверены разными ключами, поэтому свести
    /// их может только уровень выше, который держит обе; отсюда отдельная функция,
    /// а не проверка внутри [`ContentDesc::decode_verified`].
    pub fn check_against_chunk_size(&self, chunk_size: u32) -> Result<(), FormatError> {
        // Считает [`Layout`], а не собственная арифметика: формула числа чанков
        // обязана быть в одном месте. Две копии разошлись бы при первой же правке,
        // и файл, принятый проверкой, оказался бы прочитан по другим границам.
        // `payload_offset` на проверку не влияет, поэтому здесь ноль.
        Layout::new(chunk_size, self.chunk_count, self.total_len, 0).map(|_| ())
    }

    /// Тело без рамки: TLV, теги строго по возрастанию.
    fn encode_body(&self, version: u16) -> Result<Vec<u8>, FormatError> {
        // Подпись редактора в версии младше четвёртой невыразима, и попытка её
        // записать — ошибка ПИСАТЕЛЯ, а не файла. Отказ здесь стоит по тому же
        // доводу, что и проверка `chunk_count == 0` выше: наш код не должен
        // уметь произвести область, которую наш же читатель обязан отвергнуть.
        if self.editor.is_some() && version < FIRST_EDITING_VERSION {
            return Err(FormatError::UnknownCriticalField { tag: tag::EDITOR });
        }

        let mut w = TlvWriter::new();
        w.put(tag::TOTAL_LEN, &self.total_len.to_le_bytes())?;
        w.put(tag::CHUNK_COUNT, &self.chunk_count.to_le_bytes())?;
        w.put(tag::TREE_ROOT, &self.tree_root)?;
        w.put(tag::VERSION_COUNTER, &self.version_counter.to_le_bytes())?;
        let footer = self.footer_offset.map(u64::to_le_bytes);
        w.put_opt(tag::FOOTER_OFFSET, footer.as_ref().map(|b| b.as_slice()))?;
        if let Some(editor) = &self.editor {
            w.put(tag::EDITOR, &editor.encode()?)?;
        }
        Ok(w.finish().to_vec())
    }

    /// Разбор тела. Тотален: любой буфер либо даёт структуру, либо ошибку.
    fn decode_body(body: &[u8], version: u16) -> Result<Self, FormatError> {
        let mut reader = TlvReader::new(body);
        let mut total_len = None;
        let mut chunk_count = None;
        let mut tree_root = None;
        let mut version_counter = None;
        let mut footer_offset = None;
        let mut editor = None;

        // Дубликаты и перестановка невозможны: читатель требует строгого
        // возрастания тегов. Поэтому здесь не нужна проверка «поле уже встречалось».
        while let Some(field) = reader.next_field()? {
            match field.tag {
                tag::TOTAL_LEN => total_len = Some(field.u64()?),
                tag::CHUNK_COUNT => chunk_count = Some(field.u32()?),
                tag::TREE_ROOT => tree_root = Some(field.array::<32>()?),
                tag::VERSION_COUNTER => version_counter = Some(field.u64()?),
                tag::FOOTER_OFFSET => footer_offset = Some(field.u64()?),
                // ТЕГ 6 ЗНАЮТ ВЕРСИИ С ЧЕТВЁРТОЙ (`FIRST_EDITING_VERSION`; здесь
                // стояло «только версия 3» — решение нарезали в четвёртую, а
                // комментарий остался). Для младших он остаётся неизвестным
                // критичным тегом — то есть отказом, — и это не придирка: версия
                // есть набор байтов, которые она умеет прочитать.
                tag::EDITOR if version >= FIRST_EDITING_VERSION => {
                    editor = Some(EditorSignature::decode(field.value)?);
                }
                // Неизвестный критичный тег означает семантику, которой этот клиент
                // не знает; необязательный пропускается, иначе любое поле следующей
                // версии стало бы днём отказа для всех выпущенных клиентов.
                other => match unknown_tag_action(other) {
                    UnknownTag::Refuse => {
                        return Err(FormatError::UnknownCriticalField { tag: other });
                    }
                    UnknownTag::Ignore => {}
                },
            }
        }

        // Отсутствующее поле — ошибка, а не значение по умолчанию: нули вместо
        // длины и корня дерева означали бы «пустой файл с известным корнем».
        let total_len = total_len.ok_or(FormatError::MissingField { tag: tag::TOTAL_LEN })?;
        let chunk_count =
            chunk_count.ok_or(FormatError::MissingField { tag: tag::CHUNK_COUNT })?;
        let tree_root = tree_root.ok_or(FormatError::MissingField { tag: tag::TREE_ROOT })?;
        let version_counter =
            version_counter.ok_or(FormatError::MissingField { tag: tag::VERSION_COUNTER })?;

        // Ноль чанков не описывает ни один файл: у пустого их ровно один. Приняв
        // ноль, мы получили бы описание, под которое не подходит никакая полезная
        // нагрузка, и обрезание до нуля чанков выглядело бы корректным файлом.
        if chunk_count == 0 {
            return Err(FormatError::ChunkCountMismatch { expected: 1, got: 0 });
        }

        Ok(Self { total_len, chunk_count, tree_root, version_counter, footer_offset, editor })
    }

    /// Байты под MAC.
    ///
    /// `file_id` обязателен и идёт первым: без него описание, вырезанное из одного
    /// контейнера, принималось бы в другом, и подмена длины с корнем дерева
    /// сводилась бы к копированию сотни байт между файлами.
    ///
    /// Дальше идут **сырые байты тела**, а не разобранные значения. Это то же
    /// решение, что и в подписи заголовка, и по той же причине: пересчёт по
    /// повторной кодировке разобранной структуры — источник всего семейства
    /// ошибок канонизации, известного по JWS и XML-DSig.
    ///
    /// Совместимости версий это не мешает, вопреки первому впечатлению. MAC по
    /// сырым байтам сходится у любых версий **всегда**: читатель держит ровно те
    /// байты, которые заверил писатель, и никакой пересборки между ними нет.
    /// Заодно отпадает нужда связывать длину тела отдельно — она и так внутри.
    ///
    /// Главное следствие практическое: MAC становится проверяемым **до** разбора
    /// тела. Иначе разные коды ошибок (нет обязательного поля, неверная длина,
    /// неизвестный тег) сообщались бы для незаверенных байтов, и повреждение
    /// изменяемой области выглядело бы как обрезание файла, а не как подделка.
    fn mac_transcript(file_id: &[u8; 16], body: &[u8]) -> Transcript {
        let mut t = Transcript::new(label::CONTENT_MAC);
        // `fixed` для `file_id` — его длина задана типом; `field` для тела —
        // длина переменная, и без префикса кодирование стало бы неоднозначным.
        t.fixed(file_id).field(body);
        t
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    const FILE_ID: [u8; 16] = [0x11; 16];
    const OTHER_FILE_ID: [u8; 16] = [0x22; 16];

    fn key(seed: u8) -> MacKey {
        MacKey::from_bytes([seed; 32])
    }

    /// Файл в 5 МБ при чанке 64 КиБ: 77 чанков, последний неполный.
    fn sample() -> ContentDesc {
        ContentDesc {
            total_len: 5_000_000,
            chunk_count: 77,
            tree_root: [0xab; 32],
            version_counter: 3,
            footer_offset: None,
            editor: None,
        }
    }

    /// Собрать область из произвольного тела с корректным MAC — так строится ввод,
    /// который наш писатель произвести не может, но противник с CEK мог бы.
    /// MAC проверяется РАНЬШЕ разбора тела — сторож на порядок двух строк.
    ///
    /// До этого теста порядок держался на комментарии и внимательности:
    /// перестановка `mac::verify` и `decode_body` не роняла ни одной проверки.
    /// Тесты на коды разбора подавали правильный MAC, тесты на неверный MAC —
    /// корректное тело, и случай, где встречаются оба, не проверял никто.
    ///
    /// Цена регрессии — не теоретическая. Различимые коды разбора для
    /// НЕЗАВЕРЕННЫХ байтов дают противнику оракул: подделка изменяемой области
    /// отвечала бы «нет обязательного поля» или «незнакомый тег» вместо «MAC не
    /// сошёлся», то есть выглядела бы как обрезание файла, а не как подделка
    /// (И-5).
    ///
    /// Тело здесь заведомо неразбираемое, ключ заведомо чужой. Правильный ответ
    /// ровно один — `BadContentMac`; любой код разбора означает, что тело успели
    /// прочитать до проверки подлинности.
    #[test]
    fn the_mac_is_checked_before_the_body_is_parsed() {
        let file_id = [0x11u8; 16];

        // Два разных способа быть неразбираемым, потому что ветки разбора разные:
        // нехватка обязательного поля и незнакомый критичный тег.
        let empty_body = TlvWriter::new().finish().to_vec();

        let mut with_unknown_critical = TlvWriter::new();
        with_unknown_critical.put(crate::tlv::CRIT_TAG_MAX, &[0xab; 4]).unwrap();
        let unknown_body = with_unknown_critical.finish().to_vec();

        for (what, body) in [("пустое тело", empty_body), ("чужой критичный тег", unknown_body)] {
            // Убеждаемся, что тело действительно неразбираемо: иначе тест
            // проверял бы не то, что заявляет.
            assert!(
                ContentDesc::decode_body(&body, crate::header::CONTAINER_VERSION).is_err(),
                "{what}: предпосылка теста неверна, тело разбирается"
            );

            let framed = frame_with_mac(&body, &key(2), &file_id);
            let outcome = ContentDesc::decode_verified(&framed, &key(1), &file_id, crate::header::CONTAINER_VERSION);

            assert!(
                matches!(outcome, Err(FormatError::BadContentMac)),
                "{what}: разбор произошёл до проверки MAC, ответ {outcome:?} — \
                 подделка выглядит как повреждение, и это оракул разбора"
            );
        }
    }

    fn frame_with_mac(body: &[u8], key: &MacKey, file_id: &[u8; 16]) -> Vec<u8> {
        let body_len = u32::try_from(body.len()).unwrap();
        let tag = mac::compute(key, &ContentDesc::mac_transcript(file_id, body)).unwrap();
        let mut out = body_len.to_le_bytes().to_vec();
        out.extend_from_slice(body);
        out.extend_from_slice(&tag);
        out
    }

    #[test]
    fn a_description_round_trips_through_encode_and_decode() {
        for desc in [sample(), ContentDesc { footer_offset: Some(4096), ..sample() }] {
            let bytes = desc.encode(&key(1), &FILE_ID, crate::header::CONTAINER_VERSION).unwrap();
            let (back, read) = ContentDesc::decode_verified(&bytes, &key(1), &FILE_ID, crate::header::CONTAINER_VERSION).unwrap();
            assert_eq!(back, desc);
            assert_eq!(read, bytes.len());
        }
    }

    #[test]
    fn the_payload_that_follows_is_not_part_of_the_description() {
        // За областью сразу идёт полезная нагрузка, поэтому разбор обязан читать
        // ровно объявленное и сообщать, где кончился, а не глотать хвост файла.
        let desc = sample();
        let bytes = desc.encode(&key(1), &FILE_ID, crate::header::CONTAINER_VERSION).unwrap();
        let end = bytes.len();
        let mut with_payload = bytes;
        with_payload.extend_from_slice(&[0xcd; 512]);

        let (back, read) =
            ContentDesc::decode_verified(&with_payload, &key(1), &FILE_ID, crate::header::CONTAINER_VERSION).unwrap();
        assert_eq!(back, desc);
        assert_eq!(read, end);
    }

    #[test]
    fn a_description_never_verifies_under_a_foreign_mac_key() {
        let bytes = sample().encode(&key(1), &FILE_ID, crate::header::CONTAINER_VERSION).unwrap();
        assert_eq!(
            ContentDesc::decode_verified(&bytes, &key(2), &FILE_ID, crate::header::CONTAINER_VERSION),
            Err(FormatError::BadContentMac)
        );
    }

    #[test]
    fn a_description_does_not_carry_over_to_another_file() {
        // Ключ MAC выводится с участием file_id, поэтому в рабочей схеме ключи
        // разных файлов и так различны. Привязка в транскрипте — вторая линия:
        // она сохраняется, даже если ключ где-то переиспользуют, а без неё
        // описание длины и корня дерева переносилось бы между контейнерами.
        let bytes = sample().encode(&key(1), &FILE_ID, crate::header::CONTAINER_VERSION).unwrap();
        assert_eq!(
            ContentDesc::decode_verified(&bytes, &key(1), &OTHER_FILE_ID, crate::header::CONTAINER_VERSION),
            Err(FormatError::BadContentMac)
        );
    }

    #[test]
    fn corrupting_any_byte_of_the_body_or_the_mac_is_refused() {
        let bytes = sample().encode(&key(1), &FILE_ID, crate::header::CONTAINER_VERSION).unwrap();
        for i in 0..bytes.len() {
            for bit in [0x01u8, 0x40, 0x80] {
                let mut broken = bytes.clone();
                broken[i] ^= bit;
                assert!(
                    ContentDesc::decode_verified(&broken, &key(1), &FILE_ID, crate::header::CONTAINER_VERSION).is_err(),
                    "порча байта {i} битом {bit:#04x} прошла проверку"
                );
            }
        }
    }

    #[test]
    fn every_field_is_covered_by_the_mac() {
        // Поле, не вошедшее в транскрипт, правится без пересчёта MAC. Для
        // version_counter это откат на предыдущую версию содержимого, для
        // total_len — незамеченное обрезание файла.
        let base = sample();
        let variants = [
            base.clone(),
            ContentDesc { total_len: base.total_len + 1, ..base.clone() },
            ContentDesc { chunk_count: base.chunk_count + 1, ..base.clone() },
            ContentDesc { tree_root: [0xac; 32], ..base.clone() },
            ContentDesc { version_counter: base.version_counter + 1, ..base.clone() },
            // Отдельно: «футера нет» обязано отличаться от «футер по смещению 0».
            ContentDesc { footer_offset: Some(0), ..base.clone() },
        ];

        let mut seen = BTreeSet::new();
        for variant in &variants {
            let tag = mac::compute(&key(1), &ContentDesc::mac_transcript(&FILE_ID, &variant.encode_body(crate::header::CONTAINER_VERSION).unwrap())).unwrap();
            assert!(seen.insert(tag), "поле не входит в MAC: {variant:?}");
        }
    }

    #[test]
    fn truncation_at_every_boundary_is_an_error_not_a_panic() {
        let bytes = sample().encode(&key(1), &FILE_ID, crate::header::CONTAINER_VERSION).unwrap();
        for cut in 0..bytes.len() {
            assert!(
                ContentDesc::decode_verified(&bytes[..cut], &key(1), &FILE_ID, crate::header::CONTAINER_VERSION).is_err(),
                "обрезание до {cut} байт прошло как корректная область"
            );
        }
        assert!(ContentDesc::decode_verified(&bytes, &key(1), &FILE_ID, crate::header::CONTAINER_VERSION).is_ok());
    }

    #[test]
    fn a_declared_length_beyond_the_cap_is_refused_before_the_buffer_is_touched() {
        // Буфер из четырёх байт заявляет гигабайты. Отказ обязан прийти по пределу
        // длины, а не по нехватке данных: значит, объявленное число не успело
        // повлиять ни на выделение памяти, ни на чтение.
        for declared in [MAX_CONTENT_DESC_LEN + 1, u32::MAX / 2, u32::MAX] {
            let buf = declared.to_le_bytes();
            assert_eq!(
                ContentDesc::decode_verified(&buf, &key(1), &FILE_ID, crate::header::CONTAINER_VERSION),
                Err(FormatError::ContentDescTooLarge { declared })
            );
        }

        // А длина внутри предела даёт честное «обрезано» — порядок проверок именно
        // такой, а не наоборот.
        let buf = MAX_CONTENT_DESC_LEN.to_le_bytes();
        assert!(matches!(
            ContentDesc::decode_verified(&buf, &key(1), &FILE_ID, crate::header::CONTAINER_VERSION),
            Err(FormatError::Truncated { .. })
        ));
    }

    #[test]
    fn a_chunk_count_of_zero_is_impossible_to_write_and_to_read() {
        let desc = ContentDesc { total_len: 0, chunk_count: 0, ..sample() };
        assert_eq!(
            desc.encode(&key(1), &FILE_ID, crate::header::CONTAINER_VERSION),
            Err(FormatError::ChunkCountMismatch { expected: 1, got: 0 })
        );

        // И на чтении тоже — область могла быть собрана не нашим кодом, но с
        // корректным MAC: владелец CEK не должен уметь объявить файл без чанков.
        let bytes = frame_with_mac(&desc.encode_body(crate::header::CONTAINER_VERSION).unwrap(), &key(1), &FILE_ID);
        assert_eq!(
            ContentDesc::decode_verified(&bytes, &key(1), &FILE_ID, crate::header::CONTAINER_VERSION),
            Err(FormatError::ChunkCountMismatch { expected: 1, got: 0 })
        );
    }

    #[test]
    fn a_missing_required_field_is_refused_rather_than_defaulted() {
        // Нули вместо длины и корня означали бы «пустой файл с известным корнем»,
        // то есть отсутствие поля стало бы способом подменить содержимое.
        let desc = sample();
        for skipped in
            [tag::TOTAL_LEN, tag::CHUNK_COUNT, tag::TREE_ROOT, tag::VERSION_COUNTER]
        {
            let mut w = TlvWriter::new();
            if skipped != tag::TOTAL_LEN {
                w.put(tag::TOTAL_LEN, &desc.total_len.to_le_bytes()).unwrap();
            }
            if skipped != tag::CHUNK_COUNT {
                w.put(tag::CHUNK_COUNT, &desc.chunk_count.to_le_bytes()).unwrap();
            }
            if skipped != tag::TREE_ROOT {
                w.put(tag::TREE_ROOT, &desc.tree_root).unwrap();
            }
            if skipped != tag::VERSION_COUNTER {
                w.put(tag::VERSION_COUNTER, &desc.version_counter.to_le_bytes()).unwrap();
            }
            let bytes = frame_with_mac(&w.finish(), &key(1), &FILE_ID);
            assert_eq!(
                ContentDesc::decode_verified(&bytes, &key(1), &FILE_ID, crate::header::CONTAINER_VERSION),
                Err(FormatError::MissingField { tag: skipped })
            );
        }
    }

    #[test]
    fn an_unknown_optional_tag_is_ignored_and_an_unknown_critical_tag_is_refused() {
        let desc = sample();

        // Необязательный тег из будущей версии: читатель обязан пройти мимо и всё
        // равно сойтись по MAC, иначе поле версии 2 стало бы днём отказа для
        // выпущенных клиентов. Сойтись он может именно потому, что в транскрипт
        // входит длина тела, а не его байты.
        let mut body = desc.encode_body(crate::header::CONTAINER_VERSION).unwrap();
        let mut extra = TlvWriter::new();
        extra.put(0x8001, b"field from a future version").unwrap();
        body.extend_from_slice(&extra.finish());
        let bytes = frame_with_mac(&body, &key(1), &FILE_ID);
        let (back, read) = ContentDesc::decode_verified(&bytes, &key(1), &FILE_ID, crate::header::CONTAINER_VERSION).unwrap();
        assert_eq!(back, desc);
        assert_eq!(read, bytes.len());

        // Критичный неизвестный тег — отказ: файл использует семантику, которой
        // этот клиент не знает, и молча её проигнорировать нельзя.
        let mut body = desc.encode_body(crate::header::CONTAINER_VERSION).unwrap();
        let mut extra = TlvWriter::new();
        extra.put(0x7FFF, b"semantics we do not know").unwrap();
        body.extend_from_slice(&extra.finish());
        let bytes = frame_with_mac(&body, &key(1), &FILE_ID);
        assert_eq!(
            ContentDesc::decode_verified(&bytes, &key(1), &FILE_ID, crate::header::CONTAINER_VERSION),
            Err(FormatError::UnknownCriticalField { tag: 0x7FFF })
        );
    }

    #[test]
    fn a_field_of_the_wrong_length_is_refused_rather_than_padded() {
        // Короткое значение не дополняется нулями, длинное не обрезается: иначе
        // противник управляет тем, какие байты станут длиной файла.
        let mut w = TlvWriter::new();
        w.put(tag::TOTAL_LEN, &[0u8; 4]).unwrap();
        let bytes = frame_with_mac(&w.finish(), &key(1), &FILE_ID);
        assert_eq!(
            ContentDesc::decode_verified(&bytes, &key(1), &FILE_ID, crate::header::CONTAINER_VERSION),
            Err(FormatError::BadFieldLength { tag: tag::TOTAL_LEN, len: 4 })
        );
    }

    #[test]
    fn an_inconsistent_total_len_and_chunk_count_never_pass_the_chunk_size_check() {
        let desc = sample();
        assert_eq!(desc.check_against_chunk_size(65536), Ok(()));

        // Тот же файл при другом размере чанка описан неверно.
        assert!(matches!(
            desc.check_against_chunk_size(4096),
            Err(FormatError::ChunkCountMismatch { .. })
        ));

        // Подделанная длина при том же числе чанков — ровно то обрезание, ради
        // обнаружения которого длина вообще лежит под MAC.
        let lying = ContentDesc { total_len: desc.total_len + 65536, ..desc.clone() };
        assert_eq!(
            lying.check_against_chunk_size(65536),
            Err(FormatError::ChunkCountMismatch { expected: 78, got: 77 })
        );

        // Размер чанка вне контракта — отдельная ошибка, а не «сошлось».
        assert!(matches!(
            desc.check_against_chunk_size(1000),
            Err(FormatError::BadChunkSize { got: 1000 })
        ));

        // Пустой файл: ровно один чанк нулевой длины.
        let empty = ContentDesc { total_len: 0, chunk_count: 1, ..sample() };
        assert_eq!(empty.check_against_chunk_size(4096), Ok(()));
    }

    #[test]
    fn never_panics_on_arbitrary_input() {
        // Дешёвая замена фаззеру: разбор обязан быть тотальным на любом мусоре и на
        // любом префиксе корректной области.
        let valid = sample().encode(&key(1), &FILE_ID, crate::header::CONTAINER_VERSION).unwrap();
        let mut soup = valid.clone();
        soup.extend_from_slice(&[0xff; 64]);

        for cut in 0..soup.len() {
            let _ = ContentDesc::decode_verified(&soup[..cut], &key(1), &FILE_ID, crate::header::CONTAINER_VERSION);
        }
        for byte in 0u16..=255 {
            let noise = [byte as u8; 71];
            let _ = ContentDesc::decode_verified(&noise, &key(1), &FILE_ID, crate::header::CONTAINER_VERSION);
        }
        // Тело, целиком состоящее из объявленных длин: классический вход, на
        // котором наивный разборщик зацикливается или выделяет память по чужому
        // числу.
        for len in 0u32..64 {
            let mut buf = len.to_le_bytes().to_vec();
            buf.resize(buf.len() + len as usize + MAC_LEN, 0xff);
            let _ = ContentDesc::decode_verified(&buf, &key(1), &FILE_ID, crate::header::CONTAINER_VERSION);
        }
    }

    // ================= подпись редактора, тег 6 =================

    /// Заполненная подпись редактора. Байты произвольны: здесь проверяется
    /// РАСКЛАДКА, а не криптография — у неё свои векторы в `tests/kat/`.
    fn sample_editor() -> EditorSignature {
        EditorSignature {
            sig_alg: SigAlg::RsaPssSha256,
            session_head: [0x51; 32],
            journal_head: Some(JournalHead { size: 4096, root: [0x52; 32] }),
            certified_by: vec![0x53; 120],
            signature: vec![0x54; EDITOR_SIGNATURE_LEN],
        }
    }

    fn with_editor(editor: Option<EditorSignature>) -> ContentDesc {
        ContentDesc { editor, ..sample() }
    }

    /// Круг: записали в версии 4 — прочитали в версии 4, получили то же самое.
    #[test]
    fn an_editor_signature_survives_a_round_trip_in_version_four() {
        for editor in [Some(sample_editor()), None] {
            let desc = with_editor(editor);
            let bytes = desc.encode(&key(1), &FILE_ID, FIRST_EDITING_VERSION).unwrap();
            let (back, _) =
                ContentDesc::decode_verified(&bytes, &key(1), &FILE_ID, FIRST_EDITING_VERSION)
                    .unwrap();
            assert_eq!(back, desc);
        }
    }

    /// Голова журнала, которой НЕ БЫЛО, отличается от головы, которая есть.
    ///
    /// Пустое значение и значение в сорок байт — разные байты области, поэтому
    /// разные MAC и разные подписи. Если бы «не виделась» кодировалось
    /// отсутствием записи, устройство, скрывшее свою голову, было бы неотличимо
    /// от устройства, которое сервера действительно не видело.
    #[test]
    fn a_missing_journal_head_is_encoded_and_differs_from_a_present_one() {
        let without = with_editor(Some(EditorSignature {
            journal_head: None,
            ..sample_editor()
        }));
        let with = with_editor(Some(sample_editor()));

        let a = without.encode(&key(1), &FILE_ID, FIRST_EDITING_VERSION).unwrap();
        let b = with.encode(&key(1), &FILE_ID, FIRST_EDITING_VERSION).unwrap();
        assert_ne!(a, b, "две разные истории дали одни байты");

        let (back, _) =
            ContentDesc::decode_verified(&a, &key(1), &FILE_ID, FIRST_EDITING_VERSION).unwrap();
        assert_eq!(back.editor.unwrap().journal_head, None);
    }

    /// Версии младше четвёртой тег 6 НЕ ЗНАЮТ, и это не придирка.
    ///
    /// Версия есть набор байтов, которые она умеет прочитать. Приняв здесь
    /// подпись редактора в файле версии 1, мы объявили бы, что версия 1 её
    /// задаёт, — а она не задаёт, и вторая реализация, написанная по спеке
    /// версии 1, такой файл отвергнет.
    #[test]
    fn an_editor_signature_is_refused_by_older_versions() {
        // Запись в версии 4, чтение в версиях 1, 2 и 3.
        let bytes = with_editor(Some(sample_editor()))
            .encode(&key(1), &FILE_ID, FIRST_EDITING_VERSION)
            .unwrap();
        for version in [1u16, 2, 3] {
            assert_eq!(
                ContentDesc::decode_verified(&bytes, &key(1), &FILE_ID, version).map(|_| ()),
                Err(FormatError::UnknownCriticalField { tag: tag::EDITOR }),
                "версия {version} приняла тег, которого не знает"
            );
        }
    }

    /// Писатель тоже не должен уметь произвести то, что читатель отвергнет.
    ///
    /// Тот же довод, по которому `chunk_count == 0` отвергается на записи: наш
    /// код не имеет права выпустить область, которую наш же разбор обязан
    /// отбросить.
    #[test]
    fn writing_an_editor_signature_below_version_four_is_refused() {
        for version in [1u16, 2, 3] {
            assert_eq!(
                with_editor(Some(sample_editor())).encode(&key(1), &FILE_ID, version).map(|_| ()),
                Err(FormatError::UnknownCriticalField { tag: tag::EDITOR }),
                "версия {version} записала тег, которого не знает"
            );
        }
    }

    /// В теге 6 годится ТОЛЬКО RSA-PSS — зеркало проверки в заголовке, где
    /// годится только Ed25519. Иначе подпись одной схемы предъявлялась бы как
    /// подпись другой.
    #[test]
    fn only_rsa_pss_is_accepted_as_the_editor_signature_algorithm() {
        let mut inner = TlvWriter::new();
        inner.put(editor_tag::SIG_ALG, &[SigAlg::Ed25519 as u8]).unwrap();
        inner.put(editor_tag::SESSION_HEAD, &[0x51; 32]).unwrap();
        inner.put(editor_tag::JOURNAL_HEAD, &[]).unwrap();
        inner.put(editor_tag::CERTIFIED_BY, &[]).unwrap();
        inner.put(editor_tag::SIGNATURE, &[0x54; EDITOR_SIGNATURE_LEN]).unwrap();

        assert_eq!(
            EditorSignature::decode(&inner.finish()),
            Err(FormatError::BadFieldLength { tag: editor_tag::SIG_ALG, len: 1 })
        );
    }

    /// Длины проверяются на ТОЧНОЕ соответствие, а не подгоняются (И-8).
    #[test]
    fn every_length_inside_the_editor_record_is_exact() {
        let cases: [(u16, Vec<u8>); 3] = [
            // Подпись короче или длиннее модуля.
            (editor_tag::SIGNATURE, vec![0x54; EDITOR_SIGNATURE_LEN - 1]),
            (editor_tag::SIGNATURE, vec![0x54; EDITOR_SIGNATURE_LEN + 1]),
            // Голова журнала: ни ноль, ни сорок.
            (editor_tag::JOURNAL_HEAD, vec![0x52; JOURNAL_HEAD_LEN - 1]),
        ];

        for (tag, value) in cases {
            let mut inner = TlvWriter::new();
            inner.put(editor_tag::SIG_ALG, &[SigAlg::RsaPssSha256 as u8]).unwrap();
            inner.put(editor_tag::SESSION_HEAD, &[0x51; 32]).unwrap();
            let head: &[u8] = if tag == editor_tag::JOURNAL_HEAD { &value } else { &[] };
            inner.put(editor_tag::JOURNAL_HEAD, head).unwrap();
            inner.put(editor_tag::CERTIFIED_BY, &[]).unwrap();
            let sig: &[u8] =
                if tag == editor_tag::SIGNATURE { &value } else { &[0x54; EDITOR_SIGNATURE_LEN] };
            inner.put(editor_tag::SIGNATURE, sig).unwrap();

            assert_eq!(
                EditorSignature::decode(&inner.finish()),
                Err(FormatError::BadFieldLength { tag, len: value.len() }),
                "длина {} у тега {tag} принята",
                value.len()
            );
        }
    }

    /// Каждое поле записи обязательно: пропуск любого — отказ, а не умолчание.
    ///
    /// Умолчание здесь означало бы подпись без указания схемы, сеанс без головы
    /// или сертификат, который никто не предъявлял.
    #[test]
    fn every_field_of_the_editor_record_is_required() {
        let all: [(u16, Vec<u8>); 5] = [
            (editor_tag::SIG_ALG, vec![SigAlg::RsaPssSha256 as u8]),
            (editor_tag::SESSION_HEAD, vec![0x51; 32]),
            (editor_tag::JOURNAL_HEAD, Vec::new()),
            (editor_tag::CERTIFIED_BY, vec![0x53; 8]),
            (editor_tag::SIGNATURE, vec![0x54; EDITOR_SIGNATURE_LEN]),
        ];

        for skipped in 0..all.len() {
            let mut inner = TlvWriter::new();
            for (index, (tag, value)) in all.iter().enumerate() {
                if index != skipped {
                    inner.put(*tag, value).unwrap();
                }
            }
            let missing = all[skipped].0;
            assert_eq!(
                EditorSignature::decode(&inner.finish()),
                Err(FormatError::MissingField { tag: missing }),
                "без поля {missing} разбор прошёл"
            );
        }
    }

    /// Сертификат ограничен собственным пределом, а не только пределом области.
    ///
    /// Без него сертификат съел бы все 64 КиБ, вытеснив поля, ради которых
    /// область существует.
    #[test]
    fn an_oversized_certificate_is_refused_on_write() {
        let editor = EditorSignature {
            certified_by: vec![0x53; MAX_CERTIFIED_BY_LEN + 1],
            ..sample_editor()
        };
        assert_eq!(
            editor.encode().map(|_| ()),
            Err(FormatError::BadFieldLength {
                tag: editor_tag::CERTIFIED_BY,
                len: MAX_CERTIFIED_BY_LEN + 1
            })
        );
    }
}
