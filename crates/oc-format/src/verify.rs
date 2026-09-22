//! Точка входа разбора контейнера.
//!
//! Порядок операций здесь — часть контракта безопасности, а не деталь
//! реализации: структурные границы, затем подпись, и только затем использование
//! полей.
//!
//! Но это **не делает вход доверенным**. Враждебный заголовок может быть
//! безупречно подписан ключом противника, поэтому декодер обязан выдерживать
//! любой ввод, а доверие к подписанту — отдельное решение, принимаемое выше.
//!
//! # Отступление от §5.1 спецификации
//!
//! Спецификация предписывает проверять подпись **до** декодирования. Буквально
//! это неисполнимо: и публичный ключ автора, и идентификатор набора алгоритмов
//! лежат **внутри** заголовка, а без них нечем и не над чем проверять. Поэтому
//! реальный порядок такой:
//!
//! 1. структурное разрезание ([`Prologue::split`]) — без криптографии;
//! 2. декодирование заголовка ради двух значений: ключа автора и набора;
//! 3. проверка подписи по сырым байтам заголовка;
//! 4. всё остальное.
//!
//! Отступление безопасно ровно постольку, поскольку декодер тотален: он не
//! паникует, не зацикливается и не выделяет память по непроверенной длине. Это
//! требование §5.2 существует независимо от порядка — «подписать враждебный
//! заголовок может кто угодно», — поэтому декодер и так обязан выдерживать
//! непроверенный ввод, и шаг 2 не добавляет ему работы, которой он не был бы
//! обязан делать после шага 3.
//!
//! Цена отступления названа прямо: ошибка декодирования побеждает ошибку
//! подписи. Файл с неизвестным критичным полем и мусорной подписью даёт
//! [`FormatError::UnknownCriticalField`], а не отказ подписи. Наружу это отдаёт
//! один бит («заголовок разобрался»), и этот бит противник и так получает,
//! подписав свой заголовок своим ключом.

use crate::header::{
    MAX_READABLE_CONTAINER_VERSION, MIN_READABLE_CONTAINER_VERSION, ParsedHeader,
    SUPPORTED_READER_VERSION, Suite,
};
use crate::{FormatError, MAGIC, MAX_HEADER_LEN, Prologue};
use oc_crypto::{Transcript, label, sign};

/// Отказ проверки подписи заголовка.
///
/// Один вариант и на «публичный ключ не разобрался», и на «подпись не сошлась».
/// Различать их снаружи незачем: разный ответ выдал бы противнику лишний бит о
/// том, какая именно проверка не прошла.
const BAD_HEADER_SIGNATURE: FormatError = FormatError::BadHeaderSignature;

/// Что известно о подписанте.
///
/// Отдельный тип, а не булев флаг: главная ошибка в системах такого рода —
/// взять публичный ключ **из самого заголовка**, проверить им же подпись и
/// назвать результат проверенным. Это самоподписанность, доказывающая ровно
/// ничего. Разделение на два значения не даёт спутать «подпись сходится» и «мы
/// знаем, кто подписал».
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignerTrust {
    /// Ключ автора закреплён за этой организацией и совпадает.
    Pinned,
    /// Подпись корректна, но пары «организация, ключ» видим впервые. Интерфейс
    /// обязан сказать об этом прямо, а не показывать замок.
    Unknown,
    /// **Организация известна, ключ другой.**
    ///
    /// Самое важное из трёх значений и единственное, которое обязано
    /// останавливать работу. Ровно так выглядит подмена: файл выдаёт себя за
    /// того же отправителя, от которого вы уже получали файлы, но подписан не
    /// тем ключом.
    ///
    /// Честные причины у этого тоже есть — автор сменил ключ, — и различить их
    /// изнутри файла нельзя ничем: подпись корректна в обоих случаях. Поэтому
    /// решение отдаётся человеку, но по умолчанию **отказ**: цена ошибочного
    /// отказа — один звонок отправителю, цена ошибочного согласия — открытый
    /// файл злоумышленника.
    Conflict,
}

/// Хранилище закреплённых ключей авторов.
///
/// Возвращает вердикт целиком, а не «известен ли ключ»: отличить «видим
/// впервые» от «известен другой ключ» может только тот, кто владеет хранилищем,
/// и решать это за него здесь было бы нечем.
///
/// `org_id` в запросе обязателен, и это следствие устройства формата. Имени
/// автора в заголовке нет намеренно (§2, тег 5): имя, названное в самом
/// заголовке, доказывает не больше, чем сам заголовок. Единственное, к чему
/// можно привязать закрепление, — `org_id`, поле арендатора. Отсюда и граница
/// гарантии: подмену ключа **у известной организации** это ловит, а
/// злоумышленника, назвавшегося новой организацией, — нет; он просто окажется
/// неизвестным, что и есть честное состояние.
pub trait TrustStore {
    /// Что известно про пару «организация, ключ автора».
    fn lookup(&self, org_id: &[u8], author_key: &[u8; 32]) -> SignerTrust;
}

/// Хранилище, которому не известен никто.
///
/// Полезно и как значение по умолчанию, и как способ явно сказать «доверия нет»
/// в тестах: с ним любой корректно подписанный контейнер даёт
/// [`SignerTrust::Unknown`].
#[derive(Debug, Clone, Copy, Default)]
pub struct EmptyTrustStore;

impl TrustStore for EmptyTrustStore {
    fn lookup(&self, _org_id: &[u8], _author_key: &[u8; 32]) -> SignerTrust {
        SignerTrust::Unknown
    }
}

/// Проверенный заголовок вместе с байтами, по которым он разобран.
#[derive(Debug, Clone)]
pub struct VerifiedHeader<'a> {
    pub parsed: ParsedHeader,
    /// Исходные байты заголовка: по ним, а не по повторной кодировке, считаются
    /// все хеши.
    pub header_bytes: &'a [u8],
    /// Смещение первого байта изменяемой области.
    pub content_desc_offset: u64,
    pub trust: SignerTrust,
}

/// Идентификатор набора алгоритмов, входящий в подпись заголовка (§5).
///
/// Отдельного скалярного поля `suite_id` в заголовке нет: набор задан тремя
/// идентификаторами внутри поля `SUITE`. Поэтому значение выводится из
/// разобранного набора, и выводится именно из **алгоритма подписи** — того
/// единственного, от которого зависит сама проверяемая подпись. Когда [`SigAlg`]
/// получит второе значение, этот байт не даст предъявить подпись одной схемы как
/// подпись другой, если их кодировки удастся столкнуть.
///
/// Идентификаторы AEAD и хеша дерева в байт не входят намеренно: они лежат
/// внутри байтов заголовка, а те покрыты подписью целиком. Второе место, где
/// кодируется то же самое, — это второе место, которое может разойтись с первым,
/// и расхождение проявилось бы как молчаливый отказ читать корректный файл.
///
/// [`SigAlg`]: oc_crypto::SigAlg
pub fn suite_id(suite: &Suite) -> u8 {
    suite.sig as u8
}

/// Точная строка байтов под подписью автора (§5).
///
/// ```text
/// "CC/v1/header-sig" ‖ 0x00 ‖ u8(suite_id) ‖ Magic ‖ u32le(HeaderLen) ‖ Header
/// ```
///
/// Нулевой байт после метки ставит сам [`Transcript::new`], поэтому здесь его
/// добавлять нельзя: второй такой байт дал бы строку, которой нет в
/// спецификации, и файлы разошлись бы с любой другой реализацией формата.
///
/// Заголовок кладётся последним и без префикса длины — длина уже связана
/// предыдущим полем. Ради этого случая в [`Transcript`] и заведён
/// [`Transcript::tail_after_declared_length`]: он говорит, что отсутствие
/// префикса здесь осознанно, а не забыто.
///
/// Функция публична, потому что упаковщику нужно подписать ровно ту же строку.
/// Две независимые её сборки — писательская и читательская — разойдясь, дали бы
/// файл, который наш писатель подписал, а наш читатель отверг; причину пришлось
/// бы искать сравнением байтов.
pub fn header_signing_transcript(
    header_bytes: &[u8],
    suite: &Suite,
) -> Result<Transcript, FormatError> {
    let declared = u32::try_from(header_bytes.len()).map_err(|_| FormatError::OffsetOverflow)?;
    // Тот же предел, что и на чтении. Писатель не должен уметь произвести
    // заголовок, который наш же читатель обязан отвергнуть по длине.
    if declared > MAX_HEADER_LEN {
        return Err(FormatError::HeaderTooLarge { declared });
    }

    let mut transcript = Transcript::new(label::HEADER_SIG);
    transcript
        .u8(suite_id(suite))
        .fixed(&MAGIC)
        .u32le(declared)
        .tail_after_declared_length(header_bytes);
    Ok(transcript)
}

/// Разобрать и проверить пролог контейнера.
///
/// Последовательность (о её расхождении с §5.1 — в описании модуля):
/// 1. структурные границы: магия, предел длины, хватает ли байтов;
/// 2. декодирование заголовка — ради ключа автора и набора алгоритмов;
/// 3. проверка подписи Ed25519 по транскрипту с меткой домена;
/// 4. согласование версий: `min_reader_version` и диапазон `container_version`;
/// 5. определение доверия к подписанту по хранилищу.
///
/// Шаг 4 идёт **до** любого содержательного использования полей: файл,
/// требующий более новую версию клиента, обязан получить отказ, даже если всё
/// остальное разобралось и подпись сошлась. Ключ автора и набор алгоритмов на
/// шаге 2 читаются раньше — но они не «применяются», а лишь задают, чем и над
/// чем считать подпись.
///
/// Успех означает «подпись сходится», а **не** «подписанту можно верить»:
/// доверие возвращается отдельным полем [`VerifiedHeader::trust`].
pub fn verify_and_parse<'a>(
    buf: &'a [u8],
    trust_store: &dyn TrustStore,
) -> Result<VerifiedHeader<'a>, FormatError> {
    // 1. Структура. Дёшево, тотально и без криптографии, поэтому первым: буфер,
    // который вообще не наш, отсеивается до единой операции с ключами.
    let prologue = Prologue::split(buf)?;

    // 2. Декодирование. Вынужденно идёт до проверки подписи: ключ автора и набор
    // алгоритмов лежат внутри заголовка. Безопасно ровно потому, что декодер
    // тотален; см. описание модуля.
    let parsed = crate::header::Header::decode(prologue.header)?;

    // 3. Подпись — по **сырым** байтам заголовка, а не по повторной кодировке
    // разобранной структуры. Повторная сериализация здесь воспроизвела бы всё
    // семейство ошибок канонизации, известное по JWS и XML-DSig: разобрали одно,
    // подписали другое.
    //
    // Ключ приходит из непроверенного заголовка, то есть от противника.
    // `sign::verify` внутри использует `verify_strict` и отвечает отказом, а не
    // паникой, на некорректную точку кривой.
    let transcript = header_signing_transcript(prologue.header, &parsed.header.suite)?;
    sign::verify(&parsed.header.author_key, &transcript, prologue.signature)
        .map_err(|_| BAD_HEADER_SIGNATURE)?;

    // 4. Согласование версий. Отказ обязателен, даже если подпись сошлась:
    // файл использует семантику, которой этот клиент не знает, и «понять
    // большинство полей» здесь означает применить чужие правила к чужому файлу.
    // Проверка стоит до сборки результата, чтобы наружу не ушла структура,
    // которую вызывающий имел бы право использовать.
    let min_reader_version = parsed.header.min_reader_version;
    if min_reader_version > SUPPORTED_READER_VERSION {
        return Err(FormatError::ReaderTooOld {
            need: min_reader_version,
            have: SUPPORTED_READER_VERSION,
        });
    }

    // Версия самого формата проверяется отдельно от `min_reader_version`, и это
    // не дублирование.
    //
    // `min_reader_version` — это ЗАЯВЛЕНИЕ ПИСАТЕЛЯ о том, что клиент такой-то
    // версии его файл поймёт. Заявление подписано, но подписал его автор, а
    // автором может быть противник: он вправе поставить `container_version: 999`
    // и `min_reader_version: 1`, утверждая, что файл будущего формата
    // читается по правилам нынешнего. Поверив, клиент применил бы правила
    // версии 1 к семантике версии 999.
    //
    // Поэтому неизвестная версия формата — отказ. Продукт безопасности, увидев
    // то, чего не понимает, обязан не открывать, а не «понять большинство
    // полей». Прямая совместимость от этого не страдает: она обеспечена
    // диапазоном необязательных тегов (§2), который позволяет добавлять поля
    // БЕЗ смены версии формата, а смена версии как раз и означает, что
    // изменилось нечто, чего старый клиент понять не может.
    // Диапазон, а не только верхняя граница.
    //
    // Проверка одного лишь `>` пропускала версию 0 — формата, которого никогда
    // не существовало, — и файл читался по правилам версии 1. Версия ниже
    // читаемой опаснее версии выше: она не вызывает подозрений («это же старый
    // файл»), хотя означает ровно то же самое — семантику, которой у нас нет.
    //
    // НИЖНЯЯ ГРАНИЦА — ПЯТЁРКА, А НЕ ЕДИНИЦА (решение Р-1, 2026-09-19). Версии
    // 1–4 сожжены для чтения: ни один контейнер этих версий с magic `CLOSECR1`
    // наружу не выходил, потому что переименование 2026-09-08 сменило magic и
    // метки в тот же день, когда нарезалась пятая. Обещание «1–4 читаемы»
    // относилось к пустому множеству и проверялось ровно здесь — перебором
    // номера, а не открытием файла. Причина и правило Р-3 («до первого файла,
    // ушедшего наружу, читатель держит только версию писателя») записаны у
    // `MIN_READABLE_CONTAINER_VERSION`.
    let container_version = parsed.header.container_version;
    // Диапазоном, а не двумя сравнениями: пока обе границы были единицами, форма
    // записи не имела значения, а с их расхождением стало важно, что проверка
    // одна и обе границы в ней названы вместе. Сегодня границы снова совпали, но
    // диапазон остаётся: он разойдётся снова в день нарезки версии 6, и форма
    // записи, меняющаяся туда-обратно, прячет то, что менялось по существу.
    if !(MIN_READABLE_CONTAINER_VERSION..=MAX_READABLE_CONTAINER_VERSION)
        .contains(&container_version)
    {
        return Err(FormatError::UnsupportedContainerVersion {
            version: container_version,
            first: MIN_READABLE_CONTAINER_VERSION,
            max: MAX_READABLE_CONTAINER_VERSION,
        });
    }

    // 5. Доверие — отдельным значением, а не флагом «проверено». Ключ спрашивается
    // именно тот, которым проверена подпись: спросить какой-нибудь другой значило
    // бы вернуть доверие к тому, кто файл не подписывал.
    let trust = trust_store.lookup(&parsed.header.org_id, &parsed.header.author_key);

    Ok(VerifiedHeader {
        parsed,
        header_bytes: prologue.header,
        // Изменяемая область начинается сразу за подписью. Смещение берётся из
        // пролога, а не пересчитывается по длине заголовка: два независимых
        // вычисления одного смещения рано или поздно разойдутся.
        content_desc_offset: prologue.after_signature,
        trust,
    })
}

/// Разобрать пролог **без** проверки подписи.
///
/// Существует ровно для одного применения — фаззинга декодера, которому нужен
/// доступ к глубоким веткам без возни с подписью.
///
/// Закрыта `cfg`, а не только неудобным именем. Имя и `#[doc(hidden)]` — это
/// просьба к ревьюеру, а обход проверки подписи слишком дорого стоит, чтобы
/// держаться на просьбе: функция, доступная из рабочей сборки, рано или поздно
/// будет из неё вызвана — из отладочной ветки, из утилиты диагностики, из
/// «временно, чтобы посмотреть, что внутри». Теперь в сборке `cc-cli` этого
/// символа нет вовсе, и вызвать его нельзя даже намеренно.
///
/// Фаззер включает признак `fuzzing` явно: `--cfg fuzzing` (cargo-fuzz ставит
/// его сам).
#[doc(hidden)]
#[cfg(any(test, fuzzing))]
pub fn parse_without_verifying_signature_for_fuzzing_only(
    buf: &[u8],
) -> Result<ParsedHeader, FormatError> {
    let prologue = Prologue::split(buf)?;
    crate::header::Header::decode(prologue.header)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::header::{
        Authority, CONTAINER_VERSION, FIRST_CONTAINER_VERSION, Header, KeySlot, KnownSlot, SlotKind,
        tag,
    };
    use crate::tlv::TlvWriter;
    use oc_crypto::sign::{Ed25519Signer, SIGNATURE_LEN, Signer};
    use oc_crypto::{AeadAlg, KemAlg, SigAlg, TreeHashAlg};
    use oc_policy::{Action, Policy};

    /// Байты сразу за подписью. Настоящей изменяемой области здесь нет — важно
    /// лишь то, что `content_desc_offset` указывает именно на них.
    const TRAILER: &[u8] = b"<content-desc goes here>";

    /// Метка, по которой тест находит `original_root` внутри закодированного
    /// заголовка, чтобы испортить байт значения, а не длины: порча длины сломала
    /// бы разбор раньше подписи и проверяла бы не то свойство.
    const ORIGINAL_ROOT: [u8; 32] = [0x33; 32];

    fn signer(seed: u8) -> Ed25519Signer {
        // Семя, а не генератор: тест обязан воспроизводиться байт в байт.
        Ed25519Signer::from_seed(&[seed; 32])
    }

    /// Набор алгоритмов всех тестовых заголовков.
    fn sample_suite() -> Suite {
        Suite {
            sig: SigAlg::Ed25519,
            aead: AeadAlg::XChaCha20Poly1305,
            tree_hash: TreeHashAlg::Blake3,
        }
    }

    /// Хранилище, знающее перечисленные ключи независимо от организации.
    ///
    /// Организацию намеренно игнорирует: тесты этого модуля проверяют, что
    /// `verify_and_parse` спрашивает хранилище тем ключом, которым проверил
    /// подпись, а привязка к организации — свойство реализации хранилища и
    /// проверяется у неё (`cc_cli::trust`).
    #[derive(Debug, Default)]
    struct PinnedKeys(Vec<[u8; 32]>);

    impl TrustStore for PinnedKeys {
        fn lookup(&self, _org_id: &[u8], author_key: &[u8; 32]) -> SignerTrust {
            if self.0.contains(author_key) { SignerTrust::Pinned } else { SignerTrust::Unknown }
        }
    }

    /// Заголовок, заполненный целиком: разбор обязан пройти по всем ветвям, а не
    /// по минимальному подмножеству полей.
    fn sample_header(author_key: [u8; 32]) -> Header {
        Header {
            container_version: CONTAINER_VERSION,
            min_reader_version: SUPPORTED_READER_VERSION,
            file_id: [0x11; 16],
            suite: sample_suite(),
            author_key,
            header_salt: [0x22; 32],
            chunk_size: 65536,
            original_root: ORIGINAL_ROOT,
            policy: Policy::deny_all().allow(Action::View),
            key_slots: vec![KeySlot::Known(KnownSlot {
                kind: SlotKind::AuthorDevice,
                kem: KemAlg::X25519HkdfSha256,
                enc: vec![0x44; 32],
                nonce: [0x01; 24],
                ct: vec![0x55; 48],
                commitment: [0x66; 32],
                key_fpr: Some(vec![0x77; 32]),
                claim_commit: None,
            })],
            authority: Authority {
                urls: vec!["https://cc.example/api".to_string()],
                sealing_kid: [0x88; 32],
                lease_verify_key: [0x99; 32],
            },
            private_meta: vec![0xaa; 64],
            prev_header_hash: None,
            org_id: b"org".to_vec(),
            wrapped_cek: [0xbb; crate::header::WRAPPED_CEK_LEN],
            coauthors: None,
            class: 0,
            footer_offset: None,
        }
    }

    /// Сложить контейнер из готовых частей.
    ///
    /// Отдельно от подписания намеренно: тесты подделки должны уметь подставить
    /// чужую подпись, не пересобирая заголовок.
    fn assemble(header_bytes: &[u8], signature: &[u8; SIGNATURE_LEN]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&u32::try_from(header_bytes.len()).unwrap().to_le_bytes());
        out.extend_from_slice(header_bytes);
        out.extend_from_slice(signature);
        out.extend_from_slice(TRAILER);
        out
    }

    /// Корректно подписанный контейнер.
    ///
    /// `signer` и `header.author_key` разведены намеренно: только так тест может
    /// построить заголовок, названный ключ которого не тот, что реально подписал.
    fn container(header: &Header, signer: &Ed25519Signer) -> Vec<u8> {
        let header_bytes = header.encode().unwrap();
        let transcript = header_signing_transcript(&header_bytes, &header.suite).unwrap();
        let signature = signer.sign(&transcript).unwrap();
        assemble(&header_bytes, &signature)
    }

    /// Контейнер, подписанный своим же ключом: обычный честный файл.
    fn self_consistent(signer: &Ed25519Signer) -> Vec<u8> {
        container(&sample_header(signer.public_key()), signer)
    }

    #[test]
    fn a_well_formed_container_parses_and_exposes_the_bytes_it_was_parsed_from() {
        let author = signer(1);
        let buf = self_consistent(&author);

        let verified = verify_and_parse(&buf, &EmptyTrustStore).unwrap();

        assert_eq!(verified.parsed.header.author_key, author.public_key());
        assert_eq!(verified.parsed.header.chunk_size, 65536);
        assert_eq!(
            verified.header_bytes,
            sample_header(author.public_key()).encode().unwrap()
        );
        // Смещение обязано указывать ровно на первый байт за подписью: по нему
        // читатель изменяемой области начнёт разбор, и ошибка здесь сдвинула бы
        // всё, что дальше.
        let offset = usize::try_from(verified.content_desc_offset).unwrap();
        assert_eq!(buf.get(offset..), Some(TRAILER));
    }

    #[test]
    fn an_empty_trust_store_never_reports_a_pinned_signer() {
        // Значение по умолчанию обязано быть недоверием. Хранилище, которое
        // «на всякий случай» доверяет, — это отсутствие защиты с видом защиты.
        let buf = self_consistent(&signer(1));
        let verified = verify_and_parse(&buf, &EmptyTrustStore).unwrap();
        assert_eq!(verified.trust, SignerTrust::Unknown);
    }

    #[test]
    fn a_store_that_knows_the_key_reports_it_as_pinned() {
        let author = signer(1);
        let buf = self_consistent(&author);
        let store = PinnedKeys(vec![author.public_key()]);

        let verified = verify_and_parse(&buf, &store).unwrap();
        assert_eq!(verified.trust, SignerTrust::Pinned);
    }

    #[test]
    fn a_header_signed_by_a_stranger_verifies_but_is_never_trusted() {
        // ГЛАВНОЕ СВОЙСТВО ЭТОГО МОДУЛЯ.
        //
        // Противник строит заголовок, кладёт в поле автора СВОЙ публичный ключ и
        // подписывает СВОИМ приватным. Подпись сходится — иначе и быть не может,
        // ведь проверяется она названным в том же файле ключом. Самоподписанность
        // не доказывает ничего, и путать её с доверием — ровно та ошибка, ради
        // которой `SignerTrust` вообще существует отдельным типом.
        //
        // Хранилище при этом знает настоящего автора. Если бы `verify_and_parse`
        // отвечал «подписано, значит хорошо», файл противника выглядел бы для
        // пользователя так же, как файл автора.
        let author = signer(1);
        let stranger = signer(2);
        assert_ne!(author.public_key(), stranger.public_key());

        let forged = container(&sample_header(stranger.public_key()), &stranger);
        let store = PinnedKeys(vec![author.public_key()]);

        let verified = verify_and_parse(&forged, &store).unwrap();

        assert_eq!(
            verified.trust,
            SignerTrust::Unknown,
            "самоподписанный заголовок противника выдан за доверенный"
        );
        assert_eq!(
            verified.parsed.header.author_key,
            stranger.public_key(),
            "наружу обязан уходить тот ключ, которым проверена подпись"
        );

        // Контраст: то же хранилище на честном файле отвечает `Pinned`. Без этой
        // половины тест проходил бы и у реализации, которая не доверяет никому.
        let honest = self_consistent(&author);
        assert_eq!(
            verify_and_parse(&honest, &store).unwrap().trust,
            SignerTrust::Pinned
        );
    }

    #[test]
    fn a_signature_from_the_authors_key_over_a_foreign_header_is_refused() {
        // Обратная подстановка: заголовок называет автора, но подписал его не он.
        // Здесь подпись не сходится, и это уже отказ, а не вопрос доверия.
        let author = signer(1);
        let stranger = signer(2);
        let forged = container(&sample_header(author.public_key()), &stranger);

        assert_eq!(
            verify_and_parse(&forged, &PinnedKeys(vec![author.public_key()])).unwrap_err(),
            BAD_HEADER_SIGNATURE
        );
    }

    #[test]
    fn corrupting_a_single_header_byte_breaks_the_signature() {
        let author = signer(1);
        let header_bytes = sample_header(author.public_key()).encode().unwrap();
        let transcript = header_signing_transcript(&header_bytes, &sample_suite()).unwrap();
        let signature = author.sign(&transcript).unwrap();

        // Байт внутри ЗНАЧЕНИЯ поля: заголовок остаётся разбираемым, поэтому
        // отказ приходит именно от подписи, а не от декодера.
        let Some(at) = header_bytes
            .windows(ORIGINAL_ROOT.len())
            .position(|w| w == ORIGINAL_ROOT)
        else {
            panic!("original_root обязан лежать в закодированном заголовке");
        };
        let mut broken = header_bytes.clone();
        broken[at + 16] ^= 0x01;
        assert_eq!(
            verify_and_parse(&assemble(&broken, &signature), &EmptyTrustStore).unwrap_err(),
            BAD_HEADER_SIGNATURE
        );

        // И вообще любой перевёрнутый бит заголовка обязан дать отказ: подпись
        // покрывает байты целиком, поэтому «безобидных» мест в ней нет. Ошибка
        // при этом может прийти и от декодера — порча длины или тега ломает
        // разбор раньше, чем доходит до подписи.
        for position in 0..header_bytes.len() {
            for bit in [0x01u8, 0x80] {
                let mut broken = header_bytes.clone();
                broken[position] ^= bit;
                assert!(
                    verify_and_parse(&assemble(&broken, &signature), &EmptyTrustStore).is_err(),
                    "порча байта {position} битом {bit:#04x} прошла проверку"
                );
            }
        }
    }

    #[test]
    fn corrupting_a_single_signature_byte_breaks_verification() {
        let author = signer(1);
        let buf = self_consistent(&author);
        let header_bytes = sample_header(author.public_key()).encode().unwrap();
        let signature_at = crate::HEADER_OFFSET + header_bytes.len();

        for position in 0..SIGNATURE_LEN {
            for bit in [0x01u8, 0x80] {
                let mut broken = buf.clone();
                broken[signature_at + position] ^= bit;
                assert_eq!(
                    verify_and_parse(&broken, &EmptyTrustStore).unwrap_err(),
                    BAD_HEADER_SIGNATURE,
                    "испорченный байт подписи №{position} прошёл проверку"
                );
            }
        }
    }

    #[test]
    fn a_file_demanding_a_newer_reader_is_refused_even_with_a_valid_signature() {
        // Отказ по версии обязан пережить корректную подпись: файл использует
        // семантику, которой этот клиент не знает, и «разобралось большинство
        // полей» здесь означает применить не те правила к чужому файлу.
        let author = signer(1);
        let need = SUPPORTED_READER_VERSION + 1;
        let header = Header {
            min_reader_version: need,
            ..sample_header(author.public_key())
        };

        assert_eq!(
            verify_and_parse(
                &container(&header, &author),
                &PinnedKeys(vec![author.public_key()])
            )
            .unwrap_err(),
            FormatError::ReaderTooOld {
                need,
                have: SUPPORTED_READER_VERSION
            }
        );
    }

    #[test]
    fn a_correctly_signed_header_this_client_cannot_understand_is_still_refused() {
        // §5.2: подписать враждебный заголовок может кто угодно. Корректная
        // подпись не превращает неизвестное критичное поле в известное.
        let author = signer(1);
        let mut header_bytes = sample_header(author.public_key()).encode().unwrap();
        let mut extra = TlvWriter::new();
        extra
            .put(0x7FFE, b"semantics from a future version")
            .unwrap();
        header_bytes.extend_from_slice(&extra.finish());

        let transcript = header_signing_transcript(&header_bytes, &sample_suite()).unwrap();
        let signature = author.sign(&transcript).unwrap();

        assert_eq!(
            verify_and_parse(&assemble(&header_bytes, &signature), &EmptyTrustStore).unwrap_err(),
            FormatError::UnknownCriticalField { tag: 0x7FFE }
        );
    }

    #[test]
    fn a_signature_made_under_another_domain_label_is_refused() {
        // Без метки домена подпись автора, сделанная над записью отзыва или над
        // запросом активации, предъявлялась бы как подпись заголовка: данные те
        // же, контекст другой.
        let author = signer(1);
        let header = sample_header(author.public_key());
        let header_bytes = header.encode().unwrap();

        let mut wrong_domain = Transcript::new(label::REVOCATION);
        wrong_domain
            .u8(suite_id(&header.suite))
            .fixed(&MAGIC)
            .u32le(u32::try_from(header_bytes.len()).unwrap())
            .tail_after_declared_length(&header_bytes);
        let signature = author.sign(&wrong_domain).unwrap();

        assert_eq!(
            verify_and_parse(&assemble(&header_bytes, &signature), &EmptyTrustStore).unwrap_err(),
            BAD_HEADER_SIGNATURE
        );
    }

    #[test]
    fn the_signed_bytes_are_exactly_those_named_by_the_specification() {
        // §5: sig_input = "CC/v1/header-sig" ‖ 0x00 ‖ u8(suite_id) ‖ Magic ‖
        //                 u32le(HeaderLen) ‖ Header
        // Ровно один нулевой байт: его ставит `Transcript::new`, и добавлять
        // второй нельзя — получилась бы строка, которой нет в спецификации.
        let header_bytes = b"header bytes".as_slice();
        let suite = sample_suite();
        let transcript = header_signing_transcript(header_bytes, &suite).unwrap();

        let mut expected = Vec::new();
        expected.extend_from_slice(label::HEADER_SIG.as_bytes());
        expected.push(0x00);
        expected.push(SigAlg::Ed25519 as u8);
        expected.extend_from_slice(&MAGIC);
        expected.extend_from_slice(&u32::try_from(header_bytes.len()).unwrap().to_le_bytes());
        expected.extend_from_slice(header_bytes);

        assert_eq!(transcript.as_bytes(), expected.as_slice());
    }

    #[test]
    fn the_transcript_agrees_with_the_prologues_own_encoding() {
        // Строку под подписью кодируют два независимых места. Разойдясь, они дали
        // бы файл, который наш писатель подписал, а наш читатель отверг, — и
        // причину пришлось бы искать сравнением байтов. Тест связывает их намертво.
        let author = signer(1);
        let header = sample_header(author.public_key());
        let buf = container(&header, &author);
        let prologue = Prologue::split(&buf).unwrap();

        let mut by_prologue = Vec::new();
        prologue.signing_transcript(suite_id(&header.suite), &mut by_prologue);
        let by_verify = header_signing_transcript(prologue.header, &header.suite).unwrap();

        assert_eq!(by_verify.as_bytes(), by_prologue.as_slice());
    }

    #[test]
    fn the_suite_identifier_is_the_signature_algorithm() {
        // Значение входит в подписанные байты, поэтому менять его при
        // рефакторинге нельзя: ранее выпущенные файлы перестанут проверяться.
        assert_eq!(suite_id(&sample_suite()), 1);
    }

    #[test]
    fn a_container_shorter_than_its_own_prologue_is_refused_before_any_crypto() {
        let buf = self_consistent(&signer(1));
        for cut in 0..buf.len().min(crate::HEADER_OFFSET + 8) {
            assert!(
                matches!(
                    verify_and_parse(&buf[..cut], &EmptyTrustStore).unwrap_err(),
                    FormatError::Truncated { .. }
                ),
                "обрезание до {cut} байт не дало Truncated"
            );
        }
    }

    #[test]
    fn the_fuzzing_entry_point_accepts_what_verification_refuses() {
        // Точка входа для фаззера намеренно пропускает подпись — иначе глубокие
        // ветви декодера недостижимы. Тест фиксирует, что она именно такова, и
        // заодно объясняет, почему её имя такое неудобное.
        let author = signer(1);
        let mut buf = self_consistent(&author);
        let signature_at =
            crate::HEADER_OFFSET + sample_header(author.public_key()).encode().unwrap().len();
        buf[signature_at] ^= 0xff;

        assert_eq!(
            verify_and_parse(&buf, &EmptyTrustStore).unwrap_err(),
            BAD_HEADER_SIGNATURE
        );
        assert!(parse_without_verifying_signature_for_fuzzing_only(&buf).is_ok());
    }

    #[test]
    fn never_panics_on_arbitrary_input() {
        // Разбор обязан быть тотальным: любой буфер либо даёт структуру, либо
        // ошибку. Дешёвая замена фаззеру, работающая на каждой сборке.
        let valid = self_consistent(&signer(1));

        for cut in 0..valid.len() {
            let _ = verify_and_parse(&valid[..cut], &EmptyTrustStore);
        }

        for byte in 0u16..=255 {
            let _ = verify_and_parse(&[byte as u8; 97], &EmptyTrustStore);
        }

        // С правильной магией: иначе разбор всегда отваливается на первом
        // сравнении и глубже не заходит.
        for declared in [
            0u32,
            1,
            12,
            200,
            MAX_HEADER_LEN,
            MAX_HEADER_LEN + 1,
            u32::MAX,
        ] {
            let mut buf = Vec::new();
            buf.extend_from_slice(&MAGIC);
            buf.extend_from_slice(&declared.to_le_bytes());
            buf.extend_from_slice(&[0xff; 200]);
            let _ = verify_and_parse(&buf, &EmptyTrustStore);
        }

        // Поле, объявляющее длину больше буфера, — классический вектор выделения
        // памяти по непроверенному числу.
        for len in [u32::MAX, u32::MAX / 2, 1 << 20] {
            let mut header = Vec::new();
            header.extend_from_slice(&tag::FILE_ID.to_le_bytes());
            header.extend_from_slice(&len.to_le_bytes());
            let _ = verify_and_parse(&assemble(&header, &[0x5a; SIGNATURE_LEN]), &EmptyTrustStore);
        }
    }

    /// Читатель принимает ровно читаемый диапазон и отвергает обоих соседей.
    ///
    /// Обе границы, а не одна верхняя (§2.1 п.3). Версия ниже читаемой опаснее
    /// версии выше: она не вызывает подозрений — «это же старый файл», — хотя
    /// означает то же самое, семантику, которой у нас нет.
    ///
    /// ЧЕТВЁРКА В СПИСКЕ ОТВЕРГАЕМЫХ — ЭТО ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ РЕШЕНИЯ Р-1, а
    /// не ещё одно круглое число. Ноль и `MAX + 1` отвергались и до решения:
    /// проверка на них зеленела бы и на старом рубеже. Отличает новое поведение
    /// от старого ровно сосед снизу — версия 4, вчера читаемая, сегодня сожжённая.
    /// Единица здесь по той же причине, но слабее: она проверяет, что нижняя
    /// граница уехала от [`FIRST_CONTAINER_VERSION`], оставшегося записью истории.
    ///
    /// Перебор диапазона (а не одной [`CONTAINER_VERSION`]) держит второе
    /// свойство, ради которого этап существует: читатель узнаёт версию РАНЬШЕ,
    /// чем писатель начинает её производить. Сегодня границы совпали и перебор
    /// даёт один шаг; он снова станет содержательным в день бампа читателя.
    #[test]
    fn the_reader_accepts_all_released_versions_and_refuses_the_neighbours() {
        let signer = signer(7);

        for version in MIN_READABLE_CONTAINER_VERSION..=MAX_READABLE_CONTAINER_VERSION {
            let mut header = sample_header(signer.public_key());
            header.container_version = version;
            header.min_reader_version = version;
            let bytes = container(&header, &signer);
            assert!(
                verify_and_parse(&bytes, &EmptyTrustStore).is_ok(),
                "версия {version} объявлена читаемой, но отвергнута"
            );
        }

        for version in [
            0,
            FIRST_CONTAINER_VERSION,
            MIN_READABLE_CONTAINER_VERSION - 1,
            MAX_READABLE_CONTAINER_VERSION + 1,
        ] {
            let mut header = sample_header(signer.public_key());
            header.container_version = version;
            // Требование к клиенту берётся ЧИТАЕМОЕ, иначе отказ пришёл бы из
            // проверки `min_reader_version` — и проба зеленела бы, ничего не
            // говоря о рубеже версии формата.
            header.min_reader_version = MIN_READABLE_CONTAINER_VERSION;
            let bytes = container(&header, &signer);
            assert!(
                matches!(
                    verify_and_parse(&bytes, &EmptyTrustStore),
                    Err(FormatError::UnsupportedContainerVersion { .. })
                ),
                "версия {version} вне читаемого диапазона, но принята"
            );
        }
    }

    /// Отказ называет ту границу, по которой отказал.
    ///
    /// Отдельной пробой, а не `matches!` в соседней: «отказ случился» и «отказ
    /// объяснён верно» — разные утверждения, и первое зеленеет, когда второе
    /// сломано. Если бы `first` продолжал нести [`FIRST_CONTAINER_VERSION`],
    /// пользователю сообщалось бы «читаемый диапазон 1..=5» о читателе, который
    /// единицу не принимает, — неправда с видом диагностики.
    #[test]
    fn the_refusal_names_the_readable_range_not_the_history() {
        let signer = signer(7);
        let mut header = sample_header(signer.public_key());
        header.container_version = MIN_READABLE_CONTAINER_VERSION - 1;
        header.min_reader_version = MIN_READABLE_CONTAINER_VERSION;
        let bytes = container(&header, &signer);

        assert_eq!(
            verify_and_parse(&bytes, &EmptyTrustStore).err(),
            Some(FormatError::UnsupportedContainerVersion {
                version: MIN_READABLE_CONTAINER_VERSION - 1,
                first: MIN_READABLE_CONTAINER_VERSION,
                max: MAX_READABLE_CONTAINER_VERSION,
            }),
            "отказ назвал не ту нижнюю границу"
        );
    }

    /// Требование к читателю выше нашей поддержки — отказ, и отказ отдельный.
    ///
    /// Отдельный вариант ошибки нужен затем, чтобы номер версии ФОРМАТА не уходил
    /// наружу в поле, означающем версию КЛИЕНТА: это два разных пространства, и
    /// смешать их значит сказать пользователю неправду о том, что ему делать.
    #[test]
    fn a_container_demanding_a_newer_client_is_refused_as_such() {
        let signer = signer(7);
        let mut header = sample_header(signer.public_key());
        // Версия формата берётся ЧИТАЕМАЯ: с рубежом Р-1 файл версии 1 отвергся
        // бы раньше, по диапазону, и проба перестала бы говорить о том, ради чего
        // заведена, — о том, что требование к КЛИЕНТУ даёт свой, отдельный отказ.
        header.container_version = MIN_READABLE_CONTAINER_VERSION;
        header.min_reader_version = SUPPORTED_READER_VERSION + 1;
        let bytes = container(&header, &signer);

        assert!(
            matches!(verify_and_parse(&bytes, &EmptyTrustStore), Err(FormatError::ReaderTooOld { .. })),
            "файл требует клиента новее, а отказ пришёл не тот"
        );
    }
}
