//! Правило файла по атрибутам держателя — байты (Ф-27, B4b).
//!
//! # Зачем правило здесь, а не только в сервере
//!
//! До B4b правило жило одним типом в `cc-authority` и одним кодеком в его
//! хранилище: задавал его только оператор, командой на машине сервера, и
//! байты не выходили за пределы файла состояния. С подписанным распоряжением
//! автора (`order::Kind::SetRule`) те же байты едут по проводу под подписью —
//! а у документа, который подписывают и проверяют разные стороны, определение
//! обязано быть одно и лежать там, где лежат остальные документы.
//!
//! Раскладка совпадает с той, что хранилище писало до переезда, байт в байт:
//! файлы состояния прежних серверов читаются без правок, и отпечаток
//! состояния от обновления не меняется. Хранилище зовёт этот же кодек.
//!
//! # Раскладка
//!
//! TLV, теги по возрастанию, все критичные:
//!
//! | Тег | Поле | Значение |
//! |---|---|---|
//! | 1 | потолок срока лизы | `i64le` секунд, больше нуля; необязателен |
//! | 2 | условия выдачи | поток условий; пишется всегда, в том числе пустым |
//! | 3 | ужесточения | поток из пар `[условие, профиль]`; только если есть |
//!
//! Поток — подряд `u32le длина ‖ байты`. Условие — `u8 режим ‖ поток [атрибут,
//! значение…]`. Профиль — кодек политики (`policy_codec`, версия контейнера).
//!
//! # Что разбор отвергает сам
//!
//! Имя или значение не идентификатор; условие без значений; «не ниже» не с
//! одним значением; незнакомый режим; пределы числа условий, значений и
//! ужесточений; неположительный потолок срока; пустой поток ужесточений —
//! его писатель не производит, значит пришёл он не от писателя. Смысл имён
//! (есть ли такой атрибут в словаре) проверяет сервер: словарь — его.

use oc_policy::Policy;

use oc_format::FormatError;
use oc_format::tlv::{TlvReader, TlvWriter};

/// Предел длины имени атрибута и значения, в байтах.
pub const MAX_NAME_BYTES: usize = 64;
/// Сколько значений у одного условия (и у одного атрибута словаря).
pub const MAX_VALUES: usize = 64;
/// Сколько условий выдачи в правиле.
pub const MAX_CLAUSES: usize = 16;
/// Сколько ужесточений в правиле.
pub const MAX_TIGHTENINGS: usize = 8;

/// Теги правила. Все критичные (И-7).
pub mod tag {
    pub const MAX_LEASE: u16 = 1;
    pub const CLAUSES: u16 = 2;
    pub const TIGHTENINGS: u16 = 3;
}

/// Как условие читает значения.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode {
    /// Хотя бы одно из перечисленных.
    AnyOf = 1,
    /// Все перечисленные.
    AllOf = 2,
    /// Значение с рангом не ниже названного — по порядку значений в словаре.
    /// Значение в условии ровно одно.
    AtLeast = 3,
}

impl Mode {
    /// Обратное к `as u8`. Незнакомый номер — `None`, и разбор его отвергает.
    #[must_use]
    pub fn from_u8(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::AnyOf),
            2 => Some(Self::AllOf),
            3 => Some(Self::AtLeast),
            _ => None,
        }
    }
}

/// Одно условие правила: атрибут, режим, значения.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Clause {
    pub attribute: String,
    pub mode: Mode,
    pub values: Vec<String>,
}

/// Ужесточение по держанию: всем, кто НЕ проходит `unless`, — не больше `profile`.
///
/// Профиль — обычная политика и складывается пересечением (`docs/format.md`
/// §4.3), поэтому ужесточение не умеет ничего, чего не умеет строгий профиль
/// сервера, и расширить права автора не может.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tightening {
    /// Кого ужесточение НЕ касается.
    pub unless: Clause,
    /// Чем ужесточается политика для всех прочих.
    pub profile: Policy,
}

/// Правило файла: все условия разом (между условиями — «и»), потолок срока
/// лизы и ужесточения по держанию. Пустое правило — это отсутствие правила.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rule {
    pub clauses: Vec<Clause>,
    /// Не длиннее чем на столько выдаётся лиза устройству, прошедшему правило.
    /// Ужесточает срок автора, не расширяет: пересечение берётся минимумом.
    pub max_lease_seconds: Option<i64>,
    /// Ужесточения ДЕЙСТВИЙ по держанию. Ворота (`clauses`) решают, выдавать
    /// ли; ужесточения — что разрешено внутри выданного.
    pub tightenings: Vec<Tightening>,
}

impl Rule {
    /// Правила нет: ни условий, ни потолка срока, ни ужесточений. Потолок без
    /// условий — правило («всем, но на неделю»), и хранится как правило.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.clauses.is_empty() && self.max_lease_seconds.is_none() && self.tightenings.is_empty()
    }
}

/// Строка — идентификатор: латиница, цифры, `_ . : / -`, от 1 до
/// [`MAX_NAME_BYTES`] байт.
///
/// Набор знаков узкий намеренно: имена печатаются в журнале, в отказе и в
/// строке команды, и пробел или кавычка в них означали бы, что команду нельзя
/// прочитать обратно однозначно.
#[must_use]
pub fn is_identifier(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_NAME_BYTES
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'/' | b'-'))
}

/// Условие из строки команды: `имя=a|b` — любое, `имя=a&b` — все, `имя>=a` — не ниже.
///
/// Разбор один на `cca` и `cc`: соавторы набирают правило на своих машинах, и
/// одна и та же строка обязана дать одно и то же условие — иначе подписи легли
/// бы под разные намерения.
///
/// `>=` проверяется первым: строка с ним содержит и `=`, и разбор по `=`
/// прочёл бы «имя>» как имя. Значения с `|` и `&` идентификаторами не бывают,
/// поэтому разделители однозначны. Годность имён проверяет кодек при записи.
///
/// # Errors
/// Строка без `=` или смешивающая `|` и `&`.
pub fn parse_clause(text: &str) -> Result<Clause, &'static str> {
    if let Some((attribute, value)) = text.split_once(">=") {
        return Ok(Clause {
            attribute: attribute.to_owned(),
            mode: Mode::AtLeast,
            values: vec![value.to_owned()],
        });
    }
    let (attribute, values) = text.split_once('=').ok_or("ожидалось имя=значение")?;
    if values.contains('|') && values.contains('&') {
        return Err("«любое из» и «все» в одном условии не смешиваются");
    }
    let (mode, split): (Mode, char) =
        if values.contains('&') { (Mode::AllOf, '&') } else { (Mode::AnyOf, '|') };
    Ok(Clause {
        attribute: attribute.to_owned(),
        mode,
        values: values.split(split).map(str::to_owned).collect(),
    })
}

/// Закодировать правило.
///
/// # Errors
/// [`FormatError`], если правило не проходит те же проверки, что разбор:
/// документ, который мы отказываемся принять, мы и не выписываем.
pub fn encode(rule: &Rule) -> Result<Vec<u8>, FormatError> {
    check(rule)?;
    let mut w = TlvWriter::new();
    if let Some(seconds) = rule.max_lease_seconds {
        w.put(tag::MAX_LEASE, &seconds.to_le_bytes())?;
    }
    let mut clauses = Vec::with_capacity(rule.clauses.len());
    for clause in &rule.clauses {
        clauses.push(encode_clause(clause)?);
    }
    w.put(tag::CLAUSES, &stream(tag::CLAUSES, &clauses)?)?;
    // Только когда есть: правило без ужесточений кодируется теми же байтами,
    // что до их появления.
    if !rule.tightenings.is_empty() {
        let mut items = Vec::with_capacity(rule.tightenings.len());
        for tightening in &rule.tightenings {
            let profile = oc_format::policy_codec::encode(
                oc_format::header::CONTAINER_VERSION,
                &tightening.profile,
            )?;
            items.push(stream(tag::TIGHTENINGS, &[encode_clause(&tightening.unless)?, profile])?);
        }
        w.put(tag::TIGHTENINGS, &stream(tag::TIGHTENINGS, &items)?)?;
    }
    Ok(w.finish().to_vec())
}

/// Разобрать правило — строго.
///
/// # Errors
/// [`FormatError`] при незнакомом теге, неверной длине, незнакомом режиме,
/// имени не-идентификаторе или нарушенном пределе.
pub fn decode(bytes: &[u8]) -> Result<Rule, FormatError> {
    let mut rule = Rule::default();
    let mut clauses_seen = false;
    let mut reader = TlvReader::new(bytes);
    while let Some(field) = reader.next_field()? {
        match field.tag {
            tag::MAX_LEASE => {
                let raw: [u8; 8] = field.value.try_into().map_err(|_| FormatError::BadFieldLength {
                    tag: tag::MAX_LEASE,
                    len: field.value.len(),
                })?;
                rule.max_lease_seconds = Some(i64::from_le_bytes(raw));
            }
            tag::CLAUSES => {
                clauses_seen = true;
                for item in unstream(tag::CLAUSES, field.value, MAX_CLAUSES)? {
                    rule.clauses.push(decode_clause(item)?);
                }
            }
            tag::TIGHTENINGS => {
                let items = unstream(tag::TIGHTENINGS, field.value, MAX_TIGHTENINGS)?;
                // Пустой поток писатель не производит никогда — значит, пришёл
                // не от писателя. Принять его значило бы принять «ужесточения
                // были и пропали».
                if items.is_empty() {
                    return Err(FormatError::BadFieldLength { tag: tag::TIGHTENINGS, len: 0 });
                }
                for item in items {
                    let parts = unstream(tag::TIGHTENINGS, item, 2)?;
                    let [unless, profile] = parts.as_slice() else {
                        return Err(FormatError::BadFieldLength {
                            tag: tag::TIGHTENINGS,
                            len: parts.len(),
                        });
                    };
                    rule.tightenings.push(Tightening {
                        unless: decode_clause(unless)?,
                        profile: oc_format::policy_codec::decode(
                            oc_format::header::SUPPORTED_READER_VERSION,
                            profile,
                        )?,
                    });
                }
            }
            other => crate::unknown::refuse_if_critical(other)?,
        }
    }
    // Поток условий писатель ставит всегда, и его отсутствие — не «условий
    // нет», а документ не от писателя.
    if !clauses_seen {
        return Err(FormatError::MissingField { tag: tag::CLAUSES });
    }
    check(&rule)?;
    Ok(rule)
}

/// Проверки, общие для записи и разбора.
fn check(rule: &Rule) -> Result<(), FormatError> {
    if rule.clauses.len() > MAX_CLAUSES {
        return Err(FormatError::BadFieldLength { tag: tag::CLAUSES, len: rule.clauses.len() });
    }
    if rule.tightenings.len() > MAX_TIGHTENINGS {
        return Err(FormatError::BadFieldLength {
            tag: tag::TIGHTENINGS,
            len: rule.tightenings.len(),
        });
    }
    if rule.max_lease_seconds.is_some_and(|seconds| seconds <= 0) {
        return Err(FormatError::UnknownCriticalField { tag: tag::MAX_LEASE });
    }
    for clause in &rule.clauses {
        check_clause(clause, tag::CLAUSES)?;
    }
    for tightening in &rule.tightenings {
        check_clause(&tightening.unless, tag::TIGHTENINGS)?;
    }
    Ok(())
}

/// Условие исполнимо: имена — идентификаторы, значений не ноль и не сверх
/// предела, у «не ниже» ровно одно.
///
/// Условие без значений — не «выполнено у всех», а ошибка: встроенный ответ
/// `all()` на пустом списке — «истинно», и правило, выглядящее закрытым,
/// выполнялось бы у кого угодно (И-10).
fn check_clause(clause: &Clause, at: u16) -> Result<(), FormatError> {
    if !is_identifier(&clause.attribute) || !clause.values.iter().all(|v| is_identifier(v)) {
        return Err(FormatError::UnknownCriticalField { tag: at });
    }
    if clause.values.is_empty() || clause.values.len() > MAX_VALUES {
        return Err(FormatError::BadFieldLength { tag: at, len: clause.values.len() });
    }
    if clause.mode == Mode::AtLeast && clause.values.len() != 1 {
        return Err(FormatError::BadFieldLength { tag: at, len: clause.values.len() });
    }
    Ok(())
}

fn encode_clause(clause: &Clause) -> Result<Vec<u8>, FormatError> {
    let mut parts: Vec<Vec<u8>> = Vec::with_capacity(clause.values.len().saturating_add(1));
    parts.push(clause.attribute.as_bytes().to_vec());
    parts.extend(clause.values.iter().map(|value| value.as_bytes().to_vec()));
    let mut item = vec![clause.mode as u8];
    item.extend_from_slice(&stream(tag::CLAUSES, &parts)?);
    Ok(item)
}

fn decode_clause(item: &[u8]) -> Result<Clause, FormatError> {
    let (mode, rest) =
        item.split_first().ok_or(FormatError::BadFieldLength { tag: tag::CLAUSES, len: 0 })?;
    let mode = Mode::from_u8(*mode).ok_or(FormatError::UnknownCriticalField { tag: tag::CLAUSES })?;
    // Атрибут и значения: не больше предела значений плюс одно имя.
    let parts = unstream(tag::CLAUSES, rest, MAX_VALUES.saturating_add(1))?;
    let (attribute, values) =
        parts.split_first().ok_or(FormatError::BadFieldLength { tag: tag::CLAUSES, len: 0 })?;
    Ok(Clause {
        attribute: text(attribute)?,
        mode,
        values: values.iter().map(|value| text(value)).collect::<Result<_, _>>()?,
    })
}

fn text(bytes: &[u8]) -> Result<String, FormatError> {
    core::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| FormatError::UnknownCriticalField { tag: tag::CLAUSES })
}

/// Поток: подряд `u32le длина ‖ байты`.
fn stream<T: AsRef<[u8]>>(at: u16, items: &[T]) -> Result<Vec<u8>, FormatError> {
    let mut out = Vec::new();
    for item in items {
        let item = item.as_ref();
        let len = u32::try_from(item.len())
            .map_err(|_| FormatError::BadFieldLength { tag: at, len: item.len() })?;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(item);
    }
    Ok(out)
}

/// Разобрать поток — строго, и не дальше `limit` записей.
///
/// Предел проверяется ДО того, как записи копятся: поток в мегабайт иначе
/// заставил бы собрать тысячи записей, чтобы затем их отвергнуть. Обрыв внутри
/// записи и хвост после последней — ошибки, а не «почти правильно».
fn unstream(at: u16, bytes: &[u8], limit: usize) -> Result<Vec<&[u8]>, FormatError> {
    let mut out = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        if out.len() >= limit {
            return Err(FormatError::BadFieldLength { tag: at, len: out.len().saturating_add(1) });
        }
        let (head, tail) = rest
            .split_at_checked(4)
            .ok_or(FormatError::BadFieldLength { tag: at, len: rest.len() })?;
        let len = u32::from_le_bytes(
            head.try_into().map_err(|_| FormatError::BadFieldLength { tag: at, len: head.len() })?,
        );
        let len = usize::try_from(len).map_err(|_| FormatError::BadFieldLength { tag: at, len: tail.len() })?;
        let (item, after) = tail
            .split_at_checked(len)
            .ok_or(FormatError::BadFieldLength { tag: at, len: tail.len() })?;
        out.push(item);
        rest = after;
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use oc_policy::Action;

    fn clause(attribute: &str, mode: Mode, values: &[&str]) -> Clause {
        Clause {
            attribute: attribute.to_string(),
            mode,
            values: values.iter().map(|v| (*v).to_string()).collect(),
        }
    }

    fn sample() -> Rule {
        Rule {
            clauses: vec![
                clause("dept", Mode::AnyOf, &["legal", "production"]),
                clause("contract", Mode::AtLeast, &["2026"]),
            ],
            max_lease_seconds: Some(86_400),
            tightenings: vec![Tightening {
                unless: clause("clearance", Mode::AllOf, &["secret"]),
                profile: Policy::deny_all().allow(Action::View),
            }],
        }
    }

    #[test]
    fn a_rule_survives_the_round_trip() {
        let bytes = encode(&sample()).unwrap();
        assert_eq!(decode(&bytes).unwrap(), sample());
        // Пустое правило — законный документ: «правила нет».
        let empty = encode(&Rule::default()).unwrap();
        assert!(decode(&empty).unwrap().is_empty());
    }

    /// БЕЗ УЖЕСТОЧЕНИЙ — ПРЕЖНИЕ БАЙТЫ: тег 3 не пишется вовсе.
    #[test]
    fn without_tightenings_the_third_tag_is_absent() {
        let plain = Rule { tightenings: Vec::new(), ..sample() };
        let bytes = encode(&plain).unwrap();
        let mut reader = TlvReader::new(&bytes);
        while let Some(field) = reader.next_field().unwrap() {
            assert_ne!(field.tag, tag::TIGHTENINGS, "пустые ужесточения записаны");
        }
    }

    #[test]
    fn a_hostile_rule_is_refused_on_parsing() {
        let bad = |rule: Rule, why: &str| {
            assert!(encode(&rule).is_err(), "записано: {why}");
        };
        bad(Rule { clauses: vec![clause("dept", Mode::AnyOf, &[])], ..Rule::default() }, "пустое условие");
        bad(Rule { clauses: vec![clause("dept", Mode::AtLeast, &["a", "b"])], ..Rule::default() }, "«не ниже» двух");
        bad(Rule { clauses: vec![clause("отдел", Mode::AnyOf, &["a"])], ..Rule::default() }, "не идентификатор");
        bad(Rule { clauses: vec![clause("dept", Mode::AnyOf, &["a b"])], ..Rule::default() }, "пробел в значении");
        bad(Rule { max_lease_seconds: Some(0), ..Rule::default() }, "нулевой потолок");
        bad(
            Rule { clauses: vec![clause("dept", Mode::AnyOf, &["a"]); MAX_CLAUSES + 1], ..Rule::default() },
            "условий сверх предела",
        );

        // Незнакомый режим — байтами, писатель его не произведёт.
        let mut bytes = encode(&Rule { clauses: vec![clause("dept", Mode::AnyOf, &["a"])], ..Rule::default() }).unwrap();
        let at = bytes.iter().position(|b| *b == Mode::AnyOf as u8).unwrap();
        bytes[at] = 9;
        assert!(decode(&bytes).is_err(), "незнакомый режим разобран");

        // Условие без значений — байтами: писатель его не произведёт, а разбор
        // обязан отвергнуть сам (правило, выглядящее закрытым, выполнялось бы
        // у кого угодно).
        let mut item = vec![Mode::AllOf as u8];
        item.extend_from_slice(&stream(tag::CLAUSES, &[b"dept".to_vec()]).unwrap());
        let mut w = TlvWriter::new();
        w.put(tag::CLAUSES, &stream(tag::CLAUSES, &[item]).unwrap()).unwrap();
        assert!(decode(&w.finish()).is_err(), "условие без значений разобрано");

        // Без потока условий — не документ писателя.
        let mut w = TlvWriter::new();
        w.put(tag::MAX_LEASE, &10i64.to_le_bytes()).unwrap();
        assert!(matches!(decode(&w.finish()), Err(FormatError::MissingField { .. })));

        // Пустой поток ужесточений.
        let mut w = TlvWriter::new();
        w.put(tag::CLAUSES, &[]).unwrap();
        w.put(tag::TIGHTENINGS, &[]).unwrap();
        assert!(decode(&w.finish()).is_err(), "пустой поток ужесточений разобран");

        // Незнакомый тег.
        let mut w = TlvWriter::new();
        w.put(tag::CLAUSES, &[]).unwrap();
        w.put(9, &[1]).unwrap();
        assert!(matches!(decode(&w.finish()), Err(FormatError::UnknownCriticalField { tag: 9 })));
    }

    #[test]
    fn a_clause_is_read_from_the_command_line_one_way() {
        assert_eq!(parse_clause("dept=legal|production").unwrap(), clause("dept", Mode::AnyOf, &["legal", "production"]));
        assert_eq!(parse_clause("dept=legal&production").unwrap(), clause("dept", Mode::AllOf, &["legal", "production"]));
        assert_eq!(parse_clause("contract>=2026").unwrap(), clause("contract", Mode::AtLeast, &["2026"]));
        assert_eq!(parse_clause("dept=legal").unwrap(), clause("dept", Mode::AnyOf, &["legal"]));
        assert!(parse_clause("dept").is_err());
        assert!(parse_clause("dept=a|b&c").is_err(), "смешанное условие разобрано");
    }

    /// РАЗБОР ПРОИЗВОЛЬНЫХ БАЙТОВ НЕ ПАНИКУЕТ.
    #[test]
    fn decoding_arbitrary_bytes_never_panics() {
        let bytes = encode(&sample()).unwrap();
        for cut in 0..bytes.len() {
            let _ = decode(&bytes[..cut]);
        }
        for at in 0..bytes.len() {
            let mut damaged = bytes.clone();
            damaged[at] ^= 0xff;
            let _ = decode(&damaged);
        }
        // Поток, объявляющий огромную запись, — отказ, а не выделение.
        let mut w = TlvWriter::new();
        w.put(tag::CLAUSES, &u32::MAX.to_le_bytes()).unwrap();
        assert!(decode(&w.finish()).is_err());
    }
}
