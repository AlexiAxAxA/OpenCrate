//! Кодирование политики.
//!
//! Правило, определяющее весь модуль: **читатель, встретив то, чего не знает,
//! запрещает**. Действие с неизвестным тегом не игнорируется и не разрешается —
//! оно попадает в [`Policy::unknown_actions`] и делает файл менее доступным, а не
//! более. Благодаря этому любое действие, добавленное в будущей версии
//! (`ai_ingest`, `ocr`, `forward`), будет запрещено и старыми клиентами тоже,
//! без единой их правки.
//!
//! Обратное поведение — «не знаю поля, значит его нет, значит можно» — это
//! классический способ обойти политику, просто предъявив клиенту постарше.
//!
//! Из того же правила следует, что [`encode`] обязан выгружать неизвестные
//! действия обратно на провод: иначе клиент, который их не понял, стирает их
//! своей же перекодировкой, и следующий читатель получает политику, выглядящую
//! полностью понятой. Тогда «предъявить клиенту постарше» превращается в
//! «пропустить файл ЧЕРЕЗ клиента постарше» — тот же обход, только в два шага.
//!
//! То же правило распространяется на ОТСУТСТВИЕ поля, а не только на неизвестный
//! тег (§4: «отсутствующее поле означает запрет»). Опасность здесь в том, что у
//! ограничения «нулевое» значение обычно и означает «ограничения нет»: `false` у
//! обязанности снимает обязанность, `None` у лимита снимает лимит. Поэтому
//! отсутствующее поле НИКОГДА не читается как значение по умолчанию из
//! `Default` — оно читается либо как отказ разбора, либо как самое строгое из
//! осмысленных значений. Что именно выбрано для каждого поля и почему — в
//! документации [`decode`].

use crate::tlv::{TlvReader, TlvWriter};
use crate::FormatError;
use oc_policy::{Action, Binding, Network, Policy, Rule, Timestamp, Validity};
use std::collections::BTreeMap;

/// Теги полей политики.
///
/// Значения входят в подписанные автором байты, поэтому менять их нельзя: ранее
/// выпущенные файлы перестанут читаться.
pub mod tag {
    pub const ACTIONS: u16 = 1;
    pub const VALIDITY: u16 = 2;
    pub const NETWORK: u16 = 3;
    pub const MIN_BINDING: u16 = 4;
    pub const MAX_OPENS: u16 = 5;
    pub const WATERMARK: u16 = 6;
    /// Требование привязки НА ДЕЙСТВИЕ. **Начиная с версии 4.**
    ///
    /// Диапазон критичный намеренно, и это важнее, чем кажется: будь тег
    /// необязательным, клиент версии 2 пропустил бы его молча — и разрешил бы
    /// правку с программной ступени там, где автор потребовал аппаратную.
    /// Необязательное поле политики, ужесточающее требование, есть противоречие
    /// в терминах: пропустивший его клиент исполняет НЕ ту политику, которую
    /// подписал автор.
    pub const ACTION_BINDING: u16 = 7;
}

/// Теги действий внутри поля `ACTIONS`.
mod action_tag {
    pub const VIEW: u16 = 1;
    pub const EDIT: u16 = 2;
    pub const PRINT: u16 = 3;
    pub const CLIPBOARD: u16 = 4;
    pub const EXPORT: u16 = 5;
    pub const SCREENSHOT: u16 = 6;
}

/// Числовой вид разрешения. Всё, что не [`RULE_ALLOW`], — запрет.
const RULE_ALLOW: u8 = 1;
const RULE_DENY: u8 = 0;

const VALIDITY_ALWAYS: u8 = 1;
const VALIDITY_WINDOW: u8 = 2;
const VALIDITY_FROM_FIRST_OPEN: u8 = 3;

const NETWORK_STRICT_ONLINE: u8 = 1;
const NETWORK_LEASE: u8 = 2;

/// Сколько открытий разрешено, если поля [`tag::MAX_OPENS`] в политике нет вовсе.
///
/// Не `None` («без лимита») и не `0` («не открывать никогда»), а ровно одно
/// открытие — самое узкое разрешение, при котором файл всё-таки остаётся
/// открываемым. Обоснование в документации [`decode`].
const OPENS_WHEN_THE_FIELD_IS_ABSENT: u32 = 1;

const BINDING_SOFTWARE: u8 = 1;
const BINDING_HARDWARE: u8 = 2;
const BINDING_HARDWARE_ATTESTED: u8 = 3;

fn action_to_tag(action: Action) -> u16 {
    match action {
        Action::View => action_tag::VIEW,
        Action::Edit => action_tag::EDIT,
        Action::Print => action_tag::PRINT,
        Action::Clipboard => action_tag::CLIPBOARD,
        Action::Export => action_tag::EXPORT,
        Action::Screenshot => action_tag::SCREENSHOT,
    }
}

fn tag_to_action(tag: u16) -> Option<Action> {
    match tag {
        action_tag::VIEW => Some(Action::View),
        action_tag::EDIT => Some(Action::Edit),
        action_tag::PRINT => Some(Action::Print),
        action_tag::CLIPBOARD => Some(Action::Clipboard),
        action_tag::EXPORT => Some(Action::Export),
        action_tag::SCREENSHOT => Some(Action::Screenshot),
        _ => None,
    }
}

/// Первая версия формата, знающая требование привязки на действие.
pub const FIRST_ACTION_BINDING_VERSION: u16 = 4;

/// Закодировать политику ДЛЯ НАЗВАННОЙ ВЕРСИИ контейнера.
///
/// Версия параметром, а не константой, по той же причине, по какой длины слота —
/// функция пары: тег 7 критичен, и записав его в контейнер версии 3, писатель
/// сделал бы файл нечитаемым для добросовестного читателя той же версии. Версия
/// решает, что вообще существует, а не только что мы умеем.
pub fn encode(version: u16, policy: &Policy) -> Result<Vec<u8>, FormatError> {
    let mut w = TlvWriter::new();

    // Действия пишутся все шесть, включая запрещённые. Писать только разрешения
    // было бы короче, но тогда «действие запрещено» и «поле потеряно при
    // повреждении» стали бы неразличимы.
    //
    // Вместе с ними пишутся действия, которых ЭТОТ клиент не знает. Раньше их
    // писать было нечем: [`decode`] честно складывал их теги в
    // [`Policy::unknown_actions`], а сюда они не доезжали — и круг
    // decode → encode стирал сам факт «правила поняты не целиком». Политика,
    // прошедшая через клиента постарше, становилась слабее, чем её написал
    // автор: тег исчезал, следующий читатель видел полностью понятую политику,
    // и `oc_policy::evaluate` пропускал то, что обязан был запретить. Прогнать
    // файл через старую версию — приём слишком дешёвый, чтобы оставлять его
    // работающим.
    //
    // Теги внутри ACTIONS обязаны строго возрастать, а неизвестный тег может
    // оказаться где угодно среди известных (тег 0 или 7 так же законен, как
    // 999), поэтому известные и неизвестные сливаются в одну упорядоченную по
    // тегу карту, а не дописываются в конец: дописав, мы получили бы
    // `FieldsOutOfOrder` на первом же теге меньше шести.
    let mut actions_by_tag: BTreeMap<u16, u8> = BTreeMap::new();

    // Значением неизвестного действия пишется ЗАПРЕТ. Клиент не понял, что это
    // за действие, и потому не вправе от имени автора утверждать, что тот его
    // разрешил: пиши мы сюда `RULE_ALLOW`, противнику хватило бы прогнать
    // запрещающую политику через старого клиента, чтобы получить разрешение —
    // то есть та же брешь, только с другой стороны. Обратная потеря (автор
    // разрешил, записан запрет) идёт в строгую сторону: доступа она не
    // добавляет, а тег на месте, поэтому новый клиент видит, что действие
    // упомянуто. Сохранить и байт разрешения сегодня негде —
    // `Policy::unknown_actions` хранит только тег; расширять её ради
    // послабления, которого никто не проверял, было бы обменом безопасности на
    // удобство.
    for unknown in &policy.unknown_actions {
        let _ = actions_by_tag.insert(*unknown, RULE_DENY);
    }

    for action in [
        Action::View,
        Action::Edit,
        Action::Print,
        Action::Clipboard,
        Action::Export,
        Action::Screenshot,
    ] {
        let rule = if policy.rule(action) == Rule::Allow { RULE_ALLOW } else { RULE_DENY };
        // Известное действие затирает заглушку-запрет с тем же тегом. `decode`
        // такого не порождает (в `unknown_actions` попадают ровно те теги, для
        // которых `tag_to_action` вернул `None`), но `Policy` — открытая
        // структура, и собранная руками она не должна ни ронять запись, ни
        // порождать дубликат тега: на проводе окажется настоящее правило
        // автора, а не заглушка.
        let _ = actions_by_tag.insert(action_to_tag(action), rule);
    }

    let mut actions = TlvWriter::new();
    for (action_tag, rule) in &actions_by_tag {
        // `from_ref` вместо `&[*rule]` — тот же байт без копии и без индексации.
        actions.put(*action_tag, core::slice::from_ref(rule))?;
    }
    w.put(tag::ACTIONS, &actions.finish())?;

    w.put(tag::VALIDITY, &encode_validity(policy.validity))?;
    w.put(tag::NETWORK, &encode_network(policy.network))?;
    w.put(tag::MIN_BINDING, &[encode_binding(policy.min_binding)])?;

    // Лимит открытий пишется ВСЕГДА, в том числе когда его нет: пустое значение
    // и есть написанное автором «лимита я не ставил». Раньше `None` не занимал
    // места, и «автор не ставил лимита» было байт в байт неотличимо от «поле
    // потеряно (или срезано) по дороге» — а различать их обязательно, потому что
    // первое законно, а второе означает, что прочитаны не те правила.
    let max_opens = policy.max_opens.map(u32::to_le_bytes);
    let max_opens_value: &[u8] = match max_opens {
        Some(ref bytes) => bytes.as_slice(),
        None => &[],
    };
    w.put(tag::MAX_OPENS, max_opens_value)?;

    w.put(tag::WATERMARK, &[u8::from(policy.watermark)])?;

    // Требования на действие пишутся ВСЕ известные, как и сами действия, и по
    // той же причине: иначе «своего требования нет» и «поле потеряно» стали бы
    // неразличимы. Отсутствие записи означало бы послабление, а послаблений это
    // поле не выражает вовсе.
    //
    // Запись появляется только с версии 4. У версий 1–3 тег 7 не определён, и
    // записать его туда значило бы задним числом изменить, что эти версии умеют
    // читать, — ровно то, от чего защищает заморозка.
    if version >= FIRST_ACTION_BINDING_VERSION {
        let mut bindings = TlvWriter::new();
        for action in ALL_ACTIONS {
            bindings.put(
                action_to_tag(action),
                &[encode_binding(policy.action_binding.get(&action).copied().unwrap_or(oc_policy::Binding::Software))],
            )?;
        }
        w.put(tag::ACTION_BINDING, &bindings.finish())?;
    }

    Ok(w.finish().to_vec())
}

/// Шесть действий, известных этой сборке, в порядке возрастания тега.
///
/// Общий список для обоих мест, где «все действия» выписываются подряд: разойдись
/// они — и одно поле политики описывало бы другой набор действий, чем соседнее.
const ALL_ACTIONS: [Action; 6] = [
    Action::View,
    Action::Edit,
    Action::Print,
    Action::Clipboard,
    Action::Export,
    Action::Screenshot,
];

fn encode_validity(validity: Validity) -> Vec<u8> {
    let mut out = Vec::with_capacity(17);
    match validity {
        Validity::Always => out.push(VALIDITY_ALWAYS),
        Validity::Window { not_before, not_after } => {
            out.push(VALIDITY_WINDOW);
            out.extend_from_slice(&not_before.0.to_le_bytes());
            out.extend_from_slice(&not_after.0.to_le_bytes());
        }
        Validity::FromFirstOpen { seconds } => {
            out.push(VALIDITY_FROM_FIRST_OPEN);
            out.extend_from_slice(&seconds.to_le_bytes());
        }
    }
    out
}

fn encode_network(network: Network) -> Vec<u8> {
    let mut out = Vec::with_capacity(17);
    match network {
        Network::StrictOnline => out.push(NETWORK_STRICT_ONLINE),
        Network::Lease { seconds, max_offline_seconds } => {
            out.push(NETWORK_LEASE);
            out.extend_from_slice(&seconds.to_le_bytes());
            out.extend_from_slice(&max_offline_seconds.to_le_bytes());
        }
    }
    out
}

fn encode_binding(binding: Binding) -> u8 {
    match binding {
        Binding::Software => BINDING_SOFTWARE,
        Binding::Hardware => BINDING_HARDWARE,
        Binding::HardwareAttested => BINDING_HARDWARE_ATTESTED,
    }
}

/// Разобрать политику.
///
/// Тотальна. Отсутствующее поле НИКОГДА не читается как значение по умолчанию:
/// молчаливая подстановка превратила бы повреждённый или урезанный файл в файл с
/// другими правилами, причём в сторону послаблений, — а по §4 отсутствие обязано
/// работать в сторону запрета.
///
/// Что означает отсутствие каждого поля — разобрано по одному, потому что общего
/// ответа тут нет, а «очевидный» ответ у половины полей неверный.
///
/// Поля-**правила**. Их четыре, они были в формате с первого дня, и файл без
/// любого из них — не строгий файл, а файл, правила которого до нас не доехали.
/// Открыть такой как валидный значит скрыть от пользователя порчу или подмену,
/// поэтому отсутствие любого из них — [`FormatError::MissingField`]:
///
/// * `ACTIONS` — иначе набор действий был бы пуст, и файл «открылся», не дав
///   ничего сделать: пользователь увидел бы неисправность вместо честного
///   отказа. (Отсутствие ОТДЕЛЬНОГО действия ВНУТРИ поля — другое дело: это
///   запрет, основа — `Policy::deny_all`.)
/// * `VALIDITY` — «нет срока» превратилось бы в «навсегда», слабейшее значение.
/// * `NETWORK` — «нет требования сети» превратилось бы в «оффлайн всегда можно».
/// * `MIN_BINDING` — пустое место превратилось бы в `Software`, слабейшую привязку.
///
/// Поля-**модификаторы** поверх уже прочитанных правил. Их отсутствие не мешает
/// понять, что автор разрешил, поэтому отказывать в открытии — цена без пользы:
/// это сломало бы каждый файл, записанный версией, в которой поля ещё не было,
/// ради защиты, которой достигает и строгое чтение. Здесь отсутствие означает
/// самое строгое ОСМЫСЛЕННОЕ значение:
///
/// * `WATERMARK` — знак требуется. Это и была находка: `false` по умолчанию молча
///   снимал обязанность, наложенную автором, — достаточно было срезать поле.
///   Обратная ошибка невозможна: лишний водяной знак файл не ломает.
/// * `MAX_OPENS` — `OPENS_WHEN_THE_FIELD_IS_ABSENT`, то есть одно открытие.
///   Тут стоит остановиться, потому что рассуждение неочевидное. «Автор не
///   ставил лимита» — законное состояние политики, и выдумывать за автора число
///   читатель не вправе; в этом смысле отсутствие лимита действительно не
///   послабление. Но именно поэтому «лимита нет» обязано быть НАПИСАНО:
///   [`encode`] всегда пишет поле, а `None` кодирует пустым значением. Тогда
///   остаются ровно два случая. Поле есть и пусто — воля автора, читаем `None`.
///   Поля нет вовсе — значит его срезали, потеряли или его не умела писать
///   чужая реализация; о воле автора мы не знаем НИЧЕГО, и прочитать это
///   незнание как «открывай сколько хочешь» значит выдать самое слабое из
///   возможных значений за подписанное автором. Ноль («не открывать никогда»)
///   не годится: он превращает срезанное поле в неоткрываемый файл, то есть
///   даёт противнику дешёвый отказ в обслуживании. Единица — граница между
///   этими двумя ошибками: получатель откроет файл, но однократно, и разница с
///   намерением автора станет видна сразу, а не молча.
///
/// Проверка того, что ни одна комбинация отсутствующих полей не ослабляет
/// политику, — тест `no_absent_field_ever_makes_the_policy_weaker`.
pub fn decode(version: u16, bytes: &[u8]) -> Result<Policy, FormatError> {
    let mut reader = TlvReader::new(bytes);
    let mut policy = Policy::deny_all();

    // Строгое чтение модификаторов ставится ДО разбора, а не подставляется после
    // него: так «поля не было» и «поле было и его разобрали» проходят по одному
    // и тому же пути, и добавить сюда новое поле, забыв про его отсутствие,
    // нельзя — забытое поле останется в строгом значении, а не в `Default`.
    // `Policy::deny_all` даёт `watermark: false` и `max_opens: None` — оба
    // значения слабейшие, и оставить их значило бы вернуть ровно ту находку,
    // против которой написан этот блок.
    policy.watermark = true;
    policy.max_opens = Some(OPENS_WHEN_THE_FIELD_IS_ABSENT);

    let mut seen_actions = false;
    let mut seen_validity = false;
    let mut seen_network = false;
    let mut seen_binding = false;
    let mut seen_action_binding = false;

    while let Some(field) = reader.next_field()? {
        match field.tag {
            tag::ACTIONS => {
                decode_actions(field.value, &mut policy)?;
                seen_actions = true;
            }
            tag::VALIDITY => {
                policy.validity = decode_validity(field.tag, field.value)?;
                seen_validity = true;
            }
            tag::NETWORK => {
                policy.network = decode_network(field.tag, field.value)?;
                seen_network = true;
            }
            tag::MIN_BINDING => {
                policy.min_binding = decode_binding(field.tag, field.u8()?)?;
                seen_binding = true;
            }
            tag::MAX_OPENS => policy.max_opens = decode_max_opens(field.tag, field.value)?,
            tag::WATERMARK => {
                // Проверка «не ноль», а не «равно единице», — намеренная
                // зеркалка к байту разрешения: там строгая сторона — запрет, и
                // разрешением считается ровно одно значение; здесь строгая
                // сторона — знак нанесён, поэтому снять обязанность может
                // только явный ноль, а значение из будущей версии (скажем,
                // «знак с QR-кодом») читается как «знак нужен».
                policy.watermark = field.u8()? != 0;
            }
            // Требование привязки на действие существует с версии 4. У версий
            // 1–3 тег 7 не определён, и принять его там значило бы задним
            // числом дать этим версиям семантику, которой у них не было, — тот
            // же довод, по которому длина слота есть функция ПАРЫ.
            tag::ACTION_BINDING if version >= FIRST_ACTION_BINDING_VERSION => {
                decode_action_binding(field.value, &mut policy)?;
                seen_action_binding = true;
            }
            // Неизвестный тег внутри политики трактуется как критичный
            // независимо от диапазона: политика — это и есть то, что клиент
            // обязан исполнить целиком. Пропустить её кусок значит исполнить
            // не то, что подписал автор.
            other => return Err(FormatError::UnknownCriticalField { tag: other }),
        }
    }

    for (present, tag) in [
        (seen_actions, tag::ACTIONS),
        (seen_validity, tag::VALIDITY),
        (seen_network, tag::NETWORK),
        (seen_binding, tag::MIN_BINDING),
    ] {
        if !present {
            return Err(FormatError::MissingField { tag });
        }
    }

    // С версии 4 поле ОБЯЗАТЕЛЬНО, и это не педантизм. Оно умеет только
    // ужесточать, поэтому его отсутствие — единственная сторона, в которую
    // срезание поля даёт послабление: нет записи — нет и поднятой ступени.
    // Требовать его наличия дешевле, чем догадываться, что автор имел в виду.
    if version >= FIRST_ACTION_BINDING_VERSION && !seen_action_binding {
        return Err(FormatError::MissingField { tag: tag::ACTION_BINDING });
    }

    Ok(policy)
}

/// Разобрать требования привязки на действие.
///
/// Неизвестное действие здесь НЕ откладывается в `unknown_actions`: туда его уже
/// положил разбор самого поля `actions`, а требование к действию, которого
/// клиент не знает, ничего к запрету не добавляет — запрет уже полный.
/// Незнакомая же СТУПЕНЬ отвергает файл: значение из будущей версии означает
/// требование строже известных нам, и прочитать его как «сойдёт программная»
/// значило бы исполнить не ту политику, которую подписал автор.
fn decode_action_binding(bytes: &[u8], policy: &mut Policy) -> Result<(), FormatError> {
    let mut reader = TlvReader::new(bytes);
    while let Some(field) = reader.next_field()? {
        let binding = decode_binding(field.tag, field.u8()?)?;
        // Слабейшая ступень В КАРТУ НЕ КЛАДЁТСЯ, и это не экономия памяти.
        //
        // На проводе выписываются все шесть действий — иначе «своего требования
        // нет» и «поле потеряно» стали бы неразличимы. Но `Software` не
        // ужесточает ничего: действующее требование есть `max(min_binding, …)`,
        // и запись, равная слабейшему, значит ровно то же, что её отсутствие.
        // Храня её, мы завели бы два представления одного смысла — и круг
        // «разобрать → собрать» перестал бы быть тождественным, хотя байты
        // сходятся.
        if binding == oc_policy::Binding::Software {
            continue;
        }
        if let Some(action) = tag_to_action(field.tag) {
            let _ = policy.action_binding.insert(action, binding);
        }
    }
    Ok(())
}

fn decode_actions(bytes: &[u8], policy: &mut Policy) -> Result<(), FormatError> {
    let mut reader = TlvReader::new(bytes);
    while let Some(field) = reader.next_field()? {
        let rule_byte = field.u8()?;
        match tag_to_action(field.tag) {
            Some(action) => {
                // Разрешением считается ровно одно значение. Любое другое —
                // запрет, а не ошибка: файл, записанный будущей версией с новым
                // видом разрешения (скажем, «спросить пользователя»), обязан
                // читаться старым клиентом как запрет, а не отвергаться целиком.
                if rule_byte == RULE_ALLOW {
                    policy.actions.insert(action, Rule::Allow);
                }
            }
            // Действие, которого этот клиент не знает. Оно НЕ игнорируется:
            // факт его присутствия сохраняется, и уровень выше вправе отказать
            // в открытии файла, чьи правила понял не полностью.
            None => {
                let _ = policy.unknown_actions.insert(field.tag);
            }
        }
    }
    Ok(())
}

fn decode_validity(tag: u16, bytes: &[u8]) -> Result<Validity, FormatError> {
    let (kind, rest) = split_kind(tag, bytes)?;
    match kind {
        VALIDITY_ALWAYS if rest.is_empty() => Ok(Validity::Always),
        VALIDITY_WINDOW => {
            let (before, after) = two_i64(tag, rest)?;
            Ok(Validity::Window { not_before: Timestamp(before), not_after: Timestamp(after) })
        }
        VALIDITY_FROM_FIRST_OPEN => Ok(Validity::FromFirstOpen { seconds: one_i64(tag, rest)? }),
        _ => Err(FormatError::BadFieldLength { tag, len: bytes.len() }),
    }
}

fn decode_network(tag: u16, bytes: &[u8]) -> Result<Network, FormatError> {
    let (kind, rest) = split_kind(tag, bytes)?;
    match kind {
        NETWORK_STRICT_ONLINE if rest.is_empty() => Ok(Network::StrictOnline),
        NETWORK_LEASE => {
            let (seconds, max_offline_seconds) = two_i64(tag, rest)?;
            Ok(Network::Lease { seconds, max_offline_seconds })
        }
        _ => Err(FormatError::BadFieldLength { tag, len: bytes.len() }),
    }
}

/// Разобрать лимит открытий: пустое значение — «автор лимита не ставил»,
/// четыре байта — лимит.
///
/// Пустое значение — единственный способ сказать «без лимита», и сказать его
/// может только автор, потому что оно попадает под подпись. Длина проверяется
/// точно, а не подгоняется: значение из трёх байтов не дополняется нулём до
/// `u32` — иначе противник, срезав байт, управлял бы величиной лимита. Любая
/// другая длина — ошибка, а НЕ «считаем, что лимита нет»: именно такое
/// великодушие и есть послабление через порчу файла.
fn decode_max_opens(tag: u16, bytes: &[u8]) -> Result<Option<u32>, FormatError> {
    match bytes {
        [] => Ok(None),
        _ => <[u8; 4]>::try_from(bytes)
            .map(|b| Some(u32::from_le_bytes(b)))
            .map_err(|_| FormatError::BadFieldLength { tag, len: bytes.len() }),
    }
}

fn decode_binding(tag: u16, value: u8) -> Result<Binding, FormatError> {
    match value {
        BINDING_SOFTWARE => Ok(Binding::Software),
        BINDING_HARDWARE => Ok(Binding::Hardware),
        BINDING_HARDWARE_ATTESTED => Ok(Binding::HardwareAttested),
        // Неизвестная прочность привязки НЕ округляется до ближайшей известной:
        // округлив вниз, клиент ослабил бы требование автора, а округлив
        // вверх — не открыл бы файл, который открыть был должен. Отказ честнее.
        _ => Err(FormatError::BadFieldLength { tag, len: 1 }),
    }
}

fn split_kind(tag: u16, bytes: &[u8]) -> Result<(u8, &[u8]), FormatError> {
    match bytes.split_first() {
        Some((kind, rest)) => Ok((*kind, rest)),
        None => Err(FormatError::BadFieldLength { tag, len: 0 }),
    }
}

fn one_i64(tag: u16, bytes: &[u8]) -> Result<i64, FormatError> {
    <[u8; 8]>::try_from(bytes)
        .map(i64::from_le_bytes)
        .map_err(|_| FormatError::BadFieldLength { tag, len: bytes.len() })
}

fn two_i64(tag: u16, bytes: &[u8]) -> Result<(i64, i64), FormatError> {
    let pair = <[u8; 16]>::try_from(bytes)
        .map_err(|_| FormatError::BadFieldLength { tag, len: bytes.len() })?;
    let first = pair.get(0..8).and_then(|s| <[u8; 8]>::try_from(s).ok());
    let second = pair.get(8..16).and_then(|s| <[u8; 8]>::try_from(s).ok());
    match (first, second) {
        (Some(a), Some(b)) => Ok((i64::from_le_bytes(a), i64::from_le_bytes(b))),
        _ => Err(FormatError::BadFieldLength { tag, len: bytes.len() }),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    /// ТРЕБОВАНИЕ НА ДЕЙСТВИЕ ПЕРЕЖИВАЕТ КРУГ КОДИРОВАНИЯ — В ВЕРСИИ 4.
    #[test]
    fn a_per_action_binding_survives_the_round_trip_in_version_four() {
        let mut policy = Policy::deny_all();
        let _ = policy.action_binding.insert(Action::Edit, Binding::Hardware);
        let _ = policy.action_binding.insert(Action::Print, Binding::HardwareAttested);

        let bytes = encode(4, &policy).unwrap();
        let back = decode(4, &bytes).unwrap();
        assert_eq!(back.action_binding.get(&Action::Edit), Some(&Binding::Hardware));
        assert_eq!(back.action_binding.get(&Action::Print), Some(&Binding::HardwareAttested));
        // На проводе все шесть действий выписаны, но в карту слабейшая ступень
        // не кладётся: она не ужесточает ничего, и запись, равная `Software`,
        // значит то же, что её отсутствие. Два представления одного смысла —
        // это то, что однажды разъезжается.
        assert_eq!(back.action_binding.get(&Action::View), None);
        // Байты при этом полны: круг «собрать → разобрать → собрать» тождественен.
        assert_eq!(encode(4, &back).unwrap(), bytes);
    }

    /// В ВЕРСИЯХ 1–3 ТЕГ 7 НЕ СУЩЕСТВУЕТ, И ЕГО ПОЯВЛЕНИЕ ОТВЕРГАЕТ ПОЛИТИКУ.
    ///
    /// Принять его там значило бы задним числом дать этим версиям семантику,
    /// которой у них не было, — тот же довод, по которому длина слота есть
    /// функция ПАРЫ (версия, механизм).
    #[test]
    fn version_three_does_not_know_the_tag_and_refuses_it() {
        let mut policy = Policy::deny_all();
        let _ = policy.action_binding.insert(Action::Edit, Binding::Hardware);
        let four = encode(4, &policy).unwrap();
        assert!(
            matches!(decode(3, &four), Err(FormatError::UnknownCriticalField { tag: 7 })),
            "версия 3 приняла поле, которого у неё нет"
        );
        // И обратное: писатель версии 3 его не создаёт.
        let three = encode(3, &policy).unwrap();
        assert!(decode(3, &three).is_ok(), "писатель версии 3 записал тег из будущего");
    }

    /// В ВЕРСИИ 4 ПОЛЕ ОБЯЗАТЕЛЬНО: СРЕЗАННОЕ — ЭТО ПОСЛАБЛЕНИЕ.
    ///
    /// Единственная сторона, в которую потеря этого поля даёт послабление, —
    /// его отсутствие: нет записи, нет и поднятой ступени. Поэтому отсутствие
    /// обязано быть отказом, а не догадкой о намерении автора.
    #[test]
    fn in_version_four_a_missing_field_is_a_refusal_rather_than_a_guess() {
        let policy = Policy::deny_all();
        let three = encode(3, &policy).unwrap();
        assert!(
            matches!(decode(4, &three), Err(FormatError::MissingField { tag: 7 })),
            "версия 4 приняла политику без требований на действие"
        );
    }

    /// Версия, под которой собираются политики в пробах ниже.
    ///
    /// Единица, а не текущая: пробы строят TLV политики руками и тега 7 не
    /// пишут, а с версии 4 он обязателен. Смысл проб при этом не меняется — они
    /// проверяют разбор полей 1–6, общих для всех версий.
    const POLICY_TEST_VERSION: u16 = 1;

    use super::*;

    /// Каждый номер на проводе зафиксирован ЯВНО, а не через собственные константы.
    ///
    /// Смысл теста в том, что он повторяет числа из §4 руками. Сверка
    /// `BINDING_SOFTWARE == BINDING_SOFTWARE` доказывала бы только внутреннюю
    /// согласованность кода — а разошлись как раз код и **документ**: §4 называл
    /// `0 Software, 1 Hardware, 2 HardwareAttested`, код писал `1/2/3`. Обе стороны
    /// сдвига вредны: файл по документу отвергался как повреждённый, а `1 = Hardware`
    /// по документу читалось бы как `Software` — молчаливое ослабление того поля,
    /// про которое §4 настаивает, что ослабление невозможно.
    ///
    /// Ноль у привязки не занят намеренно: обнулённое или срезанное поле обязано
    /// отвергаться, а не читаться как самая слабая привязка.
    #[test]
    fn every_wire_number_matches_the_specification_literally() {
        assert_eq!(RULE_ALLOW, 1);
        assert_eq!(RULE_DENY, 0);

        assert_eq!(VALIDITY_ALWAYS, 1);
        assert_eq!(VALIDITY_WINDOW, 2);
        assert_eq!(VALIDITY_FROM_FIRST_OPEN, 3);

        assert_eq!(NETWORK_STRICT_ONLINE, 1);
        assert_eq!(NETWORK_LEASE, 2);

        assert_eq!(BINDING_SOFTWARE, 1);
        assert_eq!(BINDING_HARDWARE, 2);
        assert_eq!(BINDING_HARDWARE_ATTESTED, 3);
        assert_eq!(decode_binding(tag::MIN_BINDING, 0), Err(FormatError::BadFieldLength {
            tag: tag::MIN_BINDING,
            len: 1
        }), "ноль принят как привязка: обнулённое поле стало бы самым слабым разрешением");

        assert_eq!(OPENS_WHEN_THE_FIELD_IS_ABSENT, 1);

        // Раскладка вариантов: вид первым байтом, поля little-endian.
        assert_eq!(encode_validity(Validity::Always), vec![1]);
        assert_eq!(
            encode_validity(Validity::Window {
                not_before: Timestamp(0x0102_0304_0506_0708),
                not_after: Timestamp(-1),
            }),
            [&[2u8][..], &0x0102_0304_0506_0708i64.to_le_bytes()[..], &(-1i64).to_le_bytes()[..]]
                .concat()
        );
        assert_eq!(
            encode_validity(Validity::FromFirstOpen { seconds: 3600 }),
            [&[3u8][..], &3600i64.to_le_bytes()[..]].concat()
        );
        assert_eq!(encode_network(Network::StrictOnline), vec![1]);
        assert_eq!(
            encode_network(Network::Lease { seconds: 8 * 3600, max_offline_seconds: 3600 }),
            [&[2u8][..], &(8i64 * 3600).to_le_bytes()[..], &3600i64.to_le_bytes()[..]].concat()
        );
    }

    const ALL_ACTIONS: [Action; 6] = [
        Action::View,
        Action::Edit,
        Action::Print,
        Action::Clipboard,
        Action::Export,
        Action::Screenshot,
    ];

    fn rich_policy() -> Policy {
        Policy {
            validity: Validity::Window {
                not_before: Timestamp(1_700_000_000),
                not_after: Timestamp(1_800_000_000),
            },
            network: Network::Lease { seconds: 28_800, max_offline_seconds: 28_800 },
            min_binding: Binding::HardwareAttested,
            max_opens: Some(5),
            watermark: true,
            ..Policy::deny_all()
        }
        .allow(Action::View)
        .allow(Action::Print)
    }

    #[test]
    fn a_policy_round_trips_through_encode_and_decode() {
        for policy in [
            Policy::deny_all(),
            rich_policy(),
            Policy { validity: Validity::FromFirstOpen { seconds: 3600 }, ..Policy::deny_all() },
            Policy { network: Network::StrictOnline, ..Policy::deny_all() }.allow(Action::Edit),
        ] {
            let bytes = encode(POLICY_TEST_VERSION, &policy).unwrap();
            let back = decode(POLICY_TEST_VERSION, &bytes).unwrap();
            for action in ALL_ACTIONS {
                assert_eq!(back.rule(action), policy.rule(action), "действие {action:?}");
            }
            assert_eq!(back.validity, policy.validity);
            assert_eq!(back.network, policy.network);
            assert_eq!(back.min_binding, policy.min_binding);
            assert_eq!(back.max_opens, policy.max_opens);
            assert_eq!(back.watermark, policy.watermark);
        }
    }

    /// Тело политики со всеми шестью полями: перечисленные действия разрешены,
    /// остальное — самое мягкое из допустимого, чтобы тест проверял ровно то,
    /// что заявлено, а не спотыкался о недостающее поле.
    fn policy_bytes_with_actions(actions: &[u8]) -> Vec<u8> {
        let mut w = TlvWriter::new();
        w.put(tag::ACTIONS, actions).unwrap();
        w.put(tag::VALIDITY, &encode_validity(Validity::Always)).unwrap();
        w.put(tag::NETWORK, &encode_network(Network::StrictOnline)).unwrap();
        w.put(tag::MIN_BINDING, &[BINDING_SOFTWARE]).unwrap();
        w.put(tag::MAX_OPENS, &[]).unwrap();
        w.put(tag::WATERMARK, &[1]).unwrap();
        w.finish().to_vec()
    }

    #[test]
    fn an_action_this_client_does_not_know_is_denied_and_remembered() {
        // Главное свойство модуля. Будущее действие вроде `ai_ingest` обязано
        // быть запрещено старым клиентом — и клиент обязан ЗНАТЬ, что чего-то не
        // понял, иначе он не сможет честно сказать об этом пользователю.
        let mut actions = TlvWriter::new();
        actions.put(action_tag::VIEW, &[RULE_ALLOW]).unwrap();
        actions.put(999, &[RULE_ALLOW]).unwrap();

        let policy = decode(POLICY_TEST_VERSION, &policy_bytes_with_actions(&actions.finish())).unwrap();
        assert_eq!(policy.rule(Action::View), Rule::Allow);
        assert!(policy.unknown_actions.contains(&999), "неизвестное действие потеряно");
        for action in ALL_ACTIONS {
            if action != Action::View {
                assert_eq!(policy.rule(action), Rule::Deny);
            }
        }
    }

    /// Теги действий и их байты разрешения из закодированной политики, по порядку.
    fn encoded_action_fields(policy: &Policy) -> Vec<(u16, Vec<u8>)> {
        let bytes = encode(POLICY_TEST_VERSION, policy).unwrap();
        let mut reader = TlvReader::new(&bytes);
        let mut out = Vec::new();
        while let Some(field) = reader.next_field().unwrap() {
            if field.tag == tag::ACTIONS {
                let mut inner = TlvReader::new(field.value);
                while let Some(action) = inner.next_field().unwrap() {
                    out.push((action.tag, action.value.to_vec()));
                }
            }
        }
        out
    }

    #[test]
    fn re_encoding_a_policy_keeps_every_action_this_client_did_not_understand() {
        // Круг decode → encode → decode обязан сохранять непонятые действия
        // дословно. Иначе прогон файла через клиента постарше — а это одна
        // команда — превращал политику в «полностью понятую», и запрет,
        // который `evaluate` ставит по `unknown_actions`, переставал
        // срабатывать: действие из будущей версии просто исчезало из правил.
        //
        // Теги взяты по обе стороны от известных (0 — ниже всех, 7 и 999 —
        // выше), потому что порядок внутри ACTIONS строгий, и склейка
        // «известные, потом неизвестные» сломалась бы ровно на теге 0.
        let mut actions = TlvWriter::new();
        actions.put(0, &[RULE_ALLOW]).unwrap();
        actions.put(action_tag::VIEW, &[RULE_ALLOW]).unwrap();
        actions.put(7, &[RULE_ALLOW]).unwrap();
        actions.put(999, &[RULE_ALLOW]).unwrap();

        let once = decode(POLICY_TEST_VERSION, &policy_bytes_with_actions(&actions.finish())).unwrap();
        assert_eq!(once.unknown_actions.iter().copied().collect::<Vec<_>>(), vec![0, 7, 999]);

        let fields = encoded_action_fields(&once);
        assert_eq!(
            fields.iter().map(|(t, _)| *t).collect::<Vec<_>>(),
            vec![0, 1, 2, 3, 4, 5, 6, 7, 999],
            "непонятые теги обязаны попасть на провод вперемешку с известными, по возрастанию"
        );

        let twice = decode(POLICY_TEST_VERSION, &encode(POLICY_TEST_VERSION, &once).unwrap()).unwrap();
        assert_eq!(twice.unknown_actions, once.unknown_actions, "перекодировка стёрла непонятое");
        assert_eq!(twice.rule(Action::View), Rule::Allow);
        for action in ALL_ACTIONS {
            if action != Action::View {
                assert_eq!(twice.rule(action), Rule::Deny);
            }
        }
    }

    #[test]
    fn an_action_this_client_did_not_understand_is_re_encoded_as_a_denial() {
        // Тег сохраняется, а вот разрешение — нет: клиент не понял действия и
        // не вправе от имени автора утверждать, что тот его разрешил. Пиши мы
        // сюда разрешение, противнику хватило бы прогнать запрещающую политику
        // через старого клиента, чтобы получить разрешающую.
        let mut actions = TlvWriter::new();
        actions.put(999, &[RULE_ALLOW]).unwrap();

        let policy = decode(POLICY_TEST_VERSION, &policy_bytes_with_actions(&actions.finish())).unwrap();
        let fields = encoded_action_fields(&policy);
        assert!(
            fields.contains(&(999, vec![RULE_DENY])),
            "непонятое действие записано не запретом: {fields:?}"
        );
    }

    #[test]
    fn a_known_action_tag_listed_as_unknown_is_written_once_with_the_authors_rule() {
        // `decode` такой политики не порождает, но `Policy` — открытая
        // структура. Собранная руками, она не должна ни ронять кодирование
        // дубликатом тега, ни подменять настоящее правило автора
        // заглушкой-запретом.
        let mut policy = rich_policy();
        let _ = policy.unknown_actions.insert(action_to_tag(Action::View));

        let fields = encoded_action_fields(&policy);
        assert_eq!(fields.iter().filter(|(t, _)| *t == action_tag::VIEW).count(), 1);
        assert_eq!(decode(POLICY_TEST_VERSION, &encode(POLICY_TEST_VERSION, &policy).unwrap()).unwrap().rule(Action::View), Rule::Allow);
    }

    #[test]
    fn an_unknown_permission_value_is_read_as_a_denial() {
        // Будущее «спросить пользователя» старый клиент обязан прочитать как
        // запрет, а не отвергнуть файл целиком и не принять за разрешение.
        let mut actions = TlvWriter::new();
        actions.put(action_tag::VIEW, &[42]).unwrap();

        let policy = decode(POLICY_TEST_VERSION, &policy_bytes_with_actions(&actions.finish())).unwrap();
        assert_eq!(policy.rule(Action::View), Rule::Deny);
    }

    #[test]
    fn a_missing_required_field_is_refused_rather_than_defaulted() {
        // Подстановка значения по умолчанию превратила бы урезанный файл в файл
        // с другими правилами — и, что хуже, обычно в сторону послаблений.
        let full = encode(POLICY_TEST_VERSION, &rich_policy()).unwrap();
        for missing in [tag::ACTIONS, tag::VALIDITY, tag::NETWORK, tag::MIN_BINDING] {
            let mut w = TlvWriter::new();
            let mut reader = TlvReader::new(&full);
            while let Some(field) = reader.next_field().unwrap() {
                if field.tag != missing {
                    w.put(field.tag, field.value).unwrap();
                }
            }
            assert_eq!(
                decode(POLICY_TEST_VERSION, &w.finish()),
                Err(FormatError::MissingField { tag: missing }),
                "поле {missing} пропущено без ошибки"
            );
        }
    }

    #[test]
    fn no_absent_field_ever_makes_the_policy_weaker() {
        // Исчерпывающая форма главного свойства: перебираем ВСЕ 64 комбинации
        // присутствия полей. Дыра в прошлый раз была именно в комбинации —
        // каждое поле по отдельности выглядело правдоподобно. Разобранная
        // политика обязана быть либо отвергнута, либо НЕ СЛАБЕЕ полной.
        let author = rich_policy();
        let full = encode(POLICY_TEST_VERSION, &author).unwrap();
        let mut fields: Vec<(u16, Vec<u8>)> = Vec::new();
        let mut reader = TlvReader::new(&full);
        while let Some(field) = reader.next_field().unwrap() {
            fields.push((field.tag, field.value.to_vec()));
        }
        assert_eq!(fields.len(), 6, "в политике шесть полей");

        for mask in 0u32..(1 << 6) {
            let mut w = TlvWriter::new();
            for (bit, (tag_id, value)) in fields.iter().enumerate() {
                if mask & (1 << bit) != 0 {
                    w.put(*tag_id, value).unwrap();
                }
            }
            // Отказ — всегда корректная реакция: он ничего не ослабляет.
            let Ok(got) = decode(POLICY_TEST_VERSION, &w.finish()) else { continue };

            for action in ALL_ACTIONS {
                assert!(
                    !(got.rule(action) == Rule::Allow && author.rule(action) != Rule::Allow),
                    "набор полей {mask:#08b}: появилось разрешение на {action:?}"
                );
            }
            assert!(
                got.watermark >= author.watermark,
                "набор полей {mask:#08b}: водяной знак снят отсутствием поля"
            );
            match (author.max_opens, got.max_opens) {
                (Some(a), Some(b)) => {
                    assert!(b <= a, "набор полей {mask:#08b}: лимит открытий поднят до {b}");
                }
                (Some(_), None) => {
                    panic!("набор полей {mask:#08b}: лимит открытий снят отсутствием поля")
                }
                (None, _) => {}
            }
            assert!(
                got.min_binding >= author.min_binding,
                "набор полей {mask:#08b}: привязка ослаблена"
            );
        }
    }

    #[test]
    fn an_absent_watermark_field_leaves_the_obligation_standing() {
        // Собственно закрываемая находка: обязанность нанести знак снималась
        // молча — достаточно было срезать семь байт политики. Отказывать в
        // открытии тут не за что (правила прочитаны целиком), а вот прочитать
        // отсутствие как «знак не нужен» — значит исполнить не то, что подписал
        // автор. Лишний знак файл не ломает, снятый — ломает защиту.
        let mut w = TlvWriter::new();
        w.put(tag::ACTIONS, &TlvWriter::new().finish()).unwrap();
        w.put(tag::VALIDITY, &encode_validity(Validity::Always)).unwrap();
        w.put(tag::NETWORK, &encode_network(Network::StrictOnline)).unwrap();
        w.put(tag::MIN_BINDING, &[BINDING_SOFTWARE]).unwrap();
        w.put(tag::MAX_OPENS, &[]).unwrap();

        assert!(decode(POLICY_TEST_VERSION, &w.finish()).unwrap().watermark, "отсутствие поля сняло водяной знак");
    }

    #[test]
    fn a_watermark_value_this_client_does_not_know_keeps_the_obligation() {
        // Знак снимает только явный ноль. Значение из будущей версии («знак с
        // QR-кодом») старый клиент обязан прочитать как «знак нужен»: здесь
        // строгая сторона — нанести, в отличие от байта разрешения действия.
        for byte in 0u16..=255 {
            let mut w = TlvWriter::new();
            w.put(tag::ACTIONS, &TlvWriter::new().finish()).unwrap();
            w.put(tag::VALIDITY, &encode_validity(Validity::Always)).unwrap();
            w.put(tag::NETWORK, &encode_network(Network::StrictOnline)).unwrap();
            w.put(tag::MIN_BINDING, &[BINDING_SOFTWARE]).unwrap();
            w.put(tag::MAX_OPENS, &[]).unwrap();
            w.put(tag::WATERMARK, &[byte as u8]).unwrap();

            let policy = decode(POLICY_TEST_VERSION, &w.finish()).unwrap();
            assert_eq!(policy.watermark, byte != 0, "байт водяного знака {byte}");
        }
    }

    #[test]
    fn no_limit_on_opens_is_something_the_author_writes_and_never_something_inferred() {
        // Различие, ради которого «без лимита» вообще кодируется байтами: воля
        // автора («лимита не ставил», пустое значение) и незнание читателя
        // («поля нет») — это не одно и то же, и второе не смеет выдавать себя
        // за первое. Выдумать за автора число нельзя, поэтому пустое значение
        // читается как `None` — но и назначить `None` самим, не увидев поля,
        // тоже нельзя: это слабейшее из возможных значений.
        let no_limit = Policy { max_opens: None, ..rich_policy() };
        let bytes = encode(POLICY_TEST_VERSION, &no_limit).unwrap();
        assert_eq!(decode(POLICY_TEST_VERSION, &bytes).unwrap().max_opens, None, "явное «без лимита» не сохранилось");

        let mut w = TlvWriter::new();
        let mut reader = TlvReader::new(&bytes);
        let mut written_out = false;
        while let Some(field) = reader.next_field().unwrap() {
            if field.tag == tag::MAX_OPENS {
                assert!(field.value.is_empty(), "«без лимита» пишется пустым значением");
                written_out = true;
            } else {
                w.put(field.tag, field.value).unwrap();
            }
        }
        assert!(written_out, "поле лимита обязано присутствовать даже при `None`");
        assert_eq!(
            decode(POLICY_TEST_VERSION, &w.finish()).unwrap().max_opens,
            Some(OPENS_WHEN_THE_FIELD_IS_ABSENT),
            "срезанное поле лимита прочитано как «открывай сколько хочешь»"
        );
    }

    #[test]
    fn a_malformed_open_limit_is_refused_rather_than_read_as_no_limit() {
        // Срезанное значение НЕ дополняется нулями и НЕ трактуется как «лимита
        // нет»: иначе противник управляет лимитом, стирая байты.
        for body in [vec![1u8], vec![1, 0], vec![1, 0, 0], vec![1, 0, 0, 0, 0]] {
            let mut w = TlvWriter::new();
            w.put(tag::ACTIONS, &TlvWriter::new().finish()).unwrap();
            w.put(tag::VALIDITY, &encode_validity(Validity::Always)).unwrap();
            w.put(tag::NETWORK, &encode_network(Network::StrictOnline)).unwrap();
            w.put(tag::MIN_BINDING, &[BINDING_SOFTWARE]).unwrap();
            w.put(tag::MAX_OPENS, &body).unwrap();
            w.put(tag::WATERMARK, &[1]).unwrap();

            assert_eq!(
                decode(POLICY_TEST_VERSION, &w.finish()),
                Err(FormatError::BadFieldLength { tag: tag::MAX_OPENS, len: body.len() }),
                "лимит длиной {} байт прошёл", body.len()
            );
        }
    }

    #[test]
    fn an_unknown_policy_field_is_refused_whatever_its_tag_range() {
        // Внутри политики нет «необязательных» полей: пропустить кусок правил
        // значит исполнить не то, что подписал автор.
        for unknown in [50u16, 0x8000, u16::MAX] {
            let mut w = TlvWriter::new();
            let full = encode(POLICY_TEST_VERSION, &rich_policy()).unwrap();
            let mut reader = TlvReader::new(&full);
            while let Some(field) = reader.next_field().unwrap() {
                w.put(field.tag, field.value).unwrap();
            }
            w.put(unknown, b"whatever").unwrap();
            assert_eq!(
                decode(POLICY_TEST_VERSION, &w.finish()),
                Err(FormatError::UnknownCriticalField { tag: unknown })
            );
        }
    }

    #[test]
    fn an_unknown_binding_strength_is_refused_not_rounded() {
        let mut w = TlvWriter::new();
        w.put(tag::ACTIONS, &TlvWriter::new().finish()).unwrap();
        w.put(tag::VALIDITY, &encode_validity(Validity::Always)).unwrap();
        w.put(tag::NETWORK, &encode_network(Network::StrictOnline)).unwrap();
        w.put(tag::MIN_BINDING, &[99]).unwrap();
        assert!(matches!(decode(POLICY_TEST_VERSION, &w.finish()), Err(FormatError::BadFieldLength { .. })));
    }

    #[test]
    fn a_truncated_variant_body_is_refused() {
        for (tag_id, body) in [
            (tag::VALIDITY, vec![VALIDITY_WINDOW, 1, 2, 3]),
            (tag::NETWORK, vec![NETWORK_LEASE]),
            (tag::VALIDITY, vec![]),
        ] {
            let mut w = TlvWriter::new();
            w.put(tag::ACTIONS, &TlvWriter::new().finish()).unwrap();
            if tag_id == tag::VALIDITY {
                w.put(tag::VALIDITY, &body).unwrap();
                w.put(tag::NETWORK, &encode_network(Network::StrictOnline)).unwrap();
            } else {
                w.put(tag::VALIDITY, &encode_validity(Validity::Always)).unwrap();
                w.put(tag::NETWORK, &body).unwrap();
            }
            w.put(tag::MIN_BINDING, &[BINDING_SOFTWARE]).unwrap();
            assert!(decode(POLICY_TEST_VERSION, &w.finish()).is_err(), "обрезанное тело {tag_id} прошло");
        }
    }

    #[test]
    fn never_panics_on_arbitrary_bytes() {
        let valid = encode(POLICY_TEST_VERSION, &rich_policy()).unwrap();
        for cut in 0..valid.len() {
            let _ = decode(POLICY_TEST_VERSION, &valid[..cut]);
        }
        for position in 0..valid.len() {
            let mut broken = valid.clone();
            broken[position] ^= 0xff;
            let _ = decode(POLICY_TEST_VERSION, &broken);
        }
    }
}
