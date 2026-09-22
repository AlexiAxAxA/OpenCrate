// Проба: решатель складывает профиль сервера сам. Литы рабочего кода к пробам
// не применяются — проба вправе паниковать, это её способ отчитаться.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
//! Профиль сервера складывается с политикой автора ВНУТРИ решателя.
//!
//! Главное свойство здесь — не «пересечение считается правильно» (за это
//! отвечает `intersect` и его собственные пробы), а то, что складывает его
//! `evaluate`, и ни один вызывающий не может этого пропустить. Поэтому все
//! пробы идут через `evaluate` и ни одна не зовёт `intersect` напрямую.

use oc_policy::{
    Action, Binding, Context, DenyReason, DeviceClock, DeviceFacts, LeaseFacts, Network, Policy,
    Timestamp, TimeSource, Validity, Verdict, evaluate,
};

fn device(binding: Binding) -> DeviceFacts {
    DeviceFacts { fingerprint: [1; 32], binding, tpm_clock: DeviceClock::Absent }
}

fn ctx() -> Context {
    Context {
        now: Timestamp(1_000),
        time_source: TimeSource::Wall,
        monotonic_floor: Timestamp(0),
        first_open_at: Some(Timestamp(0)),
        opens_so_far: 0,
        opens_under_lease: 0,
        device: device(Binding::Hardware),
        highest_seq_seen: 0,
        online: true,
        policy_hash: [9; 32],
    }
}

/// Политика автора: смотреть и выгружать можно, программной привязки хватает.
fn author() -> Policy {
    let mut policy = Policy::deny_all().allow(Action::View).allow(Action::Export);
    policy.validity = Validity::Always;
    policy.network = Network::Lease { seconds: 86_400, max_offline_seconds: 86_400 };
    policy.min_binding = Binding::Software;
    policy
}

fn lease(server_policy: Option<Policy>) -> LeaseFacts {
    LeaseFacts {
        device_fingerprint: [1; 32],
        policy_hash: [9; 32],
        seq: 1,
        epoch: 0,
        issued_at: Timestamp(0),
        // Срок КОРОЧЕ авторского предела: лизинг, переживающий политику, — сам
        // по себе отказ (`LeaseOutlivesPolicy`), и проба тогда мерила бы его, а
        // не пересечение.
        expires_at: Timestamp(3_600),
        opens_remaining: None,
        revoked: false,
        tpm_clock: None,
        server_policy,
        attested: None,
    }
}

/// Профиль без собственных ограничений: разрешает всё, чем владеет автор.
fn permissive() -> Policy {
    let mut policy = Policy::deny_all();
    for action in [
        Action::View,
        Action::Edit,
        Action::Print,
        Action::Clipboard,
        Action::Export,
        Action::Screenshot,
    ] {
        policy = policy.allow(action);
    }
    policy.network = Network::Lease { seconds: i64::MAX, max_offline_seconds: i64::MAX };
    policy
}

/// Сервер убрал выгрузку — и её нет, хотя автор её давал.
#[test]
fn a_server_that_drops_export_drops_it_for_the_reader() {
    let mut server = permissive();
    let _ = server.actions.remove(&Action::Export);

    let facts = lease(Some(server));
    assert!(evaluate(&author(), Some(&facts), Action::View, &ctx()).is_allowed());
    // Виновник назван: выгрузку автор дал, отнял сервер.
    match evaluate(&author(), Some(&facts), Action::Export, &ctx()) {
        Verdict::Deny(DenyReason::ActionTightenedByServer(Action::Export)) => {}
        other => panic!("выгрузка пережила ужесточение сервера: {other:?}"),
    }
}

/// Отсутствие профиля не значит ни «всё разрешено», ни «всё запрещено».
///
/// Решение обязано совпасть с тем, каким оно было до появления поля, — иначе
/// один лишь выпуск новой сборки сервера изменил бы права у всех, кто ничего не
/// настраивал.
#[test]
fn no_profile_decides_exactly_as_before() {
    let facts = lease(None);
    // Ровно политика автора: что он дал — есть, чего не дал — нет.
    assert!(evaluate(&author(), Some(&facts), Action::View, &ctx()).is_allowed());
    assert!(evaluate(&author(), Some(&facts), Action::Export, &ctx()).is_allowed());
    match evaluate(&author(), Some(&facts), Action::Print, &ctx()) {
        Verdict::Deny(DenyReason::ActionNotPermitted(Action::Print)) => {}
        other => panic!("без профиля решение разошлось с политикой автора: {other:?}"),
    }
    // И ступень привязки осталась авторской: программная машина проходит.
    let mut soft = ctx();
    soft.device = device(Binding::Software);
    assert!(evaluate(&author(), Some(&facts), Action::View, &soft).is_allowed());
}

/// Сервер НЕ МОЖЕТ расширить права: чего автор не дал, того не будет.
///
/// Это и есть обещание И-10, и проверяется оно с самой выгодной для сервера
/// стороны: профиль разрешает всё, что бывает, — включая печать, которой автор
/// не давал. Скомпрометированный сервер получает ровно столько же.
#[test]
fn a_server_cannot_hand_out_what_the_author_withheld() {
    let facts = lease(Some(permissive()));
    match evaluate(&author(), Some(&facts), Action::Print, &ctx()) {
        Verdict::Deny(DenyReason::ActionNotPermitted(Action::Print)) => {}
        other => panic!("сервер расширил права автора: {other:?}"),
    }
}

/// Сервер поднял ступень привязки — программная машина закрывается.
#[test]
fn a_server_may_raise_the_binding_floor() {
    let mut server = permissive();
    server.min_binding = Binding::Hardware;
    let facts = lease(Some(server));

    let mut soft = ctx();
    soft.device = device(Binding::Software);
    match evaluate(&author(), Some(&facts), Action::View, &soft) {
        Verdict::Deny(DenyReason::BindingTooWeak { required, actual }) => {
            assert_eq!(required, Binding::Hardware);
            assert_eq!(actual, Binding::Software);
        }
        other => panic!("программная привязка пережила ужесточение: {other:?}"),
    }
    // На машине с ключом в TPM тот же профиль ничего не запрещает.
    assert!(evaluate(&author(), Some(&facts), Action::View, &ctx()).is_allowed());
}

/// Сервер урезал бюджет открытий — считается его число, а не авторское.
#[test]
fn a_server_may_shrink_the_open_budget() {
    let mut relaxed = author();
    relaxed.max_opens = Some(100);
    let mut server = permissive();
    server.max_opens = Some(2);
    let facts = lease(Some(server));

    let mut third = ctx();
    third.opens_so_far = 2;
    match evaluate(&relaxed, Some(&facts), Action::View, &third) {
        Verdict::Deny(DenyReason::OpenLimitReached) => {}
        other => panic!("бюджет сервера не применён: {other:?}"),
    }
    // Без профиля тот же контекст проходит: предел автора ещё далеко.
    assert!(evaluate(&relaxed, Some(&lease(None)), Action::View, &third).is_allowed());
}

/// Сервер потребовал водяной знак — обязательство приходит вместе с доступом.
///
/// Обязательства — не украшение решения: клиент исполняет их, и подмешаны они
/// тем же пересечением, что и запреты.
#[test]
fn a_server_may_demand_a_watermark() {
    let mut server = permissive();
    server.watermark = true;

    match evaluate(&author(), Some(&lease(Some(server))), Action::View, &ctx()) {
        Verdict::Allow(obligations) => assert!(obligations.watermark, "знак не потребован"),
        other => panic!("доступ закрыт вместо требования знака: {other:?}"),
    }
}

/// Сервер потребовал строгий онлайн — офлайн-клиент закрывается.
#[test]
fn a_server_may_forbid_going_offline() {
    let mut server = permissive();
    server.network = Network::StrictOnline;
    let facts = lease(Some(server));

    let mut offline = ctx();
    offline.online = false;
    match evaluate(&author(), Some(&facts), Action::View, &offline) {
        Verdict::Deny(DenyReason::OfflineNotPermitted) => {}
        other => panic!("офлайн пережил строгий онлайн сервера: {other:?}"),
    }
}

/// Правило из БУДУЩЕЙ версии, названное сервером, закрывает файл.
///
/// Иначе получалось бы худшее из возможного: сервер ужесточил доступ правилом,
/// которого клиент не знает, клиент этого правила не увидел — и открыл файл,
/// считая, что прочёл политику целиком.
#[test]
fn a_rule_the_client_cannot_read_closes_the_file() {
    let mut server = permissive();
    let _ = server.unknown_actions.insert(4_242);

    match evaluate(&author(), Some(&lease(Some(server))), Action::View, &ctx()) {
        Verdict::Deny(DenyReason::PolicyNotFullyUnderstood { unknown }) => {
            assert_eq!(unknown, 4_242);
        }
        other => panic!("непонятое правило сервера пропущено: {other:?}"),
    }
}

/// Пустой профиль закрывает всё — и это законное состояние, а не авария.
///
/// Оператору оно доступно словом (`cca policy set --allow none`), и смысл у
/// него свой: заморозка останавливает ВЫДАЧИ, а пустой профиль закрывает и уже
/// выданное — с того мига, как клиент увидит новый лизинг.
#[test]
fn an_empty_profile_closes_everything() {
    let facts = lease(Some(Policy::deny_all()));
    for action in [Action::View, Action::Export] {
        match evaluate(&author(), Some(&facts), action, &ctx()) {
            // Оба действия автор давал — значит, отказ за сервером.
            Verdict::Deny(DenyReason::ActionTightenedByServer(denied)) => assert_eq!(denied, action),
            other => panic!("пустой профиль пропустил {action:?}: {other:?}"),
        }
    }
}
