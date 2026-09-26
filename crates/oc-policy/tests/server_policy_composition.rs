// SPDX-License-Identifier: MPL-2.0
// Проба: решатель складывает профиль сервера сам. Литы рабочего кода к пробам
// не применяются — проба вправе паниковать, это её способ отчитаться.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
//! The server profile is combined with the author's policy INSIDE the evaluator.
//!
//! The key property is not "intersection is computed correctly" (covered by
//! `intersect` and its own probes), but that
//! `evaluate` performs the combination and no caller can skip it. Therefore all
//! probes use `evaluate`; none calls `intersect` directly.

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

/// Author policy: viewing and exporting allowed, software binding sufficient.
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

/// A profile with no restrictions of its own: allows everything the author controls.
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

/// The server removes export, so it is unavailable even though the author allowed it.
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

/// No profile means neither "everything allowed" nor "everything denied".
///
/// The decision must match what it was before the field existed; otherwise
/// merely releasing a new server build would change permissions for everyone who
/// configured nothing.
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

/// The server CANNOT expand permissions: what the author did not grant stays unavailable.
///
/// This is the promise of I-10, tested from the position most favorable to the server:
/// the profile allows everything possible, including printing, which the author
/// did not grant. A compromised server obtains exactly the same result.
#[test]
fn a_server_cannot_hand_out_what_the_author_withheld() {
    let facts = lease(Some(permissive()));
    match evaluate(&author(), Some(&facts), Action::Print, &ctx()) {
        Verdict::Deny(DenyReason::ActionNotPermitted(Action::Print)) => {}
        other => panic!("сервер расширил права автора: {other:?}"),
    }
}

/// The server raises the binding level, denying a software-bound machine.
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

/// The server reduces the open budget: its number applies, not the author's.
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

/// The server requires a watermark: the obligation accompanies access.
///
/// Obligations are not decorations on a verdict: the client enforces them, and they enter
/// through the same intersection as denials.
#[test]
fn a_server_may_demand_a_watermark() {
    let mut server = permissive();
    server.watermark = true;

    match evaluate(&author(), Some(&lease(Some(server))), Action::View, &ctx()) {
        Verdict::Allow(obligations) => assert!(obligations.watermark, "знак не потребован"),
        other => panic!("доступ закрыт вместо требования знака: {other:?}"),
    }
}

/// The server requires strict online operation, denying an offline client.
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

/// A rule from a FUTURE version specified by the server makes the file inaccessible.
///
/// Otherwise the worst case would arise: the server tightened access with a rule
/// unknown to the client; the client missed that rule and opened the file,
/// believing it had read the entire policy.
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

/// An empty profile denies everything: a valid state, not a failure.
///
/// The operator can request it (`cca policy set --allow none`), and its meaning
/// is distinct: freezing stops ISSUANCE, while an empty profile also closes already-issued
/// access as soon as the client sees the new lease.
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
