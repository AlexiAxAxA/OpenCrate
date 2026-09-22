// Файл-проба состязательной проверки безопасности. Часть тестов здесь КРАСНАЯ
// НАМЕРЕННО: падение теста и есть доказательство находки. Линтерные запреты
// рабочего кода к пробам не применяются — проба вправе делать то, чего продукт
// делать не должен.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]
//! Зонд скептика: перепроверка направления «policy».
//!
//! Файл создан аудитом. Рабочий код не менялся.


use oc_policy::{
    Action, Binding, Context, DeviceClock, DeviceFacts, LeaseFacts, Network, Policy, Timestamp, TimeSource,
    Validity, evaluate,
};

fn device() -> DeviceFacts {
    DeviceFacts { fingerprint: [1; 32], binding: Binding::Hardware, tpm_clock: DeviceClock::Absent }
}

fn ctx(now: i64) -> Context {
    Context {
        now: Timestamp(now),
        time_source: TimeSource::TpmClock { reset_count: 0 },
        monotonic_floor: Timestamp(0),
        first_open_at: Some(Timestamp(0)),
        opens_so_far: 0,
            opens_under_lease: 0,
        device: device(),
        highest_seq_seen: 0,
        online: true,
        policy_hash: [9; 32],
    }
}

fn lease() -> LeaseFacts {
    LeaseFacts {
        device_fingerprint: [1; 32],
        policy_hash: [9; 32],
        seq: 1,
        epoch: 0,
        issued_at: Timestamp(0),
        expires_at: Timestamp(i64::MAX),
        opens_remaining: None,
        revoked: false,
        tpm_clock: None,
        server_policy: None,
        attested: None,
    }
}

/// Автор дал час с первого открытия. Клиент, у которого нет записи о первом
/// открытии, не применяет срок ВООБЩЕ: ветка `None` в
/// `Validity::FromFirstOpen` не делает ничего.
#[test]
fn missed_a_forgotten_first_open_cancels_the_authors_deadline() {
    let policy = Policy {
        validity: Validity::FromFirstOpen { seconds: 3600 },
        network: Network::Lease { seconds: 3600, max_offline_seconds: 3600 },
        ..Policy::deny_all()
    }
    .allow(Action::View);

    // Десять лет спустя, состояние «первого открытия» отсутствует.
    let mut forgetful = ctx(10 * 365 * 24 * 3600);
    forgetful.first_open_at = None;

    let verdict = evaluate(&policy, Some(&lease()), Action::View, &forgetful);
    assert!(
        !verdict.is_allowed(),
        "срок «час с первого открытия» не применён при first_open_at = None: {verdict:?}"
    );
}

/// Тот же срок при ЗАПОЛНЕННОМ состоянии работает — значит дело именно в
/// трактовке отсутствующего значения, а не в самой ветке.
#[test]
fn control_the_same_deadline_works_when_the_state_is_present() {
    let policy = Policy {
        validity: Validity::FromFirstOpen { seconds: 3600 },
        network: Network::Lease { seconds: 3600, max_offline_seconds: 3600 },
        ..Policy::deny_all()
    }
    .allow(Action::View);

    let mut remembered = ctx(10 * 365 * 24 * 3600);
    remembered.first_open_at = Some(Timestamp(0));
    assert!(!evaluate(&policy, Some(&lease()), Action::View, &remembered).is_allowed());
}

/// Лизинг, который сервер ещё не выдал: `issued_at` в будущем, `expires_at`
/// раньше `issued_at`. `evaluate` не смотрит на `issued_at` ни разу.
#[test]
fn missed_a_lease_issued_in_the_future_is_accepted() {
    let policy = Policy {
        network: Network::Lease { seconds: 3600, max_offline_seconds: 3600 },
        ..Policy::deny_all()
    }
    .allow(Action::View);

    let not_yet = LeaseFacts {
        issued_at: Timestamp(10_000_000),
        expires_at: Timestamp(20_000_000),
        ..lease()
    };
    let verdict = evaluate(&policy, Some(&not_yet), Action::View, &ctx(60));
    assert!(!verdict.is_allowed(), "принят лизинг, выданный в будущем: {verdict:?}");
}
