// Файл-проба состязательной проверки безопасности. Тесты `probe*` писались
// КРАСНЫМИ: падение и было доказательством находки. Все три находки закрыты в
// `oc-policy`, поэтому сегодня файл зелёный целиком — и роль проб сменилась с
// обвинения на охрану: упавший `probe*` теперь означает возврат дефекта, а
// история каждого лежит в его докстроке. Линтерные запреты рабочего кода к
// пробам не применяются — проба вправе делать то, чего продукт делать не должен.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]
//! Area 5 probe: policy enforcement and the "unknown means denied" rule.
//!
//! Created during an audit. Production code has since CHANGED in response to its findings:
//! `oc-policy` reads `unknown_actions`, treats an omitted watermark field
//! as a requirement, and checks lease duration against author policy.


use oc_format::policy_codec::{self, tag};
use oc_format::tlv::TlvWriter;
use oc_policy::{
    Action, Binding, Context, DeviceClock, DeviceFacts, LeaseFacts, Network, Obligations, Policy, Rule,
    TimeSource, Timestamp, Validity, Verdict, evaluate, intersect,
};

const ALL_ACTIONS: [Action; 6] = [
    Action::View,
    Action::Edit,
    Action::Print,
    Action::Clipboard,
    Action::Export,
    Action::Screenshot,
];

/// Numeric codec constants are deliberately duplicated here: they are private in
/// `policy_codec`, and the probe must assemble bytes itself, as an attacker would.
const ACTION_VIEW: u16 = 1;
/// Action from a future format version (`ai_ingest` per specification §4).
const ACTION_FUTURE: u16 = 7;
const RULE_ALLOW: u8 = 1;
const VALIDITY_ALWAYS: u8 = 1;
const NETWORK_LEASE: u8 = 2;
const BINDING_SOFTWARE: u8 = 1;

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
        expires_at: Timestamp(8 * 3600),
        opens_remaining: None,
        revoked: false,
        tpm_clock: None,
        server_policy: None,
        attested: None,
    }
}

fn network_lease_body(seconds: i64, max_offline: i64) -> Vec<u8> {
    let mut body = vec![NETWORK_LEASE];
    body.extend_from_slice(&seconds.to_le_bytes());
    body.extend_from_slice(&max_offline.to_le_bytes());
    body
}

// ---------------------------------------------------------------------------
// НАХОДКА 1 (исправлена). `unknown_actions` читается решателем, а не только
// заполняется декодером.
// ---------------------------------------------------------------------------

/// A file written by a future version contains `ai_ingest` (tag 7).
/// An old client does not recognize it and must refuse to enforce rules it
/// has not fully understood (I-10).
///
/// The probe originated in the opposite behavior: the decoder faithfully placed the unknown tag in
/// `unknown_actions`, but `evaluate` never inspected that field, and the file
/// opened as if fully understood.
#[test]
fn probe1_an_unknown_action_does_not_reach_the_decision() {
    let mut actions = TlvWriter::new();
    actions.put(ACTION_VIEW, &[RULE_ALLOW]).unwrap();
    actions.put(ACTION_FUTURE, &[RULE_ALLOW]).unwrap();

    let mut w = TlvWriter::new();
    w.put(tag::ACTIONS, &actions.finish()).unwrap();
    w.put(tag::VALIDITY, &[VALIDITY_ALWAYS]).unwrap();
    w.put(tag::NETWORK, &network_lease_body(8 * 3600, 8 * 3600)).unwrap();
    w.put(tag::MIN_BINDING, &[BINDING_SOFTWARE]).unwrap();
    w.put(tag::WATERMARK, &[1]).unwrap();

    let policy = policy_codec::decode(1, &w.finish()).unwrap();

    // Декодер честно зафиксировал непонятое действие.
    assert!(policy.unknown_actions.contains(&ACTION_FUTURE));

    // ...и решение о доступе его не заметило.
    let verdict = evaluate(&policy, Some(&lease()), Action::View, &ctx(60));
    assert!(
        !verdict.is_allowed(),
        "клиент разрешил View по политике, которую понял не целиком: \
         unknown_actions = {:?}, вердикт = {verdict:?}",
        policy.unknown_actions
    );
}

/// The same property generally: no context and no action may
/// yield `Allow` while a tag the client did not understand remains in the policy.
#[test]
fn probe1b_no_action_is_allowed_while_the_policy_is_not_fully_understood() {
    let mut actions = TlvWriter::new();
    for tag_id in [ACTION_VIEW, 2, 3, 4, 5, 6] {
        actions.put(tag_id, &[RULE_ALLOW]).unwrap();
    }
    actions.put(ACTION_FUTURE, &[RULE_ALLOW]).unwrap();

    let mut w = TlvWriter::new();
    w.put(tag::ACTIONS, &actions.finish()).unwrap();
    w.put(tag::VALIDITY, &[VALIDITY_ALWAYS]).unwrap();
    w.put(tag::NETWORK, &network_lease_body(8 * 3600, 8 * 3600)).unwrap();
    w.put(tag::MIN_BINDING, &[BINDING_SOFTWARE]).unwrap();
    w.put(tag::WATERMARK, &[1]).unwrap();

    let policy = policy_codec::decode(1, &w.finish()).unwrap();
    assert!(!policy.unknown_actions.is_empty());

    for action in ALL_ACTIONS {
        let verdict = evaluate(&policy, Some(&lease()), action, &ctx(60));
        assert!(!verdict.is_allowed(), "{action:?} разрешено при непонятой политике");
    }
}

// ---------------------------------------------------------------------------
// НАХОДКА 2. Исчерпывающий перебор присутствия/отсутствия полей политики.
// ---------------------------------------------------------------------------

/// What the author specified: view only, watermark required,
/// at most one open.
struct AuthorIntent;

impl AuthorIntent {
    const ALLOWED: [Action; 1] = [Action::View];
    const WATERMARK: bool = true;
    const MAX_OPENS: u32 = 1;
}

/// All six policy fields. The bit index is the position in this array.
const FIELD_TAGS: [u16; 6] = [
    tag::ACTIONS,
    tag::VALIDITY,
    tag::NETWORK,
    tag::MIN_BINDING,
    tag::MAX_OPENS,
    tag::WATERMARK,
];

fn field_body(tag_id: u16) -> Vec<u8> {
    match tag_id {
        tag::ACTIONS => {
            let mut actions = TlvWriter::new();
            actions.put(ACTION_VIEW, &[RULE_ALLOW]).unwrap();
            actions.finish().to_vec()
        }
        tag::VALIDITY => vec![VALIDITY_ALWAYS],
        tag::NETWORK => network_lease_body(8 * 3600, 8 * 3600),
        tag::MIN_BINDING => vec![BINDING_SOFTWARE],
        tag::MAX_OPENS => AuthorIntent::MAX_OPENS.to_le_bytes().to_vec(),
        tag::WATERMARK => vec![u8::from(AuthorIntent::WATERMARK)],
        other => panic!("неизвестный тег политики {other}"),
    }
}

/// Iterate ALL 64 combinations of field presence and all six actions.
///
/// Claim: `Allow` never appears where the author did not grant it, and
/// obligations under `Allow` are no weaker than the author's. An absent field
/// must cause a parse failure or a stricter decision, never a more
/// permissive one (specification §4 and §2.1 item 5).
#[test]
fn probe2_no_combination_of_missing_fields_ever_relaxes_the_authors_rules() {
    let mut violations: Vec<String> = Vec::new();

    for mask in 0u32..(1 << FIELD_TAGS.len()) {
        let mut w = TlvWriter::new();
        let mut present = Vec::new();
        for (bit, tag_id) in FIELD_TAGS.iter().enumerate() {
            if mask & (1 << bit) != 0 {
                w.put(*tag_id, &field_body(*tag_id)).unwrap();
                present.push(*tag_id);
            }
        }

        // Отсутствие поля обязано означать отказ разбора либо ужесточение.
        let Ok(policy) = policy_codec::decode(1, &w.finish()) else {
            continue;
        };

        for action in ALL_ACTIONS {
            let verdict = evaluate(&policy, Some(&lease()), action, &ctx(60));
            let Verdict::Allow(obligations) = verdict else {
                continue;
            };

            if !AuthorIntent::ALLOWED.contains(&action) {
                violations.push(format!(
                    "поля {present:?}: разрешено {action:?}, которого автор не разрешал"
                ));
            }
            if AuthorIntent::WATERMARK && !obligations.watermark {
                violations.push(format!(
                    "поля {present:?}: {action:?} разрешено без водяного знака, \
                     которого требовал автор"
                ));
            }
        }

        // Лимит открытий: автор написал «не больше одного».
        let mut used_up = ctx(60);
        used_up.opens_so_far = AuthorIntent::MAX_OPENS;
        if evaluate(&policy, Some(&lease()), Action::View, &used_up).is_allowed() {
            violations.push(format!(
                "поля {present:?}: просмотр разрешён после исчерпания лимита открытий"
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "отсутствующие поля политики ослабили правила автора в {} случаях:\n{}",
        violations.len(),
        violations.join("\n")
    );
}

/// Minimal form of the same property: a policy without a watermark field
/// is accepted by the decoder, and the watermark is still applied.
///
/// The field is optional, so absence must mean "watermark
/// required", not "watermark unnecessary" (I-10). The probe originated in the reverse:
/// the decoder returned `watermark = false`, and an author whose text required a watermark
/// received a file without it after just one optional TLV was removed.
/// The test name described the DEFECT ("accepted and applies nothing") even though
/// the assertion required a watermark from the outset, saying precisely the opposite
/// of what it checked.
#[test]
fn probe2b_a_missing_watermark_field_reads_as_watermark_required() {
    let mut w = TlvWriter::new();
    for tag_id in [tag::ACTIONS, tag::VALIDITY, tag::NETWORK, tag::MIN_BINDING] {
        w.put(tag_id, &field_body(tag_id)).unwrap();
    }

    let policy = policy_codec::decode(1, &w.finish())
        .expect("декодер принял политику без поля водяного знака");

    let Verdict::Allow(obligations) = evaluate(&policy, Some(&lease()), Action::View, &ctx(60))
    else {
        panic!("ожидалось разрешение");
    };
    assert!(
        obligations.watermark,
        "отсутствующее поле watermark прочитано как «знак не нужен»"
    );
}

// ---------------------------------------------------------------------------
// НАХОДКА 3. Длительность лизинга ограничена политикой автора.
// ---------------------------------------------------------------------------

/// The author allowed offline access for one hour. The server issues a ten-year lease;
/// that must not expand the author's window: `intersect` is monotonic only
/// toward stricter policy (I-10), and the issued lease must follow the same
/// rule.
///
/// The probe originated in the reverse: `evaluate` checked only `lease.expires_at`,
/// never inspecting `Network::Lease { seconds, max_offline_seconds }` in
/// author policy, so the server could grant any duration. There are now two denial
/// names, `Deny::LeaseOutlivesPolicy` and `Deny::OfflineTooLong`, and they
/// differ: the former catches an excessive lease on presentation, the latter an excessive
/// offline period under a lease of valid duration.
#[test]
fn probe3_the_server_cannot_extend_the_authors_offline_window() {
    let hour = 3600;
    let policy = Policy {
        network: Network::Lease { seconds: hour, max_offline_seconds: hour },
        ..Policy::deny_all()
    }
    .allow(Action::View);

    let ten_years = 10 * 365 * 24 * hour;
    let generous = LeaseFacts { expires_at: Timestamp(ten_years), ..lease() };

    // Прошёл год без сети. Автор разрешал час.
    let mut a_year_later = ctx(365 * 24 * hour);
    a_year_later.online = false;

    let verdict = evaluate(&policy, Some(&generous), Action::View, &a_year_later);
    assert!(
        !verdict.is_allowed(),
        "лизинг на {ten_years} с пережил политику автора на {hour} с: {verdict:?}"
    );
}

/// The same property in isolation, without time passing: `seconds` in author policy
/// binds the presented lease's `expires_at`, already at the point of
/// presentation.
///
/// Separate from [`probe3_the_server_cannot_extend_the_authors_offline_window`]
/// for this reason: there, expiry could explain rejection; here,
/// only the duration comparison can explain it.
#[test]
fn probe3b_lease_duration_is_bound_by_the_policy_at_presentation() {
    let policy = Policy {
        network: Network::Lease { seconds: 1, max_offline_seconds: 1 },
        ..Policy::deny_all()
    }
    .allow(Action::View);

    let long = LeaseFacts { issued_at: Timestamp(0), expires_at: Timestamp(i64::MAX), ..lease() };
    let verdict = evaluate(&policy, Some(&long), Action::View, &ctx(1_000_000));
    assert!(!verdict.is_allowed(), "лизинг длиной i64::MAX принят при политике в 1 с: {verdict:?}");
}

// ---------------------------------------------------------------------------
// ПРОВЕРЕНО И ЦЕЛО. Тесты ниже обязаны проходить на нынешнем коде.
// ---------------------------------------------------------------------------

/// Monotonicity of `intersect` for every field it touches: enumerate all
/// author and server action subsets, plus all binding levels, watermark flags,
/// limits, and network modes.
#[test]
fn sound_intersect_never_widens_anything() {
    let bindings = [Binding::Software, Binding::Hardware, Binding::HardwareAttested];
    let networks = [
        Network::StrictOnline,
        Network::Lease { seconds: 100, max_offline_seconds: 50 },
        Network::Lease { seconds: 10_000, max_offline_seconds: 9_000 },
    ];
    let limits = [None, Some(0u32), Some(1), Some(u32::MAX)];

    for author_mask in 0u32..64 {
        for server_mask in 0u32..64 {
            for (ab, sb) in bindings.iter().zip(bindings.iter().rev()) {
                for an in networks {
                    for sn in networks {
                        for al in limits {
                            for sl in limits {
                                let mut author = Policy {
                                    min_binding: *ab,
                                    network: an,
                                    max_opens: al,
                                    watermark: author_mask & 1 != 0,
                                    ..Policy::deny_all()
                                };
                                let mut server = Policy {
                                    min_binding: *sb,
                                    network: sn,
                                    max_opens: sl,
                                    watermark: server_mask & 1 != 0,
                                    ..Policy::deny_all()
                                };
                                for (bit, action) in ALL_ACTIONS.iter().enumerate() {
                                    if author_mask & (1 << bit) != 0 {
                                        author = author.allow(*action);
                                    }
                                    if server_mask & (1 << bit) != 0 {
                                        server = server.allow(*action);
                                    }
                                }

                                let r = intersect(&author, &server);

                                for action in ALL_ACTIONS {
                                    assert!(
                                        !(r.rule(action) == Rule::Allow
                                            && author.rule(action) != Rule::Allow),
                                        "сервер добавил {action:?}"
                                    );
                                }
                                assert!(r.min_binding >= author.min_binding, "привязка ослаблена");
                                assert!(
                                    !author.watermark || r.watermark,
                                    "водяной знак снят сервером"
                                );
                                match (author.max_opens, r.max_opens) {
                                    (Some(a), Some(b)) => assert!(b <= a, "лимит открытий поднят"),
                                    (Some(_), None) => panic!("лимит открытий снят сервером"),
                                    (None, _) => {}
                                }
                                match (author.network, r.network) {
                                    (Network::StrictOnline, n) => {
                                        assert_eq!(n, Network::StrictOnline, "StrictOnline снят");
                                    }
                                    (
                                        Network::Lease { seconds: a, max_offline_seconds: ao },
                                        Network::Lease { seconds: b, max_offline_seconds: bo },
                                    ) => {
                                        assert!(b <= a, "срок лизинга продлён");
                                        assert!(bo <= ao, "окно оффлайна расширено");
                                    }
                                    (Network::Lease { .. }, Network::StrictOnline) => {}
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/// No `evaluate` check is bypassed: trigger each denial condition
/// individually in a policy that would otherwise allow viewing.
#[test]
fn sound_every_denying_condition_wins_over_a_permitting_policy() {
    let policy = Policy {
        network: Network::Lease { seconds: 8 * 3600, max_offline_seconds: 8 * 3600 },
        ..Policy::deny_all()
    }
    .allow(Action::View);

    assert!(evaluate(&policy, Some(&lease()), Action::View, &ctx(60)).is_allowed());

    let mut rollback = ctx(60);
    rollback.monotonic_floor = Timestamp(1_000_000);
    assert!(!evaluate(&policy, Some(&lease()), Action::View, &rollback).is_allowed());

    let hard = Policy { min_binding: Binding::HardwareAttested, ..policy.clone() };
    assert!(!evaluate(&hard, Some(&lease()), Action::View, &ctx(60)).is_allowed());

    assert!(!evaluate(&policy, None, Action::View, &ctx(60)).is_allowed());

    let revoked = LeaseFacts { revoked: true, ..lease() };
    assert!(!evaluate(&policy, Some(&revoked), Action::View, &ctx(60)).is_allowed());

    let other_device = LeaseFacts { device_fingerprint: [7; 32], ..lease() };
    assert!(!evaluate(&policy, Some(&other_device), Action::View, &ctx(60)).is_allowed());

    let other_policy = LeaseFacts { policy_hash: [0xaa; 32], ..lease() };
    assert!(!evaluate(&policy, Some(&other_policy), Action::View, &ctx(60)).is_allowed());

    let mut seen = ctx(60);
    seen.highest_seq_seen = 99;
    assert!(!evaluate(&policy, Some(&lease()), Action::View, &seen).is_allowed());

    assert!(!evaluate(&policy, Some(&lease()), Action::View, &ctx(9 * 3600)).is_allowed());
}

/// Policy bytes cannot turn the author's `Deny` into `Allow`:
/// exactly one byte means permission, and every other value means denial.
#[test]
fn sound_no_rule_byte_other_than_one_reads_as_allow() {
    for byte in 0u16..=255 {
        let mut actions = TlvWriter::new();
        actions.put(ACTION_VIEW, &[byte as u8]).unwrap();
        let mut w = TlvWriter::new();
        w.put(tag::ACTIONS, &actions.finish()).unwrap();
        w.put(tag::VALIDITY, &[VALIDITY_ALWAYS]).unwrap();
        w.put(tag::NETWORK, &network_lease_body(8 * 3600, 8 * 3600)).unwrap();
        w.put(tag::MIN_BINDING, &[BINDING_SOFTWARE]).unwrap();
        w.put(tag::WATERMARK, &[1]).unwrap();

        let policy = policy_codec::decode(1, &w.finish()).unwrap();
        let allowed = policy.rule(Action::View) == Rule::Allow;
        assert_eq!(allowed, byte as u8 == RULE_ALLOW, "байт разрешения {byte}");
    }
}

/// Default obligations: if screenshots are not allowed, capture must
/// be blocked and dumps suppressed.
#[test]
fn sound_default_obligations_are_the_strict_ones() {
    assert_eq!(
        Obligations::default(),
        Obligations { watermark: false, block_screen_capture: false, suppress_crash_dumps: false }
    );
    let policy = Policy {
        network: Network::Lease { seconds: 8 * 3600, max_offline_seconds: 8 * 3600 },
        validity: Validity::Always,
        ..Policy::deny_all()
    }
    .allow(Action::View);
    let Verdict::Allow(o) = evaluate(&policy, Some(&lease()), Action::View, &ctx(60)) else {
        panic!("ожидалось разрешение");
    };
    assert!(o.block_screen_capture);
    assert!(o.suppress_crash_dumps);
}
