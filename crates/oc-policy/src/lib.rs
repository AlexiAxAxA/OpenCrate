// SPDX-License-Identifier: MPL-2.0
// Здесь арифметика — это сроки, счётчики открытий и номера лизингов, то есть
// ровно те величины, переполнение которых означает расширение доступа. Поднято
// с `warn` до `deny`; причина выбора атрибута, а не строки в `Cargo.toml`, —
// та же, что в `oc-format`.
#![deny(clippy::arithmetic_side_effects)]

//! Security core: deciding whether an action on a file is permitted.
//!
//! The crate is pure and total. Everything the decision depends on: time, lease
//! state, and device facts, is supplied in [`Context`], not taken from the
//! environment. Time-travel and revocation tests thus become
//! mere data rather than scenarios that manipulate system clocks.
//!
//! The central invariant, tested and required to hold under every
//! extension: **an absent or unknown rule means denial**.

use core::fmt;
use std::collections::{BTreeMap, BTreeSet};

/// Compare fixed-size public digests without an explicit early exit.
///
/// This dependency-free crate uses XOR accumulation rather than `subtle`.
/// `black_box` discourages optimization but does not provide a constant-time
/// guarantee; keep secrets and authentication tags in the crypto comparison path.
#[must_use]
pub fn digest_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    core::hint::black_box(diff) == 0
}

/// A moment in Unix epoch seconds.
///
/// A custom type rather than `SystemTime`, because the attacker controls the device
/// clock: time must come from outside with its source identified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp(pub i64);

/// Source of the time in [`Context::now`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeSource {
    /// System clock. The user can move it backward.
    Wall,
    /// The TPM's own clock: monotonic and forward-only.
    TpmClock { reset_count: u32 },
    /// Time asserted by the server when issuing the lease.
    ServerAsserted,
}

/// Action on a protected file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Action {
    View,
    Edit,
    Print,
    Clipboard,
    Export,
    Screenshot,
}

/// Russian name of the action.
///
/// Introduced because denial is displayed to a HUMAN. Previously the reason used
/// the variant's debug name (`{a:?}`), producing a Russian sentence equivalent to
/// "action Export is not allowed by the author", half in a foreign language.
///
/// Kept here rather than in callers: everyone printing a denial would have to
/// substitute the word themselves, and the first omission would restore `Export`. Precisely
/// this happened: a `cc-cli` wrapper manually substituted the Russian word for export,
/// but the English name reappeared when denial used the common path. A scenario test
/// caught it by requiring the denial to name the operation correctly.
impl core::fmt::Display for Action {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::View => "просмотр",
            Self::Edit => "правка",
            Self::Print => "печать",
            Self::Clipboard => "буфер обмена",
            Self::Export => "экспорт",
            Self::Screenshot => "снимок экрана",
        })
    }
}

/// Permission for an action.
///
/// `Default` is [`Rule::Deny`], a foundational decision: any field absent from the
/// file, any action unknown to the client, and every parse error
/// converge on denial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Rule {
    Allow,
    #[default]
    Deny,
}

/// Basis on which the server accepted device key attestation (B6b).
///
/// Distinguished because the claims differ: a vendor certificate means
/// "this TPM was made by a manufacturer the deployment trusts";
/// a pinned EK means "this is the TPM the administrator had in front of them".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Attestation {
    VendorCertificate,
    EnrolledEk,
}

/// Binding level trusted by the evaluator.
///
/// A device reports its level from ITS OWN observations, which cannot
/// exceed [`Binding::Hardware`]: attestation checked by the client itself
/// proves nothing to anyone. Only the lease's attestation flag can raise it:
/// signed by the server that verified the chain. Attestation cannot raise software
/// binding: it attests a key inside the TPM, not one
/// stored in a profile.
#[must_use]
pub fn effective_binding(local: Binding, lease: Option<&LeaseFacts>) -> Binding {
    let attested = lease.is_some_and(|l| l.attested.is_some());
    match local {
        Binding::Software => Binding::Software,
        Binding::Hardware | Binding::HardwareAttested if attested => Binding::HardwareAttested,
        Binding::Hardware | Binding::HardwareAttested => Binding::Hardware,
    }
}

/// Strength of device binding. Order matters: `Software < Hardware < HardwareAttested`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Binding {
    /// DPAPI. An attacker who copies the profile with master keys and knows the
    /// password can unwrap the secret on another machine.
    Software,
    /// Nonexportable key in a TPM.
    Hardware,
    /// The same, plus a verified chain to the TPM vendor certificate.
    HardwareAttested,
}

/// Access validity period.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validity {
    Always,
    Window { not_before: Timestamp, not_after: Timestamp },
    FromFirstOpen { seconds: i64 },
}

/// Network requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    /// Every open requires contacting the server.
    StrictOnline,
    /// Offline use is allowed while the lease is valid. Its duration is the window
    /// during which revocation has not yet taken effect.
    Lease { seconds: i64, max_offline_seconds: i64 },
}

/// Author-signed policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    /// An absent action means denial, so the map stores only permissions.
    pub actions: BTreeMap<Action, Rule>,
    pub validity: Validity,
    pub max_opens: Option<u32>,
    pub network: Network,
    pub min_binding: Binding,
    /// Per-action binding requirement (policy tag 7, format version 4).
    ///
    /// The effective requirement is max(min_binding, this action's entry), so an
    /// entry can only tighten policy. Absence adds no requirement and cannot relax
    /// the policy-wide minimum.
    pub action_binding: BTreeMap<Action, Binding>,
    pub watermark: bool,
    /// Action tags unknown to this client version. Their presence by itself
    /// grants nothing, but is recorded so an old client does not assume
    /// it has seen the entire policy.
    pub unknown_actions: BTreeSet<u16>,
}

impl Policy {
    /// A policy allowing nothing. The foundation for any other policy:
    /// permissions are added explicitly.
    pub fn deny_all() -> Self {
        Self {
            actions: BTreeMap::new(),
            validity: Validity::Always,
            max_opens: None,
            network: Network::StrictOnline,
            min_binding: Binding::Software,
            action_binding: BTreeMap::new(),
            watermark: false,
            unknown_actions: BTreeSet::new(),
        }
    }

    /// The binding level the action ACTUALLY requires.
    ///
    /// A separate method, not a caller-side expression: "maximum of the
    /// two" must be one rule across the product. If client and server diverged
    /// here, a file requiring hardware editing could be edited with software binding.
    #[must_use]
    pub fn binding_for(&self, action: Action) -> Binding {
        self.min_binding.max(self.action_binding.get(&action).copied().unwrap_or(Binding::Software))
    }

    /// A server profile that tightens NOTHING: the identity element of
    /// intersection, `intersect(p, &Policy::no_tightening()) == p` for every
    /// field except unknown actions (the identity has none).
    ///
    /// The foundation narrowed by specified profile flags. Shared by all
    /// parties, for more than convenience: coauthors entering the same command on
    /// different machines must obtain byte-identical profiles; otherwise their
    /// signatures cover different intentions, and a quorum can never form.
    #[must_use]
    pub fn no_tightening() -> Self {
        let mut policy = Self::deny_all();
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
        // Не названный срок не ужесточает: `i64::MAX` — «сервер не ограничивает».
        policy.network = Network::Lease { seconds: i64::MAX, max_offline_seconds: i64::MAX };
        policy
    }

    /// Permission for an action. No entry means denial.
    pub fn rule(&self, action: Action) -> Rule {
        self.actions.get(&action).copied().unwrap_or_default()
    }

    /// Allow an action. Returns itself so a policy can be assembled
    /// in one expression.
    #[must_use]
    pub fn allow(mut self, action: Action) -> Self {
        let _ = self.actions.insert(action, Rule::Allow);
        self
    }
}

/// Facts about the device making the decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceFacts {
    pub fingerprint: [u8; 32],
    pub binding: Binding,
    /// Device hardware clock: a reading, absence, or read failure.
    ///
    /// Not a denial by itself: denial occurs only if the LEASE requires
    /// hardware time, with distinct reasons for absence and failure.
    pub tpm_clock: DeviceClock,
}

/// What the device knows about its hardware clock.
///
/// Three states, not `Option`: this is a fix. With `Option`, read failure and
/// a machine without a TPM shared `None`, so an incidental TBS failure on a clock-equipped
/// machine produced "device did not present a clock", indistinguishable from a machine
/// with none (finding 4, baseline A1, `cc_keystore::clock`). The decision
/// remains unchanged: a clock-bound lease without readings is denied in both cases
/// (I-10); the reason changes, followed by the exit code and user advice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceClock {
    /// A reading was obtained.
    Read(TpmClock),
    /// The device has no clock: software binding, machine without TPM 2.0.
    Absent,
    /// A clock exists or may exist, but could not be read.
    Unreadable,
}

impl DeviceClock {
    /// The reading, if obtained.
    #[must_use]
    pub fn reading(&self) -> Option<TpmClock> {
        match self {
            Self::Read(clock) => Some(*clock),
            Self::Absent | Self::Unreadable => None,
        }
    }
}

/// Server-issued lease. Checked in full, not one field at a time.
///
/// `Copy` was removed when server policy appeared (B4a): policy is an owning
/// structure, and copying it silently would hide a cost the caller
/// should see. Lease cloning is explicit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseFacts {
    pub device_fingerprint: [u8; 32],
    /// Hash of the policy byte range signed by the author.
    pub policy_hash: [u8; 32],
    /// Strictly increases for each (file, device) pair. A lower value indicates
    /// rollback of a restored cache.
    pub seq: u64,
    /// Increases on revocation so a pre-revocation lease can be recognized in the journal.
    ///
    /// The epoch is NOT a client check and should not become one:
    /// revocation latches a flag and forbids issuance, so no lease with an epoch
    /// above zero exists. If one did, `seq` would reject it,
    /// remaining monotonic across epoch changes. The protocol specification promised otherwise
    /// and was corrected.
    pub epoch: u64,
    pub issued_at: Timestamp,
    pub expires_at: Timestamp,
    pub opens_remaining: Option<u32>,
    /// Revocation delivered INSIDE a lease.
    ///
    /// No producer currently sets this field: the server writes `false` because it
    /// enforces revocation differently, refusing the next lease. A lease is
    /// permission, and "here is your permission; it is revoked" makes sense
    /// in exactly one case: the server can CATCH UP WITH already-issued
    /// permission. That channel will arrive with the transport.
    ///
    /// Thus the field is reserved rather than a dead check, and is retained not "just in
    /// case": the lease layout is frozen by `tests/kat/lease.kat`, and
    /// removing it would change bytes. The check below is in place so
    /// the channel, when it arrives, will not require changing the evaluator.
    pub revoked: bool,
    /// SERVER policy under its signature: how it tightened the author's policy.
    ///
    /// `None` means no server tightening; the lease behaves as before the
    /// field existed (document version 1). `Some` arrives only in a version 2 lease.
    ///
    /// The field lives here rather than as a separate evaluator parameter precisely
    /// to keep ONE evaluator: `check`, `unprotect`, the viewer, and the broker call
    /// `evaluate` with lease facts, and tightening is composed inside:
    /// callers cannot forget it because they do not perform the composition.
    ///
    /// This cannot EXPAND permissions: [`intersect`] is monotonic toward
    /// stricter policy, and author policy remains the upper bound (I-10).
    pub server_policy: Option<Policy>,
    /// Device key attestation accepted by the server during the issuance exchange (B6b,
    /// `docs/protocol.md` §9.11).
    ///
    /// The sole route to [`Binding::HardwareAttested`]: a device cannot
    /// declare itself attested; the server saw the verified chain,
    /// and it arrives under the server's signature. See [`effective_binding`].
    pub attested: Option<Attestation>,
    /// Device hardware clock reading at issuance.
    ///
    /// An independent reading can detect restored software state only if the hardware
    /// clock did not roll back with it. None is valid for devices without hardware
    /// time and provides no independent hardware-clock protection.
    pub tpm_clock: Option<TpmClock>,
}

/// TPM reset counter and persistent clock reading.
///
/// Compare both components independently: a decrease in either is rollback.
/// There is no Ord/PartialOrd because lexicographic comparison would accept a
/// higher counter with a lower clock. Raise a stored floor componentwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TpmClock {
    /// Number of platform resets. Increases, never decreases.
    pub reset_count: u32,
    /// CUMULATIVE milliseconds since the last TPM clear.
    ///
    /// Not "within the current period", as previously written here: that was
    /// false and led to missed rollback. Under TPM 2.0 the value
    /// is nonvolatile and survives power loss; only
    /// `TPM2_Clear` resets it, also resetting [`Self::reset_count`].
    ///
    /// Hence the comparison rule: **a decrease in `clock_ms` ALWAYS means rollback**,
    /// regardless of reset count. Honest hardware cannot decrease it.
    ///
    /// The value that resets at power-up is `time`; this type deliberately
    /// excludes it, since confusing the two would classify an ordinary reboot as rollback.
    pub clock_ms: u64,
}

/// Everything the decision depends on. Nothing is taken from the environment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Context {
    pub now: Timestamp,
    /// Source of now, currently informational: evaluate does not read this field.
    ///
    /// Wall and ServerAsserted therefore receive the same evaluation. Rollback checks
    /// use the monotonic floor and hardware readings, not a trust rule based on this tag.
    pub time_source: TimeSource,
    /// Greatest time the client has ever seen. Time cannot move
    /// backward: `now` below this value means a rollback attempt.
    pub monotonic_floor: Timestamp,
    pub first_open_at: Option<Timestamp>,
    pub opens_so_far: u32,
    /// Number of opens UNDER THE CURRENT lease.
    ///
    /// Distinct from [`Context::opens_so_far`], not a duplicate: that is the AUTHOR'S
    /// all-time limit (`Policy::max_opens`); this is ONE lease's budget
    /// (`LeaseFacts::opens_remaining`). The server grants the latter anew with each
    /// lease, so it must be counted anew; a shared counter would deny
    /// access forever after the first exhaustion.
    ///
    /// Reset by the counter owner when the lease `seq` changes.
    pub opens_under_lease: u32,
    pub device: DeviceFacts,
    /// Greatest `seq` the client has ever accepted for this file.
    pub highest_seq_seen: u64,
    pub online: bool,
    /// Policy hash computed by the client from signed bytes.
    pub policy_hash: [u8; 32],
}

/// What the client must do if the action is allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Obligations {
    pub watermark: bool,
    pub block_screen_capture: bool,
    pub suppress_crash_dumps: bool,
}

/// Permitted device/server clock skew, in seconds.
///
/// Five minutes, the same allowance used by Kerberos and one-time codes:
/// sufficient for unsynchronized consumer clocks and network delay
/// during lease issuance, yet orders of magnitude below the shortest meaningful
/// access period (hours). A larger value would grant a free lease extension equal
/// to itself; a smaller one would deny legitimate users whose
/// clocks drifted by a minute.
pub const MAX_CLOCK_SKEW_SECONDS: i64 = 300;

/// Denial reason. Deliberately detailed: the user needs a clear message,
/// and the journal needs a distinguishable event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    ActionNotPermitted(Action),
    /// The author ALLOWS the action, but server tightening denies it through a strict
    /// profile or possession-based rule: both use one lease field, so
    /// the client cannot distinguish them, and the person need not: both have the same contact.
    ///
    /// A separate reason, not a shade of the previous one, because the person must
    /// contact different parties: the author in the first case, the
    /// server operator in the second. "Not allowed by the author" for server tightening
    /// would be plainly false, with no visible way to recognize that.
    ///
    /// The distinction is decidable: composition denied what author policy
    /// allowed, so the second intersection operand imposed the denial.
    ActionTightenedByServer(Action),
    /// The policy contains rules this client does not recognize.
    ///
    /// Not "unknown field skipped", but complete rejection: understanding policy partly
    /// and enforcing only that part enforces different rules from those the
    /// author specified. An action added by a future version (`ai_ingest`, `ocr`,
    /// `forward`) must also be denied by old clients; the only
    /// honest way to ensure that is not to open the file at all.
    PolicyNotFullyUnderstood { unknown: u16 },
    ClockRollback,
    LeaseRollback { seen: u64, presented: u64 },
    /// Device hardware time is lower than at lease issuance.
    ///
    /// A TPM counter does not move backward. A lower reading means it was not
    /// the clock but the whole machine that was restored: snapshot rollback.
    TpmClockRollback { issued: TpmClock, presented: TpmClock },
    /// The lease requires hardware time, but the device did not present it.
    ///
    /// Denial, not a skipped check: a lease bound to hardware time cannot be verified
    /// without it, and "could not verify" must mean "not allowed"
    /// (I-10).
    TpmClockMissing,
    /// The lease requires hardware time, but reading it failed.
    ///
    /// Distinct from [`Self::TpmClockMissing`]: the same decision, denial, with "could not
    /// verify" meaning "not allowed" (I-10), but a different event. No clock
    /// is a machine property, suggesting "lease without hardware time"; a read failure
    /// is a transient event, suggesting "retry".
    TpmClockUnreadable,
    /// Hardware elapsed time exceeds the allowed wall-clock elapsed time.
    ///
    /// This reports a clock-consistency failure separately from ordinary lease expiry.
    /// The check compares elapsed readings, not hardware time against lease duration.
    HardwareClockOutranWallClock { hardware_ms: u64, wall_ms: u64 },
    NotYetValid,
    Expired,
    Revoked,
    OpenLimitReached,
    OfflineNotPermitted,
    NoLease,
    WrongDevice,
    PolicyHashMismatch,
    BindingTooWeak { required: Binding, actual: Binding },
    /// The lease was presented before the server supposedly issued it.
    ///
    /// Such a lease cannot be evaluated: `issued_at` is the only record
    /// of the last server exchange. If it lies in the future, both the offline
    /// window and lease lifetime count from a nonexistent moment.
    LeaseIssuedInTheFuture { issued_at: Timestamp, now: Timestamp },
    /// The server issued a lease longer than the author allowed in `Network::Lease`.
    ///
    /// Precisely why policy and lease must be bound:
    /// otherwise a compromised or simply generous server grants a month
    /// where the author allowed eight hours, and the client accepts it.
    LeaseOutlivesPolicy { allowed_seconds: i64, granted_seconds: i64 },
    /// The device has gone without contacting the server longer than the author allowed
    /// offline (`max_offline_seconds`).
    OfflineTooLong { allowed_seconds: i64, elapsed_seconds: i64 },
    /// The author counts validity from first open, but no record of it exists.
    FirstOpenNotRecorded,
}

impl fmt::Display for DenyReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ActionNotPermitted(a) => write!(f, "действие «{a}» не разрешено автором"),
            Self::ActionTightenedByServer(a) => write!(
                f,
                "действие «{a}» автор разрешил, но сервер его запретил своим ужесточением"
            ),
            Self::PolicyNotFullyUnderstood { unknown } => write!(
                f,
                "правила файла содержат действие {unknown}, которого эта версия не знает: \
                 нужна более новая версия клиента"
            ),
            Self::ClockRollback => write!(f, "часы устройства переведены назад"),
            Self::LeaseRollback { .. } => write!(f, "предъявлен устаревший лизинг"),
            Self::NotYetValid => write!(f, "срок доступа ещё не начался"),
            Self::Expired => write!(f, "срок доступа истёк"),
            Self::HardwareClockOutranWallClock { hardware_ms, wall_ms } => write!(
                f,
                "аппаратные часы обогнали системные: по TPM прошло {hardware_ms} мс, \
                 по системным — {wall_ms} мс. Часы TPM идут только пока машина \
                 включена, обогнать они не могут — значит системные отвели назад"
            ),
            Self::Revoked => write!(f, "доступ отозван автором"),
            Self::OpenLimitReached => write!(f, "исчерпан лимит открытий"),
            Self::OfflineNotPermitted => write!(f, "файл требует подключения к сети"),
            Self::NoLease => write!(f, "нет действующей лицензии на это устройство"),
            Self::WrongDevice => write!(f, "лицензия выдана другому устройству"),
            Self::PolicyHashMismatch => write!(f, "правила из лицензии не совпали с подписью автора"),
            Self::BindingTooWeak { .. } => {
                write!(f, "автор требует аппаратной привязки, на этом устройстве её нет")
            }
            Self::LeaseIssuedInTheFuture { .. } => {
                write!(f, "лицензия датирована будущим: проверьте часы устройства")
            }
            Self::LeaseOutlivesPolicy { allowed_seconds, .. } => write!(
                f,
                "лицензия выдана на больший срок, чем разрешил автор ({allowed_seconds} с)"
            ),
            Self::TpmClockRollback { .. } => {
                write!(f, "аппаратные часы устройства показывают меньше, чем при выдаче лизинга")
            }
            Self::TpmClockMissing => {
                write!(f, "лизинг требует аппаратных часов, устройство их не предъявило")
            }
            Self::TpmClockUnreadable => write!(
                f,
                "лизинг требует аппаратных часов, а прочитать их не удалось: это сбой чтения, \
                 а не отсутствие часов"
            ),
            Self::OfflineTooLong { allowed_seconds, .. } => write!(
                f,
                "без подключения к сети прошло больше {allowed_seconds} с, разрешённых автором"
            ),
            Self::FirstOpenNotRecorded => write!(
                f,
                "срок доступа отсчитывается с первого открытия, но записи о нём нет: \
                 откройте файл при подключении к сети"
            ),
        }
    }
}

/// Verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow(Obligations),
    Deny(DenyReason),
}

impl Verdict {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow(_))
    }
}

/// The sole point where access decisions are made.
///
/// Checks are ordered so general denials precede specific
/// ones: the user should learn "access revoked", not "printing forbidden".
pub fn evaluate(
    policy: &Policy,
    lease: Option<&LeaseFacts>,
    action: Action,
    ctx: &Context,
) -> Verdict {
    // СЕРВЕРНОЕ УЖЕСТОЧЕНИЕ СКЛАДЫВАЕТСЯ ЗДЕСЬ, до первой проверки, и складывает
    // его решатель, а не вызывающий.
    //
    // Это и есть причина, по которой профиль сервера едет полем ФАКТОВ ЛИЗИНГА,
    // а не отдельным параметром: `check`, `unprotect`, просмотрщик и брокер зовут
    // `evaluate` одинаково, и забыть ужесточение на одном из путей невозможно —
    // его никто из них не применяет руками.
    //
    // Пересечение, а не приоритет: сервер вправе сузить и не вправе расширить
    // (И-10). Непонятые действия обеих сторон объединяются внутри `intersect`,
    // поэтому проверка ниже видит и те, что назвал сервер: лизинг с правилом из
    // будущей версии закрывает файл, а не открывает его.
    let composed =
        lease.and_then(|l| l.server_policy.as_ref()).map(|server| intersect(policy, server));
    // Политика автора остаётся под рукой: по ней различается, кто запретил
    // действие — она сама или профиль сервера (`ActionTightenedByServer`).
    let author = policy;
    let policy = composed.as_ref().unwrap_or(policy);

    // Дальше: поняли ли мы правила целиком. Раньше это поле заполнялось
    // декодером и не читалось никем — то есть файл с действием из будущей версии
    // открывался старым клиентом так, будто правила поняты полностью. Ровно та
    // брешь, ради закрытия которой поле и заводилось.
    if let Some(unknown) = policy.unknown_actions.iter().next() {
        return Verdict::Deny(DenyReason::PolicyNotFullyUnderstood { unknown: *unknown });
    }

    if ctx.now < ctx.monotonic_floor {
        return Verdict::Deny(DenyReason::ClockRollback);
    }

    // Требование берётся ДЛЯ ДЕЙСТВИЯ, а не для политики целиком: `min_binding`
    // задаёт нижнюю границу всему файлу, тег 7 поднимает её отдельным действиям.
    // Максимум из двух, потому что поле умеет только ужесточать (И-10).
    let required = policy.binding_for(action);
    let actual = effective_binding(ctx.device.binding, lease);
    if actual < required {
        return Verdict::Deny(DenyReason::BindingTooWeak { required, actual });
    }

    let Some(lease) = lease else {
        return Verdict::Deny(DenyReason::NoLease);
    };

    if lease.revoked {
        return Verdict::Deny(DenyReason::Revoked);
    }
    if !digest_eq(&lease.device_fingerprint, &ctx.device.fingerprint) {
        return Verdict::Deny(DenyReason::WrongDevice);
    }
    if !digest_eq(&lease.policy_hash, &ctx.policy_hash) {
        return Verdict::Deny(DenyReason::PolicyHashMismatch);
    }
    if lease.seq < ctx.highest_seq_seen {
        return Verdict::Deny(DenyReason::LeaseRollback {
            seen: ctx.highest_seq_seen,
            presented: lease.seq,
        });
    }

    // Аппаратные часы — там, где системным и «полу» монотонности верить нельзя.
    //
    // `highest_seq_seen` и `monotonic_floor` живут в файле состояния, а файл
    // возвращается вместе со снапшотом виртуальной машины. Счётчик TPM снапшотом
    // не возвращается — если TPM настоящий (оговорка про vTPM записана в
    // `cc_keystore::ladder`).
    //
    // Проверка односторонняя: лизинг БЕЗ часов не требует их от устройства.
    // Обратное — лизинг с часами и устройство без них — отказ, потому что
    // проверить нечем, а «не смогли проверить» обязано читаться как «нельзя».
    if let Some(issued) = lease.tpm_clock {
        let presented = match ctx.device.tpm_clock {
            DeviceClock::Read(presented) => presented,
            DeviceClock::Absent => return Verdict::Deny(DenyReason::TpmClockMissing),
            DeviceClock::Unreadable => return Verdict::Deny(DenyReason::TpmClockUnreadable),
        };
        // A decrease in either reset counter or persistent clock means rollback.
        // Lexicographic comparison would hide a lower clock behind a higher counter.
        // A reboot with both components nondecreasing remains valid.
        if presented.clock_ms < issued.clock_ms || presented.reset_count < issued.reset_count {
            return Verdict::Deny(DenyReason::TpmClockRollback { issued, presented });
        }
    }

    // Лизинг, датированный будущим, оценивать нечем: `issued_at` — единственная
    // отметка о последнем разговоре с сервером, от неё отсчитываются и окно
    // оффлайна, и длина самого лизинга. Отметка из будущего растягивает оба окна
    // ровно на свою величину, поэтому лизинг отвергается целиком, а не
    // «поправляется». Допуск — только перекос часов, см. MAX_CLOCK_SKEW_SECONDS.
    if lease.issued_at.0.saturating_sub(ctx.now.0) > MAX_CLOCK_SKEW_SECONDS {
        return Verdict::Deny(DenyReason::LeaseIssuedInTheFuture {
            issued_at: lease.issued_at,
            now: ctx.now,
        });
    }

    match policy.network {
        Network::StrictOnline if !ctx.online => {
            return Verdict::Deny(DenyReason::OfflineNotPermitted);
        }
        Network::Lease { seconds, .. } => {
            // Автор задал длину лизинга, а решение принималось по одному только
            // `expires_at`. Пока эти два числа не связаны, сервер выдаёт месяц
            // там, где автор разрешил восемь часов, — то есть в обход §4
            // спецификации расширяет политику, вместо того чтобы её ужесточать.
            // saturating_sub: испорченный лизинг с `expires_at` у i64::MAX не
            // должен переполнением превращаться в короткий и потому приемлемый.
            let granted = lease.expires_at.0.saturating_sub(lease.issued_at.0);
            // Отрицательное окно (срок истёк раньше выдачи) тоже не то, что
            // разрешал автор: такой лизинг бессмыслен и принимать его нельзя.
            if granted < 0 || granted > seconds {
                return Verdict::Deny(DenyReason::LeaseOutlivesPolicy {
                    allowed_seconds: seconds,
                    granted_seconds: granted,
                });
            }
        }
        // StrictOnline с сетью: длина лизинга не создаёт окна оффлайна, потому
        // что каждое открытие всё равно требует обращения к серверу.
        Network::StrictOnline => {}
    }

    // Compare hardware and wall elapsed time to detect a restored software clock.
    // The hardware reading can remain ahead even when profile state is restored.
    // Keep wall-clock expiry too: hardware time need not advance while powered off,
    // so it cannot replace the lease's wall-clock deadline.
    if let (Some(issued), Some(presented)) = (lease.tpm_clock, ctx.device.tpm_clock.reading()) {
        // Compare hardware elapsed time with wall elapsed time, not lease duration.
        // Excess hardware elapsed indicates inconsistent wall time; shorter hardware
        // elapsed after sleep or power-off is permitted. Wall expiry is checked separately.
        let hardware_ms = presented.clock_ms.saturating_sub(issued.clock_ms);
        let wall_seconds = ctx.now.0.saturating_sub(lease.issued_at.0);
        // Отрицательный системный элапс означает, что часы отвели за момент
        // выдачи. Этот случай ловит проверка `NotYetValid`/пол монотонности; здесь
        // он даёт ноль, то есть любое движение часов TPM станет превышением.
        let wall_ms = u64::try_from(wall_seconds).unwrap_or(0).saturating_mul(1_000);
        // Допуск тот же, что у перекоса системных часов: сравниваются величины из
        // двух разных источников, и требовать от них совпадения до миллисекунды
        // значило бы отказывать на дрожании.
        let slack_ms = u64::try_from(MAX_CLOCK_SKEW_SECONDS).unwrap_or(0).saturating_mul(1_000);
        if hardware_ms > wall_ms.saturating_add(slack_ms) {
            return Verdict::Deny(DenyReason::HardwareClockOutranWallClock {
                hardware_ms,
                wall_ms,
            });
        }
    }

    if ctx.now > lease.expires_at {
        return Verdict::Deny(DenyReason::Expired);
    }

    // Второе число автора: сколько устройству позволено не разговаривать с
    // сервером. Оно может быть строго меньше длины лизинга, и тогда лизинг,
    // формально ещё живой, уже не даёт права работать без сети. Точка отсчёта —
    // `issued_at`: это последний момент, когда сервер видел это устройство.
    // Проверка стоит ПОСЛЕ проверки `expires_at`, чтобы истёкший лизинг
    // объяснялся пользователю как истёкший, а не как «слишком долго без сети».
    if !ctx.online
        && let Network::Lease { max_offline_seconds, .. } = policy.network
    {
        let elapsed = ctx.now.0.saturating_sub(lease.issued_at.0);
        if elapsed > max_offline_seconds {
            return Verdict::Deny(DenyReason::OfflineTooLong {
                allowed_seconds: max_offline_seconds,
                elapsed_seconds: elapsed,
            });
        }
    }

    match policy.validity {
        Validity::Always => {}
        Validity::Window { not_before, not_after } => {
            if ctx.now < not_before {
                return Verdict::Deny(DenyReason::NotYetValid);
            }
            if ctx.now > not_after {
                return Verdict::Deny(DenyReason::Expired);
            }
        }
        Validity::FromFirstOpen { seconds } => match ctx.first_open_at {
            Some(first) => {
                // saturating_add: переполнение означает срок, до которого никто
                // не доживёт, и превращать его в отказ незачем.
                if ctx.now.0 > first.0.saturating_add(seconds) {
                    return Verdict::Deny(DenyReason::Expired);
                }
            }
            // Записи о первом открытии нет — и ветка не делала ничего, то есть
            // клиенту достаточно было стереть своё состояние, чтобы срок автора
            // перестал существовать вовсе. Локально этот отсчёт восстановить
            // нечем: любое «считать первым открытием текущий момент» и есть то
            // самое бесконечное продление, только записанное явно.
            //
            // Единственный, кто помнит первое открытие, — сервер: он его и
            // обязан зафиксировать при выдаче лизинга. Поэтому файл с таким
            // сроком открывается ТОЛЬКО онлайн, пока запись не появится. Это не
            // ослабление: онлайн-открытие получает свежий лизинг, чьё окно уже
            // ограничено политикой автора проверками выше, так что худший исход
            // — доступ длиной в один разрешённый автором лизинг, а не вечный.
            None => {
                if !ctx.online {
                    return Verdict::Deny(DenyReason::FirstOpenNotRecorded);
                }
            }
        },
    }

    if let Some(max) = policy.max_opens
        && ctx.opens_so_far >= max
    {
        return Verdict::Deny(DenyReason::OpenLimitReached);
    }
    // БЮДЖЕТ ОДНОГО ЛИЗИНГА, и сравнивается он со счётчиком, а не с нулём.
    //
    // Прежняя редакция писала `if let Some(0) = …`, то есть отказывала ровно на
    // точном нуле. `Some(3)` не отличался от «без ограничения»: клиент значение
    // не уменьшал, сервер между лизингами не уменьшал тоже, и поле, названное в
    // сервере «бюджетом ОДНОГО лизинга», работало как булево «стоп». Автор,
    // назначивший бюджет в три открытия, получал неограниченный.
    // Аудит 2026-08-26, находка В-9.
    //
    // Сравнение одностороннее (`>=`), как и у `max_opens`: насыщенный счётчик
    // остаётся верным.
    if let Some(budget) = lease.opens_remaining
        && ctx.opens_under_lease >= budget
    {
        return Verdict::Deny(DenyReason::OpenLimitReached);
    }

    if policy.rule(action) != Rule::Allow {
        // КТО ИМЕННО ЗАПРЕТИЛ — часть решения, а не украшение текста: получателю
        // отсюда идти к автору или к оператору сервера, и это разные люди.
        return Verdict::Deny(if author.rule(action) == Rule::Allow {
            DenyReason::ActionTightenedByServer(action)
        } else {
            DenyReason::ActionNotPermitted(action)
        });
    }

    Verdict::Allow(Obligations {
        watermark: policy.watermark,
        block_screen_capture: policy.rule(Action::Screenshot) != Rule::Allow,
        suppress_crash_dumps: true,
    })
}

/// Intersection of author policy with what the server permits.
///
/// Monotonic, operating **only** toward stricter policy. This is a
/// structural guarantee: the server must not turn `Deny` into
/// `Allow`, even if compromised or acting deliberately.
#[must_use]
pub fn intersect(author: &Policy, server: &Policy) -> Policy {
    let mut result = author.clone();
    result.actions.retain(|action, rule| {
        *rule == Rule::Allow && server.actions.get(action).copied().unwrap_or_default() == Rule::Allow
    });
    result.min_binding = author.min_binding.max(server.min_binding);
    // Требования на действие складываются тем же максимумом, что и общее: сервер
    // вправе поднять ступень отдельному действию и не вправе опустить. Действия,
    // названные только сервером, попадают в результат — они ужесточают.
    for (action, binding) in &server.action_binding {
        let slot = result.action_binding.entry(*action).or_insert(*binding);
        *slot = (*slot).max(*binding);
    }
    result.watermark = author.watermark || server.watermark;
    result.max_opens = match (author.max_opens, server.max_opens) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, b) => b,
    };
    result.network = match (author.network, server.network) {
        (Network::StrictOnline, _) | (_, Network::StrictOnline) => Network::StrictOnline,
        (
            Network::Lease { seconds: a, max_offline_seconds: ao },
            Network::Lease { seconds: b, max_offline_seconds: bo },
        ) => Network::Lease { seconds: a.min(b), max_offline_seconds: ao.min(bo) },
    };
    result.validity = tighten_validity(author.validity, server.validity);
    // Непонятое действие у любой из сторон означает, что политика прочитана не
    // целиком, и `evaluate` отказывает по этому признаку. Объединение — это
    // ужесточение: множество непонятого может только вырасти.
    result.unknown_actions =
        author.unknown_actions.union(&server.unknown_actions).copied().collect();
    result
}

/// Validity interval permitting access at no moment in time.
///
/// Represents "conjunction cannot be expressed" in a type without a
/// "never" variant. A window starting after it ends is rejected by `evaluate` at the first
/// check, so denial comes from the common branch, not a special case.
const IMPOSSIBLE: Validity =
    Validity::Window { not_before: Timestamp(i64::MAX), not_after: Timestamp(i64::MIN) };

/// Intersect validity periods without widening either operand.
///
/// Always adds no restriction. Two windows use the later start and earlier end;
/// first-open durations use the shorter duration. A window/duration conjunction
/// cannot fit the current single variant, so deny instead of dropping a constraint.
/// Representing both would require a policy-format decision.
fn tighten_validity(author: Validity, server: Validity) -> Validity {
    match (author, server) {
        (Validity::Always, other) | (other, Validity::Always) => other,
        (
            Validity::Window { not_before: a_from, not_after: a_to },
            Validity::Window { not_before: b_from, not_after: b_to },
        ) => Validity::Window {
            not_before: a_from.max(b_from),
            not_after: a_to.min(b_to),
        },
        (Validity::FromFirstOpen { seconds: a }, Validity::FromFirstOpen { seconds: b }) => {
            Validity::FromFirstOpen { seconds: a.min(b) }
        }
        (Validity::Window { .. }, Validity::FromFirstOpen { .. })
        | (Validity::FromFirstOpen { .. }, Validity::Window { .. }) => IMPOSSIBLE,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {

    /// A PER-ACTION REQUIREMENT RAISES THE LEVEL FOR THAT ACTION SPECIFICALLY.
    ///
    /// Viewing can use software binding, editing cannot: the edit signature
    /// cannot be stronger than the machine's binding level. A single policy-wide `min_binding`
    /// cannot express this, and this probe verifies that the additional requirement
    /// works exactly as intended.
    #[test]
    fn a_per_action_requirement_raises_the_bar_for_that_action_alone() {
        let mut policy = viewable();
        let _ = policy.actions.insert(Action::Edit, Rule::Allow);
        let _ = policy.action_binding.insert(Action::Edit, Binding::HardwareAttested);

        // Устройство на аппаратной ступени: смотреть ему можно, править — нет.
        // Фикстура `device()` даёт именно её, и требование правки поднято НА
        // СТУПЕНЬ выше, чтобы проба разделяла два действия, а не машину.
        let ctx = ctx(60);
        assert_eq!(ctx.device.binding, Binding::Hardware, "предпосылка фикстуры");
        let lease = lease();
        assert!(matches!(evaluate(&policy, Some(&lease), Action::View, &ctx), Verdict::Allow { .. }));
        assert!(matches!(
            evaluate(&policy, Some(&lease), Action::Edit, &ctx),
            Verdict::Deny(DenyReason::BindingTooWeak {
                required: Binding::HardwareAttested,
                ..
            })
        ));
    }

    /// THE FIELD CAN ONLY TIGHTEN; IT DOES NOT REMOVE THE GLOBAL REQUIREMENT.
    ///
    /// An entry weaker than `min_binding` must not relax it, or `intersect`
    /// would cease being monotonic and could turn `Deny` into `Allow`.
    #[test]
    fn the_field_only_tightens_and_never_lowers_the_overall_requirement() {
        let mut policy = viewable();
        policy.min_binding = Binding::Hardware;
        let _ = policy.action_binding.insert(Action::View, Binding::Software);
        assert_eq!(policy.binding_for(Action::View), Binding::Hardware);
    }

    /// THE SERVER MAY RAISE AN ACTION'S BINDING LEVEL, NEVER LOWER IT.
    #[test]
    fn the_server_may_raise_a_per_action_bar_and_never_lower_it() {
        let mut author = Policy::deny_all();
        let _ = author.action_binding.insert(Action::Edit, Binding::Hardware);
        let _ = author.action_binding.insert(Action::Print, Binding::Hardware);

        let mut server = Policy::deny_all();
        let _ = server.action_binding.insert(Action::Edit, Binding::HardwareAttested);
        let _ = server.action_binding.insert(Action::Print, Binding::Software);
        // Действие, названное ТОЛЬКО сервером, тоже ужесточает.
        let _ = server.action_binding.insert(Action::Export, Binding::Hardware);

        let result = intersect(&author, &server);
        assert_eq!(result.action_binding.get(&Action::Edit), Some(&Binding::HardwareAttested));
        assert_eq!(result.action_binding.get(&Action::Print), Some(&Binding::Hardware));
        assert_eq!(result.action_binding.get(&Action::Export), Some(&Binding::Hardware));
    }
    use super::*;

    const ALL_ACTIONS: [Action; 6] = [
        Action::View,
        Action::Edit,
        Action::Print,
        Action::Clipboard,
        Action::Export,
        Action::Screenshot,
    ];

    #[test]
    fn digest_comparison_agrees_with_equality_on_every_byte_position() {
        // Копия проверки из oc-crypto: реализация здесь своя (крейт без
        // зависимостей), поэтому и проверять её надо здесь, а не полагаться на
        // то, что «там же протестировано».
        let base = [0x5Au8; 32];
        assert!(digest_eq(&base, &base.clone()));
        for position in 0..32usize {
            let mut other = base;
            if let Some(byte) = other.get_mut(position) {
                *byte ^= 0x01;
            }
            assert!(!digest_eq(&base, &other), "различие в байте {position} не замечено");
        }
    }

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


    /// ONE LEASE'S BUDGET IS ENFORCED FOR EVERY VALUE, NOT ONLY ZERO.
    ///
    /// The former implementation used `if let Some(0) = …`, rejecting only at
    /// exactly zero. `Some(3)` was indistinguishable from "unlimited": nobody
    /// decremented it, neither client nor server between leases, and the field
    /// the server called "ONE lease's budget" acted as a Boolean stop flag.
    /// Audit 2026-08-26, finding V-9.
    ///
    /// All three points are tested, with the middle, at the boundary, being crucial.
    #[test]
    fn the_per_lease_open_budget_is_spent_and_not_merely_checked_for_zero() {
        let policy = Policy::deny_all().allow(Action::View);
        let mut facts = lease();
        facts.opens_remaining = Some(3);

        // Под бюджетом — разрешено.
        for used in 0..3u32 {
            let mut c = ctx(1_000);
            c.opens_under_lease = used;
            assert!(
                evaluate(&policy, Some(&facts), Action::View, &c).is_allowed(),
                "бюджет 3, потрачено {used} — обязано быть разрешено"
            );
        }

        // РОВНО НА ГРАНИЦЕ — уже нет. Здесь и жила дыра: раньше проходило.
        let mut c = ctx(1_000);
        c.opens_under_lease = 3;
        assert_eq!(
            evaluate(&policy, Some(&facts), Action::View, &c),
            Verdict::Deny(DenyReason::OpenLimitReached),
            "исчерпанный бюджет лизинга не остановил открытие"
        );

        // Контроль осмысленности: без бюджета счётчик ничего не запрещает.
        // Без этой половины проба зеленела бы и у решателя, отказывающего всем.
        facts.opens_remaining = None;
        let mut c = ctx(1_000);
        c.opens_under_lease = 1_000_000;
        assert!(
            evaluate(&policy, Some(&facts), Action::View, &c).is_allowed(),
            "лизинг без бюджета стал ограничивать"
        );
    }

    /// LEASE BUDGET AND AUTHOR LIMIT ARE DIFFERENT QUANTITIES.
    ///
    /// A guard against merging them: `max_opens` counts all-time opens
    /// (`opens_so_far`); the budget counts under the current lease (`opens_under_lease`).
    /// Merge them, and a new lease would no longer bring a fresh budget.
    #[test]
    fn the_lease_budget_and_the_author_limit_count_different_things() {
        let policy = Policy { max_opens: Some(10), ..Policy::deny_all() }.allow(Action::View);
        let mut facts = lease();
        facts.opens_remaining = Some(2);

        // Предел автора далеко не исчерпан, бюджет лизинга — исчерпан.
        let mut c = ctx(1_000);
        c.opens_so_far = 5;
        c.opens_under_lease = 2;
        assert_eq!(
            evaluate(&policy, Some(&facts), Action::View, &c),
            Verdict::Deny(DenyReason::OpenLimitReached),
            "бюджет лизинга не сработал при незакрытом пределе автора"
        );

        // И наоборот: новый лизинг обнулил свой счётчик, а предел автора помнит всё.
        let mut c = ctx(1_000);
        c.opens_so_far = 10;
        c.opens_under_lease = 0;
        assert_eq!(
            evaluate(&policy, Some(&facts), Action::View, &c),
            Verdict::Deny(DenyReason::OpenLimitReached),
            "предел автора забыт при свежем бюджете лизинга"
        );
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

    fn viewable() -> Policy {
        Policy { network: Network::Lease { seconds: 8 * 3600, max_offline_seconds: 8 * 3600 },
            ..Policy::deny_all() }
            .allow(Action::View)
    }

    /// Enumerate policies to check `intersect` monotonicity.
    ///
    /// Not random sampling: pairs are exhaustive over a grid where every
    /// field takes both a "weak" and "strong" value, while `validity` takes all three
    /// kinds plus two representatives of each homogeneous kind. Precisely on a heterogeneous pair
    /// A lease issued with hardware time cannot be verified without it: denial.
    ///
    /// Doctrine: "could not verify" means "not allowed" (I-10).
    /// The opposite would create a one-line bypass: merely present
    /// a device without hardware time, and the rollback check disappears.
    #[test]
    fn a_lease_bound_to_hardware_clock_is_refused_without_one() {
        let policy = viewable();
        let mut l = lease();
        l.tpm_clock = Some(TpmClock { reset_count: 3, clock_ms: 1_000 });

        let c = ctx(60);
        assert_eq!(c.device.tpm_clock, DeviceClock::Absent, "предпосылка теста: часов у устройства нет");
        assert_eq!(
            evaluate(&policy, Some(&l), Action::View, &c),
            Verdict::Deny(DenyReason::TpmClockMissing)
        );

        // СБОЙ ЧТЕНИЯ — ТОЖЕ ОТКАЗ, но своей причиной. Решение то же (И-10);
        // неотличимость причин и была дефектом: случайный сбой TBS на машине с
        // часами назывался «устройство их не предъявило».
        let mut c = ctx(60);
        c.device.tpm_clock = DeviceClock::Unreadable;
        assert_eq!(
            evaluate(&policy, Some(&l), Action::View, &c),
            Verdict::Deny(DenyReason::TpmClockUnreadable)
        );

        // Контроль: лизинг без часов сбой чтения не трогает — его и не спрашивают.
        assert!(evaluate(&policy, Some(&lease()), Action::View, &c).is_allowed());
    }

    /// Decreasing either hardware-clock component must reject as rollback.
    /// A higher reset counter cannot excuse a lower persistent clock; both components
    /// nondecreasing is the valid reboot control.
    #[test]
    fn hardware_clock_going_backwards_is_a_rollback_but_a_reboot_is_not() {
        let policy = viewable();
        let issued = TpmClock { reset_count: 3, clock_ms: 10_000 };
        let mut l = lease();
        l.tpm_clock = Some(issued);

        let with_clock = |clock: TpmClock| {
            let mut c = ctx(60);
            c.device.tpm_clock = DeviceClock::Read(clock);
            c
        };

        // Тот же период, время назад — откат.
        let back = TpmClock { reset_count: 3, clock_ms: 9_999 };
        assert_eq!(
            evaluate(&policy, Some(&l), Action::View, &with_clock(back)),
            Verdict::Deny(DenyReason::TpmClockRollback { issued, presented: back })
        );

        // Счётчик сбросов назад — откат, даже если время больше.
        let older_period = TpmClock { reset_count: 2, clock_ms: 999_999 };
        assert_eq!(
            evaluate(&policy, Some(&l), Action::View, &with_clock(older_period)),
            Verdict::Deny(DenyReason::TpmClockRollback { issued, presented: older_period })
        );

        // Перезагрузка: счётчик больше, время ТОЖЕ больше — это НЕ откат.
        //
        // Здесь стояло `clock_ms: 1` с подписью «счётчик больше, время меньше —
        // это не откат». Подпись описывала неверную модель железа: по TPM 2.0
        // `clock` энергонезависим и при перезагрузке продолжает расти, а не
        // начинается заново. Такого входа честное железо не производит вовсе.
        //
        // Опасна была не неточность, а следствие: под лексикографическим
        // сравнением пара «счётчик больше, часы меньше» проходила как законная, а
        // получить её можно ровно одним способом — откатить снапшот и
        // перезагрузиться. Проверка против отката снапшота пропускала откат
        // снапшота, и тест закреплял это как правильное поведение.
        let after_reboot = TpmClock { reset_count: 4, clock_ms: 10_500 };
        assert!(
            evaluate(&policy, Some(&l), Action::View, &with_clock(after_reboot)).is_allowed(),
            "перезагрузка платформы принята за откат: отказ после каждого включения"
        );

        // А вот счётчик больше при МЕНЬШЕМ времени — откат, и теперь он ловится.
        let rolled_then_rebooted = TpmClock { reset_count: 4, clock_ms: 1 };
        assert_eq!(
            evaluate(&policy, Some(&l), Action::View, &with_clock(rolled_then_rebooted)),
            Verdict::Deny(DenyReason::TpmClockRollback {
                issued,
                presented: rolled_then_rebooted
            }),
            "откат снапшота с последующей перезагрузкой не обнаружен"
        );

        // Те же показания — не откат.
        assert!(evaluate(&policy, Some(&l), Action::View, &with_clock(issued)).is_allowed());
    }

    /// A lease without hardware time does not require it from a device that has it.
    ///
    /// Checks the one-way requirement: a server that omitted hardware time from the lease
    /// must not receive rejection from a device presenting it.
    #[test]
    fn a_lease_without_a_clock_ignores_the_one_the_device_has() {
        let policy = viewable();
        let l = lease();
        assert!(l.tpm_clock.is_none());

        let mut c = ctx(60);
        c.device.tpm_clock = DeviceClock::Read(TpmClock { reset_count: 1, clock_ms: 5 });
        assert!(evaluate(&policy, Some(&l), Action::View, &c).is_allowed());
    }

    /// (window versus first-open duration) was where the former implementation stayed silent.
    fn grid() -> Vec<Policy> {
        let validities = [
            Validity::Always,
            Validity::Window { not_before: Timestamp(10), not_after: Timestamp(200) },
            Validity::Window { not_before: Timestamp(50), not_after: Timestamp(90) },
            Validity::FromFirstOpen { seconds: 30 },
            Validity::FromFirstOpen { seconds: 500 },
        ];
        let networks = [
            Network::StrictOnline,
            Network::Lease { seconds: 3600, max_offline_seconds: 3600 },
        ];
        let bindings = [Binding::Software, Binding::Hardware];
        let opens = [None, Some(3u32)];
        let action_sets: [&[Action]; 3] = [&[], &[Action::View], &[Action::View, Action::Print]];
        // Два поля, которые сетка держала НЕПОДВИЖНЫМИ до 2026-08-26, из-за чего
        // property-тест проверял пять полей из семи и назывался проверкой всех.
        //
        // `watermark` — обязательство, и пересекается он ИЛИ, а не И: знак,
        // потребованный любой из сторон, обязан остаться. Инертное `false` с
        // обеих сторон эту ветку не исполняло ни разу.
        //
        // `unknown_actions` — теги действий, которых клиент не знает. Инертное
        // пустое множество не исполняло объединение, а именно оно и держит
        // свойство «старый клиент не считает, будто увидел политику целиком».
        // Аудит 2026-08-26, находка С-17.
        let watermarks = [false, true];
        let unknowns: [&[u16]; 3] = [&[], &[9000], &[9000, 9001]];

        let mut out = Vec::new();
        for validity in validities {
            for network in networks {
                for min_binding in bindings {
                    for max_opens in opens {
                        for actions in action_sets {
                            for watermark in watermarks {
                                for unknown in unknowns {
                                    let mut policy = Policy {
                                        validity,
                                        network,
                                        min_binding,
                                        max_opens,
                                        watermark,
                                        unknown_actions: unknown.iter().copied().collect(),
                                        ..Policy::deny_all()
                                    };
                                    for action in actions {
                                        policy = policy.allow(*action);
                                    }
                                    out.push(policy);
                                }
                            }
                        }
                    }
                }
            }
        }
        out
    }

    #[test]
    fn intersect_never_widens_access_for_any_pair_of_policies() {
        // Свойство, которое docs/format.md объявляет проверяемым, а проверки не
        // было ни одной: если пересечение что-то разрешает, то это разрешала и
        // каждая из сторон по отдельности. Сервер не может превратить Deny в
        // Allow, даже будучи скомпрометированным.
        //
        // Прежняя реализация брала validity и unknown_actions у автора и не
        // пересекала их вовсе, поэтому сервер не мог ужесточить срок — хотя
        // ужесточение и есть единственное, что ему разрешено.
        let policies = grid();
        // Лизинг обязан быть совместим с САМОЙ СТРОГОЙ политикой сетки, иначе
        // измеряется не то. Восьмичасовой лизинг из `lease()` не влезает в
        // политику `Lease { seconds: 3600 }`, и та отказывает по
        // `LeaseOutlivesPolicy` — но это проверка согласованности лизинга с
        // политикой, а не расширение доступа: пересечение, оказавшееся
        // `StrictOnline`, отменяет оффлайн целиком, то есть строже, а не слабее.
        // Взяв несовместимый лизинг, тест объявил бы дырой ровно ту ситуацию,
        // где ужесточение сработало.
        let lease = LeaseFacts { expires_at: Timestamp(3600), ..lease() };
        let moments = [Timestamp(0), Timestamp(60), Timestamp(150), Timestamp(1_000)];

        for author in &policies {
            for server in &policies {
                let merged = intersect(author, server);
                for action in ALL_ACTIONS {
                    for now in moments {
                        let mut context = ctx(now.0);
                        context.first_open_at = Some(Timestamp(0));
                        if !evaluate(&merged, Some(&lease), action, &context).is_allowed() {
                            continue;
                        }
                        assert!(
                            evaluate(author, Some(&lease), action, &context).is_allowed(),
                            "пересечение разрешило {action:?} в момент {now:?}, автор — нет"
                        );
                        assert!(
                            evaluate(server, Some(&lease), action, &context).is_allowed(),
                            "пересечение разрешило {action:?} в момент {now:?}, сервер — нет\n\
                             автор:  {author:?}\nсервер: {server:?}\nитог:   {merged:?}\n\
                             вердикт сервера: {:?}",
                            evaluate(server, Some(&lease), action, &context)
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn a_profile_carried_in_the_lease_decides_exactly_as_the_composed_policy() {
        // Свойство переноса, а не пересечения: сервер, положивший профиль в
        // лизинг, обязан получить РОВНО то решение, которое получил бы сервер,
        // применивший пересечение у себя. Иначе ужесточение, уехавшее по проводу,
        // означало бы не то же самое, что ужесточение при выдаче, — и офлайн
        // отличался бы от онлайна не сроком, а правами.
        //
        // Проверяется на всей сетке, а не на паре случаев: расхождение здесь
        // возникает в одном поле из восьми, и именно то поле забудут.
        let policies = grid();
        let base = LeaseFacts { expires_at: Timestamp(3600), ..lease() };
        let moments = [Timestamp(0), Timestamp(60), Timestamp(150), Timestamp(1_000)];

        for author in &policies {
            for server in &policies {
                let composed = intersect(author, server);
                let carried = LeaseFacts { server_policy: Some(server.clone()), ..base.clone() };
                for action in ALL_ACTIONS {
                    for now in moments {
                        let mut context = ctx(now.0);
                        context.first_open_at = Some(Timestamp(0));
                        let by_transport = evaluate(author, Some(&carried), action, &context);
                        let by_composition = evaluate(&composed, Some(&base), action, &context);
                        // Решение обязано совпасть целиком — кроме ИМЕНИ
                        // виновника у запрета действия: перенос знает, что
                        // действие дал автор и отнял сервер, а заранее
                        // пересечённая политика этого не помнит. Различие
                        // допускается ровно одно и проверяется точно: у
                        // переноса `ActionTightenedByServer`, у пересечения —
                        // `ActionNotPermitted` того же действия, и автор это
                        // действие действительно разрешал. Сравнивать «по
                        // модулю причин» целиком было бы слепее: пропустило бы
                        // расхождение в любом другом отказе.
                        let attributed = matches!(
                            (&by_transport, &by_composition),
                            (
                                Verdict::Deny(DenyReason::ActionTightenedByServer(a)),
                                Verdict::Deny(DenyReason::ActionNotPermitted(b)),
                            ) if a == b && *a == action && author.rule(action) == Rule::Allow
                        );
                        assert!(
                            attributed || by_transport == by_composition,
                            "перенос профиля разошёлся с пересечением: {action:?} в {now:?}; \
                             перенос {by_transport:?}, пересечение {by_composition:?}; \
                             автор: {author:?}; сервер: {server:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn a_profile_in_the_lease_never_widens_what_the_author_allowed() {
        // То же свойство И-10, но на ТОМ пути, которым профиль ходит на деле.
        // Предыдущий property-тест мерит `intersect`; этот — `evaluate` с полем
        // лизинга, то есть ровно то, что исполняет клиент получателя.
        let policies = grid();
        let base = LeaseFacts { expires_at: Timestamp(3600), ..lease() };

        for author in &policies {
            for server in &policies {
                let carried = LeaseFacts { server_policy: Some(server.clone()), ..base.clone() };
                for action in ALL_ACTIONS {
                    let context = ctx(60);
                    if !evaluate(author, Some(&carried), action, &context).is_allowed() {
                        continue;
                    }
                    assert!(
                        evaluate(author, Some(&base), action, &context).is_allowed(),
                        "профиль в лизинге разрешил {action:?}, автор — нет"
                    );
                }
            }
        }
    }

    #[test]
    fn a_window_and_a_from_first_open_cannot_be_merged_into_one_and_so_deny() {
        // Конъюнкция двух независимых ограничений одним членом Validity не
        // выражается. Выбрать любое из них значило бы расширить доступ
        // относительно второго, поэтому здесь отказ, а не выбор.
        let author = Policy {
            validity: Validity::Window { not_before: Timestamp(0), not_after: Timestamp(1_000) },
            network: Network::Lease { seconds: 3600, max_offline_seconds: 3600 },
            ..Policy::deny_all()
        }
        .allow(Action::View);
        let server = Policy { validity: Validity::FromFirstOpen { seconds: 900 }, ..author.clone() };

        let merged = intersect(&author, &server);
        for now in [0i64, 10, 500, 899, 1_000] {
            assert!(
                !evaluate(&merged, Some(&lease()), Action::View, &ctx(now)).is_allowed(),
                "разнородная пара сроков разрешила доступ в момент {now}"
            );
        }
    }

    #[test]
    fn the_ordinary_case_works() {
        let v = evaluate(&viewable(), Some(&lease()), Action::View, &ctx(60));
        assert!(v.is_allowed());
    }

    #[test]
    fn blocking_capture_is_the_default_obligation() {
        // Скриншот не разрешён, значит клиент обязан включить блокировку захвата,
        // а не просто "не показывать кнопку".
        let Verdict::Allow(o) = evaluate(&viewable(), Some(&lease()), Action::View, &ctx(60)) else {
            panic!("ожидалось разрешение");
        };
        assert!(o.block_screen_capture);
        assert!(o.suppress_crash_dumps);
    }

    #[test]
    fn a_deny_rule_is_never_overridden_by_any_context() {
        // Главный инвариант ядра. Перебираем контексты, которые могли бы
        // «случайно» разрешить действие, и убеждаемся, что ни один не разрешает.
        let policy = viewable();
        for action in ALL_ACTIONS {
            if policy.rule(action) == Rule::Allow {
                continue;
            }
            for now in [0, 1, 60, 7999, 8 * 3600 - 1] {
                for opens in [0, 1, u32::MAX] {
                    for online in [true, false] {
                        let mut c = ctx(now);
                        c.opens_so_far = opens;
                        c.online = online;
                        let v = evaluate(&policy, Some(&lease()), action, &c);
                        assert!(
                            !v.is_allowed(),
                            "действие {action:?} разрешено при now={now}, opens={opens}, online={online}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn a_policy_this_client_did_not_fully_understand_permits_nothing() {
        // Действие из будущей версии обязано запрещать файл целиком, а не тихо
        // выпадать из рассмотрения: иначе достаточно предъявить клиент постарше,
        // чтобы обойти правило, которого он не знает.
        let mut policy = viewable();
        let _ = policy.unknown_actions.insert(999);
        for action in ALL_ACTIONS {
            assert_eq!(
                evaluate(&policy, Some(&lease()), action, &ctx(60)),
                Verdict::Deny(DenyReason::PolicyNotFullyUnderstood { unknown: 999 }),
                "действие {action:?} прошло при непонятой политике"
            );
        }
    }

    #[test]
    fn nothing_is_allowed_without_a_lease() {
        for action in ALL_ACTIONS {
            let v = evaluate(&viewable(), None, action, &ctx(60));
            assert_eq!(v, Verdict::Deny(DenyReason::NoLease));
        }
    }

    #[test]
    fn a_policy_that_says_nothing_permits_nothing() {
        let silent = Policy::deny_all();
        for action in ALL_ACTIONS {
            assert!(!evaluate(&silent, Some(&lease()), action, &ctx(60)).is_allowed());
        }
    }

    #[test]
    fn winding_the_clock_back_is_refused_before_anything_else() {
        let mut c = ctx(50);
        c.monotonic_floor = Timestamp(100);
        assert_eq!(
            evaluate(&viewable(), Some(&lease()), Action::View, &c),
            Verdict::Deny(DenyReason::ClockRollback)
        );
    }

    #[test]
    fn restoring_an_old_lease_is_refused() {
        let mut c = ctx(60);
        c.highest_seq_seen = 5;
        let mut old = lease();
        old.seq = 2;
        assert_eq!(
            evaluate(&viewable(), Some(&old), Action::View, &c),
            Verdict::Deny(DenyReason::LeaseRollback { seen: 5, presented: 2 })
        );
    }

    #[test]
    fn revocation_beats_everything_else_that_looks_fine() {
        let mut revoked = lease();
        revoked.revoked = true;
        assert_eq!(
            evaluate(&viewable(), Some(&revoked), Action::View, &ctx(60)),
            Verdict::Deny(DenyReason::Revoked)
        );
    }

    #[test]
    fn a_lease_for_another_device_is_refused() {
        let mut other = lease();
        other.device_fingerprint = [7; 32];
        assert_eq!(
            evaluate(&viewable(), Some(&other), Action::View, &ctx(60)),
            Verdict::Deny(DenyReason::WrongDevice)
        );
    }

    #[test]
    fn a_server_that_rewrites_the_rules_is_caught() {
        // Сервер выдал лизинг под другую политику, чем подписал автор.
        let mut tampered = lease();
        tampered.policy_hash = [0xaa; 32];
        assert_eq!(
            evaluate(&viewable(), Some(&tampered), Action::View, &ctx(60)),
            Verdict::Deny(DenyReason::PolicyHashMismatch)
        );
    }

    #[test]
    fn offline_works_until_the_lease_runs_out_and_not_after() {
        let policy = viewable();
        let mut c = ctx(60);
        c.online = false;
        assert!(evaluate(&policy, Some(&lease()), Action::View, &c).is_allowed());

        let mut later = ctx(8 * 3600 + 1);
        later.online = false;
        assert_eq!(
            evaluate(&policy, Some(&lease()), Action::View, &later),
            Verdict::Deny(DenyReason::Expired)
        );
    }

    #[test]
    fn strict_online_refuses_immediately_without_network() {
        let policy = Policy { network: Network::StrictOnline, ..Policy::deny_all() }
            .allow(Action::View);
        let mut c = ctx(60);
        c.online = false;
        assert_eq!(
            evaluate(&policy, Some(&lease()), Action::View, &c),
            Verdict::Deny(DenyReason::OfflineNotPermitted)
        );
    }

    #[test]
    fn software_binding_is_refused_when_the_author_demands_hardware() {
        let policy = Policy { min_binding: Binding::HardwareAttested, ..viewable() };
        let v = evaluate(&policy, Some(&lease()), Action::View, &ctx(60));
        assert_eq!(
            v,
            Verdict::Deny(DenyReason::BindingTooWeak {
                required: Binding::HardwareAttested,
                actual: Binding::Hardware,
            })
        );
    }

    /// ONLY THE LEASE DECLARES ATTESTATION (B6b).
    ///
    /// A device calling itself attested remains hardware-bound until
    /// the flag arrives under the server's signature; that flag raises a hardware-bound
    /// device, never a software-bound one.
    #[test]
    fn only_the_lease_declares_attestation() {
        let policy = Policy { min_binding: Binding::HardwareAttested, ..viewable() };
        let mut claiming = ctx(60);
        claiming.device.binding = Binding::HardwareAttested;
        assert_eq!(
            evaluate(&policy, Some(&lease()), Action::View, &claiming),
            Verdict::Deny(DenyReason::BindingTooWeak {
                required: Binding::HardwareAttested,
                actual: Binding::Hardware,
            }),
            "самоаттестация устройства принята"
        );

        let attested = LeaseFacts { attested: Some(Attestation::EnrolledEk), ..lease() };
        assert!(evaluate(&policy, Some(&attested), Action::View, &ctx(60)).is_allowed());

        let mut software = ctx(60);
        software.device.binding = Binding::Software;
        assert_eq!(
            evaluate(&policy, Some(&attested), Action::View, &software),
            Verdict::Deny(DenyReason::BindingTooWeak {
                required: Binding::HardwareAttested,
                actual: Binding::Software,
            }),
            "признак аттестации поднял программный ключ"
        );
        // Без лизинга ступень не выше аппаратной.
        assert_eq!(effective_binding(Binding::HardwareAttested, None), Binding::Hardware);
    }

    #[test]
    fn a_lease_longer_than_the_author_allowed_is_refused() {
        // Автор разрешил час оффлайна, сервер выдал лизинг на десять лет.
        // Без связи политики с лизингом клиент принимал такой лизинг молча.
        let hour = 3600;
        let policy =
            Policy { network: Network::Lease { seconds: hour, max_offline_seconds: hour },
                ..Policy::deny_all() }
                .allow(Action::View);
        let ten_years = 10 * 365 * 24 * hour;
        let generous =
            LeaseFacts { issued_at: Timestamp(0), expires_at: Timestamp(ten_years), ..lease() };
        assert_eq!(
            evaluate(&policy, Some(&generous), Action::View, &ctx(60)),
            Verdict::Deny(DenyReason::LeaseOutlivesPolicy {
                allowed_seconds: hour,
                granted_seconds: ten_years,
            })
        );
    }

    #[test]
    fn a_lease_of_exactly_the_allowed_length_is_accepted_and_one_second_more_is_not() {
        // Граница: отказ обязан начинаться ровно там, где автор поставил предел,
        // иначе «не больше часа» на практике означает «час с хвостиком».
        let hour = 3600;
        let policy =
            Policy { network: Network::Lease { seconds: hour, max_offline_seconds: hour },
                ..Policy::deny_all() }
                .allow(Action::View);
        let exact =
            LeaseFacts { issued_at: Timestamp(0), expires_at: Timestamp(hour), ..lease() };
        assert!(evaluate(&policy, Some(&exact), Action::View, &ctx(60)).is_allowed());

        let longer = LeaseFacts { expires_at: Timestamp(hour + 1), ..exact };
        assert!(!evaluate(&policy, Some(&longer), Action::View, &ctx(60)).is_allowed());
    }

    #[test]
    fn an_absurd_lease_window_does_not_overflow_into_an_acceptable_one() {
        // Противник целится в переполнение: разность i64::MAX - i64::MIN не
        // помещается в i64, и наивное вычитание дало бы маленькое число, то есть
        // «короткий» и потому приемлемый лизинг.
        let policy =
            Policy { network: Network::Lease { seconds: 3600, max_offline_seconds: 3600 },
                ..Policy::deny_all() }
                .allow(Action::View);
        let absurd = LeaseFacts {
            issued_at: Timestamp(i64::MIN),
            expires_at: Timestamp(i64::MAX),
            ..lease()
        };
        assert!(!evaluate(&policy, Some(&absurd), Action::View, &ctx(60)).is_allowed());

        // И обратная бессмыслица: срок истёк раньше, чем лизинг выдан.
        let backwards =
            LeaseFacts { issued_at: Timestamp(1000), expires_at: Timestamp(500), ..lease() };
        assert!(!evaluate(&policy, Some(&backwards), Action::View, &ctx(600)).is_allowed());
    }

    #[test]
    fn an_offline_stretch_longer_than_the_author_allowed_is_refused() {
        // Окно оффлайна может быть строго короче лизинга: лизинг живёт восемь
        // часов, но без сети автор разрешил работать только десять минут.
        let policy =
            Policy { network: Network::Lease { seconds: 8 * 3600, max_offline_seconds: 600 },
                ..Policy::deny_all() }
                .allow(Action::View);

        let mut offline = ctx(700);
        offline.online = false;
        assert_eq!(
            evaluate(&policy, Some(&lease()), Action::View, &offline),
            Verdict::Deny(DenyReason::OfflineTooLong {
                allowed_seconds: 600,
                elapsed_seconds: 700,
            })
        );

        // Тот же момент, но с сетью: обращение к серверу и есть то, чего автор
        // требовал, поэтому отказа быть не должно.
        assert!(evaluate(&policy, Some(&lease()), Action::View, &ctx(700)).is_allowed());
    }

    #[test]
    fn a_lease_issued_in_the_future_is_refused() {
        let policy = viewable();
        let issued = 10_000_000;
        let not_yet = LeaseFacts {
            issued_at: Timestamp(issued),
            expires_at: Timestamp(issued + 8 * 3600),
            ..lease()
        };
        assert_eq!(
            evaluate(&policy, Some(&not_yet), Action::View, &ctx(60)),
            Verdict::Deny(DenyReason::LeaseIssuedInTheFuture {
                issued_at: Timestamp(issued),
                now: Timestamp(60),
            })
        );
    }

    #[test]
    fn a_lease_issued_within_the_clock_skew_allowance_is_still_accepted() {
        // Отказ по дате выдачи не должен бить по законному пользователю, у
        // которого часы отстали на минуту: допуск ровно MAX_CLOCK_SKEW_SECONDS,
        // и секундой дальше начинается отказ.
        let policy = viewable();
        let now = 60;
        let within = LeaseFacts {
            issued_at: Timestamp(now + MAX_CLOCK_SKEW_SECONDS),
            expires_at: Timestamp(now + MAX_CLOCK_SKEW_SECONDS + 8 * 3600),
            ..lease()
        };
        assert!(evaluate(&policy, Some(&within), Action::View, &ctx(now)).is_allowed());

        let beyond = LeaseFacts {
            issued_at: Timestamp(now + MAX_CLOCK_SKEW_SECONDS + 1),
            expires_at: Timestamp(now + MAX_CLOCK_SKEW_SECONDS + 1 + 8 * 3600),
            ..lease()
        };
        assert!(!evaluate(&policy, Some(&beyond), Action::View, &ctx(now)).is_allowed());
    }

    fn from_first_open() -> Policy {
        Policy {
            validity: Validity::FromFirstOpen { seconds: 3600 },
            network: Network::Lease { seconds: 8 * 3600, max_offline_seconds: 8 * 3600 },
            ..Policy::deny_all()
        }
        .allow(Action::View)
    }

    #[test]
    fn without_a_record_of_the_first_open_the_file_opens_only_online() {
        // Запись о первом открытии обязан сделать сервер: локально её взять
        // неоткуда, а «считать первым открытием сейчас» — это и есть бесконечное
        // продление. Поэтому без записи открытие возможно только с сетью.
        let policy = from_first_open();

        let mut forgetful = ctx(60);
        forgetful.first_open_at = None;
        assert!(evaluate(&policy, Some(&lease()), Action::View, &forgetful).is_allowed());

        let mut forgetful_offline = forgetful.clone();
        forgetful_offline.online = false;
        assert_eq!(
            evaluate(&policy, Some(&lease()), Action::View, &forgetful_offline),
            Verdict::Deny(DenyReason::FirstOpenNotRecorded)
        );
    }

    #[test]
    fn wiping_the_first_open_record_buys_no_more_than_one_lease() {
        // Худший исход выбранного решения, названный явно: стерев состояние,
        // клиент получает не вечный доступ, а ровно один лизинг, длина которого
        // уже ограничена политикой автора. Через десять лет он давно истёк.
        let policy = from_first_open();
        let mut forgetful = ctx(10 * 365 * 24 * 3600);
        forgetful.first_open_at = None;
        assert_eq!(
            evaluate(&policy, Some(&lease()), Action::View, &forgetful),
            Verdict::Deny(DenyReason::Expired)
        );
    }

    #[test]
    fn the_deadline_from_the_first_open_still_applies_when_the_record_exists() {
        // Контроль: правка ветки None не должна была тронуть саму проверку срока.
        let policy = from_first_open();
        let mut remembered = ctx(3601);
        remembered.first_open_at = Some(Timestamp(0));
        assert_eq!(
            evaluate(&policy, Some(&lease()), Action::View, &remembered),
            Verdict::Deny(DenyReason::Expired)
        );

        remembered.now = Timestamp(3600);
        assert!(evaluate(&policy, Some(&lease()), Action::View, &remembered).is_allowed());
    }

    #[test]
    fn intersect_can_only_narrow() {
        // Ровно то свойство, ради которого функция существует: что бы ни прислал
        // сервер, разрешений не становится больше, чем подписал автор.
        let author = Policy::deny_all().allow(Action::View);
        let greedy_server = Policy::deny_all()
            .allow(Action::View)
            .allow(Action::Edit)
            .allow(Action::Export)
            .allow(Action::Screenshot);

        let result = intersect(&author, &greedy_server);
        for action in ALL_ACTIONS {
            assert!(
                !(result.rule(action) == Rule::Allow && author.rule(action) != Rule::Allow),
                "сервер сумел добавить {action:?}"
            );
        }
        assert_eq!(result.rule(Action::View), Rule::Allow);
        assert_eq!(result.rule(Action::Edit), Rule::Deny);
    }

    #[test]
    fn intersect_takes_the_stricter_binding_and_the_shorter_lease() {
        let author = Policy {
            min_binding: Binding::Software,
            network: Network::Lease { seconds: 86400, max_offline_seconds: 86400 },
            max_opens: None,
            ..Policy::deny_all()
        };
        let server = Policy {
            min_binding: Binding::HardwareAttested,
            network: Network::Lease { seconds: 3600, max_offline_seconds: 600 },
            max_opens: Some(3),
            ..Policy::deny_all()
        };
        let r = intersect(&author, &server);
        assert_eq!(r.min_binding, Binding::HardwareAttested);
        assert_eq!(r.network, Network::Lease { seconds: 3600, max_offline_seconds: 600 });
        assert_eq!(r.max_opens, Some(3));
    }

    #[test]
    fn strict_online_is_contagious_through_intersect() {
        let lenient = Policy {
            network: Network::Lease { seconds: 3600, max_offline_seconds: 3600 },
            ..Policy::deny_all()
        };
        let strict = Policy { network: Network::StrictOnline, ..Policy::deny_all() };
        assert_eq!(intersect(&lenient, &strict).network, Network::StrictOnline);
        assert_eq!(intersect(&strict, &lenient).network, Network::StrictOnline);
    }
}
