//! Explore access decisions using synthetic facts, without a server or device.

use oc_policy::{
    Action, Binding, Context, DenyReason, DeviceClock, DeviceFacts, LeaseFacts,
    Network, Policy, TimeSource, Timestamp, Verdict, evaluate,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Учебные факты позволяют менять время без настоящих часов и сервера.
    // В приложении эти поля берутся только из проверенных подписанных данных.
    let mut policy = Policy::deny_all().allow(Action::View);
    policy.network = Network::Lease { seconds: 600, max_offline_seconds: 600 };
    let device = DeviceFacts {
        fingerprint: [1; 32],
        binding: Binding::Software,
        tpm_clock: DeviceClock::Absent,
    };
    let lease = LeaseFacts {
        device_fingerprint: device.fingerprint,
        policy_hash: [2; 32],
        seq: 1,
        epoch: 0,
        issued_at: Timestamp(1_000),
        expires_at: Timestamp(1_600),
        opens_remaining: None,
        revoked: false,
        server_policy: None,
        attested: None,
        tpm_clock: None,
    };
    let mut context = Context {
        now: Timestamp(1_100),
        time_source: TimeSource::Wall,
        monotonic_floor: Timestamp(1_000),
        first_open_at: None,
        opens_so_far: 0,
        opens_under_lease: 0,
        device,
        highest_seq_seen: 1,
        online: false,
        policy_hash: lease.policy_hash,
    };

    match evaluate(&policy, Some(&lease), Action::View, &context) {
        Verdict::Allow(obligations) => {
            println!("VIEW at t=1100: ALLOW (obligations: {obligations:?})");
        }
        Verdict::Deny(_) => return Err("expected a valid view request to be allowed".into()),
    }

    if !matches!(
        evaluate(&policy, Some(&lease), Action::Print, &context),
        Verdict::Deny(DenyReason::ActionNotPermitted(Action::Print))
    ) {
        return Err("expected printing to be denied".into());
    }
    println!("PRINT at t=1100: DENY (no print permission)");

    // Только время изменилось: тот же запрос должен перестать проходить.
    context.now = Timestamp(2_000);
    if !matches!(evaluate(&policy, Some(&lease), Action::View, &context), Verdict::Deny(_)) {
        return Err("expected an expired lease to be denied".into());
    }
    println!("VIEW at t=2000: DENY (lease window has ended)");
    Ok(())
}
