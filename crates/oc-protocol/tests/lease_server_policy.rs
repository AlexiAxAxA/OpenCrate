//! Lease version 2: the server sends its OWN profile to the recipient under its signature.
//!
//! Checks three properties motivating the field, not merely "the field survived":
//! a document with a profile MUST NOT look like the old version (otherwise an old client
//! would silently skip the restriction), the signature covers the profile (otherwise
//! anyone controlling the wire could remove it), and version and field set agree in both directions.

// Индексирование, срезы и паника разрешены ЗДЕСЬ и только здесь: проба правит
// байты заведомо известной раскладки, и выход за край обязан уронить прогон, а
// не тихо пройти мимо. В продуктовом коде эти литы остаются в силе.
#![allow(
    clippy::unwrap_used,
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use oc_crypto::sign::Signer as _;
use oc_protocol::lease::{self, Lease, LEASE_VERSION, LEASE_VERSION_WITH_SERVER_POLICY, tag};
use oc_format::FormatError;
use oc_policy::{Action, Binding, LeaseFacts, Network, Policy, Timestamp, TpmClock};

/// Server profile: viewing allowed, export forbidden, binding at least hardware-backed.
fn profile() -> Policy {
    let mut policy = Policy::deny_all().allow(Action::View);
    policy.min_binding = Binding::Hardware;
    policy.max_opens = Some(3);
    policy.network = Network::Lease { seconds: 3_600, max_offline_seconds: 600 };
    policy
}

fn facts(server_policy: Option<Policy>) -> LeaseFacts {
    LeaseFacts {
        device_fingerprint: [0x22; 32],
        policy_hash: [0x33; 32],
        seq: 7,
        epoch: 2,
        issued_at: Timestamp(1_700_000_000),
        expires_at: Timestamp(1_700_086_400),
        opens_remaining: Some(5),
        revoked: false,
        // Часы намеренно ПРИСУТСТВУЮТ: их тег 11, у профиля 12, и порядок полей
        // строго возрастает (И-7). Проба без часов не отличила бы правильный
        // порядок от обратного — а обратный отказал бы на записи.
        tpm_clock: Some(TpmClock { reset_count: 3, clock_ms: 123_456 }),
        server_policy,
        attested: None,
    }
}

fn lease(server_policy: Option<Policy>) -> Lease {
    Lease { file_id: [0x11; 16], facts: facts(server_policy) }
}

fn server() -> oc_crypto::sign::Ed25519Signer {
    oc_crypto::sign::Ed25519Signer::from_seed(&[0x5a; 32])
}

/// The version value is in the first field: tag(2) ‖ length(4) ‖ value(2).
fn set_version(body: &mut [u8], version: u16) {
    assert_eq!(u16::from_le_bytes([body[0], body[1]]), tag::VERSION, "версия не первое поле");
    assert_eq!(u32::from_le_bytes([body[2], body[3], body[4], body[5]]), 2, "версия не u16");
    body[6..8].copy_from_slice(&version.to_le_bytes());
}

/// The whole profile arrives, and the document DECLARES itself version 2.
///
/// Both halves matter. A round trip without a version check would mean that the restriction reached
/// us, while saying nothing about what happens in a client built before
/// the field existed.
#[test]
fn a_profile_travels_whole_and_the_document_calls_itself_version_two() {
    let body = lease::encode(&lease(Some(profile()))).unwrap();

    assert_eq!(
        u16::from_le_bytes([body[6], body[7]]),
        LEASE_VERSION_WITH_SERVER_POLICY,
        "документ с профилем не назвался версией 2"
    );
    assert_eq!(lease::decode(&body).unwrap(), lease(Some(profile())));
}

/// Without a profile, the version stays old: byte for byte as before B4a.
///
/// This is required for the frozen vector `tests/kat/lease.kat` to remain
/// valid (I-14): a new field must not change documents where it is absent.
#[test]
fn without_a_profile_the_document_stays_version_one() {
    let body = lease::encode(&lease(None)).unwrap();

    assert_eq!(u16::from_le_bytes([body[6], body[7]]), LEASE_VERSION);
    assert_eq!(lease::decode(&body).unwrap().facts.server_policy, None);
}

/// Version 1 with a profile is rejected: a critical field absent from that version.
///
/// This is what bypassing the version to smuggle in a restriction looks like, and also what
/// a server forgetting to bump the version looks like. The document must not be parsed
/// in either case: accepting it would accept a rule on which no agreement
/// exists.
#[test]
fn version_one_carrying_a_profile_is_refused() {
    let mut body = lease::encode(&lease(Some(profile()))).unwrap();
    set_version(&mut body, LEASE_VERSION);

    match lease::decode(&body) {
        Err(FormatError::UnknownCriticalField { tag }) => {
            assert_eq!(tag, tag::SERVER_POLICY);
        }
        other => panic!("версия 1 с профилем разобрана: {other:?}"),
    }
}

/// Version 2 without a profile is rejected: a promised field disappeared in transit.
///
/// This is precisely how removing a restriction by cutting out its field looks. The signature
/// would not survive anyway, but the parser must reject it INDEPENDENTLY: it is also called where
/// the signature is checked afterward, and "a field silently disappeared" must not
/// result in "broader access".
#[test]
fn version_two_without_a_profile_is_refused() {
    let mut body = lease::encode(&lease(None)).unwrap();
    set_version(&mut body, LEASE_VERSION_WITH_SERVER_POLICY);

    match lease::decode(&body) {
        Err(FormatError::MissingField { tag }) => assert_eq!(tag, tag::SERVER_POLICY),
        other => panic!("версия 2 без профиля разобрана: {other:?}"),
    }
}

/// A future version is rejected by number before field parsing.
///
/// This is exactly what an old client does upon encountering our version 2: it does not
/// know field 12 and need not understand it; it sees an unknown version and
/// rejects it. There is no way to test that "from within", so the mechanism is tested:
/// an unknown number means rejection, not best-effort parsing. The future number is 4:
/// version 3 was taken by the attestation flag (B6b).
#[test]
fn an_unknown_version_is_refused_by_its_number() {
    let mut body = lease::encode(&lease(Some(profile()))).unwrap();
    set_version(&mut body, 4);

    match lease::decode(&body) {
        Err(FormatError::UnsupportedLeaseVersion { version }) => assert_eq!(version, 4),
        other => panic!("версия 4 разобрана: {other:?}"),
    }
}

/// Changing ANY profile byte breaks the server signature.
///
/// Every position in the profile is tested: the signature must cover it all.
/// The profile is the last field, the location most easily overlooked.
#[test]
fn flipping_any_byte_of_the_profile_breaks_the_signature() {
    let body = lease::encode(&lease(Some(profile()))).unwrap();
    let plain = lease::encode(&lease(None)).unwrap();
    // Всё, что длиннее документа без профиля, и есть профиль с его заголовком.
    let from = plain.len();
    assert!(from < body.len(), "профиль не добавил ни байта");

    let signer = server();
    let sig = signer.sign(&lease::signing_transcript(&body)).unwrap();
    for i in from..body.len() {
        let mut damaged = body.clone();
        damaged[i] ^= 0x01;
        assert!(
            lease::verify(&damaged, &sig, &signer.public_key()).is_err(),
            "подпись пережила правку байта {i} профиля: он не покрыт"
        );
    }
}

/// The profile cannot be cut off: signature verification rejects the shortened body.
///
/// Separate from byte mutation because it protects against something different. Mutation changes
/// a restriction; cutting removes it altogether, which benefits the adversary more:
/// it restores the author's permissions, the maximum attainable access.
#[test]
fn cutting_the_profile_off_is_not_accepted() {
    let body = lease::encode(&lease(Some(profile()))).unwrap();
    let signer = server();
    let sig = signer.sign(&lease::signing_transcript(&body)).unwrap();

    let mut cut = lease::encode(&lease(None)).unwrap();
    set_version(&mut cut, LEASE_VERSION_WITH_SERVER_POLICY);
    assert!(
        lease::verify(&cut, &sig, &signer.public_key()).is_err(),
        "подпись принята для тела со срезанным профилем"
    );
}

/// Lease version 2 matches its own frozen vector.
///
/// The vector is a SEPARATE file rather than a line in `lease.kat`: that file is frozen with
/// the version 1 document and must not change (I-14). New document, new
/// file: an added witness, not a reissue of the old one.
#[test]
fn the_version_two_lease_matches_its_frozen_vector() {
    let v = load_kat("lease-v2.kat");
    let body = lease::encode(&lease(Some(profile()))).unwrap();
    assert_eq!(hex(&body), v["lease_body"], "байты тела лизинга версии 2 разошлись с вектором");

    let signer = server();
    assert_eq!(hex(&signer.public_key()), v["lease_verify_key"]);

    let sig: [u8; 64] = hex_bytes(&v["lease_signature"]).try_into().unwrap();
    lease::verify(&body, &sig, &signer.public_key())
        .expect("замороженная подпись версии 2 не принята: транскрипт разошёлся");

    // И обратно: Ed25519 детерминирован, поэтому совпадение — требование.
    let fresh = signer.sign(&lease::signing_transcript(&body)).unwrap();
    assert_eq!(hex(&fresh), v["lease_signature"]);
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hex_bytes(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn load_kat(name: &str) -> std::collections::BTreeMap<String, String> {
    let path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/kat").join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{name}: {e}"));
    text.lines()
        .filter_map(|l| l.split_once('='))
        .filter(|(k, _)| !k.trim_start().starts_with('#'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

/// Generate the lease version 2 vector. A tool, not a test.
#[test]
#[ignore = "инструмент перевыпуска векторов, а не проверка"]
fn print_version_two_lease_vector() {
    let body = lease::encode(&lease(Some(profile()))).unwrap();
    let signer = server();
    let sig = signer.sign(&lease::signing_transcript(&body)).unwrap();
    let policy =
        oc_format::policy_codec::encode(oc_format::header::CONTAINER_VERSION, &profile()).unwrap();
    println!("lease_verify_key = {}", hex(&signer.public_key()));
    println!("lease_body = {}", hex(&body));
    println!("lease_signature = {}", hex(&sig));
    println!("# профиль сервера отдельно: {}", hex(&policy));
}
