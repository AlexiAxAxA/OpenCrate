// SPDX-License-Identifier: MPL-2.0
// Индексирование, срезы и чтение файла разрешены ЗДЕСЬ и только здесь, тем же
// порядком, что в `agent_vectors.rs`: вектор лежит вне кода намеренно, чтобы
// вторая реализация могла свериться, не читая наш Rust. Запрет часов, файлов и
// сети остаётся в силе для самого крейта — он проверяется отдельным прогоном
// clippy по пяти чистым крейтам, а тестовых целей тот прогон не трогает.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

//! Frozen action-grant and action-lease bodies, transcripts and signatures.
//!
//! The lease vector also guards domain separation from file leases using the same
//! server key. These protocol documents are outside the `.cc` container version.

use oc_crypto::sign::{Ed25519Signer, Signer as _};
use oc_protocol::action::{
    ActionGrant, ActionKind, ActionLease, ActionRule, Args, Constraint, Method, args_within,
    decode_grant, decode_lease, encode_grant, encode_lease, grant_body, grant_transcript,
    lease_body, lease_transcript,
};

/// Author key: the one that signed the container header.
fn author() -> Ed25519Signer {
    Ed25519Signer::from_seed(&[0xa1; 32])
}

/// Server lease-signing key: `authority.lease_verify_key` from the header.
fn server() -> Ed25519Signer {
    Ed25519Signer::from_seed(&[0x5e; 32])
}

/// Door fingerprint. For X25519, the fingerprint IS the key-agreement public key (K27).
const DOOR_FPR: [u8; 32] = [0xd1; 32];

fn grant() -> ActionGrant {
    let mut g = ActionGrant {
        grant_id: [0x67; 16],
        rules: vec![
            ActionRule {
                kind: ActionKind::GitPush,
                constraint: Constraint::GitPush {
                    remote: "origin".to_string(),
                    branch: "agent/work".to_string(),
                },
                max_uses: 10,
                confirm: false,
                delegable: true,
            },
            ActionRule {
                kind: ActionKind::HttpRequest,
                constraint: Constraint::HttpRequest {
                    host: "api.example.com".to_string(),
                    methods: vec![Method::Get, Method::Post],
                    path_prefix: "/v1/issues".to_string(),
                    secret_ref: Some("FORGE_TOKEN".to_string()),
                },
                max_uses: 0,
                confirm: true,
                delegable: false,
            },
        ],
        issued_at: 1_700_000_000,
        expires_at: 1_700_086_400,
        author_key: author().public_key(),
        signature: [0; 64],
    };
    let body = grant_body(&g).unwrap();
    g.signature = author().sign(&grant_transcript(&body)).unwrap();
    g
}

fn lease() -> ActionLease {
    let mut l = ActionLease {
        grant_id: [0x67; 16],
        door_fpr: DOOR_FPR,
        kind: ActionKind::GitPush,
        args: Args::GitPush {
            remote: "origin".to_string(),
            branch: "agent/work".to_string(),
        },
        nonce: [0x5a; 16],
        issued_at: 1_700_010_000,
        expires_at: 1_700_010_030,
        seq: 7,
        signature: [0; 64],
    };
    let body = lease_body(&l).unwrap();
    l.signature = server().sign(&lease_transcript(&body)).unwrap();
    l
}

/// The action grant matches the frozen vector: key, body and signature.
#[test]
fn the_action_grant_matches_its_frozen_vector() {
    let v = load_kat("action_grant.kat");
    let g = grant();

    assert_eq!(hex(&author().public_key()), v["author_key"]);

    let body = grant_body(&g).unwrap();
    assert_eq!(hex(&body), v["grant_body"], "байты тела гранта действий разошлись с вектором");

    // Подпись, снятая сейчас, совпадает с замороженной: Ed25519 детерминирован,
    // поэтому это законное требование, а не удача.
    assert_eq!(hex(&g.signature), v["grant_signature"]);

    // И обратно: замороженная подпись принимается — значит транскрипт тот же.
    let frozen: [u8; 64] = hex_bytes(&v["grant_signature"]).try_into().unwrap();
    let mut document = frozen.to_vec();
    document.extend_from_slice(&body);
    let back = decode_grant(&document, &author().public_key())
        .expect("замороженный грант не принят: транскрипт разошёлся");
    assert_eq!(back, g);
}

/// The action lease matches the frozen vector.
#[test]
fn the_action_lease_matches_its_frozen_vector() {
    let v = load_kat("action_lease.kat");
    let l = lease();

    assert_eq!(hex(&server().public_key()), v["lease_verify_key"]);

    let body = lease_body(&l).unwrap();
    assert_eq!(hex(&body), v["lease_body"], "байты тела лизы разошлись с вектором");
    assert_eq!(hex(&l.signature), v["lease_signature"]);

    let frozen: [u8; 64] = hex_bytes(&v["lease_signature"]).try_into().unwrap();
    let mut document = frozen.to_vec();
    document.extend_from_slice(&body);
    let back = decode_lease(&document, &server().public_key())
        .expect("замороженная лиза не принята: транскрипт разошёлся");
    assert_eq!(back, l);
}

/// THE FROZEN BYTES PASS THE `args_within` GATE, DEFINING ITS MEANING.
///
/// Not a retelling of unit tests: rules and arguments come from the SAME
/// bytes stored in the vectors, testing exactly what a second
/// implementation will see on the wire. Without this test, vectors would freeze document
/// shape without saying anything about what those documents permit.
#[test]
fn the_frozen_lease_is_within_the_frozen_grant() {
    let grant_v = load_kat("action_grant.kat");
    let lease_v = load_kat("action_lease.kat");

    let mut grant_bytes = hex_bytes(&grant_v["grant_signature"]);
    grant_bytes.extend_from_slice(&hex_bytes(&grant_v["grant_body"]));
    let mut lease_bytes = hex_bytes(&lease_v["lease_signature"]);
    lease_bytes.extend_from_slice(&hex_bytes(&lease_v["lease_body"]));

    let g = decode_grant(&grant_bytes, &author().public_key()).expect("вектор гранта принят");
    let l = decode_lease(&lease_bytes, &server().public_key()).expect("вектор лизы принят");

    let rule = g
        .rules
        .iter()
        .find(|r| r.kind == l.kind)
        .expect("в замороженном гранте нет правила того вида, что в лизе");
    args_within(rule, &l.args).expect("аргументы замороженной лизы вне замороженного гранта");

    // Положительный контроль: ворота не пропускают что попало. Другая ветка при
    // том же правиле — отказ, и без этой половины зелень выше означала бы
    // «проверка всегда согласна».
    let other = Args::GitPush { remote: "origin".to_string(), branch: "main".to_string() };
    assert!(args_within(rule, &other).is_err(), "ворота пропустили чужую ветку");
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hex_bytes(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn load_kat(name: &str) -> std::collections::BTreeMap<String, String> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/kat")
        .join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{name}: {e}"));
    text.lines()
        .filter_map(|l| l.split_once('='))
        .filter(|(k, _)| !k.trim_start().starts_with('#'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

/// Generate vectors. A tool, not a test.
///
/// Exists because manual edits would fix only the failing lines and
/// silently leave the rest inconsistent.
#[test]
#[ignore = "инструмент перевыпуска векторов, а не проверка"]
fn print_action_vectors() {
    let g = grant();
    let l = lease();
    println!("author_key = {}", hex(&author().public_key()));
    println!("grant_body = {}", hex(&grant_body(&g).unwrap()));
    println!("grant_signature = {}", hex(&g.signature));
    println!("lease_verify_key = {}", hex(&server().public_key()));
    println!("lease_body = {}", hex(&lease_body(&l).unwrap()));
    println!("lease_signature = {}", hex(&l.signature));
    // Круговая сверка инструмента: документы, собранные печатью, разбираются.
    let _ = encode_grant(&g).unwrap();
    let _ = encode_lease(&l).unwrap();
}
