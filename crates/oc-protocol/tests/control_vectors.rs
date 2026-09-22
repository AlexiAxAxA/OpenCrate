//! Frozen control and replica document vectors (E2, B2/B4/B7).
//!
//! These documents arrive ENTIRELY FROM THE WIRE and must not change silently:
//! a wire-byte change requires a decision recorded in the specification, the same
//! rule as for the container. The vector is what makes a silent
//! change impossible.
//!
//! The signature is frozen together with the body, for the same reason as leases:
//! a body without a signature is a sheet of paper, while transcript divergence is silent
//! (the signature simply fails to verify, making it look as though "the server broke").
//!
//! The generator is `print_vectors`, marked `#[ignore]`: it prints what later
//! resides in `tests/kat/control.kat`. Rerun ONLY together with
//! a recorded decision to change the bytes.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

use std::collections::BTreeMap;

use oc_crypto::sign::Ed25519Signer;
use oc_crypto::sign::Signer as _;
use oc_protocol::control::Binding;
use oc_protocol::control::Durability;
use oc_protocol::control::OldLeases;
use oc_protocol::control::Recovery;
use oc_protocol::control::Status;
use oc_protocol::control::Transfer;
use oc_protocol::replica::Ack;
use oc_protocol::replica::Push;

/// Vector keys. Seeds, not randomness: the vector must be reproducible.
const SERVER_SEED: [u8; 32] = [0x51; 32];
const CONTROLLER_SEED: [u8; 32] = [0x52; 32];
const REPLICA_SEED: [u8; 32] = [0x53; 32];

const AUTHORITY_ID: [u8; 16] = [0x60; 16];
const AT: i64 = 1_800_000_000;

fn server() -> Ed25519Signer {
    Ed25519Signer::from_seed(&SERVER_SEED)
}

fn controller() -> Ed25519Signer {
    Ed25519Signer::from_seed(&CONTROLLER_SEED)
}

fn replica_signer() -> Ed25519Signer {
    Ed25519Signer::from_seed(&REPLICA_SEED)
}

fn binding(epoch: u64) -> Binding {
    Binding {
        tenant: "acme".to_string(),
        authority_id: AUTHORITY_ID,
        epoch,
        revision: 3,
        lease_public: server().public_key(),
        sealing_public: [0x61; 32],
        urls: vec!["127.0.0.1:9000".to_string()],
        pins: vec![[0x62; 32]],
        durability: Durability::Witnessed,
        recovery: Recovery::Package,
        status: Status::Serving,
        roster: vec![controller().public_key()],
        threshold: 1,
        operation_id: [0x63; 16],
        previous: [0x64; 32],
        issued_at: AT,
        expires_at: AT + 86_400,
    }
}

fn transfer() -> Transfer {
    Transfer {
        authority_id: AUTHORITY_ID,
        from_epoch: 0,
        to_epoch: 1,
        from_lease: server().public_key(),
        transition_at: AT + 500,
        old_leases: OldLeases::RejectAfterTransition,
        issued_at: AT,
        expires_at: AT + 86_400,
        binding: binding(1).sign(&server()).unwrap(),
    }
}

fn push() -> Push {
    Push {
        authority_id: AUTHORITY_ID,
        epoch: 0,
        seq: 7,
        previous: [0x68; 32],
        state_hash: oc_crypto::sha256(b"state"),
        snapshot: true,
        at: AT + 20,
        state: b"state".to_vec(),
    }
}

fn ack() -> Ack {
    Ack {
        authority_id: AUTHORITY_ID,
        epoch: 0,
        seq: 7,
        state_hash: oc_crypto::sha256(b"state"),
        replica: replica_signer().public_key(),
        at: AT + 21,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn load_kat(name: &str) -> BTreeMap<String, String> {
    // Загрузчик повторён намеренно, как и у прочих векторов
    // (`tests/kat/README.md`): общий помощник связал бы вектор с кодом, который
    // он проверяет.
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/kat").join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

#[test]
fn the_control_and_replica_documents_match_the_frozen_vectors() {
    let v = load_kat("control.kat");

    assert_eq!(hex(&server().public_key()), v["server_public"], "ключ сервера вектора не тот");
    assert_eq!(hex(&controller().public_key()), v["controller_public"], "ключ управляющего не тот");
    assert_eq!(hex(&replica_signer().public_key()), v["replica_public"], "ключ реплики не тот");

    assert_eq!(
        hex(&binding(0).sign(&server()).unwrap()),
        v["binding_epoch0"],
        "байты подписанной привязки разошлись с вектором"
    );
    assert_eq!(
        hex(&transfer().sign(&controller()).unwrap()),
        v["transfer_0_to_1"],
        "байты сертификата передачи разошлись с вектором"
    );
    assert_eq!(hex(&push().sign(&server()).unwrap()), v["replica_push"], "толчок реплики разошёлся");
    assert_eq!(
        hex(&ack().sign(&replica_signer()).unwrap()),
        v["replica_ack"],
        "подтверждение реплики разошлось"
    );

    // Вектор обязан РАЗБИРАТЬСЯ теми же разборщиками, а не только совпадать
    // побайтно: совпадение мёртвых байтов ничего не говорит о читателе.
    let anchor = server().public_key();
    Binding::open(&hex_bytes(&v["binding_epoch0"]), &anchor).expect("привязка не разобралась");
    let (parsed, signers) =
        oc_protocol::control::open_transfer(&hex_bytes(&v["transfer_0_to_1"])).expect("передача");
    assert_eq!(parsed.to_epoch, 1);
    assert_eq!(signers, vec![controller().public_key()]);
    Push::open(&hex_bytes(&v["replica_push"]), &anchor).expect("толчок не разобрался");
    Ack::open(&hex_bytes(&v["replica_ack"]), &replica_signer().public_key()).expect("подтверждение");
}

fn hex_bytes(text: &str) -> Vec<u8> {
    let raw = text.as_bytes();
    let mut out = Vec::with_capacity(raw.len() / 2);
    let mut index = 0;
    while index + 1 < raw.len() {
        let hi = (raw[index] as char).to_digit(16).unwrap();
        let lo = (raw[index + 1] as char).to_digit(16).unwrap();
        out.push(u8::try_from(hi * 16 + lo).unwrap());
        index += 2;
    }
    out
}

#[test]
#[ignore = "генератор вектора: печатает значения для tests/kat/control.kat, запускается вручную"]
fn print_vectors() {
    println!("server_public = {}", hex(&server().public_key()));
    println!("controller_public = {}", hex(&controller().public_key()));
    println!("replica_public = {}", hex(&replica_signer().public_key()));
    println!("binding_epoch0 = {}", hex(&binding(0).sign(&server()).unwrap()));
    println!("transfer_0_to_1 = {}", hex(&transfer().sign(&controller()).unwrap()));
    println!("replica_push = {}", hex(&push().sign(&server()).unwrap()));
    println!("replica_ack = {}", hex(&ack().sign(&replica_signer()).unwrap()));
}
