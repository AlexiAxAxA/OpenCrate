//! Operation identity bytes on the wire versus the frozen vector
//! `tests/kat/operation_id.kat` (`docs/protocol.md` §9.10).
//!
//! This tests the wire: an activation request with tag 9 and echo responses (issuance tag 3,
//! refusal tag 2). The K28 derivation itself is checked in `oc-crypto/tests/kat.rs`,
//! and the client-constructed identity in `cc-cli/tests/kat_wire.rs`.

// Запрет `disallowed_methods` адресован продукту чистого крейта; тест векторов
// читает файл по определению (довод `kat_policy.rs`). Снимается точечно.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::disallowed_methods
)]

use oc_protocol::activation::{
    ActivateReq, ClockReport, Deny, Grant, Request, Response, SlotBlob, decode_request, decode_response,
    encode_request, encode_response,
};
use std::collections::BTreeMap;
use std::path::PathBuf;

fn load(name: &str) -> BTreeMap<String, Vec<u8>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/kat").join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line.split_once('=').expect("строка не вида «имя = hex»");
        let value = value.trim();
        let bytes = (0..value.len() / 2)
            .map(|i| u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).expect("не hex"))
            .collect();
        out.insert(key.trim().to_string(), bytes);
    }
    out
}

fn id(v: &BTreeMap<String, Vec<u8>>) -> [u8; 32] {
    v["k28_operation_id"].as_slice().try_into().unwrap()
}

/// The vector request, using the field names from the file header.
fn request(operation_id: Option<[u8; 32]>) -> ActivateReq {
    ActivateReq {
        file_id: [0x11; 16],
        policy_hash: [0x22; 32],
        device_fpr: [0x33; 32],
        device_kem: 1,
        device_public: vec![0x33; 32],
        server_slot: SlotBlob { enc: vec![0x55; 32], nonce: [0x66; 24], ct: vec![0x77; 48] },
        lease_seconds: 28_800,
        device_clock: Some(ClockReport { reset_count: 7, clock_ms: 900_000, read_at: 1_924_992_000 }),
        operation_id,
    }
}

#[test]
fn the_activation_request_with_an_operation_id_matches_its_frozen_bytes() {
    let v = load("operation_id.kat");
    let with_id = Request::Activate(Box::new(request(Some(id(&v)))));
    assert_eq!(encode_request(&with_id).unwrap(), v["activate_request_with_id"], "запрос с тождеством закодирован не теми байтами");
    assert_eq!(decode_request(&v["activate_request_with_id"]).unwrap(), with_id, "замороженный запрос разобран не в то");
    // Тело без тега 9 — вход K28, и оно же байт в байт прежний запрос.
    let without = encode_request(&Request::Activate(Box::new(request(None)))).unwrap();
    assert_eq!(&without[1..], v["activate_body_without_id"].as_slice(), "тело без тождества разошлось с вектором");
}

#[test]
fn the_answers_with_an_echo_match_their_frozen_bytes() {
    let v = load("operation_id.kat");
    let granted = Response::Granted(Grant { share: vec![0xa1; 40], lease: vec![0xb2; 120], operation_id: Some(id(&v)) });
    assert_eq!(encode_response(&granted).unwrap(), v["granted_with_echo"]);
    assert_eq!(decode_response(&v["granted_with_echo"]).unwrap(), granted);
    let text = String::from_utf8(v["deny_text"].clone()).unwrap();
    let denied = Response::Denied(Deny { text, operation_id: Some(id(&v)) });
    assert_eq!(encode_response(&denied).unwrap(), v["denied_with_echo"]);
    assert_eq!(decode_response(&v["denied_with_echo"]).unwrap(), denied);
}
