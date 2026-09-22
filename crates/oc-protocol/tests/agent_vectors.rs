// Индексирование, срезы и чтение файла разрешены ЗДЕСЬ и только здесь, тем же
// порядком, что в `lease_signature.rs`: вектор лежит вне кода намеренно, чтобы
// вторая реализация могла свериться, не читая наш Rust. Запрет часов, файлов и
// сети остаётся в силе для самого крейта — он проверяется отдельным прогоном
// clippy по пяти чистым крейтам, а он тестовых целей не трогает.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

//! Замороженные векторы Agent Protocol: тела, транскрипты и подписи.
//!
//! Отдельным файлом, а не в модуле: здесь нужны настоящие подписывающие ключи,
//! то есть `oc-crypto` целиком, — и здесь же читается файл вектора.
//!
//! # Что заморожено и почему ИМЕННО подпись, а не только тело
//!
//! Тело само по себе ничего не значит: грант — это утверждение АВТОРА, а
//! делегирование — утверждение ДВЕРИ. Заморозив только байты тела, мы оставили
//! бы на свободе транскрипт, то есть то, ЧТО именно подписано; расхождение там
//! молчаливо — подпись просто не сойдётся, и выглядеть это будет как «сервер
//! сломался». Тот же довод, что у `lease.kat` и `control.kat`.
//!
//! Версии контейнера векторы не касаются: ни один их байт в `.cc` не лежит.

use oc_crypto::sign::{Ed25519Signer, Signer as _};
use oc_protocol::access::Blob;
use oc_protocol::agent::{
    AgentGrant, ChainFacts, Delegation, Entry, decode_grant, delegation_body,
    delegation_transcript, encode_delegation, encode_grant, grant_body, grant_transcript,
    verify_grant_chain,
};

/// Ключ автора: тот, которым подписан заголовок контейнера.
fn author() -> Ed25519Signer {
    Ed25519Signer::from_seed(&[0xa1; 32])
}

/// Ключ ПОДПИСИ двери — им дверь заверяет делегирования.
fn door() -> Ed25519Signer {
    Ed25519Signer::from_seed(&[0xd0; 32])
}

/// Согласовательный ключ двери. У X25519 отпечаток И ЕСТЬ ключ (K27).
const DOOR_PUBLIC: [u8; 32] = [0xd1; 32];

/// Согласовательный ключ потомка, он же его отпечаток.
const CHILD_PUBLIC: [u8; 32] = [0xc1; 32];

fn child() -> Ed25519Signer {
    Ed25519Signer::from_seed(&[0xc0; 32])
}

fn blob(seed: u8) -> Blob {
    Blob { enc: vec![seed; 32], nonce: [seed; 24], ct: vec![seed; 48] }
}

fn file_id(n: u16) -> [u8; 16] {
    let mut id = [0u8; 16];
    id[0] = (n >> 8) as u8;
    id[1] = n as u8;
    id
}

fn grant() -> AgentGrant {
    let mut g = AgentGrant {
        grant_id: [0x67; 16],
        door_fpr: DOOR_PUBLIC,
        door_kem: 1,
        door_public: DOOR_PUBLIC.to_vec(),
        door_verify: door().public_key(),
        entries: vec![
            Entry { file_id: file_id(1), share_b: blob(0x11) },
            Entry { file_id: file_id(2), share_b: blob(0x22) },
        ],
        issued_at: 1_700_000_000,
        expires_at: 1_700_086_400,
        tightening: None,
        max_depth: 2,
        author_key: author().public_key(),
        signature: [0; 64],
    };
    let body = grant_body(&g).unwrap();
    g.signature = author().sign(&grant_transcript(&body)).unwrap();
    g
}

fn delegation() -> Delegation {
    let mut d = Delegation {
        grant_id: [0x67; 16],
        parent_fpr: DOOR_PUBLIC,
        child_fpr: CHILD_PUBLIC,
        child_kem: 1,
        child_public: CHILD_PUBLIC.to_vec(),
        child_verify: child().public_key(),
        entries: vec![Entry { file_id: file_id(1), share_b: blob(0x44) }],
        expires_at: 1_700_050_000,
        tightening: None,
        depth: 1,
        actions: Vec::new(),
        signature: [0; 64],
    };
    let body = delegation_body(&d).unwrap();
    d.signature = door().sign(&delegation_transcript(&body)).unwrap();
    d
}

/// Грант сходится с замороженным вектором — ключ, тело и подпись.
#[test]
fn the_grant_matches_its_frozen_vector() {
    let v = load_kat("agent_grant.kat");
    let g = grant();

    assert_eq!(hex(&author().public_key()), v["author_key"]);
    assert_eq!(hex(&door().public_key()), v["door_verify"]);

    let body = grant_body(&g).unwrap();
    assert_eq!(hex(&body), v["grant_body"], "байты тела гранта разошлись с вектором");

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

/// Делегирование сходится с замороженным вектором.
#[test]
fn the_delegation_matches_its_frozen_vector() {
    let v = load_kat("delegation.kat");
    let d = delegation();

    assert_eq!(hex(&child().public_key()), v["child_verify"]);

    let body = delegation_body(&d).unwrap();
    assert_eq!(hex(&body), v["delegation_body"], "байты тела делегирования разошлись");
    assert_eq!(hex(&d.signature), v["delegation_signature"]);
}

/// Цепочка «грант + одно звено» проверяется по замороженным байтам.
///
/// Не пересказ модульных проб: здесь цепочка собирается из ТЕХ ЖЕ байтов,
/// которые лежат в векторе, то есть проверяется ровно то, что вторая реализация
/// увидит на проводе.
#[test]
fn the_frozen_chain_verifies_at_the_named_moment() {
    let grant_v = load_kat("agent_grant.kat");
    let link_v = load_kat("delegation.kat");

    let mut grant_bytes = hex_bytes(&grant_v["grant_signature"]);
    grant_bytes.extend_from_slice(&hex_bytes(&grant_v["grant_body"]));
    let mut link_bytes = hex_bytes(&link_v["delegation_signature"]);
    link_bytes.extend_from_slice(&hex_bytes(&link_v["delegation_body"]));

    let now: i64 = link_v["chain_now"].parse().expect("момент проверки — число");
    let facts: ChainFacts = verify_grant_chain(
        &author().public_key(),
        &grant_bytes,
        &[link_bytes.as_slice()],
        now,
    )
    .expect("замороженная цепочка не принята");

    assert_eq!(hex(&facts.holder_fpr), link_v["chain_holder_fpr"]);
    assert_eq!(hex(&facts.holder_verify), link_v["chain_holder_verify"]);
    assert_eq!(facts.files.len(), 1);
    assert_eq!(hex(&facts.files[0]), link_v["chain_file"]);
    assert_eq!(facts.expires_at, 1_700_050_000);
    // Звено объявило `depth = 1`, значит потомку разрешено ещё одно звено ниже.
    assert_eq!(facts.depth_left, 1);
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

/// Выпустить векторы. Инструмент, не проверка.
///
/// Существует потому, что руками поправят ровно те строки, которые упали, и
/// молча оставят рассогласованными остальные.
#[test]
#[ignore = "инструмент перевыпуска векторов, а не проверка"]
fn print_agent_vectors() {
    let g = grant();
    let d = delegation();
    println!("author_key = {}", hex(&author().public_key()));
    println!("door_verify = {}", hex(&door().public_key()));
    println!("grant_body = {}", hex(&grant_body(&g).unwrap()));
    println!("grant_signature = {}", hex(&g.signature));
    println!("child_verify = {}", hex(&child().public_key()));
    println!("delegation_body = {}", hex(&delegation_body(&d).unwrap()));
    println!("delegation_signature = {}", hex(&d.signature));
    println!("chain_holder_fpr = {}", hex(&d.child_fpr));
    println!("chain_holder_verify = {}", hex(&d.child_verify));
    println!("chain_file = {}", hex(&file_id(1)));
    // Круговая сверка инструмента: документы, собранные печатью, разбираются.
    let _ = encode_grant(&g).unwrap();
    let _ = encode_delegation(&d).unwrap();
}
