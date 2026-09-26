// SPDX-License-Identifier: MPL-2.0
// Запрет `disallowed_methods` в `clippy.toml` адресован ПРОДУКТУ: ввод-вывод в
// чистых крейтах жить не должен. Тест векторов читает файл по определению — векторы
// затем и лежат отдельным файлом, чтобы вторая реализация могла свериться, не читая
// наш Rust. Снимается точечно и только здесь.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::disallowed_methods
)]
//! Frozen policy, core-hash and mutable-region vectors.
//!
//! `policy_value` covers discriminants, little-endian fields, trailing-byte rejection
//! and absent/empty distinctions. `policy_hash` hashes the record value without
//! its six-byte tag/length prefix. It enters slot AAD, so its boundaries must match
//! across implementations.

use std::collections::BTreeMap;
use std::path::PathBuf;

use oc_format::header::{
    Authority, Header, KeySlot, Suite,
    WRAPPED_CEK_LEN,
};
use oc_crypto::MacKey;
use oc_crypto::{AeadAlg, SigAlg, TreeHashAlg};
use oc_format::content::ContentDesc;
use oc_policy::{Action, Binding, Network, Policy, Timestamp, Validity};

/// Vector policy. Arbitrary values, but FIXED forever.
///
/// Chosen to exercise every nontrivial encoding branch at once:
/// a two-field `validity` variant, a two-field `network` variant, nonempty `max_opens`,
/// nondefault binding, a raised flag, and exactly one allowed action.
fn frozen_policy() -> Policy {
    Policy {
        validity: Validity::Window {
            not_before: Timestamp(1_700_000_000),
            not_after: Timestamp(1_800_000_000),
        },
        network: Network::Lease { seconds: 8 * 3600, max_offline_seconds: 3600 },
        min_binding: Binding::Hardware,
        max_opens: Some(5),
        watermark: true,
        ..Policy::deny_all()
    }
    .allow(Action::View)
}

fn kat_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/kat").join(name)
}

fn load(name: &str) -> BTreeMap<String, Vec<u8>> {
    let path = kat_path(name);
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}. Векторы обязаны лежать в репозитории", path.display()));
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line.split_once('=').expect("строка вида «имя = hex»");
        out.insert(key.trim().to_string(), unhex(value.trim()));
    }
    out
}

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "нечётная длина hex: {text}");
    let bytes = text.as_bytes();
    (0..text.len() / 2)
        .map(|i| {
            let hi = (bytes[i * 2] as char).to_digit(16).expect("не hex") as u8;
            let lo = (bytes[i * 2 + 1] as char).to_digit(16).expect("не hex") as u8;
            (hi << 4) | lo
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Header surrounding the frozen policy. Needed solely to obtain
/// the field's actual byte range: `policy_hash` uses that rather than
/// re-encoding.
fn header_with(policy: Policy) -> Header {
    Header {
        // Литералы, а не CONTAINER_VERSION / SUPPORTED_READER_VERSION, и это
        // несущее решение, а не мелочь стиля.
        //
        // `header.kat` — замороженный вектор ВЕРСИИ 1. Константы записи станут
        // двойкой на последнем этапе перехода, и вектор, собранный через них,
        // поехал бы вместе с ними — то есть замороженный артефакт изменился бы
        // молча, вслед за кодом. Ровно это И-14 и запрещает.
        //
        // Обратная сторона тоже нужна: когда появится вектор версии 2, он будет
        // собран такими же литералами 2/2 и заморожен отдельно. Два вектора,
        // каждый про свою версию, — а не один, следующий за константой.
        container_version: 1,
        min_reader_version: 1,
        file_id: [0x11; 16],
        suite: Suite {
            sig: SigAlg::Ed25519,
            aead: AeadAlg::XChaCha20Poly1305,
            tree_hash: TreeHashAlg::Blake3,
        },
        author_key: [0x01; 32],
        header_salt: [0x21; 32],
        chunk_size: 65536,
        original_root: [0x33; 32],
        policy,
        key_slots: Vec::<KeySlot>::new(),
        authority: Authority {
            urls: Vec::new(),
            sealing_kid: [0x88; 32],
            lease_verify_key: [0x99; 32],
        },
        private_meta: vec![0xaa; 64],
        prev_header_hash: None,
        org_id: b"acme".to_vec(),
        class: 0,
        footer_offset: None,
        wrapped_cek: [0xbb; WRAPPED_CEK_LEN],
        coauthors: None,
    }
}

fn check(vectors: &BTreeMap<String, Vec<u8>>, name: &str, actual: &[u8]) {
    let expected = vectors
        .get(name)
        .unwrap_or_else(|| panic!("в файле векторов нет строки «{name}». Ожидалось: {}", hex(actual)));
    assert_eq!(
        hex(actual),
        hex(expected),
        "\nВЕКТОР {name} НЕ СОШЁЛСЯ.\n\
         Это изменение байтов формата. Поправить вектор под новый код можно ТОЛЬКО\n\
         вместе с решением в docs/format.md — иначе вектор перестаёт быть\n\
         доказательством и становится отражением кода.\n"
    );
}

#[test]
fn the_policy_bytes_and_hash_match_their_frozen_vectors() {
    let v = load("policy.kat");
    let header = header_with(frozen_policy());
    let bytes = header.encode().unwrap();
    let parsed = Header::decode(&bytes).unwrap();

    // Байты политики — ровно то значение записи с тегом 9, которое видит хеш.
    let value = &bytes[parsed.spans.policy_value.clone()];
    check(&v, "policy_value", value);
    check(&v, "policy_hash", &Header::policy_hash(&bytes, &parsed.spans).unwrap());

    // И обратный ход: замороженные байты обязаны разбираться в ту же политику.
    // Без этого вектор фиксировал бы только запись, а вторая реализация читает.
    let decoded = Header::decode(&bytes).unwrap().header.policy;
    assert_eq!(decoded, frozen_policy(), "политика не пережила круговой прогон");
}

/// Mutable region MAC key and vector `file_id`. Fixed forever.
///
/// The key is supplied directly, not derived from the CEK: K6 is already frozen in `derivations.kat`,
/// and repeating that derivation here would test it twice, whereas what must be frozen
/// is the region's own layout.
const MAC_KEY: [u8; 32] = [0x6c; 32];

/// The vector's mutable region. Numbers are mutually consistent under §6.1:
/// `chunk_count = max(1, ⌈total_len / chunk_size⌉)` with `chunk_size = 64 KiB`.
fn frozen_content_desc() -> ContentDesc {
    ContentDesc {
        total_len: 5_000_000,
        chunk_count: 77,
        tree_root: [0xab; 32],
        version_counter: 0,
        footer_offset: None,
        editor: None,
    }
}

/// Compare `core_hash` with its frozen header bytes and the full mutable region.
///
/// Hash raw byte ranges, not a re-encoded structure. The region includes
/// `ContentDescLen(4) ‖ body ‖ MAC(32)`; the MAC contributes to layout arithmetic.
#[test]
fn the_header_core_hash_and_content_desc_match_their_frozen_vectors() {
    let v = load("header.kat");
    let header = header_with(frozen_policy());
    let bytes = header.encode().unwrap();
    let parsed = Header::decode(&bytes).unwrap();

    check(&v, "header_bytes", &bytes);
    check(&v, "core_hash", &Header::core_hash(&bytes, &parsed.spans).unwrap());

    let key = MacKey::from_bytes(MAC_KEY);
    let encoded = frozen_content_desc().encode(&key, &header.file_id, oc_format::header::CONTAINER_VERSION).unwrap();
    check(&v, "content_desc", &encoded);

    // Контроль: область не переносится в другой файл. Без него вектор доказывал бы
    // лишь то, что MAC что-то считает.
    assert!(
        ContentDesc::decode_verified(&encoded, &key, &[0x22; 16], oc_format::header::CONTAINER_VERSION).is_err(),
        "изменяемая область принята под чужим file_id: привязка не работает"
    );
    let (back, read) = ContentDesc::decode_verified(&encoded, &key, &header.file_id, oc_format::header::CONTAINER_VERSION).unwrap();
    assert_eq!(back, frozen_content_desc());
    assert_eq!(read, encoded.len(), "область обязана кончаться ровно на MAC");
}

/// Reissuance tool. `#[ignore]` because this is not a check.
#[test]
#[ignore = "инструмент перевыпуска векторов, а не проверка"]
fn print_policy_vectors() {
    let header = header_with(frozen_policy());
    let bytes = header.encode().unwrap();
    let parsed = Header::decode(&bytes).unwrap();
    println!("policy_value = {}", hex(&bytes[parsed.spans.policy_value.clone()]));
    println!("policy_hash = {}", hex(&Header::policy_hash(&bytes, &parsed.spans).unwrap()));

    println!("
===== header.kat =====");
    println!("header_bytes = {}", hex(&bytes));
    println!("core_hash = {}", hex(&Header::core_hash(&bytes, &parsed.spans).unwrap()));
    let key = MacKey::from_bytes(MAC_KEY);
    println!(
        "content_desc = {}",
        hex(&frozen_content_desc().encode(&key, &header.file_id, oc_format::header::CONTAINER_VERSION).unwrap())
    );
}
