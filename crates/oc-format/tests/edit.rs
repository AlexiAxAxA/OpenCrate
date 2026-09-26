// SPDX-License-Identifier: MPL-2.0
//! Editing at byte level: certificate, editor signature, session head, and
//! the `verify_edition` decision (`docs/format.md`, "EDITING IS EXECUTABLE").
//!
//! Signed with the software test signer (`oc_crypto::rsa_test_signer`):
//! salt is a parameter, making the vector reproducible. The product key lives in the TPM.

// Пробы вправе паниковать и считать без проверок; чтение вектора с диска —
// единственный ввод-вывод, и он в пробе, а не в крейте.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::disallowed_methods
)]

use oc_crypto::rsa_test_signer::{TEST_KEY_A, TEST_KEY_B};
use oc_crypto::sign::{Ed25519Signer, Signer as _};
use oc_crypto::{AeadAlg, KemAlg, MacKey, SigAlg, TreeHashAlg};
use oc_format::content::{ContentDesc, JournalHead};
use oc_format::edit::{
    EditError, EditorCert, edition_digest, editor_transcript, next_counter, session_start, session_step,
    unsigned_editor, verify_edition,
};
use oc_format::header::{
    Authority, CONTAINER_VERSION, Coauthors, Header, KeySlot, KnownSlot, SUPPORTED_READER_VERSION, SlotKind,
    Suite, WRAPPED_CEK_LEN,
};
use oc_policy::{Action, Policy};

const FILE_ID: [u8; 16] = [0x11; 16];
const CORE_HASH: [u8; 32] = [0xc0; 32];
const NOW: i64 = 1_800_000_000;
const DEVICE: [u8; 32] = [0xde; 32];

fn author() -> Ed25519Signer {
    Ed25519Signer::from_seed(&[1; 32])
}

fn header(policy: Policy) -> Header {
    Header {
        container_version: CONTAINER_VERSION,
        min_reader_version: SUPPORTED_READER_VERSION,
        file_id: FILE_ID,
        suite: Suite { sig: SigAlg::Ed25519, aead: AeadAlg::XChaCha20Poly1305, tree_hash: TreeHashAlg::Blake3 },
        author_key: author().public_key(),
        header_salt: [0x22; 32],
        chunk_size: 65536,
        original_root: [0x33; 32],
        policy,
        key_slots: vec![KeySlot::Known(KnownSlot {
            kind: SlotKind::AuthorDevice,
            kem: KemAlg::X25519HkdfSha256,
            enc: vec![0x44; 32],
            nonce: [0x01; 24],
            ct: vec![0x55; 48],
            commitment: [0x66; 32],
            key_fpr: Some(vec![0x77; 32]),
            claim_commit: None,
        })],
        authority: Authority {
            urls: vec!["https://cc.example/api".to_string()],
            sealing_kid: [0x88; 32],
            lease_verify_key: [0x99; 32],
        },
        private_meta: vec![0xaa; 64],
        prev_header_hash: None,
        org_id: b"org".to_vec(),
        wrapped_cek: [0xbb; WRAPPED_CEK_LEN],
        coauthors: None,
        class: 0,
        footer_offset: None,
    }
}

fn editable() -> Header {
    header(Policy::deny_all().allow(Action::View).allow(Action::Edit))
}

fn cert_by(signer: &Ed25519Signer, file_id: [u8; 16], key: [u8; 256], not_after: i64) -> Vec<u8> {
    EditorCert::issue(signer, file_id, DEVICE, key, not_after).unwrap()
}

/// Signed edit: description, authenticated body, digest.
fn signed_edit(
    cert: Vec<u8>,
    key: &oc_crypto::rsa_test_signer::TestRsaKey,
    counter: u64,
    root: [u8; 32],
    core_hash: &[u8; 32],
) -> (ContentDesc, Vec<u8>) {
    let head = session_step(&session_start(&FILE_ID, counter - 1, &[0x33; 32]), 1, &root, 70_000);
    let mut desc = ContentDesc {
        total_len: 70_000,
        chunk_count: 2,
        tree_root: root,
        version_counter: counter,
        footer_offset: None,
        editor: Some(unsigned_editor(head, Some(JournalHead { size: 5, root: [0x55; 32] }), cert)),
    };
    let body = desc.body_bytes(CONTAINER_VERSION).unwrap();
    let transcript = editor_transcript(core_hash, &body).unwrap();
    let signature = key.sign_pss_sha256(transcript.as_bytes(), &[0x5a; 32]).unwrap();
    desc.editor.as_mut().unwrap().signature = signature.to_vec();
    let body = desc.body_bytes(CONTAINER_VERSION).unwrap();
    (desc, body)
}

/// Through the MAC and back: the way the reader obtains the body.
fn round_trip(desc: &ContentDesc) -> (ContentDesc, Vec<u8>) {
    let key = MacKey::from_bytes([9; 32]);
    let bytes = desc.encode(&key, &FILE_ID, CONTAINER_VERSION).unwrap();
    let (parsed, body, _) =
        ContentDesc::decode_verified_with_body(&bytes, &key, &FILE_ID, CONTAINER_VERSION).unwrap();
    (parsed, body.to_vec())
}

#[test]
fn a_properly_signed_edition_is_accepted_through_the_mac() {
    let cert = cert_by(&author(), FILE_ID, TEST_KEY_A.modulus(), NOW + 60);
    let (desc, _) = signed_edit(cert, &TEST_KEY_A, 1, [0x44; 32], &CORE_HASH);
    let (parsed, body) = round_trip(&desc);
    let edition = verify_edition(&editable(), &CORE_HASH, &parsed, &body, Some(NOW)).unwrap().unwrap();
    assert_eq!(edition.counter, 1);
    assert_eq!(edition.cert.device, DEVICE);
    assert_eq!(edition.digest, edition_digest(&editor_transcript(&CORE_HASH, &body).unwrap()));
}

#[test]
fn the_digest_does_not_depend_on_the_random_salt() {
    let cert = cert_by(&author(), FILE_ID, TEST_KEY_A.modulus(), NOW + 60);
    let (desc, body) = signed_edit(cert, &TEST_KEY_A, 1, [0x44; 32], &CORE_HASH);
    let mut other = desc.clone();
    let transcript = editor_transcript(&CORE_HASH, &body).unwrap();
    other.editor.as_mut().unwrap().signature =
        TEST_KEY_A.sign_pss_sha256(transcript.as_bytes(), &[0x77; 32]).unwrap().to_vec();
    assert_ne!(other, desc, "соль не изменила подпись");
    let a = verify_edition(&editable(), &CORE_HASH, &desc, &body, Some(NOW)).unwrap().unwrap();
    let other_body = other.body_bytes(CONTAINER_VERSION).unwrap();
    let b = verify_edition(&editable(), &CORE_HASH, &other, &other_body, Some(NOW)).unwrap().unwrap();
    assert_eq!(a.digest, b.digest);
}

#[test]
fn an_unedited_file_needs_no_editor_and_refuses_one() {
    let plain = ContentDesc {
        total_len: 1,
        chunk_count: 1,
        tree_root: [0x33; 32],
        version_counter: 0,
        footer_offset: None,
        editor: None,
    };
    let body = plain.body_bytes(CONTAINER_VERSION).unwrap();
    assert_eq!(verify_edition(&editable(), &CORE_HASH, &plain, &body, Some(NOW)), Ok(None));

    let cert = cert_by(&author(), FILE_ID, TEST_KEY_A.modulus(), NOW + 60);
    let (mut desc, _) = signed_edit(cert, &TEST_KEY_A, 1, [0x44; 32], &CORE_HASH);
    desc.version_counter = 0;
    let body = desc.body_bytes(CONTAINER_VERSION).unwrap();
    assert_eq!(verify_edition(&editable(), &CORE_HASH, &desc, &body, Some(NOW)), Err(EditError::EditorOnUnedited));
}

#[test]
fn an_edition_without_a_signature_or_permission_is_refused() {
    let unsigned = ContentDesc {
        total_len: 1,
        chunk_count: 1,
        tree_root: [0x44; 32],
        version_counter: 3,
        footer_offset: None,
        editor: None,
    };
    let body = unsigned.body_bytes(CONTAINER_VERSION).unwrap();
    assert_eq!(
        verify_edition(&editable(), &CORE_HASH, &unsigned, &body, Some(NOW)),
        Err(EditError::UnsignedEdit { version: 3 })
    );

    let cert = cert_by(&author(), FILE_ID, TEST_KEY_A.modulus(), NOW + 60);
    let (desc, body) = signed_edit(cert, &TEST_KEY_A, 1, [0x44; 32], &CORE_HASH);
    let view_only = header(Policy::deny_all().allow(Action::View));
    assert_eq!(verify_edition(&view_only, &CORE_HASH, &desc, &body, Some(NOW)), Err(EditError::EditNotAllowed));

    let mut old = editable();
    old.container_version = 3;
    assert!(matches!(
        verify_edition(&old, &CORE_HASH, &desc, &body, Some(NOW)),
        Err(EditError::VersionTooOld { container_version: 3, .. })
    ));
}

#[test]
fn certificates_are_checked_by_issuer_signature_file_and_time() {
    // Чужой выдавший.
    let stranger = Ed25519Signer::from_seed(&[2; 32]);
    let (desc, body) = signed_edit(cert_by(&stranger, FILE_ID, TEST_KEY_A.modulus(), NOW + 60), &TEST_KEY_A, 1, [0x44; 32], &CORE_HASH);
    assert_eq!(verify_edition(&editable(), &CORE_HASH, &desc, &body, Some(NOW)), Err(EditError::ForeignIssuer));

    // Он же как соавтор — принят.
    let mut with_coauthor = editable();
    with_coauthor.coauthors = Some(Coauthors { threshold: 1, keys: vec![stranger.public_key()] });
    assert!(verify_edition(&with_coauthor, &CORE_HASH, &desc, &body, Some(NOW)).unwrap().is_some());

    // Другой файл.
    let (desc, body) = signed_edit(cert_by(&author(), [0x12; 16], TEST_KEY_A.modulus(), NOW + 60), &TEST_KEY_A, 1, [0x44; 32], &CORE_HASH);
    assert_eq!(verify_edition(&editable(), &CORE_HASH, &desc, &body, Some(NOW)), Err(EditError::CertificateForOtherFile));

    // Истёкший — «старый сертификат».
    let (desc, body) = signed_edit(cert_by(&author(), FILE_ID, TEST_KEY_A.modulus(), NOW - 1), &TEST_KEY_A, 1, [0x44; 32], &CORE_HASH);
    assert_eq!(
        verify_edition(&editable(), &CORE_HASH, &desc, &body, Some(NOW)),
        Err(EditError::CertificateExpired { not_after: NOW - 1 })
    );

    // Подделанный сертификат: подменён ключ правки после подписи.
    let mut forged = cert_by(&author(), FILE_ID, TEST_KEY_A.modulus(), NOW + 60);
    let (parsed, _) = EditorCert::decode(&forged).unwrap();
    let mut swapped = parsed.clone();
    swapped.editor_key = TEST_KEY_B.modulus();
    forged = swapped.encode().unwrap();
    let (desc, body) = signed_edit(forged, &TEST_KEY_B, 1, [0x44; 32], &CORE_HASH);
    assert_eq!(verify_edition(&editable(), &CORE_HASH, &desc, &body, Some(NOW)), Err(EditError::BadCertificate));
}

#[test]
fn the_editor_signature_binds_the_key_the_header_and_every_field() {
    let cert = cert_by(&author(), FILE_ID, TEST_KEY_A.modulus(), NOW + 60);
    // Подписал не тот ключ, что в сертификате.
    let (desc, body) = signed_edit(cert.clone(), &TEST_KEY_B, 1, [0x44; 32], &CORE_HASH);
    assert_eq!(verify_edition(&editable(), &CORE_HASH, &desc, &body, Some(NOW)), Err(EditError::BadEditorSignature));

    // Та же область под другим заголовком.
    let (desc, body) = signed_edit(cert, &TEST_KEY_A, 1, [0x44; 32], &CORE_HASH);
    assert_eq!(verify_edition(&editable(), &[0xc1; 32], &desc, &body, Some(NOW)), Err(EditError::BadEditorSignature));

    // Подменено любое поле под подписью.
    let mutants: [fn(&mut ContentDesc); 5] = [
        |d| d.tree_root[0] ^= 1,
        |d| d.total_len += 1,
        |d| d.version_counter += 1,
        |d| d.editor.as_mut().unwrap().session_head[0] ^= 1,
        |d| d.editor.as_mut().unwrap().journal_head = None,
    ];
    for (i, mutate) in mutants.iter().enumerate() {
        let mut bad = desc.clone();
        mutate(&mut bad);
        let bad_body = bad.body_bytes(CONTAINER_VERSION).unwrap();
        assert_eq!(
            verify_edition(&editable(), &CORE_HASH, &bad, &bad_body, Some(NOW)),
            Err(EditError::BadEditorSignature),
            "мутация {i} прошла"
        );
    }
}

#[test]
fn the_cut_removes_exactly_the_signature_sub_record() {
    let cert = cert_by(&author(), FILE_ID, TEST_KEY_A.modulus(), NOW + 60);
    let (desc, body) = signed_edit(cert, &TEST_KEY_A, 1, [0x44; 32], &CORE_HASH);
    let cut = oc_format::edit::body_without_signature(&body).unwrap();
    assert_eq!(body.len() - cut.len(), 6 + 256);
    let sig = &desc.editor.as_ref().unwrap().signature;
    assert!(!cut.windows(sig.len()).any(|w| w == sig.as_slice()), "подпись осталась под подписью");
}

#[test]
fn the_session_chain_binds_the_base_and_every_save() {
    let base = session_start(&FILE_ID, 4, &[1; 32]);
    assert_ne!(base, session_start(&FILE_ID, 5, &[1; 32]));
    assert_ne!(base, session_start(&FILE_ID, 4, &[2; 32]));
    assert_ne!(base, session_start(&[0x12; 16], 4, &[1; 32]));
    let one = session_step(&base, 1, &[3; 32], 10);
    assert_ne!(one, session_step(&base, 2, &[3; 32], 10));
    assert_ne!(one, session_step(&base, 1, &[3; 32], 11));
    assert_eq!(next_counter(4), Ok(5));
    assert_eq!(next_counter(u64::MAX), Err(EditError::CounterExhausted));
}

#[test]
fn certificate_bytes_round_trip_and_reject_damage() {
    let bytes = cert_by(&author(), FILE_ID, TEST_KEY_A.modulus(), NOW + 60);
    let (cert, _) = EditorCert::decode(&bytes).unwrap();
    assert_eq!(cert.encode().unwrap(), bytes);
    assert!(EditorCert::decode(&bytes[..bytes.len() - 1]).is_err());
    let mut unknown = bytes.clone();
    unknown.extend_from_slice(&8u16.to_le_bytes());
    unknown.extend_from_slice(&0u32.to_le_bytes());
    assert!(EditorCert::decode(&unknown).is_err(), "неизвестный критичный тег принят");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len()).step_by(2).map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap()).collect()
}

/// Values of `tests/kat/edit.kat` as produced by this code.
fn kat_values() -> Vec<(&'static str, Vec<u8>)> {
    let cert = cert_by(&author(), FILE_ID, TEST_KEY_A.modulus(), NOW + 60);
    let start = session_start(&FILE_ID, 0, &[0x33; 32]);
    let head = session_step(&start, 1, &[0x44; 32], 70_000);
    let (desc, body) = signed_edit(cert.clone(), &TEST_KEY_A, 1, [0x44; 32], &CORE_HASH);
    let transcript = editor_transcript(&CORE_HASH, &body).unwrap();
    vec![
        ("author_seed", vec![1; 32]),
        ("cert", cert),
        ("session_start", start.to_vec()),
        ("session_head", head.to_vec()),
        ("core_hash", CORE_HASH.to_vec()),
        ("body", body),
        ("transcript", transcript.as_bytes().to_vec()),
        ("digest", edition_digest(&transcript).to_vec()),
        ("modulus", TEST_KEY_A.modulus().to_vec()),
        ("salt", vec![0x5a; 32]),
        ("signature", desc.editor.unwrap().signature),
    ]
}

/// Print the vector for reissuance TOGETHER with a decision in `docs/format.md`.
#[test]
#[ignore = "печать вектора, не проба"]
fn print_edit_kat() {
    for (name, value) in kat_values() {
        println!("{name} = {}", hex(&value));
    }
}

/// FROZEN EDIT VECTOR.
///
/// A failure means certificate, transcript, or session chain bytes have changed,
/// despite their immutability promise (I-14): fix the code, not the vector.
#[test]
fn the_frozen_edit_vector_still_holds() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/kat/edit.kat");
    let text = std::fs::read_to_string(&path).unwrap();
    let frozen: std::collections::BTreeMap<String, Vec<u8>> = text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let (k, v) = l.split_once(" = ").unwrap();
            (k.to_owned(), unhex(v.trim()))
        })
        .collect();
    let values = kat_values();
    assert_eq!(frozen.len(), values.len(), "в векторе не тот набор величин");
    for (name, value) in values {
        assert_eq!(frozen[name], value, "величина {name} разошлась с вектором");
    }
    // Подпись вектора принимает продуктовый проверяющий.
    let modulus: [u8; 256] = frozen["modulus"].as_slice().try_into().unwrap();
    oc_crypto::rsa::verify_pss_sha256(&modulus, &frozen["transcript"], &frozen["signature"]).unwrap();
}
