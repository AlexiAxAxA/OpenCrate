// SPDX-License-Identifier: MPL-2.0
//! Edit writer: frame reuse, fresh nonces, tree, signature.
//!
//! Central property: I-1 during editing. Different plaintext at the same index receives
//! a different nonce even when the seed repeats (snapshot rollback); unchanged plaintext
//! at the same index retains the same triple of byte sequences when copied.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use oc_crypto::aead::{NONCE_LEN, open_chunk};
use oc_crypto::rsa_test_signer::TEST_KEY_A;
use oc_crypto::secret::{MacKey, PayloadKey, SecretBuf};
use oc_crypto::sign::Ed25519Signer;
use oc_crypto::AeadAlg;
use oc_engine::edit::{EditPlan, EditWriteError, Piece, finish, prepare};
use oc_format::content::ContentDesc;
use oc_format::edit::{EditorCert, editor_transcript};
use oc_format::header::CONTAINER_VERSION;

const FILE_ID: [u8; 16] = [0x21; 16];
const CHUNK: u32 = 4096;
const CORE: [u8; 32] = [0x9c; 32];

fn key() -> PayloadKey {
    PayloadKey::from_bytes([3; 32])
}

fn cert() -> Vec<u8> {
    EditorCert::issue(&Ed25519Signer::from_seed(&[1; 32]), FILE_ID, [0xde; 32], TEST_KEY_A.modulus(), i64::MAX)
        .unwrap()
}

fn plan<'a>(pieces: Vec<Piece<'a>>, base_counter: u64) -> EditPlan<'a> {
    EditPlan {
        file_id: FILE_ID,
        aead: AeadAlg::XChaCha20Poly1305,
        chunk_size: CHUNK,
        container_version: CONTAINER_VERSION,
        core_hash: CORE,
        base_counter,
        base_root: [0x11; 32],
        certified_by: cert(),
        journal_head: None,
        pieces,
    }
}

fn frames(payload: &[u8], lens: &[usize]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut at = 0;
    for len in lens {
        let size = NONCE_LEN + len + 16;
        out.push(payload[at..at + size].to_vec());
        at += size;
    }
    assert_eq!(at, payload.len(), "кадры не покрыли полезную нагрузку");
    out
}

fn open(frame: &[u8], index: u32) -> Vec<u8> {
    let nonce: [u8; NONCE_LEN] = frame[..NONCE_LEN].try_into().unwrap();
    let mut out = SecretBuf::with_capacity(CHUNK as usize);
    open_chunk(&key(), AeadAlg::XChaCha20Poly1305, &FILE_ID, index, &nonce, &frame[NONCE_LEN..], &mut out).unwrap();
    out.as_slice().to_vec()
}

#[test]
fn unchanged_frames_are_carried_and_changed_ones_get_fresh_nonces() {
    let a = [b'a'; 4096];
    let b = [b'b'; 4096];
    let c = b"tail";
    let first = prepare(
        &key(),
        plan(
            vec![
                Piece::Seal { plaintext: &a, seed: [1; 24] },
                Piece::Seal { plaintext: &b, seed: [2; 24] },
                Piece::Seal { plaintext: c, seed: [3; 24] },
            ],
            0,
        ),
    )
    .unwrap();
    let old = frames(&first.payload, &[4096, 4096, 4]);

    // Правка второго куска тем же засевом — как при откате генератора.
    let b2 = [b'B'; 4096];
    let second = prepare(
        &key(),
        plan(
            vec![Piece::Keep(&old[0]), Piece::Seal { plaintext: &b2, seed: [2; 24] }, Piece::Keep(&old[2])],
            1,
        ),
    )
    .unwrap();
    let new = frames(&second.payload, &[4096, 4096, 4]);
    assert_eq!(new[0], old[0], "перенесённый кадр изменился");
    assert_eq!(new[2], old[2]);
    assert_ne!(new[1][..NONCE_LEN], old[1][..NONCE_LEN], "другой текст на том же индексе получил тот же nonce");
    assert_eq!(open(&new[1], 1), b2);
    assert_eq!(open(&new[0], 0), a);

    assert_eq!(second.desc.version_counter, 2);
    assert_eq!(second.desc.total_len, 8196);
    assert_eq!(second.desc.chunk_count, 3);
    assert_ne!(second.desc.tree_root, first.desc.tree_root);
}

#[test]
fn a_signed_edition_passes_the_reader_check() {
    let text = b"hello, edited world";
    let unsigned = prepare(&key(), plan(vec![Piece::Seal { plaintext: text, seed: [9; 24] }], 0)).unwrap();
    let signature = TEST_KEY_A.sign_pss_sha256(unsigned.transcript.as_bytes(), &[4; 32]).unwrap();
    let digest = unsigned.digest;
    let mac = MacKey::from_bytes([5; 32]);
    let (_, area, _) = finish(unsigned, &signature, &mac, &FILE_ID, CONTAINER_VERSION).unwrap();
    let (desc, body, read) = ContentDesc::decode_verified_with_body(&area, &mac, &FILE_ID, CONTAINER_VERSION).unwrap();
    assert_eq!(read, area.len());
    let transcript = editor_transcript(&CORE, body).unwrap();
    oc_crypto::rsa::verify_pss_sha256(&TEST_KEY_A.modulus(), transcript.as_bytes(), &desc.editor.unwrap().signature)
        .unwrap();
    assert_eq!(oc_format::edit::edition_digest(&transcript), digest);
}

#[test]
fn a_broken_layout_is_refused() {
    let short = [0u8; 10];
    let full = [0u8; 4096];
    let long = [0u8; 4097];
    let err = |pieces| prepare(&key(), plan(pieces, 0)).unwrap_err();
    assert_eq!(err(vec![]), EditWriteError::BadLayout { index: 0 });
    assert_eq!(
        err(vec![Piece::Seal { plaintext: &short, seed: [0; 24] }, Piece::Seal { plaintext: &full, seed: [0; 24] }]),
        EditWriteError::BadLayout { index: 0 }
    );
    assert_eq!(err(vec![Piece::Seal { plaintext: &long, seed: [0; 24] }]), EditWriteError::BadLayout { index: 0 });
    assert_eq!(err(vec![Piece::Keep(&[0u8; 30])]), EditWriteError::BadFrame { index: 0 });
    assert!(matches!(
        prepare(&key(), plan(vec![Piece::Seal { plaintext: &full, seed: [0; 24] }], u64::MAX)),
        Err(EditWriteError::Edit(oc_format::edit::EditError::CounterExhausted))
    ));
}

#[test]
fn the_same_edit_on_another_base_is_another_signature() {
    let text = b"x";
    let one = prepare(&key(), plan(vec![Piece::Seal { plaintext: text, seed: [7; 24] }], 3)).unwrap();
    let mut other_plan = plan(vec![Piece::Seal { plaintext: text, seed: [7; 24] }], 3);
    other_plan.base_root = [0x12; 32];
    let two = prepare(&key(), other_plan).unwrap();
    assert_eq!(one.desc.tree_root, two.desc.tree_root, "тот же текст и засев дали другой корень");
    assert_ne!(one.digest, two.digest, "основа не вошла под подпись");
}
