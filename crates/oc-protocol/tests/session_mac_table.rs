// SPDX-License-Identifier: MPL-2.0
//! Session MAC: authenticated-kind table and trailer separation, in the owning crate.
//!
//! Why a separate file when six tests in `cc-authority/tests/session_mac.rs`
//! already make the server reject tampered frames? Because BOTH quantities live
//! HERE, yet only the neighboring crate guarded them. Removing `KIND_ACTIVATE`
//! from [`is_session_sealed`] broke none of the 104 `oc-protocol` tests,
//! yet it removes activation's MAC entirely: the client uses the same table to decide
//! whether to append the trailer, and both peers stop requiring it together. The function's doc comment
//! explicitly calls it "one table for both ends of the wire"; such a
//! quantity must have a test where it is defined, not only where
//! it happened to be used.
//!
//! The test follows THE PATH: kind comes not from a constant but from the first byte of a frame
//! built by [`encode_request`], exactly as read by `cc_cli::activate`
//! (`seal_request`) and `cc_authority::serve` (`converse`). Comparing with the number 3
//! would survive renaming a variant; frame construction would not.

// Литы сняты по названным причинам: `unwrap`/`panic` — словарь проверки,
// индексирование — чтение первого байта кадра заведомо непустой длины.
// В продуктовом коде запреты остаются в силе.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use oc_protocol::activation::{
    ActivateReq, ClockReport, Hello, Proof, Request, SlotBlob, encode_request, is_session_sealed,
    split_request_mac,
};

fn activate_req() -> Box<ActivateReq> {
    Box::new(ActivateReq {
        file_id: [0x41; 16],
        policy_hash: [0x33; 32],
        device_fpr: [0x22; 32],
        device_kem: 1,
        device_public: vec![0x22; 32],
        server_slot: SlotBlob { enc: vec![0x01; 32], nonce: [0x02; 24], ct: vec![0x03; 48] },
        lease_seconds: 3600,
        device_clock: Some(ClockReport { reset_count: 1, clock_ms: 1000, read_at: 1_756_000_000 }),
        operation_id: None,
    })
}

fn evidence() -> oc_protocol::attestation::Evidence {
    oc_protocol::attestation::Evidence {
        ek_public: vec![0x11; 32],
        ek_certificate: None,
        intermediates: Vec::new(),
        identity_public: vec![0x12; 32],
        attest: vec![0x13; 32],
        signature: vec![0x14; 64],
        device_public: vec![0x15; 32],
    }
}

/// FRAME KIND DETERMINES WHETHER A SESSION MAC IS REQUIRED; EACH DECISION IS LISTED HERE BY NAME.
///
/// Authenticated kinds are exactly those whose bodies CHANGE THE OUTCOME of a conversation and
/// arrive AFTER the handshake: activation and renewal (their clock readings
/// permanently advance the anti-rollback floor, finding N-2), plus the three attestation steps,
/// whose verdict changes what activation issues in this same conversation (B6b).
///
/// The handshake, `Hello` and `Prove`, cannot and must not be authenticated this way:
/// no session key exists beforehand; it is derived from this conversation. Requiring a MAC
/// here would make the handshake impossible; not requiring one for activation would remove
/// the MAC entirely.
#[test]
fn the_kinds_sealed_by_the_session_mac_are_the_named_ones() {
    // (имя для сообщения, запрос, обязан ли нести хвост K25)
    let cases: [(&str, Request, bool); 9] = [
        ("Activate", Request::Activate(activate_req()), true),
        ("Renew", Request::Renew(activate_req()), true),
        ("AttestOpen", Request::AttestOpen, true),
        ("AttestEvidence", Request::AttestEvidence(Box::new(evidence())), true),
        ("AttestSecret", Request::AttestSecret([0x77; 32]), true),
        (
            "Hello",
            Request::Hello(Hello {
                device_fpr: [0x22; 32],
                device_public: [0x22; 32],
                device_tpm: None,
                device_hybrid: None,
            }),
            false,
        ),
        ("Prove", Request::Prove(Proof { echo: vec![0x44; 32] }), false),
        ("Requests", Request::Requests { file_id: [0x41; 16] }, false),
        ("Revocation", Request::Revocation { file_id: [0x41; 16] }, false),
    ];

    for (name, request, sealed) in cases {
        let framed = encode_request(&request).expect("запрос не кодируется");
        let kind = framed[0];
        assert_eq!(
            is_session_sealed(kind),
            sealed,
            "вид кадра `{name}` (байт {kind}): таблица MAC сессии говорит {}, а обязана {}. \
             Таблица одна на обе стороны провода — снятое здесь снимается и у клиента, \
             и у сервера разом, и MAC исчезает молча",
            is_session_sealed(kind),
            sealed
        );
    }
}

/// THE WHOLE TRAILER IS SEPARATED, AND THE MAC COVERS THE ENTIRE FRAME INCLUDING ITS KIND BYTE.
///
/// Two essential properties in one statement. First, the MAC includes the kind byte:
/// otherwise an intermediary could change `Activate` to `Renew` in an intercepted frame without
/// touching the trailer, letting renewal pass as activation. Second, the separated
/// body is EXACTLY what reaches parsing, byte for byte, without the trailer; leaving even
/// one MAC byte would make parsing see a field the sender never wrote.
#[test]
fn the_mac_tail_splits_off_whole_and_leaves_the_kind_byte_under_the_mac() {
    let framed = encode_request(&Request::Activate(activate_req())).unwrap();
    let mut sealed = framed.clone();
    let tail = [0x9e_u8; 32];
    sealed.extend_from_slice(&tail);

    let (body, mac) = split_request_mac(&sealed).expect("кадр с хвостом не разделился");
    assert_eq!(body, framed.as_slice(), "тело под MAC не совпало с кадром: хвост отделён не целиком");
    assert_eq!(body[0], framed[0], "байт вида выпал из тела под MAC");
    assert_eq!(mac, &tail, "хвост взят не с конца кадра");
}

/// A FRAME NO LONGER THAN THE TRAILER IS REJECTED, NOT TREATED AS AN EMPTY BODY.
///
/// Exactly 32 bytes means "empty body, the entire frame is the MAC". Accepting that
/// would leave the frame without even a kind byte to select a branch; rejection
/// here is cheaper than guessing what emptiness should mean.
#[test]
fn a_frame_no_longer_than_the_tail_is_refused() {
    for len in [0_usize, 1, 31, 32] {
        let short = vec![0x03_u8; len];
        assert!(
            split_request_mac(&short).is_err(),
            "кадр длиной {len} разделился, хотя тела в нём нет"
        );
    }
    assert!(split_request_mac(&[0x03_u8; 33]).is_ok(), "кадр из тела в один байт и хвоста отбит");
}
