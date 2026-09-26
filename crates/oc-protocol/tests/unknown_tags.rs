// SPDX-License-Identifier: MPL-2.0
//! Tag-range rule for PROTOCOL DOCUMENTS (I-7, decision of 2026-09-21).
//!
//! # What is tested here
//!
//! One rule across all fourteen parsers: an unknown tag > `0x7FFF`
//! is skipped; an unknown tag ≤ `0x7FFF` is rejected with the same error variant
//! used for every unknown tag before the decision; strict tag ordering
//! (I-7) also applies to skipped tags.
//!
//! # Why a table rather than twelve files
//!
//! Because there is ONE rule. Copying its test into one file per document would
//! create twelve independently editable places, exactly how this repository develops
//! the "one path fixed, its neighbor forgotten" problem.
//! Here a new document adds one table row and immediately receives all four
//! cases.
//!
//! # Why the unknown tag appears ONLY AT THE END
//!
//! Not laziness: no other position is possible. Tags strictly increase (I-7), and all
//! KNOWN protocol document tags lie in the critical range (1..=20 for the
//! richest document). An optional-range tag is therefore larger by construction
//! than every known tag and can only follow them. These documents have no middle
//! position where it could be inserted, unlike the
//! container header, where optional tag `0x8001` is already occupied.
//!
//! # Why signing happens AFTER the tag is added
//!
//! Case (i) must test PARSING. Signing a body without the tag and supplying one with
//! the tag would fail signature verification, letting the test pass without saying anything about
//! parsing. Thus signed documents have their body extended first, then
//! signed. The reverse order is separate case (iv), asserting
//! exactly what justifies the optional range: an outsider cannot append
//! a tag because the signature covers the raw body bytes.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]

use oc_crypto::sign::{Ed25519Signer, Signer};
use oc_crypto::{Transcript, label};
use oc_format::FormatError;
use oc_format::tlv::CRIT_TAG_MAX;
use oc_protocol::{access, activation, attestation, attribute_rule, control, directory, lease, order, replica, revocation, standing};

/// Unknown tag in the OPTIONAL range.
const OPTIONAL: u16 = 0x8ABC;
/// Unknown tag in the CRITICAL range.
const CRITICAL: u16 = 0x7ABC;

/// Append an entry with this tag to the body.
fn with_tag(body: &[u8], tag: u16, value: &[u8]) -> Vec<u8> {
    let mut out = body.to_vec();
    out.extend_from_slice(&tag.to_le_bytes());
    out.extend_from_slice(&u32::try_from(value.len()).unwrap().to_le_bytes());
    out.extend_from_slice(value);
    out
}

/// Document entry point: accepts a BODY, wraps it as the product does
/// (signing it for signed documents), then calls the public parser.
type Door = Box<dyn Fn(&[u8]) -> Result<String, FormatError>>;

/// The same entry point, but signs the FIRST body and parses the SECOND.
type Forge = Box<dyn Fn(&[u8], &[u8]) -> Result<String, FormatError>>;

struct Doc {
    name: &'static str,
    /// Canonical body as written by the crate's encoder.
    body: Vec<u8>,
    open: Door,
    /// `None` for unsigned documents.
    forge: Option<Forge>,
    /// Parsing remains STRICT: the document has no optional range.
    /// Exactly one such document exists: the author's decision; rationale in `access.rs`.
    strict: bool,
}

fn signer(seed: u8) -> Ed25519Signer {
    Ed25519Signer::from_seed(&[seed; 32])
}

fn transcript(l: oc_crypto::Label, body: &[u8]) -> Transcript {
    let mut t = Transcript::new(l);
    t.field(body);
    t
}

/// Document with layout `signature(64) ‖ body`.
fn sig_first(body: &[u8], tr: fn(&[u8]) -> Transcript, s: &Ed25519Signer) -> Vec<u8> {
    let mut out = s.sign(&tr(body)).unwrap().to_vec();
    out.extend_from_slice(body);
    out
}

/// Document with layout `count(1) ‖ (key ‖ signature)* ‖ body` (`control`).
fn signers_first(body: &[u8], tr: fn(&[u8]) -> Transcript, s: &Ed25519Signer) -> Vec<u8> {
    let mut out = vec![1u8];
    out.extend_from_slice(&s.public_key());
    out.extend_from_slice(&s.sign(&tr(body)).unwrap());
    out.extend_from_slice(body);
    out
}

// ---------------------------------------------------------------------------
// Образцы документов.

fn lease_body() -> Vec<u8> {
    use oc_policy::{LeaseFacts, Timestamp};
    lease::encode(&lease::Lease {
        file_id: [0x5a; 16],
        facts: LeaseFacts {
            device_fingerprint: [0x11; 32],
            policy_hash: [0x22; 32],
            seq: 4,
            epoch: 0,
            issued_at: Timestamp(1_756_000_000),
            expires_at: Timestamp(1_756_003_600),
            opens_remaining: Some(5),
            revoked: false,
            tpm_clock: None,
            server_policy: None,
            attested: None,
        },
    })
    .unwrap()
}

fn order_body() -> Vec<u8> {
    order::encode(&order::Order {
        max_devices: Some(3),
        ..order::Order::new([0x5a; 16], order::Kind::Register, 1_756_000_000)
    })
    .unwrap()
}

fn standing_body() -> Vec<u8> {
    standing::encode(&standing::Standing {
        file_id: [0x5a; 16],
        revoked: false,
        max_devices: Some(3),
        max_grants: None,
        coauthors: Vec::new(),
        coauthor_threshold: 0,
        proposal_ttl: 0,
        approvers: Vec::new(),
        approver_threshold: 0,
        heir: standing::HeirStanding::Absent,
        last_alive: None,
        votes: Vec::new(),
        proposals: Vec::new(),
        frozen: false,
    })
    .unwrap()
}

fn ask_body() -> Vec<u8> {
    access::encode_ask(&access::AskAccess {
        file_id: [0x11; 16],
        device_fpr: [0x22; 32],
        device_public: vec![0x33; 32],
        device_kem: 1,
        note: "Petr from accounting".to_string(),
    })
    .unwrap()
}

fn pending_body() -> Vec<u8> {
    access::encode_pending(&access::Pending {
        seq: 7,
        file_id: [0x11; 16],
        device_fpr: [0x22; 32],
        device_public: vec![0x33; 32],
        device_kem: 1,
        note: "Petr from accounting".to_string(),
        at: 1_756_000_000,
    })
    .unwrap()
}

fn decision_body() -> Vec<u8> {
    let author = signer(0x71);
    let mut decision = access::Decision {
        seq: 7,
        file_id: [0x11; 16],
        device_fpr: [0x22; 32],
        approve: false,
        share_b: None,
        author_key: author.public_key(),
        signature: [0; 64],
    };
    let body = access::decision_body(&decision).unwrap();
    decision.signature = author.sign(&access::decision_transcript(&body)).unwrap();
    access::encode_decision(&decision).unwrap()
}

fn activate_req_body() -> Vec<u8> {
    activation::encode_req(&activation::ActivateReq {
        file_id: [0x11; 16],
        policy_hash: [0x22; 32],
        device_fpr: [0x33; 32],
        device_kem: 1,
        device_public: vec![0x44; 32],
        server_slot: activation::SlotBlob { enc: vec![0x55; 32], nonce: [0x66; 24], ct: vec![0x77; 48] },
        lease_seconds: 8 * 3600,
        device_clock: None,
        operation_id: None,
    })
    .unwrap()
}

fn hello_body() -> Vec<u8> {
    activation::encode_hello(&activation::Hello {
        device_fpr: [0x33; 32],
        device_public: [0x44; 32],
        device_tpm: None,
        device_hybrid: None,
    })
    .unwrap()
}

fn challenge_body() -> Vec<u8> {
    activation::encode_challenge(&activation::Challenge {
        software: activation::SlotBlob { enc: vec![0x55; 32], nonce: [0x66; 24], ct: vec![0x77; 48] },
        hardware: None,
        hybrid: None,
    })
    .unwrap()
}

fn evidence_body() -> Vec<u8> {
    attestation::encode_evidence(&attestation::Evidence {
        ek_public: vec![1; 316],
        ek_certificate: Some(vec![2; 900]),
        intermediates: vec![vec![3; 800]],
        identity_public: vec![5; 282],
        attest: vec![6; 173],
        signature: vec![7; 262],
        device_public: vec![8; 90],
    })
    .unwrap()
}

fn rule_body() -> Vec<u8> {
    attribute_rule::encode(&attribute_rule::Rule {
        clauses: vec![attribute_rule::Clause {
            attribute: "dept".to_string(),
            mode: attribute_rule::Mode::AnyOf,
            values: vec!["legal".to_string()],
        }],
        max_lease_seconds: Some(86_400),
        tightenings: Vec::new(),
    })
    .unwrap()
}

fn record_body() -> Vec<u8> {
    directory::Record::new(
        "acme",
        "petr",
        oc_crypto::KemAlg::X25519HkdfSha256,
        &[0x31; 32],
        1,
        directory::KeyState::Active,
        "отдел кадров",
        1_756_000_000,
    )
    .unwrap()
    .encode()
    .unwrap()
}

fn binding(s: &Ed25519Signer) -> control::Binding {
    control::Binding {
        tenant: "acme".into(),
        authority_id: [0x0a; 16],
        epoch: 0,
        revision: 0,
        lease_public: s.public_key(),
        sealing_public: [0x0b; 32],
        urls: vec!["127.0.0.1:4455".into()],
        pins: vec![],
        durability: control::Durability::Local,
        recovery: control::Recovery::Package,
        status: control::Status::Serving,
        roster: vec![],
        threshold: 0,
        operation_id: [0; 16],
        previous: [0; 32],
        issued_at: 1_756_000_000,
        expires_at: 1_756_086_400,
    }
}

fn request_body(s: &Ed25519Signer) -> Vec<u8> {
    let r = control::ControlRequest {
        tenant: "acme".into(),
        authority_id: [0x0a; 16],
        epoch: 0,
        operation_id: [0x77; 16],
        expected_revision: 3,
        issued_at: 1_756_000_000,
        expires_at: 1_756_000_600,
        payload: control::Payload::AddAuthor([3; 32]),
    };
    // Тело добывается из подписанного документа: своей публичной двери у него
    // нет, а вторую сборку тела заводить нельзя — разойдутся.
    let signed = r.sign(s).unwrap();
    signed[1 + 32 + 64..].to_vec()
}

fn receipt_body(s: &Ed25519Signer) -> Vec<u8> {
    let receipt = control::Receipt {
        request_hash: [1; 32],
        operation_id: [2; 16],
        outcome: control::Outcome::PendingDurability,
        revision: 4,
        commit: [3; 32],
        epoch: 0,
        durability: control::Durability::Local,
        reason: "реплика не ответила".into(),
        at: 1_756_000_000,
    };
    receipt.sign(s).unwrap()[64..].to_vec()
}

fn transfer_body(anchor: &Ed25519Signer, s: &Ed25519Signer) -> Vec<u8> {
    let transfer = control::Transfer {
        authority_id: [0x60; 16],
        from_epoch: 0,
        to_epoch: 1,
        from_lease: s.public_key(),
        transition_at: 1_756_000_500,
        old_leases: control::OldLeases::RejectAfterTransition,
        issued_at: 1_756_000_000,
        expires_at: 1_756_086_400,
        binding: binding(anchor).sign(anchor).unwrap(),
    };
    transfer.sign(s).unwrap()[1 + 32 + 64..].to_vec()
}

fn push_body(s: &Ed25519Signer) -> Vec<u8> {
    let state = b"state bytes";
    let p = replica::Push {
        authority_id: [0x0a; 16],
        epoch: 0,
        seq: 3,
        previous: [0x11; 32],
        state_hash: oc_crypto::sha256(state),
        snapshot: false,
        at: 1_756_000_000,
        state: state.to_vec(),
    };
    p.sign(s).unwrap()[64..].to_vec()
}

fn ack_body(s: &Ed25519Signer) -> Vec<u8> {
    let ack = replica::Ack {
        authority_id: [0x0a; 16],
        epoch: 0,
        seq: 3,
        state_hash: [0x44; 32],
        replica: s.public_key(),
        at: 1_756_000_000,
    };
    ack.sign(s).unwrap()[64..].to_vec()
}

/// Document with layout `signature(64) ‖ body`, signed by one key.
///
/// One builder for seven documents: they share the layout, and seven copies of
/// this construction would diverge on the very first edit, silently.
fn sig_doc(
    name: &'static str,
    body: Vec<u8>,
    seed: u8,
    tr: fn(&[u8]) -> Transcript,
    open: fn(&[u8], &[u8; 32]) -> Result<String, FormatError>,
) -> Doc {
    Doc {
        name,
        body,
        open: Box::new(move |b| {
            let s = signer(seed);
            open(&sig_first(b, tr, &s), &s.public_key())
        }),
        forge: Some(Box::new(move |signed_over: &[u8], delivered: &[u8]| {
            let s = signer(seed);
            let mut doc = s.sign(&tr(signed_over)).unwrap().to_vec();
            doc.extend_from_slice(delivered);
            open(&doc, &s.public_key())
        })),
        strict: false,
    }
}

/// Document with layout `count(1) ‖ (key ‖ signature)* ‖ body`: both
/// `control` documents, which may have multiple signers.
fn multisig_doc(
    name: &'static str,
    body: Vec<u8>,
    seed: u8,
    tr: fn(&[u8]) -> Transcript,
    open: fn(&[u8]) -> Result<String, FormatError>,
) -> Doc {
    Doc {
        name,
        body,
        open: Box::new(move |b| open(&signers_first(b, tr, &signer(seed)))),
        forge: Some(Box::new(move |signed_over: &[u8], delivered: &[u8]| {
            let s = signer(seed);
            let mut doc = vec![1u8];
            doc.extend_from_slice(&s.public_key());
            doc.extend_from_slice(&s.sign(&tr(signed_over)).unwrap());
            doc.extend_from_slice(delivered);
            open(&doc)
        })),
        strict: false,
    }
}

fn binding_transcript(b: &[u8]) -> Transcript {
    transcript(label::AUTHORITY_BINDING, b)
}
fn receipt_transcript(b: &[u8]) -> Transcript {
    transcript(label::OPERATION_RECEIPT, b)
}
fn push_transcript(b: &[u8]) -> Transcript {
    transcript(label::REPLICA_PUSH, b)
}
fn ack_transcript(b: &[u8]) -> Transcript {
    transcript(label::REPLICA_ACK, b)
}
fn request_transcript(b: &[u8]) -> Transcript {
    transcript(label::CONTROL_REQUEST, b)
}
fn transfer_transcript(b: &[u8]) -> Transcript {
    transcript(label::AUTHORITY_TRANSFER, b)
}

/// Signer seeds. Arbitrary numbers, but they must DIFFER: a document
/// opened with a foreign key would pass for the wrong reason.
const SERVER: u8 = 0x5a;
const AUTHOR: u8 = 0x41;
const ANCHOR: u8 = 0x71;
const CONTROLLER: u8 = 0x51;
const REPLICA: u8 = 0x31;

/// Document table.
fn table() -> Vec<Doc> {
    let anchor = signer(ANCHOR);
    let controller = signer(CONTROLLER);
    let replica_key = signer(REPLICA);

    let mut docs: Vec<Doc> = vec![
        sig_doc("лизинг", lease_body(), SERVER, lease::signing_transcript, |doc, key| {
            lease::verify_signed(doc, key).map(|v| format!("{v:?}"))
        }),
        sig_doc(
            "отзывная",
            revocation::encode(&revocation::Revocation { file_id: [0x5a; 16], epoch: 2, at: 1_756_000_000 }).unwrap(),
            SERVER,
            revocation::signing_transcript,
            |doc, key| revocation::verify_signed(doc, key).map(|v| format!("{v:?}")),
        ),
        sig_doc("распоряжение автора", order_body(), AUTHOR, order::signing_transcript, |doc, key| {
            order::verify_signed(doc, key).map(|v| format!("{v:?}"))
        }),
        sig_doc(
            "привязка сервера",
            binding(&anchor).sign(&anchor).unwrap()[64..].to_vec(),
            ANCHOR,
            binding_transcript,
            |doc, key| control::Binding::open(doc, key).map(|v| format!("{v:?}")),
        ),
        sig_doc("квитанция операции", receipt_body(&anchor), ANCHOR, receipt_transcript, |doc, key| {
            control::Receipt::open(doc, key).map(|v| format!("{v:?}"))
        }),
        sig_doc("толчок реплики", push_body(&replica_key), REPLICA, push_transcript, |doc, key| {
            replica::Push::open(doc, key).map(|v| format!("{v:?}"))
        }),
        sig_doc("подтверждение реплики", ack_body(&replica_key), REPLICA, ack_transcript, |doc, key| {
            replica::Ack::open(doc, key).map(|v| format!("{v:?}"))
        }),
        // Печатается РАЗОБРАННОЕ намерение и подписанты, но НЕ `body_hash`, и это
        // не подгонка под зелёный: отпечаток считается по СЫРЫМ байтам тела
        // (`control.rs`, `open_request`), и у тела с дописанным необязательным
        // тегом он ДРУГОЙ — обязан быть другим. Тем же отпечатком сервер
        // опознаёт повтор операции (`cc_authority::control`, `remembered`),
        // поэтому то же намерение, посланное заново с новым необязательным
        // полем под тем же тождеством, получит `IdConflict`, а не прежнюю
        // квитанцию. Сверять здесь отпечаток значило бы требовать от него
        // независимости от байтов — то есть ровно того, чего он не обещает.
        multisig_doc("намерение управляющих", request_body(&controller), CONTROLLER, request_transcript, |doc| {
            control::open_request(doc).map(|v| format!("{:?} {:?}", v.request, v.signers))
        }),
        multisig_doc(
            "сертификат передачи",
            transfer_body(&anchor, &controller),
            CONTROLLER,
            transfer_transcript,
            |doc| control::open_transfer(doc).map(|v| format!("{v:?}")),
        ),
    ];

    // --- незаверенные ---
    for (name, body, door) in [
        ("положение файла", standing_body(), Box::new(|b: &[u8]| standing::decode(b).map(|v| format!("{v:?}"))) as Door),
        ("просьба о доступе", ask_body(), Box::new(|b: &[u8]| access::decode_ask(b).map(|v| format!("{v:?}")))),
        ("запись очереди", pending_body(), Box::new(|b: &[u8]| access::decode_pending(b).map(|v| format!("{v:?}")))),
        ("запрос активации", activate_req_body(), Box::new(|b: &[u8]| activation::decode_req(b).map(|v| format!("{v:?}")))),
        (
            "выдача",
            activation::encode_grant(&activation::Grant { share: vec![1; 40], lease: vec![2; 120], operation_id: None }).unwrap(),
            Box::new(|b: &[u8]| activation::decode_grant(b).map(|v| format!("{v:?}"))),
        ),
        (
            "отказ",
            activation::encode_deny(&activation::Deny::text("нет".to_string())).unwrap(),
            Box::new(|b: &[u8]| activation::decode_deny(b).map(|v| format!("{v:?}"))),
        ),
        ("приветствие", hello_body(), Box::new(|b: &[u8]| activation::decode_hello(b).map(|v| format!("{v:?}")))),
        ("вызов", challenge_body(), Box::new(|b: &[u8]| activation::decode_challenge(b).map(|v| format!("{v:?}")))),
        (
            "доказательство владения",
            activation::encode_proof(&activation::Proof { echo: vec![0x9a; 32] }).unwrap(),
            Box::new(|b: &[u8]| activation::decode_proof(b).map(|v| format!("{v:?}"))),
        ),
        ("доказательство аттестации", evidence_body(), Box::new(|b: &[u8]| attestation::decode_evidence(b).map(|v| format!("{v:?}")))),
        ("правило по атрибутам", rule_body(), Box::new(|b: &[u8]| attribute_rule::decode(b).map(|v| format!("{v:?}")))),
        ("запись каталога", record_body(), Box::new(|b: &[u8]| directory::Record::decode(b).map(|v| format!("{v:?}")))),
    ] {
        docs.push(Doc { name, body, open: door, forge: None, strict: false });
    }

    // --- единственный строгий ---
    docs.push(Doc {
        name: "решение автора",
        body: decision_body(),
        open: Box::new(|b: &[u8]| access::decode_decision(b).map(|v| format!("{v:?}"))),
        forge: None,
        strict: true,
    });

    docs
}

/// Table health: every sample must parse AS IS.
///
/// Without this positive control, the entire test is blind: a document that cannot
/// parse at all would reject every case and appear green in three
/// of four.
#[test]
fn every_sample_in_the_table_parses_as_it_is() {
    for doc in table() {
        (doc.open)(&doc.body).unwrap_or_else(|e| panic!("{}: образец не разбирается: {e:?}", doc.name));
    }
}

/// (i) AN UNKNOWN OPTIONAL TAG IS SKIPPED; KNOWN FIELDS STAY UNCHANGED.
///
/// Signed documents are signed AFTER adding the tag; otherwise
/// signature verification would fail and the test would pass for the wrong reason.
#[test]
fn an_unknown_optional_tag_is_skipped_and_the_known_fields_are_untouched() {
    for doc in table() {
        let plain = (doc.open)(&doc.body).unwrap();
        for value in [b"".as_ref(), b"\xde\xad\xbe\xef".as_ref()] {
            let extended = with_tag(&doc.body, OPTIONAL, value);
            match ((doc.open)(&extended), doc.strict) {
                (Ok(parsed), false) => assert_eq!(
                    parsed, plain,
                    "{}: незнакомый необязательный тег изменил знакомые поля",
                    doc.name
                ),
                (Err(e), false) => {
                    panic!("{}: незнакомый необязательный тег {OPTIONAL:#x} отвергнут: {e:?}", doc.name)
                }
                (Err(FormatError::UnknownCriticalField { tag }), true) => {
                    assert_eq!(tag, OPTIONAL, "{}: отказ назвал не тот тег", doc.name);
                }
                (other, true) => {
                    panic!("{}: строгий разборщик принял необязательный тег: {other:?}", doc.name)
                }
            }
        }
    }
}

/// (ii) AN UNKNOWN CRITICAL TAG IS REJECTED WITH THE SAME VARIANT AS BEFORE THE DECISION.
///
/// The error variant is part of the check: changing it to `BadFieldLength` would make
/// a caller interpreting the rejection reason mislead the user.
#[test]
fn an_unknown_critical_tag_is_refused_by_the_very_same_error() {
    for doc in table() {
        for tag in [CRITICAL, CRIT_TAG_MAX] {
            let extended = with_tag(&doc.body, tag, b"\x01\x02");
            match (doc.open)(&extended) {
                Err(FormatError::UnknownCriticalField { tag: named }) => {
                    assert_eq!(named, tag, "{}: отказ назвал не тот тег", doc.name);
                }
                other => panic!("{}: незнакомый критичный тег {tag:#x} дал {other:?}", doc.name),
            }
        }
    }
}

/// (iii) TAG ORDERING ALSO APPLIES TO SKIPPED TAGS.
///
/// Duplicates and decreasing tags yield `FieldsOutOfOrder`, not a silent skip:
/// otherwise the optional range would leave a canonicality hole allowing
/// the same body to be encoded in two ways.
#[test]
fn optional_tags_must_ascend_and_must_not_repeat() {
    for doc in table() {
        // У СТРОГОГО разборщика до второго тега дело не доходит: он отвергает
        // первый же незнакомый. Отказ обязан быть, но назвать он вправе ровно
        // то, обо что споткнулся, — и требовать от него `FieldsOutOfOrder`
        // значило бы требовать разобрать то, что он разбирать отказался.
        let ordering = |got: Result<String, FormatError>, previous: u16, found: u16, what: &str| match (got, doc.strict)
        {
            (Err(FormatError::FieldsOutOfOrder { previous: p, found: f }), false) => {
                assert_eq!((p, f), (previous, found), "{}: {what}", doc.name);
            }
            // `previous` — тот тег, что лежит в теле ПЕРВЫМ; о него строгий и
            // спотыкается.
            (Err(FormatError::UnknownCriticalField { tag }), true) => {
                assert_eq!(tag, previous, "{}: {what}", doc.name);
            }
            (other, _) => panic!("{}: {what} дало {other:?}", doc.name),
        };

        let twice = with_tag(&with_tag(&doc.body, OPTIONAL, b"a"), OPTIONAL, b"b");
        ordering((doc.open)(&twice), OPTIONAL, OPTIONAL, "дубликат необязательного тега");

        let descending = with_tag(&with_tag(&doc.body, OPTIONAL + 1, b"a"), OPTIONAL, b"b");
        ordering((doc.open)(&descending), OPTIONAL + 1, OPTIONAL, "убывание необязательных тегов");
    }
}

/// (iv) AN OUTSIDER CANNOT APPEND A TAG: THE SIGNATURE COVERS RAW BYTES.
///
/// This is the justification for the crate's optional range,
/// tested as fact rather than stated in a doc comment. The tag is appended AFTER
/// signing, exactly as an intermediary would do.
#[test]
fn a_tag_appended_after_the_signature_breaks_the_signature() {
    let mut checked = 0usize;
    for doc in table() {
        let Some(forge) = doc.forge else { continue };
        checked = checked.saturating_add(1);
        // Положительный контроль: та же дверь на неиспорченном теле проходит.
        forge(&doc.body, &doc.body).unwrap_or_else(|e| panic!("{}: честный документ отвергнут: {e:?}", doc.name));
        let tampered = with_tag(&doc.body, OPTIONAL, b"\xde\xad");
        match forge(&doc.body, &tampered) {
            Err(FormatError::BadHeaderSignature) => {}
            other => panic!("{}: дописанный посторонним тег дал {other:?}", doc.name),
        }
    }
    assert!(checked >= 9, "подписанных документов в таблице стало меньше: {checked}");
}

/// SPECIAL CASE (a): UNAUTHENTICATED GREETING AND CONVERSATION TRANSCRIPT (K31).
///
/// # The question this test answers
///
/// The greeting and challenge travel over the wire BEFORE any authentication: neither
/// is signed, and the session MAC is not derived yet. An intermediary can therefore append
/// an optional tag to the greeting, and the range rule made such a
/// greeting PARSEABLE for the first time; formerly the server would reject it. The question:
/// is this harmless because the field is ignored?
///
/// # Answer: harmless, but NOT because it is ignored
///
/// It relies on the handshake transcript (K31,
/// `oc_crypto::kdf::handshake_transcript`, `docs/format.md`, "ECHO BOUND TO THE
/// CONVERSATION 2026-09-21"). It is computed over RAW FRAME BYTES: the device
/// uses bytes it SENT (`cc_cli::activate::greet`), the server bytes
/// it RECEIVED (`cc_authority::serve::step`, `Request::Hello` branch).
/// Editing a frame in transit makes these quantities differ, so the device's computed
/// proof-of-possession echo fails at the server.
///
/// Thus the parties hash DIFFERENT bytes precisely when an intermediary intervened,
/// and identical bytes when none did. That is what this test verifies rather than
/// merely retelling it.
#[test]
fn a_tag_smuggled_into_the_unauthenticated_hello_parts_the_handshake_transcript() {
    let hello = activation::Request::Hello(activation::Hello {
        device_fpr: [0x33; 32],
        device_public: [0x44; 32],
        device_tpm: None,
        device_hybrid: None,
    });
    let sent = activation::encode_request(&hello).unwrap();
    let challenge = activation::encode_response(&activation::Response::Challenge(activation::Challenge {
        software: activation::SlotBlob { enc: vec![0x55; 32], nonce: [0x66; 24], ct: vec![0x77; 48] },
        hardware: None,
        hybrid: None,
    }))
    .unwrap();

    // Посредник дописывает необязательный тег в ТЕЛО кадра (вид ‖ TLV).
    let received = with_tag(&sent, OPTIONAL, b"\xde\xad");

    // Разбор его пропускает: серверу дописанное поле НЕ ВИДНО.
    assert_eq!(
        format!("{:?}", activation::decode_request(&received).unwrap()),
        format!("{:?}", activation::decode_request(&sent).unwrap()),
        "дописанный тег изменил разобранное приветствие"
    );

    // Положительный контроль: без вмешательства обе стороны считают одно.
    let honest = oc_crypto::kdf::handshake_transcript(&sent, &challenge);
    assert_eq!(honest, oc_crypto::kdf::handshake_transcript(&sent, &challenge));

    // И ровно то, ради чего проба: транскрипты расходятся.
    let by_server = oc_crypto::kdf::handshake_transcript(&received, &challenge);
    assert_ne!(
        honest, by_server,
        "правка кадра по дороге не изменила транскрипт — эхо перестало быть функцией разговора"
    );

    // Следствие для эха: посчитанное устройством, у сервера не сходится.
    let secret = [0x9e; 64];
    let fpr = [0x33; 32];
    assert_ne!(
        oc_crypto::kdf::echo_transcript(&secret, &fpr, &honest),
        oc_crypto::kdf::echo_transcript(&secret, &fpr, &by_server),
        "эхо не заметило подмены транскрипта"
    );
}
