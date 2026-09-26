// SPDX-License-Identifier: MPL-2.0
// Проба скептика: перепроверка заявления «внутри слота ключа неизвестный тег из
// критичного диапазона молча отбрасывается». Прежняя проба брала тег 7, который
// у слота ЗАНЯТ (nonce), и получала отказ по длине значения — то есть проверяла
// не то, что заявляла. Здесь берётся тег, действительно неизвестный слоту.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::assertions_on_constants
)]

use oc_crypto::{AeadAlg, KemAlg, SigAlg, TreeHashAlg};
use oc_format::header::{
    Authority, CONTAINER_VERSION, Header, KeySlot, KnownSlot, SUPPORTED_READER_VERSION, SlotKind,
    Suite, WRAPPED_CEK_LEN, tag as htag,
};
use oc_format::FormatError;
use oc_format::tlv::{CRIT_TAG_MAX, TlvReader, TlvWriter};
use oc_policy::Policy;

fn sample_header() -> Header {
    sample_header_at(CONTAINER_VERSION)
}

/// Header with an EXPLICIT container version.
///
/// Needed because slot field shape depends on the pair (version, mechanism), and
/// tests of "this version's shape" must specify their version rather than inherit
/// the writer constant. That constant rises at the final migration stage and
/// would carry along the meaning of tests about version 1.
fn sample_header_at(container_version: u16) -> Header {
    Header {
        container_version,
        min_reader_version: SUPPORTED_READER_VERSION,
        file_id: [0x11; 16],
        suite: Suite {
            sig: SigAlg::Ed25519,
            aead: AeadAlg::XChaCha20Poly1305,
            tree_hash: TreeHashAlg::Blake3,
        },
        author_key: [0x01; 32],
        header_salt: [0x22; 32],
        chunk_size: 65536,
        original_root: [0x33; 32],
        policy: Policy::deny_all(),
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
            urls: Vec::new(),
            sealing_kid: [0x88; 32],
            lease_verify_key: [0x99; 32],
        },
        private_meta: vec![0xaa; 64],
        prev_header_hash: None,
        org_id: b"org".to_vec(),
        class: 0,
        footer_offset: None,
        wrapped_cek: [0xbb; WRAPPED_CEK_LEN],
        coauthors: None,
    }
}

fn replace_field(header_bytes: &[u8], tag: u16, new_value: &[u8]) -> Vec<u8> {
    let mut reader = TlvReader::new(header_bytes);
    let mut w = TlvWriter::new();
    while let Some(field) = reader.next_field().unwrap() {
        if field.tag == tag {
            w.put(field.tag, new_value).unwrap();
        } else {
            w.put(field.tag, field.value).unwrap();
        }
    }
    w.finish().to_vec()
}

#[test]
fn an_unknown_critical_tag_inside_a_key_slot_is_not_dropped_in_silence() {
    // Теги слота из docs/format.md §3.3. Берётся ВЕРХНЯЯ граница критичного
    // диапазона, а не первый свободный номер: реестр растёт снизу, и «первый
    // свободный» уже дважды успевал стать занятым (тег 7 → NONCE, тег 8 →
    // CLAIM_COMMIT). Проба при этом продолжала проходить, проверяя вместо
    // диапазона тега длину известного поля.
    const UNKNOWN_CRITICAL: u16 = CRIT_TAG_MAX;

    let mut slot = TlvWriter::new();
    slot.put(1, &(SlotKind::AuthorDevice as u16).to_le_bytes()).unwrap();
    slot.put(2, &[KemAlg::X25519HkdfSha256 as u8]).unwrap();
    slot.put(3, &[0x44; 32]).unwrap();
    slot.put(4, &[0x55; 48]).unwrap();
    slot.put(5, &[0x66; 32]).unwrap();
    slot.put(6, &[0x77; 32]).unwrap();
    slot.put(7, &[0x01; 24]).unwrap();
    slot.put(UNKNOWN_CRITICAL, b"a constraint from a future version").unwrap();

    let mut slots = TlvWriter::new();
    slots.put(0, &slot.finish()).unwrap();
    let header =
        replace_field(&sample_header().encode().unwrap(), htag::KEY_SLOTS, &slots.finish());

    match Header::decode(&header) {
        // Отказ — корректная реакция по §2.
        Err(_) => {}
        Ok(parsed) => {
            assert!(
                !matches!(parsed.header.key_slots.first(), Some(KeySlot::Known(_))),
                "слот с неизвестным критичным полем {UNKNOWN_CRITICAL} отдан как пригодный: \
                 ограничение из будущей версии потеряно молча"
            );
        }
    }
}

/// A slot using a mechanism whose shape version 1 does not define must be skipped,
/// not reject the entire container.
///
/// This is item R-3, concerning the §3.3 promise: "a slot with a known kind but unknown
/// `kem_id` is skipped rather than rejecting the file". It was impossible to satisfy
/// for a subtle reason. The fallback "unknown mechanism → `Unknown`"
/// came AFTER the field parsing loop, while `enc` length was checked INSIDE it,
/// unconditionally requiring 32 bytes; the fallback was never reached. Worse,
/// a second issue made it unreachable: `KemAlg::from_u8` recognizes 2 and 3,
/// so P-256 never counted as an "unknown mechanism" at all.
///
/// A P-256 public key takes 33 or 65 bytes, neither fitting in 32.
/// A P-256 slot was therefore not "unknown" but **impossible**: any such
/// container was entirely rejected even beside our own,
/// fully openable slot. F-6 planned precisely P-256 through a TPM.
///
/// ## This test must break, and its tempting fix is wrong
///
/// It depends on version 1's P-256 shape being UNDEFINED. F-6 defines it: the
/// `spikes/tpm-ecdh` spike showed PCP exports only uncompressed public keys, so
/// the wire will carry `0x04 ‖ X ‖ Y`, precisely the 65 bytes constructed below. From then on
/// the slot will stop being `Unknown`, become parseable, and fail this test.
///
/// The failure will be CORRECT; the obvious fix will not. Changing the expectation to
/// `Known` turns a R-3 test into a test that P-256 works;
/// the "unknown mechanism is skipped rather than breaking the file" branch loses all
/// coverage, and the next regression of the same kind passes silently.
///
/// ## How this was actually resolved
///
/// The prescription above, "move to `kem_id = 3`", was correct when shape
/// depended only on mechanism. Version 2 made it a function of the PAIR (version,
/// mechanism), opening a better option: test both claims rather than
/// replace one with the other.
///
/// This test stays about P-256 and is pinned to **version 1**, where its shape is
/// undefined and will remain so forever: what a version cannot do is frozen
/// as well as what it can. The R-3 claim remains verbatim, gaining the additional
/// role of preventing retroactive semantics in version 1.
///
/// The "mechanism whose shape NO version defines" branch is guarded by the neighboring
/// `kem_id = 3` test in a version 2 container, where P-256 already parses.
/// Together they cover what either alone would cover only intermittently.
#[test]
fn a_slot_whose_kem_shape_this_version_does_not_define_is_skipped_not_fatal() {
    // Два слота: чужой (P-256 с 65-байтным `enc`) и наш. Контейнер версии 1.
    let mut foreign = TlvWriter::new();
    foreign.put(1, &(SlotKind::RecipientIdentity as u16).to_le_bytes()).unwrap();
    foreign.put(2, &[KemAlg::P256HkdfSha256 as u8]).unwrap();
    // Несжатая точка P-256: 0x04 ‖ X(32) ‖ Y(32).
    let mut p256 = vec![0x04u8];
    p256.extend_from_slice(&[0xab; 64]);
    foreign.put(3, &p256).unwrap();
    foreign.put(4, &[0x55; 48]).unwrap();
    foreign.put(5, &[0x66; 32]).unwrap();
    foreign.put(6, &p256).unwrap();
    foreign.put(7, &[0x01; 24]).unwrap();

    let ours = sample_header_at(1).key_slots;
    let ours_encoded = {
        let mut only_ours = sample_header_at(1);
        only_ours.key_slots = ours.clone();
        // Кодируем наш слот тем же путём, которым его пишет продукт, и вынимаем
        // готовую запись: собирать её здесь руками значило бы проверять свою же
        // сборку вместо продуктовой.
        let bytes = only_ours.encode().unwrap();
        let mut reader = TlvReader::new(&bytes);
        let mut found = None;
        while let Some(field) = reader.next_field().unwrap() {
            if field.tag == htag::KEY_SLOTS {
                let mut inner = TlvReader::new(field.value);
                if let Some(slot) = inner.next_field().unwrap() {
                    found = Some(slot.value.to_vec());
                }
            }
        }
        found.expect("слот обязан быть в закодированном заголовке")
    };

    let mut slots = TlvWriter::new();
    slots.put(0, &foreign.finish()).unwrap();
    slots.put(1, &ours_encoded).unwrap();
    let header =
        replace_field(&sample_header_at(1).encode().unwrap(), htag::KEY_SLOTS, &slots.finish());

    let parsed = Header::decode(&header).expect(
        "контейнер отвергнут целиком из-за слота на чужом механизме: обещание §3.3 \
         «пропускается, а не отвергает файл» не выполняется",
    );

    assert!(
        matches!(parsed.header.key_slots.first(), Some(KeySlot::Unknown { .. })),
        "чужой слот разобран как пригодный: {:?}",
        parsed.header.key_slots.first()
    );
    assert!(
        matches!(parsed.header.key_slots.get(1), Some(KeySlot::Known(_))),
        "наш слот потерян: {:?}",
        parsed.header.key_slots.get(1)
    );

    // И-8 не ослаблен: для механизма, форму которого версия задаёт, длина
    // по-прежнему точная. 33 байта в `enc` при `kem_id = 1` — отказ, а не «сойдёт».
    let mut wrong = TlvWriter::new();
    wrong.put(1, &(SlotKind::AuthorDevice as u16).to_le_bytes()).unwrap();
    wrong.put(2, &[KemAlg::X25519HkdfSha256 as u8]).unwrap();
    wrong.put(3, &[0x44; 33]).unwrap();
    wrong.put(4, &[0x55; 48]).unwrap();
    wrong.put(5, &[0x66; 32]).unwrap();
    wrong.put(7, &[0x01; 24]).unwrap();
    let mut slots = TlvWriter::new();
    slots.put(0, &wrong.finish()).unwrap();
    let header =
        replace_field(&sample_header().encode().unwrap(), htag::KEY_SLOTS, &slots.finish());
    assert!(
        Header::decode(&header).is_err(),
        "33 байта в enc при X25519 приняты: точная длина известного механизма ослаблена"
    );
}

/// A claim-code slot cannot carry bytes for which nobody is accountable.
///
/// Item R-4. §2.0 declares the slot composition table enforceable **in full**, but
/// only two thirds were enforced: `ct` and `claim_commit` were checked, not kind-specific `key_fpr`
/// or zeroed `enc`/`nonce`. A claim-code slot could thus carry 32 bytes of
/// `key_fpr` and 56 arbitrary bytes in `enc` and `nonce`, pass verification, and live inside
/// an **author-signed** header without anyone reading them.
///
/// This is exactly the specification's argument against nonempty `ct` in this same slot:
/// "bytes nobody is accountable for... room for a covert channel within
/// an author-signed header". The ban had been stated for one of three fields.
#[test]
fn a_claim_slot_cannot_smuggle_bytes_in_fields_it_does_not_use() {
    let base = |enc: &[u8], nonce: &[u8], with_fpr: bool| {
        let mut slot = TlvWriter::new();
        slot.put(1, &(SlotKind::RecipientClaim as u16).to_le_bytes()).unwrap();
        slot.put(2, &[KemAlg::X25519HkdfSha256 as u8]).unwrap();
        slot.put(3, enc).unwrap();
        slot.put(4, &[]).unwrap();
        slot.put(5, &[0x66; 32]).unwrap();
        if with_fpr {
            slot.put(6, &[0x77; 32]).unwrap();
        }
        slot.put(7, nonce).unwrap();
        slot.put(8, &[0x99; 32]).unwrap();
        let mut slots = TlvWriter::new();
        slots.put(0, &slot.finish()).unwrap();
        replace_field(&sample_header().encode().unwrap(), htag::KEY_SLOTS, &slots.finish())
    };

    // Контроль: честный слот кода-претензии обязан разбираться. Без него зелёные
    // отказы ниже могли бы означать, что отвергается вообще всё.
    let honest = base(&[0u8; 32], &[0u8; 24], false);
    assert!(
        matches!(Header::decode(&honest).map(|p| p.header.key_slots), Ok(slots) if
            matches!(slots.first(), Some(KeySlot::Known(_)))),
        "честный слот кода-претензии отвергнут"
    );

    // Три канала контрабанды, каждый по отдельности.
    for (what, header) in [
        ("enc", base(&[0xab; 32], &[0u8; 24], false)),
        ("nonce", base(&[0u8; 32], &[0xcd; 24], false)),
        ("key_fpr", base(&[0u8; 32], &[0u8; 24], true)),
    ] {
        assert!(
            Header::decode(&header).is_err(),
            "слот кода-претензии с непустым {what} принят: подписанный автором \
             заголовок несёт байты, которых никто не читает"
        );
    }
}

/// A claim-code slot declares `kem_id = 1`, always; this concerns BYTES.
///
/// §2 item 5 says verbatim: "A claim-code slot (`kind = 3`) declares
/// `kem_id = 1` **always**, with zeroed `enc` and `nonce` of length 32 and 24.
/// Without this statement, zeroed `enc` length would depend on an unrelated default
/// mechanism choice, silently changing `claim.cc` bytes."
///
/// This statement had no check, and the omission was INVISIBLE: a slot with
/// `kem_id = 2` carries 65 zeros instead of 32; both pass the "all zero" check,
/// and each length is valid for its own mechanism. Thus the same
/// `claim.cc` could be issued in two byte forms, both accepted.
/// For a format declared frozen, this is precisely the danger §2 item 5 warns about.
///
/// Worse, both sides accepted it: the writer produced what the reader should
/// reject. An empirical probe found this, not code inspection.
#[test]
fn a_claim_slot_must_declare_the_first_mechanism() {
    let claim_with = |kem: KemAlg, enc_len: usize| {
        let mut slot = TlvWriter::new();
        slot.put(1, &(SlotKind::RecipientClaim as u16).to_le_bytes()).unwrap();
        slot.put(2, &[kem as u8]).unwrap();
        slot.put(3, &vec![0u8; enc_len]).unwrap();
        slot.put(4, &[]).unwrap();
        slot.put(5, &[0x66; 32]).unwrap();
        slot.put(7, &[0u8; 24]).unwrap();
        slot.put(8, &[0x99; 32]).unwrap();
        let mut slots = TlvWriter::new();
        slots.put(0, &slot.finish()).unwrap();
        replace_field(&sample_header().encode().unwrap(), htag::KEY_SLOTS, &slots.finish())
    };

    // Контроль: единица с 32 нулями обязана разбираться, иначе зелёный отказ
    // ниже не отличался бы от «отвергается вообще всё».
    assert!(
        Header::decode(&claim_with(KemAlg::X25519HkdfSha256, 32)).is_ok(),
        "честный слот кода-претензии отвергнут"
    );

    // P-256 с его законными 65 нулями — и всё же отказ: механизм у этого слота
    // не выбирается.
    assert!(
        Header::decode(&claim_with(KemAlg::P256HkdfSha256, 65)).is_err(),
        "слот кода-претензии с kem_id = 2 принят: байты claim.cc перестали быть \
            однозначными"
    );

    // И писатель обязан отказывать там же, где читатель. Наш писатель не должен
    // уметь произвести то, что наш же читатель обязан отвергнуть.
    let mut header = sample_header();
    header.key_slots = vec![KeySlot::Known(KnownSlot {
        kind: SlotKind::RecipientClaim,
        kem: KemAlg::P256HkdfSha256,
        enc: vec![0u8; 65],
        nonce: [0u8; 24],
        ct: Vec::new(),
        commitment: [0x66; 32],
        key_fpr: None,
        claim_commit: Some([0x99; 32]),
    })];
    assert!(
        header.encode().is_err(),
        "писатель произвёл слот кода-претензии на P-256 — читатель обязан его \
            отвергнуть, значит производить его нельзя"
    );
}

/// A mechanism whose shape NO version defines is skipped in a version 2
/// container, where P-256 already parses.
///
/// Companion to the test above; without it coverage would be partial. That test is pinned to
/// version 1 and prevents retroactive semantics there; this one guards
/// the skip branch itself, ensuring it still works in the current version rather than only the past.
///
/// `kem_id = 3` (RSA-OAEP) is chosen because its registry number is assigned but its shape
/// is undefined and unplanned: `KemAlg::from_u8` recognizes it, so the
/// "unknown number" branch cannot apply. The slot must be skipped specifically because
/// its shape is undefined: exactly the case that once broke an entire container.
///
/// The `enc` length is deliberately unlike 32 or 65: RSA-OAEP encapsulation
/// occupies hundreds of bytes; checking another mechanism's shape with our own measure
/// is precisely what must not happen.
#[test]
fn a_mechanism_no_version_defines_is_still_skipped_in_version_two() {
    let mut foreign = TlvWriter::new();
    foreign.put(1, &(SlotKind::RecipientIdentity as u16).to_le_bytes()).unwrap();
    foreign.put(2, &[KemAlg::RsaOaepSha256 as u8]).unwrap();
    foreign.put(3, &vec![0xcd; 256]).unwrap();
    foreign.put(4, &[0x55; 48]).unwrap();
    foreign.put(5, &[0x66; 32]).unwrap();
    foreign.put(6, &vec![0xcd; 256]).unwrap();
    foreign.put(7, &[0x01; 24]).unwrap();

    let mut slots = TlvWriter::new();
    slots.put(0, &foreign.finish()).unwrap();
    let header =
        replace_field(&sample_header_at(2).encode().unwrap(), htag::KEY_SLOTS, &slots.finish());

    let parsed = Header::decode(&header).expect(
        "контейнер версии 2 отвергнут целиком из-за слота на механизме без заданной формы: \
         обещание §3.3 не выполняется",
    );
    assert!(
        matches!(parsed.header.key_slots.first(), Some(KeySlot::Unknown { .. })),
        "слот RSA-OAEP разобран как пригодный: {:?}",
        parsed.header.key_slots.first()
    );
}

/// A compressed P-256 point is rejected by the FORMAT; that claim belongs here.
///
/// The check was claimed in the wrong place. An `oc-crypto` probe said "P-256 rejects
/// compressed form" while feeding `agree` thirty-three `0x04` bytes. Rejection came
/// from SEC1 parsing (`0x04` prefixes an UNcompressed point; neither form looks like that),
/// not from its form. The agreement layer does not have the claimed property:
/// `from_sec1_bytes` parses both forms, and both yield the same secret.
///
/// The ban lives in the exact-length table (§3.3: `enc` for `kem_id = 2` is exactly 65
/// bytes, uncompressed SEC1 point `0x04 ‖ X ‖ Y`), upheld by I-8. The specification's
/// reason concerns BYTES: two valid forms of one key would yield two different
/// slot records for one recipient, hence divergent `core_hash` and signatures
/// between two conforming implementations.
///
/// EXACTLY `BadFieldLength { tag: ENC }` is required: "any error" is precisely
/// the wording that let the previous probe pass for the wrong reason.
#[test]
fn a_compressed_p256_point_is_refused_by_the_exact_length_table() {
    // Слот P-256 версии 2, отличающийся от корректного ровно длиной `enc`.
    let slot = |enc_len: usize| {
        let mut w = TlvWriter::new();
        w.put(1, &(SlotKind::AuthorDevice as u16).to_le_bytes()).unwrap();
        w.put(2, &[KemAlg::P256HkdfSha256 as u8]).unwrap();
        // Первый байт — префикс несжатой точки: содержимое `enc` формат не
        // разбирает, и отказ обязан прийти от длины, а не от вида байтов.
        let mut enc = vec![0x04u8];
        enc.resize(enc_len, 0xcd);
        w.put(3, &enc).unwrap();
        w.put(4, &[0x55; 48]).unwrap();
        w.put(5, &[0x66; 32]).unwrap();
        w.put(7, &[0x01; 24]).unwrap();
        let mut slots = TlvWriter::new();
        slots.put(0, &w.finish()).unwrap();
        replace_field(&sample_header_at(2).encode().unwrap(), htag::KEY_SLOTS, &slots.finish())
    };

    // Несжатая форма — слот пригоден. Без этого случая «отказ на 33 байтах» не
    // отличить от «P-256 в версии 2 не разбирается вовсе».
    let parsed = Header::decode(&slot(65)).expect("слот P-256 с несжатой точкой отвергнут");
    assert!(
        matches!(parsed.header.key_slots.first(), Some(KeySlot::Known(_))),
        "слот P-256 с несжатой точкой не разобран как пригодный: {:?}",
        parsed.header.key_slots.first()
    );

    // Сжатая форма — отказ по длине `enc`, а не пропуск слота как незнакомого.
    match Header::decode(&slot(33)) {
        Err(FormatError::BadFieldLength { tag, len }) => {
            assert_eq!(tag, 3, "отказ пришёл не от длины `enc`");
            assert_eq!(len, 33, "отвергнута не та длина");
        }
        other => panic!("сжатая точка P-256 принята форматом: {other:?}"),
    }
}
