// Файл-проба состязательной проверки безопасности. Часть тестов здесь КРАСНАЯ
// НАМЕРЕННО: падение теста и есть доказательство находки. Линтерные запреты
// рабочего кода к пробам не применяются — проба вправе делать то, чего продукт
// делать не должен.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::disallowed_methods,
    clippy::disallowed_types,    clippy::assertions_on_constants
)]
//! Направление 3: разбор враждебного ввода.
//!
//! `parser_robustness.rs` покрывает `TlvReader`, `Prologue` и `Layout`, но не
//! доходит до `Header::decode`, `policy_codec::decode` и
//! `ContentDesc::decode_verified`. Этот файл закрывает пробел и заодно сверяет
//! разбор с текстом спецификации там, где расхождение уже случалось.
//!
//! Три пробы этого файла (обёртка CEK, транскрипт MAC изменяемой области, состав
//! `suite`) были написаны по РАННЕЙ редакции `docs/format.md` и утверждали
//! обратное тому, что спецификация говорит сейчас. Они пересмотрены явно: у
//! каждой в комментарии записано, чего требовала прежняя редакция и почему
//! исполнить это требование было нельзя. Молчаливой подгонки под код нет ни в
//! одной — каждое утверждение сверено с нынешним текстом §1.2, §2 и §3.3.
//!
//! Харнесс держит СВОЙ ключ подписи и СВОЙ ключ MAC — иначе глубокие ветви
//! (`verify_and_parse` после подписи, `ContentDesc::decode_body` после MAC)
//! недостижимы. Ровно это и требует `docs/format.md` §5.2.


use std::panic::{AssertUnwindSafe, catch_unwind};

use oc_crypto::mac::{self, MAC_LEN};
use oc_crypto::sign::{Ed25519Signer, Signer};
use oc_crypto::{AeadAlg, KemAlg, MacKey, SigAlg, Transcript, TreeHashAlg, label};
use oc_format::content::{ContentDesc, tag as ctag};
use oc_format::header::{
    Authority, CONTAINER_VERSION, Header, KeySlot, KnownSlot, SUPPORTED_READER_VERSION, SlotKind,
    Suite, WRAPPED_CEK_LEN, tag as htag,
};
use oc_format::tlv::TlvWriter;
use oc_format::verify::{EmptyTrustStore, header_signing_transcript, verify_and_parse};
use oc_format::{FormatError, MAGIC, MAX_KEY_SLOTS, policy_codec};
use oc_policy::{Action, Binding, Network, Policy, Timestamp, Validity};

// ---------------------------------------------------------------------------
// Инструментарий
// ---------------------------------------------------------------------------

/// SplitMix64: детерминированный, падение воспроизводится по номеру итерации.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: usize) -> usize {
        if bound == 0 { 0 } else { (self.next() % bound as u64) as usize }
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| (self.next() & 0xff) as u8).collect()
    }

    fn pick<T: Copy>(&mut self, from: &[T]) -> T {
        from[self.below(from.len())]
    }
}

const FILE_ID: [u8; 16] = [0x11; 16];

fn mac_key() -> MacKey {
    MacKey::from_bytes([0x5a; 32])
}

fn sample_policy() -> Policy {
    Policy {
        validity: Validity::Window {
            not_before: Timestamp(1_700_000_000),
            not_after: Timestamp(1_800_000_000),
        },
        network: Network::Lease { seconds: 28_800, max_offline_seconds: 28_800 },
        min_binding: Binding::HardwareAttested,
        max_opens: Some(5),
        watermark: true,
        ..Policy::deny_all()
    }
    .allow(Action::View)
    .allow(Action::Print)
}

fn sample_header(author_key: [u8; 32]) -> Header {
    Header {
        container_version: CONTAINER_VERSION,
        min_reader_version: SUPPORTED_READER_VERSION,
        file_id: FILE_ID,
        suite: Suite {
            sig: SigAlg::Ed25519,
            aead: AeadAlg::XChaCha20Poly1305,
            tree_hash: TreeHashAlg::Blake3,
        },
        author_key,
        header_salt: [0x22; 32],
        chunk_size: 65536,
        original_root: [0x33; 32],
        policy: sample_policy(),
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
        class: 0,
        footer_offset: None,
        wrapped_cek: [0xbb; WRAPPED_CEK_LEN],
        coauthors: None,
    }
}

/// Сырая запись TLV: тег, объявленная длина и байты значения — независимо друг
/// от друга. Именно так строится «почти корректный» ввод: правильные теги,
/// испорченные длины.
fn raw_record(tag: u16, declared_len: u32, value: &[u8], out: &mut Vec<u8>) {
    out.extend_from_slice(&tag.to_le_bytes());
    out.extend_from_slice(&declared_len.to_le_bytes());
    out.extend_from_slice(value);
}

/// Собрать контейнер вокруг готовых байт заголовка и подписать их своим ключом.
fn signed_container(header_bytes: &[u8], signer: &Ed25519Signer, suite: &Suite) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&(header_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(header_bytes);
    match header_signing_transcript(header_bytes, suite) {
        Ok(t) => match signer.sign(&t) {
            Ok(sig) => out.extend_from_slice(&sig),
            Err(_) => out.extend_from_slice(&[0u8; 64]),
        },
        Err(_) => out.extend_from_slice(&[0u8; 64]),
    }
    out.extend_from_slice(&[0xcd; 96]);
    out
}

// ---------------------------------------------------------------------------
// 1. Фаззинг Header::decode
// ---------------------------------------------------------------------------

/// Все известные теги заголовка плюс соседние неизвестные из обоих диапазонов.
const HEADER_TAGS: [u16; 24] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 500, 0x7FFF, 0x8000,
    0x9000, 0xFFFF,
];

#[test]
fn header_decode_survives_structurally_plausible_garbage() {
    let mut rng = Rng(0xa11ce);
    let good = sample_header([0x01; 32]).encode().unwrap();

    for iteration in 0..60_000u32 {
        let mut buf = Vec::new();
        let fields = 1 + rng.below(8);
        let mut tags: Vec<u16> = (0..fields).map(|_| rng.pick(&HEADER_TAGS)).collect();
        tags.sort_unstable();
        tags.dedup();

        for tag in tags {
            // Значение: то правильной длины для этого тега, то случайной.
            let value: Vec<u8> = match rng.below(4) {
                0 => { let n = rng.below(40); rng.bytes(n) }
                1 => vec![0u8; rng.below(70)],
                2 => { let n = rng.pick(&[0usize, 1, 2, 4, 8, 16, 32, 48]); rng.bytes(n) }
                _ => good[..rng.below(good.len().min(64))].to_vec(),
            };
            // Объявленная длина: то честная, то от противника.
            let declared = match rng.below(5) {
                0 => u32::MAX,
                1 => u32::MAX / 2,
                2 => (value.len() as u32).wrapping_add(rng.below(4) as u32),
                3 => rng.next() as u32,
                _ => value.len() as u32,
            };
            raw_record(tag, declared, &value, &mut buf);
        }

        let outcome = catch_unwind(AssertUnwindSafe(|| Header::decode(&buf).map(|_| ())));
        assert!(
            outcome.is_ok(),
            "итерация {iteration}: паника Header::decode на {} байтах: {buf:02x?}",
            buf.len()
        );
    }
}

#[test]
fn header_decode_survives_bit_flips_and_truncation_of_a_valid_header() {
    let mut rng = Rng(0xbeef_cafe);
    let valid = sample_header([0x01; 32]).encode().unwrap();

    for cut in 0..=valid.len() {
        let outcome = catch_unwind(AssertUnwindSafe(|| Header::decode(&valid[..cut]).map(|_| ())));
        assert!(outcome.is_ok(), "паника на обрезании до {cut} байт");
    }

    for iteration in 0..40_000u32 {
        let mut buf = valid.clone();
        let flips = 1 + rng.below(6);
        for _ in 0..flips {
            let pos = rng.below(buf.len());
            buf[pos] ^= 1u8 << rng.below(8);
        }
        let outcome = catch_unwind(AssertUnwindSafe(|| Header::decode(&buf).map(|_| ())));
        assert!(outcome.is_ok(), "итерация {iteration}: паника после порчи битов");
    }
}

/// Вложенность: слот, содержащий TLV, содержащий TLV, …
///
/// Рекурсии в разборе слота нет, поэтому глубина не обязана иметь предел — но
/// это надо доказать, а не предположить: стековое переполнение от глубины
/// вложенности вообще не ловится `catch_unwind`.
#[test]
fn deeply_nested_tlv_inside_a_key_slot_does_not_blow_the_stack() {
    for depth in [1usize, 8, 64, 512, 4096, 32_768] {
        let mut body = vec![0xffu8; 8];
        for level in 0..depth {
            let mut w = TlvWriter::new();
            // Тег внутри слота: чередуем известный и неизвестный.
            w.put(if level % 2 == 0 { 4 } else { 9 }, &body).unwrap();
            body = w.finish().to_vec();
            if body.len() > 400_000 {
                break;
            }
        }
        let mut slots = TlvWriter::new();
        slots.put(0, &body).unwrap();

        let mut header = sample_header([0x01; 32]).encode().unwrap();
        // Заменить запись слотов целиком проще, чем править на месте: собираем
        // заголовок заново из готового набора записей.
        header = replace_field(&header, htag::KEY_SLOTS, &slots.finish());

        let outcome = catch_unwind(AssertUnwindSafe(|| Header::decode(&header).map(|_| ())));
        assert!(outcome.is_ok(), "глубина {depth}: паника или переполнение стека");
    }
}

/// Значение поля заголовка по тегу — как оно лежит в байтах.
fn field_value(header_bytes: &[u8], tag: u16) -> Option<Vec<u8>> {
    let mut reader = oc_format::tlv::TlvReader::new(header_bytes);
    while let Some(field) = reader.next_field().unwrap() {
        if field.tag == tag {
            return Some(field.value.to_vec());
        }
    }
    None
}

fn replace_field(header_bytes: &[u8], tag: u16, new_value: &[u8]) -> Vec<u8> {
    let mut reader = oc_format::tlv::TlvReader::new(header_bytes);
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

/// Тег `kind` внутри записи слота. Модуль `slot_tag` приватен, поэтому число
/// повторено здесь: проба обязана собирать байты сама, а не через конструктор.
const SLOT_TAG_KIND: u16 = 1;

/// Вид слота, которого `SlotKind::from_u16` не знает. Такой слот `decode_slot`
/// ПРИНИМАЕТ и возвращает как `KeySlot::Unknown` — правило чтения §3.3.
const UNKNOWN_SLOT_KIND: u16 = 0xBEEF;

/// Заголовок, у которого запись `key_slots` заменена на `count` слотов,
/// принимаемых `decode_slot`.
///
/// Минимальный принимаемый слот — одно поле `kind` с незнакомым значением: 14
/// байт на запись вместе с обоими заголовками TLV. Именно принимаемость здесь
/// существенна, см. пробу ниже.
fn header_with_accepted_slots(count: usize) -> Vec<u8> {
    let mut slots = TlvWriter::new();
    for index in 0..count {
        let mut slot = TlvWriter::new();
        slot.put(SLOT_TAG_KIND, &UNKNOWN_SLOT_KIND.to_le_bytes()).unwrap();
        slots.put(u16::try_from(index).unwrap(), &slot.finish()).unwrap();
    }
    replace_field(
        &sample_header([0x01; 32]).encode().unwrap(),
        htag::KEY_SLOTS,
        &slots.finish(),
    )
}

/// Предел числа слотов обязан срабатывать ДО накопления, а не после.
///
/// Записи здесь НЕ пустые, и это главное в пробе. Прежняя её редакция клала
/// 20 000 пустых записей по 6 байт — а пустая запись отвергается на первой же
/// итерации, `MissingField { tag: 1 }`, задолго до сравнения с `MAX_KEY_SLOTS`.
/// Поэтому проба была зелена и с проверкой предела, и с удалённой: она сторожила
/// обязательность поля `kind`, а не предел, при том что называлась пределом.
///
/// Отсюда же требование ИМЕННО `BadFieldLength { tag: KEY_SLOTS }`: «любая
/// ошибка» — это ровно та формулировка, которая позволила прежней редакции
/// зеленеть не по своей причине.
#[test]
fn the_key_slot_limit_is_enforced_before_accumulation() {
    let over = header_with_accepted_slots(MAX_KEY_SLOTS.saturating_add(1));
    let outcome = catch_unwind(AssertUnwindSafe(|| Header::decode(&over).map(|_| ())));
    assert!(outcome.is_ok(), "паника на MAX_KEY_SLOTS + 1 слотах");
    match Header::decode(&over) {
        Err(FormatError::BadFieldLength { tag, len }) => {
            assert_eq!(tag, htag::KEY_SLOTS, "предел сработал не на записи слотов");
            // Накопление обязано остановиться РОВНО на пределе, а не после него:
            // отчёт о `len`, большем `MAX_KEY_SLOTS`, означал бы, что лишние
            // слоты уже разобраны и лежат в памяти.
            assert_eq!(len, MAX_KEY_SLOTS, "предел сработал после накопления");
        }
        other => panic!("ожидался отказ по пределу слотов, получено {other:?}"),
    }
}

/// Обратная половина предела: ровно `MAX_KEY_SLOTS` слотов обязаны приниматься.
///
/// Без неё «предел» проходил бы и при `MAX_KEY_SLOTS = 0`: отказ на 1025 записях
/// сам по себе не отличает границу от запрета вообще.
#[test]
fn exactly_max_key_slots_are_accepted() {
    let at_limit = header_with_accepted_slots(MAX_KEY_SLOTS);
    let header = Header::decode(&at_limit).expect("MAX_KEY_SLOTS слотов отвергнуты");
    assert_eq!(header.header.key_slots.len(), MAX_KEY_SLOTS);
}

// ---------------------------------------------------------------------------
// 2. Фаззинг policy_codec::decode
// ---------------------------------------------------------------------------

const POLICY_TAGS: [u16; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 50, 0x7FFF, 0x8000, 0xFFFF];

#[test]
fn policy_decode_survives_structurally_plausible_garbage() {
    let mut rng = Rng(0xf00d);
    for iteration in 0..60_000u32 {
        let mut buf = Vec::new();
        let fields = 1 + rng.below(7);
        let mut tags: Vec<u16> = (0..fields).map(|_| rng.pick(&POLICY_TAGS)).collect();
        tags.sort_unstable();
        tags.dedup();

        for tag in tags {
            let value: Vec<u8> = match rng.below(5) {
                0 => vec![],
                1 => vec![rng.next() as u8],
                2 => { let n = rng.pick(&[1usize, 4, 8, 9, 16, 17, 18]); rng.bytes(n) }
                3 => {
                    // Вложенный набор действий: правильная форма, случайные значения.
                    let mut inner = Vec::new();
                    let mut t = 0u16;
                    for _ in 0..rng.below(9) {
                        t = t.wrapping_add(1 + rng.below(3) as u16);
                        raw_record(t, 1, &[rng.next() as u8], &mut inner);
                    }
                    inner
                }
                _ => { let n = rng.below(24); rng.bytes(n) }
            };
            let declared = match rng.below(4) {
                0 => u32::MAX,
                1 => rng.next() as u32,
                2 => (value.len() as u32).wrapping_sub(1),
                _ => value.len() as u32,
            };
            raw_record(tag, declared, &value, &mut buf);
        }

        let outcome = catch_unwind(AssertUnwindSafe(|| policy_codec::decode(1, &buf).map(|_| ())));
        assert!(
            outcome.is_ok(),
            "итерация {iteration}: паника policy_codec::decode на {buf:02x?}"
        );
    }
}

// ---------------------------------------------------------------------------
// 3. Фаззинг ContentDesc::decode_verified с ПРАВИЛЬНЫМ MAC
// ---------------------------------------------------------------------------

/// Транскрипт MAC так, как его считает код (`content.rs::mac_transcript`).
fn code_transcript(file_id: &[u8; 16], body: &[u8]) -> Transcript {
    let mut t = Transcript::new(label::CONTENT_MAC);
    t.fixed(file_id).field(body);
    t
}

fn frame_with_code_mac(body: &[u8], key: &MacKey, file_id: &[u8; 16]) -> Vec<u8> {
    let tag = mac::compute(key, &code_transcript(file_id, body)).unwrap();
    let mut out = (body.len() as u32).to_le_bytes().to_vec();
    out.extend_from_slice(body);
    out.extend_from_slice(&tag);
    out
}

const CONTENT_TAGS: [u16; 10] = [0, 1, 2, 3, 4, 5, 6, 0x7FFF, 0x8000, 0xFFFF];

#[test]
fn content_desc_body_decoder_survives_garbage_that_carries_a_valid_mac() {
    // Без правильного MAC разбор тела недостижим: `decode_verified` отвергает
    // область раньше. Харнесс держит ключ MAC ровно поэтому.
    let key = mac_key();
    let mut rng = Rng(0x0ddba11);

    for iteration in 0..40_000u32 {
        let mut body = Vec::new();
        let fields = 1 + rng.below(6);
        let mut tags: Vec<u16> = (0..fields).map(|_| rng.pick(&CONTENT_TAGS)).collect();
        tags.sort_unstable();
        tags.dedup();
        for tag in tags {
            let n = rng.pick(&[0usize, 1, 2, 4, 8, 12, 16, 32]);
            let value = rng.bytes(n);
            let declared = match rng.below(4) {
                0 => u32::MAX,
                1 => rng.next() as u32,
                2 => (value.len() as u32).wrapping_add(1),
                _ => value.len() as u32,
            };
            raw_record(tag, declared, &value, &mut body);
        }
        let framed = frame_with_code_mac(&body, &key, &FILE_ID);

        let outcome = catch_unwind(AssertUnwindSafe(|| {
            ContentDesc::decode_verified(&framed, &key, &FILE_ID, oc_format::header::CONTAINER_VERSION).map(|_| ())
        }));
        assert!(outcome.is_ok(), "итерация {iteration}: паника на теле {body:02x?}");

        // И то же тело при испорченной рамке.
        let mut broken = framed.clone();
        let pos = rng.below(broken.len());
        broken[pos] ^= 1u8 << rng.below(8);
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            ContentDesc::decode_verified(&broken, &key, &FILE_ID, oc_format::header::CONTAINER_VERSION).map(|_| ())
        }));
        assert!(outcome.is_ok(), "итерация {iteration}: паника на испорченной рамке");
    }
}

/// Экстремальные, но заверенные MAC значения: владелец CEK — тоже противник.
#[test]
fn extreme_but_authenticated_content_values_never_panic_downstream() {
    let key = mac_key();
    for (total_len, chunk_count, footer) in [
        (u64::MAX, u32::MAX, Some(u64::MAX)),
        (u64::MAX, 1u32, None),
        (0u64, u32::MAX, Some(0)),
        (u64::MAX / 2, 0u32, None),
        (4096, u32::MAX, None),
    ] {
        let mut w = TlvWriter::new();
        w.put(ctag::TOTAL_LEN, &total_len.to_le_bytes()).unwrap();
        w.put(ctag::CHUNK_COUNT, &chunk_count.to_le_bytes()).unwrap();
        w.put(ctag::TREE_ROOT, &[0xab; 32]).unwrap();
        w.put(ctag::VERSION_COUNTER, &u64::MAX.to_le_bytes()).unwrap();
        if let Some(f) = footer {
            w.put(ctag::FOOTER_OFFSET, &f.to_le_bytes()).unwrap();
        }
        let framed = frame_with_code_mac(&w.finish(), &key, &FILE_ID);

        let outcome = catch_unwind(AssertUnwindSafe(|| {
            let decoded = ContentDesc::decode_verified(&framed, &key, &FILE_ID, oc_format::header::CONTAINER_VERSION);
            if let Ok((desc, _)) = decoded {
                for size in [4096u32, 65536, 1 << 20] {
                    let _ = desc.check_against_chunk_size(size);
                }
            }
        }));
        assert!(
            outcome.is_ok(),
            "паника на total_len={total_len} chunk_count={chunk_count} footer={footer:?}"
        );
    }
}

// ---------------------------------------------------------------------------
// 4. Корректно подписанный враждебный заголовок (docs/format.md §5.2)
// ---------------------------------------------------------------------------

#[test]
fn verify_and_parse_survives_hostile_headers_signed_by_the_harness_key() {
    let signer = Ed25519Signer::from_seed(&[0x42; 32]);
    let suite = Suite {
        sig: SigAlg::Ed25519,
        aead: AeadAlg::XChaCha20Poly1305,
        tree_hash: TreeHashAlg::Blake3,
    };
    let mut rng = Rng(0x5ec1_2117);
    let good = sample_header(signer.public_key()).encode().unwrap();

    for iteration in 0..20_000u32 {
        let mut header = good.clone();
        match rng.below(4) {
            0 => {
                let flips = 1 + rng.below(5);
                for _ in 0..flips {
                    let pos = rng.below(header.len());
                    header[pos] ^= 1u8 << rng.below(8);
                }
            }
            1 => header.truncate(rng.below(header.len() + 1)),
            2 => {
                let tag = rng.pick(&HEADER_TAGS);
                let n = rng.below(40);
                let value = rng.bytes(n);
                raw_record(tag, rng.next() as u32, &value, &mut header);
            }
            _ => {
                let n = rng.below(48);
                header.extend_from_slice(&rng.bytes(n));
            }
        }
        let buf = signed_container(&header, &signer, &suite);
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            verify_and_parse(&buf, &EmptyTrustStore).map(|_| ())
        }));
        assert!(outcome.is_ok(), "итерация {iteration}: паника verify_and_parse");
    }
}

// ---------------------------------------------------------------------------
// 5. Транскрипт MAC изменяемой области против §1.2
// ---------------------------------------------------------------------------

/// Транскрипт §1.2, набранный по тексту спецификации независимо от `content.rs`:
/// метка ‖ 0x00, затем `fixed(file_id)`, затем `field(тело)` — то есть
/// u32le(длина тела) ‖ СЫРЫЕ байты тела.
fn spec_transcript(file_id: &[u8; 16], body: &[u8]) -> Transcript {
    let mut t = Transcript::new(label::CONTENT_MAC);
    t.fixed(file_id).field(body);
    t
}

/// Транскрипт из прежней редакции спецификации: по РАЗОБРАННЫМ значениям полей.
/// Оставлен намеренно — им доказывается, что нынешний читатель такую область
/// отвергает, и объясняется, почему это правильно (см. тест ниже).
fn superseded_value_transcript(
    file_id: &[u8; 16],
    desc: &ContentDesc,
    body_len: u32,
) -> Transcript {
    let mut t = Transcript::new(label::CONTENT_MAC);
    t.fixed(file_id)
        .u32le(body_len)
        .u64be(desc.total_len)
        .u32be(desc.chunk_count)
        .fixed(&desc.tree_root)
        .u64be(desc.version_counter)
        .u8(u8::from(desc.footer_offset.is_some()))
        .u64be(desc.footer_offset.unwrap_or(0));
    t
}

/// ПЕРЕСМОТРЕНО ОТКРЫТО, не молча. Прежняя редакция этой пробы называлась
/// `the_content_mac_follows_the_transcript_named_by_the_specification` и
/// требовала, чтобы читатель принял область, заверенную транскриптом по
/// РАЗОБРАННЫМ значениям полей. Такой транскрипт стоял в прежней редакции §1.2;
/// нынешняя редакция задаёт `fixed(file_id) ‖ field(тело)` над сырыми байтами и
/// объясняет, почему иначе нельзя.
///
/// Требование прежней пробы было не просто устаревшим, а несовместимым с двумя
/// другими обещаниями формата. Транскрипт по значениям (1) заставил бы обе
/// стороны знать ВСЕ поля тела — тогда необязательный тег версии 2 ломал бы MAC
/// у клиента версии 1, то есть точка расширения §2.1 п.3 переставала бы работать
/// ровно там, где обещана; (2) требовал бы отдельного байта-признака «футер
/// есть», хотя §1.2 прямо говорит, что «футера нет» и «футер по смещению 0»
/// различимы самими байтами тела; (3) воспроизводил бы канонизационную ошибку
/// JWS/XML-DSig — разобрали одно, заверили другое.
#[test]
fn the_content_mac_covers_the_raw_body_bytes_so_unknown_optional_fields_still_verify() {
    let key = mac_key();
    let desc = ContentDesc {
        total_len: 5_000_000,
        chunk_count: 77,
        tree_root: [0xab; 32],
        version_counter: 3,
        footer_offset: None,
        editor: None,
    };

    // Харнесс играет вторую реализацию, написанную по тексту §1.2: собирает
    // область сам и предъявляет её нашему читателю.
    let ours = desc.encode(&key, &FILE_ID, oc_format::header::CONTAINER_VERSION).unwrap();
    let body = &ours[4..ours.len() - MAC_LEN];
    let body_len = u32::try_from(body.len()).unwrap();

    let framed = |body: &[u8]| {
        let tag = mac::compute(&key, &spec_transcript(&FILE_ID, body)).unwrap();
        let mut area = u32::try_from(body.len()).unwrap().to_le_bytes().to_vec();
        area.extend_from_slice(body);
        area.extend_from_slice(&tag);
        area
    };

    let got = ContentDesc::decode_verified(&framed(body), &key, &FILE_ID, oc_format::header::CONTAINER_VERSION);
    assert!(
        matches!(&got, Ok((decoded, _)) if *decoded == desc),
        "область, собранная строго по §1.2, отвергнута нашим читателем: {got:?}"
    );

    // Свойство, ради которого транскрипт и берёт сырые байты: писатель версии 2
    // дописал необязательный тег, читатель версии 1 обязан сойтись по MAC и
    // пропустить тег. При транскрипте по значениям это было бы невозможно.
    let mut future_body = body.to_vec();
    let mut extra = TlvWriter::new();
    extra.put(0x8001, b"field from a future version").unwrap();
    future_body.extend_from_slice(&extra.finish());
    let (back, read) =
        ContentDesc::decode_verified(&framed(&future_body), &key, &FILE_ID, oc_format::header::CONTAINER_VERSION).unwrap();
    assert_eq!(back, desc, "необязательный тег версии 2 изменил разобранное описание");
    assert_eq!(read, 4 + future_body.len() + MAC_LEN);

    // И обратная сторона: область, заверенная транскриптом прежней редакции, для
    // нынешнего читателя — подделка. Иначе одна и та же область имела бы два
    // допустимых MAC, и «подлинность» перестала бы быть однозначной.
    let stale_tag =
        mac::compute(&key, &superseded_value_transcript(&FILE_ID, &desc, body_len)).unwrap();
    let mut stale_area = body_len.to_le_bytes().to_vec();
    stale_area.extend_from_slice(body);
    stale_area.extend_from_slice(&stale_tag);
    assert!(
        ContentDesc::decode_verified(&stale_area, &key, &FILE_ID, oc_format::header::CONTAINER_VERSION).is_err(),
        "область с транскриптом прежней редакции принята: у одной области два MAC"
    );
}

// ---------------------------------------------------------------------------
// 6. НАХОДКА: отсутствующее поле политики трактуется как послабление
// ---------------------------------------------------------------------------

/// Тело политики без указанных тегов.
fn policy_body_without(skip: &[u16]) -> Vec<u8> {
    let mut actions = TlvWriter::new();
    actions.put(1, &[1]).unwrap(); // View = Allow
    let actions = actions.finish().to_vec();

    let mut w = TlvWriter::new();
    let all: [(u16, Vec<u8>); 6] = [
        (policy_codec::tag::ACTIONS, actions),
        (policy_codec::tag::VALIDITY, vec![1]),        // Always
        (policy_codec::tag::NETWORK, vec![1]),         // StrictOnline
        (policy_codec::tag::MIN_BINDING, vec![1]),     // Software
        (policy_codec::tag::MAX_OPENS, 3u32.to_le_bytes().to_vec()),
        (policy_codec::tag::WATERMARK, vec![1]),       // watermark включён
    ];
    for (tag, value) in all {
        if !skip.contains(&tag) {
            w.put(tag, &value).unwrap();
        }
    }
    w.finish().to_vec()
}

#[test]
fn a_policy_field_that_is_absent_is_never_read_as_a_relaxation() {
    // §4: «Отсутствующее поле означает запрет», в клиенте любой версии.
    // §2.1 п.5: инвариант проверяется перебором комбинаций отсутствующих полей.
    //
    // Полный набор полей включает watermark. Убрав ровно это поле, мы обязаны
    // получить либо отказ, либо политику НЕ СЛАБЕЕ полной. Сейчас разбор
    // молча возвращает watermark = false.
    let full = policy_codec::decode(1, &policy_body_without(&[])).unwrap();
    assert!(full.watermark, "контроль: полная политика требует водяной знак");

    for skip in [
        vec![policy_codec::tag::WATERMARK],
        vec![policy_codec::tag::MAX_OPENS],
        vec![policy_codec::tag::WATERMARK, policy_codec::tag::MAX_OPENS],
    ] {
        let bytes = policy_body_without(&skip);
        match policy_codec::decode(1, &bytes) {
            // Отказ — корректная реакция: клиент не понял правила целиком.
            Err(_) => {}
            Ok(weakened) => {
                assert!(
                    weakened.watermark >= full.watermark,
                    "без полей {skip:?} водяной знак отключился: отсутствие поля стало послаблением"
                );
                let opens_ok = match (full.max_opens, weakened.max_opens) {
                    (Some(a), Some(b)) => b <= a,
                    (Some(_), None) => false,
                    (None, _) => true,
                };
                assert!(
                    opens_ok,
                    "без полей {skip:?} лимит открытий снят: {:?} → {:?}",
                    full.max_opens, weakened.max_opens
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 7. Состав полей заголовка против таблицы §2
// ---------------------------------------------------------------------------

/// Убрать запись с указанным тегом, сохранив остальные байт в байт.
fn header_without(header_bytes: &[u8], tag: u16) -> Vec<u8> {
    let mut reader = oc_format::tlv::TlvReader::new(header_bytes);
    let mut w = TlvWriter::new();
    while let Some(field) = reader.next_field().unwrap() {
        if field.tag != tag {
            w.put(field.tag, field.value).unwrap();
        }
    }
    w.finish().to_vec()
}

/// ПЕРЕСМОТРЕНО ОТКРЫТО, не молча. Прежняя редакция этой пробы называлась
/// `a_header_containing_exactly_the_fields_of_the_specification_is_readable` и
/// требовала обратного: чтобы заголовок БЕЗ тега 17 разбирался, а сам тег 17
/// лежал в необязательном диапазоне (> 0x7FFF). Проба опиралась на редакцию
/// `docs/format.md`, где таблица §2 обрывалась на теге 16. В нынешней редакции
/// §2 строка 17 есть, и она гласит: `wrapped_cek`, bytes[72], **обязателен**;
/// его отсутствие — отказ.
///
/// Требование прежней пробы нельзя было исполнить ни одной из двух правок.
/// Перенос поля в необязательный диапазон означал бы, что читатель, который его
/// не знает, ПРОПУСКАЕТ единственный завёрнутый ключ содержимого и затем не
/// открывает ни байта, сообщая об этом как о повреждении файла, — то есть ровно
/// молчаливое расхождение, ради предотвращения которого диапазоны и разделены.
/// А приём заголовка без тега 17 означал бы контейнер, который нечем
/// расшифровать, признанным корректным.
#[test]
fn the_wrapped_cek_field_is_mandatory_and_stays_in_the_critical_tag_range() {
    let full = sample_header([0x01; 32]).encode().unwrap();

    // Контроль: полный заголовок по §2 читается, и обёртка ровно той длины,
    // которую §3.1 закрепляет форматом (24 + 32 + 16).
    let parsed = Header::decode(&full).expect("полный заголовок §2 обязан разбираться");
    assert_eq!(parsed.header.wrapped_cek.len(), 72, "§3.1: обёртка CEK — ровно 72 байта");

    // §2, строка 17: отсутствие поля — отказ, а не заголовок с «пустой» обёрткой.
    assert_eq!(
        Header::decode(&header_without(&full, htag::WRAPPED_CEK)).map(|_| ()),
        Err(oc_format::FormatError::MissingField { tag: htag::WRAPPED_CEK }),
        "заголовок без обязательного по §2 поля 17 принят как корректный"
    );

    // §2: тег ≤ 0x7FFF критичен. Обёртка обязана оставаться именно здесь: клиент,
    // который её не знает, должен отказаться открывать файл, а не пропустить поле.
    assert!(
        htag::WRAPPED_CEK <= oc_format::tlv::CRIT_TAG_MAX,
        "обязательное поле уехало в необязательный диапазон: незнающий его клиент \
         пропустил бы обёртку CEK и сообщил бы о неоткрываемом файле как о повреждении"
    );
}

/// ПЕРЕСМОТРЕНО ОТКРЫТО, не молча. Прежняя редакция этой пробы называлась
/// `the_suite_map_accepts_the_members_the_specification_lists` и требовала,
/// чтобы `suite` с членами `kdf_id`(4) и `kem_id`(5) разбирался: так `suite`
/// был описан в прежней редакции §2. Нынешняя редакция §2 говорит «ровно три
/// члена: sig_alg(1), aead_id(2), tree_hash_id(3). Ни kdf_id, ни kem_id» и
/// отводит обоим отсутствующим членам по абзацу объяснения.
///
/// Исполнить требование прежней пробы значило бы завести второй источник истины
/// о KEM: по §3.3 `kem_id` задаётся НА КАЖДЫЙ СЛОТ, ради того слоты и заведены —
/// слот сервера и слот устройства автора уже идут к разным KEM. Общефайловый
/// `kem_id` либо запретил бы это сосуществование, либо разошёлся бы со слотом, и
/// тогда файл читался бы по разным KEM у двух реализаций. `kdf_id` же имеет
/// ровно одно допустимое значение: критичное поле, которое читатель может только
/// молча проигнорировать, — это то, что формат запрещает прямо.
#[test]
fn the_suite_map_holds_exactly_the_three_members_of_the_specification() {
    let base = sample_header([0x01; 32]).encode().unwrap();

    // Контроль: три члена §2 и ничего больше — читается.
    let mut suite = TlvWriter::new();
    suite.put(1, &[SigAlg::Ed25519 as u8]).unwrap();
    suite.put(2, &[AeadAlg::XChaCha20Poly1305 as u8]).unwrap();
    suite.put(3, &[TreeHashAlg::Blake3 as u8]).unwrap();
    let three = suite.finish();
    let parsed = Header::decode(&replace_field(&base, htag::SUITE, &three))
        .expect("набор из трёх членов §2 обязан разбираться");
    assert_eq!(parsed.header.suite.sig, SigAlg::Ed25519);

    // §2 + §3.3: KEM берётся из СЛОТА, а не из набора алгоритмов. Единственный
    // источник истины о KEM — вот он.
    assert!(
        matches!(
            parsed.header.key_slots.first(),
            Some(KeySlot::Known(KnownSlot { kem: KemAlg::X25519HkdfSha256, .. }))
        ),
        "kem_id обязан читаться из записи слота"
    );

    // Любой четвёртый член лежит в критичном диапазоне и этому клиенту неизвестен:
    // §2 требует отказа, а не молчаливого пропуска.
    for (extra_tag, value) in [(4u16, vec![1u8]), (5u16, vec![KemAlg::X25519HkdfSha256 as u8])] {
        let mut suite = TlvWriter::new();
        suite.put(1, &[SigAlg::Ed25519 as u8]).unwrap();
        suite.put(2, &[AeadAlg::XChaCha20Poly1305 as u8]).unwrap();
        suite.put(3, &[TreeHashAlg::Blake3 as u8]).unwrap();
        suite.put(extra_tag, &value).unwrap();
        assert_eq!(
            Header::decode(&replace_field(&base, htag::SUITE, &suite.finish())).map(|_| ()),
            Err(oc_format::FormatError::UnknownCriticalField { tag: extra_tag }),
            "член {extra_tag} набора алгоритмов, которого нет в §2, принят молча"
        );
    }
}

// ---------------------------------------------------------------------------
// 8. НАХОДКА: внутри слота неизвестный КРИТИЧНЫЙ тег молча игнорируется
// ---------------------------------------------------------------------------

#[test]
fn an_unknown_critical_field_inside_a_key_slot_is_not_silently_dropped() {
    // §2: «тег ≤ 0x7FFF критичен, и неизвестный такой тег означает отказ
    // открывать файл». Правило сформулировано как свойство ДИАПАЗОНА тега, а не
    // одного конкретного контейнера, и `Header::decode`, `decode_suite`,
    // `decode_authority`, `policy_codec::decode` его соблюдают.
    //
    // ИСТОРИЯ. Проба заводилась, когда `decode_slot` отбрасывал ЛЮБОЙ незнакомый
    // тег: слот с известным видом и KEM, но с добавленным в версии 2 критичным
    // ограничением, открывался клиентом версии 1 так, будто ограничения нет.
    // Затем маятник ушёл в другую крайность — отвергался весь ФАЙЛ, и точка
    // расширения, ради которой слоты заведены, оказалась закрыта: любой будущий
    // вид слота делал контейнер нечитаемым даже для клиента, у которого есть
    // собственный открываемый слот.
    //
    // Нынешнее правило (пункт С-6): непригоден СЛОТ, а не файл. Он отдаётся как
    // `Unknown` — то есть сохраняется целиком и не используется, ровно как слот
    // незнакомого вида или с незнакомым `kem_id`.
    //
    // Тег берётся МАКСИМАЛЬНЫЙ критичный, а не первый свободный, и это третья
    // редакция этой строки. Сначала здесь стоял тег 7 — и стал NONCE. Потом тег 8
    // как «первый свободный» — и стал CLAIM_COMMIT вместе с кодом-претензией. В
    // оба раза проба продолжала проходить, но проверяла уже не диапазон тега, а
    // длину известного поля: реестр вырос, а проба об этом не узнала.
    //
    // `CRIT_TAG_MAX` — верхняя граница критичного диапазона. Реестр растёт снизу,
    // поэтому дойти до неё он может только вместе с решением, которое заметят.
    const UNKNOWN_CRITICAL: u16 = oc_format::tlv::CRIT_TAG_MAX;

    let mut slot = TlvWriter::new();
    slot.put(1, &(SlotKind::AuthorDevice as u16).to_le_bytes()).unwrap(); // KIND
    slot.put(2, &[KemAlg::X25519HkdfSha256 as u8]).unwrap(); // KEM
    slot.put(3, &[0x44; 32]).unwrap(); // ENC
    slot.put(4, &[0x55; 48]).unwrap(); // CT
    slot.put(5, &[0x66; 32]).unwrap(); // COMMITMENT
    slot.put(6, &[0x77; 32]).unwrap(); // KEY_FPR
    slot.put(7, &[0x88; 24]).unwrap(); // NONCE
    // Критичный диапазон, тег этому клиенту неизвестен.
    slot.put(UNKNOWN_CRITICAL, b"a constraint from a future version").unwrap();

    let mut slots = TlvWriter::new();
    slots.put(0, &slot.finish()).unwrap();
    let header = replace_field(
        &sample_header([0x01; 32]).encode().unwrap(),
        htag::KEY_SLOTS,
        &slots.finish(),
    );

    let parsed = Header::decode(&header).expect(
        "неизвестное критичное поле в ОДНОМ слоте не должно отвергать весь контейнер: \
         у клиента может быть собственный открываемый слот",
    );
    let slot = parsed.header.key_slots.first().cloned();
    assert!(
        matches!(slot, Some(KeySlot::Unknown { .. })),
        "слот с неизвестным критичным полем 8 отдан как пригодный: ограничение из \
         будущей версии потеряно молча, получено {slot:?}"
    );
}

/// Незнакомый тег из НЕОБЯЗАТЕЛЬНОГО диапазона внутри вложенных map пропускается.
///
/// Правило §2 — свойство диапазона тега, а не свойство конкретного декодера.
/// Раньше `decode_suite` и `decode_authority` отвергали любой незнакомый тег
/// безусловно, то есть необязательного диапазона внутри них не существовало
/// вовсе, и добавить туда поле в версии 2 стало бы днём отказа (пункт С-7).
#[test]
fn an_optional_unknown_tag_inside_suite_and_authority_is_skipped() {
    let base = sample_header([0x01; 32]).encode().unwrap();
    let parsed = Header::decode(&base).unwrap();

    for (tag, name) in [(htag::SUITE, "suite"), (htag::AUTHORITY, "authority")] {
        // Пересобираем вложенную map, дописав тег из необязательного диапазона.
        let mut rebuilt = field_value(&base, tag).expect("поле обязано присутствовать");
        // Тег 0x8000 — первый необязательный; длина 4, значение произвольное.
        rebuilt.extend_from_slice(&0x8000u16.to_le_bytes());
        rebuilt.extend_from_slice(&4u32.to_le_bytes());
        rebuilt.extend_from_slice(b"hint");

        let header = replace_field(&base, tag, &rebuilt);
        let got = Header::decode(&header)
            .unwrap_or_else(|e| panic!("необязательный тег внутри {name} отвергнут: {e}"));
        assert_eq!(
            got.header.suite, parsed.header.suite,
            "разбор {name} изменился от необязательного тега"
        );
    }
}

/// АДРЕС СЕРВЕРА — ПЕЧАТНЫЙ ASCII, И ЭТО ПРОВЕРЯЕТСЯ ОБЕИМИ СТОРОНАМИ.
///
/// # Почему проверяется именно содержимое, а не только длина
///
/// Единственное, что продукт делает с `authority.urls`, — печатает их человеку,
/// чтобы тот сравнил названные автором адреса с тем, куда идёт сам. Согласие
/// человека здесь и есть защитный механизм, а строку, которую печатают, выбирает
/// автор файла — то есть в общем случае противник.
///
/// Три образца ниже ломают ровно это сравнение, и все три — законный UTF-8,
/// проходивший прежнюю проверку целиком:
///
/// * `ESC` открывает управляющую последовательность: напечатанный ниже адрес
///   способен затереть строку, напечатанную выше;
/// * U+202E переворачивает порядок и показывает `moc.dab` как `bad.com`;
/// * кириллическая `а` неотличима от латинской `a` в любом шрифте.
#[test]
fn a_server_address_outside_printable_ascii_is_refused_on_both_sides() {
    let hostile = [
        ("управляющая последовательность", "https://ok.example\u{1b}[2K\u{1b}[Aevil"),
        ("переворот направления", "https://\u{202e}moc.dab/api"),
        ("кириллическая а вместо латинской", "https://p\u{430}ypal.example/api"),
        ("перевод строки", "https://ok.example\nhttps://evil.example"),
        ("пробел", "https://ok.example /api"),
    ];

    for (name, url) in hostile {
        // Все они — корректный UTF-8: прежняя проверка их пропускала.
        assert!(core::str::from_utf8(url.as_bytes()).is_ok(), "{name}: образец не UTF-8");

        // 1. НА ЗАПИСИ: такой контейнер нельзя выпустить.
        let mut header = sample_header([0x01; 32]);
        header.authority.urls = vec![url.to_string()];
        assert!(header.encode().is_err(), "{name}: выпущен контейнер с таким адресом");

        // 2. НА РАЗБОРЕ: уже выпущенный такой контейнер нельзя принять. Проверка
        //    на записи одна не годится — файл приходит от чужой реализации.
        let base = sample_header([0x01; 32]).encode().unwrap();
        let mut urls = TlvWriter::new();
        urls.put(0, url.as_bytes()).unwrap();
        let mut authority = TlvWriter::new();
        authority.put(1, &urls.finish()).unwrap();
        authority.put(2, &[0x88; 32]).unwrap();
        authority.put(3, &[0x99; 32]).unwrap();
        let bytes = replace_field(&base, htag::AUTHORITY, &authority.finish());
        assert!(Header::decode(&bytes).is_err(), "{name}: такой адрес принят на разборе");
    }
}

/// Контроль: обычный адрес по-прежнему проходит.
///
/// Без него предыдущая проба зеленела бы и от проверки, отвергающей всё подряд, —
/// а такая проверка сломала бы уже выпущенные эталоны.
#[test]
fn an_ordinary_address_still_passes() {
    let mut header = sample_header([0x01; 32]);
    header.authority.urls = vec![
        "https://cc.example/api".to_string(),
        // Нелатинское имя отсекается не как имя, а как U-форма: проводная форма
        // у него ASCII, и она проходит.
        "https://xn--80aswg.xn--p1ai:8443/api?v=1".to_string(),
        "127.0.0.1:5555".to_string(),
    ];
    let bytes = header.encode().expect("обычные адреса обязаны выпускаться");
    let back = Header::decode(&bytes).expect("обычные адреса обязаны разбираться");
    assert_eq!(back.header.authority.urls, header.authority.urls);
}
