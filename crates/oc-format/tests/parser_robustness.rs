//! Устойчивость разборщиков к враждебному вводу.
//!
//! Настоящий фаззер с `cargo-fuzz` требует nightly и отдельной установки, и он
//! появится в проекте отдельно. Этот тест закрывает тот же класс ошибок в
//! обычном `cargo test`, поэтому проверка идёт на каждой сборке, а не когда о ней
//! вспомнят: разбор обязан быть тотальным — либо структура, либо ошибка, но
//! никогда паника, зацикливание или чтение чужой памяти.
//!
//! Генератор детерминирован намеренно. Падение обязано воспроизводиться по
//! номеру итерации, иначе отладка превращается в гадание.

#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

use oc_format::tlv::{TlvReader, TlvWriter};
use oc_format::{FormatError, Layout, MAGIC, Prologue};

/// SplitMix64: короткий, воспроизводимый, хорошо перемешивающий.
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
}

fn drain_tlv(buf: &[u8]) -> Result<usize, FormatError> {
    let mut r = TlvReader::new(buf);
    let mut count = 0usize;
    while r.next_field()?.is_some() {
        count += 1;
        // Ограничитель на случай, если позиция вдруг перестанет расти: тест не
        // должен висеть, он должен падать с внятным сообщением.
        assert!(count < 100_000, "разборщик не продвигается по буферу");
    }
    Ok(count)
}

#[test]
fn tlv_reader_survives_pure_noise() {
    let mut rng = Rng(0x5eed);
    for iteration in 0..20_000 {
        let len = rng.below(96);
        let buf = rng.bytes(len);
        let result = std::panic::catch_unwind(|| drain_tlv(&buf));
        assert!(result.is_ok(), "итерация {iteration}: паника на буфере {buf:02x?}");
    }
}

#[test]
fn tlv_reader_survives_bit_flips_in_valid_input() {
    // Чистый шум почти никогда не проходит первую проверку, поэтому основная
    // ценность — в порче КОРРЕКТНЫХ данных: так тестируются глубокие ветки.
    let mut rng = Rng(0xc0ffee);
    let mut w = TlvWriter::new();
    w.put(1, b"alpha").unwrap();
    w.put(7, &[0u8; 32]).unwrap();
    w.put(9, b"").unwrap();
    w.put(0x8001, b"optional field").unwrap();
    let valid = w.finish();

    for iteration in 0..20_000 {
        let mut buf = valid.clone();
        let flips = 1 + rng.below(4);
        for _ in 0..flips {
            let pos = rng.below(buf.len());
            let bit = 1u8 << rng.below(8);
            buf[pos] ^= bit;
        }
        let result = std::panic::catch_unwind(|| drain_tlv(&buf));
        assert!(result.is_ok(), "итерация {iteration}: паника после порчи битов");
    }
}

#[test]
fn tlv_reader_survives_truncation_of_valid_input() {
    let mut w = TlvWriter::new();
    w.put(1, b"alpha").unwrap();
    w.put(2, &[0xaa; 64]).unwrap();
    w.put(3, b"omega").unwrap();
    let valid = w.finish();

    for cut in 0..=valid.len() {
        let result = std::panic::catch_unwind(|| drain_tlv(&valid[..cut]));
        assert!(result.is_ok(), "паника при обрезании до {cut} байт");
    }
}

#[test]
fn prologue_survives_noise_and_near_misses() {
    let mut rng = Rng(0xd15ea5e);
    for iteration in 0..20_000 {
        let mut buf = Vec::new();
        // Половина случаев начинается с правильной магии: иначе разбор всегда
        // отваливается на первом же сравнении и глубже не заходит.
        if iteration % 2 == 0 {
            buf.extend_from_slice(&MAGIC);
        }
        let noise_len = rng.below(80);
        buf.extend(rng.bytes(noise_len));
        let result = std::panic::catch_unwind(|| Prologue::split(&buf).map(|p| p.header.len()));
        assert!(result.is_ok(), "итерация {iteration}: паника на прологе {buf:02x?}");
    }
}

#[test]
fn prologue_never_reports_a_header_longer_than_the_buffer() {
    // Свойство важнее отсутствия паники: заголовок, выходящий за буфер, означал бы
    // чтение чужой памяти, а объявленная длина приходит от противника.
    let mut rng = Rng(0xbadc0de);
    for _ in 0..20_000 {
        let mut buf = Vec::new();
        buf.extend_from_slice(&MAGIC);
        buf.extend_from_slice(&(rng.next() as u32).to_le_bytes());
        let noise_len = rng.below(200);
        buf.extend(rng.bytes(noise_len));

        if let Ok(p) = Prologue::split(&buf) {
            assert!(p.header.len() <= buf.len(), "заголовок длиннее буфера");
            assert!(p.after_signature <= buf.len() as u64, "подпись выходит за буфер");
        }
    }
}

#[test]
fn layout_never_produces_a_span_outside_the_declared_payload() {
    // Виртуальная файловая система будет читать по этим смещениям, поэтому выход
    // за пределы означал бы чтение чужих байтов с диска.
    let mut rng = Rng(0xfeed_face);
    for _ in 0..5_000 {
        let chunk_size = 1u32 << (12 + rng.below(9)); // 4 КиБ … 1 МиБ
        let total_len = rng.next() % (1 << 26);
        let payload_offset = rng.next() % 4096;

        let expected_chunks = total_len.div_ceil(u64::from(chunk_size)).max(1);
        let Ok(count) = u32::try_from(expected_chunks) else { continue };
        let Ok(layout) = Layout::new(chunk_size, count, total_len, payload_offset) else {
            continue;
        };

        let mut covered = 0u64;
        for i in 0..layout.chunk_count() {
            let span = layout.ciphertext_span(i).unwrap();
            assert!(span.start >= payload_offset, "чанк {i} начинается до полезной нагрузки");
            assert!(span.end > span.start, "пустой диапазон у чанка {i}");
            covered += layout.plaintext_len_of(i).unwrap();
        }
        assert_eq!(covered, total_len, "чанки не покрывают файл целиком и без нахлёста");
    }
}

#[test]
fn layout_read_mapping_is_consistent_with_chunk_bounds() {
    let mut rng = Rng(0x1234_5678);
    let chunk_size = 65536u32;
    let total_len = 5_000_000u64;
    let count = u32::try_from(total_len.div_ceil(u64::from(chunk_size))).unwrap();
    let layout = Layout::new(chunk_size, count, total_len, 4096).unwrap();

    for _ in 0..20_000 {
        let offset = rng.next() % (total_len + 1000);
        let len = rng.next() % 200_000;
        let Ok(Some(range)) = layout.chunks_for(offset, len) else { continue };

        // Первый чанк обязан содержать начальный байт чтения.
        let first_start = u64::from(range.start) * u64::from(chunk_size);
        assert!(first_start <= offset, "первый чанк начинается позже начала чтения");

        // Последний чанк обязан содержать последний читаемый байт.
        let last_byte = (offset + len - 1).min(total_len - 1);
        let last_start = u64::from(range.end - 1) * u64::from(chunk_size);
        let last_end = last_start + u64::from(chunk_size);
        assert!(last_start <= last_byte && last_byte < last_end, "последний чанк не покрывает хвост");
        assert!(range.end <= layout.chunk_count(), "диапазон выходит за число чанков");
    }
}
