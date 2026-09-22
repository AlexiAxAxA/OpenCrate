// Литы сняты для ЗАМЕРА. `unwrap`/`expect`/`panic` — словарь инструмента,
// останавливающегося на первой неудаче; арифметика и индексация — счёт по
// чанкам; часы запрещены чистым крейтам, а здесь измеряется именно время.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

//! ЗАМЕР: из чего складывается скорость упаковки.
//!
//! # Зачем он появился и что исправляет
//!
//! Из ответа на `docs/deferred.md` §14 — «стоит ли брать аппаратный AEAD ради
//! скорости». Ответ там нет, и разбор в `docs/plan.md`, пункт `Д-аеад`.
//!
//! Но по дороге вскрылось важнее самого ответа. `Д-замер` подписал свою цифру
//! **«упаковка целиком (AEAD + лист)»**, и подпись неверна: проходов по байтам
//! чанка **три**, а не два. Третий — засев nonce, `HKDF-SHA256`, где открытый
//! текст идёт **как IKM**, то есть полный проход SHA-256 ради двадцати четырёх
//! байт.
//!
//! Пропуск был не косметический: из него я вывела «AEAD ≈ 542 МиБ/с» вычитанием
//! и на этом основании открыла §14. Прямой замер даёт 690–800, то есть вывод
//! опирался на цифру, которой никто не мерил.
//!
//! # Что здесь меряется
//!
//! Три прохода по отдельности и путь упаковки как их сумма:
//! `1/(1/hedge + 1/aead + 1/leaf)`. Расчёт сходится с прямым замером `Д-замер`
//! (417–462 против 454 МиБ/с), поэтому модели можно верить.
//!
//! Главное, что она показывает, — **потолок**: даже мгновенный шифр ускорил бы
//! упаковку лишь вдвое-втрое. Один проход из трёх не может дать больше.
//!
//! Запуск (только `--release`, иначе меряется отсутствие оптимизаций):
//! `cargo test -p oc-crypto --release --test measure_packing_path -- --ignored --nocapture`

use std::time::{Duration, Instant};

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use oc_crypto::kdf::hedged_nonce;
use oc_crypto::merkle::leaf_of;

/// Размер чанка продукта. Мерить на другом значило бы мерить не продукт.
const CHUNK: usize = 64 * 1024;

/// «Сотни мегабайт», как в `Д-замер`, плюс меньший размер.
const SIZES_MIB: [usize; 2] = [64, 256];

/// Повторов на величину; берётся минимум — помеха способна только добавить
/// время. Обоснование то же, что в `cc-cli/tests/measure_edit_cost.rs`.
const REPEATS: usize = 3;

fn mib_per_sec(bytes: usize, took: Duration) -> f64 {
    let s = took.as_secs_f64();
    if s <= 0.0 { f64::INFINITY } else { (bytes as f64 / (1024.0 * 1024.0)) / s }
}

fn best_of(mut body: impl FnMut() -> Duration) -> Duration {
    let mut best = Duration::MAX;
    for _ in 0..REPEATS {
        let took = body();
        if took < best {
            best = took;
        }
    }
    best
}

fn fill_pseudo(buf: &mut [u8]) {
    let mut state: u64 = 0x243f_6a88_85a3_08d3;
    for block in buf.chunks_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        for (dst, src) in block.iter_mut().zip(state.to_le_bytes().iter()) {
            *dst = *src;
        }
    }
}

/// Проход первый: засев nonce. `HKDF-SHA256`, открытый текст как IKM.
///
/// Именно он был пропущен в `Д-замер`. Дёшево его не сделать: зависимость nonce
/// от открытого текста — это и есть защита от повтора генератора (С-13, Р-2), и
/// она требует хеша по всему чанку.
fn measure_hedge(plain: &[u8]) -> f64 {
    let chunks = plain.len() / CHUNK;
    let seed = [0x77u8; 24];
    let took = best_of(|| {
        let start = Instant::now();
        let mut sink = 0u8;
        for i in 0..chunks {
            let piece = &plain[i * CHUNK..(i + 1) * CHUNK];
            // Метка берётся из реестра, а не пишется строкой. Раньше здесь
            // стоял литерал `b"CC/v1/frame-nonce"`, набранный от руки: замер
            // мерил бы вывод в домене, который случайно совпал с реестровым, а
            // при правке метки разошёлся бы с ним молча.
            let n: [u8; 24] = hedged_nonce(oc_crypto::label::FRAME_NONCE, &seed, piece, &oc_crypto::aead::chunk_aad(&[0; 16], i as u32, oc_crypto::AeadAlg::XChaCha20Poly1305)).unwrap();
            sink ^= n[0];
        }
        let took = start.elapsed();
        // `black_box`, а не `assert_eq!(sink, sink)`, как стояло сперва: то
        // сравнение тривиально истинно, оптимизатор вправе выбросить и его, и
        // работу перед ним. То есть страховка от пустого цикла сама была пустой,
        // а комментарий рядом утверждал обратное. Поймал clippy (`eq_op`).
        core::hint::black_box(sink);
        took
    });
    mib_per_sec(plain.len(), took)
}

/// Проход второй: сам шифр.
fn measure_aead(plain: &[u8]) -> (f64, f64) {
    let chunks = plain.len() / CHUNK;
    let cipher = XChaCha20Poly1305::new((&[0x5au8; 32]).into());
    let nonce = [0x11u8; 24];
    let aad = b"CC/v1/chunk measurement";
    let mut sealed: Vec<Vec<u8>> = Vec::new();

    let t_seal = best_of(|| {
        let start = Instant::now();
        let mut out = Vec::with_capacity(chunks);
        for i in 0..chunks {
            let msg = &plain[i * CHUNK..(i + 1) * CHUNK];
            out.push(cipher.encrypt(&nonce.into(), Payload { msg, aad }).expect("шифрование"));
        }
        let took = start.elapsed();
        sealed = out;
        took
    });

    let t_open = best_of(|| {
        let start = Instant::now();
        for frame in &sealed {
            let got = cipher
                .decrypt(&nonce.into(), Payload { msg: frame.as_slice(), aad })
                .expect("расшифровка");
            assert_eq!(got.len(), CHUNK);
        }
        start.elapsed()
    });

    (mib_per_sec(plain.len(), t_seal), mib_per_sec(plain.len(), t_open))
}

/// Проход третий: лист дерева, BLAKE3 по шифротексту.
fn measure_leaf(plain: &[u8]) -> f64 {
    let chunks = plain.len() / CHUNK;
    let nonce = [0x22u8; 24];
    let tag = [0x33u8; 16];
    let took = best_of(|| {
        let start = Instant::now();
        let mut sink = 0u8;
        for i in 0..chunks {
            let leaf = leaf_of(i as u32, &nonce, &tag, &plain[i * CHUNK..(i + 1) * CHUNK]);
            sink ^= leaf.0[0];
        }
        let took = start.elapsed();
        core::hint::black_box(sink);
        took
    });
    mib_per_sec(plain.len(), took)
}

/// Путь упаковки: три последовательных прохода по байтам одного чанка.
///
/// Ускорение ОДНОГО прохода даёт продукту меньше, чем кажется по отношению
/// скоростей, и путать эти две величины значит обещать втрое больше сделанного.
fn packing_path(hedge: f64, aead: f64, leaf: f64) -> f64 {
    1.0 / (1.0 / hedge + 1.0 / aead + 1.0 / leaf)
}

fn measure_one_size(mib: usize) {
    let total = mib * 1024 * 1024;
    let mut plain = vec![0u8; total];
    fill_pseudo(&mut plain);

    let hedge = measure_hedge(&plain);
    let (seal, open) = measure_aead(&plain);
    let leaf = measure_leaf(&plain);
    let path = packing_path(hedge, seal, leaf);

    println!("\n=== {mib} МиБ, чанк 64 КиБ ===");
    println!("  засев nonce, HKDF-SHA256 по открытому тексту {hedge:>8.0} МиБ/с");
    println!("  шифр XChaCha20-Poly1305                      {seal:>8.0} МиБ/с");
    println!("  лист дерева, BLAKE3 по шифротексту           {leaf:>8.0} МиБ/с");
    println!("  расшифровка (для справки)                    {open:>8.0} МиБ/с");
    println!("  ПУТЬ УПАКОВКИ, три прохода                   {path:>8.0} МиБ/с");
    println!(
        "  потолок: мгновенный шифр дал бы всего x{:.2}",
        packing_path(hedge, f64::INFINITY, leaf) / path
    );
}

#[test]
#[ignore = "замер, а не проверка: минуты времени и полгигабайта памяти"]
fn what_the_packing_path_is_made_of() {
    println!("\nЗамер к docs/plan.md, пункты Д-замер и Д-аеад.");
    println!("Собирать ОБЯЗАТЕЛЬНО с --release.");
    for mib in SIZES_MIB {
        measure_one_size(mib);
    }
    println!();
}
