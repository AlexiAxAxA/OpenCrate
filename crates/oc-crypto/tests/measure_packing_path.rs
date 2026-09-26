// SPDX-License-Identifier: MPL-2.0
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

//! MEASUREMENT: what makes up packing throughput.
//!
//! # Why it exists and what it corrects
//!
//! From the answer to `docs/deferred.md` §14, "is hardware AEAD worthwhile for
//! speed?" The answer there is no; analysis is in `docs/plan.md`, item `D-aead`.
//!
//! Something more important emerged en route. `D-measure` labeled its figure
//! **"complete packing (AEAD + leaf)"**, incorrectly: there are **three** passes
//! through chunk bytes, not two. The third is nonce hedging, `HKDF-SHA256`, with plaintext
//! **as IKM**, meaning a complete SHA-256 pass for twenty-four
//! bytes.
//!
//! The omission was not cosmetic: I inferred "AEAD ≈ 542 MiB/s" by subtraction
//! and opened §14 on that basis. Direct measurement gives 690–800, so the conclusion
//! rested on a figure nobody had measured.
//!
//! # What is measured here
//!
//! Three passes individually, and packing as their sum:
//! `1/(1/hedge + 1/aead + 1/leaf)`. The calculation agrees with direct `D-measure` results
//! (417–462 versus 454 MiB/s), making the model credible.
//!
//! Its main finding is the **ceiling**: even an instantaneous cipher would speed up
//! packing only two- to threefold. One pass out of three cannot give more.
//!
//! Run (only `--release`, or this measures missing optimizations):
//! `cargo test -p oc-crypto --release --test measure_packing_path -- --ignored --nocapture`

use std::time::{Duration, Instant};

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use oc_crypto::kdf::hedged_nonce;
use oc_crypto::merkle::leaf_of;

/// Product chunk size. Measuring another would not measure the product.
const CHUNK: usize = 64 * 1024;

/// "Hundreds of megabytes", as in `D-measure`, plus a smaller size.
const SIZES_MIB: [usize; 2] = [64, 256];

/// Repetitions per size; take the minimum, since interference can only add
/// time. Same rationale as `cc-cli/tests/measure_edit_cost.rs`.
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

/// First pass: nonce hedging. `HKDF-SHA256`, plaintext as IKM.
///
/// This was omitted in `D-measure`. It cannot be made cheap: nonce dependence
/// on plaintext is precisely the defense against repeated RNG state (C-13, R-2),
/// requiring a hash over the entire chunk.
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

/// Second pass: the cipher itself.
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

/// Third pass: tree leaf, BLAKE3 over ciphertext.
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

/// Packing path: three sequential passes through one chunk's bytes.
///
/// Speeding up ONE pass benefits the product less than throughput ratios suggest;
/// confusing the two means promising three times what was delivered.
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
