// SPDX-License-Identifier: MPL-2.0
// Чтение спеки на этапе компиляции: `include_str!` не рантайм-I/O, чистота крейта
// не нарушена. Прочие послабления — обычные для тестов.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    // Арифметика по смещениям внутри строки известной длины: выход за границы
    // уронил бы тест, а не продукт, и уронил бы громко. В самом крейте запрет
    // остаётся в силе.
    clippy::arithmetic_side_effects
)]

//! Check specification labels against `label::ALL` byte for byte.
//!
//! Other tests check uniqueness and prefix-freeness; this catches code/spec drift.
//! `include_str!` embeds the specification without runtime filesystem access.

const SPEC: &str = include_str!("../../../docs/format.md");

/// Extract labels from the `### 3.6 Domain labels` section.
///
/// Only that section, not the entire document: prose also mentions labels,
/// and collecting all mentions would compare the list with itself.
fn labels_from_spec() -> Vec<&'static str> {
    let start = SPEC.find("### 3.6 ").expect("раздел §3.6 не найден");
    let rest = &SPEC[start..];
    let open = rest.find("```").expect("блок меток не найден");
    let after_open = &rest[start_of_next_line(rest, open)..];
    let close = after_open.find("```").expect("блок меток не закрыт");
    let block = &after_open[..close];

    let mut out = Vec::new();
    let mut tail = block;
    while let Some(q1) = tail.find('"') {
        let after = &tail[q1 + 1..];
        let Some(q2) = after.find('"') else { break };
        out.push(&after[..q2]);
        tail = &after[q2 + 1..];
    }
    out
}

fn start_of_next_line(s: &str, from: usize) -> usize {
    s[from..].find('\n').map_or(s.len(), |n| from + n + 1)
}

/// Both lists match as sets; discrepancies are named individually.
///
/// Compare sets rather than order: the specification arranges labels in rows for
/// readability, and demanding identical code order would prohibit rearrangement
/// that changes nothing.
#[test]
fn the_spec_label_list_matches_the_code_byte_for_byte() {
    let from_spec: std::collections::BTreeSet<&str> = labels_from_spec().into_iter().collect();
    // Сверяются БАЙТЫ, а не значения `Label`: тип стережёт место вызова, а эта
    // проба — содержимое реестра, и вопрос у неё тот же, что был до типа, —
    // «совпадают ли строки со спекой». Поэтому здесь `as_bytes`, и заменять его
    // сравнением `Label` нельзя: значения совпадали бы тривиально.
    let from_code: std::collections::BTreeSet<&str> = oc_crypto::label::ALL
        .iter()
        .map(|l| core::str::from_utf8(l.as_bytes()).expect("метка не UTF-8"))
        .collect();

    assert!(!from_spec.is_empty(), "из §3.6 не выдрано ни одной метки: разбор сломан");

    let only_spec: Vec<_> = from_spec.difference(&from_code).collect();
    let only_code: Vec<_> = from_code.difference(&from_spec).collect();

    assert!(
        only_spec.is_empty(),
        "метки есть в §3.6 и нет в label::ALL — мёртвые строки: {only_spec:?}"
    );
    assert!(
        only_code.is_empty(),
        "метки есть в label::ALL и нет в §3.6 — вторая реализация не разделит домен: {only_code:?}"
    );
    assert_eq!(from_spec.len(), from_code.len());
}

/// Section parsing actually extracts labels rather than nothing.
///
/// Checks the test itself for degeneration: if `labels_from_spec` began
/// returning an empty list, say after a section-heading rename,
/// the set comparison above would pass… no, it would not, but its diagnosis
/// would concern "dead lines" rather than broken parsing. Here that is stated directly.
#[test]
fn the_extraction_actually_finds_labels() {
    let labels = labels_from_spec();
    assert!(labels.len() > 20, "выдрано подозрительно мало меток: {}", labels.len());
    assert!(labels.iter().all(|l| l.starts_with("CC/v1/")), "выдрано что-то помимо меток");
}

/// Crate source text: to ask questions values cannot answer.
const CODE: &str = include_str!("../src/lib.rs");

/// Entire `label` module body, found by counting braces.
///
/// Counting rather than finding its end by indentation: indentation is a formatting convention,
/// and a test relying on it could someday skip half the module without
/// saying so.
fn label_module_body() -> &'static str {
    let at = CODE.find("pub mod label {").expect("модуля label нет — тест устарел");
    let open = at + CODE[at..].find('{').expect("нет открывающей скобки");
    let mut depth = 0usize;
    for (offset, ch) in CODE[open..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &CODE[open..open + offset];
                }
            }
            _ => {}
        }
    }
    panic!("модуль label не закрыт");
}

/// Names of all `pub const` declarations in the label module.
///
/// `pub const fn` is filtered separately, not as syntactic nitpicking: with
/// `Label`, the module contains `const fn as_bytes`, `len`,
/// `is_empty`, and `ad_hoc`; the old parser ("everything after `pub const ` up to
/// the colon") treated them as label names and demanded their inclusion in `ALL`. Parsing here
/// is deliberately inclusive, since an extra name is costlier than a missing one, but not to the point
/// of false FAILURE: a guard that fails for no reason gets removed.
fn declared_constants(body: &str) -> Vec<&str> {
    let mut names = Vec::new();
    for line in body.lines() {
        let Some(rest) = line.trim().strip_prefix("pub const ") else { continue };
        if rest.starts_with("fn ") {
            continue;
        }
        let Some(name) = rest.split(':').next() else { continue };
        names.push(name.trim());
    }
    names
}

/// Check that every declared label appears in `ALL`.
///
/// Uniqueness, prefix and spec checks all consume `ALL`, so they cannot detect a
/// constant omitted from it. Inspect the embedded source to catch that omission.
#[test]
fn every_declared_label_is_listed_in_all() {
    let body = label_module_body();
    let declared = declared_constants(body);

    // Контроль вырожденности: разбор обязан что-то находить, иначе зелень ниже
    // означала бы «нечего проверять».
    assert!(
        declared.len() > 20,
        "в модуле label выдрано подозрительно мало констант: {}",
        declared.len()
    );
    assert!(declared.contains(&"ALL"), "разбор не нашёл сам ALL — значит нашёл не то");

    let at = body.find("pub const ALL:").expect("списка ALL нет");
    let listed = &body[at..];

    let missing: Vec<&str> = declared
        .iter()
        .copied()
        .filter(|name| *name != "ALL")
        // Слово целиком: `KEK` не должен «найтись» внутри `SEAL_KEY`.
        .filter(|name| {
            !listed
                .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .any(|word| word == *name)
        })
        .collect();

    assert!(
        missing.is_empty(),
        "метки объявлены и НЕ внесены в label::ALL — их не видит ни один из трёх \
         тестов И-12, включая сверку со спекой: {missing:?}"
    );
}
