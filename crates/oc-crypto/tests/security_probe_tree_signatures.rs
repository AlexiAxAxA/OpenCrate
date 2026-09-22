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
    clippy::disallowed_types
)]
//! Track 7: primitives, integrity tree, and signatures.
//!
//! This file deliberately has two parts.
//!
//! Part I: attempts to BREAK the tree, comparing shape with the RFC 6962
//! reference implementation, agreement between the four sites encoding promotion,
//! searching for two leaf sets with one root (CVE-2012-2459 class), and moving
//! a proof to another index or length.
//!
//! Part II: tests prefixed `probe_bug_`, introduced to reproduce
//! found defects and failing against the code at that time. After fixes, each
//! serves as a regression. The suite description was updated alongside the code:
//! a header outliving a fix misrepresents the build's state
//! just as a comment outliving a construction change does.

use std::collections::BTreeMap;

use oc_crypto::merkle::{Leaf, MerkleTree, leaf_of, node_of, root_of};
use oc_crypto::secret::{Cek, ClaimSecret, Kek, MacKey, PayloadKey, SecretA, SecretB, X25519Secret};
use oc_crypto::{TreeHashAlg, Transcript, label};
use zeroize::ZeroizeOnDrop;

// ---------------------------------------------------------------------------
// Инструментарий
// ---------------------------------------------------------------------------

/// Leaf deterministically derived from index and "generation".
///
/// Generation provides a second leaf set with the same indices:
/// without it, one cannot test that the root depends on content rather than only
/// leaf count.
fn leaf(index: u32, generation: u8) -> Leaf {
    let seed = *blake3::hash(&[&index.to_be_bytes()[..], &[generation]].concat()).as_bytes();
    let mut nonce = [0u8; 24];
    let mut tag = [0u8; 16];
    nonce.copy_from_slice(&seed[..24]);
    tag.copy_from_slice(&seed[..16]);
    // Шифротекст входит в лист, поэтому у синтетических листьев он тоже есть:
    // иначе пробы проверяли бы прообраз, которого продукт не производит.
    leaf_of(index, &nonce, &tag, &seed)
}

fn leaves(count: u32) -> Vec<Leaf> {
    (0..count).map(|i| leaf(i, 0)).collect()
}

/// RFC 6962 §2.1 reference, verbatim:
/// `MTH(D[n]) = HASH(0x01 ‖ MTH(D[0:k]) ‖ MTH(D[k:n]))`, where `k` is the largest
/// power of two **strictly less than** `n`. The implementation is recursive and deliberately
/// unlike the tested one: agreement between two independent expressions of one rule
/// is precisely evidence that the rule is encoded correctly.
fn rfc6962_root(set: &[Leaf]) -> [u8; 32] {
    match set.len() {
        0 => panic!("RFC 6962 не определяет MTH для пустого набора"),
        1 => set[0].0,
        n => {
            let mut k = 1usize;
            while k * 2 < n {
                k *= 2;
            }
            node_of(&rfc6962_root(&set[..k]), &rfc6962_root(&set[k..]))
        }
    }
}

/// The RFC 6962 reference yields the APEX (MTH), whereas the tree exposes a root,
/// the apex bound to leaf count. The probe compares shape, so it must
/// compare like with like: the reference apex is wrapped in the same root_of
/// as the actual apex. Directly comparing apex and root would misclassify
/// as divergence the very fix for which the binding was introduced.
fn rfc6962_reference_root(set: &[Leaf]) -> [u8; 32] {
    let count = u32::try_from(set.len()).expect("набор не влезает в u32");
    root_of(count, &rfc6962_root(set))
}

/// Path shape from leaf to root: levels at which a node is promoted.
/// A second independent encoding of the rule, specifically to catch
/// divergence between `is_promoted` and the remaining code.
fn promotion_pattern(count: u32, index: u32) -> Vec<bool> {
    let mut pattern = Vec::new();
    let mut len = count as usize;
    let mut position = index as usize;
    while len > 1 {
        pattern.push(len % 2 == 1 && position + 1 == len);
        position /= 2;
        len = len.div_ceil(2);
    }
    pattern
}

// ---------------------------------------------------------------------------
// Часть I. Дерево целостности
// ---------------------------------------------------------------------------

/// §6.3: "An odd node is promoted, as in RFC 6962".
///
/// Tests bytes rather than comments: `MerkleTree::build`'s root must
/// match the reference recursion's root at every leaf count. Divergence
/// would appear only at particular `n`, hence at a customer's site.
#[test]
fn the_shape_matches_the_rfc6962_reference_at_every_leaf_count() {
    let mut sizes: Vec<u32> = (1..=300).collect();
    sizes.extend([511, 512, 513, 1023, 1024, 1025, 4096, 4097]);
    for count in sizes {
        let set = leaves(count);
        assert_eq!(
            MerkleTree::build(&set).unwrap().root(),
            rfc6962_reference_root(&set),
            "форма дерева разошлась с RFC 6962 при {count} листьях"
        );
    }
}

/// Four sites implement promotion: construction, updating, proof collection,
/// and verification. Divergence at even one level would make
/// proofs fail at particular chunk counts.
#[test]
fn all_four_places_agree_at_every_leaf_count_and_index() {
    let mut sizes: Vec<u32> = (1..=64).collect();
    sizes.extend([100, 127, 128, 129, 255, 256, 257]);
    for count in sizes {
        let set = leaves(count);
        let tree = MerkleTree::build(&set).unwrap();
        let root = tree.root();
        assert_eq!(tree.leaf_count(), count);

        for index in 0..count {
            // 1. Построение ↔ сбор доказательства ↔ проверка.
            let path = tree.proof(index).unwrap();
            assert_eq!(
                path.len(),
                promotion_pattern(count, index).iter().filter(|p| !**p).count(),
                "длина пути не соответствует форме при {count} листьях, индекс {index}"
            );
            assert!(
                MerkleTree::verify_proof(&root, index, count, &set[index as usize], &path),
                "путь листа {index} из {count} не проверился"
            );

            // 2. Инкрементальное обновление ↔ полное перестроение.
            let mut updated = MerkleTree::build(&set).unwrap();
            let replacement = leaf(index, 1);
            let new_root = updated.update_leaf(index, replacement).unwrap();

            let mut rebuilt_set = set.clone();
            rebuilt_set[index as usize] = replacement;
            let rebuilt = MerkleTree::build(&rebuilt_set).unwrap();

            assert_eq!(new_root, rebuilt.root(), "правка {index} из {count}: корень");
            assert_eq!(updated, rebuilt, "правка {index} из {count}: уровни");
            // Эталон RFC 6962 даёт вершину; сравнивается корень, поэтому эталон
            // оборачивается той же связкой с числом листьев.
            assert_eq!(
                new_root,
                rfc6962_reference_root(&rebuilt_set),
                "правка {index} из {count}: RFC"
            );
        }
    }
}

/// CVE-2012-2459: two different leaf sequences with one root.
///
/// EXHAUSTIVE enumeration over a three-leaf alphabet and lengths 1…6: 1092
/// sequences, including every trailing duplicate, permutation, and
/// repetition implicated in the vulnerability.
#[test]
fn no_two_distinct_leaf_sequences_share_a_root() {
    let alphabet = [leaf(0, 0), leaf(1, 0), leaf(2, 0)];
    let mut roots: BTreeMap<[u8; 32], Vec<usize>> = BTreeMap::new();
    let mut total = 0usize;

    for len in 1..=6usize {
        for mut code in 0..3usize.pow(len as u32) {
            let mut set = Vec::with_capacity(len);
            let mut digits = Vec::with_capacity(len);
            for _ in 0..len {
                digits.push(code % 3);
                set.push(alphabet[code % 3]);
                code /= 3;
            }
            total += 1;
            let root = MerkleTree::build(&set).unwrap().root();
            if let Some(previous) = roots.insert(root, digits.clone()) {
                panic!("два набора листьев дали один корень: {previous:?} и {digits:?}");
            }
        }
    }
    assert_eq!(roots.len(), total, "перебор выродился");
}

/// Moving a proof to another index or length.
///
/// The leaf is computed through `leaf_of`, just as the reader computes it:
/// the chunk index enters its hash. Thus "proof of leaf i presented as
/// proof of leaf j" means verification with a leaf computed for j.
///
/// The only exception is acknowledged by the code itself: with `j == i` and
/// identical path shape, trees are indistinguishable because input lacks
/// distinguishing information. The actual boundary is MAC-covered `chunk_count`.
#[test]
fn a_proof_does_not_move_to_another_index_or_another_leaf_count() {
    for count in [2u32, 3, 4, 5, 6, 7, 8, 9, 12, 16, 17] {
        let set = leaves(count);
        let tree = MerkleTree::build(&set).unwrap();
        let root = tree.root();

        for index in 0..count {
            let path = tree.proof(index).unwrap();
            for other_count in 1..=count + 4 {
                for other_index in 0..other_count {
                    if other_index == index
                        && promotion_pattern(other_count, index) == promotion_pattern(count, index)
                    {
                        continue;
                    }
                    assert!(
                        !MerkleTree::verify_proof(
                            &root,
                            other_index,
                            other_count,
                            &leaf(other_index, 0),
                            &path
                        ),
                        "путь листа {index} из {count} прошёл как путь {other_index} из \
                         {other_count}"
                    );
                }
            }
        }
    }
}

/// `root()` contains `unwrap_or([0u8; 32])`. That branch must be unreachable:
/// a zero root is a value an adversary can compute while possessing
/// nothing.
#[test]
fn the_degenerate_zero_root_is_unreachable() {
    for count in 1..=128u32 {
        let tree = MerkleTree::build(&leaves(count)).unwrap();
        assert_ne!(tree.root(), [0u8; 32], "нулевой корень при {count} листьях");
        assert!(tree.leaf_count() > 0);
    }
    // Пустой набор — единственный вход, который мог бы породить пустые уровни.
    assert!(MerkleTree::build(&[]).is_err());
}

/// Leaves and internal nodes must inhabit different domains, or an internal node
/// can masquerade as a leaf, replacing an n-leaf tree with a smaller one.
#[test]
fn a_node_hash_is_never_a_leaf_hash() {
    let a = leaf(0, 0);
    let b = leaf(1, 0);
    let parent = node_of(&a.0, &b.0);
    for index in 0..64u32 {
        for generation in 0..4u8 {
            assert_ne!(leaf(index, generation).0, parent);
        }
    }
}

// ---------------------------------------------------------------------------
// Часть I (продолжение). Транскрипт и секреты
// ---------------------------------------------------------------------------

/// Prefix-free labels ⇒ `label₁ ‖ X` never equals `label₂ ‖ Y` for
/// different labels. Ordinary tests check the labels themselves; this checks
/// the consequence motivating the requirement: HKDF `info` is assembled
/// by concatenation without delimiters.
#[test]
fn no_two_labels_can_be_made_equal_by_appending_anything() {
    // Метки берутся БАЙТАМИ: беспрефиксность — свойство строк, и тип `Label`
    // его не проверяет, он запрещает лишь строку вне реестра.
    for a in label::ALL.iter().map(|l| l.as_bytes()) {
        for b in label::ALL.iter().map(|l| l.as_bytes()) {
            if a == b {
                continue;
            }
            let (short, long) = if a.len() <= b.len() { (a, b) } else { (b, a) };
            assert!(
                !long.starts_with(short),
                "{:?} — префикс {:?}: info-строки столкнутся",
                core::str::from_utf8(short).unwrap_or("<не utf8>"),
                core::str::from_utf8(long).unwrap_or("<не utf8>")
            );
        }
    }
}

/// The delimiter after a label must not occur inside the label, or
/// "label ‖ 0x00 ‖ data" ceases to split unambiguously.
#[test]
fn no_label_contains_the_separator_byte() {
    for l in label::ALL.iter().map(|l| l.as_bytes()) {
        assert!(!l.contains(&0x00), "метка {l:?} содержит нулевой байт-разделитель");
    }
}

/// `field` must be injective: a variable-length field sequence must be uniquely
/// recoverable from bytes.
#[test]
fn field_is_injective_on_realistic_lengths() {
    let mut seen = BTreeMap::new();
    for first in 0..12usize {
        for second in 0..12usize {
            let mut t = Transcript::new(label::CONTENT_MAC);
            t.field(&vec![0xaa; first]).field(&vec![0xbb; second]);
            if let Some(previous) = seen.insert(t.as_bytes().to_vec(), (first, second)) {
                panic!("две разные пары полей дали одни байты: {previous:?} и {:?}", (first, second));
            }
        }
    }
}

/// All secret types must wipe on destruction, including clones.
#[test]
fn every_secret_type_is_zeroize_on_drop() {
    fn assert_zod<T: ZeroizeOnDrop>() {}
    assert_zod::<Cek>();
    assert_zod::<Kek>();
    assert_zod::<SecretA>();
    assert_zod::<SecretB>();
    assert_zod::<PayloadKey>();
    assert_zod::<MacKey>();
    assert_zod::<ClaimSecret>();
    assert_zod::<X25519Secret>();

    // Клон обязан быть независимым буфером: иначе затирание одного оставило бы
    // второй живым, а `Drop` второго затёр бы уже чужую память.
    let original = Cek::from_bytes([0x5a; 32]);
    let clone = original.clone();
    assert_eq!(original.expose(), clone.expose());
    assert_ne!(
        original.expose().as_ptr(),
        clone.expose().as_ptr(),
        "клон разделяет буфер с оригиналом"
    );
}

// ---------------------------------------------------------------------------
// Часть II. Заведены как воспроизведение дефектов; ПОЧИНЕНО, теперь регрессия.
// ---------------------------------------------------------------------------

/// BUG (fixed): the tree-hash identifier parsed and entered the author-signed
/// header, but was never applied.
///
/// `merkle::leaf_of` and `merkle::node_of` hardcode BLAKE3 and accept
/// no `TreeHashAlg` argument or other input (see signatures), while
/// `TreeHashAlg::from_u8(2)` returned `Ok(Sha256)`. The build thus CLAIMED
/// SHA-256 tree support while silently computing BLAKE3, the same defect class
/// that produced `alg: none` in JWS.
///
/// Fixed by a second boundary, `merkle::ensure_supported`, called
/// directly from `from_u8`. The former AEAD comparison here ("AEAD has a second
/// boundary, the tree does not") no longer describes the code: AEAD's boundary then
/// lived in `seal_with`/`open_with`, firing only at the first chunk;
/// item D-9 moved it into `AeadAlg::from_u8`. Both identifiers are now
/// checked identically, at the same point: parsing.
///
/// The test asserts what must hold: a build unable to compute a SHA-256
/// tree must reject this identifier rather than accept it.
#[test]
fn probe_bug_a_tree_hash_identifier_this_build_cannot_honour_is_accepted() {
    // Лист считается ровно как BLAKE3, независимо ни от чего. Прообраз собран
    // здесь ВРУЧНУЮ, а не через `leaf_of`: смысл проверки в том, что она не
    // повторяет продукт, а воспроизводит формулу §6.3 независимо. Поэтому при
    // смене прообраза этот блок обязан править человек — и обязан сверить его со
    // спекой, а не с кодом.
    const CT: [u8; 33] = [0x03; 33];
    let blake3_leaf = {
        let mut h = blake3::Hasher::new();
        h.update(&[0x00]);
        h.update(label::LEAF.as_bytes());
        h.update(&7u32.to_be_bytes());
        h.update(&(CT.len() as u64).to_be_bytes());
        h.update(&[0x01; 24]);
        h.update(&[0x02; 16]);
        h.update(&CT);
        *h.finalize().as_bytes()
    };
    assert_eq!(
        leaf_of(7, &[0x01; 24], &[0x02; 16], &CT).0,
        blake3_leaf,
        "дерево считается BLAKE3 безусловно"
    );

    // И при этом идентификатор SHA-256 принимается как поддерживаемый.
    assert_eq!(
        TreeHashAlg::from_u8(2).ok(),
        None,
        "сборка принимает tree_hash_id=2 (SHA-256), хотя дерево умеет считать только BLAKE3: \
         заявленный в подписанном заголовке алгоритм не управляет ничем"
    );
}
