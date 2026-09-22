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
//! Направление 7: примитивы, дерево целостности и подписи.
//!
//! Файл сознательно делится на две части.
//!
//! Часть I — попытки СЛОМАТЬ дерево: сверка формы с эталонной реализацией
//! RFC 6962, согласованность четырёх мест, где записано правило продвижения,
//! поиск двух наборов листьев с одним корнем (класс CVE-2012-2459) и перенос
//! доказательства на другой индекс или другую длину.
//!
//! Часть II — тесты с префиксом `probe_bug_`: заведены как воспроизведение
//! найденных дефектов и падали на тогдашнем коде. Дефект исправлен, тест
//! работает как регрессионный. Описание набора обновлено вместе с кодом —
//! шапка, пережившая исправление, вводит в заблуждение о состоянии сборки
//! ровно так же, как комментарий, переживший смену конструкции.

use std::collections::BTreeMap;

use oc_crypto::merkle::{Leaf, MerkleTree, leaf_of, node_of, root_of};
use oc_crypto::secret::{Cek, ClaimSecret, Kek, MacKey, PayloadKey, SecretA, SecretB, X25519Secret};
use oc_crypto::{TreeHashAlg, Transcript, label};
use zeroize::ZeroizeOnDrop;

// ---------------------------------------------------------------------------
// Инструментарий
// ---------------------------------------------------------------------------

/// Лист, детерминированно выведенный из индекса и «поколения».
///
/// Поколение нужно, чтобы получить второй набор листьев с теми же индексами:
/// без него нельзя проверить, что корень зависит от содержимого, а не только от
/// числа листьев.
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

/// Эталон RFC 6962 §2.1, дословно:
/// `MTH(D[n]) = HASH(0x01 ‖ MTH(D[0:k]) ‖ MTH(D[k:n]))`, где `k` — наибольшая
/// степень двойки, **строго меньшая** `n`. Реализация рекурсивная и намеренно
/// не похожа на проверяемую: совпадение двух независимых записей одного правила
/// — это и есть доказательство, что правило записано верно.
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

/// Эталон RFC 6962 даёт ВЕРШИНУ (MTH), а наружу дерево отдаёт корень —
/// вершину, связанную с числом листьев. Проба сравнивает форму, поэтому обязана
/// сравнивать сопоставимое: эталонная вершина оборачивается тем же root_of,
/// что и настоящая. Сравнивать вершину с корнем напрямую значило бы объявить
/// расхождением ровно то исправление, ради которого связка и заведена.
fn rfc6962_reference_root(set: &[Leaf]) -> [u8; 32] {
    let count = u32::try_from(set.len()).expect("набор не влезает в u32");
    root_of(count, &rfc6962_root(set))
}

/// Форма пути от листа до корня: на каких уровнях узел продвигается.
/// Второе независимое место, где записано правило, — специально, чтобы поймать
/// расхождение между `is_promoted` и остальным кодом.
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

/// §6.3: «Нечётный узел продвигается, как в RFC 6962».
///
/// Проверяется не комментарий, а байты: корень `MerkleTree::build` обязан
/// совпасть с корнем эталонной рекурсии на каждом числе листьев. Расхождение
/// проявилось бы только при определённом `n`, то есть у заказчика.
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

/// Четыре места, где живёт правило продвижения: построение, обновление, сбор
/// доказательства и его проверка. Разойдись они хоть на одном уровне —
/// доказательства перестали бы проверяться при определённом числе чанков.
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

/// CVE-2012-2459: две разные последовательности листьев с одним корнем.
///
/// Перебор ИСЧЕРПЫВАЮЩИЙ по алфавиту из трёх листьев и длинам 1…6 — это 1092
/// последовательности, включая все хвостовые дубликаты, все перестановки и все
/// повторы, ради которых уязвимость и существует.
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

/// Перенос доказательства на другой индекс или другую длину.
///
/// Лист считается через `leaf_of`, то есть так, как его считает читатель:
/// номер чанка входит в хеш листа. Поэтому «доказательство листа i, выданное за
/// доказательство листа j» означает проверку с листом, посчитанным для j.
///
/// Единственное исключение — то, что признано в самом коде: при `j == i` и
/// совпавшей форме пути деревья неотличимы, потому что различающей информации во
/// входных данных нет. Настоящую границу задаёт `chunk_count` под MAC.
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

/// `root()` содержит `unwrap_or([0u8; 32])`. Ветка обязана быть недостижимой:
/// нулевой корень — это значение, которое противник может вычислить, не имея
/// ничего.
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

/// Лист и внутренний узел обязаны лежать в разных доменах, иначе внутренний узел
/// выдаётся за лист и дерево из n листьев подменяется деревом из меньшего числа.
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

/// Набор меток беспрефиксный ⇒ `label₁ ‖ X` никогда не равно `label₂ ‖ Y` при
/// разных метках. Штатный тест проверяет только сами метки; здесь проверяется
/// следствие, ради которого требование и введено: HKDF `info` собирается
/// конкатенацией без разделителя.
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

/// Разделитель после метки обязан быть недостижим изнутри самой метки: иначе
/// «метка ‖ 0x00 ‖ данные» перестаёт однозначно разделяться.
#[test]
fn no_label_contains_the_separator_byte() {
    for l in label::ALL.iter().map(|l| l.as_bytes()) {
        assert!(!l.contains(&0x00), "метка {l:?} содержит нулевой байт-разделитель");
    }
}

/// `field` обязан быть инъективным: последовательность полей переменной длины
/// восстанавливается из байтов однозначно.
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

/// Все типы секретов обязаны затираться при уничтожении, включая клоны.
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

/// ДЕФЕКТ (исправлен): идентификатор хеша дерева разбирался, входил в
/// подписанный автором заголовок — и нигде не применялся.
///
/// `merkle::leaf_of` и `merkle::node_of` жёстко зашивают BLAKE3 и не принимают
/// `TreeHashAlg` ни аргументом, ни как-либо ещё (см. их сигнатуры), а
/// `TreeHashAlg::from_u8(2)` отвечал `Ok(Sha256)`. То есть сборка ЗАЯВЛЯЛА
/// поддержку SHA-256 для дерева и молча считала BLAKE3 — тот же класс дефекта,
/// из-за которого в JWS появилось `alg: none`.
///
/// Исправлено вторым рубежом `merkle::ensure_supported`, который вызывается
/// прямо из `from_u8`. Сравнение с AEAD, стоявшее здесь раньше («у AEAD второй
/// рубеж есть, а у дерева нет»), больше не описывает код: у AEAD рубеж тогда
/// стоял в `seal_with`/`open_with`, то есть срабатывал лишь на первом чанке, и
/// пункт Д-9 поднял его в `AeadAlg::from_u8`. Теперь оба идентификатора
/// проверяются одинаково и в одном месте — на разборе.
///
/// Тест утверждает то, что обязано быть верно: сборка, не умеющая считать дерево
/// на SHA-256, обязана отвергать этот идентификатор, а не принимать его.
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
