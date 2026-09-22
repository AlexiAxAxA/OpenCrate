// Файл-проба состязательной проверки. Запреты рабочего кода к пробам не
// применяются — проба вправе делать то, чего продукт делать не должен.
//
// ИСТОРИЯ. Тесты с префиксом `probe_bug_` заводились КРАСНЫМИ: падение и было
// доказательством находки. Обе находки этого файла с тех пор починены, и тесты
// стали регрессионными — зелёными. Шапка обновлена вместе с ними: описание
// набора, пережившее исправление кода, врёт ровно так же, как комментарий,
// переживший смену конструкции, и стоит дороже, потому что по нему судят о
// состоянии сборки не открывая тестов.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]
//! Направление 7, второй заход: `SecretBuf`, форма дерева при повторных правках,
//! связывание пары «индекс + число листьев» и малleability подписи.
//!
//! Часть I — свойства, которые обязаны выполняться.
//! Часть II — тесты с префиксом `probe_bug_`: заведены как воспроизведение
//! найденных дефектов, после исправления кода работают как регрессионные.

use oc_crypto::merkle::{Leaf, MerkleTree, leaf_of};
use oc_crypto::secret::SecretBuf;
use oc_crypto::sign::{Ed25519Signer, Signer, verify};
use oc_crypto::{CryptoError, Transcript, label};

// ---------------------------------------------------------------------------
// Инструментарий
// ---------------------------------------------------------------------------

fn leaf(index: u32, generation: u8) -> Leaf {
    let seed = *blake3::hash(&[&index.to_be_bytes()[..], &[generation]].concat()).as_bytes();
    let mut nonce = [0u8; 24];
    let mut tag = [0u8; 16];
    nonce.copy_from_slice(&seed[..24]);
    tag.copy_from_slice(&seed[16..32]);
    // Шифротекст входит в лист, поэтому у синтетических листьев он тоже есть:
    // иначе пробы проверяли бы прообраз, которого продукт не производит.
    leaf_of(index, &nonce, &tag, &seed)
}

fn leaves(count: u32) -> Vec<Leaf> {
    (0..count).map(|i| leaf(i, 0)).collect()
}

/// Детерминированный генератор: проба обязана воспроизводиться байт в байт.
struct TestRng(u64);
impl TestRng {
    fn step(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
}
impl rand_core::TryRng for TestRng {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.step() as u32)
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.step())
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in dst.chunks_mut(8) {
            let word = self.step().to_le_bytes();
            for (out, src) in chunk.iter_mut().zip(word.iter()) {
                *out = *src;
            }
        }
        Ok(())
    }
}
impl rand_core::TryCryptoRng for TestRng {}

// ---------------------------------------------------------------------------
// Часть I. SecretBuf
// ---------------------------------------------------------------------------

/// Ёмкость объявлена неизменной («задаётся один раз и не меняется»). Затирание
/// не имеет права её сдвинуть: иначе `declare_len` начинает пропускать длины,
/// которых буфер не обещал, и контракт с вызывающим расходится с реальностью.
#[test]
fn capacity_survives_wipe_at_every_size() {
    for size in [0usize, 1, 7, 31, 32, 100, 4096, 65536] {
        let mut buf = SecretBuf::with_capacity(size);
        assert_eq!(buf.capacity(), size, "ёмкость сразу после создания");
        assert_eq!(buf.as_capacity_mut().len(), size, "окно записи короче ёмкости");
        buf.wipe();
        assert_eq!(buf.capacity(), size, "ёмкость изменилась после wipe при size={size}");
        assert_eq!(buf.len(), 0);
        buf.wipe();
        assert_eq!(buf.capacity(), size, "ёмкость поехала на втором wipe при size={size}");
    }
}

/// Обещание типа: `wipe` затирает ВЕСЬ буфер, включая незначимый хвост.
#[test]
fn wipe_clears_the_whole_buffer_including_the_insignificant_tail() {
    let mut buf = SecretBuf::with_capacity(256);
    buf.as_capacity_mut().fill(0xaa);
    buf.declare_len(256).unwrap();
    assert!(buf.as_slice().iter().all(|b| *b == 0xaa));

    buf.wipe();
    assert_eq!(buf.len(), 0);
    // Объявляем полную длину заново: если хвост не затёрт, он тут же выйдет наружу.
    buf.declare_len(256).unwrap();
    assert!(
        buf.as_slice().iter().all(|b| *b == 0),
        "после wipe в буфере остались незанулённые байты"
    );
}

/// Короткая запись поверх длинной обязана уносить хвост с собой — ради этого тип
/// и существует.
#[test]
fn fill_from_erases_the_tail_of_a_longer_previous_write() {
    let mut buf = SecretBuf::with_capacity(128);
    buf.fill_from(&[0xaa; 128]).unwrap();
    buf.fill_from(&[0xbb; 8]).unwrap();
    assert_eq!(buf.len(), 8);
    assert_eq!(buf.as_slice(), &[0xbb; 8]);

    buf.declare_len(128).unwrap();
    assert!(
        buf.as_slice()[8..].iter().all(|b| *b == 0),
        "хвост предыдущей более длинной записи пережил короткую"
    );
}

/// Границы `fill_from`: ровно ёмкость — можно, на байт больше — отказ, и буфер
/// после отказа не содержит ни старого, ни нового.
#[test]
fn fill_from_respects_the_capacity_boundary_exactly() {
    let mut buf = SecretBuf::with_capacity(16);
    assert_eq!(buf.fill_from(&[0x11; 16]), Ok(()));
    assert_eq!(buf.len(), 16);

    assert_eq!(
        buf.fill_from(&[0x22; 17]),
        Err(CryptoError::BadLength),
        "запись длиннее ёмкости обязана отвергаться, а не растить буфер"
    );
    assert_eq!(buf.capacity(), 16, "отказавшая запись вырастила буфер");
    assert_eq!(buf.len(), 0, "после отказа длина обязана быть нулевой");
    buf.declare_len(16).unwrap();
    assert!(
        buf.as_slice().iter().all(|b| *b == 0),
        "отказавший fill_from оставил в буфере прежний открытый текст"
    );
}

/// `declare_len` не имеет права объявить больше ёмкости: иначе `as_slice`
/// смотрел бы за границу выделенной памяти или молча укорачивался.
#[test]
fn declare_len_refuses_anything_beyond_capacity() {
    let mut buf = SecretBuf::with_capacity(32);
    assert_eq!(buf.declare_len(32), Ok(()));
    assert_eq!(buf.as_slice().len(), 32);
    assert_eq!(buf.declare_len(33), Err(CryptoError::BadLength));
    assert_eq!(buf.declare_len(usize::MAX), Err(CryptoError::BadLength));
    assert_eq!(buf.len(), 32, "отказавший declare_len изменил длину");
}

/// Свежий буфер обязан отдавать нули, а не то, что лежало в куче до него.
#[test]
fn a_fresh_buffer_hands_out_zeroes_not_heap_residue() {
    for size in [1usize, 33, 4096] {
        let mut buf = SecretBuf::with_capacity(size);
        buf.declare_len(size).unwrap();
        assert!(buf.as_slice().iter().all(|b| *b == 0), "свежий буфер не занулён при size={size}");
    }
}

/// `Debug` не имеет права печатать содержимое.
#[test]
fn debug_of_secret_buf_never_leaks_the_plaintext() {
    let mut buf = SecretBuf::with_capacity(8);
    buf.fill_from(&[0xab; 8]).unwrap();
    let rendered = format!("{buf:?}");
    assert!(!rendered.contains("ab"), "Debug выдал байты: {rendered}");
    assert!(rendered.contains("скрыто"));
}

// ---------------------------------------------------------------------------
// Часть I. Дерево: повторные правки
// ---------------------------------------------------------------------------

/// Штатные тесты правят ОДИН лист свежепостроенного дерева. Реальное
/// редактирование правит один и тот же файл многократно, и накопленная ошибка
/// проявилась бы только на n-й правке.
#[test]
fn repeated_updates_still_equal_a_full_rebuild() {
    for count in 1..=40u32 {
        let mut set = leaves(count);
        let mut tree = MerkleTree::build(&set).unwrap();

        // Детерминированная последовательность правок, задевающая и последний
        // лист (он продвигается), и середину.
        for step in 0..(count * 2 + 3) {
            let index = (step.wrapping_mul(7).wrapping_add(step / 3)) % count;
            let generation = (step % 250) as u8 + 2;
            let replacement = leaf(index, generation);
            let new_root = tree.update_leaf(index, replacement).unwrap();
            set[index as usize] = replacement;

            let rebuilt = MerkleTree::build(&set).unwrap();
            assert_eq!(new_root, rebuilt.root(), "правка №{step} при {count} листьях: корень");
            assert_eq!(tree, rebuilt, "правка №{step} при {count} листьях: уровни");
            assert_eq!(tree.leaf_count(), count);

            // И доказательство КАЖДОГО листа обязано проверяться после правки:
            // расхождение в середине дерева иначе всплыло бы только на соседе.
            for probe in 0..count {
                let path = tree.proof(probe).unwrap();
                assert!(
                    MerkleTree::verify_proof(&new_root, probe, count, &set[probe as usize], &path),
                    "после правки №{step} лист {probe} из {count} перестал подтверждаться"
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Часть I. Подпись
// ---------------------------------------------------------------------------

/// Малleability по скаляру `S`: подпись `(R, S + L)` описывает то же уравнение,
/// что и `(R, S)`. Приняв её, формат получил бы вторую байтовую строку для того
/// же файла — а подпись заголовка здесь и есть идентичность файла.
#[test]
fn a_signature_malleated_by_adding_the_group_order_is_refused() {
    // L = 2^252 + 27742317777372353535851937790883648493, little-endian.
    const L: [u8; 32] = [
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde,
        0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
    ];

    let mut rng = TestRng(11);
    let signer = Ed25519Signer::generate(&mut rng);
    let mut t = Transcript::new(label::HEADER_SIG);
    t.field(b"canonical header bytes");
    let signature = signer.sign(&t).unwrap();
    assert_eq!(verify(&signer.public_key(), &t, &signature), Ok(()));

    let mut malleated = signature;
    let mut carry = 0u16;
    for i in 0..32 {
        let sum = u16::from(malleated[32 + i]) + u16::from(L[i]) + carry;
        malleated[32 + i] = sum as u8;
        carry = sum >> 8;
    }
    assert_ne!(malleated, signature, "подпись не изменилась — тест выродился");
    assert_eq!(
        verify(&signer.public_key(), &t, &malleated),
        Err(CryptoError::BadSignature),
        "принята вторая подпись того же сообщения: свойство «одна подпись — один файл» нарушено"
    );
}

/// Подпись обязана быть привязана к длине данных, а не только к их байтам.
#[test]
fn a_signature_over_a_length_prefixed_field_does_not_move_to_a_resplit() {
    let mut rng = TestRng(12);
    let signer = Ed25519Signer::generate(&mut rng);

    let mut a = Transcript::new(label::GRANT);
    a.field(b"ab").field(b"c");
    let mut b = Transcript::new(label::GRANT);
    b.field(b"a").field(b"bc");

    let signature = signer.sign(&a).unwrap();
    assert_eq!(verify(&signer.public_key(), &a, &signature), Ok(()));
    assert_eq!(verify(&signer.public_key(), &b, &signature), Err(CryptoError::BadSignature));
}

// ---------------------------------------------------------------------------
// Часть II. Заведены как воспроизведение дефектов; ПОЧИНЕНО, теперь регрессия.
// ---------------------------------------------------------------------------

/// ДЕФЕКТ (исправлен): `as_capacity_mut` отдавал окно записи, НЕ затирая буфер,
/// а `declare_len` затем вправе объявить любую длину до ёмкости. Открытый текст
/// предыдущей, более длинной записи выходил наружу через `as_slice`.
///
/// Обещание типа: «затирать нужно и „хвост“ за границей значимых данных, иначе
/// остатки предыдущего, более длинного чанка переживут запись более короткого».
/// На пути `fill_from` обещание выполнялось, на пути `as_capacity_mut` +
/// `declare_len` — нет. Именно этим путём пользуется
/// `cc-cli::payload::seal_stream`.
///
/// Исправлено затиранием в самом `as_capacity_mut`. Тест оставлен как
/// регрессионный: путь «длинная запись → короткая → снова длинная» короче любого
/// сценария, в котором дефект был бы замечен на настоящем файле.
#[test]
fn probe_bug_declare_len_hands_out_stale_plaintext_written_before_the_current_one() {
    let mut buf = SecretBuf::with_capacity(64);

    // Первая запись: «предыдущий длинный чанк».
    buf.as_capacity_mut().fill(0xaa);
    buf.declare_len(64).unwrap();

    // Вторая запись: «текущий короткий чанк». Пишем только начало, ровно как
    // делает read_full на последнем чанке файла.
    buf.as_capacity_mut()[..8].fill(0xbb);
    buf.declare_len(8).unwrap();
    assert_eq!(buf.as_slice(), &[0xbb; 8]);

    // А теперь длину объявляют заново — и буфер выдаёт чужой открытый текст.
    buf.declare_len(64).unwrap();
    assert!(
        buf.as_slice()[8..].iter().all(|b| *b == 0),
        "declare_len выдал {} байт открытого текста предыдущей записи",
        buf.as_slice()[8..].iter().filter(|b| **b == 0xaa).count()
    );
}

/// ДЕФЕКТ (исправлен): доказательство не связывало пару «индекс + число листьев».
///
/// Закрыто связкой корня с числом листьев (`root_of`). Тест оставлен
/// регрессионным: он перебирает деревья до 16 листьев и ищет вторую пару, под
/// которой проходит тот же путь, — то есть проверяет отсутствие коллизии, а не
/// один заранее известный случай.
///
/// Проверка ходит по форме пути, а форма у пары (i, n) может совпасть с формой
/// пары (j, m) при i ≠ j и n ≠ m. Тогда одни и те же байты листа и один и тот же
/// путь проходят под ДВУМЯ разными утверждениями о положении чанка в файле.
///
/// Штатная проба (`a_proof_does_not_move_to_another_index_or_another_leaf_count`)
/// это не ловит: она пересчитывает лист под другой индекс, а `leaf_of` номер
/// чанка в себя включает. Здесь лист берётся ТОТ ЖЕ — то есть проверяется
/// свойство самого `verify_proof`, а не свойство `leaf_of`.
#[test]
fn probe_bug_a_proof_verifies_under_a_second_pair_of_index_and_leaf_count() {
    let mut collisions: Vec<(u32, u32, u32, u32)> = Vec::new();

    for count in 1..=16u32 {
        let set = leaves(count);
        let tree = MerkleTree::build(&set).unwrap();
        let root = tree.root();
        for index in 0..count {
            let path = tree.proof(index).unwrap();
            let this = set[index as usize];
            for other_count in 1..=20u32 {
                for other_index in 0..other_count {
                    if (other_index, other_count) == (index, count) {
                        continue;
                    }
                    if MerkleTree::verify_proof(&root, other_index, other_count, &this, &path) {
                        collisions.push((index, count, other_index, other_count));
                    }
                }
            }
        }
    }

    assert!(
        collisions.is_empty(),
        "путь листа проходит и под вторым утверждением о положении; первые случаи: {:?}",
        &collisions[..collisions.len().min(12)]
    );
}
