//! Дисциплина нарезки полезной нагрузки на чанки.
//!
//! # Почему это здесь, а не там, где ввод-вывод
//!
//! До 2026-09-09 цикл жил в `cc_cli::payload::seal_stream`, и это было верно,
//! пока хост был один. Хостов становится два: тот же цикл нужен обёртке для
//! чужих языков, которая собирается под `wasm32` и до `cc-cli` не дотягивается
//! — тот крейт под wasm не собирается вовсе.
//!
//! Переписать цикл во втором месте нельзя, и дело не в экономии строк. То, что
//! он делает, — КРИПТОГРАФИЧЕСКИЙ КОНТРАКТ, а не работа с файлами:
//!
//! * пустой вход даёт ОДИН чанк нулевой длины, а не ноль чанков — иначе у файла
//!   не было бы ни одного тега подлинности и ни одного листа дерева;
//! * nonce каждого чанка выводится ХЕДЖИРОВАНИЕМ из засева и открытого текста
//!   (И-1, решение С-13), а не берётся из генератора;
//! * лист дерева считается из `nonce ‖ tag ‖ ct`, и порядок листьев — порядок
//!   чанков.
//!
//! Разойдись две реализации хоть в одном из трёх — и файлы, собранные разными
//! хостами, перестали бы открываться друг у друга, а заметить это было бы
//! нечем: обе прошли бы свои тесты.
//!
//! # Чем это остаётся чистым
//!
//! Ни файлов, ни часов, ни собственного генератора. Источник и приёмник
//! приходят замыканиями, генератор — параметром. `std::io` здесь не упомянут:
//! адаптер над `Read`/`Write` живёт у того хоста, у которого они есть.

use crate::aead::{NONCE_LEN, TAG_LEN, seal_chunk_hedged};
use crate::merkle::{Leaf, MerkleTree};
use crate::secret::{PayloadKey, SecretBuf};
use crate::{AeadAlg, CryptoError};
use zeroize::Zeroizing;

/// Что вышло из прогона потока.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sealed {
    pub total_len: u64,
    pub chunk_count: u32,
    pub tree_root: [u8; 32],
}

/// Отказ прогона: наш или хозяйский.
///
/// Хозяйские ошибки не сводятся к нашим намеренно: у одного хоста это
/// `std::io::Error`, у другого — исключение JavaScript, и приводить их к общему
/// виду здесь значило бы терять причину ровно там, где она нужна.
#[derive(Debug)]
pub enum StreamError<E> {
    /// Крипта: ключ, алгоритм, ёмкость буфера.
    Crypto(CryptoError),
    /// Источник или приёмник хоста.
    Host(E),
    /// Файл больше, чем адресуемо форматом.
    TooLarge,
}

impl<E> From<CryptoError> for StreamError<E> {
    fn from(err: CryptoError) -> Self {
        Self::Crypto(err)
    }
}

impl<E: core::fmt::Display> core::fmt::Display for StreamError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Crypto(err) => write!(f, "{err}"),
            Self::Host(err) => write!(f, "{err}"),
            Self::TooLarge => f.write_str("файл больше, чем адресуемо форматом"),
        }
    }
}

impl<E: core::fmt::Debug + core::fmt::Display> core::error::Error for StreamError<E> {}

/// Зашифровать поток чанками и отдать кадры приёмнику.
///
/// `source` заполняет буфер и возвращает, сколько байт положил; ноль означает
/// конец входа. Дочитывать до полного буфера НЕ его забота — это делает цикл
/// здесь: короткое чтение посреди файла иначе резало бы чанк не там, где
/// договорено, и каждый хост чинил бы это у себя по-своему.
///
/// `sink` получает готовые байты кадра: сперва `nonce`, затем `tag ‖ ct`.
///
/// # Errors
/// [`StreamError`]: отказ крипты, отказ хоста или файл длиннее адресуемого.
pub fn seal_chunks<G, E>(
    key: &PayloadKey,
    alg: AeadAlg,
    file_id: &[u8; 16],
    chunk_size: u32,
    rng: &mut G,
    mut source: impl FnMut(&mut [u8]) -> Result<usize, E>,
    mut sink: impl FnMut(&[u8]) -> Result<(), E>,
) -> Result<Sealed, StreamError<E>>
where
    G: rand_core::CryptoRng + ?Sized,
{
    let capacity = usize::try_from(chunk_size).map_err(|_| StreamError::TooLarge)?;
    // Затирающий буфер фиксированной ёмкости: обычный вектор уносил бы каждый
    // прочитанный кусок исходного файла в кучу — и при уничтожении, и при росте
    // (И-11).
    let mut plaintext = SecretBuf::with_capacity(capacity);
    let mut framed = Vec::with_capacity(capacity.saturating_add(TAG_LEN));
    let mut leaves: Vec<Leaf> = Vec::new();
    let mut total_len = 0u64;
    let mut index = 0u32;

    loop {
        let filled = fill(&mut source, plaintext.as_capacity_mut())?;
        plaintext.declare_len(filled)?;
        // Выходим только когда предыдущий чанк был полным: иначе пустой файл не
        // получил бы ни одного чанка.
        if filled == 0 && index > 0 {
            break;
        }

        let piece = plaintext.as_slice();
        // Nonce через засев, а не прямо из генератора (решение С-13, доведённое
        // до всех четырёх nonce сборки пунктом Р-2). Генератор повторяется при
        // откате снапшота ВМ, клоне образа и восстановлении из копии; повторись
        // он здесь — повторился бы и ключ полезной нагрузки, потому что `CEK` с
        // `header_salt` берутся из того же генератора, и два разных документа
        // получили бы один поток ключей. Открытый текст в засеве это разводит.
        let mut nonce_seed = Zeroizing::new([0u8; NONCE_LEN]);
        rand_core::Rng::fill_bytes(rng, nonce_seed.as_mut_slice());
        let (nonce, leaf) =
            seal_chunk_hedged(key, alg, file_id, index, &nonce_seed, piece, &mut framed)?;

        sink(&nonce).map_err(StreamError::Host)?;
        sink(&framed).map_err(StreamError::Host)?;

        leaves.push(leaf);
        total_len =
            total_len.checked_add(filled as u64).ok_or(StreamError::TooLarge)?;
        index = index.checked_add(1).ok_or(StreamError::TooLarge)?;

        if filled < capacity {
            break;
        }
    }

    let tree = MerkleTree::build(&leaves)?;
    Ok(Sealed { total_len, chunk_count: index, tree_root: tree.root() })
}

/// Дочитать буфер до конца или до конца входа.
///
/// Короткое чтение — обычное дело у труб и сетевых источников, и оно НЕ
/// означает конца: приняв его за конец, мы нарезали бы чанк не там, где
/// договорено, и файл, собранный через трубу, отличался бы от собранного с
/// диска. Конец входа — только нулевое чтение.
fn fill<E>(
    source: &mut impl FnMut(&mut [u8]) -> Result<usize, E>,
    buf: &mut [u8],
) -> Result<usize, StreamError<E>> {
    let mut filled = 0usize;
    while filled < buf.len() {
        let Some(rest) = buf.get_mut(filled..) else {
            break;
        };
        let got = source(rest).map_err(StreamError::Host)?;
        if got == 0 {
            break;
        }
        filled = filled.saturating_add(got);
    }
    Ok(filled)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// Генератор проб: детерминированный, потому что здесь проверяется
    /// ДИСЦИПЛИНА нарезки, а не случайность. Со случайным генератором два
    /// прогона нельзя было бы сравнить между собой.
    struct Fixed(u8);

    impl rand_core::TryRng for Fixed {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(u32::from(self.0))
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(u64::from(self.0))
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            dst.fill(self.0);
            Ok(())
        }
    }
    impl rand_core::TryCryptoRng for Fixed {}

    fn key() -> PayloadKey {
        PayloadKey::from_bytes([7u8; 32])
    }

    /// Прогнать вход, отдавая его кусками не больше `step` байт.
    ///
    /// `step` — это и есть модель короткого чтения: труба отдаёт столько,
    /// сколько у неё есть сейчас, а не столько, сколько попросили.
    fn run(input: &[u8], chunk_size: u32, step: usize) -> (Sealed, Vec<u8>) {
        let mut left = input;
        let mut out = Vec::new();
        let sealed = seal_chunks(
            &key(),
            AeadAlg::XChaCha20Poly1305,
            &[1u8; 16],
            chunk_size,
            &mut Fixed(0x5a),
            |buf| -> Result<usize, core::convert::Infallible> {
                let take = left.len().min(buf.len()).min(step);
                buf.get_mut(..take).unwrap_or_default().copy_from_slice(&left[..take]);
                left = &left[take..];
                Ok(take)
            },
            |bytes| -> Result<(), core::convert::Infallible> {
                out.extend_from_slice(bytes);
                Ok(())
            },
        )
        .expect("прогон не удался");
        (sealed, out)
    }

    /// У ПУСТОГО ВХОДА ОДИН ЧАНК, А НЕ НОЛЬ.
    ///
    /// Иначе у файла не было бы ни одного тега подлинности и ни одного листа
    /// дерева, и разбору пришлось бы заводить особый случай — то есть место,
    /// где подделка «файл без чанков» выглядела бы законно.
    #[test]
    fn an_empty_input_still_gets_exactly_one_chunk() {
        let (sealed, _) = run(&[], 64, 64);
        assert_eq!(sealed.chunk_count, 1, "у пустого входа не один чанк");
        assert_eq!(sealed.total_len, 0);
    }

    /// КОРОТКОЕ ЧТЕНИЕ НЕ МЕНЯЕТ НИ ОДНОГО БАЙТА.
    ///
    /// Главное свойство этого модуля и причина, по которой цикл обязан быть
    /// один. Труба отдаёт по байту, диск — целыми чанками; нарежь хост файл по
    /// тому, сколько ему дали за раз, — и один и тот же документ, поданный
    /// двумя способами, дал бы РАЗНЫЕ контейнеры. Заметить это на живом файле
    /// почти невозможно: оба открываются.
    #[test]
    fn a_short_read_changes_nothing() {
        let input: Vec<u8> = (0..300u32).map(|i| u8::try_from(i % 251).unwrap_or(0)).collect();
        let (whole, bytes_whole) = run(&input, 64, usize::MAX);
        for step in [1usize, 7, 63, 64, 65, 128] {
            let (piecemeal, bytes_piecemeal) = run(&input, 64, step);
            assert_eq!(piecemeal, whole, "шаг {step}: нарезка разошлась");
            assert_eq!(bytes_piecemeal, bytes_whole, "шаг {step}: байты разошлись");
        }
    }

    /// ЧИСЛО ЧАНКОВ СЧИТАЕТСЯ ПО РАЗМЕРУ, А НЕ ПО УДАЧЕ.
    ///
    /// Отдельно проверяется граница «вход ровно в размер чанка»: там легко
    /// получить лишний пустой чанк или, наоборот, потерять последний.
    #[test]
    fn the_chunk_count_follows_the_size_including_the_edges() {
        for (len, expected) in [(0usize, 1u32), (1, 1), (63, 1), (64, 1), (65, 2), (128, 2), (129, 3)] {
            let input = vec![0xa5u8; len];
            let (sealed, _) = run(&input, 64, usize::MAX);
            assert_eq!(sealed.chunk_count, expected, "длина {len}");
            assert_eq!(sealed.total_len, len as u64, "длина {len}");
        }
    }

    /// ОТКАЗ ХОСТА ДОХОДИТ ДО ВЫЗЫВАЮЩЕГО СВОИМ ТИПОМ.
    ///
    /// Не сводится к нашей ошибке: у одного хоста это `std::io::Error`, у
    /// другого — исключение JavaScript, и причина нужна ровно та, что была.
    #[test]
    fn a_host_failure_arrives_as_itself() {
        let err = seal_chunks(
            &key(),
            AeadAlg::XChaCha20Poly1305,
            &[1u8; 16],
            64,
            &mut Fixed(1),
            |_buf| Err("источник отвалился"),
            |_bytes| Ok(()),
        )
        .expect_err("отказ источника не заметили");
        match err {
            StreamError::Host(said) => assert_eq!(said, "источник отвалился"),
            other => panic!("отказ хоста подменён нашим: {other:?}"),
        }
    }
}
