// SPDX-License-Identifier: MPL-2.0
//! Streaming payload encryption shared by native and WASM hosts.
//!
//! Source and sink are closures; randomness is supplied by the caller. Empty
//! input produces one authenticated, zero-length chunk. Nonces use hedging, and
//! Merkle leaves bind each chunk's index, nonce, tag, and ciphertext in stream order.
//! Keeping this loop shared preserves the same bytes across host adapters.

use crate::aead::{NONCE_LEN, TAG_LEN, seal_chunk_hedged};
use crate::merkle::{Leaf, MerkleTree};
use crate::secret::{PayloadKey, SecretBuf};
use crate::{AeadAlg, CryptoError};
use zeroize::Zeroizing;

/// Result of processing a stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sealed {
    pub total_len: u64,
    pub chunk_count: u32,
    pub tree_root: [u8; 32],
}

/// Stream failure: ours or the host's.
///
/// Host errors deliberately remain distinct from ours: one host has
/// `std::io::Error`, another JavaScript exceptions; normalizing them
/// here would discard the cause exactly where it is needed.
#[derive(Debug)]
pub enum StreamError<E> {
    /// Cryptography: key, algorithm, buffer capacity.
    Crypto(CryptoError),
    /// Host source or sink.
    Host(E),
    /// File exceeds the format's addressable size.
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

/// Encrypt a stream in chunks and deliver frames to the sink.
///
/// `source` fills the buffer and returns the number of bytes written; zero means
/// end of input. Filling the buffer completely is NOT its responsibility; this loop
/// does that, or a short read in mid-file would split a chunk at the wrong
/// boundary and each host would fix it differently.
///
/// `sink` receives ready-made frame bytes: first `nonce`, then `tag ‖ ct`.
///
/// # Errors
/// [`StreamError`]: crypto failure, host failure, or an unaddressably large file.
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
    // Zero capacity skips the source and would seal a nonempty file as empty.
    if capacity == 0 {
        return Err(CryptoError::BadLength.into());
    }
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

/// Read until the buffer is full or input ends.
///
/// Short reads are normal for pipes and network sources; they do NOT
/// mean end-of-input. Treating them as the end would split chunks at the wrong
/// boundary, producing different files from pipe input and disk
/// input. Only a zero-byte read means end of input.
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

    /// Probe RNG: deterministic because this tests chunking
    /// DISCIPLINE, not randomness. With a random RNG, two
    /// runs could not be compared.
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

    /// Process input in pieces no larger than `step` bytes.
    ///
    /// `step` models short reads: a pipe returns what
    /// it currently has, not what was requested.
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

    /// EMPTY INPUT HAS ONE CHUNK, NOT ZERO.
    ///
    /// Otherwise the file would have no authentication tag and no tree
    /// leaf, forcing the parser to introduce a special case, a place
    /// where the forgery "file without chunks" would look legitimate.
    #[test]
    fn an_empty_input_still_gets_exactly_one_chunk() {
        let (sealed, _) = run(&[], 64, 64);
        assert_eq!(sealed.chunk_count, 1, "у пустого входа не один чанк");
        assert_eq!(sealed.total_len, 0);
    }

    /// SHORT READS CHANGE NO BYTES.
    ///
    /// This module's main property and the reason the loop must exist
    /// only once. Pipes return bytes, disks return whole chunks; if a host split by
    /// how much it received at a time, the same document supplied in
    /// two ways would yield DIFFERENT containers. Almost impossible to notice in a live
    /// file: both open.
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

    /// CHUNK COUNT DEPENDS ON SIZE, NOT LUCK.
    ///
    /// The "input exactly one chunk long" boundary is checked separately: it is easy
    /// to create an extra empty chunk there or lose the last one.
    #[test]
    fn the_chunk_count_follows_the_size_including_the_edges() {
        for (len, expected) in [(0usize, 1u32), (1, 1), (63, 1), (64, 1), (65, 2), (128, 2), (129, 3)] {
            let input = vec![0xa5u8; len];
            let (sealed, _) = run(&input, 64, usize::MAX);
            assert_eq!(sealed.chunk_count, expected, "длина {len}");
            assert_eq!(sealed.total_len, len as u64, "длина {len}");
        }
    }

    /// HOST ERRORS REACH THE CALLER WITH THEIR ORIGINAL TYPE.
    ///
    /// Not collapsed into our error: one host has `std::io::Error`, another
    /// JavaScript exceptions, and the original cause must be preserved.
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
