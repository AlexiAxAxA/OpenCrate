//! Писатель правки: кадры, дерево, изменяемая область (`docs/format.md`,
//! «ПРАВКА ИСПОЛНИМА», п. G).
//!
//! Чистый, как весь движок: ни ввода-вывода, ни часов, ни генератора — засевы
//! nonce приходят параметром. Подпись ставит не он: ключ правки живёт в TPM, и
//! движку отдаётся только транскрипт на подпись и готовая подпись обратно.
//!
//! # Что писатель обязан и чего не вправе
//!
//! * Кадр, чей открытый текст не менялся, **переносится как есть**. Повтор
//!   тройки (nonce, шифротекст, тег) на том же индексе не повторяет nonce на
//!   ДРУГОМ тексте — это та же запись, а не новая.
//! * Изменившийся кадр запечатывается только `seal_chunk_hedged`: передать
//!   nonce в него нечем, а выведенный nonce зависит от текста (И-1).
//! * Перенесённый кадр обязан стоять на СВОЁМ индексе: AAD связывает индекс, и
//!   кадр, переставленный на чужое место, не откроется у читателя. Писатель
//!   индексов не сверяет — это обещание вызывающего, и нарушение его ловит
//!   читатель, а не пропускает.

use oc_crypto::aead::{NONCE_LEN, TAG_LEN, seal_chunk_hedged};
use oc_crypto::merkle::{Leaf, MerkleTree, leaf_of};
use oc_crypto::rsa::MODULUS_LEN;
use oc_crypto::secret::{MacKey, PayloadKey};
use oc_crypto::transcript::Transcript;
use oc_crypto::{AeadAlg, CryptoError};
use oc_format::FormatError;
use oc_format::content::{ContentDesc, JournalHead};
use oc_format::edit::{
    EditError, edition_digest, editor_transcript, next_counter, session_start, session_step, unsigned_editor,
};

/// Кусок новой редакции.
#[derive(Debug)]
pub enum Piece<'a> {
    /// Кадр старого файла с ЭТИМ ЖЕ индексом: `nonce ‖ ct ‖ tag`.
    Keep(&'a [u8]),
    /// Новый открытый текст и свежий засев nonce.
    Seal { plaintext: &'a [u8], seed: [u8; NONCE_LEN] },
}

/// Что нужно, чтобы собрать редакцию.
#[derive(Debug)]
pub struct EditPlan<'a> {
    pub file_id: [u8; 16],
    pub aead: AeadAlg,
    pub chunk_size: u32,
    pub container_version: u16,
    /// `core_hash` заголовка (§3.2): подпись привязывается к нему.
    pub core_hash: [u8; 32],
    /// Основа правки: её счётчик и корень.
    pub base_counter: u64,
    pub base_root: [u8; 32],
    pub certified_by: Vec<u8>,
    pub journal_head: Option<JournalHead>,
    pub pieces: Vec<Piece<'a>>,
}

/// Редакция без подписи: описание, транскрипт на подпись, сумма, кадры.
#[derive(Debug)]
pub struct Unsigned {
    pub desc: ContentDesc,
    pub transcript: Transcript,
    pub digest: [u8; 32],
    pub payload: Vec<u8>,
}

/// Отказ писателя правки.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditWriteError {
    Format(FormatError),
    Crypto(CryptoError),
    Edit(EditError),
    /// Перенесённый кадр короче nonce и тега.
    BadFrame { index: u32 },
    /// Куски не складываются в раскладку: не последний короче чанка, или
    /// длиннее, или кусков нет.
    BadLayout { index: u32 },
}

impl From<FormatError> for EditWriteError {
    fn from(err: FormatError) -> Self {
        Self::Format(err)
    }
}

impl From<CryptoError> for EditWriteError {
    fn from(err: CryptoError) -> Self {
        Self::Crypto(err)
    }
}

impl From<EditError> for EditWriteError {
    fn from(err: EditError) -> Self {
        Self::Edit(err)
    }
}

/// Собрать редакцию без подписи.
///
/// # Errors
/// [`EditWriteError`] — кадр, раскладка, крипта или счётчик.
pub fn prepare(key: &PayloadKey, plan: EditPlan<'_>) -> Result<Unsigned, EditWriteError> {
    let chunk = usize::try_from(plan.chunk_size).map_err(|_| FormatError::OffsetOverflow)?;
    let count = plan.pieces.len();
    if count == 0 {
        return Err(EditWriteError::BadLayout { index: 0 });
    }
    let mut leaves: Vec<Leaf> = Vec::with_capacity(count);
    let mut payload = Vec::new();
    let mut total_len = 0u64;
    let mut framed = Vec::with_capacity(chunk.saturating_add(TAG_LEN));
    for (position, piece) in plan.pieces.iter().enumerate() {
        let index = u32::try_from(position).map_err(|_| FormatError::OffsetOverflow)?;
        let last = position.saturating_add(1) == count;
        let len = match piece {
            Piece::Keep(frame) => {
                let (nonce, rest) =
                    frame.split_first_chunk::<NONCE_LEN>().ok_or(EditWriteError::BadFrame { index })?;
                let (ct, tag) = rest.split_last_chunk::<TAG_LEN>().ok_or(EditWriteError::BadFrame { index })?;
                leaves.push(leaf_of(index, nonce, tag, ct));
                payload.extend_from_slice(frame);
                ct.len()
            }
            Piece::Seal { plaintext, seed } => {
                let (nonce, leaf) =
                    seal_chunk_hedged(key, plan.aead, &plan.file_id, index, seed, plaintext, &mut framed)?;
                leaves.push(leaf);
                payload.extend_from_slice(&nonce);
                payload.extend_from_slice(&framed);
                plaintext.len()
            }
        };
        // Не последний — ровно чанк; последний — не длиннее чанка (и может
        // быть пустым только если он же единственный: это проверит раскладка).
        if (!last && len != chunk) || len > chunk {
            return Err(EditWriteError::BadLayout { index });
        }
        total_len = total_len.checked_add(len as u64).ok_or(FormatError::OffsetOverflow)?;
    }

    let root = MerkleTree::build(&leaves)?.root();
    let counter = next_counter(plan.base_counter)?;
    let head = session_step(
        &session_start(&plan.file_id, plan.base_counter, &plan.base_root),
        1,
        &root,
        total_len,
    );
    let desc = ContentDesc {
        total_len,
        chunk_count: u32::try_from(count).map_err(|_| FormatError::OffsetOverflow)?,
        tree_root: root,
        version_counter: counter,
        footer_offset: None,
        editor: Some(unsigned_editor(head, plan.journal_head, plan.certified_by)),
    };
    desc.check_against_chunk_size(plan.chunk_size)?;
    let body = desc.body_bytes(plan.container_version)?;
    let transcript = editor_transcript(&plan.core_hash, &body)?;
    let digest = edition_digest(&transcript);
    Ok(Unsigned { desc, transcript, digest, payload })
}

/// Вложить подпись и заверить изменяемую область.
///
/// Возвращает `(область, кадры)`: область — `ContentDescLen ‖ тело ‖ MAC`.
///
/// # Errors
/// [`EditWriteError`] — кодирование не удалось.
pub fn finish(
    unsigned: Unsigned,
    signature: &[u8; MODULUS_LEN],
    mac_key: &MacKey,
    file_id: &[u8; 16],
    container_version: u16,
) -> Result<(ContentDesc, Vec<u8>, Vec<u8>), EditWriteError> {
    let mut desc = unsigned.desc;
    if let Some(editor) = desc.editor.as_mut() {
        editor.signature = signature.to_vec();
    }
    let area = desc.encode(mac_key, file_id, container_version)?;
    Ok((desc, area, unsigned.payload))
}
