// SPDX-License-Identifier: MPL-2.0
//! Edit writer: frames, tree, mutable region (`docs/format.md`,
//! "EDITING IS EXECUTABLE", item G).
//!
//! Pure like the entire engine: no I/O, clocks, or RNG; nonce seeds
//! are parameters. It does not sign: the editing key resides in a TPM,
//! and only a signing transcript and the completed return signature are exchanged with the engine.
//!
//! # What the writer must do and must not do
//!
//! * A frame whose plaintext is unchanged **is copied unchanged**. Repeating
//!   (nonce, ciphertext, tag) at the same index does not reuse a nonce for
//!   DIFFERENT plaintext; it is the same record, not a new one.
//! * A changed frame is sealed only through `seal_chunk_hedged`, which accepts no
//!   nonce, while the derived nonce depends on plaintext (I-1).
//! * A copied frame must retain ITS OWN index: AAD binds the index, so a
//!   frame moved elsewhere will not open for the reader. The writer
//!   does not check indices; that is the caller's promise, with violations detected
//!   rather than accepted by the reader.

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

/// A piece of the new revision.
pub enum Piece<'a> {
    /// An old-file frame with THIS SAME index: `nonce ‖ ct ‖ tag`.
    Keep(&'a [u8]),
    /// New plaintext and a fresh nonce seed.
    Seal { plaintext: &'a [u8], seed: [u8; NONCE_LEN] },
}

impl core::fmt::Debug for Piece<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Keep(frame) => f.debug_tuple("Keep").field(&frame.len()).finish(),
            Self::Seal { plaintext, .. } => f.debug_struct("Seal")
                .field("plaintext_len", &plaintext.len())
                .field("seed", &"<redacted>")
                .finish(),
        }
    }
}

/// Inputs needed to assemble a revision.
#[derive(Debug)]
pub struct EditPlan<'a> {
    pub file_id: [u8; 16],
    pub aead: AeadAlg,
    pub chunk_size: u32,
    pub container_version: u16,
    /// Header `core_hash` (§3.2): the signature binds to it.
    pub core_hash: [u8; 32],
    /// Edit base: its counter and root.
    pub base_counter: u64,
    pub base_root: [u8; 32],
    pub certified_by: Vec<u8>,
    pub journal_head: Option<JournalHead>,
    pub pieces: Vec<Piece<'a>>,
}

/// Unsigned revision: descriptor, signing transcript, digest, frames.
#[derive(Debug)]
pub struct Unsigned {
    pub desc: ContentDesc,
    pub transcript: Transcript,
    pub digest: [u8; 32],
    pub payload: Vec<u8>,
}

/// Edit-writer failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditWriteError {
    Format(FormatError),
    Crypto(CryptoError),
    Edit(EditError),
    /// A copied frame is shorter than nonce plus tag.
    BadFrame { index: u32 },
    /// Pieces do not fit the layout: a nonfinal piece shorter than a chunk,
    /// a piece too long, or no pieces.
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

/// Assemble an unsigned revision.
///
/// # Errors
/// [`EditWriteError`]: frame, layout, cryptography, or counter.
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

/// Insert the signature and authenticate the mutable region.
///
/// Returns `(region, frames)`: region is `ContentDescLen ‖ body ‖ MAC`.
///
/// # Errors
/// [`EditWriteError`]: encoding failed.
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
