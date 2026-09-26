// SPDX-License-Identifier: MPL-2.0
//! Witnessing a server journal head (`docs/protocol.md` §9.13, D3).
//!
//! # What this contains and why
//!
//! A signed head (`size ‖ root`) proves only that the server
//! agrees with itself: rewriting the journal also rewrites its root. Value
//! comes from a copy of the head OUTSIDE the server, and someone able to compare a
//! new head with it without possessing the journal. That is the witness: it stores one head,
//! receives a new one from the server with a consistency proof
//! (RFC 9162), and signs it after the server if it extends
//! the old one.
//!
//! Only bytes and checks live here: a head, a view (head with proof),
//! a cosigned head, and the relationship between two heads. Networking, disk and clocks belong
//! to the witness (`cc_authority::witness`).
//!
//! # What this does NOT provide
//!
//! Independent public time or operator independence: a witness on the same
//! machine or under the same operator signs what it is shown and
//! rolls back with it. The witness detects rollback and forks
//! RELATIVE TO ITS OWN MEMORY, nothing more.

use oc_format::FormatError;
use oc_crypto::merkle::MerkleTree;
use oc_crypto::sign::{PUBLIC_KEY_LEN, SIGNATURE_LEN};
use oc_crypto::transcript::Transcript;
use oc_crypto::{digest_eq, label};

/// Signed head length: `u64le size ‖ root(32) ‖ signature(64)`.
///
/// The layout matches the `cca checkpoint --out` file: a head captured
/// by the operator and one from a view are the same bytes.
pub const SIGNED_HEAD_LEN: usize = 8 + 32 + SIGNATURE_LEN;

/// Cosigned head length:
/// `head(104) ‖ i64le time ‖ witness key(32) ‖ witness signature(64)`.
pub const COSIGNED_LEN: usize = SIGNED_HEAD_LEN + 8 + PUBLIC_KEY_LEN + SIGNATURE_LEN;

/// Maximum path length in a view.
///
/// A consistency proof for a tree of up to 2^32 leaves is shorter than 2·32 + 1
/// nodes; twice that is headroom, not a calculation. The limit serves parsing, not
/// verification: without it, a view could be an arbitrarily large buffer.
pub const MAX_PATH: usize = 128;

/// Which server journal is being witnessed.
///
/// The server has two journals, whose heads assert different things: the event journal
/// (leaves are record MACs) and the key directory journal (leaves are directory
/// record hashes, `crate::directory`). Journal kind is covered by both signatures:
/// a head of one journal signed by the server or witness cannot serve as a head of the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Log {
    /// Server event journal (`cca journal`).
    Journal = 1,
    /// Key directory journal (D4).
    Directory = 2,
}

impl Log {
    /// Head signature label for this journal.
    #[must_use]
    pub const fn head_label(self) -> oc_crypto::Label {
        match self {
            Self::Journal => label::AUDIT_HEAD,
            Self::Directory => label::DIRECTORY_HEAD,
        }
    }

    /// Parse a kind byte. Unknown means rejection (a registry with reserved values).
    ///
    /// # Errors
    /// [`FormatError::UnknownCriticalField`]: unknown kind.
    pub const fn from_u8(v: u8) -> Result<Self, FormatError> {
        match v {
            1 => Ok(Self::Journal),
            2 => Ok(Self::Directory),
            other => Err(FormatError::UnknownCriticalField { tag: other as u16 }),
        }
    }

    /// Name for humans and the command line.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Journal => "journal",
            Self::Directory => "directory",
        }
    }

    /// Parse a name.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "journal" => Some(Self::Journal),
            "directory" => Some(Self::Directory),
            _ => None,
        }
    }
}

/// Journal head signature transcript.
///
/// The sole definition: `cc_authority::journal::Checkpoint`
/// and the server directory call this same function. Two definitions would eventually diverge,
/// and the witness would stop verifying server-signed heads.
#[must_use]
pub fn head_transcript(log: Log, size: u64, root: &[u8; 32]) -> Transcript {
    let mut t = Transcript::new(log.head_label());
    t.u64be(size);
    t.fixed(root);
    t
}

/// Journal head with server signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedHead {
    pub size: u64,
    pub root: [u8; 32],
    pub sig: [u8; SIGNATURE_LEN],
}

impl SignedHead {
    /// Head bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; SIGNED_HEAD_LEN] {
        let mut out = [0u8; SIGNED_HEAD_LEN];
        let (size, rest) = out.split_at_mut(8);
        let (root, sig) = rest.split_at_mut(32);
        size.copy_from_slice(&self.size.to_le_bytes());
        root.copy_from_slice(&self.root);
        sig.copy_from_slice(&self.sig);
        out
    }

    /// Parse a head. Exact length (I-8).
    ///
    /// # Errors
    /// [`FormatError::BadFieldLength`]: length is not [`SIGNED_HEAD_LEN`].
    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        let exact: &[u8; SIGNED_HEAD_LEN] =
            bytes.try_into().map_err(|_| FormatError::BadFieldLength { tag: 0, len: bytes.len() })?;
        let (size, rest) = exact.split_at(8);
        let (root, sig) = rest.split_at(32);
        let bad = |_| FormatError::BadFieldLength { tag: 0, len: bytes.len() };
        Ok(Self {
            size: u64::from_le_bytes(size.try_into().map_err(bad)?),
            root: root.try_into().map_err(bad)?,
            sig: sig.try_into().map_err(bad)?,
        })
    }

    /// Whether this server signed the head of this journal.
    #[must_use]
    pub fn signed_by(&self, log: Log, server_key: &[u8; PUBLIC_KEY_LEN]) -> bool {
        oc_crypto::sign::verify(server_key, &head_transcript(log, self.size, &self.root), &self.sig).is_ok()
    }
}

/// Journal view: the server head and proof that it extends
/// a head of size `since`.
///
/// Layout: `head(104) ‖ u64le since ‖ path(32·N)`. `since = 0` means no old
/// head; the path is empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct View {
    pub head: SignedHead,
    pub since: u64,
    pub path: Vec<[u8; 32]>,
}

impl View {
    /// View bytes.
    ///
    /// # Errors
    /// [`FormatError::BadFieldLength`]: path exceeds [`MAX_PATH`] or is nonempty
    /// when `since = 0`.
    pub fn encode(&self) -> Result<Vec<u8>, FormatError> {
        self.check()?;
        let mut out = Vec::with_capacity(SIGNED_HEAD_LEN.saturating_add(8).saturating_add(self.path.len().saturating_mul(32)));
        out.extend_from_slice(&self.head.encode());
        out.extend_from_slice(&self.since.to_le_bytes());
        for node in &self.path {
            out.extend_from_slice(node);
        }
        Ok(out)
    }

    /// Parse a view strictly: a tail not divisible by 32, or extra nodes, is rejected.
    ///
    /// # Errors
    /// [`FormatError::BadFieldLength`]: inconsistent layout.
    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        let bad = FormatError::BadFieldLength { tag: 0, len: bytes.len() };
        let (head, rest) = bytes.split_at_checked(SIGNED_HEAD_LEN).ok_or(bad)?;
        let (since, path) = rest.split_at_checked(8).ok_or(bad)?;
        if !path.len().is_multiple_of(32) {
            return Err(bad);
        }
        let mut nodes = Vec::with_capacity(path.len() / 32);
        for node in path.chunks_exact(32) {
            nodes.push(<[u8; 32]>::try_from(node).map_err(|_| bad)?);
        }
        let view = Self {
            head: SignedHead::decode(head)?,
            since: u64::from_le_bytes(since.try_into().map_err(|_| bad)?),
            path: nodes,
        };
        view.check()?;
        Ok(view)
    }

    fn check(&self) -> Result<(), FormatError> {
        let len = self.path.len().saturating_mul(32);
        if self.path.len() > MAX_PATH || (self.since == 0 && !self.path.is_empty()) || self.since > self.head.size {
            return Err(FormatError::BadFieldLength { tag: 0, len });
        }
        Ok(())
    }
}

/// How the new head relates to the old one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relation {
    /// The same head.
    Same,
    /// The new head extends the old one: the proof verified.
    Extends,
    /// The new head is SHORTER: the journal is append-only and only becomes shorter
    /// when a stale backup is restored or tampering occurs.
    Rollback,
    /// Two histories: equal length with a different root, or a failed proof.
    Fork,
    /// Size beyond what the tree can prove (greater than `u32`).
    Unprovable,
}

/// Compare the new head with the old one using a consistency proof.
///
/// Signatures are not checked here; the caller must check them BEFOREHAND: an untrusted
/// head is unsuitable for any comparison.
#[must_use]
pub fn relate(old_size: u64, old_root: &[u8; 32], new_size: u64, new_root: &[u8; 32], path: &[[u8; 32]]) -> Relation {
    if new_size < old_size {
        return Relation::Rollback;
    }
    if new_size == old_size {
        return if digest_eq(old_root, new_root) && path.is_empty() { Relation::Same } else { Relation::Fork };
    }
    let (Ok(old), Ok(new)) = (u32::try_from(old_size), u32::try_from(new_size)) else {
        return Relation::Unprovable;
    };
    if MerkleTree::verify_consistency(old, old_root, new, new_root, path) {
        Relation::Extends
    } else {
        Relation::Fork
    }
}

/// Witness signature transcript.
///
/// The server key is signed: a cosigned head belongs to a particular
/// server's journal and cannot be transplanted to another with the same
/// `(size, root)`. Journal kind is signed: a directory head attestation
/// cannot attest to the event journal. Time is signed:
/// "the witness saw this no later than" is half of what the attestation
/// asserts.
#[must_use]
pub fn cosign_transcript(
    log: Log,
    server_key: &[u8; PUBLIC_KEY_LEN],
    size: u64,
    root: &[u8; 32],
    at: i64,
) -> Transcript {
    let mut t = Transcript::new(label::WITNESS_COSIGN);
    t.u8(log as u8);
    t.fixed(server_key);
    t.u64be(size);
    t.fixed(root);
    t.fixed(&at.to_be_bytes());
    t
}

/// A server-signed and witnessed head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cosigned {
    pub head: SignedHead,
    /// When the witness saw the head (Unix seconds, witness clock).
    pub at: i64,
    pub witness: [u8; PUBLIC_KEY_LEN],
    pub sig: [u8; SIGNATURE_LEN],
}

/// Why a cosigned head was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CosignedError {
    /// The server signature did not verify with the specified key.
    ServerSignature,
    /// The witness is not the trusted one.
    OtherWitness,
    /// The witness signature did not verify.
    WitnessSignature,
}

impl Cosigned {
    /// Cosigned head bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; COSIGNED_LEN] {
        let mut out = [0u8; COSIGNED_LEN];
        let (head, rest) = out.split_at_mut(SIGNED_HEAD_LEN);
        let (at, rest) = rest.split_at_mut(8);
        let (witness, sig) = rest.split_at_mut(PUBLIC_KEY_LEN);
        head.copy_from_slice(&self.head.encode());
        at.copy_from_slice(&self.at.to_le_bytes());
        witness.copy_from_slice(&self.witness);
        sig.copy_from_slice(&self.sig);
        out
    }

    /// Parse. Exact length.
    ///
    /// # Errors
    /// [`FormatError::BadFieldLength`]: length is not [`COSIGNED_LEN`].
    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        let bad = FormatError::BadFieldLength { tag: 0, len: bytes.len() };
        if bytes.len() != COSIGNED_LEN {
            return Err(bad);
        }
        let (head, rest) = bytes.split_at_checked(SIGNED_HEAD_LEN).ok_or(bad)?;
        let (at, rest) = rest.split_at_checked(8).ok_or(bad)?;
        let (witness, sig) = rest.split_at_checked(PUBLIC_KEY_LEN).ok_or(bad)?;
        Ok(Self {
            head: SignedHead::decode(head)?,
            at: i64::from_le_bytes(at.try_into().map_err(|_| bad)?),
            witness: witness.try_into().map_err(|_| bad)?,
            sig: sig.try_into().map_err(|_| bad)?,
        })
    }

    /// Verify both signatures: the server's using its key, the witness's using a key
    /// trusted by the verifier.
    ///
    /// The witness key embedded in the bytes is a hint, not a trust source: it is compared
    /// with the specified key; otherwise anyone could sign a head with their own key and place it
    /// alongside the signature.
    ///
    /// # Errors
    /// [`CosignedError`]: which check failed.
    pub fn verify(
        &self,
        log: Log,
        server_key: &[u8; PUBLIC_KEY_LEN],
        witness_key: &[u8; PUBLIC_KEY_LEN],
    ) -> Result<(), CosignedError> {
        if !self.head.signed_by(log, server_key) {
            return Err(CosignedError::ServerSignature);
        }
        if !digest_eq(&self.witness, witness_key) {
            return Err(CosignedError::OtherWitness);
        }
        let transcript = cosign_transcript(log, server_key, self.head.size, &self.head.root, self.at);
        oc_crypto::sign::verify(witness_key, &transcript, &self.sig).map_err(|_| CosignedError::WitnessSignature)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use oc_crypto::merkle::{Leaf, MerkleTree};
    use oc_crypto::sign::{Ed25519Signer, Signer};

    fn tree(n: u8) -> MerkleTree {
        let leaves: Vec<Leaf> = (0..n).map(|i| Leaf([i; 32])).collect();
        MerkleTree::build(&leaves).unwrap()
    }

    fn head(signer: &Ed25519Signer, t: &MerkleTree) -> SignedHead {
        let size = u64::from(t.leaf_count());
        let root = t.root();
        SignedHead { size, root, sig: signer.sign(&head_transcript(Log::Journal, size, &root)).unwrap() }
    }

    #[test]
    fn heads_views_and_cosignatures_round_trip_and_verify() {
        let server = Ed25519Signer::from_seed(&[1; 32]);
        let witness = Ed25519Signer::from_seed(&[2; 32]);
        let (old, new) = (tree(3), tree(7));
        let view = View { head: head(&server, &new), since: 3, path: new.consistency(3).unwrap() };
        let back = View::decode(&view.encode().unwrap()).unwrap();
        assert_eq!(back, view);
        assert!(back.head.signed_by(Log::Journal, &server.public_key()));
        assert!(!back.head.signed_by(Log::Journal, &witness.public_key()));
        // Голова журнала событий не годится головой каталога.
        assert!(!back.head.signed_by(Log::Directory, &server.public_key()));
        assert_eq!(relate(3, &old.root(), 7, &new.root(), &back.path), Relation::Extends);

        let at = 1_800_000_000;
        let c = Cosigned {
            head: view.head,
            at,
            witness: witness.public_key(),
            sig: witness.sign(&cosign_transcript(Log::Journal, &server.public_key(), 7, &new.root(), at)).unwrap(),
        };
        let c = Cosigned::decode(&c.encode()).unwrap();
        let (sk, wk) = (server.public_key(), witness.public_key());
        assert_eq!(c.verify(Log::Journal, &sk, &wk), Ok(()));
        assert_eq!(c.verify(Log::Directory, &sk, &wk), Err(CosignedError::ServerSignature));
        assert_eq!(c.verify(Log::Journal, &wk, &wk), Err(CosignedError::ServerSignature));
        assert_eq!(c.verify(Log::Journal, &sk, &sk), Err(CosignedError::OtherWitness));
        // Перенос момента или головы ломает подпись свидетеля.
        let mut later = c;
        later.at += 1;
        assert_eq!(later.verify(Log::Journal, &sk, &wk), Err(CosignedError::WitnessSignature));
        // Подпись свидетеля под другим сервером не годится этому.
        let other = Ed25519Signer::from_seed(&[3; 32]);
        let mut moved = c;
        moved.head = head(&other, &new);
        assert_eq!(moved.verify(Log::Journal, &other.public_key(), &wk), Err(CosignedError::WitnessSignature));
        // Свидетельство, подписанное для каталога, не годится журналу событий.
        let mut other_log = c;
        other_log.sig = witness.sign(&cosign_transcript(Log::Directory, &sk, 7, &new.root(), at)).unwrap();
        assert_eq!(other_log.verify(Log::Journal, &sk, &wk), Err(CosignedError::WitnessSignature));
        assert_eq!(Log::from_u8(3), Err(FormatError::UnknownCriticalField { tag: 3 }));
        assert_eq!(Log::parse(Log::Directory.name()), Some(Log::Directory));
    }

    #[test]
    fn relations_name_rollback_and_fork() {
        let (a3, a7) = (tree(3), tree(7));
        let forked: Vec<Leaf> = (0..7u8).map(|i| Leaf([i ^ u8::from(i == 1); 32])).collect();
        let b7 = MerkleTree::build(&forked).unwrap();
        assert_eq!(relate(7, &a7.root(), 3, &a3.root(), &[]), Relation::Rollback);
        assert_eq!(relate(7, &a7.root(), 7, &a7.root(), &[]), Relation::Same);
        assert_eq!(relate(7, &a7.root(), 7, &b7.root(), &[]), Relation::Fork);
        assert_eq!(relate(3, &a3.root(), 7, &b7.root(), &b7.consistency(3).unwrap()), Relation::Fork);
        assert_eq!(relate(3, &a3.root(), 7, &a7.root(), &[]), Relation::Fork);
        assert_eq!(relate(3, &a3.root(), u64::from(u32::MAX) + 1, &a7.root(), &[]), Relation::Unprovable);
    }

    #[test]
    fn malformed_bytes_are_refused() {
        let server = Ed25519Signer::from_seed(&[1; 32]);
        let t = tree(4);
        let view = View { head: head(&server, &t), since: 2, path: t.consistency(2).unwrap() };
        let bytes = view.encode().unwrap();
        assert!(View::decode(&bytes[..bytes.len() - 1]).is_err());
        assert!(View::decode(&[bytes.as_slice(), &[0]].concat()).is_err());
        assert!(View::decode(&bytes[..SIGNED_HEAD_LEN + 7]).is_err());
        // Путь при since = 0 и since больше головы — отказ.
        let mut zero = view.clone();
        zero.since = 0;
        assert!(zero.encode().is_err());
        let mut raw = bytes.clone();
        raw[SIGNED_HEAD_LEN..SIGNED_HEAD_LEN + 8].copy_from_slice(&0u64.to_le_bytes());
        assert!(View::decode(&raw).is_err());
        raw[SIGNED_HEAD_LEN..SIGNED_HEAD_LEN + 8].copy_from_slice(&9u64.to_le_bytes());
        assert!(View::decode(&raw).is_err());
        let long = View { head: view.head, since: 2, path: vec![[0; 32]; MAX_PATH + 1] };
        assert!(long.encode().is_err());
        assert!(SignedHead::decode(&[0; SIGNED_HEAD_LEN + 1]).is_err());
        assert!(Cosigned::decode(&[0; COSIGNED_LEN - 1]).is_err());
    }
}
