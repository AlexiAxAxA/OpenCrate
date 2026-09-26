// SPDX-License-Identifier: MPL-2.0
//! Cryptographic core of the `.cc` container.
//!
//! A crate-wide, lint-enforced rule: **no I/O,
//! clocks, or randomness from thin air**. Nonces and RNGs are passed
//! as arguments. This makes every test deterministic, while Wycheproof vectors
//! exercise our own call sites, not merely the underlying crates.
//!
//! Parsing ensures that plaintext never leaves the function before the authentication
//! tag is checked: on failure the buffer is wiped, and the caller must treat it
//! as unusable.

pub mod aead;
pub mod agreement;
pub mod kdf;
pub mod mac;
pub mod merkle;
pub mod mlkem_p256;
pub mod rsa;
/// Software RSA-PSS signer: only for probes and the testbed (`docs/format.md`,
/// "EDITING IS EXECUTABLE"). Excluded from production: the `test-signer` feature.
#[cfg(any(test, feature = "test-signer"))]
pub mod rsa_test_signer;
pub mod seal;
pub mod secret;
pub mod sign;
/// Payload chunking discipline: one loop for every host.
pub mod stream;
pub mod tpm;
pub mod transcript;
pub mod wrap;
pub mod xwing;

pub use label::Label;
pub use secret::{
    Cek, ClaimSecret, Kek, MacKey, MetaKey, PayloadKey, SecretA, SecretB, SecretBuf, X25519Secret,
};
pub use transcript::Transcript;

/// Cryptographic operation errors.
///
/// Variants deliberately reveal few details: an error message must not give
/// an adversary another bit of information about precisely which check
/// failed or at which byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// Authentication failed: AEAD tag, MAC, or slot commitment.
    /// One variant for all three cases, deliberately.
    Authentication,
    /// The signature is invalid or noncanonical.
    BadSignature,
    /// Input or output length violates the contract.
    BadLength,
    /// Data does not match the tree root.
    TreeMismatch,
    /// Access outside the tree.
    IndexOutOfRange,
    /// The key is not a valid curve point or is forbidden (small order).
    BadKey,
    /// This client build does not support the algorithm identifier.
    UnsupportedAlgorithm,
}

impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let text = match self {
            Self::Authentication => "проверка подлинности не прошла",
            Self::BadSignature => "подпись неверна",
            Self::BadLength => "некорректная длина данных",
            Self::TreeMismatch => "данные не соответствуют дереву целостности",
            Self::IndexOutOfRange => "индекс за пределами дерева",
            Self::BadKey => "некорректный ключ",
            Self::UnsupportedAlgorithm => "алгоритм не поддерживается",
        };
        f.write_str(text)
    }
}

impl core::error::Error for CryptoError {}

/// Algorithm identifiers covered by the header signature.
///
/// Agility uses explicit numbers rather than "the current best choice" because
/// the KEM will change during the product's lifetime: X25519 will give way to an ML-KEM hybrid,
/// and slots using different KEMs must coexist in one file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AeadAlg {
    /// Primary profile. A 192-bit nonce allows storing a random nonce.
    XChaCha20Poly1305 = 1,
    /// Profile for FIPS requirements. A 96-bit nonce requires a counter and
    /// makes the container effectively write-once.
    Aes256Gcm = 2,
    /// Nonce-reuse-resistant variant.
    ///
    /// This used to say "for editable files", which was a promise, not a
    /// description: editable files use `aead_id = 1`, like all
    /// others. The property SIV was meant to provide comes from plaintext-hedged
    /// nonces ([`aead::seal_chunk_hedged`]), introduced after
    /// the promise itself and making the second profile unnecessary. See
    /// `docs/format.md` §6.1.
    ///
    /// The member remains to prevent assigning number 3 to another cipher.
    Aes256GcmSiv = 3,
}

impl AeadAlg {
    /// Parse an identifier from a file. Unknown values cause rejection, not
    /// substitution of a default.
    ///
    /// Parsing immediately passes the second boundary, [`aead::ensure_supported`],
    /// just as [`TreeHashAlg::from_u8`] already does. The asymmetry was
    /// substantive: a header with `aead_id = 2` passed signature verification, slot parsing,
    /// key agreement, and CEK unwrapping before failing on the first chunk. All
    /// that work was done on a file already known, at parsing time,
    /// to be impossible to open.
    pub fn from_u8(v: u8) -> Result<Self, CryptoError> {
        let alg = match v {
            1 => Self::XChaCha20Poly1305,
            2 => Self::Aes256Gcm,
            3 => Self::Aes256GcmSiv,
            _ => return Err(CryptoError::UnsupportedAlgorithm),
        };
        aead::ensure_supported(alg)?;
        Ok(alg)
    }
}

/// Signature algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SigAlg {
    /// Author signature. The only one this build executes.
    Ed25519 = 1,
    /// Editing-device signature: RSA-PSS-SHA256, MGF1-SHA256,
    /// 32-byte salt and exponent 65537 (format version 3).
    ///
    /// PSS salt repetition does not disclose the signing key, unlike ECDSA
    /// nonce reuse. Verification is [`rsa::verify_pss_sha256`] and builds for WASM.
    /// This identifier is valid only for mutable-region tag 6; the author's
    /// `suite.sig_alg` remains Ed25519.
    RsaPssSha256 = 2,
}

impl SigAlg {
    /// Whether the build can execute the declared algorithm.
    ///
    /// A second boundary, like [`aead::ensure_supported`] and
    /// [`merkle::ensure_supported`]. Without it, an identifier in a signed
    /// header controls nothing: a file declaring RSA-PSS would still
    /// be verified as Ed25519 and accepted. This is the same defect class
    /// that produced `alg: none` in JWS.
    ///
    /// The `match` deliberately has no `_`: adding a member must break the build here,
    /// beside verification, rather than pass silently.
    pub fn ensure_supported(self) -> Result<(), CryptoError> {
        match self {
            Self::Ed25519 => Ok(()),
            // Исполняется с появлением `rsa::verify_pss_sha256`. До него здесь
            // стоял отказ, и это было верно: номер, который сборка не умеет
            // исполнить, обязан отвергаться на разборе.
            Self::RsaPssSha256 => Ok(()),
        }
    }

    /// Parse an identifier from a file.
    ///
    /// As with [`AeadAlg::from_u8`], parsing immediately passes through
    /// [`Self::ensure_supported`]: a header using an unimplemented algorithm must
    /// be rejected AT PARSING, not after key agreement and CEK unwrapping.
    pub fn from_u8(v: u8) -> Result<Self, CryptoError> {
        let alg = match v {
            1 => Self::Ed25519,
            2 => Self::RsaPssSha256,
            _ => return Err(CryptoError::UnsupportedAlgorithm),
        };
        alg.ensure_supported()?;
        Ok(alg)
    }
}

/// Key encapsulation mechanism. Specified **per slot**, not per file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KemAlg {
    /// Author → server and author → recipient.
    X25519HkdfSha256 = 1,
    /// Server → device. P-256 specifically, not X25519: Microsoft Platform Crypto
    /// Provider does not provide X25519; TPM 2.0 offers ECDH P-256 and RSA.
    P256HkdfSha256 = 2,
    /// Fallback for TPMs without ECDH support.
    RsaOaepSha256 = 3,
    /// X25519 and ML-KEM-768 hybrid using X-Wing: a post-quantum half
    /// alongside a classical half. Mechanism: [`crate::xwing`]; normative form:
    /// `docs/format.md`, "VERSION 3 OPENED", item 1 (the item itself is in version 4).
    ///
    /// Targets a SOFTWARE key: X-Wing is defined over X25519, while a TPM key
    /// is P-256. Post-quantum protection and hardware binding of the recipient are currently
    /// mutually exclusive; see `docs/threat-model.md` §2.
    XWing = 4,
    /// ECDH P-256 and ML-KEM-768 hybrid: MLKEM768-P256. Mechanism:
    /// [`crate::mlkem_p256`]; normative form: `docs/format.md`, version 5.
    ///
    /// The difference from [`Self::XWing`] is not strength but WHERE the classical
    /// half resides: Platform Crypto Provider supports P-256 but not X25519. Thus
    /// the fifth mechanism is the only one combining post-quantum protection with
    /// TPM key non-exportability rather than making them mutually exclusive.
    MlKem768P256 = 5,
}

impl KemAlg {
    /// Reject a KEM this build cannot execute.
    ///
    /// Delegates to [`seal::supports_kem`], keeping the support table beside
    /// the implementations. This is its `Result` form for callers needing an error.
    ///
    /// # Errors
    /// [`CryptoError::UnsupportedAlgorithm`] for a registered but unsupported KEM.
    pub fn ensure_supported(self) -> Result<(), CryptoError> {
        if seal::supports_kem(self) { Ok(()) } else { Err(CryptoError::UnsupportedAlgorithm) }
    }

    /// Parse a registered KEM identifier.
    ///
    /// An unsupported or unknown slot is skipped rather than rejecting the file
    /// (format §3.3/§3.5), because another slot may be usable. Check
    /// [`Self::ensure_supported`] separately before executing the mechanism.
    pub fn from_u8(v: u8) -> Result<Self, CryptoError> {
        match v {
            1 => Ok(Self::X25519HkdfSha256),
            2 => Ok(Self::P256HkdfSha256),
            3 => Ok(Self::RsaOaepSha256),
            4 => Ok(Self::XWing),
            5 => Ok(Self::MlKem768P256),
            _ => Err(CryptoError::UnsupportedAlgorithm),
        }
    }
}

/// Payload-tree hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TreeHashAlg {
    /// Naturally tree-based and substantially faster than SHA-256.
    Blake3 = 1,
    /// Listed in the format registry but not used to compute trees in this build: see
    /// [`merkle::ensure_supported`]. The member remains to prevent reusing number 2
    /// for another hash; otherwise old files would be read with the wrong
    /// algorithm rather than rejected.
    Sha256 = 2,
}

impl TreeHashAlg {
    /// Parse an identifier from a file.
    ///
    /// Parsing a number and being able to execute it are distinct; previously this build
    /// only did the first: it accepted `tree_hash_id = 2`, yet still computed the tree
    /// using BLAKE3. Parsing therefore immediately passes a second boundary,
    /// [`merkle::ensure_supported`], the sole declaration of what this
    /// build supports. A single place prevents the supported-algorithm list from
    /// diverging from the hasher's behavior.
    pub fn from_u8(v: u8) -> Result<Self, CryptoError> {
        let alg = match v {
            1 => Self::Blake3,
            2 => Self::Sha256,
            _ => return Err(CryptoError::UnsupportedAlgorithm),
        };
        merkle::ensure_supported(alg)?;
        Ok(alg)
    }
}

/// Domain-separation labels.
///
/// None is used twice across the system. The only route into
/// a signature is through [`Transcript`], whose constructor requires a label.
pub mod label {
    /// Domain label from the protocol registry.
    ///
    /// The private constructor restricts values to this module's constants.
    /// [`ALL`] is checked for uniqueness, prefix-freeness and agreement with §3.6.
    /// Labels are public, so Debug shows their text for diagnosing domain mismatches.
    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct Label(&'static [u8]);

    impl Label {
        /// Create a label. Deliberately private: see the type documentation.
        ///
        /// `const fn` because all labels are constants; a constant
        /// constructed at runtime would require `OnceLock` where all that is needed
        /// is a byte array.
        const fn new(bytes: &'static [u8]) -> Self {
            Self(bytes)
        }

        /// Label bytes: what enters `info`, the transcript, and the preimage.
        #[must_use]
        pub const fn as_bytes(self) -> &'static [u8] {
            self.0
        }

        /// Byte length. Needed in `const` context: the private-metadata AAD layout
        /// is computed at build time (`aead::META_AAD_LEN`).
        #[must_use]
        pub const fn len(self) -> usize {
            self.0.len()
        }

        /// Whether the label is empty. Always `false`: a label with no bytes cannot separate
        /// domains, but without this method `clippy::len_without_is_empty` is right.
        #[must_use]
        pub const fn is_empty(self) -> bool {
            self.0.is_empty()
        }

        /// A label OUTSIDE THE REGISTRY: for prototypes and probes only.
        ///
        /// Needed by two out-of-tree prototypes (`experiments/attested-release`,
        /// `spikes/disclosure-capsules`): each signs ITS OWN statement in
        /// its own domain (`"F29/proto/evidence"`, `"SS/spike/..."`); adding those
        /// strings to the registry is forbidden, since the registry is normative and the prototype may die tomorrow.
        ///
        /// The `ad-hoc-label` feature is disabled by default and listed as
        /// non-shipping (`cc-cli/tests/repository_hygiene.rs`) for the same
        /// reason as `explicit-nonce`: enabling it in a release restores the
        /// production escape hatch that this type was introduced to close.
        #[cfg(any(test, feature = "ad-hoc-label"))]
        #[must_use]
        pub const fn ad_hoc(bytes: &'static [u8]) -> Self {
            Self::new(bytes)
        }
    }

    impl core::fmt::Debug for Label {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            match core::str::from_utf8(self.0) {
                Ok(text) => write!(f, "Label({text})"),
                // Метки реестра — ASCII по построению, и эта ветка недостижима
                // для них. Она существует ради `ad_hoc`, которому байты передают
                // прототипы.
                Err(_) => write!(f, "Label({:?})", self.0),
            }
        }
    }

    pub const HEADER_SIG: Label = Label::new(b"CC/v1/header-sig");
    pub const REVOCATION: Label = Label::new(b"CC/v1/revocation");
    pub const GRANT: Label = Label::new(b"CC/v1/grant");
    /// Author signature on an agent grant: door, expiry, depth and subtree shares B
    /// (`oc_protocol::agent::AgentGrant`, Agent Protocol stage 1).
    ///
    /// Separate from [`GRANT`], which approves access to one file. Sharing a signing
    /// key does not make the two statements interchangeable; their labels remain
    /// prefix-free and do not change the container layout.
    pub const AGENT_GRANT: Label = Label::new(b"CC/v1/agent-grant");
    /// Parent-door signature on a DELEGATION to a child
    /// (`oc_protocol::agent::Delegation`, same source).
    ///
    /// Distinct from [`AGENT_GRANT`]: the author signs a grant with the container
    /// header's key, while the door signs delegations with its own ephemeral Ed25519 key. A signature
    /// on one must not work for the other, or a door receiving
    /// a grant could issue itself another grant, with new depth and expiry.
    ///
    /// Prefix-free: the nearest `d` labels are `"CC/v1/device-fpr"`,
    /// `"CC/v1/directory-entry"`, and `"CC/v1/directory-head"`, all differing
    /// at byte eight (`e` versus `e`/`i`; for `device-fpr`, at byte nine,
    /// `l` versus `v`).
    pub const DELEGATION: Label = Label::new(b"CC/v1/delegation");
    /// Author signature on an action grant: permitted actions and constraints
    /// (`oc_protocol::action::ActionGrant`, Agent Protocol stage 2, §4.1).
    ///
    /// Separate from [`AGENT_GRANT`] and [`GRANT`]: permission to execute an action
    /// must not be accepted as permission to distribute file shares, or vice versa.
    pub const ACTION_GRANT: Label = Label::new(b"CC/v1/action-grant");
    /// Server signature on a single-use action lease
    /// (`oc_protocol::action::ActionLease`, Agent Protocol stage 2, §4.3).
    ///
    /// Uses the file lease-signing key with a distinct, prefix-free domain.
    /// A file lease authorizes opening; this document authorizes a specific action.
    pub const ACTION_LEASE: Label = Label::new(b"CC/v1/action-lease");
    /// Author signature on an action-execution decision
    /// (`oc_protocol::action::ActionDecision`, Agent Protocol stage 2, §5).
    ///
    /// Separate from access decisions under [`GRANT`], although both use the author
    /// key. The label distinguishes the statements independently of their TLV tags.
    pub const ACTION_DECISION: Label = Label::new(b"CC/v1/action-decision");
    pub const LEASE: Label = Label::new(b"CC/v1/lease");
    pub const ACTIVATE_REQ: Label = Label::new(b"CC/v1/activate-req");
    pub const AUDIT_ENTRY: Label = Label::new(b"CC/v1/audit-entry");
    /// Signed log head: size and tree root over the entries.
    ///
    /// Its own label rather than a shared entry label, for good reason: heads and entries are
    /// DIFFERENT statements. A signature on one must not work for the other,
    /// or a signed entry could be presented as a signed head.
    ///
    /// Prefix-free: `"CC/v1/audit-entry"` is not its prefix, nor vice versa
    /// (I-12), tested across the entire list.
    pub const AUDIT_HEAD: Label = Label::new(b"CC/v1/audit-head");
    pub const ATTEST_NONCE: Label = Label::new(b"CC/v1/attest-nonce");
    pub const CONTENT_MAC: Label = Label::new(b"CC/v1/content-mac");
    /// Editor signature over the mutable region (`docs/format.md`, "EDITING IS
    /// EXECUTABLE", item C).
    pub const EDITOR_SIG: Label = Label::new(b"CC/v1/editor-sig");
    /// Editing-key certificate: the author or a coauthor certifies "device X has
    /// editing key S for this file" (same source, item B).
    ///
    /// Prefix-free with [`EDITOR_SIG`]: they share only `"CC/v1/editor-"`, and
    /// neither extends the other.
    pub const EDITOR_CERT: Label = Label::new(b"CC/v1/editor-cert");
    /// Editing-session head: a hash chain of saves (same source, item D).
    pub const EDIT_SESSION: Label = Label::new(b"CC/v1/edit-session");
    /// Revision submission to the server (`docs/protocol.md` §9.12): a separate label so
    /// an editing-key signature on a submission cannot serve as a region signature,
    /// or vice versa (I-12).
    pub const EDITION_CLAIM: Label = Label::new(b"CC/v1/edition-claim");
    /// File imprint for an RFC 3161 timestamp (`docs/format.md`, "FOOTER AND
    /// TIMESTAMP", item B).
    pub const FOOTER_IMPRINT: Label = Label::new(b"CC/v1/footer-imprint");
    /// Witness signature over the server's log head (`docs/protocol.md`
    /// §9.13, D3). Separate from `audit-head`: the server signs the head,
    /// while another party signs the witness statement; one's signature must not serve
    /// as the other's.
    pub const WITNESS_COSIGN: Label = Label::new(b"CC/v1/witness-cosign");
    /// Key-directory log leaf: directory-entry hash (`docs/protocol.md`
    /// §9.14, D4). Unlike the event log, the leaf hashes the entry ITSELF, not
    /// its MAC: verifiers must see exactly what is proved.
    pub const DIRECTORY_ENTRY: Label = Label::new(b"CC/v1/directory-entry");
    /// Directory-log head signature. Separate from `audit-head`: a directory
    /// head and an event-log head are different statements.
    pub const DIRECTORY_HEAD: Label = Label::new(b"CC/v1/directory-head");
    /// Semantic-mark layout fingerprint (D5): which points and which
    /// equivalent variants they contain.
    pub const MARK_LAYOUT: Label = Label::new(b"CC/v1/mark-layout");
    /// Semantic-mark variant selection using the organization key (D5). Prefix-free with
    /// `mark-layout`: they share only `"CC/v1/mark-"`.
    pub const MARK_CHOICE: Label = Label::new(b"CC/v1/mark-choice");
    /// Server recovery-package manifest signature using the lease-signing key
    /// (E2, B5): which keys, state, and log head the package contains.
    /// Does not affect the container.
    pub const RECOVERY_MANIFEST: Label = Label::new(b"CC/v1/recovery-manifest");
    /// Server-binding signature using the lease-signing key (E2, B2,
    /// `oc_protocol::control::Binding`).
    pub const AUTHORITY_BINDING: Label = Label::new(b"CC/v1/authority-binding");
    /// Controller signature on an intent (E2, B2,
    /// `oc_protocol::control::ControlRequest`).
    pub const CONTROL_REQUEST: Label = Label::new(b"CC/v1/control-request");
    /// Server signature on an operation receipt (E2, B2,
    /// `oc_protocol::control::Receipt`). Prefix-free with `operation-id`: they share
    /// only `"CC/v1/operation-"`.
    pub const OPERATION_RECEIPT: Label = Label::new(b"CC/v1/operation-receipt");
    /// Signature on a state snapshot sent to a replica (E2, B4,
    /// `oc_protocol::replica::Push`).
    pub const REPLICA_PUSH: Label = Label::new(b"CC/v1/replica-push");
    /// Replica signature on an accepted snapshot (E2, B4,
    /// `oc_protocol::replica::Ack`). Separate from `replica-push`: different
    /// parties sign, and one's signature must not serve as the other's.
    pub const REPLICA_ACK: Label = Label::new(b"CC/v1/replica-ack");
    /// Controller signature transferring authority to a successor (E2, B7,
    /// `oc_protocol::control::Transfer`). Separate from `control-request`:
    /// an intent changes binding within an epoch; a transfer changes the epoch,
    /// and a signature on one must not work for the other.
    pub const AUTHORITY_TRANSFER: Label = Label::new(b"CC/v1/authority-transfer");
    pub const CHUNK: Label = Label::new(b"CC/v1/chunk");
    pub const LEAF: Label = Label::new(b"CC/v1/leaf");
    pub const NODE: Label = Label::new(b"CC/v1/node");

    pub const KEK: Label = Label::new(b"CC/v1/kek");
    pub const PAYLOAD: Label = Label::new(b"CC/v1/payload");
    pub const NONCE_BASE: Label = Label::new(b"CC/v1/nonce-base");
    pub const PRIVATE_META: Label = Label::new(b"CC/v1/private-meta");
    /// Device keypair derived from a claim code.
    ///
    /// A code-based heir receives the file's existing share B sealed to this keypair.
    /// This domain stays separate from `SLOT_B_CLAIM`, which derives a share directly;
    /// reusing that derivation would make the private key equal to the slot share.
    pub const CLAIM_DEVICE: Label = Label::new(b"CC/v1/claim-device");
    pub const SLOT_B_CLAIM: Label = Label::new(b"CC/v1/slot-b-claim");
    pub const SLOT_B_COMMIT: Label = Label::new(b"CC/v1/slot-b-commit");
    pub const SLOT_COMMIT: Label = Label::new(b"CC/v1/slot-commit");
    pub const A_TO_DEVICE: Label = Label::new(b"CC/v1/a-to-device");
    /// Share B sent FROM THE AUTHOR to the recipient's device.
    ///
    /// A distinct domain from [`A_TO_DEVICE`], not symmetry for its own sake:
    /// DIFFERENT parties issue shares under different decisions. If domains matched, a block
    /// issued by the server could stand in for an author block, or vice versa.
    ///
    /// Prefix-free relative to `a-to-device` and all others (I-12): their initial
    /// bytes differ.
    pub const B_TO_DEVICE: Label = Label::new(b"CC/v1/b-to-device");
    /// Deliberately not `"CC/v1/lease-cache"`: that string would extend
    /// [`LEASE`], while labels also prefix HKDF `info`, with no
    /// separating zero byte. The label set must be prefix-free.
    pub const CACHED_LEASE: Label = Label::new(b"CC/v1/cached-lease");
    pub const SEAL_KEY: Label = Label::new(b"CC/v1/seal-key");
    /// Slot-sealing nonce hedging (§3.3).
    ///
    /// A **nonce** derivation label: its introduction clarifies rather than abandons
    /// "nonces are stored, not derived". The reader still takes the nonce
    /// **without computing it**, from the slot record. The sender derives it,
    /// solely to stop the value being a pure function of
    /// RNG state. See [`crate::kdf::hedged_nonce`].
    pub const SEAL_NONCE: Label = Label::new(b"CC/v1/seal-nonce");
    /// CEK-wrapper nonce hedging (§3.1). Same purpose as [`SEAL_NONCE`].
    pub const WRAP_NONCE: Label = Label::new(b"CC/v1/wrap-nonce");
    /// Payload-frame nonce hedging (§6.1).
    ///
    /// The label must not extend [`CHUNK`]: labels prefix HKDF `info` without a
    /// separator, so `"CC/v1/chunk"‖"-nonce"‖X` would collide with
    /// `"CC/v1/chunk-nonce"‖X`. The registry checks prefix-freeness.
    pub const FRAME_NONCE: Label = Label::new(b"CC/v1/frame-nonce");
    /// Private-metadata nonce hedging (§2.0).
    ///
    /// Repeated RNG state cost more here than for a chunk: `CEK` and
    /// `header_salt` come from the same RNG, so snapshot rollback
    /// repeated both the K5 key and nonce while plaintexts (filename, size)
    /// differed. This reuses the keystream and repeats the one-time
    /// Poly1305 key inside the author-signed header.
    pub const META_NONCE: Label = Label::new(b"CC/v1/meta-nonce");
    /// Header-core hash: everything except key material.
    pub const CORE_HASH: Label = Label::new(b"CC/v1/core-hash");
    /// Policy hash over its byte range.
    pub const POLICY_HASH: Label = Label::new(b"CC/v1/policy-hash");

    /// Slot purpose: license-server share.
    ///
    /// Each slot kind has its own label in the sealing `info`.
    /// Consequently, ciphertext addressed to the server does not open as ciphertext
    /// addressed to the author's device, even if both are sealed to the same key.
    pub const SLOT_SERVER: Label = Label::new(b"CC/v1/slot-server");
    /// Slot purpose: recipient share.
    pub const SLOT_RECIPIENT: Label = Label::new(b"CC/v1/slot-recipient");
    /// Slot purpose: both shares for the author's device.
    pub const SLOT_AUTHOR_DEVICE: Label = Label::new(b"CC/v1/slot-author-device");

    /// Claim-code text → `claim_secret` (§3.4).
    ///
    /// Lives here although used in the client: the system has one label registry,
    /// and declaring a label outside it breaks the only available prefix-freeness
    /// guarantee, the test over [`ALL`]. There would be nothing to check it with,
    /// precisely because the list is complete.
    ///
    /// The difference from [`SLOT_B_CLAIM`] matters: that label derives a **share** from
    /// an existing 32-byte secret, while this one transforms
    /// **printed text** into that secret. Different inputs, different domains.
    pub const CLAIM_CODE: Label = Label::new(b"CC/v1/claim-code");
    /// An author's wire instruction to the server to register or revoke a file.
    /// Signed by the author key, the same one that signed the header.
    pub const AUTHOR_ORDER: Label = Label::new(b"CC/v1/author-order");

    /// Proof of opening a secret challenge (K23).
    ///
    /// **Unused by the protocol since 2026-09-21** (`docs/format.md`, section
    /// "ECHO BOUND TO THE CONVERSATION 2026-09-21"): K31 derives the echo from
    /// the handshake transcript. The label and derivation remain for the frozen
    /// `k23_prove_echo` vector in `derivations_wire.kat`: I-14 forbids changing
    /// frozen artifacts, and removing the label from the registry would remove
    /// the tested domain beneath the vector.
    pub const PROVE_ECHO: Label = Label::new(b"CC/v1/prove-echo");
    /// Request MAC key after proof (K24).
    pub const SESSION_MAC: Label = Label::new(b"CC/v1/session-mac");
    /// Conversation-bound proof-of-possession echo (K31, protocol §9.4).
    ///
    /// Labels both the handshake transcript and its challenge-keyed HMAC.
    /// Domain separation prevents collision with K23 under the same key; the label
    /// also remains prefix-free with the older `"CC/v1/prove-echo"` domain.
    pub const ECHO_TRANSCRIPT: Label = Label::new(b"CC/v1/echo-transcript");

    /// Device fingerprint for mechanisms whose public keys exceed 32 bytes
    /// (K27). For X25519 the fingerprint IS the key, and this label is unused:
    /// that form is frozen by K11, K21, K23, and K24 vectors.
    pub const DEVICE_FPR: Label = Label::new(b"CC/v1/device-fpr");

    /// Wire operation identity (K28, `docs/protocol.md` §9.10).
    ///
    /// The identifier derives from a seed and the request body rather than coming directly
    /// from the RNG, for the same reason as nonce hedging (C-13): RNGs
    /// repeat after snapshot rollback and image cloning, and a server would treat two DIFFERENT
    /// requests with one identifier as one request, giving the second
    /// someone else's "issued" outcome.
    pub const OPERATION_ID: Label = Label::new(b"CC/v1/operation-id");
    /// Fresh value generated by the SERVER (K30, `docs/format.md`, section
    /// "SERVER FRESHNESS IS DERIVED 2026-09-20").
    ///
    /// One label serves two purposes, attestation challenge (§9.11.1) and
    /// proof-of-possession secret (§9.4), separated by `kind` inside the preimage,
    /// as with [`OPERATION_ID`]. A second label would create a second domain where
    /// there is only one: a server freshness value.
    ///
    /// Prefix-free: `"CC/v1/seal-key"`, `"CC/v1/seal-nonce"`, and
    /// `"CC/v1/session-mac"` differ at byte eight, and no registry label
    /// is its prefix.
    pub const SERVER_FRESH: Label = Label::new(b"CC/v1/server-fresh");

    /// Publisher signature on a distribution-package `manifest.txt`.
    ///
    /// A separate domain prevents reuse of an Ed25519 publisher signature as a
    /// container or protocol signature. Registration keeps the label prefix-free;
    /// the domain does not change the container layout.
    pub const PACKAGE_MANIFEST: Label = Label::new(b"CC/v1/package-manifest");

    /// K29: qualifying data for a TPM statement about the device key (B6a,
    /// `docs/protocol.md` §9.11): `extraData` in `TPMS_ATTEST`.
    ///
    /// Separate from [`ATTEST_NONCE`]: that already serves as `info` when sealing a proof-of-possession
    /// challenge (§9.4), and one label for two applications leaves
    /// an unseparated domain (I-12). Prefix-free: `"CC/v1/attest-nonce"` is not
    /// a prefix of this string, nor vice versa.
    pub const ATTEST_QUALIFY: Label = Label::new(b"CC/v1/attest-qualify");

    /// All labels in one list for the uniqueness test.
    ///
    /// The list remains the SOLE source for the four I-12 probes even after
    /// [`Label`] was introduced: the type guards call sites, the list guards
    /// the registry's contents. Neither check replaces the other.
    pub const ALL: &[Label] = &[
        HEADER_SIG, REVOCATION, GRANT, LEASE, ACTIVATE_REQ, AUDIT_ENTRY, AUDIT_HEAD,
        ATTEST_NONCE,
        CONTENT_MAC, EDITOR_SIG, CHUNK, LEAF, NODE, KEK, PAYLOAD, NONCE_BASE,
        PRIVATE_META, CLAIM_DEVICE, SLOT_B_CLAIM, SLOT_B_COMMIT, SLOT_COMMIT, A_TO_DEVICE,
        B_TO_DEVICE,
        CACHED_LEASE,
        SEAL_KEY, SEAL_NONCE, WRAP_NONCE, FRAME_NONCE, META_NONCE, CORE_HASH, POLICY_HASH,
        SLOT_SERVER, SLOT_RECIPIENT, SLOT_AUTHOR_DEVICE, CLAIM_CODE, AUTHOR_ORDER, PROVE_ECHO, SESSION_MAC,
        ECHO_TRANSCRIPT,
        DEVICE_FPR, OPERATION_ID, ATTEST_QUALIFY, EDITOR_CERT, EDIT_SESSION, EDITION_CLAIM, FOOTER_IMPRINT,
        WITNESS_COSIGN, DIRECTORY_ENTRY, DIRECTORY_HEAD, MARK_LAYOUT, MARK_CHOICE,
        RECOVERY_MANIFEST, AUTHORITY_BINDING, CONTROL_REQUEST, OPERATION_RECEIPT,
        REPLICA_PUSH, REPLICA_ACK, AUTHORITY_TRANSFER,
        SERVER_FRESH, PACKAGE_MANIFEST,
        AGENT_GRANT, DELEGATION,
        ACTION_GRANT, ACTION_LEASE, ACTION_DECISION,
    ];
}

/// Minimum claim-code entropy, checked by the code generator.
///
/// A compressed 32-byte `ClaimSecret` does not reveal the original code's entropy.
/// Enforce this bound using the generator's alphabet and length. Guessing is
/// offline against the public commitment, so server attempt limits cannot help.
pub const MIN_CLAIM_BITS: u32 = 128;

/// SHA-256 of arbitrary bytes, including data outside the container format.
/// Compare digests through [`digest_eq`].
#[must_use]
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::digest(bytes).into()
}

/// Compare two 32-byte digests in constant time.
///
/// The only way to compare hashes, roots, fingerprints, and commitments throughout the
/// repository, a rule rather than an optimization. Some values are public
/// (the tree root is plaintext in the file), some are not (the slot commitment), and
/// the boundary moves over time: `original_root` is public today, but
/// becomes an address in detached mode. Permitting "ordinary `==` here
/// because the value is public" would oblige us to prove that again with
/// every change, and eventually prove it incorrectly.
///
/// Comparison accepts fixed-length arrays rather than slices: a length that can
/// be confused is a second way to err, which is unnecessary here.
#[must_use]
pub fn digest_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    use subtle::ConstantTimeEq;
    bool::from(a.ct_eq(b))
}

/// Compare public key byte strings.
///
/// Unequal public lengths return `false` immediately. Equal-length contents use
/// `subtle`; this API makes no timing guarantee for secret lengths.
#[must_use]
pub fn public_key_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    bool::from(a.ct_eq(b))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn digest_comparison_agrees_with_equality_on_every_byte_position() {
        // Проверяется не «работает ли ct_eq» — за это отвечает subtle, — а то, что
        // единый способ сравнения не разошёлся с обычным равенством ни в одном
        // разряде. Ошибка вида «сравнили первые 16 байт» прошла бы мимо теста на
        // паре случайных значений, но не мимо перебора позиций.
        let base = [0xA5u8; 32];
        assert!(digest_eq(&base, &base.clone()));
        for position in 0..32usize {
            let mut other = base;
            if let Some(byte) = other.get_mut(position) {
                *byte ^= 0x80;
            }
            assert!(!digest_eq(&base, &other), "различие в байте {position} не замечено");
        }
    }

    #[test]
    fn every_domain_label_is_unique() {
        // Повторно использованная метка — тихая уязвимость: подпись из одного
        // контекста начинает приниматься в другом. Дешевле поймать тестом.
        // Сравниваются БАЙТЫ, а не значения `Label`: две константы с одной и той
        // же строкой — это и есть повтор домена, и `Label` их не различает лишь
        // потому, что различать там нечего. Сверка по байтам оставляет проверку
        // той же, какой она была до появления типа.
        let unique: BTreeSet<&[u8]> = label::ALL.iter().map(|l| l.as_bytes()).collect();
        assert_eq!(unique.len(), label::ALL.len(), "метки домена повторяются");
    }

    #[test]
    fn no_label_is_a_prefix_of_another() {
        // Префиксная метка позволяет столкнуть кодировки: "CC/v1/lease" и
        // "CC/v1/lease-cache" различаются только тем, что идёт дальше.
        // Разделитель 0x00 в транскрипте закрывает это, тест фиксирует намерение.
        for a in label::ALL.iter().map(|l| l.as_bytes()) {
            for b in label::ALL.iter().map(|l| l.as_bytes()) {
                if a != b {
                    assert!(!b.starts_with(a) || b.len() == a.len(), "метка {a:?} — префикс {b:?}");
                }
            }
        }
    }

    #[test]
    fn every_domain_label_is_versioned() {
        for l in label::ALL.iter().map(|l| l.as_bytes()) {
            assert!(
                l.starts_with(b"CC/v1/"),
                "метка {:?} без версии: при переходе на v2 её нельзя будет отличить",
                core::str::from_utf8(l).unwrap_or("<не utf8>")
            );
        }
    }

    #[test]
    fn algorithm_ids_are_stable_numbers() {
        // Значения входят в подписанный транскрипт, поэтому их нельзя менять
        // местами при рефакторинге: старые файлы перестанут проверяться.
        assert_eq!(AeadAlg::XChaCha20Poly1305 as u8, 1);
        assert_eq!(SigAlg::Ed25519 as u8, 1);
        assert_eq!(KemAlg::X25519HkdfSha256 as u8, 1);
        assert_eq!(KemAlg::P256HkdfSha256 as u8, 2);
        assert_eq!(KemAlg::XWing as u8, 4);
        assert_eq!(KemAlg::MlKem768P256 as u8, 5);
        assert_eq!(TreeHashAlg::Blake3 as u8, 1);
    }

    #[test]
    fn unknown_algorithm_ids_are_refused_not_defaulted() {
        for v in [0u8, 6, 99, 255] {
            assert_eq!(AeadAlg::from_u8(v), Err(CryptoError::UnsupportedAlgorithm));
            assert!(KemAlg::from_u8(v).is_err(), "неизвестный kem_id {v} принят");
        }
        // ЧЕТВЁРКА ОТСЮДА УБРАНА, и это тот же случай, что с `SigAlg::from_u8(2)`
        // ниже. Она перестала быть неизвестным номером: её занял гибрид X-Wing
        // решением версии 4. Оставь её здесь — и проба утверждала бы, что формат
        // четвёртого механизма не знает, ровно тогда, когда он заработал.
        assert!(KemAlg::from_u8(4).is_ok(), "четвёрка занята гибридом X-Wing");
        // Пятёрка ушла отсюда по той же причине, что и четвёрка до неё: её занял
        // аппаратный гибрид MLKEM768-P256 решением версии 5. Список неизвестных
        // номеров тает с каждым занятым, и это нормально — он про НЕЗАНЯТЫЕ.
        assert!(KemAlg::from_u8(5).is_ok(), "пятёрка занята аппаратным гибридом");
        // `SigAlg::from_u8(2)` ЗДЕСЬ БОЛЬШЕ НЕ ПРОВЕРЯЕТСЯ, и это не упущение.
        // Двойка перестала быть неизвестным номером: она занята RSA-PSS решением
        // версии 3. Отказ остался тем же, но означает другое — «занято, не
        // исполняется», — и проба под именем «неизвестные номера» утверждала бы
        // неправду. Перенесено ниже, к своим соседям.
        assert_eq!(SigAlg::from_u8(3), Err(CryptoError::UnsupportedAlgorithm));
    }

    #[test]
    fn both_signature_algorithms_are_executable_and_numbered_stably() {
        // Обе схемы сборка теперь исполняет: Ed25519 подписывает автор, RSA-PSS
        // — редактировавшее устройство. Номера входят в подписанный транскрипт
        // (`verify::suite_id`), поэтому меняться местами не вправе.
        //
        // «Умеем исполнить» — не то же, что «годится здесь»: `suite.sig_alg`
        // допускает только Ed25519, и эту проверку ставит разбор заголовка. Она
        // проверяется там же, у своего места, а не здесь.
        assert_eq!(SigAlg::Ed25519 as u8, 1);
        assert_eq!(SigAlg::RsaPssSha256 as u8, 2);
        assert_eq!(SigAlg::from_u8(1), Ok(SigAlg::Ed25519));
        assert_eq!(SigAlg::from_u8(2), Ok(SigAlg::RsaPssSha256));
        assert_eq!(SigAlg::Ed25519.ensure_supported(), Ok(()));
        assert_eq!(SigAlg::RsaPssSha256.ensure_supported(), Ok(()));
    }

    #[test]
    fn an_aead_id_this_build_cannot_execute_is_refused_at_parse_time() {
        // Симметрично TreeHashAlg. Номера 2 и 3 в реестре формата существуют
        // (docs/format.md §6.1), но профилей AES в сборке нет, поэтому отказ
        // обязан приходить на разборе, а не на первом чанке — иначе подпись,
        // слот, согласование ключей и разворот CEK делаются впустую над файлом,
        // про который уже всё известно.
        for v in [2u8, 3] {
            assert_eq!(
                AeadAlg::from_u8(v),
                Err(CryptoError::UnsupportedAlgorithm),
                "aead_id {v} принят разбором, хотя исполнять его нечем"
            );
        }
        assert_eq!(AeadAlg::from_u8(1), Ok(AeadAlg::XChaCha20Poly1305));
    }
}
