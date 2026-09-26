// SPDX-License-Identifier: MPL-2.0
//! Edit certificates, editor signatures, session heads and revision verification.
//!
//! Checks author authorization for a revision. Accepted-revision counters require
//! host state; time is a parameter. Call after verifying the mutable-region MAC
//! and parsing its body through `ContentDesc::decode_verified_with_body`.

use crate::content::{ContentDesc, EditorSignature, FIRST_EDITING_VERSION, editor_tag, tag};
use crate::header::Header;
use crate::tlv::{FIELD_PREFIX_LEN, TlvReader, TlvWriter, UnknownTag, unknown_tag_action};
use crate::FormatError;
use oc_crypto::rsa::MODULUS_LEN;
use oc_crypto::sign::{PUBLIC_KEY_LEN, SIGNATURE_LEN, Signer};
use oc_crypto::transcript::Transcript;
use oc_crypto::{label, sha256};

/// Edit key certificate tags (`certified_by`), all critical.
pub mod cert_tag {
    pub const VERSION: u16 = 1;
    pub const FILE_ID: u16 = 2;
    pub const DEVICE: u16 = 3;
    pub const EDITOR_KEY: u16 = 4;
    pub const NOT_AFTER: u16 = 5;
    pub const ISSUER: u16 = 6;
    pub const SIGNATURE: u16 = 7;
}

/// Certificate layout version.
pub const CERT_VERSION: u8 = 1;

/// Edit key certificate: "device `device` has edit key `editor_key` for file
/// `file_id` until `not_after`", signed by `issuer`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditorCert {
    pub file_id: [u8; 16],
    pub device: [u8; 32],
    pub editor_key: [u8; MODULUS_LEN],
    pub not_after: i64,
    pub issuer: [u8; PUBLIC_KEY_LEN],
    pub signature: [u8; SIGNATURE_LEN],
}

/// Edit rejection: distinct reasons because each requires a different explanation to the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EditError {
    /// Region or certificate bytes cannot be parsed.
    Format(FormatError),
    /// Editor signature on an unedited file.
    EditorOnUnedited,
    /// Nonzero counter without an editor signature.
    UnsignedEdit { version: u64 },
    /// The file version does not support editor signatures.
    VersionTooOld { container_version: u16, version: u64 },
    /// The author did not allow editing.
    EditNotAllowed,
    /// The certificate was issued by neither the author nor a coauthor.
    ForeignIssuer,
    /// Certificate signature mismatch.
    BadCertificate,
    /// Certificate issued for another file.
    CertificateForOtherFile,
    /// Certificate expired.
    CertificateExpired { not_after: i64 },
    /// Editor signature mismatch.
    BadEditorSignature,
    /// Counter exhausted: no further edit is possible.
    CounterExhausted,
}

impl From<FormatError> for EditError {
    fn from(err: FormatError) -> Self {
        Self::Format(err)
    }
}

impl core::fmt::Display for EditError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Format(err) => write!(f, "правка не разбирается: {err:?}"),
            Self::EditorOnUnedited => write!(
                f,
                "у неправленого файла стоит подпись редактора: изменяемая область пересажена"
            ),
            Self::UnsignedEdit { version } => write!(
                f,
                "редакция {version} без подписи редактора: файл правил кто-то, чьих правок проверить нечем"
            ),
            Self::VersionTooOld { container_version, version } => write!(
                f,
                "редакция {version} в файле версии {container_version}: эта версия подписи редактора не знает"
            ),
            Self::EditNotAllowed => write!(f, "файл правлен, но автор правку не разрешал"),
            Self::ForeignIssuer => write!(
                f,
                "сертификат ключа правки выдан не автором и не соавтором файла"
            ),
            Self::BadCertificate => write!(f, "подпись сертификата ключа правки не сходится"),
            Self::CertificateForOtherFile => write!(f, "сертификат ключа правки выдан на другой файл"),
            Self::CertificateExpired { not_after } => {
                write!(f, "сертификат ключа правки истёк (действовал до {not_after})")
            }
            Self::BadEditorSignature => write!(f, "подпись редактора не сходится: правка подделана"),
            Self::CounterExhausted => write!(f, "счётчик редакций исчерпан"),
        }
    }
}

impl EditorCert {
    /// Unsigned body: tags 1–6.
    fn signed_body(&self) -> Result<Vec<u8>, FormatError> {
        let mut w = TlvWriter::new();
        w.put(cert_tag::VERSION, &[CERT_VERSION])?;
        w.put(cert_tag::FILE_ID, &self.file_id)?;
        w.put(cert_tag::DEVICE, &self.device)?;
        w.put(cert_tag::EDITOR_KEY, &self.editor_key)?;
        w.put(cert_tag::NOT_AFTER, &self.not_after.to_le_bytes())?;
        w.put(cert_tag::ISSUER, &self.issuer)?;
        Ok(w.finish().to_vec())
    }

    fn transcript(signed_body: &[u8]) -> Transcript {
        let mut t = Transcript::new(label::EDITOR_CERT);
        t.field(signed_body);
        t
    }

    /// Issue a certificate: sign and encode.
    ///
    /// # Errors
    /// [`FormatError`] if encoding or signing fails.
    pub fn issue(
        signer: &dyn Signer,
        file_id: [u8; 16],
        device: [u8; 32],
        editor_key: [u8; MODULUS_LEN],
        not_after: i64,
    ) -> Result<Vec<u8>, FormatError> {
        let mut cert = Self {
            file_id,
            device,
            editor_key,
            not_after,
            issuer: signer.public_key(),
            signature: [0u8; SIGNATURE_LEN],
        };
        let body = cert.signed_body()?;
        cert.signature =
            signer.sign(&Self::transcript(&body)).map_err(|_| FormatError::BadHeaderSignature)?;
        cert.encode()
    }

    /// Certificate bytes.
    ///
    /// # Errors
    /// [`FormatError`] if encoding fails.
    pub fn encode(&self) -> Result<Vec<u8>, FormatError> {
        let mut body = self.signed_body()?;
        let mut w = TlvWriter::new();
        w.put(cert_tag::SIGNATURE, &self.signature)?;
        body.extend_from_slice(&w.finish());
        Ok(body)
    }

    /// Parse the certificate and return it with the signed bytes.
    ///
    /// # Errors
    /// [`FormatError`] on any layout inconsistency.
    pub fn decode(bytes: &[u8]) -> Result<(Self, Vec<u8>), FormatError> {
        let mut reader = TlvReader::new(bytes);
        let mut version = None;
        let mut file_id = None;
        let mut device = None;
        let mut editor_key = None;
        let mut not_after = None;
        let mut issuer = None;
        let mut signature = None;
        let mut signed = Vec::with_capacity(bytes.len());
        while let Some(field) = reader.next_field()? {
            let start = field.span.start.checked_sub(FIELD_PREFIX_LEN).ok_or(FormatError::OffsetOverflow)?;
            let record = bytes.get(start..field.span.end).ok_or(FormatError::OffsetOverflow)?;
            if field.tag == cert_tag::SIGNATURE {
                signature = Some(field.array::<SIGNATURE_LEN>()?);
                continue;
            }
            signed.extend_from_slice(record);
            match field.tag {
                cert_tag::VERSION => version = Some(field.u8()?),
                cert_tag::FILE_ID => file_id = Some(field.array::<16>()?),
                cert_tag::DEVICE => device = Some(field.array::<32>()?),
                cert_tag::EDITOR_KEY => editor_key = Some(field.array::<MODULUS_LEN>()?),
                cert_tag::NOT_AFTER => not_after = Some(i64::from_le_bytes(field.array::<8>()?)),
                cert_tag::ISSUER => issuer = Some(field.array::<PUBLIC_KEY_LEN>()?),
                other => match unknown_tag_action(other) {
                    UnknownTag::Refuse => return Err(FormatError::UnknownCriticalField { tag: other }),
                    UnknownTag::Ignore => {}
                },
            }
        }
        let version = version.ok_or(FormatError::MissingField { tag: cert_tag::VERSION })?;
        if version != CERT_VERSION {
            return Err(FormatError::BadFieldLength { tag: cert_tag::VERSION, len: usize::from(version) });
        }
        let cert = Self {
            file_id: file_id.ok_or(FormatError::MissingField { tag: cert_tag::FILE_ID })?,
            device: device.ok_or(FormatError::MissingField { tag: cert_tag::DEVICE })?,
            editor_key: editor_key.ok_or(FormatError::MissingField { tag: cert_tag::EDITOR_KEY })?,
            not_after: not_after.ok_or(FormatError::MissingField { tag: cert_tag::NOT_AFTER })?,
            issuer: issuer.ok_or(FormatError::MissingField { tag: cert_tag::ISSUER })?,
            signature: signature.ok_or(FormatError::MissingField { tag: cert_tag::SIGNATURE })?,
        };
        Ok((cert, signed))
    }

    /// Verify the certificate for this header; check expiry at `now` if
    /// supplied.
    ///
    /// Not every caller checks expiry: a reader judges it using the accepted-revision journal
    /// (an already accepted revision opens even after expiry); then `now` here
    /// is `None`, and the stateful layer makes the decision.
    ///
    /// # Errors
    /// [`EditError`] for an unauthorized issuer, invalid signature, different file, or expiry.
    pub fn verify_for(bytes: &[u8], header: &Header, now: Option<i64>) -> Result<Self, EditError> {
        let (cert, signed) = Self::decode(bytes)?;
        // Выдавший — сначала: подпись, проверенная ключом из самого сертификата,
        // не доказывает ничего, пока ключ не узнан.
        let known = cert.issuer == header.author_key
            || header.coauthors.as_ref().is_some_and(|c| c.keys.contains(&cert.issuer));
        if !known {
            return Err(EditError::ForeignIssuer);
        }
        oc_crypto::sign::verify(&cert.issuer, &Self::transcript(&signed), &cert.signature)
            .map_err(|_| EditError::BadCertificate)?;
        if cert.file_id != header.file_id {
            return Err(EditError::CertificateForOtherFile);
        }
        if now.is_some_and(|now| now > cert.not_after) {
            return Err(EditError::CertificateExpired { not_after: cert.not_after });
        }
        Ok(cert)
    }
}

/// Mutable region body bytes without the `signature` subfield of record 6.
///
/// # Errors
/// [`FormatError`] if record 6 or its signature is absent, or the body cannot be parsed.
pub fn body_without_signature(body: &[u8]) -> Result<Vec<u8>, FormatError> {
    let mut reader = TlvReader::new(body);
    while let Some(field) = reader.next_field()? {
        if field.tag != tag::EDITOR {
            continue;
        }
        let mut inner = TlvReader::new(field.value);
        while let Some(sub) = inner.next_field()? {
            if sub.tag != editor_tag::SIGNATURE {
                continue;
            }
            let base = field.span.start;
            let cut_start = base
                .checked_add(sub.span.start)
                .and_then(|v| v.checked_sub(FIELD_PREFIX_LEN))
                .ok_or(FormatError::OffsetOverflow)?;
            let cut_end = base.checked_add(sub.span.end).ok_or(FormatError::OffsetOverflow)?;
            let mut out = Vec::with_capacity(body.len());
            out.extend_from_slice(body.get(..cut_start).ok_or(FormatError::OffsetOverflow)?);
            out.extend_from_slice(body.get(cut_end..).ok_or(FormatError::OffsetOverflow)?);
            return Ok(out);
        }
        return Err(FormatError::MissingField { tag: editor_tag::SIGNATURE });
    }
    Err(FormatError::MissingField { tag: tag::EDITOR })
}

/// Editor signature transcript (item C).
///
/// # Errors
/// [`FormatError`]: see [`body_without_signature`].
pub fn editor_transcript(core_hash: &[u8; 32], body: &[u8]) -> Result<Transcript, FormatError> {
    let cut = body_without_signature(body)?;
    let mut t = Transcript::new(label::EDITOR_SIG);
    t.fixed(core_hash);
    t.field(&cut);
    Ok(t)
}

/// Revision digest: SHA-256 of the editor signature transcript (item A).
#[must_use]
pub fn edition_digest(transcript: &Transcript) -> [u8; 32] {
    sha256(transcript.as_bytes())
}

/// Start of the session chain: the edit base (item D).
#[must_use]
pub fn session_start(file_id: &[u8; 16], base_counter: u64, base_root: &[u8; 32]) -> [u8; 32] {
    let mut t = Transcript::new(label::EDIT_SESSION);
    t.fixed(file_id);
    t.u64be(base_counter);
    t.fixed(base_root);
    sha256(t.as_bytes())
}

/// Session chain step: the `i`th save.
#[must_use]
pub fn session_step(prev: &[u8; 32], save: u64, root: &[u8; 32], total_len: u64) -> [u8; 32] {
    let mut t = Transcript::new(label::EDIT_SESSION);
    t.fixed(prev);
    t.u64be(save);
    t.fixed(root);
    t.u64be(total_len);
    sha256(t.as_bytes())
}

/// Verified revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedEdition {
    pub counter: u64,
    pub digest: [u8; 32],
    pub cert: EditorCert,
    pub session_head: [u8; 32],
}

/// Verify the revision (item F, step 13 a–f).
///
/// `Ok(None)` means the file is unedited: the caller compares `tree_root` with
/// `original_root` as before. `Ok(Some(..))` means the edit is signed by someone
/// authorized by the author, and `tree_root` is authenticated by the editor.
///
/// `now = None` means certificate expiry is not checked here: the layer holding
/// the accepted-revision journal judges it (item B).
///
/// # Errors
/// [`EditError`] according to the cause.
pub fn verify_edition(
    header: &Header,
    core_hash: &[u8; 32],
    desc: &ContentDesc,
    body: &[u8],
    now: Option<i64>,
) -> Result<Option<VerifiedEdition>, EditError> {
    let Some(editor) = &desc.editor else {
        if desc.version_counter == 0 {
            return Ok(None);
        }
        if header.container_version < FIRST_EDITING_VERSION {
            return Err(EditError::VersionTooOld {
                container_version: header.container_version,
                version: desc.version_counter,
            });
        }
        return Err(EditError::UnsignedEdit { version: desc.version_counter });
    };
    if desc.version_counter == 0 {
        return Err(EditError::EditorOnUnedited);
    }
    // Разбор тега 6 уже отвергает его в версиях ниже четвёртой; повтор здесь —
    // не недоверие к разбору, а то, что решение принимается у места.
    if header.container_version < FIRST_EDITING_VERSION {
        return Err(EditError::VersionTooOld {
            container_version: header.container_version,
            version: desc.version_counter,
        });
    }
    if !header.policy.actions.contains_key(&oc_policy::Action::Edit) {
        return Err(EditError::EditNotAllowed);
    }
    let cert = EditorCert::verify_for(&editor.certified_by, header, now)?;
    let transcript = editor_transcript(core_hash, body)?;
    oc_crypto::rsa::verify_pss_sha256(&cert.editor_key, transcript.as_bytes(), &editor.signature)
        .map_err(|_| EditError::BadEditorSignature)?;
    Ok(Some(VerifiedEdition {
        counter: desc.version_counter,
        digest: edition_digest(&transcript),
        cert,
        session_head: editor.session_head,
    }))
}

/// Draft editor signature: everything except the signature itself.
///
/// The signature is filled with zeros: the transcript omits it (item C), so
/// the signed bytes do not depend on its value.
#[must_use]
pub fn unsigned_editor(
    session_head: [u8; 32],
    journal_head: Option<crate::content::JournalHead>,
    certified_by: Vec<u8>,
) -> EditorSignature {
    EditorSignature {
        sig_alg: oc_crypto::SigAlg::RsaPssSha256,
        session_head,
        journal_head,
        certified_by,
        signature: vec![0u8; MODULUS_LEN],
    }
}

/// The counter following the base.
///
/// # Errors
/// [`EditError::CounterExhausted`] if the limit prevents further edits.
pub fn next_counter(base: u64) -> Result<u64, EditError> {
    base.checked_add(1).ok_or(EditError::CounterExhausted)
}

/// Revision submission tags (`docs/protocol.md` §9.12), all critical.
pub mod claim_tag {
    pub const FILE_ID: u16 = 1;
    pub const COUNTER: u16 = 2;
    pub const BASE_DIGEST: u16 = 3;
    pub const DIGEST: u16 = 4;
    pub const SESSION_HEAD: u16 = 5;
    pub const CERTIFIED_BY: u16 = 6;
    pub const AT: u16 = 7;
    pub const SIGNATURE: u16 = 8;
}

/// Revision submission to the server: "base `base_digest` produced revision
/// `counter` with digest `digest`", signed with the certificate's edit key.
///
/// No proof of possession of the device key is required: the author's certificate
/// grants authority, while the edit key signature proves possession of that key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EditionClaimDoc {
    pub file_id: [u8; 16],
    pub counter: u64,
    /// Base digest; zeros for an unedited file.
    pub base_digest: [u8; 32],
    pub digest: [u8; 32],
    pub session_head: [u8; 32],
    pub certified_by: Vec<u8>,
    /// Signing time, for freshness as with orders.
    pub at: i64,
}

impl EditionClaimDoc {
    fn body(&self) -> Result<Vec<u8>, FormatError> {
        let mut w = TlvWriter::new();
        w.put(claim_tag::FILE_ID, &self.file_id)?;
        w.put(claim_tag::COUNTER, &self.counter.to_le_bytes())?;
        w.put(claim_tag::BASE_DIGEST, &self.base_digest)?;
        w.put(claim_tag::DIGEST, &self.digest)?;
        w.put(claim_tag::SESSION_HEAD, &self.session_head)?;
        w.put(claim_tag::CERTIFIED_BY, &self.certified_by)?;
        w.put(claim_tag::AT, &self.at.to_le_bytes())?;
        Ok(w.finish().to_vec())
    }

    /// Transcript to sign with the edit key.
    ///
    /// # Errors
    /// [`FormatError`] if encoding fails.
    pub fn transcript(&self) -> Result<Transcript, FormatError> {
        let mut t = Transcript::new(label::EDITION_CLAIM);
        t.field(&self.body()?);
        Ok(t)
    }

    /// Submission bytes including the signature.
    ///
    /// # Errors
    /// [`FormatError`] if encoding fails.
    pub fn encode(&self, signature: &[u8; MODULUS_LEN]) -> Result<Vec<u8>, FormatError> {
        let mut out = self.body()?;
        let mut w = TlvWriter::new();
        w.put(claim_tag::SIGNATURE, signature)?;
        out.extend_from_slice(&w.finish());
        Ok(out)
    }

    /// Parse and VERIFY the submission: certificate (issued by `author` or one
    /// of `coauthors`), certificate expiry at `now`, and edit key signature.
    ///
    /// # Errors
    /// [`EditError`] according to the cause.
    pub fn verify(
        bytes: &[u8],
        author: &[u8; PUBLIC_KEY_LEN],
        coauthors: &[[u8; PUBLIC_KEY_LEN]],
        now: i64,
    ) -> Result<(Self, EditorCert), EditError> {
        let mut reader = TlvReader::new(bytes);
        let mut file_id = None;
        let mut counter = None;
        let mut base_digest = None;
        let mut digest = None;
        let mut session_head = None;
        let mut certified_by = None;
        let mut at = None;
        let mut signature = None;
        while let Some(field) = reader.next_field()? {
            match field.tag {
                claim_tag::FILE_ID => file_id = Some(field.array::<16>()?),
                claim_tag::COUNTER => counter = Some(field.u64()?),
                claim_tag::BASE_DIGEST => base_digest = Some(field.array::<32>()?),
                claim_tag::DIGEST => digest = Some(field.array::<32>()?),
                claim_tag::SESSION_HEAD => session_head = Some(field.array::<32>()?),
                claim_tag::CERTIFIED_BY => {
                    if field.value.len() > crate::content::MAX_CERTIFIED_BY_LEN {
                        return Err(FormatError::BadFieldLength { tag: field.tag, len: field.value.len() }.into());
                    }
                    certified_by = Some(field.value.to_vec());
                }
                claim_tag::AT => at = Some(i64::from_le_bytes(field.array::<8>()?)),
                claim_tag::SIGNATURE => signature = Some(field.array::<MODULUS_LEN>()?),
                other => match unknown_tag_action(other) {
                    UnknownTag::Refuse => return Err(FormatError::UnknownCriticalField { tag: other }.into()),
                    UnknownTag::Ignore => {}
                },
            }
        }
        let doc = Self {
            file_id: file_id.ok_or(FormatError::MissingField { tag: claim_tag::FILE_ID })?,
            counter: counter.ok_or(FormatError::MissingField { tag: claim_tag::COUNTER })?,
            base_digest: base_digest.ok_or(FormatError::MissingField { tag: claim_tag::BASE_DIGEST })?,
            digest: digest.ok_or(FormatError::MissingField { tag: claim_tag::DIGEST })?,
            session_head: session_head.ok_or(FormatError::MissingField { tag: claim_tag::SESSION_HEAD })?,
            certified_by: certified_by.ok_or(FormatError::MissingField { tag: claim_tag::CERTIFIED_BY })?,
            at: at.ok_or(FormatError::MissingField { tag: claim_tag::AT })?,
        };
        let signature = signature.ok_or(FormatError::MissingField { tag: claim_tag::SIGNATURE })?;
        if doc.counter == 0 {
            return Err(EditError::UnsignedEdit { version: 0 });
        }

        let (cert, signed) = EditorCert::decode(&doc.certified_by)?;
        if cert.issuer != *author && !coauthors.contains(&cert.issuer) {
            return Err(EditError::ForeignIssuer);
        }
        oc_crypto::sign::verify(&cert.issuer, &EditorCert::transcript(&signed), &cert.signature)
            .map_err(|_| EditError::BadCertificate)?;
        if cert.file_id != doc.file_id {
            return Err(EditError::CertificateForOtherFile);
        }
        if now > cert.not_after {
            return Err(EditError::CertificateExpired { not_after: cert.not_after });
        }
        oc_crypto::rsa::verify_pss_sha256(&cert.editor_key, doc.transcript()?.as_bytes(), &signature)
            .map_err(|_| EditError::BadEditorSignature)?;
        Ok((doc, cert))
    }
}
