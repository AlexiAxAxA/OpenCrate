//! Revocation: a server-signed "file revoked" document.
//!
//! # Why a document when revocation already works
//!
//! Revocation works by the server ceasing to issue leases, so it reaches
//! only those who contact the server. A revocation document makes revocation DATA:
//! a document signed with the lease-signing key that a reader accepts
//! from anywhere: a subscription, a query, a file beside the container, or a
//! peer. The channel is no longer the only route (F-18, tier 3).
//!
//! It cannot be forged without the server key; spreading a genuine document means
//! spreading the truth. It is verified with the same key as a lease: the author
//! pinned it in the container header under their signature, so revocation introduces
//! no second trust root.
//!
//! # Layout
//!
//! Like a lease: `signature(64) ‖ body`, the body is TLV under I-7 and I-8;
//! the signature transcript uses label `"CC/v1/revocation"` from the shared registry in §3.6
//! (the label was reserved earlier and had not been used before this date).
//! Revocation is final: the epoch in the document serves journals and reports, not
//! comparisons of "which revocation is newer".

use oc_crypto::CryptoError;

use oc_format::FormatError;
use oc_format::tlv::{TlvReader, TlvWriter};

/// Document version. Independent of the container version.
pub const REVOCATION_VERSION: u16 = 1;

/// Signature length before the body.
pub const SIGNATURE_LEN: usize = 64;

/// Body tags. All critical: unknown means rejection.
pub mod tag {
    /// `u16le`.
    pub const VERSION: u16 = 1;
    /// `bytes[16]`.
    pub const FILE_ID: u16 = 2;
    /// File epoch after revocation. `u64le`.
    pub const EPOCH: u16 = 3;
    /// Revocation time according to the server clock. `i64le`, seconds.
    pub const AT: u16 = 4;
}

/// Parsed revocation document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Revocation {
    pub file_id: [u8; 16],
    pub epoch: u64,
    pub at: i64,
}

/// Signature transcript through [`oc_crypto::Transcript`], which requires a label.
#[must_use]
pub fn signing_transcript(body: &[u8]) -> oc_crypto::Transcript {
    let mut t = oc_crypto::Transcript::new(oc_crypto::label::REVOCATION);
    t.field(body);
    t
}

/// Build the body. The key holder applies the signature.
///
/// # Errors
/// [`FormatError`] if the body cannot be encoded.
pub fn encode(revocation: &Revocation) -> Result<Vec<u8>, FormatError> {
    let mut w = TlvWriter::new();
    w.put(tag::VERSION, &REVOCATION_VERSION.to_le_bytes())?;
    w.put(tag::FILE_ID, &revocation.file_id)?;
    w.put(tag::EPOCH, &revocation.epoch.to_le_bytes())?;
    w.put(tag::AT, &revocation.at.to_le_bytes())?;
    Ok(w.finish().to_vec())
}

/// Parse the body. The signature is NOT checked here; see [`verify_signed`].
///
/// # Errors
/// [`FormatError`] for an unknown tag, inexact length or missing field.
pub fn decode(body: &[u8]) -> Result<Revocation, FormatError> {
    let mut reader = TlvReader::new(body);
    let mut version = None;
    let mut file_id = None;
    let mut epoch = None;
    let mut at = None;
    while let Some(field) = reader.next_field()? {
        match field.tag {
            tag::VERSION => version = Some(u16_le(field.tag, field.value)?),
            tag::FILE_ID => file_id = Some(exact16(field.tag, field.value)?),
            tag::EPOCH => epoch = Some(u64_le(field.tag, field.value)?),
            tag::AT => at = Some(u64_le(field.tag, field.value)?.cast_signed()),
            other => crate::unknown::refuse_if_critical(other)?,
        }
    }
    if version.ok_or(FormatError::MissingField { tag: tag::VERSION })? != REVOCATION_VERSION {
        return Err(FormatError::UnknownCriticalField { tag: tag::VERSION });
    }
    Ok(Revocation {
        file_id: file_id.ok_or(FormatError::MissingField { tag: tag::FILE_ID })?,
        epoch: epoch.ok_or(FormatError::MissingField { tag: tag::EPOCH })?,
        at: at.ok_or(FormatError::MissingField { tag: tag::AT })?,
    })
}

/// Verify the body signature with the lease-signing key from the container header.
///
/// # Errors
/// [`CryptoError`] if the signature does not verify.
pub fn verify(
    body: &[u8],
    signature: &[u8; SIGNATURE_LEN],
    lease_verify_key: &[u8; 32],
) -> Result<(), CryptoError> {
    oc_crypto::sign::verify(lease_verify_key, &signing_transcript(body), signature)
}

/// Verify the signature, then parse: in this order only.
///
/// Parsing unauthenticated bytes would yield distinguishable rejections for data that nobody
/// signed (I-5 for documents). The caller checks that `file_id` matches the container:
/// there is no container here.
///
/// # Errors
/// [`FormatError::BadHeaderSignature`] for a short or invalid signature;
/// otherwise, parsing errors.
pub fn verify_signed(bytes: &[u8], lease_verify_key: &[u8; 32]) -> Result<Revocation, FormatError> {
    let (signature, body) =
        bytes.split_at_checked(SIGNATURE_LEN).ok_or(FormatError::BadHeaderSignature)?;
    let signature: [u8; SIGNATURE_LEN] =
        signature.try_into().map_err(|_| FormatError::BadHeaderSignature)?;
    verify(body, &signature, lease_verify_key).map_err(|_| FormatError::BadHeaderSignature)?;
    decode(body)
}

fn exact16(tag: u16, value: &[u8]) -> Result<[u8; 16], FormatError> {
    value.try_into().map_err(|_| FormatError::BadFieldLength { tag, len: value.len() })
}

fn u16_le(tag: u16, value: &[u8]) -> Result<u16, FormatError> {
    let bytes: [u8; 2] =
        value.try_into().map_err(|_| FormatError::BadFieldLength { tag, len: value.len() })?;
    Ok(u16::from_le_bytes(bytes))
}

fn u64_le(tag: u16, value: &[u8]) -> Result<u64, FormatError> {
    let bytes: [u8; 8] =
        value.try_into().map_err(|_| FormatError::BadFieldLength { tag, len: value.len() })?;
    Ok(u64::from_le_bytes(bytes))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use oc_crypto::sign::{Ed25519Signer, Signer};

    fn signed(revocation: &Revocation, signer: &Ed25519Signer) -> Vec<u8> {
        let body = encode(revocation).unwrap();
        let sig = signer.sign(&signing_transcript(&body)).unwrap();
        let mut out = sig.to_vec();
        out.extend_from_slice(&body);
        out
    }

    /// A signed revocation passes with its own key and is rejected with a foreign key, corrupt
    /// signature, corrupt body or short document.
    #[test]
    fn a_signed_revocation_verifies_with_the_lease_key_and_nothing_else_passes() {
        let server = Ed25519Signer::from_seed(&[0x41; 32]);
        let stranger = Ed25519Signer::from_seed(&[0x42; 32]);
        let doc = Revocation { file_id: [0x5a; 16], epoch: 3, at: 1_755_561_600 };
        let bytes = signed(&doc, &server);

        assert_eq!(verify_signed(&bytes, &server.public_key()).unwrap(), doc);
        assert!(verify_signed(&bytes, &stranger.public_key()).is_err(), "чужой ключ принят");

        let mut bad_sig = bytes.clone();
        bad_sig[10] ^= 1;
        assert!(verify_signed(&bad_sig, &server.public_key()).is_err(), "битая подпись принята");

        let mut bad_body = bytes.clone();
        let last = bad_body.len() - 1;
        bad_body[last] ^= 1;
        assert!(verify_signed(&bad_body, &server.public_key()).is_err(), "битое тело принято");

        assert!(verify_signed(&bytes[..40], &server.public_key()).is_err(), "обрубок принят");
    }

    /// THE SIGNATURE IS VERIFIED BEFORE BODY PARSING: a guard on the order of two lines.
    ///
    /// The adjacent test supplies a parseable body, and parsing tests call [`decode`]
    /// directly, so moving `decode` before `verify` inside
    /// [`verify_signed`] broke none of them. Nobody tested the case combining both
    /// conditions, an unparseable body AND a wrong signature; yet that is precisely
    /// the case this combinator exists for: distinct parsing error codes
    /// returned for unauthenticated bytes form a parsing oracle (I-5 for documents).
    #[test]
    fn the_signature_is_checked_before_the_body_is_parsed() {
        let server = Ed25519Signer::from_seed(&[0x41; 32]);
        let stranger = Ed25519Signer::from_seed(&[0x42; 32]);

        // Два способа быть неразбираемым: нет обязательного поля и незнакомый
        // критичный тег — ветки разбора у них разные.
        let empty = TlvWriter::new().finish().to_vec();
        let mut w = TlvWriter::new();
        w.put(0x7FFF, &[0xab; 4]).unwrap();
        let unknown_critical = w.finish().to_vec();

        for (what, body) in [("пустое тело", empty), ("чужой критичный тег", unknown_critical)] {
            assert!(decode(&body).is_err(), "{what}: предпосылка пробы неверна, тело разбирается");
            let sig = stranger.sign(&signing_transcript(&body)).unwrap();
            let mut bytes = sig.to_vec();
            bytes.extend_from_slice(&body);
            let outcome = verify_signed(&bytes, &server.public_key());
            assert!(
                matches!(outcome, Err(FormatError::BadHeaderSignature)),
                "{what}: разбор произошёл до проверки подписи, ответ {outcome:?}"
            );
        }
    }

    /// Body: unknown tag rejected; inexact length rejected; wrong version rejected.
    #[test]
    fn the_body_is_parsed_strictly() {
        let doc = Revocation { file_id: [1; 16], epoch: 0, at: 0 };
        let body = encode(&doc).unwrap();
        assert_eq!(decode(&body).unwrap(), doc);

        let mut w = TlvWriter::new();
        w.put(tag::VERSION, &REVOCATION_VERSION.to_le_bytes()).unwrap();
        w.put(tag::FILE_ID, &[1; 15]).unwrap();
        w.put(tag::EPOCH, &0u64.to_le_bytes()).unwrap();
        w.put(tag::AT, &0i64.to_le_bytes()).unwrap();
        assert!(decode(&w.finish()).is_err(), "короткий идентификатор дополнен");

        let mut w = TlvWriter::new();
        w.put(tag::VERSION, &2u16.to_le_bytes()).unwrap();
        w.put(tag::FILE_ID, &[1; 16]).unwrap();
        w.put(tag::EPOCH, &0u64.to_le_bytes()).unwrap();
        w.put(tag::AT, &0i64.to_le_bytes()).unwrap();
        assert!(decode(&w.finish()).is_err(), "чужая версия принята");
    }
}
