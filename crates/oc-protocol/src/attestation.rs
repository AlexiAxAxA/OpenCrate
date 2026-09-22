//! Device key attestation documents on the wire (B6b, `docs/protocol.md`
//! §9.11.1).
//!
//! # Three steps, and why not two
//!
//! The model in §9.11 has two verifier moves: credentials for the attestation
//! key's name under the EK, then the secret and the attestation. The Windows provider works differently:
//! the attestation key is created TOGETHER with the attestation (`KAST` wrapper, B6b measurement), and
//! the attestation needs the verifier's challenge beforehand. Hence three wire steps:
//!
//! 1. The device requests a challenge; the server responds with `Nonce`.
//! 2. The device sends complete `Evidence`: EK, attestation key and attestation
//!    with that challenge, and receives credentials.
//! 3. The device returns the decrypted secret; the server delivers its verdict.
//!
//! All three requests follow proof of possession and are protected by the session MAC (K25):
//! attestation concerns the key whose possession was proved in this same
//! conversation, not a key merely named by the peer.
//!
//! # What is not verified here
//!
//! TPM structures and certificates within are bytes: the verifier parses them
//! (`cc_authority::attest`), strictly and with its own limits. This module handles only
//! the document layout and length caps, so that envelope parsing cannot allocate memory
//! based solely on the sender's claims.

use oc_format::tlv::{TlvReader, TlvWriter};
use oc_format::FormatError;

/// `TPM2B_PUBLIC` size cap.
pub const MAX_PUBLIC: usize = 1026;
/// Certificate size cap.
pub const MAX_CERTIFICATE: usize = 8 * 1024;
/// Number of intermediate certificates accepted: the chain is at most four certificates long.
pub const MAX_INTERMEDIATES: usize = 2;
/// `TPMS_ATTEST` size cap.
pub const MAX_ATTEST: usize = 1024;
/// `TPMT_SIGNATURE` size cap.
pub const MAX_SIGNATURE: usize = 600;
/// Credential size cap: `TPM2B_ID_OBJECT ‖ TPM2B_ENCRYPTED_SECRET`.
pub const MAX_CREDENTIAL: usize = 2 + 132 + 2 + 512;
/// Length of the challenge and credential secret.
pub const SECRET_LEN: usize = 32;

/// Basis of trust in the endorsement key, as stated by the verdict.
pub mod basis {
    /// Vendor certificate chaining to the deployment root.
    pub const VENDOR_CERTIFICATE: u8 = 1;
    /// Endorsement key pinned by the administrator.
    pub const ENROLLED_EK: u8 = 2;
}

/// Evidence tags.
pub mod evidence_tag {
    /// Endorsement key's `TPM2B_PUBLIC`.
    pub const EK_PUBLIC: u16 = 1;
    /// EK certificate (DER). Optional: many TPMs do not have one.
    pub const EK_CERTIFICATE: u16 = 2;
    /// Intermediate certificates: consecutive `u16be(len) ‖ der`, at most two.
    pub const INTERMEDIATES: u16 = 3;
    /// Attestation key's `TPM2B_PUBLIC`.
    pub const IDENTITY_PUBLIC: u16 = 4;
    /// `TPMS_ATTEST` bytes, as signed by the TPM.
    pub const ATTEST: u16 = 5;
    /// The `TPMT_SIGNATURE` over them.
    pub const SIGNATURE: u16 = 6;
    /// `TPM2B_PUBLIC` of the device key being attested.
    pub const DEVICE_PUBLIC: u16 = 7;
}

/// Everything the device presents about its key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evidence {
    pub ek_public: Vec<u8>,
    pub ek_certificate: Option<Vec<u8>>,
    pub intermediates: Vec<Vec<u8>>,
    pub identity_public: Vec<u8>,
    pub attest: Vec<u8>,
    pub signature: Vec<u8>,
    pub device_public: Vec<u8>,
}

fn bounded(tag: u16, value: &[u8], limit: usize) -> Result<Vec<u8>, FormatError> {
    if value.is_empty() || value.len() > limit {
        return Err(FormatError::BadFieldLength { tag, len: value.len() });
    }
    Ok(value.to_vec())
}

/// Encode evidence.
///
/// # Errors
/// [`FormatError`]: an empty or oversized field, or more than two intermediates.
pub fn encode_evidence(e: &Evidence) -> Result<Vec<u8>, FormatError> {
    let mut w = TlvWriter::new();
    w.put(evidence_tag::EK_PUBLIC, &bounded(evidence_tag::EK_PUBLIC, &e.ek_public, MAX_PUBLIC)?)?;
    if let Some(cert) = &e.ek_certificate {
        w.put(evidence_tag::EK_CERTIFICATE, &bounded(evidence_tag::EK_CERTIFICATE, cert, MAX_CERTIFICATE)?)?;
    }
    if !e.intermediates.is_empty() {
        if e.intermediates.len() > MAX_INTERMEDIATES {
            return Err(FormatError::BadFieldLength { tag: evidence_tag::INTERMEDIATES, len: e.intermediates.len() });
        }
        let mut chain = Vec::new();
        for cert in &e.intermediates {
            let cert = bounded(evidence_tag::INTERMEDIATES, cert, MAX_CERTIFICATE)?;
            let len = u16::try_from(cert.len())
                .map_err(|_| FormatError::BadFieldLength { tag: evidence_tag::INTERMEDIATES, len: cert.len() })?;
            chain.extend_from_slice(&len.to_be_bytes());
            chain.extend_from_slice(&cert);
        }
        w.put(evidence_tag::INTERMEDIATES, &chain)?;
    }
    w.put(evidence_tag::IDENTITY_PUBLIC, &bounded(evidence_tag::IDENTITY_PUBLIC, &e.identity_public, MAX_PUBLIC)?)?;
    w.put(evidence_tag::ATTEST, &bounded(evidence_tag::ATTEST, &e.attest, MAX_ATTEST)?)?;
    w.put(evidence_tag::SIGNATURE, &bounded(evidence_tag::SIGNATURE, &e.signature, MAX_SIGNATURE)?)?;
    w.put(evidence_tag::DEVICE_PUBLIC, &bounded(evidence_tag::DEVICE_PUBLIC, &e.device_public, MAX_PUBLIC)?)?;
    Ok(w.finish().to_vec())
}

/// Decode evidence.
///
/// # Errors
/// [`FormatError`]: tag ordering, unknown tag, length or missing field.
pub fn decode_evidence(bytes: &[u8]) -> Result<Evidence, FormatError> {
    if bytes.len() > crate::activation::MAX_DOCUMENT {
        return Err(FormatError::OffsetOverflow);
    }
    let mut reader = TlvReader::new(bytes);
    let (mut ek_public, mut ek_certificate, mut intermediates) = (None, None, Vec::new());
    let (mut identity_public, mut attest, mut signature, mut device_public) = (None, None, None, None);
    while let Some(field) = reader.next_field()? {
        let (tag, value) = (field.tag, field.value);
        match tag {
            evidence_tag::EK_PUBLIC => ek_public = Some(bounded(tag, value, MAX_PUBLIC)?),
            evidence_tag::EK_CERTIFICATE => ek_certificate = Some(bounded(tag, value, MAX_CERTIFICATE)?),
            evidence_tag::INTERMEDIATES => {
                let mut rest = value;
                if rest.is_empty() {
                    return Err(FormatError::BadFieldLength { tag, len: 0 });
                }
                while !rest.is_empty() {
                    if intermediates.len() >= MAX_INTERMEDIATES {
                        return Err(FormatError::BadFieldLength { tag, len: value.len() });
                    }
                    let (len, tail) = rest
                        .split_first_chunk::<2>()
                        .ok_or(FormatError::BadFieldLength { tag, len: value.len() })?;
                    let (cert, tail) = tail
                        .split_at_checked(usize::from(u16::from_be_bytes(*len)))
                        .ok_or(FormatError::BadFieldLength { tag, len: value.len() })?;
                    intermediates.push(bounded(tag, cert, MAX_CERTIFICATE)?);
                    rest = tail;
                }
            }
            evidence_tag::IDENTITY_PUBLIC => identity_public = Some(bounded(tag, value, MAX_PUBLIC)?),
            evidence_tag::ATTEST => attest = Some(bounded(tag, value, MAX_ATTEST)?),
            evidence_tag::SIGNATURE => signature = Some(bounded(tag, value, MAX_SIGNATURE)?),
            evidence_tag::DEVICE_PUBLIC => device_public = Some(bounded(tag, value, MAX_PUBLIC)?),
            other => crate::unknown::refuse_if_critical(other)?,
        }
    }
    Ok(Evidence {
        ek_public: ek_public.ok_or(FormatError::MissingField { tag: evidence_tag::EK_PUBLIC })?,
        ek_certificate,
        intermediates,
        identity_public: identity_public.ok_or(FormatError::MissingField { tag: evidence_tag::IDENTITY_PUBLIC })?,
        attest: attest.ok_or(FormatError::MissingField { tag: evidence_tag::ATTEST })?,
        signature: signature.ok_or(FormatError::MissingField { tag: evidence_tag::SIGNATURE })?,
        device_public: device_public.ok_or(FormatError::MissingField { tag: evidence_tag::DEVICE_PUBLIC })?,
    })
}

/// Credentials: `TPM2B_ID_OBJECT ‖ TPM2B_ENCRYPTED_SECRET`, the layout
/// accepted by the Windows provider's activation property (B6b measurement).
///
/// # Errors
/// [`FormatError`]: empty, oversized or fields inconsistent with the length.
pub fn check_credential(bytes: &[u8]) -> Result<(), FormatError> {
    let bad = || FormatError::BadFieldLength { tag: 0, len: bytes.len() };
    if bytes.is_empty() || bytes.len() > MAX_CREDENTIAL {
        return Err(bad());
    }
    let (first, rest) = bytes.split_first_chunk::<2>().ok_or_else(bad)?;
    let (_, rest) = rest.split_at_checked(usize::from(u16::from_be_bytes(*first))).ok_or_else(bad)?;
    let (second, rest) = rest.split_first_chunk::<2>().ok_or_else(bad)?;
    if rest.len() != usize::from(u16::from_be_bytes(*second)) {
        return Err(bad());
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn sample() -> Evidence {
        Evidence {
            ek_public: vec![1; 316],
            ek_certificate: Some(vec![2; 900]),
            intermediates: vec![vec![3; 800], vec![4; 700]],
            identity_public: vec![5; 282],
            attest: vec![6; 173],
            signature: vec![7; 262],
            device_public: vec![8; 90],
        }
    }

    #[test]
    fn evidence_round_trips_with_and_without_optional_fields() {
        let full = sample();
        assert_eq!(decode_evidence(&encode_evidence(&full).unwrap()).unwrap(), full);
        let bare = Evidence { ek_certificate: None, intermediates: vec![], ..sample() };
        assert_eq!(decode_evidence(&encode_evidence(&bare).unwrap()).unwrap(), bare);
    }

    #[test]
    fn evidence_limits_are_enforced_both_ways() {
        let three = Evidence { intermediates: vec![vec![3; 10]; 3], ..sample() };
        assert!(encode_evidence(&three).is_err());
        let long = Evidence { attest: vec![0; MAX_ATTEST + 1], ..sample() };
        assert!(encode_evidence(&long).is_err());
        let empty = Evidence { signature: vec![], ..sample() };
        assert!(encode_evidence(&empty).is_err());

        // Три промежуточных, собранные руками, разбор не принимает.
        let bytes = encode_evidence(&Evidence { intermediates: vec![vec![3; 10]; 2], ..sample() }).unwrap();
        let mut w = TlvWriter::new();
        let mut chain = Vec::new();
        for _ in 0..3 {
            chain.extend_from_slice(&10u16.to_be_bytes());
            chain.extend_from_slice(&[3; 10]);
        }
        w.put(evidence_tag::EK_PUBLIC, &[1; 4]).unwrap();
        w.put(evidence_tag::INTERMEDIATES, &chain).unwrap();
        assert!(decode_evidence(&w.finish()).is_err());
        // Обрыв и хвост.
        assert!(decode_evidence(&bytes[..bytes.len() - 1]).is_err());
        let mut tail = bytes;
        tail.push(0);
        assert!(decode_evidence(&tail).is_err());
    }

    #[test]
    fn a_credential_must_be_exactly_two_sized_fields() {
        let mut good = vec![0, 2, 9, 9, 0, 3, 1, 2, 3];
        assert!(check_credential(&good).is_ok());
        good.push(0);
        assert!(check_credential(&good).is_err());
        assert!(check_credential(&[0, 2, 9, 9, 0, 3, 1, 2]).is_err());
        assert!(check_credential(&[]).is_err());
    }
}
