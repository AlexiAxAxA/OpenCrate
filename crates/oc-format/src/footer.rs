//! Footer: self-authenticating content after the frames (`docs/format.md`, "FOOTER AND
//! TIMESTAMP", decision 2026-09-17, D3).
//!
//! This module contains the footer bytes and the imprint timestamped by the time service.
//! Parsing the timestamp itself (CMS, X.509) lives in `cc_cli::notary`: a pure crate
//! does not need certificates, but every reader needs the imprint.

use crate::FormatError;
use crate::tlv::{TlvReader, TlvWriter, UnknownTag, unknown_tag_action};
use oc_crypto::transcript::Transcript;
use oc_crypto::{label, sha256};

/// Footer tags.
pub mod tag {
    /// RFC 3161 timestamp (`TimeStampToken`, DER).
    pub const TIMESTAMP: u16 = 1;
}

/// Upper bound on the footer.
pub const MAX_FOOTER_LEN: usize = 32 * 1024;

/// Upper bound on the timestamp.
pub const MAX_TOKEN_LEN: usize = 16 * 1024;

/// Parsed footer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Footer {
    /// The timestamp is currently the footer's sole content and is required:
    /// an empty footer attests nothing and would merely shift the boundary.
    pub timestamp: Vec<u8>,
}

impl Footer {
    /// Footer bytes.
    ///
    /// # Errors
    /// [`FormatError`] if the timestamp exceeds the limit or encoding fails.
    pub fn encode(&self) -> Result<Vec<u8>, FormatError> {
        if self.timestamp.is_empty() || self.timestamp.len() > MAX_TOKEN_LEN {
            return Err(FormatError::BadFieldLength { tag: tag::TIMESTAMP, len: self.timestamp.len() });
        }
        let mut w = TlvWriter::new();
        w.put(tag::TIMESTAMP, &self.timestamp)?;
        Ok(w.finish().to_vec())
    }

    /// Parse the entire footer: the bytes from its offset to the end of the file.
    ///
    /// # Errors
    /// [`FormatError`] on a limit violation, truncation, unknown critical tag, or missing timestamp.
    pub fn decode(bytes: &[u8]) -> Result<Self, FormatError> {
        if bytes.len() > MAX_FOOTER_LEN {
            return Err(FormatError::BadFieldLength { tag: 0, len: bytes.len() });
        }
        let mut reader = TlvReader::new(bytes);
        let mut timestamp = None;
        while let Some(field) = reader.next_field()? {
            match field.tag {
                tag::TIMESTAMP => {
                    if field.value.is_empty() || field.value.len() > MAX_TOKEN_LEN {
                        return Err(FormatError::BadFieldLength { tag: field.tag, len: field.value.len() });
                    }
                    timestamp = Some(field.value.to_vec());
                }
                other => match unknown_tag_action(other) {
                    UnknownTag::Refuse => return Err(FormatError::UnknownCriticalField { tag: other }),
                    UnknownTag::Ignore => {}
                },
            }
        }
        Ok(Self { timestamp: timestamp.ok_or(FormatError::MissingField { tag: tag::TIMESTAMP })? })
    }
}

/// File imprint for the timestamp (item B).
#[must_use]
pub fn imprint(core_hash: &[u8; 32], tree_root: &[u8; 32], total_len: u64, version_counter: u64) -> [u8; 32] {
    let mut t = Transcript::new(label::FOOTER_IMPRINT);
    t.fixed(core_hash);
    t.fixed(tree_root);
    t.u64be(total_len);
    t.u64be(version_counter);
    sha256(t.as_bytes())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn a_footer_round_trips_and_refuses_damage() {
        let footer = Footer { timestamp: vec![0x30, 0x03, 0x02, 0x01, 0x01] };
        let bytes = footer.encode().unwrap();
        assert_eq!(Footer::decode(&bytes).unwrap(), footer);
        assert!(Footer::decode(&bytes[..bytes.len() - 1]).is_err(), "обрыв принят");
        assert!(Footer::decode(&[]).is_err(), "пустой футер принят");
        let mut longer = bytes.clone();
        longer.push(0);
        assert!(Footer::decode(&longer).is_err(), "хвост за футером принят");
        let mut unknown = bytes.clone();
        unknown.extend_from_slice(&2u16.to_le_bytes());
        unknown.extend_from_slice(&0u32.to_le_bytes());
        assert!(Footer::decode(&unknown).is_err(), "незнакомый критичный тег принят");
        assert!(Footer { timestamp: Vec::new() }.encode().is_err());
        assert!(Footer { timestamp: vec![0; MAX_TOKEN_LEN + 1] }.encode().is_err());
    }

    #[test]
    fn the_imprint_binds_every_field() {
        let base = imprint(&[1; 32], &[2; 32], 3, 4);
        assert_ne!(base, imprint(&[9; 32], &[2; 32], 3, 4));
        assert_ne!(base, imprint(&[1; 32], &[9; 32], 3, 4));
        assert_ne!(base, imprint(&[1; 32], &[2; 32], 9, 4));
        assert_ne!(base, imprint(&[1; 32], &[2; 32], 3, 9));
    }
}
