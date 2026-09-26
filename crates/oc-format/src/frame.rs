// SPDX-License-Identifier: MPL-2.0
//! Message framing: four length bytes, least significant byte first.
//!
//! # Why this lives here rather than with the first consumer
//!
//! Because there are already three consumers: the engine behind a pipe, its client,
//! and the server behind a socket. All share one rule: **check the limit BEFORE
//! allocating**; two copies of that rule already existed, both only in prose.
//!
//! Divergent copies here mean different interpretations of length between
//! processes, not a stylistic difference: one side accepts a message, while
//! the other ends the conversation. Hence one implementation, in a crate all can see.
//!
//! This also receives what appeared in `oc-engine` yesterday: once there was a third
//! consumer, the former location was no longer shared.
//!
//! # What is NOT here
//!
//! I/O. The engine uses a pipe, the client a child process, the server
//! a socket; combining three different forms of I/O into one type would hide
//! differences that must remain visible: each has its own errors and end of conversation.

use crate::FormatError;

/// Frame header length.
pub const HEADER_LEN: usize = 4;

/// Frame header for a body of length `len`.
///
/// # Errors
/// Returns [`FormatError::OffsetOverflow`] if the body exceeds `max`.
pub fn header(len: usize, max: usize) -> Result<[u8; HEADER_LEN], FormatError> {
    if len > max {
        return Err(FormatError::OffsetOverflow);
    }
    let value = u32::try_from(len).map_err(|_| FormatError::OffsetOverflow)?;
    Ok(value.to_le_bytes())
}

/// Body length from a frame header, with a limit.
///
/// The limit is essential: four bytes from the other side are an instruction
/// for how much memory to allocate. Unchecked, they mean "allocate four
/// gigabytes", making denial of service cost the attacker a single packet.
///
/// # Errors
/// Returns [`FormatError::OffsetOverflow`] if the declared length exceeds `max`.
pub fn body_len(head: [u8; HEADER_LEN], max: usize) -> Result<usize, FormatError> {
    let len = u32::from_le_bytes(head) as usize;
    if len > max {
        return Err(FormatError::OffsetOverflow);
    }
    Ok(len)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    /// THE LIMIT HOLDS IN BOTH DIRECTIONS AND EXACTLY AT THE BOUNDARY.
    #[test]
    fn the_ceiling_holds_in_both_directions() {
        assert_eq!(header(3, 10).unwrap(), 3u32.to_le_bytes());
        assert_eq!(header(10, 10).unwrap(), 10u32.to_le_bytes(), "ровно потолок законен");
        assert!(header(11, 10).is_err());

        assert_eq!(body_len(3u32.to_le_bytes(), 10).unwrap(), 3);
        assert_eq!(body_len(10u32.to_le_bytes(), 10).unwrap(), 10);
        assert!(body_len(11u32.to_le_bytes(), 10).is_err());

        // Четыре байта, обещающие четыре гигабайта, — тот самый случай, ради
        // которого потолок и стоит.
        assert!(body_len(u32::MAX.to_le_bytes(), 1 << 20).is_err());
    }
}
