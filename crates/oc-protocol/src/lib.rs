// SPDX-License-Identifier: MPL-2.0
//! Client, server, and witness documents outside the `.cc` container.
//!
//! Container parsing lives in [`oc_format`]. This crate depends on it for TLV and
//! [`oc_format::FormatError`]; the dependency does not run in the other direction.
//! Protocol documents have their own versions and lifecycles. The crate performs
//! no I/O and reads neither clocks nor randomness from the environment.
//!
//! # Unknown fields
//!
//! Unknown critical tags are rejected; unknown optional tags are skipped through
//! `oc_format::tlv::unknown_tag_action`. Known field lengths, ordering, duplicate
//! rejection, enum values, and message kinds remain strict.
//!
//! Signed documents verify raw body bytes before parsing. Skipping an optional
//! field therefore cannot hide a change to the signed body. Two layouts differ:
//!
//! * [`access::decode_decision`] rejects every unknown tag because verification
//!   reconstructs the body; skipping a field would remove it from the transcript.
//! * [`witness`] uses fixed-length layouts rather than TLV.

/// Access request documents: the recipient requests, the author approves.
pub mod access;
/// Action door documents (Agent Protocol, stage 2): action grant, request,
/// one-time lease and argument validation.
pub mod action;
pub mod activation;
/// Agent Protocol documents: agent grant, delegation, chain verification.
pub mod agent;
/// Device key attestation on the wire: evidence, credentials, verdict (B6b).
pub mod attestation;
/// File rule based on holder attributes: issuance and tightening gates (F-27, B4b).
pub mod attribute_rule;
pub mod control;
pub mod directory;
pub mod lease;
/// An author's signed orders to the server: registration, revocation, heir,
/// proof of life.
pub mod order;
pub mod replica;
/// Revocation: a server-signed "file revoked" document accepted from any source.
pub mod revocation;
/// File standing on the server: which author orders currently apply.
pub mod standing;
mod unknown;
pub mod witness;
