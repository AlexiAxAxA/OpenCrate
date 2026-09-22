//! Product protocol documents: everything exchanged between client, server and
//! witness that does not reside inside the `.cc` container.
//!
//! # Why this is a separate crate rather than modules in `oc-format`
//!
//! The boundary follows the RATE OF CHANGE, not directory
//! neighbors. The container format freezes: after the first file leaves the system,
//! every header byte is promised forever, and changing it requires a new
//! format version together with a recorded decision (I-14). The product protocol
//! grows with the server: a new request kind, a new field in the file standing,
//! a new rejection reason appear exactly when the mechanism appears, with
//! no promise of permanence.
//!
//! While both kinds lived in one crate, they were indistinguishable externally: the crate
//! promised to be frozen and opened contained eight and a half thousand
//! lines changing every week. Mixing them meant either freezing what
//! must change or exposing the freeze to things that change independently. Decision
//! R-2 (`docs/plan.md`, «D-core-freeze») separated them into crates; now
//! the difference is VISIBLE in a `use` statement, before any gate runs.
//!
//! # What lives where
//!
//! [`oc_format`] contains the container: splitting the prologue, the header and its slots,
//! the mutable area, chunk frames, the footer, the policy codec, the TLV parser,
//! signature verification and the shared error type [`oc_format::FormatError`]. This crate holds
//! what arrives from or goes onto the wire: activation, author orders,
//! file standing on the server, access requests and decisions, leases, revocations,
//! device key attestation, the witness journal, the recipient directory, attribute
//! rules, control operations and replicas.
//!
//! There is exactly one dependency arrow: protocol depends on format. The reverse does not
//! and cannot exist: no container parser calls any protocol document;
//! this was verified in the code before the move, not merely promised.
//!
//! The lease ([`lease`]) lives here although it is cached alongside the container and
//! verified by the reader: it is a SEPARATE document with its own version
//! ([`lease::LEASE_VERSION`]) and lifecycle, issued by the server,
//! and changes at the server's pace rather than the format's pace.
//!
//! # Purity
//!
//! The crate passes through the same gate as `oc-format`, `oc-crypto`, `oc-policy` and
//! `oc-engine`: no I/O, clocks or random number generator.
//! The verification check is a `wasm32-unknown-unknown` build. This is not a
//! style concern: tests for time travel and revocation must be DATA,
//! not a replacement of the system clock.
//!
//! # Unknown tags
//!
//! **The same rule as the container (I-7), since 2026-09-21.** A tag ≤
//! `oc_format::tlv::CRIT_TAG_MAX` is critical: an unknown such tag is rejected with
//! [`oc_format::FormatError::UnknownCriticalField`], the same error
//! variant as before the decision. Higher tags are optional: their values are skipped. The decision
//! is made by `oc_format::tlv::unknown_tag_action`, the same function used by
//! the container; the protocol has no separate one.
//!
//! Before that date, protocol parsers rejected EVERY unknown tag, justified
//! by clients and servers updating together. That argument ceased to hold
//! even before the first release: after release, servers and clients
//! update at different times: a solo operator runs their server, while recipients
//! use unmanaged machines. Under the old rule, the very first
//! new field after release would break every released peer.
//! Before release, the change is free: there are no external clients, and client and server ship
//! as one package. After release, it would require a wire version.
//!
//! # The optional range does NOT enable forgery
//!
//! Verification order has not changed: signatures and MACs are verified BEFORE body parsing
//! (I-5), and unknown tags are skipped AFTERWARD, within already authenticated
//! bytes. Signatures cover the RAW body bytes: `lease`, `revocation`, `order`,
//! `control` and `replica` sign exactly the slice they subsequently parse,
//! so a third party cannot append a tag in transit: the signature would no longer
//! verify. Unauthenticated documents are discussed below, each with its own rationale.
//!
//! There are two exceptions, both documented locally:
//!
//! * [`access::decode_decision`] remains STRICT. Its signature is verified not over
//!   raw bytes but over a body REBUILT from the parsed structure
//!   ([`access::decision_body`]); a skipped tag disappears from that reconstruction.
//!   Thus an optional range there would enable exactly what this paragraph
//!   promises to prevent: a third party could append a tag to a signed decision,
//!   and its signature would verify. It would provide no extension capability either: a field added
//!   to `decision_body` by a new build would still fail signature verification in an old build.
//! * [`witness`] does not follow this rule because it contains no TLV: heads, views and
//!   cosigned heads have exact-length layouts.
//!
//! What has NOT changed: request and response kinds (`KIND_*`) are not tags; an unknown
//! kind is still rejected. Enumerations WITHIN values (lease state, operation
//! outcome, inheritance mode) are not tags; an unknown value of a known field
//! is still rejected. Strict tag ordering, duplicate rejection and exact lengths
//! of known fields (I-7, I-8) remain unchanged, and ordering is checked even for
//! skipped tags.

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
