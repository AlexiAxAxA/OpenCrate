// SPDX-License-Identifier: MPL-2.0
//! Activation documents and the shared request/response envelope.
//!
//! Device keys perform agreement, not signing. Authentication and proof of
//! possession belong to the handshake (`docs/protocol.md` §9.4), not to a device
//! signature in these documents. A claimed fingerprint alone proves no identity.
//!
//! The envelope's kind registry also covers access requests; their layouts live
//! in [`crate::access`]. Codecs enforce field order, exact lengths, and complete
//! consumption of the input independently of transport.

use oc_format::tlv::{TlvReader, TlvWriter};
use oc_format::{FormatError, MAX_HEADER_LEN};

/// Activation-request tags.
pub mod req_tag {
    /// The file being opened. 16 bytes.
    pub const FILE_ID: u16 = 1;
    /// Policy hash computed by the device from signed bytes. 32 bytes.
    ///
    /// The server compares it with its own, recorded at registration. Substituting
    /// the hash gains nothing: it will not match, and activation will be rejected.
    pub const POLICY_HASH: u16 = 2;
    /// Device fingerprint. 32 bytes.
    pub const DEVICE_FPR: u16 = 3;
    /// Device-key agreement mechanism. `u8`.
    pub const DEVICE_KEM: u16 = 4;
    /// Device public key: 32 bytes for X25519, 65 for P-256.
    ///
    /// Variable length, checked BY mechanism rather than accepted as supplied: the
    /// format already applies this rule to slots (§2.0); repeating it differently
    /// would introduce a second place that determines key length.
    pub const DEVICE_PUBLIC: u16 = 5;
    /// Server slot extracted by the device from the container.
    ///
    /// Contents: `u32le(len) ‖ enc ‖ nonce(24) ‖ u32le(len) ‖ ct`. The slot is not
    /// a separate document: it is part of the header, not an independent
    /// quantity, so its layout need not be reinvented here.
    pub const SERVER_SLOT: u16 = 6;
    /// Lease duration requested by the device, in seconds. `i64le`.
    ///
    /// A request, not a demand: the server tightens it using the author's policy and may
    /// issue less.
    pub const LEASE_SECONDS: u16 = 7;
    /// Hardware clock reading: `u32le` reset_count ‖ `u64le` clock_ms ‖
    /// `i64le` sampling time. Optional — absent on a machine without a TPM.
    pub const DEVICE_CLOCK: u16 = 8;
    /// Operation identity (K28, protocol §9.10), 32 bytes; optional.
    ///
    /// This is a critical tag because it changes retry semantics: the server
    /// returns the stored outcome instead of executing again. A server that does
    /// not understand it must reject the request rather than issue another grant.
    pub const OPERATION_ID: u16 = 9;
}

/// Grant tags.
pub mod grant_tag {
    /// Server share resealed to the device key.
    pub const SHARE: u16 = 1;
    /// Signed lease: `signature(64) ‖ body`.
    pub const LEASE: u16 = 2;
    /// Operation-identity echo: the server RECORDED this operation under this identity
    /// in the same commit as its outcome. 32 bytes.
    ///
    /// Only returned for requests carrying [`super::req_tag::OPERATION_ID`]:
    /// an old client sends no field and receives no echo; its parser, unaware
    /// of the tag, would otherwise reject the response.
    ///
    /// The echo signals SUPPORT, not proof: wire responses are unauthenticated
    /// (§9.6), and an intermediary may remove or substitute it. A removed echo
    /// sends the client down the old, non-retrying path — the safe direction.
    pub const OPERATION_ID: u16 = 3;
}

/// Refusal tags.
pub mod deny_tag {
    /// Refusal text.
    pub const TEXT: u16 = 1;
    /// Operation-identity echo — as for grants ([`super::grant_tag::OPERATION_ID`]).
    ///
    /// Refusal with echo is FINAL for this identity: recorded and returned unchanged
    /// on retry. Refusal without echo to an identified request means the operation
    /// did NOT execute under it — the server does not know or did not accept the identity.
    pub const OPERATION_ID: u16 = 2;
}

/// Greeting tags: the device identifies itself before any work.
pub mod hello_tag {
    /// Device fingerprint. 32 bytes.
    pub const DEVICE_FPR: u16 = 1;
    /// Device agreement key (X25519). 32 bytes.
    pub const DEVICE_PUBLIC: u16 = 2;
    /// Hardware key (P-256), if present. 65 SEC1 bytes.
    pub const DEVICE_TPM: u16 = 3;
    /// Hybrid device-key mechanism: `u8`, number from the `kem_id` registry.
    ///
    /// PAIRED with [`DEVICE_HYBRID_PUBLIC`]: either alone is meaningless;
    /// parsing requires both or neither. Key length is checked BY this
    /// number, not accepted as supplied (I-8).
    pub const DEVICE_HYBRID_KEM: u16 = 4;
    /// Hybrid device public key. Length depends on mechanism:
    /// 1216 for X-Wing, 1249 for MLKEM768-P256.
    pub const DEVICE_HYBRID_PUBLIC: u16 = 5;
}

/// Challenge tags: one or two sealed components of the secret.
pub mod challenge_tag {
    /// Component sealed to the agreement key. Same layout as a slot.
    pub const SOFTWARE: u16 = 1;
    /// Component sealed to the hardware key.
    pub const HARDWARE: u16 = 2;
    /// Component sealed to the HYBRID device key.
    ///
    /// Present if and only if the device presented a hybrid
    /// pair in its greeting. Same layout as other components, but `enc`
    /// is longer: 1120 bytes for X-Wing, 1153 for MLKEM768-P256.
    pub const HYBRID: u16 = 3;
}

/// Echo tags.
pub mod proof_tag {
    /// Recovered challenge secret, components concatenated in the same order.
    pub const ECHO: u16 = 1;
}

/// Greeting: who the device claims to be.
///
/// A separate document rather than activation-request fields because the challenge
/// is issued BEFORE the server learns which file is involved. This verifies key
/// possession, not file rights; these questions must not be confused: rights without
/// possession mean nothing, while possession without rights is legitimate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub device_fpr: [u8; 32],
    pub device_public: [u8; 32],
    pub device_tpm: Option<Vec<u8>>,
    /// The device's hybrid pair: mechanism and public key.
    ///
    /// Presented so the device can PROVE possession of the hybrid
    /// key rather than merely name it. Without proof, an intermediary could submit
    /// another party's consistent `(fpr, kem, public)` triple: it would obtain no share,
    /// but consume the victim's limits and attribute journal entries to them (N-1).
    ///
    /// The classical pair remains mandatory even with a hybrid: `device_fpr`
    /// equals `device_public` and enters challenge `info`, the lease, and the journal;
    /// the lease format is frozen. The hybrid is an ADDITIONAL provable
    /// identity, not a replacement for the classical one.
    pub device_hybrid: Option<(u8, Vec<u8>)>,
}

/// Challenge: secret components sealed to the presented keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    pub software: SlotBlob,
    pub hardware: Option<SlotBlob>,
    /// Component sealed to the hybrid key.
    ///
    /// Present if and only if the device presented a hybrid pair.
    /// It must open ALL components: echo uses the concatenated secret, and
    /// proof of hybrid possession is inseparable from proof of classical
    /// possession — opening one alone cannot pass.
    pub hybrid: Option<SlotBlob>,
}

/// K23 echo: exactly 32 HMAC bytes.
/// The hardware component enters the HMAC key, so even a 64-byte challenge
/// yields a 32-byte echo; the old raw challenge is never accepted as proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    pub echo: Vec<u8>,
}

/// Device-to-server message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Hello(Hello),
    Prove(Proof),
    Activate(Box<ActivateReq>),
    /// Access request: a recipient not issued a share asks for it.
    Ask(Box<crate::access::AskAccess>),
    /// The author asks who awaits a decision for their file.
    ///
    /// The asker's identity is not verified here, and there is no means to do so: the
    /// author key lives in the header, not with the device. The queue is public anyway —
    /// requester fingerprints in it are not secret; a share is issued through
    /// a signature, not viewing the list.
    Requests { file_id: [u8; 16] },
    /// Collect the author's decision, if already made.
    Collect(CollectReq),
    /// Subscribe to file events on this connection.
    ///
    /// `since` is the first unseen journal record; zero starts at the beginning.
    /// The server sends the backlog, then live events for up to [`MAX_WATCH_FILES`]
    /// files. Reconnect with the next unseen record number to resume.
    /// Notifications expose public queue/journal data and need no possession proof;
    /// decisions still require `Collect`. The conversation lasts until disconnect
    /// or subscription expiry.
    Watch { files: Vec<[u8; 16]>, since: u64 },
    /// Subscription to “all the author's files” (`docs/protocol.md` §9.9, B5).
    ///
    /// Unlike [`Request::Watch`], authority does not derive from knowing
    /// identifiers: `proof` is a fresh signed `WatchAuthor` order
    /// addressed to this server. The server computes scope itself from
    /// files recording this key as author, at every step, so new author files
    /// arrive without resubscription.
    WatchAuthor { since: u64, proof: Vec<u8> },
    /// File revocation notice: server-signed “file revoked” document.
    ///
    /// No proof of possession: no secret here — truth about a file,
    /// signed by the server; distributing it distributes
    /// truth. Clients accept it over the wire or as a file beside the container
    /// (`oc_protocol::revocation`).
    Revocation { file_id: [u8; 16] },
    /// Renewal: same request as activation, for an already activated
    /// device, without journal writes or grant-limit consumption.
    ///
    /// Same body as [`Request::Activate`], for a reason: the share
    /// is resealed to the device with a derivation containing the lease number
    /// (`u64be(seq)` in K11); a new number therefore requires a new share,
    /// obtained by the server only from the `Server` slot — renewal needs
    /// exactly the same fields. Its distinct kind serves the JOURNAL: the server
    /// must distinguish “first issuance” from “renewal for an open document,”
    /// or the author's journal would gain twelve entries per hour for each
    /// open window, and one reader would exhaust the grant limit.
    /// The server returns the same `Granted` as for activation.
    Renew(Box<ActivateReq>),
    /// File registration by author order.
    ///
    /// `header` is the container prefix through the author's signature:
    /// magic, header, signature. No content is present or permitted. The server
    /// verifies the header signature, takes its author key, and uses it to verify
    /// `order` (`oc_protocol::order`) — learning the author's key from
    /// a document the recipient cannot alter, rather than from
    /// the requester's word. Response: `Accepted`.
    Register { header: Vec<u8>, order: Vec<u8> },
    /// File revocation by author order; verified with the key remembered at
    /// registration. Response: `Accepted`.
    Revoke { order: Vec<u8> },
    /// The complete author decision, including signature.
    ///
    /// Opaque bytes rather than a parsed [`crate::access::Decision`],
    /// deliberately: signatures cover BYTES, and reconstructing the document en route
    /// introduces a second place assembling them. The server must verify
    /// the signature over exactly what arrived.
    Decide(Vec<u8>),
    /// Other author order: heir, proof of life. Response: `Accepted`.
    ///
    /// Bytes, for the same reason as decisions: the signature covers the body,
    /// which must not be reconstructed in transit.
    Order(Vec<u8>),
    /// Co-author signature on a proposal: same body, their own signature.
    ///
    /// The signer's key travels alongside, not inferred by trying the roster:
    /// enumeration would make signature-check count depend on roster size,
    /// silently giving an intermediary a way to burden the server with sixteen
    /// checks per message.
    Endorse { signer: [u8; 32], order: Vec<u8> },
    /// The file's current standing. Response: [`Response::Standing`].
    ///
    /// No proof of possession, like the request queue: the author supplied all of
    /// this to the server, and the recipient can see it in the queue and journal.
    Standing { file_id: [u8; 16] },
    /// Attestation, step 1: device requests a challenge (§9.11.1). No body.
    AttestOpen,
    /// Attestation, step 2: complete evidence about the device key.
    AttestEvidence(Box<crate::attestation::Evidence>),
    /// Attestation, step 3: secret recovered through credential activation.
    AttestSecret([u8; crate::attestation::SECRET_LEN]),
    /// Edition claim (`oc_format::edit::EditionClaimDoc`, `docs/protocol.md`
    /// §9.12). Opaque bytes for the same reason as decisions: the signature
    /// covers the body. Response: `Accepted` or refusal.
    RegisterEdition(Vec<u8>),
    /// Journal view for a witness (`crate::witness`, `docs/protocol.md`
    /// §9.13): head at length `upto` (zero means current), with proof that it
    /// extends the head at length `since` (zero means no proof). Response:
    /// [`Response::LogView`] or refusal. No handshake: head and
    /// proof are public.
    JournalView { since: u64, upto: u64 },
    /// The same for the key-directory log (D4, §9.14).
    DirectoryView { since: u64, upto: u64 },
    /// Directory record for an organization member, at head length `size`
    /// (zero means current). Response: [`Response::DirectoryEntry`] or refusal
    /// (record absence is the server's assertion, §9.14).
    DirectoryLookup { tenant: String, name: String, size: u64 },
    /// Directory-log page for a monitor: `count` records starting at
    /// `from`. Response: [`Response::DirectoryRecords`].
    DirectoryRecords { from: u64, count: u32 },
    /// Controllers' intent (`crate::control`, §9.16). Opaque bytes for
    /// the same reason as author decisions: signatures cover the body,
    /// and reconstruction here would break them. Response: [`Response::Receipt`] or
    /// refusal.
    Control(Vec<u8>),
    /// “Show the binding.” Response: [`Response::Binding`] or refusal if
    /// no binding has been initialized.
    Binding,
    /// State snapshot for a replica (`crate::replica::Push`). Response:
    /// [`Response::ReplicaAck`] or refusal with the replica's reason.
    ReplicaPush(Vec<u8>),
    /// Author-issued agent grant (`crate::agent::AgentGrant`), as opaque
    /// bytes. Response: [`Response::ChainStored`] or refusal.
    ///
    /// Bytes rather than a parsed document for the same reason as author
    /// decisions: the signature covers BYTES, and reconstruction in transit
    /// introduces a second assembly point. Moreover, the envelope has no
    /// verification key — the server obtains it from the file record.
    ///
    /// No proof of possession, like `Decide`: the document bears the author's
    /// signature, which is all that matters. The door key is INSIDE the signed
    /// body, so an intermediary delivering the grant cannot substitute its recipient.
    PutGrant(Vec<u8>),
    /// Parent-door delegation (`crate::agent::Delegation`), as bytes.
    /// Response: [`Response::ChainStored`] or refusal.
    ///
    /// Also without proof of possession: the link is signed by the parent's `door_verify`
    /// key, named in the grant under the author's signature.
    PutDelegation(Vec<u8>),
    /// Collect one's chain: grant and links through the named holder.
    ///
    /// Only after a handshake; the server compares the named fingerprint with the
    /// PROVED one — the same check as [`Request::Collect`]. Without it, anyone
    /// could collect another door's chain: fingerprints are public, and links contain
    /// shares B sealed to its key.
    ///
    /// Response: [`Response::Chain`] or [`Response::NoChain`].
    FetchChain { holder_fpr: [u8; 32] },
    /// Author-issued ACTION grant (`crate::action::ActionGrant`), as bytes.
    /// Response: [`Response::ChainStored`] or refusal.
    ///
    /// No proof of possession for the same reason as [`Self::PutGrant`]:
    /// the document bears the author's signature; the server obtains its verification key
    /// from the FILE grant to which it is bound — an action has no container
    /// header, so its anchor is the grant, not the file.
    ///
    /// The same `ChainStored` response, not a separate one: the action grant belongs
    /// to THE SAME chain (same `grant_id`, holder, redemption); a second
    /// response kind would promise a second entity that does not exist.
    PutActionGrant(Vec<u8>),
    /// Door request to execute an action (`crate::action::ActionRequest`),
    /// as bytes. Response: [`Response::ActionGranted`], [`Response::ActionPending`],
    /// or [`Response::ActionRefused`].
    ///
    /// The request is UNSIGNED: the door has an agreement key, incapable
    /// of signing. The server does not take requester identity from the document:
    /// the named `door_fpr` is compared with the fingerprint PROVED in this conversation
    /// in constant time, as for [`Self::Collect`].
    ///
    /// Bytes rather than a parsed document for the same reason as author
    /// decisions: the consumer parses it; a second parser in the envelope
    /// would diverge from the first.
    RequestAction(Vec<u8>),
    /// Door execution report: lease number, outcome, and hash of what was executed.
    ///
    /// No TLV: all three fields are required and fixed-length; no optional fields
    /// exist — TLV would add exactly one possibility here: sending them
    /// in another order (same argument as [`CollectReq`]).
    ///
    /// A hash, not content: the server need not see WHAT the door executed;
    /// a hash sufficiently binds the report to execution. Response: `Accepted`.
    ReportAction { seq: u64, ok: bool, digest: [u8; 32] },
    /// The owner asks which requests under this grant await their “yes.”
    ///
    /// No proof of possession, like [`Self::Requests`], for the same
    /// reason: the owner decides by SIGNING with the author key, which the device
    /// does not have; the queue contains what the door already told the server.
    /// Response: [`Response::ActionQueue`].
    ActionRequests { grant_id: [u8; 16] },
    /// Owner decision on a request (`crate::action::ActionDecision`), as bytes.
    ///
    /// Bytes rather than a parsed document for the same reason as
    /// [`Self::Decide`]: signatures cover BYTES, and reconstruction in transit
    /// introduces a second assembly point. Response: `Accepted`.
    DecideAction(Vec<u8>),
}

/// Who is collecting a decision, and for which file.
///
/// No TLV: both fields required, both fixed-length, no optional fields at
/// all — TLV would add exactly one possibility: sending them in another
/// order. The envelope already carries documentless bodies (see [`Response::Proven`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CollectReq {
    pub file_id: [u8; 16],
    /// Collector fingerprint.
    ///
    /// The receiver compares it with proof of possession obtained in the same
    /// conversation — the field alone proves nothing.
    pub device_fpr: [u8; 32],
}

/// Server-to-device message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    Challenge(Challenge),
    /// Echo matched. No response content of its own — the fact itself matters.
    Proven,
    Granted(Grant),
    Denied(Deny),
    /// Request accepted and queued under this number.
    Asked { seq: u64 },
    /// Request queue: consecutive `u32le length ‖ document Pending`.
    ///
    /// An opaque body, not a parsed list: the party presenting it to the
    /// user parses it; doing so twice — in the envelope and there —
    /// creates two parsers for the same data that will diverge.
    ///
    /// An empty body is valid and means “nobody is asking,” unlike a decision,
    /// where emptiness would be a promise without fulfillment.
    Queue(Vec<u8>),
    /// Author decision as signed. Both approval and refusal appear here:
    /// a field inside the document distinguishes them, not the message kind.
    Decided(Vec<u8>),
    /// No decision yet.
    ///
    /// A SEPARATE kind, not a refusal; the distinction is essential: the author may remain silent,
    /// and “has not answered” is not “refused.” If waiting arrived as refusal, the recipient
    /// would tell the user they had been denied when they simply
    /// had not been considered yet.
    Waiting,
    /// Server accepted the author's decision. No content — the fact itself matters.
    Accepted,
    /// Subscription notification. One connection, many notifications.
    Notice(Notice),
    /// Revocation notice: `signature(64) ‖ body`, as for a lease.
    Revocation(Vec<u8>),
    /// File not revoked (or unknown to the server — no need to distinguish; see
    /// `Waiting`: nobody needs a “does this file exist?” oracle here).
    NotRevoked,
    /// File standing: `oc_protocol::standing` document.
    Standing(Vec<u8>),
    /// Proposal endorsed, but still lacking enough signatures.
    ///
    /// Separate from `Accepted`; the distinction is essential: `Accepted` means “done,”
    /// this means “accepted for consideration.” Combining them would make an author believe
    /// a file revoked while revocation still awaited a second signature.
    Endorsed { have: u8, need: u8 },
    /// Attestation challenge for this conversation.
    AttestNonce([u8; crate::attestation::SECRET_LEN]),
    /// Credentials for the attestation key: `TPM2B_ID_OBJECT ‖ TPM2B_ENCRYPTED_SECRET`.
    AttestCredential(Vec<u8>),
    /// Attestation accepted; basis: [`crate::attestation::basis`].
    Attested { basis: u8 },
    /// Journal view: `crate::witness::View`, parsed on receipt.
    LogView(Box<crate::witness::View>),
    /// Directory record with inclusion proof (D4).
    DirectoryEntry(Box<crate::directory::Lookup>),
    /// Directory-record page; every record parsed on receipt.
    DirectoryRecords(Vec<Vec<u8>>),
    /// Control-operation receipt (`crate::control::Receipt`).
    Receipt(Vec<u8>),
    /// Authority binding (`crate::control::Binding`).
    Binding(Vec<u8>),
    /// Replica acknowledgment (`crate::replica::Ack`).
    ReplicaAck(Vec<u8>),
    /// Grant or link accepted and recorded. No content — the fact matters.
    ChainStored,
    /// Holder chain with optional lease-signing key and action grant.
    ///
    /// `documents` is an ordered grant/link stream with `u32le` lengths
    /// ([`join_chain`], [`split_chain`]). Preserve the signed document bytes.
    /// `lease_verify_key` supports action-only holders without a file header.
    /// It is the server's claim, not a trust anchor; compare it with a signed
    /// header when one is available.
    /// `action_grant`, when present, requires separate author-key verification
    /// before the door uses its rules for local checks.
    Chain {
        documents: Vec<u8>,
        lease_verify_key: Option<[u8; 32]>,
        action_grant: Option<Vec<u8>>,
    },
    /// This holder has no chain.
    ///
    /// A SEPARATE kind, not refusal, for the same reason as [`Response::Waiting`]:
    /// “you were not issued a grant” is a legitimate state, not misconduct;
    /// the door tells the user “no grant issued,” not “server refused.”
    NoChain,
    /// Complete action lease (`signature(64) ‖ body`): execute THIS.
    ActionGranted(Vec<u8>),
    /// Request queued under this number for the owner's live “yes.”
    ///
    /// A SEPARATE kind, not refusal, for the same reason as [`Self::Waiting`]:
    /// the owner may not have answered yet; “no answer” is not “refused.”
    /// The door retries the request with THE SAME `nonce` until receiving a lease or
    /// refusal; it must not wait for a response within the call itself — an agent call
    /// must not hang for minutes.
    ActionPending { seq: u64 },
    /// Action not allowed, with a reason in words.
    ///
    /// Separate from [`Self::Denied`]; the distinction is essential: `Denied` concerns the
    /// CONVERSATION (no handshake, wrong identity), this concerns the ACTION itself,
    /// and is final: repeating the request with the same arguments
    /// is pointless. Merging them would prevent the door from distinguishing
    /// “server will not listen to me” from “you were not allowed to do this.”
    ///
    /// Reason is REQUIRED and nonempty: without it, neither the user can understand
    /// what happened nor the agent correct its request. The codec itself rejects an
    /// empty string, so our side cannot produce one.
    ActionRefused { why: String },
    /// Queue of requests awaiting the owner's “yes”: consecutive `u32le length ‖ document
    /// PendingAction` (`crate::action::split_action_queue`).
    ///
    /// Opaque body, with empty body valid — the same reasoning as
    /// [`Self::Queue`].
    ActionQueue(Vec<u8>),
}

/// What happened to a subscribed file.
///
/// A notification is a SIGNAL, not content: it says “ask,” using
/// the same request as without a subscription. Thus subscribing adds nothing
/// to what is already issued and introduces no second path to a decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notice {
    /// Server alive, no events. Sent so the subscriber can distinguish silence from
    /// disconnection: without heartbeats, silence and a dead pipe look alike.
    Heartbeat,
    /// Server journal entry for one of the subscribed files.
    ///
    /// `seq` is the record number; the subscriber remembers `seq + 1` and supplies it
    /// as `since` in the next subscription: numbering starts at zero. `event` is the event kind in
    /// [`journal_event`]; unknown kinds are skipped, not rejected:
    /// the server journal may grow; a new event is not wire corruption.
    Event { seq: u64, event: u8, file_id: [u8; 16], device_fpr: Option<[u8; 32]> },
}

/// How many files one subscription accepts.
pub const MAX_WATCH_FILES: usize = 32;

/// Server journal event kinds transmitted in notifications.
///
/// Numbers match the journal (`cc_authority::journal::Event`), guarded
/// by a test there: the wire registry is singular, while the journal lives in a private
/// crate, so its public counterpart is defined here.
pub mod journal_event {
    pub const FILE_REGISTERED: u8 = 1;
    pub const DEVICE_ACTIVATED: u8 = 2;
    pub const LEASE_ISSUED: u8 = 3;
    pub const REVOKED: u8 = 4;
    pub const ACCESS_REQUESTED: u8 = 9;
    pub const ACCESS_DECIDED: u8 = 10;
    pub const COAUTHORS_SET: u8 = 11;
    pub const APPROVERS_SET: u8 = 12;
    pub const DEVICE_APPROVED: u8 = 13;
    pub const ISSUE_HELD_FOR_QUORUM: u8 = 14;
    pub const LIMITS_CHANGED: u8 = 15;
    pub const HEIR_SET: u8 = 16;
    pub const HEIR_RELEASED: u8 = 17;
    pub const CLOSED_BY_SILENCE: u8 = 18;
    pub const PROPOSAL_ENDORSED: u8 = 19;
    pub const FROZEN: u8 = 20;
    pub const THAWED: u8 = 21;
    /// Agent Protocol, stage 1: grant issued to door, link issued to descendant, grant
    /// redeemed. Notification fingerprint belongs to the holder, not file recipient.
    pub const AGENT_GRANT_REGISTERED: u8 = 29;
    pub const DELEGATION_REGISTERED: u8 = 30;
    pub const AGENT_GRANT_REVOKED: u8 = 31;
    /// Agent Protocol, stage 2: action grant recorded, door requested
    /// execution, lease issued, execution succeeded, execution failed.
    ///
    /// These records have NO file (zeros, as for attribute holdings), deliberately:
    /// an action has no file — its subject is arguments,
    /// not a container. The cost is explicit: subscriptions filter by file, so
    /// file subscribers never receive these records; owners see them through journal views
    /// and the `ActionRequests` queue; the grant is recovered using its holder's
    /// fingerprint — one door holds exactly one chain.
    pub const ACTION_GRANT_REGISTERED: u8 = 32;
    pub const ACTION_REQUESTED: u8 = 33;
    pub const ACTION_LEASED: u8 = 34;
    pub const ACTION_DONE: u8 = 35;
    pub const ACTION_FAILED: u8 = 36;
}

// Виды сообщений. Числа свои, провода: они не имеют отношения к номерам формата
// и не обязаны с ними совпадать.
const KIND_HELLO: u8 = 1;
const KIND_PROVE: u8 = 2;
pub const KIND_ACTIVATE: u8 = 3;
const KIND_CHALLENGE: u8 = 4;
const KIND_PROVEN: u8 = 5;
const KIND_GRANTED: u8 = 6;
const KIND_DENIED: u8 = 7;
const KIND_ASK: u8 = 8;
const KIND_COLLECT: u8 = 9;
const KIND_DECIDE: u8 = 10;
const KIND_ASKED: u8 = 11;
const KIND_DECIDED: u8 = 12;
const KIND_WAITING: u8 = 13;
const KIND_ACCEPTED: u8 = 14;
/// Author query for a file's request queue.
///
/// The message kind belongs to the shared registry used by both endpoints.
const KIND_REQUESTS: u8 = 15;
/// Its response: queue as consecutive `u32le length ‖ document`.
const KIND_QUEUE: u8 = 16;
/// File-event subscription. Introduced 2026-09-02 (F-17, item 10) instead of
/// polling: the server announces events rather than waiting for a query.
pub const KIND_WATCH: u8 = 17;
/// Subscription notification. Body: kind byte; events also carry their layout.
const KIND_NOTICE: u8 = 18;
/// Revocation-notice request and its two responses. F-18, tier 3.
const KIND_REVOCATION_REQ: u8 = 19;
const KIND_REVOCATION: u8 = 20;
const KIND_NOT_REVOKED: u8 = 21;
/// Lease renewal for an open document. F-18, continuation of tier 1.
pub const KIND_RENEW: u8 = 22;
/// Author orders over the wire: registration and revocation. 2026-09-03.
const KIND_REGISTER: u8 = 23;
const KIND_REVOKE: u8 = 24;
/// Other author orders under one kind: heir, proof of life, later also
/// quorum.
///
/// One kind rather than one per order, deliberately. Message-kind numbers share
/// a socket registry and are costly: each number is permanent. The enclosed `order`
/// has its OWN freely growing kind registry, and the server must parse
/// its body anyway to know the command. A separate message number for every
/// order would provide a second answer to the same question; eventually the two
/// would diverge.
///
/// Registration and revocation keep their numbers: the first needs a header beside
/// the order, the second returns an epoch — neither is “just an order.”
const KIND_ORDER: u8 = 25;
/// Co-author signature on a proposal: order body plus signer key.
const KIND_ENDORSE: u8 = 26;
/// The author queries their file's current standing.
const KIND_STANDING_REQ: u8 = 27;
/// Subscription to the “author's files” scope with key-possession proof. B5.
pub const KIND_WATCH_AUTHOR: u8 = 30;
/// Response: “proposal endorsed, waiting for the others.”
const KIND_ENDORSED: u8 = 28;
/// Standing-query response: `oc_protocol::standing` document.
const KIND_STANDING: u8 = 29;
/// Device-key attestation: three requests and three responses (B6b, §9.11.1).
///
/// Requests use a session MAC, like activation: the attestation verdict changes
/// what the server issues to this conversation; unauthenticated bytes must not choose it.
pub const KIND_ATTEST_OPEN: u8 = 31;
pub const KIND_ATTEST_EVIDENCE: u8 = 32;
pub const KIND_ATTEST_SECRET: u8 = 33;
const KIND_ATTEST_NONCE: u8 = 34;
const KIND_ATTEST_CREDENTIAL: u8 = 35;
const KIND_ATTESTED: u8 = 36;
/// Edition claim (D1, §9.12).
pub const KIND_REGISTER_EDITION: u8 = 37;
/// Journal-view request for a witness and its response (D3, §9.13).
pub const KIND_JOURNAL_VIEW_REQ: u8 = 38;
/// View response shared by both logs — the head signature identifies which.
const KIND_LOG_VIEW: u8 = 39;
/// Key directory (D4, §9.14): log view, record, record page.
pub const KIND_DIRECTORY_VIEW_REQ: u8 = 40;
pub const KIND_DIRECTORY_LOOKUP_REQ: u8 = 41;
const KIND_DIRECTORY_ENTRY: u8 = 42;
pub const KIND_DIRECTORY_RECORDS_REQ: u8 = 43;
const KIND_DIRECTORY_RECORDS: u8 = 44;
/// Authority control (E2, B2, §9.16): controllers' intent and receipt,
/// binding query and binding.
///
/// No handshake, without weakening security: intent is signed by the controller
/// roster, binding by the server key, while a session MAC proves possession
/// of a DEVICE key, which a controller may not have at all.
pub const KIND_CONTROL: u8 = 45;
const KIND_RECEIPT: u8 = 46;
pub const KIND_BINDING_REQ: u8 = 47;
const KIND_BINDING: u8 = 48;
/// State replica (E2, B4, §9.17): snapshot and acknowledgment.
pub const KIND_REPLICA_PUSH: u8 = 49;
const KIND_REPLICA_ACK: u8 = 50;
/// Agent Protocol, stage 1 (`docs/agent-protocol/stage-1-door.md` §3.4): agent
/// grant, descendant delegation, and collection of one's own chain.
///
/// Three numbers, not one “Agent Protocol document” with an embedded kind:
/// grant and link have DIFFERENT verification keys (author and parent door),
/// which the server must choose before body parsing. One number would require
/// parsing the body to discover its verification key — parsing unauthenticated bytes.
pub const KIND_PUT_GRANT: u8 = 51;
pub const KIND_PUT_DELEGATION: u8 = 52;
pub const KIND_FETCH_CHAIN: u8 = 53;
const KIND_CHAIN_STORED: u8 = 54;
const KIND_CHAIN: u8 = 55;
const KIND_NO_CHAIN: u8 = 56;
/// Agent Protocol, stage 2 (`docs/agent-protocol/stage-2-actions.md` §4.4):
/// action door.
///
/// Five requests and four responses, each with its own number for the same reason
/// as stage 1's three numbers: the first byte chooses parsing BEFORE the document's
/// owner is known. Action grant, request, report, and owner
/// decision have different verification keys (author, none, none, author) and
/// proofs (none, proved door identity, same, none).
/// One number would require parsing the body to discover how to verify it.
///
/// `PutActionGrant` returns the existing `ChainStored` (54); `ReportAction` and
/// `DecideAction` return the existing `Accepted` (14): they make no new promises.
pub const KIND_PUT_ACTION_GRANT: u8 = 57;
pub const KIND_REQUEST_ACTION: u8 = 58;
pub const KIND_REPORT_ACTION: u8 = 59;
pub const KIND_ACTION_REQUESTS: u8 = 60;
pub const KIND_DECIDE_ACTION: u8 = 61;
const KIND_ACTION_GRANTED: u8 = 62;
const KIND_ACTION_PENDING: u8 = 63;
const KIND_ACTION_REFUSED: u8 = 64;
const KIND_ACTION_QUEUE: u8 = 65;

/// Body tags for [`Response::Chain`].
///
/// Before stage 2, the body was a BARE document stream without framing. The stream
/// remains identical, now under [`chain_tag::DOCUMENTS`]: there was nowhere to
/// append the lease-signing key — no tags or optional-field
/// space; a record appended to its tail is indistinguishable from an extra
/// document.
pub mod chain_tag {
    /// Chain document stream: consecutive `u32le length ‖ document`. Critical.
    pub const DOCUMENTS: u16 = 1;
    /// Server lease-signing key, 32 bytes. OPTIONAL (tag > `0x7FFF`):
    /// the stage-one server did not send it; readers must accept responses
    /// without it (I-7).
    pub const LEASE_VERIFY_KEY: u16 = 0x8001;
    /// Complete author-signed action grant for this chain.
    ///
    /// Optional tag (`> 0x7FFF`); chains without action grants remain valid.
    /// The door verifies these bytes using the author key, then combines the root
    /// rules with link restrictions for local checks before networking
    /// ([`crate::agent::verify_grant_chain_with_actions`]).
    pub const ACTION_GRANT: u16 = 0x8002;
}

/// Number of documents in a chain: grant and links through the holder.
///
/// Derived from maximum delegation depth, not chosen independently: two numbers
/// for the same limit would diverge on its first change, silently — an oversized
/// response would look like wire corruption.
pub const MAX_CHAIN_DOCUMENTS: usize = 1usize.saturating_add(crate::agent::MAX_GRANT_DEPTH as usize);

/// Assemble grant and links into a [`Response::Chain`] body.
///
/// One function for both wire endpoints: stream layout is defined here,
/// and only here. Two assemblers of one stream would diverge at the first
/// nonstandard-length document.
///
/// # Errors
/// [`FormatError`] if there are no documents, more than
/// [`MAX_CHAIN_DOCUMENTS`], or any document is empty or exceeds
/// [`MAX_DOCUMENT`].
pub fn join_chain(documents: &[&[u8]]) -> Result<Vec<u8>, FormatError> {
    if documents.is_empty() || documents.len() > MAX_CHAIN_DOCUMENTS {
        return Err(FormatError::BadFieldLength { tag: 0, len: documents.len() });
    }
    let mut body = Vec::new();
    for document in documents {
        if document.is_empty() || document.len() > MAX_DOCUMENT {
            return Err(FormatError::BadFieldLength { tag: 0, len: document.len() });
        }
        let len = u32::try_from(document.len()).map_err(|_| FormatError::OffsetOverflow)?;
        body.extend_from_slice(&len.to_le_bytes());
        body.extend_from_slice(document);
    }
    Ok(body)
}

/// Parse a [`Response::Chain`] body into documents.
///
/// Strict: truncation inside a record or trailing bytes after the last are rejected,
/// not “nearly correct.” Check the document-count limit WITHIN THE LOOP, before allocating
/// the next document: another party supplies the stream length.
///
/// # Errors
/// [`FormatError`] on truncation, trailing bytes, an empty stream, or exceeding the limit.
pub fn split_chain(body: &[u8]) -> Result<Vec<&[u8]>, FormatError> {
    let bad = |len: usize| FormatError::BadFieldLength { tag: 0, len };
    let mut out: Vec<&[u8]> = Vec::new();
    let mut rest = body;
    while !rest.is_empty() {
        if out.len() >= MAX_CHAIN_DOCUMENTS {
            return Err(bad(out.len().saturating_add(1)));
        }
        let (head, tail) = rest.split_at_checked(4).ok_or_else(|| bad(rest.len()))?;
        let len = u32::from_le_bytes(head.try_into().map_err(|_| bad(rest.len()))?) as usize;
        if len == 0 || len > MAX_DOCUMENT {
            return Err(bad(len));
        }
        let (document, after) = tail.split_at_checked(len).ok_or_else(|| bad(len))?;
        out.push(document);
        rest = after;
    }
    if out.is_empty() {
        return Err(bad(0));
    }
    Ok(out)
}

fn view_request(since: u64, upto: u64) -> Vec<u8> {
    let mut body = Vec::with_capacity(16);
    body.extend_from_slice(&since.to_le_bytes());
    body.extend_from_slice(&upto.to_le_bytes());
    body
}

fn decode_view_request(body: &[u8]) -> Result<(u64, u64), FormatError> {
    let raw: &[u8; 16] = body.try_into().map_err(|_| FormatError::BadFieldLength { tag: 0, len: body.len() })?;
    let (since, upto) = raw.split_at(8);
    let bad = |_| FormatError::BadFieldLength { tag: 0, len: body.len() };
    Ok((u64::from_le_bytes(since.try_into().map_err(bad)?), u64::from_le_bytes(upto.try_into().map_err(bad)?)))
}

const NOTICE_HEARTBEAT: u8 = 0;
/// Journal-event notification kind. Values 1–3 are retired; `event` identifies
/// the journal record type.
const NOTICE_EVENT: u8 = 4;
/// Event body: number (8) ‖ kind (1) ‖ file (16) ‖ has-fingerprint (1) ‖
/// fingerprint (32, zeros if absent). Fixed layout, exact length.
const NOTICE_EVENT_LEN: usize = 8 + 1 + 16 + 1 + 32;

fn encode_notice(notice: &Notice) -> Vec<u8> {
    match notice {
        Notice::Heartbeat => vec![NOTICE_HEARTBEAT],
        Notice::Event { seq, event, file_id, device_fpr } => {
            let mut out = Vec::with_capacity(NOTICE_EVENT_LEN.saturating_add(1));
            out.push(NOTICE_EVENT);
            out.extend_from_slice(&seq.to_le_bytes());
            out.push(*event);
            out.extend_from_slice(file_id);
            match device_fpr {
                Some(fpr) => {
                    out.push(1);
                    out.extend_from_slice(fpr);
                }
                None => {
                    out.push(0);
                    out.extend_from_slice(&[0u8; 32]);
                }
            }
            out
        }
    }
}

/// Exact lengths (I-8): heartbeat exactly one byte, event exactly
/// fifty-nine. Trailing bytes mean layout disagreement, not “extra data.”
fn decode_notice(bytes: &[u8]) -> Result<Notice, FormatError> {
    let (kind, body) = split_kind(bytes)?;
    match kind {
        NOTICE_HEARTBEAT => no_body(body).map(|()| Notice::Heartbeat),
        NOTICE_EVENT => {
            if body.len() != NOTICE_EVENT_LEN {
                return Err(FormatError::BadFieldLength { tag: 0, len: body.len() });
            }
            let bad = || FormatError::BadFieldLength { tag: 0, len: body.len() };
            let seq = u64::from_le_bytes(body.get(..8).and_then(|b| b.try_into().ok()).ok_or_else(bad)?);
            let event = *body.get(8).ok_or_else(bad)?;
            let file_id: [u8; 16] = body.get(9..25).and_then(|b| b.try_into().ok()).ok_or_else(bad)?;
            let has = *body.get(25).ok_or_else(bad)?;
            let fpr: [u8; 32] = body.get(26..58).and_then(|b| b.try_into().ok()).ok_or_else(bad)?;
            let device_fpr = match has {
                0 => None,
                1 => Some(fpr),
                _ => return Err(bad()),
            };
            Ok(Notice::Event { seq, event, file_id, device_fpr })
        }
        other => Err(FormatError::UnknownCriticalField { tag: u16::from(other) }),
    }
}

/// Subscription: `since` (8) ‖ file count (1) ‖ 16-byte files. Exact length.
fn encode_watch(files: &[[u8; 16]], since: u64) -> Result<Vec<u8>, FormatError> {
    if files.is_empty() || files.len() > MAX_WATCH_FILES {
        return Err(FormatError::BadFieldLength { tag: 0, len: files.len() });
    }
    let mut out = Vec::with_capacity(9usize.saturating_add(files.len().saturating_mul(16)));
    out.extend_from_slice(&since.to_le_bytes());
    out.push(u8::try_from(files.len()).map_err(|_| FormatError::BadFieldLength { tag: 0, len: files.len() })?);
    for file in files {
        out.extend_from_slice(file);
    }
    Ok(out)
}

fn decode_watch(body: &[u8]) -> Result<Request, FormatError> {
    let bad = || FormatError::BadFieldLength { tag: 0, len: body.len() };
    let since = u64::from_le_bytes(body.get(..8).and_then(|b| b.try_into().ok()).ok_or_else(bad)?);
    let count = usize::from(*body.get(8).ok_or_else(bad)?);
    if count == 0 || count > MAX_WATCH_FILES {
        return Err(bad());
    }
    let rest = body.get(9..).ok_or_else(bad)?;
    if rest.len() != count.saturating_mul(16) {
        return Err(bad());
    }
    let files = rest
        .chunks_exact(16)
        .map(|chunk| <[u8; 16]>::try_from(chunk).map_err(|_| bad()))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Request::Watch { files, since })
}

/// [`CollectReq`] body length: `file_id(16) ‖ device_fpr(32)`.
const COLLECT_LEN: usize = 48;

/// Maximum activation-document size.
///
/// Derived from maximum header size, not chosen arbitrarily: the largest item here
/// is a server slot, part of a header and therefore no larger than one.
pub const MAX_DOCUMENT: usize = MAX_HEADER_LEN as usize;

/// Device hardware-clock reading on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockReport {
    pub reset_count: u32,
    pub clock_ms: u64,
    pub read_at: i64,
}

/// Server slot as received from the device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotBlob {
    pub enc: Vec<u8>,
    pub nonce: [u8; 24],
    pub ct: Vec<u8>,
}

/// Activation request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivateReq {
    pub file_id: [u8; 16],
    pub policy_hash: [u8; 32],
    pub device_fpr: [u8; 32],
    pub device_kem: u8,
    pub device_public: Vec<u8>,
    pub server_slot: SlotBlob,
    pub lease_seconds: i64,
    pub device_clock: Option<ClockReport>,
    /// Operation identity (K28). `None` means an old request without identity.
    pub operation_id: Option<[u8; 32]>,
}

/// Grant: share and signed lease.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    pub share: Vec<u8>,
    pub lease: Vec<u8>,
    /// Operation-identity echo — [`grant_tag::OPERATION_ID`].
    pub operation_id: Option<[u8; 32]>,
}

/// Refusal.
///
/// Text rather than a code, deliberately, not carelessly. The server has its own
/// refusal taxonomy; transmitting it would introduce a SECOND numbered
/// registry that would diverge from the first. The client has nothing to distinguish:
/// every refusal means “no lease,” hence denial under I-10. The engine wire
/// makes the same choice for the same reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deny {
    pub text: String,
    /// Operation-identity echo — [`deny_tag::OPERATION_ID`].
    pub operation_id: Option<[u8; 32]>,
}

impl Deny {
    /// Refusal without echo: any refusal not recorded under an operation identity.
    #[must_use]
    pub fn text(text: impl Into<String>) -> Self {
        Self { text: text.into(), operation_id: None }
    }
}

fn put_blob(w: &mut TlvWriter, tag: u16, value: &[u8]) -> Result<(), FormatError> {
    w.put(tag, value)
}

/// Encode an activation request.
///
/// # Errors
/// Returns [`FormatError`] if a value does not fit the declared length.
pub fn encode_req(req: &ActivateReq) -> Result<Vec<u8>, FormatError> {
    let mut w = TlvWriter::new();
    put_blob(&mut w, req_tag::FILE_ID, &req.file_id)?;
    put_blob(&mut w, req_tag::POLICY_HASH, &req.policy_hash)?;
    put_blob(&mut w, req_tag::DEVICE_FPR, &req.device_fpr)?;
    put_blob(&mut w, req_tag::DEVICE_KEM, &[req.device_kem])?;
    put_blob(&mut w, req_tag::DEVICE_PUBLIC, &req.device_public)?;

    let mut slot = Vec::new();
    let enc_len =
        u32::try_from(req.server_slot.enc.len()).map_err(|_| FormatError::OffsetOverflow)?;
    slot.extend_from_slice(&enc_len.to_le_bytes());
    slot.extend_from_slice(&req.server_slot.enc);
    slot.extend_from_slice(&req.server_slot.nonce);
    let ct_len = u32::try_from(req.server_slot.ct.len()).map_err(|_| FormatError::OffsetOverflow)?;
    slot.extend_from_slice(&ct_len.to_le_bytes());
    slot.extend_from_slice(&req.server_slot.ct);
    put_blob(&mut w, req_tag::SERVER_SLOT, &slot)?;

    put_blob(&mut w, req_tag::LEASE_SECONDS, &req.lease_seconds.to_le_bytes())?;

    if let Some(clock) = req.device_clock {
        let mut value = Vec::with_capacity(20);
        value.extend_from_slice(&clock.reset_count.to_le_bytes());
        value.extend_from_slice(&clock.clock_ms.to_le_bytes());
        value.extend_from_slice(&clock.read_at.to_le_bytes());
        put_blob(&mut w, req_tag::DEVICE_CLOCK, &value)?;
    }

    if let Some(id) = &req.operation_id {
        put_blob(&mut w, req_tag::OPERATION_ID, id)?;
    }

    Ok(w.finish().to_vec())
}

/// Parse an activation request.
///
/// # Errors
/// Returns [`FormatError`] on truncation, an unknown tag, incorrect
/// field length, or a missing required field.
pub fn decode_req(bytes: &[u8]) -> Result<ActivateReq, FormatError> {
    if bytes.len() > MAX_DOCUMENT {
        return Err(FormatError::OffsetOverflow);
    }
    let mut reader = TlvReader::new(bytes);
    let (mut file_id, mut policy_hash, mut device_fpr) = (None, None, None);
    let (mut device_kem, mut device_public, mut slot) = (None, None, None);
    let (mut lease_seconds, mut device_clock, mut operation_id) = (None, None, None);

    while let Some(field) = reader.next_field()? {
        match field.tag {
            req_tag::FILE_ID => file_id = Some(exact16(field.tag, field.value)?),
            req_tag::POLICY_HASH => policy_hash = Some(exact32(field.tag, field.value)?),
            req_tag::DEVICE_FPR => device_fpr = Some(exact32(field.tag, field.value)?),
            req_tag::DEVICE_KEM => {
                let [byte] = field.value else {
                    return Err(FormatError::BadFieldLength { tag: field.tag, len: field.value.len() });
                };
                device_kem = Some(*byte);
            }
            req_tag::DEVICE_PUBLIC => {
                // Длина не проверяется здесь по механизму намеренно: механизм
                // объявлен СОСЕДНИМ полем, а порядок полей задаёт отправитель.
                // Сверку «длина соответствует kem_id» делает тот, кто принимает
                // разобранный документ, — там она уже есть для слотов, и второго
                // места, где решается длина ключа, заводить нельзя.
                if field.value.is_empty() {
                    return Err(FormatError::BadFieldLength { tag: field.tag, len: field.value.len() });
                }
                device_public = Some(field.value.to_vec());
            }
            req_tag::SERVER_SLOT => slot = Some(decode_slot(field.value)?),
            req_tag::LEASE_SECONDS => {
                let value: [u8; 8] =
                    field.value.try_into().map_err(|_| FormatError::BadFieldLength { tag: field.tag, len: field.value.len() })?;
                lease_seconds = Some(i64::from_le_bytes(value));
            }
            req_tag::DEVICE_CLOCK => {
                let reset = field.value.get(..4).ok_or(FormatError::BadFieldLength { tag: field.tag, len: field.value.len() })?;
                let ms = field.value.get(4..12).ok_or(FormatError::BadFieldLength { tag: field.tag, len: field.value.len() })?;
                let at = field.value.get(12..20).ok_or(FormatError::BadFieldLength { tag: field.tag, len: field.value.len() })?;
                if field.value.len() != 20 {
                    return Err(FormatError::BadFieldLength { tag: field.tag, len: field.value.len() });
                }
                device_clock = Some(ClockReport {
                    reset_count: u32::from_le_bytes(
                        reset.try_into().map_err(|_| FormatError::BadFieldLength { tag: field.tag, len: field.value.len() })?,
                    ),
                    clock_ms: u64::from_le_bytes(
                        ms.try_into().map_err(|_| FormatError::BadFieldLength { tag: field.tag, len: field.value.len() })?,
                    ),
                    read_at: i64::from_le_bytes(
                        at.try_into().map_err(|_| FormatError::BadFieldLength { tag: field.tag, len: field.value.len() })?,
                    ),
                });
            }
            // Длина точная (И-8): короткое тождество, дополненное нулями, совпало
            // бы с чужим, а длинное, обрезанное, — тоже.
            req_tag::OPERATION_ID => operation_id = Some(exact32(field.tag, field.value)?),
            other => crate::unknown::refuse_if_critical(other)?,
        }
    }

    Ok(ActivateReq {
        file_id: file_id.ok_or(FormatError::MissingField { tag: req_tag::FILE_ID })?,
        policy_hash: policy_hash.ok_or(FormatError::MissingField { tag: req_tag::POLICY_HASH })?,
        device_fpr: device_fpr.ok_or(FormatError::MissingField { tag: req_tag::DEVICE_FPR })?,
        device_kem: device_kem.ok_or(FormatError::MissingField { tag: req_tag::DEVICE_KEM })?,
        device_public: device_public
            .ok_or(FormatError::MissingField { tag: req_tag::DEVICE_PUBLIC })?,
        server_slot: slot.ok_or(FormatError::MissingField { tag: req_tag::SERVER_SLOT })?,
        lease_seconds: lease_seconds
            .ok_or(FormatError::MissingField { tag: req_tag::LEASE_SECONDS })?,
        device_clock,
        operation_id,
    })
}

fn decode_slot(bytes: &[u8]) -> Result<SlotBlob, FormatError> {
    let enc_len = read_len(bytes, 0)?;
    let enc_from = 4usize;
    let enc_to = enc_from.checked_add(enc_len).ok_or(FormatError::OffsetOverflow)?;
    let enc = bytes.get(enc_from..enc_to).ok_or(FormatError::OffsetOverflow)?.to_vec();

    let nonce_to = enc_to.checked_add(24).ok_or(FormatError::OffsetOverflow)?;
    let nonce: [u8; 24] = bytes
        .get(enc_to..nonce_to)
        .ok_or(FormatError::OffsetOverflow)?
        .try_into()
        .map_err(|_| FormatError::OffsetOverflow)?;

    let ct_len = read_len(bytes, nonce_to)?;
    let ct_from = nonce_to.checked_add(4).ok_or(FormatError::OffsetOverflow)?;
    let ct_to = ct_from.checked_add(ct_len).ok_or(FormatError::OffsetOverflow)?;
    let ct = bytes.get(ct_from..ct_to).ok_or(FormatError::OffsetOverflow)?.to_vec();

    // Хвост после слота — отказ: он означает, что стороны понимают раскладку
    // по-разному, и молчаливое проглатывание позволило бы дописать что угодно.
    if ct_to != bytes.len() {
        return Err(FormatError::OffsetOverflow);
    }
    Ok(SlotBlob { enc, nonce, ct })
}

fn read_len(bytes: &[u8], at: usize) -> Result<usize, FormatError> {
    let to = at.checked_add(4).ok_or(FormatError::OffsetOverflow)?;
    let raw = bytes.get(at..to).ok_or(FormatError::OffsetOverflow)?;
    let value = u32::from_le_bytes(raw.try_into().map_err(|_| FormatError::OffsetOverflow)?);
    Ok(value as usize)
}

fn exact16(tag: u16, value: &[u8]) -> Result<[u8; 16], FormatError> {
    value.try_into().map_err(|_| FormatError::BadFieldLength { tag, len: value.len() })
}

fn exact32(tag: u16, value: &[u8]) -> Result<[u8; 32], FormatError> {
    value.try_into().map_err(|_| FormatError::BadFieldLength { tag, len: value.len() })
}

/// Encode a grant.
///
/// # Errors
/// Returns [`FormatError`] if a value does not fit the declared length.
pub fn encode_grant(grant: &Grant) -> Result<Vec<u8>, FormatError> {
    let mut w = TlvWriter::new();
    put_blob(&mut w, grant_tag::SHARE, &grant.share)?;
    put_blob(&mut w, grant_tag::LEASE, &grant.lease)?;
    if let Some(id) = &grant.operation_id {
        put_blob(&mut w, grant_tag::OPERATION_ID, id)?;
    }
    Ok(w.finish().to_vec())
}

/// Parse a grant.
///
/// # Errors
/// Returns [`FormatError`] on truncation, an unknown tag, or
/// a missing required field.
pub fn decode_grant(bytes: &[u8]) -> Result<Grant, FormatError> {
    if bytes.len() > MAX_DOCUMENT {
        return Err(FormatError::OffsetOverflow);
    }
    let mut reader = TlvReader::new(bytes);
    let (mut share, mut lease, mut operation_id) = (None, None, None);
    while let Some(field) = reader.next_field()? {
        match field.tag {
            grant_tag::SHARE => share = Some(field.value.to_vec()),
            grant_tag::LEASE => lease = Some(field.value.to_vec()),
            grant_tag::OPERATION_ID => operation_id = Some(exact32(field.tag, field.value)?),
            other => crate::unknown::refuse_if_critical(other)?,
        }
    }
    Ok(Grant {
        share: share.ok_or(FormatError::MissingField { tag: grant_tag::SHARE })?,
        lease: lease.ok_or(FormatError::MissingField { tag: grant_tag::LEASE })?,
        operation_id,
    })
}

/// Encode a refusal.
///
/// # Errors
/// Returns [`FormatError`] if the text does not fit the declared length.
pub fn encode_deny(deny: &Deny) -> Result<Vec<u8>, FormatError> {
    let mut w = TlvWriter::new();
    put_blob(&mut w, deny_tag::TEXT, deny.text.as_bytes())?;
    if let Some(id) = &deny.operation_id {
        put_blob(&mut w, deny_tag::OPERATION_ID, id)?;
    }
    Ok(w.finish().to_vec())
}

/// Parse a refusal.
///
/// # Errors
/// Returns [`FormatError`] on truncation, an unknown tag, non-UTF-8
/// text, or a missing required field.
pub fn decode_deny(bytes: &[u8]) -> Result<Deny, FormatError> {
    if bytes.len() > MAX_DOCUMENT {
        return Err(FormatError::OffsetOverflow);
    }
    let mut reader = TlvReader::new(bytes);
    let (mut text, mut operation_id) = (None, None);
    while let Some(field) = reader.next_field()? {
        match field.tag {
            deny_tag::TEXT => {
                text = Some(
                    String::from_utf8(field.value.to_vec())
                        .map_err(|_| FormatError::BadFieldLength { tag: deny_tag::TEXT, len: field.value.len() })?,
                );
            }
            deny_tag::OPERATION_ID => operation_id = Some(exact32(field.tag, field.value)?),
            other => crate::unknown::refuse_if_critical(other)?,
        }
    }
    Ok(Deny { text: text.ok_or(FormatError::MissingField { tag: deny_tag::TEXT })?, operation_id })
}

/// Encode a greeting.
///
/// # Errors
/// Returns [`FormatError`] if a value does not fit the declared length.
pub fn encode_hello(hello: &Hello) -> Result<Vec<u8>, FormatError> {
    let mut w = TlvWriter::new();
    w.put(hello_tag::DEVICE_FPR, &hello.device_fpr)?;
    w.put(hello_tag::DEVICE_PUBLIC, &hello.device_public)?;
    if let Some(tpm) = &hello.device_tpm {
        w.put(hello_tag::DEVICE_TPM, tpm)?;
    }
    if let Some((kem, public)) = &hello.device_hybrid {
        w.put(hello_tag::DEVICE_HYBRID_KEM, &[*kem])?;
        w.put(hello_tag::DEVICE_HYBRID_PUBLIC, public)?;
    }
    Ok(w.finish().to_vec())
}

/// Parse a greeting.
///
/// # Errors
/// Returns [`FormatError`] on truncation, an unknown tag, incorrect
/// field length, or a missing required field.
pub fn decode_hello(bytes: &[u8]) -> Result<Hello, FormatError> {
    let mut reader = TlvReader::new(bytes);
    let (mut fpr, mut public, mut tpm) = (None, None, None);
    let (mut hybrid_kem, mut hybrid_public): (Option<u8>, Option<Vec<u8>>) = (None, None);
    while let Some(field) = reader.next_field()? {
        match field.tag {
            hello_tag::DEVICE_FPR => fpr = Some(exact32(field.tag, field.value)?),
            hello_tag::DEVICE_PUBLIC => public = Some(exact32(field.tag, field.value)?),
            hello_tag::DEVICE_TPM => {
                // Длина аппаратного ключа проверяется точно: SEC1 без сжатия —
                // 65 байт, и «почти столько» здесь не бывает (И-8).
                if field.value.len() != 65 {
                    return Err(FormatError::BadFieldLength {
                        tag: field.tag,
                        len: field.value.len(),
                    });
                }
                tpm = Some(field.value.to_vec());
            }
            hello_tag::DEVICE_HYBRID_KEM => {
                let [byte] = field.value else {
                    return Err(FormatError::BadFieldLength {
                        tag: field.tag,
                        len: field.value.len(),
                    });
                };
                hybrid_kem = Some(*byte);
            }
            hello_tag::DEVICE_HYBRID_PUBLIC => hybrid_public = Some(field.value.to_vec()),
            other => crate::unknown::refuse_if_critical(other)?,
        }
    }
    // ПАРА ИЛИ НИЧЕГО. Механизм без ключа — заявка без предъявления; ключ без
    // механизма — байты, чью длину не с чем сверить. Оба случая отвергаются на
    // разборе, а не «пропускаются как необязательные»: незнание механизма
    // означало бы угадывание длины, а угадывание длины — это И-8 наоборот.
    let device_hybrid = match (hybrid_kem, hybrid_public) {
        (Some(kem), Some(public)) => {
            // Длина проверяется ПО механизму. Тот же реестр, что у слотов.
            let expected = match kem {
                4 => oc_crypto::xwing::PUBLIC_KEY_LEN,
                5 => oc_crypto::mlkem_p256::PUBLIC_KEY_LEN,
                // Классические механизмы в этом поле не предъявляются: для них
                // есть `device_public`, и второе место для той же величины
                // разошлось бы с первым.
                _ => {
                    return Err(FormatError::BadFieldLength {
                        tag: hello_tag::DEVICE_HYBRID_KEM,
                        len: 1,
                    });
                }
            };
            if public.len() != expected {
                return Err(FormatError::BadFieldLength {
                    tag: hello_tag::DEVICE_HYBRID_PUBLIC,
                    len: public.len(),
                });
            }
            Some((kem, public))
        }
        (None, None) => None,
        (Some(_), None) => {
            return Err(FormatError::MissingField { tag: hello_tag::DEVICE_HYBRID_PUBLIC });
        }
        (None, Some(_)) => {
            return Err(FormatError::MissingField { tag: hello_tag::DEVICE_HYBRID_KEM });
        }
    };
    Ok(Hello {
        device_fpr: fpr.ok_or(FormatError::MissingField { tag: hello_tag::DEVICE_FPR })?,
        device_public: public
            .ok_or(FormatError::MissingField { tag: hello_tag::DEVICE_PUBLIC })?,
        device_tpm: tpm,
        device_hybrid,
    })
}

fn encode_slot(slot: &SlotBlob) -> Result<Vec<u8>, FormatError> {
    let mut out = Vec::new();
    let enc_len = u32::try_from(slot.enc.len()).map_err(|_| FormatError::OffsetOverflow)?;
    out.extend_from_slice(&enc_len.to_le_bytes());
    out.extend_from_slice(&slot.enc);
    out.extend_from_slice(&slot.nonce);
    let ct_len = u32::try_from(slot.ct.len()).map_err(|_| FormatError::OffsetOverflow)?;
    out.extend_from_slice(&ct_len.to_le_bytes());
    out.extend_from_slice(&slot.ct);
    Ok(out)
}

/// Encode a challenge.
///
/// # Errors
/// Returns [`FormatError`] if a value does not fit the declared length.
pub fn encode_challenge(challenge: &Challenge) -> Result<Vec<u8>, FormatError> {
    let mut w = TlvWriter::new();
    w.put(challenge_tag::SOFTWARE, &encode_slot(&challenge.software)?)?;
    if let Some(hard) = &challenge.hardware {
        w.put(challenge_tag::HARDWARE, &encode_slot(hard)?)?;
    }
    if let Some(hybrid) = &challenge.hybrid {
        w.put(challenge_tag::HYBRID, &encode_slot(hybrid)?)?;
    }
    Ok(w.finish().to_vec())
}

/// Parse a challenge.
///
/// # Errors
/// Returns [`FormatError`] on truncation, an unknown tag, or
/// a missing required field.
pub fn decode_challenge(bytes: &[u8]) -> Result<Challenge, FormatError> {
    let mut reader = TlvReader::new(bytes);
    let (mut software, mut hardware, mut hybrid) = (None, None, None);
    while let Some(field) = reader.next_field()? {
        match field.tag {
            challenge_tag::SOFTWARE => software = Some(decode_slot(field.value)?),
            challenge_tag::HARDWARE => hardware = Some(decode_slot(field.value)?),
            challenge_tag::HYBRID => hybrid = Some(decode_slot(field.value)?),
            other => crate::unknown::refuse_if_critical(other)?,
        }
    }
    Ok(Challenge {
        software: software
            .ok_or(FormatError::MissingField { tag: challenge_tag::SOFTWARE })?,
        hardware,
        hybrid,
    })
}

/// Encode an echo.
///
/// # Errors
/// Returns [`FormatError`] if a value does not fit the declared length.
pub fn encode_proof(proof: &Proof) -> Result<Vec<u8>, FormatError> {
    let mut w = TlvWriter::new();
    w.put(proof_tag::ECHO, &proof.echo)?;
    Ok(w.finish().to_vec())
}

/// Parse an echo.
///
/// # Errors
/// Returns [`FormatError`] on truncation, an unknown tag, or
/// a missing required field.
pub fn decode_proof(bytes: &[u8]) -> Result<Proof, FormatError> {
    let mut reader = TlvReader::new(bytes);
    let mut echo = None;
    while let Some(field) = reader.next_field()? {
        match field.tag {
            proof_tag::ECHO => {
                if field.value.len() != 32 {
                    return Err(FormatError::BadFieldLength { tag: field.tag, len: field.value.len() });
                }
                echo = Some(field.value.to_vec());
            }
            other => crate::unknown::refuse_if_critical(other)?,
        }
    }
    Ok(Proof { echo: echo.ok_or(FormatError::MissingField { tag: proof_tag::ECHO })? })
}

/// Protocol trailing-MAC length; the outer frame length is not MAC-covered.
pub const REQUEST_MAC_LEN: usize = 32;

/// Whether this request kind is authenticated by the session MAC (K25).
///
/// One table for both endpoints: the server uses it to decide whether to verify a MAC
/// before parsing; the client, whether to add one. Two tables for one value have already
/// diverged (B6b: client failed to authenticate attestation steps the server expected).
#[must_use]
pub const fn is_session_sealed(kind: u8) -> bool {
    matches!(
        kind,
        KIND_ACTIVATE | KIND_RENEW | KIND_ATTEST_OPEN | KIND_ATTEST_EVIDENCE | KIND_ATTEST_SECRET
    )
}

/// Separate MAC before parsing fields: unauthenticated TLV must not affect the response.
/// # Errors
/// Rejects missing kind byte or incomplete MAC trailer.
pub fn split_request_mac(framed: &[u8]) -> Result<(&[u8], &[u8; 32]), FormatError> {
    let len = framed.len().checked_sub(REQUEST_MAC_LEN).filter(|n| *n > 0)
        .ok_or(FormatError::Truncated { need: 33, have: framed.len() as u64 })?;
    let (body, tail) = framed.split_at(len);
    let mac = tail.try_into().map_err(|_| FormatError::Truncated { need: 33, have: framed.len() as u64 })?;
    Ok((body, mac))
}

/// Encode a device message: kind ‖ body.
///
/// # Errors
/// Returns [`FormatError`] if the body cannot be encoded.
pub fn encode_request(request: &Request) -> Result<Vec<u8>, FormatError> {
    let (kind, body) = match request {
        Request::Hello(h) => (KIND_HELLO, encode_hello(h)?),
        Request::Prove(p) => (KIND_PROVE, encode_proof(p)?),
        Request::Activate(a) => (KIND_ACTIVATE, encode_req(a)?),
        Request::Ask(ask) => (KIND_ASK, crate::access::encode_ask(ask)?),
        Request::Requests { file_id } => (KIND_REQUESTS, file_id.to_vec()),
        Request::Collect(c) => (KIND_COLLECT, encode_collect(c)),
        Request::Decide(signed) => (KIND_DECIDE, opaque(signed)?),
        Request::Watch { files, since } => (KIND_WATCH, encode_watch(files, *since)?),
        Request::WatchAuthor { since, proof } => {
            if proof.len() <= crate::order::SIGNATURE_LEN || proof.len() > MAX_DOCUMENT {
                return Err(FormatError::BadFieldLength { tag: 0, len: proof.len() });
            }
            let mut body = Vec::with_capacity(proof.len().saturating_add(8));
            body.extend_from_slice(&since.to_le_bytes());
            body.extend_from_slice(proof);
            (KIND_WATCH_AUTHOR, body)
        }
        Request::Revocation { file_id } => (KIND_REVOCATION_REQ, file_id.to_vec()),
        Request::Renew(a) => (KIND_RENEW, encode_req(a)?),
        Request::Register { header, order } => (KIND_REGISTER, encode_register(header, order)?),
        Request::Revoke { order } => (KIND_REVOKE, opaque(order)?),
        Request::Order(order) => (KIND_ORDER, opaque(order)?),
        Request::Endorse { signer, order } => (KIND_ENDORSE, encode_endorse(signer, order)?),
        Request::Standing { file_id } => (KIND_STANDING_REQ, file_id.to_vec()),
        Request::AttestOpen => (KIND_ATTEST_OPEN, Vec::new()),
        Request::AttestEvidence(e) => (KIND_ATTEST_EVIDENCE, crate::attestation::encode_evidence(e)?),
        Request::AttestSecret(secret) => (KIND_ATTEST_SECRET, secret.to_vec()),
        Request::RegisterEdition(claim) => (KIND_REGISTER_EDITION, opaque(claim)?),
        Request::JournalView { since, upto } => (KIND_JOURNAL_VIEW_REQ, view_request(*since, *upto)),
        Request::DirectoryView { since, upto } => (KIND_DIRECTORY_VIEW_REQ, view_request(*since, *upto)),
        Request::DirectoryLookup { tenant, name, size } => {
            (KIND_DIRECTORY_LOOKUP_REQ, crate::directory::encode_lookup_request(tenant, name, *size)?)
        }
        Request::DirectoryRecords { from, count } => {
            let mut body = Vec::with_capacity(12);
            body.extend_from_slice(&from.to_le_bytes());
            body.extend_from_slice(&count.to_le_bytes());
            (KIND_DIRECTORY_RECORDS_REQ, body)
        }
        Request::Control(intent) => (KIND_CONTROL, opaque(intent)?),
        Request::Binding => (KIND_BINDING_REQ, Vec::new()),
        Request::ReplicaPush(push) => (KIND_REPLICA_PUSH, opaque(push)?),
        Request::PutGrant(grant) => (KIND_PUT_GRANT, opaque(grant)?),
        Request::PutDelegation(link) => (KIND_PUT_DELEGATION, opaque(link)?),
        Request::FetchChain { holder_fpr } => (KIND_FETCH_CHAIN, holder_fpr.to_vec()),
        Request::PutActionGrant(grant) => (KIND_PUT_ACTION_GRANT, opaque(grant)?),
        Request::RequestAction(ask) => (KIND_REQUEST_ACTION, opaque(ask)?),
        Request::ReportAction { seq, ok, digest } => {
            (KIND_REPORT_ACTION, encode_report(*seq, *ok, digest))
        }
        Request::ActionRequests { grant_id } => (KIND_ACTION_REQUESTS, grant_id.to_vec()),
        Request::DecideAction(signed) => (KIND_DECIDE_ACTION, opaque(signed)?),
    };
    let mut out = Vec::with_capacity(body.len().saturating_add(1));
    out.push(kind);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Parse a device message.
///
/// # Errors
/// Returns [`FormatError`] on an empty message, unknown kind, or
/// unparseable body.
pub fn decode_request(bytes: &[u8]) -> Result<Request, FormatError> {
    let (kind, body) = split_kind(bytes)?;
    match kind {
        KIND_HELLO => Ok(Request::Hello(decode_hello(body)?)),
        KIND_PROVE => Ok(Request::Prove(decode_proof(body)?)),
        KIND_ACTIVATE => Ok(Request::Activate(Box::new(decode_req(body)?))),
        KIND_RENEW => Ok(Request::Renew(Box::new(decode_req(body)?))),
        KIND_REGISTER => {
            let (header, order) = decode_register(body)?;
            Ok(Request::Register { header, order })
        }
        KIND_REVOKE => Ok(Request::Revoke { order: opaque(body)? }),
        KIND_ORDER => Ok(Request::Order(opaque(body)?)),
        KIND_REGISTER_EDITION => Ok(Request::RegisterEdition(opaque(body)?)),
        KIND_JOURNAL_VIEW_REQ => {
            let (since, upto) = decode_view_request(body)?;
            Ok(Request::JournalView { since, upto })
        }
        KIND_DIRECTORY_VIEW_REQ => {
            let (since, upto) = decode_view_request(body)?;
            Ok(Request::DirectoryView { since, upto })
        }
        KIND_CONTROL => Ok(Request::Control(opaque(body)?)),
        KIND_BINDING_REQ => no_body(body).map(|()| Request::Binding),
        KIND_REPLICA_PUSH => Ok(Request::ReplicaPush(opaque(body)?)),
        KIND_DIRECTORY_LOOKUP_REQ => {
            let (tenant, name, size) = crate::directory::decode_lookup_request(body)?;
            Ok(Request::DirectoryLookup { tenant, name, size })
        }
        KIND_DIRECTORY_RECORDS_REQ => {
            let raw: &[u8; 12] = body.try_into().map_err(|_| FormatError::BadFieldLength { tag: 0, len: body.len() })?;
            let (from, count) = raw.split_at(8);
            let bad = |_| FormatError::BadFieldLength { tag: 0, len: body.len() };
            let count = u32::from_le_bytes(count.try_into().map_err(bad)?);
            if count == 0 || count > crate::directory::MAX_PAGE {
                return Err(FormatError::BadFieldLength { tag: 0, len: body.len() });
            }
            Ok(Request::DirectoryRecords { from: u64::from_le_bytes(from.try_into().map_err(bad)?), count })
        }
        KIND_ENDORSE => {
            let (signer, order) = decode_endorse(body)?;
            Ok(Request::Endorse { signer, order })
        }
        KIND_STANDING_REQ => Ok(Request::Standing {
            file_id: body
                .try_into()
                .map_err(|_| FormatError::BadFieldLength { tag: 0, len: body.len() })?,
        }),
        KIND_ASK => Ok(Request::Ask(Box::new(crate::access::decode_ask(body)?))),
        KIND_REQUESTS => Ok(Request::Requests {
            // Длина проверяется ТОЧНО (И-8): короткое не дополняется нулями,
            // длинное не обрезается.
            file_id: body
                .try_into()
                .map_err(|_| FormatError::BadFieldLength { tag: 0, len: body.len() })?,
        }),
        KIND_COLLECT => Ok(Request::Collect(decode_collect(body)?)),
        KIND_DECIDE => Ok(Request::Decide(opaque(body)?)),
        KIND_WATCH => decode_watch(body),
        KIND_WATCH_AUTHOR => {
            // Длины — точно по границам (И-8): курсор ровно 8 байт, за ним
            // подписанный документ длиннее подписи и не длиннее документа.
            let (since, proof) = body
                .split_at_checked(8)
                .ok_or(FormatError::BadFieldLength { tag: 0, len: body.len() })?;
            if proof.len() <= crate::order::SIGNATURE_LEN || proof.len() > MAX_DOCUMENT {
                return Err(FormatError::BadFieldLength { tag: 0, len: proof.len() });
            }
            let since = u64::from_le_bytes(
                since.try_into().map_err(|_| FormatError::BadFieldLength { tag: 0, len: body.len() })?,
            );
            Ok(Request::WatchAuthor { since, proof: proof.to_vec() })
        }
        KIND_ATTEST_OPEN => no_body(body).map(|()| Request::AttestOpen),
        KIND_ATTEST_EVIDENCE => {
            Ok(Request::AttestEvidence(Box::new(crate::attestation::decode_evidence(body)?)))
        }
        KIND_ATTEST_SECRET => Ok(Request::AttestSecret(
            body.try_into().map_err(|_| FormatError::BadFieldLength { tag: 0, len: body.len() })?,
        )),
        KIND_REVOCATION_REQ => Ok(Request::Revocation {
            file_id: body
                .try_into()
                .map_err(|_| FormatError::BadFieldLength { tag: 0, len: body.len() })?,
        }),
        KIND_PUT_GRANT => Ok(Request::PutGrant(opaque(body)?)),
        KIND_PUT_DELEGATION => Ok(Request::PutDelegation(opaque(body)?)),
        // Длина точная (И-8): короткий отпечаток, дополненный нулями, назвал бы
        // не того держателя, а длинный, обрезанный, — тоже.
        KIND_FETCH_CHAIN => Ok(Request::FetchChain {
            holder_fpr: body
                .try_into()
                .map_err(|_| FormatError::BadFieldLength { tag: 0, len: body.len() })?,
        }),
        KIND_PUT_ACTION_GRANT => Ok(Request::PutActionGrant(opaque(body)?)),
        KIND_REQUEST_ACTION => Ok(Request::RequestAction(opaque(body)?)),
        KIND_REPORT_ACTION => decode_report(body),
        KIND_ACTION_REQUESTS => Ok(Request::ActionRequests {
            grant_id: body
                .try_into()
                .map_err(|_| FormatError::BadFieldLength { tag: 0, len: body.len() })?,
        }),
        KIND_DECIDE_ACTION => Ok(Request::DecideAction(opaque(body)?)),
        other => Err(FormatError::UnknownCriticalField { tag: u16::from(other) }),
    }
}

/// Co-author signature: key (32) ‖ signed order.
///
/// No TLV: both fields required, first fixed-length, no optional fields.
/// Same rationale as [`CollectReq`].
fn encode_endorse(signer: &[u8; 32], order: &[u8]) -> Result<Vec<u8>, FormatError> {
    let body = opaque(order)?;
    let mut out = Vec::with_capacity(body.len().saturating_add(32));
    out.extend_from_slice(signer);
    out.extend_from_slice(&body);
    Ok(out)
}

fn decode_endorse(body: &[u8]) -> Result<([u8; 32], Vec<u8>), FormatError> {
    let (head, rest) = body
        .split_at_checked(32)
        .ok_or(FormatError::BadFieldLength { tag: 0, len: body.len() })?;
    let signer = <[u8; 32]>::try_from(head)
        .map_err(|_| FormatError::BadFieldLength { tag: 0, len: head.len() })?;
    Ok((signer, opaque(rest)?))
}

fn encode_collect(c: &CollectReq) -> Vec<u8> {
    let mut out = Vec::with_capacity(COLLECT_LEN);
    out.extend_from_slice(&c.file_id);
    out.extend_from_slice(&c.device_fpr);
    out
}

fn decode_collect(bytes: &[u8]) -> Result<CollectReq, FormatError> {
    // Длина точная (И-8): короткое не дополняется нулями, длинное не режется.
    // Дополни мы короткое — отпечаток, по которому ищется решение, оказался бы
    // наполовину выбран отправителем, наполовину нами.
    if bytes.len() != COLLECT_LEN {
        return Err(FormatError::BadFieldLength { tag: 0, len: bytes.len() });
    }
    let file_id: [u8; 16] = bytes
        .get(..16)
        .and_then(|s| <[u8; 16]>::try_from(s).ok())
        .ok_or(FormatError::BadFieldLength { tag: 0, len: bytes.len() })?;
    let device_fpr: [u8; 32] = bytes
        .get(16..COLLECT_LEN)
        .and_then(|s| <[u8; 32]>::try_from(s).ok())
        .ok_or(FormatError::BadFieldLength { tag: 0, len: bytes.len() })?;
    Ok(CollectReq { file_id, device_fpr })
}

/// A body carried by the envelope WITHOUT PARSING.
///
/// Empty is rejected: no signed decision can have zero length; accepting
/// it would defer refusal until parsing, by which time the sender would already
/// have learned how far we read. Same limit as activation
/// documents: a decision is a document, not a stream.
/// Registration: `u32le(len) ‖ header ‖ order`. One length — the second document
/// runs to message end; an extra trailing byte would become part of the order
/// and therefore break its signature.
fn encode_register(header: &[u8], order: &[u8]) -> Result<Vec<u8>, FormatError> {
    if header.is_empty() || header.len() > MAX_DOCUMENT {
        return Err(FormatError::BadFieldLength { tag: 0, len: header.len() });
    }
    let order = opaque(order)?;
    let len = u32::try_from(header.len())
        .map_err(|_| FormatError::BadFieldLength { tag: 0, len: header.len() })?;
    let mut out = Vec::with_capacity(header.len().saturating_add(order.len()).saturating_add(4));
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(header);
    out.extend_from_slice(&order);
    Ok(out)
}

fn decode_register(body: &[u8]) -> Result<(Vec<u8>, Vec<u8>), FormatError> {
    let (len, rest) = body.split_at_checked(4).ok_or(FormatError::Truncated {
        need: 4,
        have: body.len() as u64,
    })?;
    let len = u32::from_le_bytes(len.try_into().map_err(|_| FormatError::Truncated {
        need: 4,
        have: body.len() as u64,
    })?);
    let len = usize::try_from(len).map_err(|_| FormatError::BadFieldLength { tag: 0, len: 0 })?;
    if len == 0 || len > MAX_DOCUMENT {
        return Err(FormatError::BadFieldLength { tag: 0, len });
    }
    let (header, order) = rest.split_at_checked(len).ok_or(FormatError::Truncated {
        need: len.saturating_add(4) as u64,
        have: body.len() as u64,
    })?;
    Ok((header.to_vec(), opaque(order)?))
}

fn opaque(bytes: &[u8]) -> Result<Vec<u8>, FormatError> {
    if bytes.is_empty() || bytes.len() > MAX_DOCUMENT {
        return Err(FormatError::BadFieldLength { tag: 0, len: bytes.len() });
    }
    Ok(bytes.to_vec())
}

/// Execution-report body: `u64le seq ‖ u8 ok ‖ digest(32)` — exactly 41 bytes.
fn encode_report(seq: u64, ok: bool, digest: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(41);
    out.extend_from_slice(&seq.to_le_bytes());
    out.push(u8::from(ok));
    out.extend_from_slice(digest);
    out
}

/// Parse a report. EXACT length, outcome strictly 0 or 1.
fn decode_report(body: &[u8]) -> Result<Request, FormatError> {
    let bad = || FormatError::BadFieldLength { tag: 0, len: body.len() };
    let seq: [u8; 8] = body.get(..8).and_then(|s| s.try_into().ok()).ok_or_else(bad)?;
    // «Байт не ноль» дал бы двести пятьдесят пять разных «удалось», и запись
    // журнала зависела бы от того, какой именно прислали.
    let ok = match body.get(8) {
        Some(0) => false,
        Some(1) => true,
        _ => return Err(bad()),
    };
    let digest: [u8; 32] = body.get(9..).and_then(|s| s.try_into().ok()).ok_or_else(bad)?;
    Ok(Request::ReportAction { seq: u64::from_le_bytes(seq), ok, digest })
}

/// Valid refusal reason: nonempty, within the limit, without characters used
/// to spoof display.
///
/// Empty means refusal: half of “refusal carries words”; the other half
/// is checking on send too, making our side incapable of producing an
/// empty refusal (mutating “reason → empty string” fails the codec).
///
/// Rejected character categories are shared (`oc_format::text`), as for
/// notes: the text is displayed beside lines the user trusts.
fn check_refusal(why: &str) -> Result<(), FormatError> {
    if why.is_empty() || why.len() > crate::action::MAX_REFUSAL {
        return Err(FormatError::BadFieldLength { tag: 0, len: why.len() });
    }
    if let Some(bad) = why.chars().find(|c| oc_format::text::is_display_unsafe(*c)) {
        return Err(FormatError::BadNoteChar { tag: 0, code: u32::from(bad) });
    }
    Ok(())
}

/// Build a [`Response::Chain`] response body: document stream and, if present,
/// lease-signing key.
///
/// The stream limit is checked here on SEND too: our writer must not
/// be able to produce a response our reader must reject.
///
/// # Errors
/// [`FormatError`] if the stream fails [`split_chain`] or the body cannot
/// be assembled.
fn encode_chain_reply(
    documents: &[u8],
    lease_verify_key: Option<&[u8; 32]>,
    action_grant: Option<&[u8]>,
) -> Result<Vec<u8>, FormatError> {
    split_chain(documents)?;
    let mut w = TlvWriter::new();
    w.put(chain_tag::DOCUMENTS, documents)?;
    if let Some(key) = lease_verify_key {
        w.put(chain_tag::LEASE_VERIFY_KEY, key)?;
    }
    if let Some(bytes) = action_grant {
        // Пустой грант действий не пишется вовсе: пустое значение и
        // отсутствие тега — два представления одного смысла, а тег
        // необязательный и потому просто опускается.
        if !bytes.is_empty() {
            w.put(chain_tag::ACTION_GRANT, bytes)?;
        }
    }
    Ok(w.finish().to_vec())
}

/// Parse a [`Response::Chain`] response body.
///
/// Document-count limit is checked BEFORE any content access:
/// the body comes from another party.
///
/// # Errors
/// [`FormatError`] on truncation, an unknown critical tag, missing document
/// stream, or incorrect key length.
#[allow(clippy::type_complexity)]
fn decode_chain_reply(
    body: &[u8],
) -> Result<(Vec<u8>, Option<[u8; 32]>, Option<Vec<u8>>), FormatError> {
    let mut reader = TlvReader::new(body);
    let (mut documents, mut key, mut actions) = (None, None, None);
    while let Some(field) = reader.next_field()? {
        match field.tag {
            chain_tag::DOCUMENTS => {
                split_chain(field.value)?;
                documents = Some(field.value.to_vec());
            }
            chain_tag::LEASE_VERIFY_KEY => key = Some(field.array::<32>()?),
            chain_tag::ACTION_GRANT => {
                // Пустое значение — не «гранта нет», а разночтение раскладки:
                // отсутствие обозначается отсутствием тега.
                if field.value.is_empty() {
                    return Err(FormatError::BadFieldLength {
                        tag: chain_tag::ACTION_GRANT,
                        len: 0,
                    });
                }
                actions = Some(field.value.to_vec());
            }
            other => crate::unknown::refuse_if_critical(other)?,
        }
    }
    Ok((
        documents.ok_or(FormatError::MissingField { tag: chain_tag::DOCUMENTS })?,
        key,
        actions,
    ))
}

/// For a contentless kind, trailing bytes mean layout disagreement, not “extra data.”
fn no_body(body: &[u8]) -> Result<(), FormatError> {
    if body.is_empty() {
        Ok(())
    } else {
        Err(FormatError::BadFieldLength { tag: 0, len: body.len() })
    }
}

/// Encode a server message.
///
/// # Errors
/// Returns [`FormatError`] if the body cannot be encoded.
pub fn encode_response(response: &Response) -> Result<Vec<u8>, FormatError> {
    let (kind, body) = match response {
        Response::Challenge(c) => (KIND_CHALLENGE, encode_challenge(c)?),
        Response::Proven => (KIND_PROVEN, Vec::new()),
        Response::Granted(g) => (KIND_GRANTED, encode_grant(g)?),
        Response::Denied(d) => (KIND_DENIED, encode_deny(d)?),
        Response::Asked { seq } => (KIND_ASKED, seq.to_le_bytes().to_vec()),
        Response::Queue(bytes) => (KIND_QUEUE, bytes.clone()),
        Response::Decided(signed) => (KIND_DECIDED, opaque(signed)?),
        Response::Waiting => (KIND_WAITING, Vec::new()),
        Response::Accepted => (KIND_ACCEPTED, Vec::new()),
        Response::Notice(notice) => (KIND_NOTICE, encode_notice(notice)),
        Response::Revocation(bytes) => (KIND_REVOCATION, opaque(bytes)?),
        Response::NotRevoked => (KIND_NOT_REVOKED, Vec::new()),
        Response::Standing(bytes) => (KIND_STANDING, opaque(bytes)?),
        Response::Endorsed { have, need } => (KIND_ENDORSED, vec![*have, *need]),
        Response::AttestNonce(nonce) => (KIND_ATTEST_NONCE, nonce.to_vec()),
        Response::AttestCredential(bytes) => {
            crate::attestation::check_credential(bytes)?;
            (KIND_ATTEST_CREDENTIAL, bytes.clone())
        }
        Response::Attested { basis } => (KIND_ATTESTED, vec![*basis]),
        Response::LogView(view) => (KIND_LOG_VIEW, view.encode()?),
        Response::DirectoryEntry(lookup) => (KIND_DIRECTORY_ENTRY, lookup.encode()?),
        Response::DirectoryRecords(records) => (KIND_DIRECTORY_RECORDS, crate::directory::encode_page(records)?),
        Response::Receipt(bytes) => (KIND_RECEIPT, opaque(bytes)?),
        Response::Binding(bytes) => (KIND_BINDING, opaque(bytes)?),
        Response::ReplicaAck(bytes) => (KIND_REPLICA_ACK, opaque(bytes)?),
        Response::ChainStored => (KIND_CHAIN_STORED, Vec::new()),
        // Потолок проверяется и на ОТПРАВКЕ: наш писатель не должен уметь
        // произвести ответ, который наш же читатель обязан отвергнуть, — иначе
        // обнаружилось бы это у двери, как «сервер прислал мусор».
        Response::Chain { documents, lease_verify_key, action_grant } => (
            KIND_CHAIN,
            encode_chain_reply(
                documents,
                lease_verify_key.as_ref(),
                action_grant.as_deref(),
            )?,
        ),
        Response::NoChain => (KIND_NO_CHAIN, Vec::new()),
        Response::ActionGranted(lease) => (KIND_ACTION_GRANTED, opaque(lease)?),
        Response::ActionPending { seq } => (KIND_ACTION_PENDING, seq.to_le_bytes().to_vec()),
        // Причина проверяется НА ОТПРАВКЕ: пустой отказ наш писатель произвести
        // не должен уметь вовсе, иначе правило «отказ несёт слова» держалось бы
        // на внимательности того, кто составляет текст.
        Response::ActionRefused { why } => {
            check_refusal(why)?;
            (KIND_ACTION_REFUSED, why.as_bytes().to_vec())
        }
        Response::ActionQueue(body) => (KIND_ACTION_QUEUE, body.clone()),
    };
    let mut out = Vec::with_capacity(body.len().saturating_add(1));
    out.push(kind);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Parse a server message.
///
/// # Errors
/// Returns [`FormatError`] on an empty message, unknown kind, or
/// unparseable body.
pub fn decode_response(bytes: &[u8]) -> Result<Response, FormatError> {
    let (kind, body) = split_kind(bytes)?;
    match kind {
        KIND_CHALLENGE => Ok(Response::Challenge(decode_challenge(body)?)),
        KIND_PROVEN => no_body(body).map(|()| Response::Proven),
        KIND_GRANTED => Ok(Response::Granted(decode_grant(body)?)),
        KIND_DENIED => Ok(Response::Denied(decode_deny(body)?)),
        KIND_QUEUE => Ok(Response::Queue(body.to_vec())),
        KIND_ASKED => {
            let raw: [u8; 8] = body
                .try_into()
                .map_err(|_| FormatError::BadFieldLength { tag: 0, len: body.len() })?;
            Ok(Response::Asked { seq: u64::from_le_bytes(raw) })
        }
        KIND_DECIDED => Ok(Response::Decided(opaque(body)?)),
        KIND_WAITING => no_body(body).map(|()| Response::Waiting),
        KIND_ACCEPTED => no_body(body).map(|()| Response::Accepted),
        KIND_NOTICE => Ok(Response::Notice(decode_notice(body)?)),
        KIND_REVOCATION => Ok(Response::Revocation(opaque(body)?)),
        KIND_NOT_REVOKED => no_body(body).map(|()| Response::NotRevoked),
        KIND_STANDING => Ok(Response::Standing(opaque(body)?)),
        KIND_LOG_VIEW => Ok(Response::LogView(Box::new(crate::witness::View::decode(body)?))),
        KIND_DIRECTORY_ENTRY => Ok(Response::DirectoryEntry(Box::new(crate::directory::Lookup::decode(body)?))),
        KIND_DIRECTORY_RECORDS => Ok(Response::DirectoryRecords(crate::directory::decode_page(body)?)),
        KIND_RECEIPT => Ok(Response::Receipt(opaque(body)?)),
        KIND_BINDING => Ok(Response::Binding(opaque(body)?)),
        KIND_REPLICA_ACK => Ok(Response::ReplicaAck(opaque(body)?)),
        KIND_CHAIN_STORED => no_body(body).map(|()| Response::ChainStored),
        // ПОТОЛОК ПРОВЕРЯЕТСЯ НА ПРИЁМЕ, до всякого обращения к содержимому:
        // тело приходит от чужой стороны, и «разобрать всё, потом посчитать»
        // означало бы выделить столько, сколько скажет собеседник.
        KIND_CHAIN => {
            let (documents, lease_verify_key, action_grant) = decode_chain_reply(body)?;
            Ok(Response::Chain { documents, lease_verify_key, action_grant })
        }
        KIND_NO_CHAIN => no_body(body).map(|()| Response::NoChain),
        KIND_ACTION_GRANTED => Ok(Response::ActionGranted(opaque(body)?)),
        KIND_ACTION_PENDING => {
            let raw: [u8; 8] = body
                .try_into()
                .map_err(|_| FormatError::BadFieldLength { tag: 0, len: body.len() })?;
            Ok(Response::ActionPending { seq: u64::from_le_bytes(raw) })
        }
        KIND_ACTION_REFUSED => {
            let why = core::str::from_utf8(body).map_err(|_| FormatError::NotUtf8 { tag: 0 })?;
            check_refusal(why)?;
            Ok(Response::ActionRefused { why: why.to_string() })
        }
        KIND_ACTION_QUEUE => Ok(Response::ActionQueue(body.to_vec())),
        KIND_ATTEST_NONCE => Ok(Response::AttestNonce(
            body.try_into().map_err(|_| FormatError::BadFieldLength { tag: 0, len: body.len() })?,
        )),
        KIND_ATTEST_CREDENTIAL => {
            crate::attestation::check_credential(body)?;
            Ok(Response::AttestCredential(body.to_vec()))
        }
        KIND_ATTESTED => match body {
            [basis @ (crate::attestation::basis::VENDOR_CERTIFICATE | crate::attestation::basis::ENROLLED_EK)] => {
                Ok(Response::Attested { basis: *basis })
            }
            other => Err(FormatError::BadFieldLength { tag: 0, len: other.len() }),
        },
        KIND_ENDORSED => match body {
            [have, need] => Ok(Response::Endorsed { have: *have, need: *need }),
            other => Err(FormatError::BadFieldLength { tag: 0, len: other.len() }),
        },
        other => Err(FormatError::UnknownCriticalField { tag: u16::from(other) }),
    }
}

fn split_kind(bytes: &[u8]) -> Result<(u8, &[u8]), FormatError> {
    let kind = *bytes.first().ok_or(FormatError::MissingField { tag: 0 })?;
    let body = bytes.get(1..).ok_or(FormatError::MissingField { tag: 0 })?;
    Ok((kind, body))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn req() -> ActivateReq {
        ActivateReq {
            file_id: [0x11; 16],
            policy_hash: [0x22; 32],
            device_fpr: [0x33; 32],
            device_kem: 1,
            device_public: vec![0x44; 32],
            server_slot: SlotBlob { enc: vec![0x55; 32], nonce: [0x66; 24], ct: vec![0x77; 48] },
            lease_seconds: 8 * 3600,
            device_clock: Some(ClockReport { reset_count: 7, clock_ms: 900_000, read_at: 1_700 }),
            operation_id: None,
        }
    }

    /// OPERATION IDENTITY SURVIVES THE WIRE, AND OLD DOCUMENTS REMAIN VALID.
    ///
    /// Three aspects of one property: an identified request, echoed grant, and echoed refusal
    /// parse back to what was encoded; a document without the field is exactly the old
    /// document (byte-identical to encoding by the build without this field); the field
    /// comes last and breaks tag order if moved (I-7).
    #[test]
    fn the_operation_id_survives_the_wire_and_documents_without_it_are_unchanged() {
        let mut r = req();
        let bare = encode_req(&r).unwrap();
        r.operation_id = Some([0xab; 32]);
        let with_id = encode_req(&r).unwrap();
        assert_eq!(decode_req(&with_id).unwrap(), r);
        // Прежние байты — префикс новых, и тег тождества — хвостовая запись.
        assert_eq!(&with_id[..bare.len()], bare.as_slice(), "поле тождества сдвинуло прежние байты");
        assert_eq!(&with_id[bare.len()..bare.len() + 2], &req_tag::OPERATION_ID.to_le_bytes());
        let mut without = r.clone();
        without.operation_id = None;
        assert_eq!(decode_req(&bare).unwrap(), without, "документ без тождества перестал разбираться");

        for grant in [
            Grant { share: vec![1; 40], lease: vec![2; 120], operation_id: None },
            Grant { share: vec![1; 40], lease: vec![2; 120], operation_id: Some([0x11; 32]) },
        ] {
            let bytes = encode_response(&Response::Granted(grant.clone())).unwrap();
            assert_eq!(decode_response(&bytes).unwrap(), Response::Granted(grant));
        }
        for deny in [Deny::text("нет"), Deny { text: "нет".to_string(), operation_id: Some([0x22; 32]) }] {
            let bytes = encode_response(&Response::Denied(deny.clone())).unwrap();
            assert_eq!(decode_response(&bytes).unwrap(), Response::Denied(deny));
        }
    }

    /// IDENTITY AND ECHO LENGTHS ARE EXACT (I-8), IN REQUESTS AND RESPONSES.
    ///
    /// A short value padded with zeros would match another identity; a long,
    /// truncated one would too. Require specifically `BadFieldLength` with the field tag,
    /// on a complete document: missing-required-field refusal is not adequate here.
    #[test]
    fn the_operation_id_and_its_echo_check_their_length_exactly() {
        let mut r = req();
        r.operation_id = Some([0x5c; 32]);
        for wrong in [31usize, 33, 0] {
            let bytes = encode_req(&r).unwrap();
            let mut reader = TlvReader::new(&bytes);
            let mut w = TlvWriter::new();
            while let Some(field) = reader.next_field().unwrap() {
                if field.tag == req_tag::OPERATION_ID {
                    w.put(field.tag, &vec![0x5c; wrong]).unwrap();
                } else {
                    w.put(field.tag, field.value).unwrap();
                }
            }
            match decode_req(&w.finish()) {
                Err(FormatError::BadFieldLength { tag, len }) => {
                    assert_eq!((tag, len), (req_tag::OPERATION_ID, wrong));
                }
                other => panic!("тождество длиной {wrong} дало {other:?}"),
            }

            let mut g = TlvWriter::new();
            g.put(grant_tag::SHARE, &[1; 8]).unwrap();
            g.put(grant_tag::LEASE, &[2; 8]).unwrap();
            g.put(grant_tag::OPERATION_ID, &vec![3; wrong]).unwrap();
            assert!(
                matches!(decode_grant(&g.finish()), Err(FormatError::BadFieldLength { tag: grant_tag::OPERATION_ID, .. })),
                "эхо выдачи длиной {wrong} принято"
            );
            let mut d = TlvWriter::new();
            d.put(deny_tag::TEXT, "нет".as_bytes()).unwrap();
            d.put(deny_tag::OPERATION_ID, &vec![4; wrong]).unwrap();
            assert!(
                matches!(decode_deny(&d.finish()), Err(FormatError::BadFieldLength { tag: deny_tag::OPERATION_ID, .. })),
                "эхо отказа длиной {wrong} принято"
            );
        }
        // Незнакомый тег ПОСЛЕ тождества по-прежнему отказ: необязательного
        // диапазона у документов активации нет.
        let mut bytes = encode_req(&r).unwrap();
        bytes.extend_from_slice(&10u16.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.push(0);
        assert!(matches!(decode_req(&bytes), Err(FormatError::UnknownCriticalField { tag: 10 })));
    }

    /// Author orders survive the wire; truncation and empty input are rejected.
    #[test]
    fn author_orders_survive_a_round_trip_and_damage_is_refused() {
        let register = Request::Register { header: vec![0x88; 300], order: vec![0x99; 120] };
        let bytes = encode_request(&register).unwrap();
        assert_eq!(bytes[0], KIND_REGISTER);
        assert_eq!(decode_request(&bytes).unwrap(), register);
        // Обрубок распоряжения провод не ловит — оно непрозрачно, и обрезанный
        // документ ловит подпись; обрубок заголовка виден по длине.
        assert!(decode_request(&bytes[..200]).is_err(), "обрубок заголовка принят");
        assert!(decode_request(&bytes[..305]).is_err(), "пустое распоряжение принято");
        assert!(encode_request(&Request::Register { header: vec![], order: vec![1] }).is_err());
        assert!(encode_request(&Request::Register { header: vec![1], order: vec![] }).is_err());

        let revoke = Request::Revoke { order: vec![0x77; 96] };
        let bytes = encode_request(&revoke).unwrap();
        assert_eq!(bytes[0], KIND_REVOKE);
        assert_eq!(decode_request(&bytes).unwrap(), revoke);
        assert!(encode_request(&Request::Revoke { order: vec![] }).is_err());
    }

    /// Attestation: three requests and three responses survive the wire; exact lengths,
    /// verdict basis strictly from the registry (B6b).
    #[test]
    fn attestation_messages_survive_the_wire_and_damage_is_refused() {
        let evidence = crate::attestation::Evidence {
            ek_public: vec![1; 316],
            ek_certificate: None,
            intermediates: vec![],
            identity_public: vec![2; 90],
            attest: vec![3; 173],
            signature: vec![4; 72],
            device_public: vec![5; 90],
        };
        for request in [
            Request::AttestOpen,
            Request::AttestEvidence(Box::new(evidence)),
            Request::AttestSecret([7; 32]),
        ] {
            let bytes = encode_request(&request).unwrap();
            assert_eq!(decode_request(&bytes).unwrap(), request);
            let mut tail = bytes.clone();
            tail.push(0);
            assert!(decode_request(&tail).is_err(), "хвост принят: {request:?}");
        }
        assert_eq!(encode_request(&Request::AttestOpen).unwrap(), vec![KIND_ATTEST_OPEN]);
        assert!(decode_request(&[KIND_ATTEST_SECRET, 1, 2]).is_err());

        let credential = vec![0, 2, 9, 9, 0, 3, 1, 2, 3];
        for response in [
            Response::AttestNonce([8; 32]),
            Response::AttestCredential(credential),
            Response::Attested { basis: crate::attestation::basis::ENROLLED_EK },
        ] {
            let bytes = encode_response(&response).unwrap();
            assert_eq!(decode_response(&bytes).unwrap(), response);
        }
        assert!(decode_response(&[KIND_ATTESTED, 0]).is_err(), "основание вне реестра");
        assert!(decode_response(&[KIND_ATTESTED, 1, 1]).is_err());
        assert!(decode_response(&[KIND_ATTEST_CREDENTIAL, 0, 5, 1]).is_err());
        assert!(decode_response(&[KIND_ATTEST_NONCE; 32]).is_err());
    }

    /// Author-scope subscription: exactly 8 cursor bytes, followed by a signed
    /// document longer than its signature; truncation and empty input rejected (B5).
    #[test]
    fn an_author_scope_subscription_survives_the_wire_and_damage_is_refused() {
        let watch = Request::WatchAuthor { since: 42, proof: vec![0x5c; 140] };
        let bytes = encode_request(&watch).unwrap();
        assert_eq!(bytes[0], KIND_WATCH_AUTHOR);
        assert_eq!(decode_request(&bytes).unwrap(), watch);
        assert!(decode_request(&bytes[..5]).is_err(), "обрубок курсора принят");
        assert!(decode_request(&bytes[..9 + 64]).is_err(), "доказательство из одной подписи принято");
        assert!(encode_request(&Request::WatchAuthor { since: 0, proof: vec![1; 64] }).is_err());
        assert!(encode_request(&Request::WatchAuthor { since: 0, proof: Vec::new() }).is_err());
    }

    /// Renewal uses the activation body under its own kind: encodes and parses,
    /// never confused with activation in either direction.
    #[test]
    fn a_renewal_is_an_activation_body_under_its_own_kind() {
        let renew = Request::Renew(Box::new(req()));
        let bytes = encode_request(&renew).unwrap();
        assert_eq!(bytes[0], KIND_RENEW);
        assert_eq!(decode_request(&bytes).unwrap(), renew);
        let activate = encode_request(&Request::Activate(Box::new(req()))).unwrap();
        assert_eq!(&bytes[1..], &activate[1..], "тела обязаны совпадать байт в байт");
        assert_ne!(decode_request(&activate).unwrap(), renew);
    }

    /// Subscriptions and notifications survive the wire; truncation and extra bytes are rejected.
    #[test]
    fn watch_and_notices_survive_a_round_trip_and_damage_is_refused() {
        let watch = Request::Watch { files: vec![[0x5a; 16], [0x5b; 16]], since: 77 };
        assert_eq!(decode_request(&encode_request(&watch).unwrap()).unwrap(), watch);
        for notice in [
            Notice::Heartbeat,
            Notice::Event { seq: 9, event: journal_event::ACCESS_DECIDED, file_id: [1; 16], device_fpr: Some([0x33; 32]) },
            Notice::Event { seq: 10, event: journal_event::REVOKED, file_id: [1; 16], device_fpr: None },
        ] {
            let bytes = encode_response(&Response::Notice(notice.clone())).unwrap();
            assert_eq!(decode_response(&bytes).unwrap(), Response::Notice(notice));
        }
        // Событие короче на байт — отказ, а не дополнение нулями (И-8).
        let mut short = encode_response(&Response::Notice(Notice::Event {
            seq: 1, event: 1, file_id: [1; 16], device_fpr: None,
        }))
        .unwrap();
        short.pop();
        assert!(decode_response(&short).is_err());
        // Сердцебиение с хвостом — разночтение раскладки, не «лишнее».
        let mut tail = encode_response(&Response::Notice(Notice::Heartbeat)).unwrap();
        tail.push(0);
        assert!(decode_response(&tail).is_err());
        // Подписка: усечённый файл — отказ; без файлов — отказ; выше потолка — отказ.
        let mut cut = encode_request(&watch).unwrap();
        cut.pop();
        assert!(decode_request(&cut).is_err());
        assert!(encode_request(&Request::Watch { files: vec![], since: 0 }).is_err());
        assert!(encode_request(&Request::Watch { files: vec![[0; 16]; MAX_WATCH_FILES + 1], since: 0 }).is_err());

        // Отзывная: запрос и оба ответа переживают провод; пустая отзывная — отказ.
        let ask = Request::Revocation { file_id: [7; 16] };
        assert_eq!(decode_request(&encode_request(&ask).unwrap()).unwrap(), ask);
        let doc = Response::Revocation(vec![9; 100]);
        assert_eq!(decode_response(&encode_response(&doc).unwrap()).unwrap(), doc);
        assert_eq!(decode_response(&encode_response(&Response::NotRevoked).unwrap()).unwrap(), Response::NotRevoked);
        assert!(encode_response(&Response::Revocation(vec![])).is_err());
    }

    /// Documents survive the wire losslessly, with clocks and without.
    #[test]
    fn the_documents_survive_a_round_trip() {
        for clock in [None, Some(ClockReport { reset_count: 0, clock_ms: 0, read_at: 0 })] {
            let mut r = req();
            r.device_clock = clock;
            assert_eq!(decode_req(&encode_req(&r).unwrap()).unwrap(), r);
        }

        let g = Grant { share: vec![1, 2, 3], lease: vec![4; 200], operation_id: None };
        assert_eq!(decode_grant(&encode_grant(&g).unwrap()).unwrap(), g);

        let d = Deny::text("исчерпан лимит устройств (2)");
        assert_eq!(decode_deny(&encode_deny(&d).unwrap()).unwrap(), d);
    }

    /// TRUNCATED, EXTRA, AND UNKNOWN DATA ARE REJECTED, NOT GUESSED AT.
    ///
    /// A document comes from another party: this is hostile-input parsing.
    /// Leniency would mean the parties interpret the layout
    /// differently, and the sender can append anything to the message.
    #[test]
    fn a_damaged_document_is_refused_rather_than_guessed() {
        let bytes = encode_req(&req()).unwrap();

        // Одна длина законна, и это не поблажка: часы НЕОБЯЗАТЕЛЬНЫ, они
        // последнее поле, и документ без них — полноценный документ устройства
        // без TPM. Требовать отказа на каждой длине значило бы требовать, чтобы
        // необязательное поле было обязательным.
        //
        // Это второй раз за сессию, когда «отказ на любой обрезке» оказывается
        // неверным ожиданием: в файле состояния сервера тем же способом законной
        // оказалась граница записи потока. Правило общее — обрезка по границе
        // даёт не испорченный документ, а другой, законный.
        let mut without_clock = req();
        without_clock.device_clock = None;
        let legal = encode_req(&without_clock).unwrap().len();
        assert!(legal < bytes.len());

        for cut in 0..bytes.len() {
            if cut == legal {
                assert!(decode_req(&bytes[..cut]).is_ok(), "документ без часов отвергнут");
                continue;
            }
            assert!(decode_req(&bytes[..cut]).is_err(), "обрезка на {cut} принята");
        }

        // НЕИЗВЕСТНЫЙ ТЕГ — на ПОЛНОМ документе, а не на огрызке.
        //
        // Первая редакция ставила тег 999 рядом с одним лишь `file_id`, и такой
        // документ отвергался по ОТСУТСТВИЮ обязательных полей — то есть тест
        // зеленел, даже когда разбор неизвестные теги молча пропускал. Проверено
        // краснотой, и это третий за сессию случай теста, проходившего не по той
        // причине.
        //
        // У документов активации необязательного диапазона нет вовсе: это не
        // контейнер, который читают клиенты чужих версий, а разговор двух сторон
        // одной сборки. Незнакомое поле означает разночтение раскладки.
        let mut full = bytes.clone();
        full.extend_from_slice(&999u16.to_le_bytes());
        full.extend_from_slice(&7u32.to_le_bytes());
        full.extend_from_slice(b"lishnee");
        assert!(decode_req(&full).is_err(), "неизвестный тег принят на полном документе");

        // Отсутствие обязательного поля.
        let mut w = TlvWriter::new();
        w.put(req_tag::FILE_ID, &[0x11; 16]).unwrap();
        assert!(decode_req(&w.finish()).is_err(), "документ без обязательных полей принят");
    }

    /// Complete valid request with one field's value replaced.
    ///
    /// Field order is preserved: [`TlvWriter`] accepts only increasing
    /// tags (I-7); reconstruction through the reader is the only way to change
    /// one value without touching the layout.
    fn req_with_field(tag: u16, value: &[u8]) -> Vec<u8> {
        let bytes = encode_req(&req()).unwrap();
        let mut reader = TlvReader::new(&bytes);
        let mut w = TlvWriter::new();
        let mut replaced = false;
        while let Some(field) = reader.next_field().unwrap() {
            if field.tag == tag {
                w.put(field.tag, value).unwrap();
                replaced = true;
            } else {
                w.put(field.tag, field.value).unwrap();
            }
        }
        assert!(replaced, "тег {tag} отсутствует в образцовом запросе: подменять нечего");
        w.finish().to_vec()
    }

    /// EXACT LENGTH CHECKS (I-8): short values are not padded, long ones not truncated.
    ///
    /// The corrupted field is in a COMPLETE document, importantly. The previous
    /// revision put a single wrong-length field in a document,
    /// which is rejected for MISSING required fields — the
    /// test would therefore pass with length checks entirely removed. Same class
    /// as the neighboring unknown-tag test, same repair: corrupt exactly
    /// one property of a valid document.
    ///
    /// This also requires EXACTLY `BadFieldLength` with EXACTLY this tag:
    /// `is_err()` was the formulation that allowed failure to arise from
    /// anywhere.
    #[test]
    fn every_fixed_field_checks_its_length_exactly() {
        for (tag, wrong) in [
            (req_tag::FILE_ID, vec![0u8; 15]),
            (req_tag::FILE_ID, vec![0u8; 17]),
            (req_tag::POLICY_HASH, vec![0u8; 31]),
            (req_tag::POLICY_HASH, vec![0u8; 33]),
            (req_tag::DEVICE_FPR, vec![0u8; 33]),
            (req_tag::DEVICE_KEM, vec![0u8; 2]),
            (req_tag::DEVICE_KEM, vec![0u8; 0]),
            (req_tag::LEASE_SECONDS, vec![0u8; 7]),
            (req_tag::LEASE_SECONDS, vec![0u8; 9]),
            (req_tag::DEVICE_CLOCK, vec![0u8; 19]),
            (req_tag::DEVICE_CLOCK, vec![0u8; 21]),
            // Пустой публичный ключ: «ключ есть, но его нет» не бывает. Длина у
            // него переменная — по механизму, — и единственная незаконная здесь
            // именно нулевая.
            (req_tag::DEVICE_PUBLIC, vec![0u8; 0]),
        ] {
            let doc = req_with_field(tag, &wrong);
            match decode_req(&doc) {
                Err(FormatError::BadFieldLength { tag: got, len }) => {
                    assert_eq!(got, tag, "отказ пришёл от чужого поля");
                    assert_eq!(len, wrong.len(), "отвергнута не та длина");
                }
                other => {
                    panic!("тег {tag}: длина {} дала {other:?}", wrong.len())
                }
            }
        }

        // Контрольная половина: та же пересборка с ПРАВИЛЬНЫМИ длинами принимается.
        // Без неё «отказ на каждой строке» не отличить от «пересборка ломает
        // документ сама по себе».
        assert!(
            decode_req(&req_with_field(req_tag::FILE_ID, &[0u8; 16])).is_ok(),
            "пересобранный запрос с законной длиной отвергнут"
        );
    }

    /// TRAILING BYTES INSIDE A SLOT ARE REJECTED.
    ///
    /// A slot carries two lengths with a nonce between them; extra bytes after ciphertext
    /// mean the sender assumes a different layout.
    #[test]
    fn trailing_bytes_inside_the_slot_are_refused() {
        let mut r = req();
        let good = encode_req(&r).unwrap();
        assert!(decode_req(&good).is_ok());

        // Собираем слот руками, с лишним байтом в конце.
        let mut slot = Vec::new();
        slot.extend_from_slice(&32u32.to_le_bytes());
        slot.extend_from_slice(&[0x55; 32]);
        slot.extend_from_slice(&[0x66; 24]);
        slot.extend_from_slice(&4u32.to_le_bytes());
        slot.extend_from_slice(&[0x77; 4]);
        slot.push(0);

        r.server_slot = SlotBlob { enc: vec![], nonce: [0; 24], ct: vec![] };
        let mut w = TlvWriter::new();
        w.put(req_tag::FILE_ID, &r.file_id).unwrap();
        w.put(req_tag::POLICY_HASH, &r.policy_hash).unwrap();
        w.put(req_tag::DEVICE_FPR, &r.device_fpr).unwrap();
        w.put(req_tag::DEVICE_KEM, &[r.device_kem]).unwrap();
        w.put(req_tag::DEVICE_PUBLIC, &r.device_public).unwrap();
        w.put(req_tag::SERVER_SLOT, &slot).unwrap();
        w.put(req_tag::LEASE_SECONDS, &r.lease_seconds.to_le_bytes()).unwrap();
        assert!(decode_req(&w.finish()).is_err(), "хвост внутри слота принят");
    }

    /// THE ENVELOPE DISTINGUISHES KINDS AND REJECTS UNKNOWN ONES.
    ///
    /// Message kind is the first byte; activation documents have no optional
    /// range at all: this is a conversation between peers of the same build.
    #[test]
    fn the_envelope_round_trips_and_refuses_unknown_kinds() {
        let hello = Hello {
            device_fpr: [0x11; 32],
            device_public: [0x22; 32],
            device_hybrid: None,
            device_tpm: Some(vec![0x04; 65]),
        };
        let r = Request::Hello(hello.clone());
        assert_eq!(decode_request(&encode_request(&r).unwrap()).unwrap(), r);

        let mut bare = hello.clone();
        bare.device_tpm = None;
        let r = Request::Hello(bare);
        assert_eq!(decode_request(&encode_request(&r).unwrap()).unwrap(), r);

        let p = Request::Prove(Proof { echo: vec![7; 32] });
        assert_eq!(decode_request(&encode_request(&p).unwrap()).unwrap(), p);

        let ch = Response::Challenge(Challenge {
            software: SlotBlob { enc: vec![1; 32], nonce: [2; 24], ct: vec![3; 48] },
            hardware: Some(SlotBlob { enc: vec![4; 65], nonce: [5; 24], ct: vec![6; 48] }),
            hybrid: Some(SlotBlob { enc: vec![7; 1120], nonce: [8; 24], ct: vec![9; 48] }),
        });
        assert_eq!(decode_response(&encode_response(&ch).unwrap()).unwrap(), ch);

        assert_eq!(
            decode_response(&encode_response(&Response::Proven).unwrap()).unwrap(),
            Response::Proven
        );

        // Неизвестный вид — отказ, а не пропуск.
        assert!(decode_request(&[99, 0, 0]).is_err(), "неизвестный вид запроса принят");
        assert!(decode_response(&[99, 0, 0]).is_err(), "неизвестный вид ответа принят");
        // Пустое сообщение — тоже отказ: вид обязателен.
        assert!(decode_request(&[]).is_err());
        assert!(decode_response(&[]).is_err());
        // У подтверждения тела нет; хвост при нём — разночтение раскладки.
        assert!(decode_response(&[5, 1]).is_err(), "хвост при подтверждении принят");
    }

    /// THE ENVELOPE ALSO CARRIES ACCESS REQUESTS; WAITING IS DISTINCT FROM REFUSAL.
    ///
    /// The latter is essential. `Waiting` and `Denied` must be DIFFERENT
    /// kinds: authors may remain silent; a recipient interpreting silence as
    /// denial would misinform the user.
    #[test]
    fn the_envelope_carries_the_access_request_and_tells_waiting_from_refusal() {
        let ask = Request::Ask(Box::new(crate::access::AskAccess {
            file_id: [0x11; 16],
            device_fpr: [0x22; 32],
            device_public: vec![0x33; 32],
            device_kem: 1,
            note: "Petr from accounting".to_string(),
        }));
        assert_eq!(decode_request(&encode_request(&ask).unwrap()).unwrap(), ask);

        let collect =
            Request::Collect(CollectReq { file_id: [0x11; 16], device_fpr: [0x22; 32] });
        assert_eq!(decode_request(&encode_request(&collect).unwrap()).unwrap(), collect);

        let decide = Request::Decide(vec![0x44; 200]);
        assert_eq!(decode_request(&encode_request(&decide).unwrap()).unwrap(), decide);

        for r in [
            Response::Asked { seq: u64::MAX },
            Response::Decided(vec![0x55; 200]),
            Response::Waiting,
            Response::Accepted,
        ] {
            assert_eq!(decode_response(&encode_response(&r).unwrap()).unwrap(), r);
        }

        // ОЖИДАНИЕ — НЕ ОТКАЗ. Проверяется на байтах, а не на типах: разными
        // должны быть именно виды сообщения, иначе получатель их не различит.
        let waiting = encode_response(&Response::Waiting).unwrap();
        let denied =
            encode_response(&Response::Denied(Deny::text("нет"))).unwrap();
        assert_ne!(waiting.first(), denied.first(), "ожидание неотличимо от отказа");

        // Тела без документа: хвост при них — разночтение раскладки.
        assert!(decode_response(&[KIND_WAITING, 0]).is_err(), "хвост при ожидании принят");
        assert!(decode_response(&[KIND_ACCEPTED, 0]).is_err(), "хвост при принятии принят");
        // Номер очереди — ровно восемь байт.
        for len in [0usize, 7, 9] {
            let mut bytes = vec![KIND_ASKED];
            bytes.extend_from_slice(&vec![0u8; len]);
            assert!(decode_response(&bytes).is_err(), "номер длиной {len} принят");
        }
        // Пустое непрозрачное тело — отказ: решения нулевой длины не бывает.
        assert!(decode_request(&[KIND_DECIDE]).is_err(), "пустое решение принято");
        assert!(decode_response(&[KIND_DECIDED]).is_err(), "пустое решение принято");
        // Длина просьбы забрать решение — точная.
        for len in [0usize, 47, 49] {
            let mut bytes = vec![KIND_COLLECT];
            bytes.extend_from_slice(&vec![0u8; len]);
            assert!(decode_request(&bytes).is_err(), "тело длиной {len} принято");
        }
    }

    /// HARDWARE-KEY LENGTH IS CHECKED EXACTLY.
    ///
    /// Uncompressed SEC1 is 65 bytes; “nearly that much” is invalid (I-8).
    /// Accepting a shorter value would pass a sender-controlled
    /// quantity into sealing.
    #[test]
    fn the_hardware_key_length_is_checked_exactly() {
        for wrong in [1usize, 32, 64, 66] {
            let mut w = TlvWriter::new();
            w.put(hello_tag::DEVICE_FPR, &[0x11; 32]).unwrap();
            w.put(hello_tag::DEVICE_PUBLIC, &[0x22; 32]).unwrap();
            w.put(hello_tag::DEVICE_TPM, &vec![0x04; wrong]).unwrap();
            assert!(decode_hello(&w.finish()).is_err(), "длина {wrong} принята");
        }
    }

    /// AGENT PROTOCOL DOCUMENTS SURVIVE THE WIRE; CORRUPTED INPUT IS REJECTED.
    ///
    /// Round-trip every new kind; reject an empty opaque body, trailing bytes
    /// on a contentless body, and wrong-length fingerprint.
    #[test]
    fn the_agent_protocol_messages_survive_the_wire_and_damage_is_refused() {
        for request in [
            Request::PutGrant(vec![0x5a; 300]),
            Request::PutDelegation(vec![0x5b; 200]),
            Request::FetchChain { holder_fpr: [0x5c; 32] },
        ] {
            let bytes = encode_request(&request).unwrap();
            assert_eq!(decode_request(&bytes).unwrap(), request);
            let mut tail = bytes.clone();
            tail.push(0);
            // Хвост ловится только у вида с точной длиной: у непрозрачных тел он
            // часть документа и ломает подпись — её и ловит получатель.
            if matches!(request, Request::FetchChain { .. }) {
                assert!(decode_request(&tail).is_err(), "хвост при отпечатке принят");
            }
        }
        // Пустое непрозрачное тело — отказ: гранта нулевой длины не бывает.
        assert!(decode_request(&[KIND_PUT_GRANT]).is_err(), "пустой грант принят");
        assert!(decode_request(&[KIND_PUT_DELEGATION]).is_err(), "пустое звено принято");
        assert!(encode_request(&Request::PutGrant(Vec::new())).is_err());
        assert!(encode_request(&Request::PutDelegation(Vec::new())).is_err());
        // Отпечаток держателя — ровно тридцать два байта (И-8).
        for len in [0usize, 31, 33] {
            let mut bytes = vec![KIND_FETCH_CHAIN];
            bytes.extend_from_slice(&vec![0u8; len]);
            assert!(decode_request(&bytes).is_err(), "отпечаток длиной {len} принят");
        }

        let chain = join_chain(&[&[0x11; 120], &[0x22; 90]]).unwrap();
        for response in [
            Response::ChainStored,
            Response::Chain {
                documents: chain.clone(),
                lease_verify_key: None,
                action_grant: None,
            },
            Response::Chain {
                documents: chain.clone(),
                lease_verify_key: Some([0x4d; 32]),
                action_grant: None,
            },
            Response::Chain {
                documents: chain,
                lease_verify_key: Some([0x4d; 32]),
                action_grant: Some(vec![0x33; 77]),
            },
            Response::NoChain,
        ] {
            let bytes = encode_response(&response).unwrap();
            assert_eq!(decode_response(&bytes).unwrap(), response);
        }
        // У ответов без содержимого хвост — разночтение раскладки.
        assert!(decode_response(&[KIND_CHAIN_STORED, 0]).is_err(), "хвост при записи принят");
        assert!(decode_response(&[KIND_NO_CHAIN, 0]).is_err(), "хвост при «цепочки нет» принят");
    }

    /// CHAIN LIMIT AND LAYOUT ARE CHECKED ON RECEIPT.
    ///
    /// Another party supplies stream length: without checks, “parse everything, then
    /// count” would allocate as much as the peer says.
    /// Positive control alongside: a chain exactly at the limit is ACCEPTED;
    /// an unconditional refusal looks the same with a broken check and with broken
    /// assembly.
    #[test]
    fn a_chain_body_is_refused_above_the_ceiling_and_when_it_does_not_add_up() {
        let full: Vec<Vec<u8>> = (0..MAX_CHAIN_DOCUMENTS).map(|n| vec![n as u8; 40]).collect();
        let refs: Vec<&[u8]> = full.iter().map(Vec::as_slice).collect();
        let body = join_chain(&refs).unwrap();
        assert_eq!(split_chain(&body).unwrap().len(), MAX_CHAIN_DOCUMENTS);
        let full_reply = Response::Chain {
            documents: body.clone(),
            lease_verify_key: Some([0x4d; 32]),
            action_grant: None,
        };
        assert!(decode_response(&encode_response(&full_reply).unwrap()).is_ok());

        // Одним документом больше потолка — отказ на обоих концах.
        let over: Vec<Vec<u8>> =
            (0..=MAX_CHAIN_DOCUMENTS).map(|n| vec![n as u8; 40]).collect();
        let over_refs: Vec<&[u8]> = over.iter().map(Vec::as_slice).collect();
        assert!(join_chain(&over_refs).is_err(), "сборка выпустила цепочку выше потолка");
        let mut too_many = body.clone();
        too_many.extend_from_slice(&40u32.to_le_bytes());
        too_many.extend_from_slice(&[0x99; 40]);
        assert!(split_chain(&too_many).is_err(), "цепочка выше потолка принята");
        assert!(
            decode_response(&[&[KIND_CHAIN], wrap_chain(&too_many).as_slice()].concat()).is_err()
        );

        // Пустая цепочка — отказ: гранта в ней нет, а «цепочки нет» говорит
        // отдельный вид.
        assert!(join_chain(&[]).is_err());
        assert!(split_chain(&[]).is_err());
        assert!(decode_response(&[KIND_CHAIN]).is_err(), "тело без потока документов принято");
        assert!(
            decode_response(&[&[KIND_CHAIN], wrap_chain(&[]).as_slice()].concat()).is_err(),
            "пустая цепочка принята"
        );

        // Обрыв внутри записи и хвост после последней — отказ, а не «почти
        // правильно».
        for cut in [1usize, 3, 5, body.len().saturating_sub(1)] {
            assert!(split_chain(&body[..cut]).is_err(), "обрубок длиной {cut} принят");
        }
        let mut tail = body.clone();
        tail.push(0);
        assert!(split_chain(&tail).is_err(), "хвост после цепочки принят");
        // Длина, обещающая больше предела документа, — отказ до выделения.
        let mut lying = (MAX_DOCUMENT as u32).saturating_add(1).to_le_bytes().to_vec();
        lying.extend_from_slice(&[0x11; 8]);
        assert!(split_chain(&lying).is_err(), "обещанная длина выше предела принята");
        // Документ нулевой длины внутри потока — тоже отказ.
        assert!(split_chain(&0u32.to_le_bytes()).is_err(), "пустой документ в потоке принят");
    }

    /// Document stream framed as a response, WITHOUT checking the stream itself.
    ///
    /// For negative tests: `encode_chain_reply` will not emit an invalid stream,
    /// while receipt is precisely what must be tested.
    fn wrap_chain(documents: &[u8]) -> Vec<u8> {
        let mut w = TlvWriter::new();
        w.put(chain_tag::DOCUMENTS, documents).unwrap();
        w.finish().to_vec()
    }

    /// ACTION-DOOR KINDS SURVIVE THE WIRE; EACH CHECKS ITS OWN SHAPE.
    ///
    /// Round-trip all nine; trailing bytes for exact-length kinds; empty
    /// opaque body; exact grant-name and number lengths.
    #[test]
    fn the_action_door_kinds_survive_the_wire_and_check_their_shapes() {
        for request in [
            Request::PutActionGrant(vec![0x11; 90]),
            Request::RequestAction(vec![0x22; 70]),
            Request::ReportAction { seq: 0x0102_0304_0506_0708, ok: true, digest: [0x33; 32] },
            Request::ReportAction { seq: 0, ok: false, digest: [0; 32] },
            Request::ActionRequests { grant_id: [0x44; 16] },
            Request::DecideAction(vec![0x55; 80]),
        ] {
            let bytes = encode_request(&request).unwrap();
            assert_eq!(decode_request(&bytes).unwrap(), request, "вид не пережил провод");
            let mut tail = bytes.clone();
            tail.push(0);
            // Хвост ловится у видов с ТОЧНОЙ длиной; у непрозрачных тел он часть
            // документа и ломает подпись — её и ловит получатель.
            if matches!(request, Request::ReportAction { .. } | Request::ActionRequests { .. }) {
                assert!(decode_request(&tail).is_err(), "хвост у вида с точной длиной принят");
            }
        }
        // Пустое непрозрачное тело — отказ на обоих концах: документа нулевой
        // длины не бывает.
        for kind in [KIND_PUT_ACTION_GRANT, KIND_REQUEST_ACTION, KIND_DECIDE_ACTION] {
            assert!(decode_request(&[kind]).is_err(), "пустое тело вида {kind} принято");
        }
        assert!(encode_request(&Request::PutActionGrant(Vec::new())).is_err());
        assert!(encode_request(&Request::RequestAction(Vec::new())).is_err());
        assert!(encode_request(&Request::DecideAction(Vec::new())).is_err());
        // Имя гранта — ровно шестнадцать байтов (И-8).
        for len in [0usize, 15, 17] {
            let mut bytes = vec![KIND_ACTION_REQUESTS];
            bytes.extend_from_slice(&vec![0u8; len]);
            assert!(decode_request(&bytes).is_err(), "имя гранта длиной {len} принято");
        }
        // Исход отчёта — строго 0 или 1: «байт не ноль» дал бы двести пятьдесят
        // пять разных «удалось», и запись журнала зависела бы от того, какой
        // именно прислали.
        for byte in [2u8, 0xff] {
            let mut bytes = vec![KIND_REPORT_ACTION];
            bytes.extend_from_slice(&0u64.to_le_bytes());
            bytes.push(byte);
            bytes.extend_from_slice(&[0x33; 32]);
            assert!(decode_request(&bytes).is_err(), "исход {byte} принят");
        }

        let queue = {
            let mut body = Vec::new();
            body.extend_from_slice(&4u32.to_le_bytes());
            body.extend_from_slice(&[0x11; 4]);
            body
        };
        for response in [
            Response::ActionGranted(vec![0x66; 100]),
            Response::ActionPending { seq: 42 },
            Response::ActionRefused { why: "ветка не та, что названа в гранте".to_string() },
            Response::ActionQueue(queue),
            // Пустая очередь законна: «никто не просит» — не отказ.
            Response::ActionQueue(Vec::new()),
        ] {
            let bytes = encode_response(&response).unwrap();
            assert_eq!(decode_response(&bytes).unwrap(), response, "ответ не пережил провод");
        }
        // Номер просьбы — ровно восемь байтов.
        for len in [0usize, 7, 9] {
            let mut bytes = vec![KIND_ACTION_PENDING];
            bytes.extend_from_slice(&vec![0u8; len]);
            assert!(decode_response(&bytes).is_err(), "номер длиной {len} принят");
        }
        // Пустая лиза — отказ: документа нулевой длины не бывает.
        assert!(decode_response(&[KIND_ACTION_GRANTED]).is_err(), "пустая лиза принята");
    }

    /// A REASONLESS REFUSAL IS NEITHER PRODUCED NOR ACCEPTED.
    ///
    /// Mutating “reason → empty string” fails the CODEC, not merely the server
    /// test: “refusal carries words” must not depend on the
    /// text writer's care. Alongside is the positive
    /// control: a nonempty reason passes.
    #[test]
    fn a_refusal_without_a_reason_is_neither_written_nor_read() {
        assert!(
            encode_response(&Response::ActionRefused { why: String::new() }).is_err(),
            "пустая причина закодирована"
        );
        assert!(decode_response(&[KIND_ACTION_REFUSED]).is_err(), "пустая причина принята");
        // Символы, которыми подделывают показ, — отказ: текст печатают рядом со
        // строками, которым человек верит.
        assert!(
            encode_response(&Response::ActionRefused { why: "ветка\nне та".to_string() }).is_err(),
            "перевод строки в причине закодирован"
        );
        // Длиннее потолка — отказ на обоих концах.
        let long = "я".repeat(crate::action::MAX_REFUSAL);
        assert!(long.len() > crate::action::MAX_REFUSAL);
        assert!(encode_response(&Response::ActionRefused { why: long.clone() }).is_err());
        assert!(decode_response(&[&[KIND_ACTION_REFUSED], long.as_bytes()].concat()).is_err());
        // Положительный контроль.
        let ok = Response::ActionRefused { why: "владелец отказал: не сегодня".to_string() };
        assert_eq!(decode_response(&encode_response(&ok).unwrap()).unwrap(), ok);
    }

    /// LEASE-SIGNING KEY IS AN OPTIONAL TAG; A RESPONSE WITHOUT IT REMAINS UNCHANGED.
    ///
    /// Three aspects of one property: response without key parses to `None`;
    /// its bytes are a PREFIX of those with key, so the tag
    /// comes last and preserves order (I-7); key length is exact (I-8).
    #[test]
    fn the_lease_verify_key_is_an_optional_tag_and_the_reply_without_it_is_unchanged() {
        let documents = join_chain(&[&[0x11; 64]]).unwrap();
        let bare = encode_response(&Response::Chain {
            documents: documents.clone(),
            lease_verify_key: None,
            action_grant: None,
        })
        .unwrap();
        let with_key = encode_response(&Response::Chain {
            documents: documents.clone(),
            lease_verify_key: Some([0x4d; 32]),
            action_grant: None,
        })
        .unwrap();
        assert_eq!(&with_key[..bare.len()], bare.as_slice(), "ключ сдвинул прежние байты");
        assert_eq!(
            decode_response(&bare).unwrap(),
            Response::Chain { documents, lease_verify_key: None, action_grant: None },
            "ответ без ключа перестал разбираться"
        );

        // Длина ключа — ровно тридцать два байта: короткий, дополненный нулями,
        // назвал бы чужой ключ.
        for len in [31usize, 33, 0] {
            let mut w = TlvWriter::new();
            w.put(chain_tag::DOCUMENTS, &join_chain(&[&[0x11; 64]]).unwrap()).unwrap();
            w.put(chain_tag::LEASE_VERIFY_KEY, &vec![0x4d; len]).unwrap();
            let bytes = [&[KIND_CHAIN], w.finish().as_slice()].concat();
            assert!(decode_response(&bytes).is_err(), "ключ длиной {len} принят");
        }
    }

    /// ACTION GRANT IS ALSO AN OPTIONAL TAG AND DOES NOT SHIFT PREVIOUS ONES.
    ///
    /// Same three aspects and reasons as the lease-signing key: a response
    /// without action grant parses to `None` (the chain may have been granted
    /// no actions at all); bytes without it are a PREFIX of bytes with it, so the tag
    /// comes last and preserves increasing order (I-7); an empty value
    /// is rejected because absence is represented by an absent tag,
    /// not emptiness.
    #[test]
    fn the_action_grant_is_an_optional_tag_and_the_reply_without_it_is_unchanged() {
        let documents = join_chain(&[&[0x11; 64]]).unwrap();
        let bare = encode_response(&Response::Chain {
            documents: documents.clone(),
            lease_verify_key: Some([0x4d; 32]),
            action_grant: None,
        })
        .unwrap();
        let with_actions = encode_response(&Response::Chain {
            documents: documents.clone(),
            lease_verify_key: Some([0x4d; 32]),
            action_grant: Some(vec![0x77; 100]),
        })
        .unwrap();
        assert_eq!(
            &with_actions[..bare.len()],
            bare.as_slice(),
            "грант действий сдвинул прежние байты"
        );
        assert_eq!(
            decode_response(&bare).unwrap(),
            Response::Chain {
                documents: documents.clone(),
                lease_verify_key: Some([0x4d; 32]),
                action_grant: None,
            },
            "ответ без гранта действий перестал разбираться"
        );

        // Пустое значение — разночтение раскладки, а не «гранта нет».
        let mut w = TlvWriter::new();
        w.put(chain_tag::DOCUMENTS, &documents).unwrap();
        w.put(chain_tag::ACTION_GRANT, &[]).unwrap();
        let bytes = [&[KIND_CHAIN], w.finish().as_slice()].concat();
        assert!(decode_response(&bytes).is_err(), "пустой грант действий принят");
    }
}
