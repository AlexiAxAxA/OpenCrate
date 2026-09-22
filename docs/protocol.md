# License server protocol

Normative document. Describes what travels over the network between the `cc` client and the server, and what the client must verify upon receiving a response.

The conventions are the same as in `docs/format.md`: integers are little-endian unless otherwise specified; `‖` means concatenation; lengths are in bytes.

A separate, unapproved proposal covers possible lifecycle, protected-channel, registry and recovery extensions. It changes neither normative bytes nor current authority and is outside this core specification. Historical implementation-status statements below must be read together with their dated amendments.

## 0. What is frozen here, and what is not yet frozen

**The lease document (§2) is frozen.** Its bytes and signature transcript have a vector in `tests/kat/lease.kat` and change only with a new document version.

**In addition to the lease, the request ENVELOPE is frozen — 2026-09-06, recorded here on 2026-09-09.** `tests/kat/derivations_wire.kat` holds K23, K24, and K25, and with K25 the request transcript: the MAC covers `u8(kind) ‖ encoded body`, and `MAC(32)` itself follows the body. Two tests check this: against the specification (`crates/oc-crypto/tests/kat.rs`) and through the client's product path (`crates/cc-cli/tests/kat_wire.rs`).

The vector also fixes the KIND NUMBER: `activate::seal_request` refuses to authenticate a body whose kind is not authenticated by the session (`oc_protocol::activation::is_session_sealed`: activation 3, renewal 22, and attestation steps 31–33, §9.11.1); changing the number therefore breaks the vector. The journal (§4) is frozen too — `tests/kat/journal.kat`, under its own document version.

**Frozen by a vector on 2026-09-15: operation identity (§9.10).** `tests/kat/operation_id.kat` holds K28, the layout of tag 9 in the activation request body, and the echo tags in a grant (3) and denial (2). The rest of the activation body is still unfrozen; these three numbers are frozen, together with the identity formula.

**The wire accepts hybrid mechanisms as of 2026-09-09.** The fingerprint is defined for all mechanisms (K27), and ownership of a hybrid key is proved in the handshake: `Hello` carries the `(kem, public)` pair in tags 4 and 5; `Challenge` carries a third challenge component in tag 3, sealed using that key's mechanism. All components share one secret; the echo is computed over their concatenation, so EVERY component must be opened.

The `device_kem != 1` rejections have been removed. Two mandatory checks replace them: the fingerprint must name the submitted key and must have been proved in this conversation. An access request deliberately has no proof — anyone may request access — and retains the first check; it suffices because that check specifically prevents name substitution.

**Document BODIES and the kind registry are not frozen.** The layout of `ActivateReq`, its tag numbers, the numbers of other message kinds, and the registry's membership have no vector; activation has no document version constant at all, unlike the lease, order, and revocation notice, each of which has its own.

**The previous qualification has been removed, and this deserves explicit mention.** This section used to say “nothing else is frozen… until the transport ships, this is an intention, not a commitment.” That condition has expired: the transport has shipped; activation, registration, and revocation travel over the wire (§8 of this document was corrected on 2026-09-08). There is already a commitment, but specifically to the envelope: the body may be edited, while the kind number and envelope shape require a recorded decision and reissued vector (I-14).

### 0.1. Document encoding and the tag-range rule — decision of 2026-09-21

Every document in this crate, except the journal-head witness (§9.13, which has an exact-length layout rather than TLV), uses the same TLV encoding as the container header: `u16` tag, `u32` length, value; fields appear in **strictly increasing tag order** (I-7).

**Protocol documents use the same tag-range rule as the container.** A tag ≤ `0x7FFF` is critical: an unknown tag in that range is rejected (`FormatError::UnknownCriticalField`). A tag > `0x7FFF` is optional: its value is skipped. `oc_format::tlv::unknown_tag_action` makes this decision — the same function as for the container; the protocol has no separate function and must not acquire one (two critical-range boundaries would silently diverge).

Until 2026-09-21, protocol parsers rejected EVERY unknown tag, regardless of range. The sole exception was the lease.

**Reason for the change.** The previous argument was “client and server update together”; it will cease to be true on release day: a solo operator runs the server, recipients use unmanaged machines, and the sides update at different times. Under the previous rule, the first new field after release would make all shipped peers fail. Before release, the change is free — there are no external clients, and client and server ship together; afterwards, it would require a wire version.

**The optional range does NOT permit forgery.** Verification order is unchanged: signatures and MACs are checked BEFORE parsing the body (I-5); unknown tags are skipped AFTERWARDS, inside bytes that have already been authenticated. Signatures cover RAW body bytes — leases, revocation notices, author orders, all control documents, and both replica records sign exactly the slice subsequently parsed — so a third party cannot append a tag in transit: the signature no longer matches. Verified by `crates/oc-protocol/tests/unknown_tags.rs`, test `a_tag_appended_after_the_signature_breaks_the_signature` (nine signed documents, a tag appended AFTER signing).

**What has NOT changed.**

* Request and response kinds (`KIND_*`) are not tags. An unknown kind is still rejected.
* Enumerations INSIDE values — lease status, attestation basis, operation outcome, inheritance mode, treatment of old leases — are not tags. An unknown value in a known field is still rejected: parsing a number and being able to implement its meaning are different things.
* Strict tag ordering, prohibition of duplicates (I-7), and exact lengths of KNOWN fields (I-8). Ordering is checked even for a skipped tag: duplicate optional tags and descending tags are rejected as `FieldsOutOfOrder`.
* The wire version. Document writers and frozen vectors (`tests/kat/`) are untouched: only parsing changes.

**Where an optional tag can occur.** Only AT THE END of the body. Every known protocol-document tag is in the critical range, and tags increase; an optional-range tag therefore exceeds every known tag. These documents have no middle position in which to insert it (unlike the container header, where optional `0x8001` is already assigned).

#### Special cases considered when making the decision

**Documents without a signature or MAC.** Greeting, challenge, proof of possession, activation request, grant, denial, access request, queue record, file status, attribute rule, attestation proof. An intermediary can append an optional tag to these, and parsing now skips it. This is harmless not because the field is ignored, but because handshake frames form part of the **conversation transcript** (K31, §9.4): it is computed over RAW frame bytes — the device uses the bytes it sent, the server the bytes it received. Editing a frame in transit makes these values diverge, and the proof-of-possession echo fails. Verified by `a_tag_smuggled_into_the_unauthenticated_hello_parts_the_handshake_transcript`. Other unauthenticated documents travel under the session MAC (K25) or make no decisions on their own.

**The author's decision (§10.5) remains STRICT; this is the only exception.** Its signature is verified over a body RECONSTRUCTED from the parsed structure rather than raw bytes (`access::decision_body`, called in `cc_authority::Authority::decide_access` and `cc_cli::granted::verified_decision`). A skipped tag disappears from that reconstruction — an outsider could therefore append a tag to an already signed decision, and the signature WOULD MATCH: the document carrying share B would become malleable, contrary to I-6. The optional range would provide no extensibility in return: a field that a new build includes in `decision_body` would still cause an old build to reject the signature. Fixing this requires a wire change — signing raw bytes, as the other documents do — and was therefore not done.

**Documents checked against themselves.** Authority binding, controllers' intent and its nested payload, receipt, transfer certificate, directory record: their parsers re-encode the parsed structure and require the ORIGINAL bytes. The comparison now uses the body WITHOUT skipped optional records: canonicality of KNOWN fields remains fully guarded, while unknown optional fields bypass that check. Entire records — tag, length, value — are removed, using the same technique as I-3.

**The cost, stated explicitly.** For documents whose BYTES carry identity, identity changes with an optional field; it cannot be otherwise:

* The controllers' intent `body_hash` (`control::open_request`) is computed over raw body bytes. The server uses it to recognize a repeated operation; resending the same intent with a new optional field under the same `operation_id` therefore yields `IdConflict`, not the previous receipt.
* The directory journal leaf (`directory::Record::leaf`) is computed over raw record bytes. A record with an optional field is a different leaf, hence a different directory version.

**Re-encoding after parsing.** A skipped tag is lost upon re-encoding; the visible instance is named: `crates/cc-cli/src/quorum.rs:126` (`resign`) — a co-author parses another party's sample proposal and encodes it with THEIR OWN bytes. The proposal is identified by its intent digest (`order::intent_digest`), which is computed over the re-encoded body; an old-build co-author and new-build server will therefore compute different digests and fail to form a quorum. The previous rule gave a clear “sample proposal cannot be parsed” failure; the new one gives a silent “still not enough signatures.” This is not fixed here: `resign` does not and cannot forward the author's signed bytes — the sample has another issue time and another signer's key — and preserving raw bytes would change the proposal's wire shape.

This decision does not affect parsing of inherited documents outside `oc-protocol`: server state (`cc_authority::store`) stores the attribute rule using that crate's own codec, and a field skipped there is lost just as in any other re-encoding.

## 1. What the server does and does not do

The server holds the **second share** of a 2-of-2 scheme and decides to whom and until when it is issued. It never sees the content encryption key (CEK): `KEK = HKDF(secret_A ‖
secret_B)`, share A is with the server, share B with the recipient, and neither opens the file alone.

This gives the storage its main property: **containers are not stored on the server**. File identifiers, device fingerprints, policy hashes, and journals are stored. A server database leak yields no openable file — it yields a list of who owned what, which is also a loss, but of a different kind.

What the server does **not** do: store content, receive the CEK, sign containers (the author signs them), or decide for the author.

> **The server acquired its own rules on 2026-09-16.** Until then, this box said “it has none at all”: `intersect` existed, was monotone, and had a property test, but nobody called it outside tests, and the server tightened exactly one thing — lease duration.
>
> Now the operator configures the server profile (`cca policy set`); it is intersected with the author's policy on every grant and **travels to the recipient in a version 2 lease**, signed by the server (§2.3). It cannot expand author-granted rights: this is a property of `intersect`, not a server promise, and the field-by-field composition rule is recorded in `docs/format.md` §4.3.
>
> The cost is stated there too: an older client build rejects a version 2 lease entirely, so updating the client is a prerequisite for tightening policy.

## 2. Lease

A server-signed permission to open **one file** on **one device** until a specified time.

### 2.1 Why a separate document rather than a container field

The container is signed by the author and does not change after release. A lease is issued, expires, is renewed, and is revoked — many times for the same file. Putting it inside would make every renewal rewrite the container, requiring a new author signature on a file the author did not touch.

Practical consequence: **the container format version does not change for the server.** The header's authority fields have been laid out and signed since version 1 — `authority.urls`, `authority.sealing_kid`, `authority.lease_verify_key` — while the lease has its own version and lifecycle.

### 2.2 Why the lease is trusted

Its signature under `authority.lease_verify_key` — the very key **the author pinned in the header under their signature**. A fake server cannot substitute its own key: replacing the verification key means replacing the header, and the author-signed header is checked by `verify_strict` (I-6).

This is the only place where the client trusts an outside party; the trust chain is short precisely because the author established it, not the network.

### 2.3 Bytes

TLV, strictly increasing tags, criticality by range — the same rules as format §2. Numbers are normative: the body is signed as **raw bytes**, so an implementation numbering fields differently would produce a different signature and silently diverge.

| Tag | Field | Type |
|---|---|---|
| 1 | `version` | u16le: 1 — without server profile, 2 — with profile, 3 — with attestation indicator |
| 2 | `file_id` | bytes[16] |
| 3 | `device_fpr` | bytes[32] |
| 4 | `policy_hash` | bytes[32] |
| 5 | `seq` | u64le |
| 6 | `epoch` | u64le |
| 7 | `issued_at` | i64le, seconds |
| 8 | `expires_at` | i64le, seconds |
| 9 | `status` | u8: 1 active, 2 revoked. **Always** written |
| 10 | `opens_remaining` | u32le or **empty value** = “no limit imposed.” **Always** written |
| 11 | `tpm_clock` | u32le `reset_count` ‖ u64le `clock_ms`; optional |
| 12 | `server_policy` | policy codec (format §4); **required in version 2, optional in version 3, forbidden in version 1** |
| 13 | `attested` | u8: basis of device-key attestation — 1 vendor certificate, 2 pinned EK; **version 3 only, and required there** (§9.11.1) |

#### Version 3: attestation indicator

Written only when the server accepted attestation of the key on which the share is sealed during the issuance conversation (§9.11.1). The version and indicator must agree in both directions; an unknown basis is a parse rejection. An older client rejects version 3 but does not receive it either: the indicator is issued only to a client that underwent attestation. Vector: `tests/kat/lease-v3.kat`.

#### Version 2: strict server profile

The server may **tighten** the author's policy and may not expand it. The operator sets the profile (`cca policy set`); it resides in server state and is intersected with the file policy on every grant using `oc_policy::intersect` — monotone only towards denial (I-10).

**The profile travels to the recipient instead of staying on the server**, which is the essential feature of version 2. A restriction applied only at issuance is removed by unplugging the network: a client holding a lease would continue enforcing only the author's policy. The profile therefore resides in the lease body, under the server's signature, and the client composes it itself — inside `oc_policy::evaluate`, not in calling code. The evaluator has many callers (`cc check`, `cc unprotect`, viewer, broker); if each applied the restriction manually, eventually one would omit it.

**The version is written according to the field's presence, and the two must agree in both directions.** A version 1 document with tag 12 is rejected (`UnknownCriticalField`), as is version 2 without tag 12 (`MissingField`). Both cases create rights nobody granted: the first would let an old client accept a document without noticing the restriction; the second means the restriction was lost in transit.

**An older client rejects version 2 entirely**; this is correct behavior, not an inconvenience: it does not know tag 12 and must not guess its meaning. The cost is explicit — client updates become a prerequisite for tightening policy; the benefit is the same as throughout I-10: an unrecognized rule closes the file rather than opening it.

**Without a profile, the bytes are unchanged.** A server with nothing to tighten issues a version 1 document, byte-for-byte identical to the document before this field existed; frozen vector `tests/kat/lease.kat` remains valid (I-14).

**`file_id` is required in a lease**, and this is not a formality: without it, permission for one file would work for any other — the cheapest possible mistake and the most expensive in consequences.

**The distinction between “field absent” and “field present but empty” is normative** for `opens_remaining`, following `max_opens` in format §4 for the same reason: an empty value is the server's written “I imposed no limit”; an absent field means its intent is unknown, and is a rejection.

**An unknown `status` is rejected during parsing**, not interpreted as a denial. Parsing a number and being able to implement it are different things: a future-version status could mean anything, and the client may not guess.

### 2.4 Signature

```
transcript = "CC/v1/lease" ‖ 0x00 ‖ u32le(len(body)) ‖ body
signature  = Ed25519(lease_verify_key, transcript)
```

The label is prefix-free relative to all others (I-12): the neighboring cache is called `"CC/v1/cached-lease"` specifically to keep `"CC/v1/lease-cache"` from extending this label.

The signature covers **raw body bytes**, not a reconstructed structure. The same rule applies to the header (format §5) and mutable area (I-5), for the same reason: reconstruction before verification reproduces the entire family of canonicalization errors known from JWS and XML-DSig.

Both body and signature are frozen: `tests/kat/lease.kat`. Leaving the transcript unfrozen would leave **exactly what** is signed unfrozen; divergence there is silent — the signature fails, appearing as “the server is broken.”

### 2.5 What the client must verify

In order, and the order matters:

1. **Signature** — with `authority.lease_verify_key` from ITS OWN container, not the server response. Before verifying the signature, the lease contents must not be parsed for any decisions.
2. **`file_id`** matches the container's `file_id`.
3. **`policy_hash`** matches the container policy hash. The server must not be able to issue permission under rules the author did not write.
4. **`device_fpr`** is ours. `oc_policy::evaluate` decides from there; all remaining checks (expiry, rollback, binding, action) reside there.

### 2.6 Lease file

Until a server exists, the lease resides in a file supplied through `cc check --lease`. Layout:

```
signature(64) ‖ body
```

The signature deliberately comes first: its length is fixed, and the reader reaches it without parsing a single body byte. This is the same doctrine that checks the mutable area's MAC before parsing its TLV (I-5): unauthenticated data must not be parsed, because distinguishable error codes for unauthenticated bytes are themselves an oracle.

When transport arrives, the same document will travel over the network unchanged: the file is a delivery mechanism, not part of the format.

## 3. Rollback protection

Three mechanisms cover different things. They must not be confused: each leaves a gap covered by the next. They are the monotonic floor, `seq`, and `tpm_clock`; `epoch` is NOT among them, for the reason below.

**`seq`** strictly increases per (file, device) pair. The client remembers `highest_seq_seen`; a smaller value means a restored cache. Gap: `highest_seq_seen` is in a state file, and that file returns with a snapshot.

**The monotonic floor** is the greatest time the client has ever seen. It detects the system clock being set back. It advances BEFORE the decision, not afterwards; otherwise an adversary who waited for a denial could obtain the clock “as before.” The gap is the same as for `seq`: the floor lives in the same state file.

**`epoch`** increases on revocation and serves as a **journal marker**, not a client check. It identifies in the server journal a lease issued before revocation.

The previous revision promised otherwise: “a client that has seen a new epoch will not accept a lease from an old one.” That promise was not and could not be fulfilled. `revoke` increments the epoch and latches `revoked` in the same call; `activate` rejects a revoked file immediately — the server therefore cannot issue a lease with an epoch above zero at all, and the check could never trigger. Nor is it needed: `revoke` leaves the sequence counter untouched, so `seq` is monotone across epochs for a (file, device) pair; any old-epoch lease also has a smaller `seq`, fully covered by the check already described.

There is one job an epoch can do that `seq` cannot: convey knowledge of revocation **outside a lease**, through a signed journal head. This is a separate mechanism; it will arrive with the transport, needs memory beside the revocation channel rather than in file counters, and its denial reason is “access revoked,” not “rollback.”

**`tpm_clock`** is the pair (`reset_count`, `clock_ms`). A decrease in **either** value is rollback.

> **This section used to specify lexicographic comparison, and that allowed rollback.** Its rationale was “the clock resets on platform reset while the counter increases, so a smaller time alone is not rollback.” That model is wrong: in TPM 2.0, `clock` is nonvolatile and survives power-off; only `TPM2_Clear` clears it, and that clears the reset counter as well. A different quantity, `time`, resets at power-on; the product deliberately does not read it.
>
> This was not merely a wording error: the pair “larger counter, smaller clock” passed as a legitimate reboot, and exactly one action could produce it — restoring a snapshot and rebooting. A check introduced to prevent snapshot rollback allowed snapshot rollback.

A reboot still is not rollback: the counter increases, `clock` continues increasing with it, and neither value decreases. Both are needed because `TPM2_Clear` clears both, and a decreasing counter is an independent signal.

This is the only mechanism surviving snapshot rollback: `seq` and the monotonic floor live in a file, whereas a snapshot does not restore the TPM counter — **if the TPM is real**. In a virtual machine with vTPM, the hypervisor restores it too; the qualification is recorded in `cc_keystore::ladder` and the README.

**Comparing direction detects less than this text previously claimed.** The previous revision promised that the TPM clock detected “both copying the folder and restoring the whole machine.” That is incorrect, and the error was measured. `presented < issued` triggers only when the clock ITSELF moves backwards, namely when a snapshot including the virtual TPM is restored. On a live machine with a real TPM, it always moves forward; an adversary who restored the profile and set back the system clock obtained permission even though live state before the copy yielded denial.

**`tpm_clock` as a measure of ELAPSED TIME.** Therefore **two elapsed durations** are compared: hardware duration — the difference in `clock_ms`; and system duration — the difference `now − issued_at`.

The supporting invariant is that the TPM clock runs **no faster** than wall time because it runs only while the machine is on. Hardware elapsed time exceeding system elapsed time therefore means exactly one thing: the system clock was set back. Restoring a profile does not change the `clock_ms` difference, so this measure survives it.

Comparing hardware elapsed time with LEASE DURATION is a mistake made in the first revision. The client takes the reading; the lease is issued later, sometimes much later. The entire gap contributes to hardware elapsed time, so a legitimate user who took a reading the previous day was denied on the first opening. Two requirements follow.

**Readings include their sampling time.** The client reports a triple: reset counter, milliseconds, and system time at that same instant. The server adjusts the reading to issue time, assuming the machine may have run throughout. Adjustment is towards a LARGER clock, hence a smaller measured elapsed duration: the error favors permission. This is deliberate — wrongly denying a legitimate user costs more here than weakening protection by the gap's length.

The sampling time is untrusted and need not be trusted: by lying, the device weakens the check in its favor by exactly the lie's magnitude and gains nothing more, because durations, not absolutes, are compared.

The two measures combine rather than replace each other. The TPM clock runs only while the machine is on: after a week powered off, it may show one minute elapsed, so hardware time alone would admit an expired lease. System time catches that case. Denial on EITHER measure is strictly stronger than either alone.

The denial has its OWN substantive reason: “hardware clock has overtaken system clock.” “Expired” is ordinary; overtaking reports a clock setback, which is what the operator needs to know.

**The device reports its own clock**; under-reporting is detected by server memory rather than trust: the server stores the greatest reading seen from that device and refuses activation for a smaller one. Once a device has presented a clock, it must continue doing so — otherwise “forgetting the TPM” would disable the check in one line.

A lease **without** a clock does not require one. A lease **with** a clock is denied if the device lacks it: “could not verify” must mean “not allowed” (I-10). The opposite would be a one-line bypass — present a clockless device and rollback checking disappears.

**A clock-read failure is not “no clock”; decision of 2026-09-15 (A2a).** The client knows one of three things about its clock: a reading, absence (non-Windows, `TBS_E_TPM_NOT_FOUND`, `TBS_E_SERVICE_DISABLED`), or a read failure (`oc_policy::DeviceClock`). Previously, the last two were one “none,” from one attempt: a transient TBS failure on a machine with a clock was called “the device did not present one,” indistinguishable from a machine without TPM (intermittent failure in `dod_scenario::a_clock_bound_licence_opens_the_file`).

* **Product processes queue** (`cc_keystore::queue`, a named mutex for the login session) for clock reads and every TPM device-key operation: TBS itself cancels simultaneous commands. The queue is not a prerequisite: after waiting 5 s, the operation proceeds without it.
* **Transient failures are retried** — up to eight attempts, pauses of 20…320 ms with jitter (`cc_keystore::clock::RETRY_PAUSES_MS`). Only codes whose documentation says “retry” are transient: TPM 2.0 warnings `TPM_RC_YIELDED`, `TPM_RC_CANCELED`, `TPM_RC_TESTING`, `TPM_RC_RETRY`, and TBS codes `TBS_E_COMMAND_CANCELED`, `TBS_E_TOO_MANY_TBS_CONTEXTS`, `TBS_E_TOO_MANY_RESOURCES`, `TBS_E_SERVICE_START_PENDING`. `TPM2_ReadClock` writes nothing and requires no authorization; retries affect neither TPM state nor guessing protection. Unknown codes and a cleared `safe` flag are not retried. Rationale and measurements: `cc_keystore::clock` and `docs/evidence/local-completion.md`, A2a.
* **A remaining failure is denied with its own reason**: `DenyReason::TpmClockUnreadable`, exit code 6 (as for I/O failure: a problem with the device at this moment), and text containing the response code and attempt count. “Retry” is advised only for a transient code that exhausted its attempts; for a persistent code, the text says the opposite (last item below), and both use the same exit code. Clock absence remains `TpmClockMissing`, code 5. The decision is unchanged in every case: a clock-bound lease without readings is denied (I-10); the reason and code change.
* **Activation and renewal do not go onto the wire after a clock-read failure.** Without readings, a server that had seen the device clock would deny with “clock was presented before, now absent” and record `ClockWithdrawnRefused` in the author's journal: a transient TBS failure would resemble an attempt to disable rollback checking. The client denies locally, code 6, sending nothing.
* **The cost is availability, explicitly acknowledged (A2a review).** A machine with persistently failing clock reads other than “absence” — TBS access denied, `TBS_E_INTERNAL_ERROR`, cleared `safe`, unknown code — cannot activate or renew ANY file, including files on servers whose leases do not require a clock: before the conversation the client does not know whether the server requires it, and a server that once saw the device clock would deny and journal it. Already issued clockless leases still open — the evaluator requests a clock only for clock-bound leases. The user's only remedy is to repair TBS/TPM; letting the user choose between “failure” and “no clock” would restore the one-line bypass. The denial text says “retry later” only for a transient code with exhausted attempts; for a persistent failure, it says retrying will not help and the denial affects any file (`cc_keystore::clock::Reading::is_persistent_failure`). All three content paths — `cc`, `ccview`, `ccbroker` — use code 6: they share one exit-code table (`cc_cli::exit`).

### 3.1. Witness outside the profile and accepted-history journal — decision of 2026-09-17 (D2)

Access state (`access-state`) stores the floor and `highest_seq_seen` threshold; this file returns with the profile. Two things protect against profile restoration, answering different questions.

**Witness head** (`cc_cli::witness`) — “has state fallen behind?” Stored within and outside the profile (`%ProgramData%\CloseCrate\<user>`), authenticated with K12 (`CC/v1/cached-lease`), and can only advance. A version 2 head (80 bytes) carries the epoch, accepted-history journal length, and final-record tag; a version 1 head (40 bytes) remains readable but does not witness the journal.

**Accepted-history journal** (`cc_cli::accepted`, file `accepted-journal` in the key directory) — “what exactly was accepted?” For each file: which lease under which `seq` (SHA-256 of verified lease bytes) and which revision under which counter. Every record is authenticated with K12 together with the preceding tag and its own number.

The order is normative for the client:

1. Verified lease or revision;
2. under the journal lock (`accepted-journal.lock`, an OS lock released upon process death): reread journal and counters from disk, compare journal against heads;
3. write journal (temporary file, `sync_all`, rename);
4. write state (likewise);
5. write head;
6. access — the first content byte.

Any write failure before step 6 denies access: acceptance is not confirmed until recorded. Interruption between writes is safe by construction: a journal ahead of state is recognized (the same lease is “already accepted” and not written twice); when state is ahead of the head, the head does not witness it until caught up. A head ahead of the journal is impossible: the head is written from a journal read or written by the same process.

Failures (all before the evaluator, exit code 6, as for I/O):

* **equivocation**: different lease bytes under an accepted `seq`, or different revision contents under an accepted counter. This represents a server issuing conflicting truths or a lease replaced after acceptance. The threshold alone missed this: the number was not below it;
* **revision rollback**: counter below the accepted one. For leases, the journal does not judge a lower number — the evaluator does so using `highest_seq_seen`; whatever it accepts is recorded;
* **truncation**: journal shorter than any head has seen;
* **history substitution**: a different tag at the length witnessed by a head — for example, a profile restored from a backup and extended with different history of the same length while the outside-profile witness was hidden. Epochs still match; state freshness cannot see this;
* **corruption**: unparseable line or broken chain. An interrupted LAST line without a newline is skipped — comparison with the head detects the journal falling behind.

Size is bounded: after 512 records, older ones are folded into a checkpoint (authenticated by the same chain; retains the highest number and digest per kind and file); the last 128 remain. The cost is explicit: equivocation OLDER than the checkpoint is detected only for the highest number; a head pointing into the compacted part is compared by length alone.

**What this does not provide.** Protection against the machine owner: K12 derives from the device key in their profile. Protection against a WHOLE-machine snapshot: the outside-profile head returns with it — only the TPM clock (above) addresses that. The refusal text states the remedy for someone who intentionally restored a profile: a new lease from the server, or deletion of witness files, removing this protection entirely.

Neither shares nor keys are written to the journal: only numbers, digests, and epochs. Tests: `cc_cli::accepted` (chain, tampering, wrong key, splicing histories, interruption, compaction, lock), `cc_cli::witness` (version 2 head), `crates/cc-cli/tests/accepted_history.rs` (using processes: substitution, revisions, truncation and deletion, same-length history substitution, five concurrent peers without loss, killing a process mid-write, write failure).

## 4. What the protocol does not provide

The list is short and honest; it is repeated in the README because it concerns users, not implementation.

- **Server–recipient collusion opens the file.** This is a boundary of the 2-of-2 scheme, not a defect: two parties hold two shares; if they cooperate, one party has both.
- **Recipient-key substitution is not prevented cryptographically.** The server supplies recipient keys and is therefore a key directory; the author pins in the header whichever key was supplied. Pinning provides **after-the-fact detection**, not prevention.
- **The device limit is a commercial control, not a cryptographic one.** An adversary presents fresh key pairs of their own, honestly proves possession of each, and consumes the limit in one go. It stops a user, not an attacker.
- **Revocation is not immediate for someone already offline.** It takes effect no later than the end of the current window; the author sets its length with `max_offline_seconds` via the `protect` flag `--offline-window`. The server does not tighten it: no server policy exists, see §1. Before the flag existed, the window always equaled lease duration, and revocation waited until its end.
- **The journal detects editing but not truncation.** The MAC chain (K13) detects record modification; detecting a discarded tail requires an external anchor — F-10.
- **The server state file is NOT AUTHENTICATED; this is a threat-model boundary.** An adversary with write access to the server directory is **outside the perimeter**: they can erase revocation, raise device limits, and roll back counters. Authenticating the file would not stop them — the authentication key would reside on the same machine and be accessible to the same adversary.

  This is recorded here because previously the decision existed only in a module docstring. A docstring is not a specification; “a decision known only to the code author” is equivalent to no decision: the next reader will consider the missing MAC an oversight and either add it needlessly or assume protection exists.

  What this boundary does NOT imply is permission to read corrupted bytes leniently. State parsing must reject malformed structures — short fields, long fields, repeated tags — and does (I-8). Partial writes and volume corruption occur without adversaries; “the weakest default” would silently turn a revoked file active.

  The real mitigation is to keep state where only the service may write, which is deployment, not format.

## 5. Activation and share issuance

After `Prove`, an `Activate`/`Renew` wire frame is `u8(kind) ‖ encoded body ‖ MAC(32)`. K25 authenticates the kind and raw body, not the outer frame length. The server requires proof and verifies the MAC BEFORE parsing fields (I-5). A missing or invalid MAC causes rejection and closes the conversation: no lease is issued and no journal entry written.

The author **registers** the file: supplies `file_id`, rules, their hash, and the device limit. Content is neither transmitted nor requested.

The device **activates**: sends its fingerprint, public key, mechanism, and the container's **`Server` slot record**. The server opens the slot with its key, obtains `secret_A`, reseals it to the device key using derivation K11, and returns it with a signed lease.

The share **does not remain** in the database. That is why a server database leak opens no container: it stores identifiers, hashes, fingerprints, and a journal — nothing secret.

K11 derivation `info`:

```
"CC/v1/a-to-device" ‖ u8(kem_id) ‖ file_id(16) ‖ device_fpr(32) ‖ u64be(seq)
```

`u8(kem_id)` was added in format version 2 before first use. A device now has two mechanisms — P-256 in the TPM and X25519 for the software tier — and without the mechanism in the derivation, a slot relabeled with a different `kem_id` would produce **the same key**. Format §3.3 analyzes this error for K10; it was not repeated.

**Reactivating a known device does not consume the limit.** Devices, not activations, are counted: otherwise reinstalling the client on the same machine would consume a slot, and one person would exhaust a three-device limit.

**Lease duration is capped at what the author permits.** The server may tighten but not expand; a request for a longer term is fulfilled with a shorter term, not rejected.

**Retrying activation is safe only under an operation identity** (§9.10, decision of 2026-09-15). A request without identity executes as before: a client losing the response and retrying receives a second grant.

### 5.1. Renewal — decision of 2026-09-03

An open document renews its lease every few minutes (F-18, tier 1); the first revision used activation for this. The cost was explicitly stated and proved unacceptable: each renewal wrote `LeaseIssued` to the author's journal and consumed the grant limit, so one reader with an open window wrote twelve records per hour and exhausted `--max-grants` alone.

Renewal therefore has **its own request kind** (`Renew`, kind 22), with the same body as activation and the same `Granted` response. The body is identical for a reason: derivation K11 includes the lease sequence number, so a new number requires a new share, obtained by the server only from the `Server` slot — renewal needs exactly the same fields. There are exactly three differences, all on the server:

* The device must be **already activated** for this file, otherwise “not activated” is returned: renewal grants nothing the device did not already have;
* **no journal entry**: renewal is continuation of an existing grant, not an event;
* **no grant-limit consumption**: the limit concerns how many devices the author agrees to give a share, not how long they read.

Everything else is checked as for activation: revocation, policy hash, proof of possession, device clock. Clock refusals are journaled here too — a rollback attempt is an event, not a grant.

**Since this date, the grant limit is counted from the journal**, not the sum of lease sequence numbers: renewal takes the next number but is not a grant. The journal is the count — the number compared with the limit and the number shown to the operator are identical by construction.

The client renews with `Renew`, then tries activation if refused: an older server does not know kind 22, while the lease is the same — at the cost of one journal entry.

## 6. Revocation

`revoke` advances the file epoch and forbids further activation. Already issued leases remain valid until expiry — otherwise revocation would mean instantly disconnecting everyone, including offline users who do not know about it.

The boundary matters and is recorded in §3: the epoch detects cache restoration **after** a new epoch has been observed. It does not catch someone who went offline one second before revocation.

### 6.1. Revocation notice — decision of 2026-09-02

Revocation implemented solely by withholding new leases reaches only those who contact the server. A **revocation notice** makes revocation data: a document `signature(64) ‖ body`, with a TLV body (`version u16le`, `file_id`, `epoch u64le`, `time i64le`), signed by the lease-signing key over a transcript labeled `"CC/v1/revocation"` from the §3.6 registry (the label was reserved in advance but unused until this date). Verification uses the same key as the lease — pinned by the author in the header; no second trust relationship is introduced. Layout: `oc_protocol::revocation`; the document is unfrozen, like the other protocol documents.

The reader accepts notices from three places, none requiring server connectivity at read time: the cache beside licenses (`<id>.revoked` in the key directory); a file beside the container (`<container>.revoked` — the author forwards it in the same message; `cca revoke` writes it as a file); the wire (`Revocation { file_id }`, kind 19; responses `Revocation(bytes)`, kind 20, and `NotRevoked`, kind 21 — no proof of possession, since it contains no secret). A viewer hearing a revocation through a subscription fetches the notice over the wire, verifies it, and caches it: the next launch denies without a network. A notice found beside the container is copied to the cache.

What it provides: revocation is final and overrides an active cached lease — `cc check`, `cc unprotect`, and the viewer deny on it before the lease and evaluator; `cc inspect` identifies the file as revoked. What it does not: it cannot be forged, while distributing an authentic notice distributes the truth — a planted notice with someone else's signature therefore interferes with nothing, as tested. It does not obstruct the author: policy does not apply to them.

## 7. Journal

A K13 chain: each record's key is the preceding MAC. No secret is required; the head is public and anyone may verify it.

Recorded events: file registration, device activation, lease issuance, revocation, and **device-limit refusal**. A refusal is an event too, and knowing about it matters no less than knowing about success.

An absent fingerprint is encoded with a separate byte rather than zeros: zeros are a legitimate fingerprint value; confusing “no device” with “all-zero fingerprint” would give two records the same representation.

**The chain does not detect journal truncation** — a signed head addresses this. Discarding the tail leaves an internally consistent journal: the chain witnesses internal integrity, not length.

The head is `size ‖ root ‖ signature`, where `root` is the tree root over record MACs, and the signature covers `"CC/v1/audit-head" ‖ 0x00 ‖ u64be(size) ‖ root`. It has its own label, separate from records: a head and a record assert different things; a signature for one must not work for the other.

Verification: take the first `size` records of the current journal, compute their root, and compare with the witnessed root. Truncation means fewer records than promised; rewriting the middle and rebuilding the rest makes the prefix root diverge even when length matches.

**A necessary condition: someone other than the server must store the head.** A head beside the journal only witnesses that the server agrees with itself. An external anchor (OpenTimestamps) removes the “recipient must remember” requirement but not the principle — the witness must be outside.

Commands: `cca checkpoint --out <file>` captures the head; `cca checkpoint --verify
<file>` verifies it. A mismatch produces a nonzero exit code, not merely a line of output.

When state is read, the journal is **rebuilt**, not restored with saved MACs: a MAC in the same file as its records witnesses nothing — whoever forges the records can forge it too.

## 8. What is still missing

**~~Network transport.~~ BUILT; status corrected on 2026-09-08.** This section said “there is not one line of networking code in the product.” That ceased to be true when §9 was implemented: `crates/cc-authority/src/serve.rs:129` uses `TcpListener`/`TcpStream`; the server handles multiple connections; end-to-end tests run real binaries through a socket. The paragraph remains struck through rather than erased: the section is called “what is still missing,” and a vanished line would not tell a reader the item was completed.

Status silently diverged from code in exactly the manner warned about by repository law: the document asserted absence, and absence has no check until someone asks. The lifecycle review found this on 2026-09-08.

**A key transparency log.** F-10 needs it for anchoring; introducing it before its consumer would freeze a format nobody could verify.

**EK attestation.** Moved here from F-6 and still unresolved: measurements are in `crates/cc-keystore/tests/hardware.rs`. An attestable key must be **created** as attestable; this decision has an expiry date — once user keys have first shipped, it will require recreating them.

---

## 9. Transport: decision of 2026-08-26

This item was deliberately deferred (`docs/deferred.md` §6.1) and addressed when needed. What follows records the decision, measurements, and conditions for reconsideration.

### 9.1. What we use

**Protocol documents separate from delivery.** These are different things and must not be confused: a document is a commitment, a socket carries bytes. The lease already follows this pattern (signature ‖ body, §2) and survives any transport change.

Thus activation requests, grants, and refusals become DOCUMENTS — TLV under I-7 and I-8, strict parsing, a vector beside `tests/kat/lease.kat`. Delivery uses “length ‖ body” frames over bare TCP, the same technique already used by the engine (`oc_engine::wire`).

**Zero new dependencies.** The language provides `std::net`; a strictly parsed frame already exists; the protocol gets its OWN `MAX_MESSAGE`: the engine uses `1 << 20`, exactly `MAX_HEADER_LEN`, and a maximum-sized prologue will not fit its frame.

### 9.2. What we do NOT use: HTTP and TLS

Rejected based on measurement, following the CMS decision (F-10). Each reason stands independently.

1. **Transport contributes no cryptographic-strength property.** The lease signature is checked with the key pinned by the author in the signed header; the share is sealed to the device key through K11, which includes the lease number; absence of a lease means denial under I-10. TLS adds nothing to this — it adds metadata privacy and availability, and only those.
2. **Duplicate `getrandom`.** The TLS graph introduces branch 0.2 alongside our 0.4.3, while `deny.toml` enforces `multiple-versions = "deny"` for a substantive reason: two entropy-source versions in one tree give two different answers to where keys come from.
3. **A license outside the allowlist.** The graph includes `CDLA-Permissive-2.0`, absent from `deny.toml`. Adding a license for transport is a separate decision larger than the transport itself.
4. **Build toolchain.** Default `rustls` pulls in `aws-lc-sys`, and with it `cmake` — exactly why this repository explicitly bans `openssl`.

**Measurement precision, honestly stated.** The new-crate count (roughly seventy) was not rechecked against the index and is an order-of-magnitude estimate; replacing `aws-lc-rs` with `ring` was NOT measured — only the blocking `cmake` fact is known. Reasons 2–4 were verified and stand independently, so the conclusion does not depend on the count's accuracy. Today's comparison baseline is 334 exemptions in `supply-chain/config.toml`, not the 76 quoted in F-10: that figure belongs to August 2026 and is outdated.

**Conditions for reconsideration.** Metadata privacy becomes a customer requirement; or a TLS implementation appears without duplicate `getrandom`, off-list licenses, and a C build toolchain. Until then, the deployment ENVIRONMENT provides the tunnel, not our dependency tree; this is recorded as a requirement, not left implicit.

### 9.3. What is exposed over the network, and how three holes are closed

The first revision (2026-08-26) exposed ONE network operation — activation — leaving `register` and `revoke` as operator commands. (Access requests and author decisions followed in §10, subscription in §9.9, revocation notices in §6.1, and renewal in §5.1; none gives a device anything beyond activation.)

The reason was not caution but three holes concealed by the file boundary, all confirmed in code:

* **`register` inserts through `or_insert`.** The FIRST writer sets the limits. A container reaching a recipient before author registration lets that recipient register the file on their own terms — with a matching `policy_hash`, taken from the same container;
* **`revoke` checks nobody's authority**, while `file_id` is plaintext in the header;
* **`activate` requires no proof of possession** of the presented key: merely presenting someone else's fingerprint consumes device and grant limits.

All three were then protected solely by a human running the commands. The wire removes this protection; “transport changes no check” — wording that appeared here, in `docs/deferred.md`, and in the `cca` docstring — is **false** for these three operations. Corrected in the same commit.

**Status on 2026-09-03: all three are covered, and registration and revocation travel over the wire as AUTHOR ORDERS.** `Register` (kind 23) and `Revoke` (kind 24), response: `Accepted`. An order is an `oc_protocol::order` document signed with the author's key (label `CC/v1/author-order`, layout `signature(64) ‖ body`; body: `file_id`, kind, issue time, and, for registration, device and grant limits).

* **Registration carries the container HEADER** — the file prefix through the end of the author's signature, without content. The server verifies the header signature, takes the author key from it, and verifies the order with that key.

  **This is insufficient, contrary to the first revision of this paragraph.** It said: “one cannot register someone else's file on one's own terms — the recipient lacks the author's key.” The recipient does not need it. The header signature is verified using a key IN THAT SAME header, proving only knowledge of one's own key; `file_id` originates as random packer bytes and is public, bound to no key. An outsider takes the real header, substitutes their own author key, signs with it — preserving `file_id` — and claims the file before its real author. The “first writer sets the limits” hole was not closed but **moved from operator to network** (review of 2026-09-03, `docs/plan.md`, `D-socket`, P-6).

  **The operator's author-key allowlist closes it**: `cca author add <hex> | remove <hex> | list`, stored in server state (tag 7). Wire registration succeeds only if the header's author key is listed; otherwise: “author key is not admitted by this server's operator.” An empty list means “nobody registers over the wire” — pure I-10. The list is the only anchor independent of the submitted document: the server operator vouches for the key. `cca register` does not depend on the list: whoever runs the command vouches for the file, and running a command on the server machine is itself authority.

  Removing admission does not affect already registered files: their author key is recorded with the file, and orders are checked against that key, not the list. The list decides only who may claim a NEW file.

  Re-registration by the same author changes nothing and is not journaled; a different key yields “not the author.” A file registered by the operator without an author key obtains its key from the first signed order by an admitted author.
* **Revocation is verified with the author key recorded at registration.** A file without a recorded key cannot be revoked over the wire. An already revoked file is not revoked again: no epoch advance or journal entry — replaying an intercepted order gains nothing.
* **Activation** has required proof of possession since 2026-08-26 (§9.4).

An order is accepted only while FRESH: issue time differing from the server clock by more than the skew allowance (`MAX_CLOCK_SKEW_SECONDS`, five minutes) is rejected with its age stated. This protects against a document resurfacing after sitting somewhere, not replay — both operations are idempotent and replay harmless. Orders need no proof of possession of a device key, like an author decision (§10): they are signed with the author key, and that signature is what must be checked.

`cca register` and `cca revoke` remain operator commands for the same server — for a machine where author and server are the same person and no second program exists. Packaging with `cc protect --url` registers over the wire and calls a neighboring `cca` only after failure; `cc revoke` revokes over the wire and immediately retrieves the revocation notice (§6.1), placing it beside the container.

### 9.4. Proof of possession — by sealing, not signing

A device CANNOT sign: its key is for agreement, `device_agreements` returns only `KeyAgreement`, and `cc-keystore` has no `sign` at all.

Proof therefore uses the primitive already sealing the share: the server sends a challenge sealed to the presented key. The device returns an ECHO, not the challenge itself: HMAC-SHA256 keyed by the challenge (input form below, K31). `max_devices` and `max_grants` budgets are consumed only after the echo matches.

Applied to both keys simultaneously, the same technique also closes the gap between `device_fpr` and the `--device-tpm-key` key, which the server currently checks by no means.

The challenge remains secret between the two parties and becomes material for K24 — the session MAC key. The echo is always exactly 32 bytes; the hardware component of the 64-byte challenge contributes to the HMAC key, not echo length. Verification is one `digest_eq` comparison over 32 bytes. Requests and subscriptions do not prove possession: an unknown device requests, and a subscription carries only notifications. Orders are authenticated with the author's signature. These receive no session MAC; K25 covers only Activate and Renew.

**The secret is DERIVED, not taken directly from the generator (since 2026-09-20, K30).** The server draws 32 SEED bytes and expands the secret through K30 (`docs/format.md` §3.5 and “SERVER FRESHNESS IS DERIVED 2026-09-20”): `kind = 2`; the input contains the seed, server clock reading, and device fingerprint; there is one component per presented key, separated by the counter inside `HKDF-Expand`. The reasoning matches nonce seeds (I-1, S-13): the generator repeats after snapshot rollback, together with server state, so a repeated secret would mean a repeated echo (K23) and repeated session MAC key (K24) for the same fingerprint. The decision section also states the cost of repetition and protection boundaries.

**The device and intermediary do NOT see this and must not see it.** The secret arrives sealed as before; the `Challenge` format, echo length, and verification do not change. The recipient does not compute the value — it opens it.

Flag day 2026-09-08: the old raw 32-byte echo receives `NotProven`; the old 64-byte hardware echo is rejected by the length parser. No compatibility: accepting a raw challenge would disclose K24 to an intermediary and restore the downgrade. The container version does not change with this protocol change.

**The echo covers the CONVERSATION TRANSCRIPT (since 2026-09-21, K31).** Until then, it was `HMAC(secret, "CC/v1/prove-echo" ‖ device_fpr)`, depending on the conversation only through the secret itself: a captured echo worked in any other conversation by that device where the secret repeated. Now the input includes the handshake hash, computed identically by both parties:

```
transcript = "CC/v1/echo-transcript" ‖ 0x00 ‖
             u32le(len(hello)) ‖ hello ‖ u32le(len(challenge)) ‖ challenge
handshake  = SHA-256(transcript)
echo       = HMAC-SHA256(key = challenge secret,
                         "CC/v1/echo-transcript" ‖ device_fpr ‖ handshake)
```

`hello` is the RAW greeting-frame bytes (`kind ‖ TLV`); `challenge` is the RAW challenge-frame bytes (`kind ‖ TLV`), in wire order. Specifically raw: reconstruction from parsed data would silently diverge in the presence of an intermediary (I-5 rationale). Lengths are mandatory — without them bytes could move between frames without changing the hash.

**Who holds what.** The server remembers `handshake` together with the fingerprint it challenged, as one value so they cannot diverge (`Session::greeted`, `crates/cc-authority/src/serve.rs`), and passes it to `Authority::prove` as a required parameter: transport knows the transcript, not `Authority`; forgetting the binding is impossible because it cannot be omitted. The device computes `handshake` from the frame it SENT and the frame it RECEIVED (`cc_cli::activate::greet`). If bytes diverge in transit, the honest device's echo will not match; failure is specifically “not proven,” not a parse failure or panic.

An echo captured in one conversation therefore does not fit another even if the secret repeats: the server seals afresh in each conversation, with its own ephemeral `Seal` pair, and the challenge-frame bytes differ. Guarantee boundaries and what this decision does NOT provide are in `docs/format.md`, “ECHO BOUND TO THE CONVERSATION 2026-09-21.”

**The session MAC key (K24) is deliberately not covered by this binding.** It derives from the secret, available only to the holder of the device private key; the echo does not disclose it. An adversary unable to construct the bound echo also cannot derive K24, so a second lock on the same door is not introduced — the same specification section discusses costs and benefits.

**Flag day 2026-09-21.** The server **rejects** old-form echoes (K23): there is no transition period; the product is unreleased; client and server ship together (rule R-3). Label `"CC/v1/prove-echo"` and the derivation remain in the registry marked “not used by the protocol,” for the frozen vector.


### 9.5. What must be fixed BEFORE the port opens

**The item number in the state file is `u16`.** Refused activations are journaled; after 65536 records, `save()` begins failing, permanently breaking state persistence. With human-submitted requests this is unreachable; with a socket it is a cheap, irreversible denial of service. Fixing it after opening the port means opening with a known defect.

The failure is not silent — it is printed — but comes TOO LATE: the lease has already been issued while state has not been saved.

### 9.6. What transport does NOT provide

The complete adversary picture is in `docs/threat-model.md`; only transport-specific limits appear here.

* **instant revocation.** An issued lease lasts until expiry; the server always writes `revoked` as `false`, and there is no producer of a true value;
* **protection from the machine owner** — impossible by construction;
* **request-metadata privacy** — without TLS, the server and everyone on the path see who activates which file and when;
* **notification authenticity** — `Notice` is unsigned. The viewer therefore closes the document on a REVOCATION NOTICE verified with the header key, not a notification: a forged notification is reason to ask, not a verdict (N-5). An intermediary can suppress notification; actual revocation arrives as a renewal refusal (F-18).

**Closed on 2026-09-08: REQUEST integrity.** K25 (`docs/format.md` §3.5) covers `Activate` and `Renew` after `Prove`: substituting or removing clock readings is rejected before parsing and state changes. Metadata remains plaintext. Access requests, subscriptions, and orders are not covered by this MAC (§9.4).

**Wire issues closed by the crypto review of 2026-09-06.** Proof-of-possession challenges belong to the CONVERSATION, not the fingerprint: fingerprints are public, and another party's greeting using one no longer cancels its owner's challenge (N-3). Activation and renewal with a mechanism other than 1 are rejected on the wire, as requests already were: with P-256 the supplied key is not bound to the proved fingerprint (N-1). A file record without an author key is not claimed by the first admitted author using the same `file_id` (N-6). Comparing a request's fingerprint with its key is equality of public values, not proof of possession; comments claiming otherwise were corrected (N-4).

### 9.7. What changes in the threat model — no small matter

The model itself is in `docs/threat-model.md`, rows “wire observer” and “compromised server.”

Today the server learns about a file only when its author brings the container. With transport it sees activations in real time — who, when, which file, from which address. This is sold as auditing and is surveillance; both descriptions are true.

Before the first networking line is written, the activation-record fields, including network address, and their retention period must be recorded. The journal still knows about GRANTS, not openings — a construction property, not unfinished work: there is no return channel, and none can be added while the device key cannot sign.

### 9.8. What is NOT introduced with transport

* **revocation inside the lease** (`status = 2`): it would make `epoch` nonzero and invalidate the explanation in `oc-policy` and §3;
* **server-side policy tightening**: it would affect the wire, while the lease format is frozen by `tests/kat/lease.kat` (I-14);
* **a return channel counting openings**: the obstacle is not transport but the device's lack of signing, and even with signing it would provide observability, not a guarantee.

### 9.9. Subscription — decision of 2026-09-02

The customer's substantive decision: the server must announce events itself rather than wait to be asked. Recorded here because it changes the wire — a new request kind and response kind in the common registry (`oc_protocol::activation`, kinds 17 and 18; author-scope subscription is kind 30, B5 below).

**What we use (second revision, same day).** `Watch { files, since }` as the connection's first message — up to 32 files and the number of the first unseen journal record (zero means from the beginning; numbering starts at zero); response: a `Notice` stream, with a heartbeat every twenty-five seconds and `Event { seq, event, file_id, device_fpr }` — server JOURNAL RECORDS for the named files, first everything from `since`, then live events. A subscription tails the journal, so disconnection loses nothing by construction: resubscribe with the last number and receive what was missed. The same tail delivers actions by another process, such as operator revocation: the subscription rereads the journal on wakeup and at least every half-minute. For this reason requests and author decisions are now journaled too (events 9 and 10); wire event numbers match journal event numbers, guarded by a test. Subscribers skip unknown numbers instead of rejecting them: the journal may grow. The first revision, with three notification types (“request,” “decision,” “revocation”), was discarded the same day: it lost events on disconnection and missed operator actions.

A subscription lasts one hour, then the server closes it; the client side (`cc_cli::activate::watch_forever`) automatically resubscribes with its cursor and an increasing jittered delay from five seconds to one minute. Limits: 64 subscriptions per server, 8 per file; subscriber identity for FILE subscriptions is not verified, just as for `Requests`: notification signals a query, not content, and decisions still require `Collect` with proof of possession. The “author's files” scope is different: authorization is not derived from knowing identifiers and requires proof of possession of the author key (B5 below).

**What we do NOT use: WebSocket.** It provides HTTP-proxy traversal and browser access, neither present in this product; it would reintroduce an HTTP handshake, a new dependency, and the TLS debate settled in §9.2. Subscriptions use the same frames and kind registry, with zero new dependencies.

**What had to change in connection handling.** Until this date, connections were strictly sequential, so one subscription would block everyone. Now there is a thread per connection; state-changing conversations use one lock and remain sequential (state lives on disk and is reread before each); subscriptions wait OUTSIDE the lock. Measured by `crates/cc-authority/tests/watch.rs`: with a subscription open, requests and decisions on other connections succeed; a subscriber from zero receives history (file registration), then request and decision with the affected device's fingerprint and increasing numbers; a subscription “after the request” delivers the decision but not the request — exactly what a disconnected, resubscribing client sees.

**Who listens.** The access-request window (retrieve the author's decision immediately rather than in twenty seconds), recipient viewer (revocation arrives within half a minute rather than after the offline window — the “no later than N” promise is unchanged; subscriptions speed up the usual case), and author window (refresh the queue on a new request). Polling remains a fallback for all three: inexpensive, works through any NAT, and survives a broken subscription.

#### Subscription to the “author's files” scope — decision of 2026-09-16 (B5)

**What this addresses.** File subscriptions allow up to 32 files per connection and authorize by knowledge of `file_id`. An author window with a hundred files could not observe all of them; a newly registered file stayed unobserved until subscription recreation. Allowing “all files by this author” solely by knowledge of a public key would expose other people's file-event streams to anyone who had seen it — every recipient has, since the author key is public in the header.

**Request.** Message kind 30 `WatchAuthor`: `u64le since ‖ signed
order`. The order is the ordinary §11 document of kind 12 `WatchAuthor`: zero `file_id` (scope: all files of the key), required `signer_key` (whose scope), required tag 20 `authority_key` (addressee), and `at` (issue time). Tag 20 is forbidden for other kinds; kind 12 does not execute through the order entry point (`Order`) — it is proof, not a command.

**Why an order rather than a new document.** The product has one control document: the author's order, with `verify_strict` signature (I-6) over the `"CC/v1/author-order"` transcript, strict parsing, and kind-dependent field membership enforced both ways. A second format with its own label would introduce a second definition of “what the author signed,” and eventually they would diverge. Domain separation is the kind byte inside the signed body: subscription proof cannot execute as a command (the `Order` entry point rejects it); a command is not accepted as proof (subscription checks the kind).

**What the server checks, in order.**

1. Signature — using `signer_key`, `verify_strict`.
2. `authority_key` — THIS server's lease-signing key. In a hosted profile each tenant has its own, so server binding also binds the tenant: another tenant rejects proof captured at one.
3. Freshness — `|now − at| ≤ 300 s`, the same allowance as orders (§11). Older proof is rejected: “later” means denial.
4. Replay — the server remembers fingerprints of accepted proofs for twice the freshness window; the same document cannot open a subscription twice. This memory lives in the acceptor process and does not survive restart: proof intercepted during the five minutes before restart is accepted once again afterwards. The cost of this window is the author's file-event stream (numbers, kinds, files, device fingerprints) for one subscription's lifetime; it contains no content or shares, and a wire observer (threat-model §2) sees the same conversation even without replay.
5. Authority — the key is recorded as author of at least one REGISTERED, NON-frozen file on this server. Co-authors and approvers are not the author: their scope is files by identifiers (§12 grants them neither inheritance nor revocation of another key; subscribing by another's key would amount to precisely that).

   *Subscriber consequence found by a test on 2026-09-21.* `at` uses whole seconds, and Ed25519 signatures are deterministic: two proofs from the same key for the same server issued within one second are byte-identical, so the second is rejected by this rule. The product client resubscribes after five seconds and never encounters this; a subscriber calling in a loop must issue an `at` strictly greater than its predecessor (`cc_sdk::author::fresh_proof_moment`). This does not change the wire rule.

**Scope calculation.** The server obtains the key's files on EVERY journal-tail step, not just at entry: a file registered after subscription begins arrives without resubscription — registration immediately wakes that author's subscriptions; other steps use per-file wakeups or polling at least every 30 s.

**Revoking authority.** Authority is rechecked at every step. The author's panic button (`Freeze`, §11.9) closes their subscriptions: a frozen key is one the author themselves considers potentially lost, and its event stream no longer reaches its holder. New subscriptions are denied until thaw. Closure is a `Denied` response with a reason and disconnection; the client does not silently resubscribe. Subscriber departure frees a slot within one second (`LIVENESS_CHECK`).

**Cursor.** `since` is the first unseen record. A cursor AHEAD of the server journal (different server, state rollback) is rejected with the journal length stated rather than silently waiting: otherwise the subscriber would miss everything between the journal end and its cursor. The same rule applies to file subscriptions.

**Queue.** The journal is the queue; memory holds one catch-up batch per subscriber (256 records). A slow subscriber hits the socket-write deadline (30 s); the subscription closes, the client resubscribes using its cursor and receives undelivered entries — no loss or duplicates.

**Limits.** 64 subscriptions per server (shared with file subscriptions), 8 per author key. Subscriptions wait outside the lock and briefly acquire it to catch up; a saturated pool does not delay other clients' grants, renewals, or revocations — checked by a test with a timing assertion.

**Compatibility.** An older server answers kind 30 with “unknown message”; the product client states this explicitly and switches to file subscriptions with a visible window indication, not silently.

### 9.10. Operation identity — decision of 2026-09-15

**What this addresses.** Test bench A2b found that a grant committed before the server response was issued twice upon client retry: a second “license issued” record, grant-limit consumption, and permanent loss of a one-time file for a recipient who never received the lease (A2b-1). It also found that the storage operations table was never written on the wire path (A2b-2). An inventory of all state-changing wire operations (`docs/managed-store-contract.md` §5.3) found more: an approver vote and a proposal signature duplicate journal entries even when EXACTLY THE SAME bytes are replayed, and an author decision loses its outcome on retry.

Before this decision, safe retry was not promised (`managed-store-contract.md` §5), and a client had no way to “reread the outcome”: no request told a device whether its grant had been recorded.

**One identity per operation, two expressions, one table.**

* **Explicit** — the `operation_id` field in `Activate` and `Renew` bodies. The activation body is NOT a signed document and may legitimately repeat across operations: a clockless device sends byte-identical activations on Monday and Tuesday. Only a client-chosen identifier for this operation distinguishes them.
* **Derived** — for requests whose body is a signed author document: `Register`, `Revoke`, `Order`, `Endorse`, `Decide`. Identity is `SHA-256(u8(kind) ‖ body)`: Ed25519 signatures are deterministic, orders contain an issue time, and identical bytes mean one command (`managed-store-contract.md` §5.1). They gain no new field — their wire representation is unchanged.

**K28 — from a seed and body, not bare random bytes** (`docs/format.md` §3.5):

```
operation_id = SHA-256("CC/v1/operation-id" ‖ 0x00 ‖ seed(32) ‖ u8(kind) ‖ body without the operation-id field)
```

The rationale matches nonce seeds (I-1, S-13): the generator repeats under VM snapshot rollback and image cloning; a bare random value would collide between two different requests, causing the second to receive the first's saved outcome. Including the body separates different requests even if the generator repeats; only identical requests coincide, for which a shared outcome is truthful. Kind is included because activation and renewal share a body. Identity contains no secret: it travels in plaintext and requires uniqueness, not unpredictability. Vector: `tests/kat/operation_id.kat`.

**Bytes** (`oc_protocol::activation`):

| Where | Tag | Length | Meaning |
|---|---|---|---|
| `Activate`/`Renew` body | 9 `operation_id` | exactly 32 | optional; last, after clocks (I-7). `Renew` parses but does not use it: response without echo (below) |
| `Granted` grant | 3 `operation_id` | exactly 32 | echo: grant RECORDED under this identity |
| `Denied` refusal | 2 `operation_id` | exactly 32 | echo: server understood the identity, and refusal is final for this request — nothing was granted under this identity (whether denial is recorded: rule 5 below) |

Tag 9 is **critical** (≤ `0x7FFF`), deliberately: the field changes retry semantics. A server unaware of it that silently skipped it would execute a retry as a second grant — exactly what the field prevents. An unknown critical field causes parse rejection, so an old server does NOT execute an identified request at all. Identity is inside the body and thus under the session MAC (K25): an intermediary cannot substitute it without breaking the MAC.

An echo appears only in response to tag 9: an old client sends no field and gets no echo — its parser would reject an unknown response tag. The echo signals SUPPORT, not proof: wire responses are unauthenticated (§9.6). Conversely, refusal WITHOUT an echo proves nothing; the client does not infer nonexecution from it if a request with this identity could already have reached the server (“Client” below; review of 2026-09-15).

**Server.** Table key: `(actor, operation ID)`. The actor of an explicit identity is the fingerprint proved IN THIS conversation (`Proven::proves`): otherwise someone naming the same identity could read another's outcome. The actor of a derived identity is 32 zero bytes: identity resides in the signature, which resides in the body; only someone already holding those bytes can read the outcome. Body hash: `SHA-256(u8(kind) ‖ body)`, without MAC — each conversation has its own MAC.

1. Conversation checks — mechanism, key name (K27), proof — precede the table; their failures do not see the identity and carry no echo. Renewal (`Renew`) does not use identity at all: it has no duplicate effect, and renewal records would occupy slots needed by protected grants (below).
2. No record — first **admit the identity**: if execution may produce a protected grant (a file with a grant limit), space must be available (see “Storage”). No space — explicit “operation identity limit … exhausted” refusal WITH ECHO; nothing executes or is recorded, and this is a final refusal for the client. Space available — execute; the complete grant response (including echo) enters state in the same commit as the effect: one state-file write via rename for file storage; one SQL transaction with an `operations` table row (`op = Some` on the wire path). Respond after commit (contract rule 1).
3. Record with the same hash — return the saved response byte-for-byte, execute nothing. For a grant, first recheck revocation, freeze, and saved-lease expiry: revoked, frozen, or expired yields a current refusal with echo, not recorded (§29.10 `deferred.md`, step 5: retry does not resurrect permission). Thaw restores the saved grant response.
4. Record with a different hash — “operation identifier already used by another request,” with echo; neither execution nor recording.
5. **An explicit-identity refusal always has an echo, but is recorded only if it changed state; a derived-identity refusal is not recorded.** An activation refusal that wrote to the journal (device and grant limits, clocks, quorum, attributes) is recorded so a retry returns the refusal instead of journaling it again. A refusal changing NOTHING (“no such file,” wrong policy) is not recorded: retry duplicates nothing, while recording let anyone with a key fill the table (review of 2026-09-15). Its echo remains: without it the client could not distinguish it from an in-transit forgery and, after a delivered request, would report “outcome unknown” where it is known. Signed decision bytes may legitimately arrive again AFTER refusal — for example, if sent before file registration — and a refused order has no effect.

**Storage: 24 hours by the server clock, at most 4096 records per server.** Retention is twice the client's same-identity retry window (12 hours, below), allowing for client/server clock divergence, which is not checked here. The count bounds state size: a response with share and lease is up to one and a half kilobytes for a hybrid device; the state file is fully rewritten on each commit; 4096 records are a few megabytes; legitimate load for the first profile is hundreds of activations daily. Expired records are removed when a new one is written.

**Who occupies how much — review of 2026-09-15.** The first revision said “live records are never evicted; a full table yields denial without echo and the client takes the old path.” Anyone could fill it: proof of possession succeeds with a newly generated key, and every refusal entered the table. Once flooded, legitimate activation took the old path, where lost responses and retries again caused a second grant. Records are now distinguished by the cost of losing them (`cc_authority::operations`):

| Record | Cost of loss | Allocation and limits | No space |
|---|---|---|---|
| **protected grant** — grant for a file with a grant limit | retry consumes the limit; for a one-time file, the right itself | 3072 per server; 256 per proved device; per file: its grant limit (each record is a grant counted by it) and 1024 | not evicted; a new identity gets “operation identity limit …” with echo; nothing executes |
| **author document** (derived identity) | extra journal record when identical bytes are retried, not access | 1024 per server; 64 per file | executes without recording: the table does not delay revocation or freeze |
| **evictable** — refusal that wrote a journal entry; grant for a file without a grant limit | extra journal record; lease number one higher. The device limit is consumed only on first execution: retry grants to an already known device | available space | yields space first, oldest first |
| refusal changing nothing | nothing | not recorded | — |

Allocations sum exactly to the cap (3072 + 1024 = 4096): a protected grant or document admitted within its allocation always finds space by evicting evictable records. Grant class uses the file limit AT COUNTING TIME: an author imposing a limit makes previous grants protected from that moment.

The cost of flooding now: refusals and unlimited-file grants take no reserved space. Only grants for grant-limited files create protected records, consuming that limit — damage a header holder can do even without the table. Exhausting the server allocation requires grants for files with combined limits of at least 3072 (no more than 1024 from one file); legitimate activations of limited files then get the explicit refusal — one day's availability denial, not a second grant. Only a file signer can exhaust the document allocation.

**Client.**

* **`cc activate` and viewer** (`obtain_and_store`): seed from the OS generator; K28 over the body without the field. BEFORE sending, write a pending operation in the key directory (`pending/activate-<file_id>.op`: identity, body, time). On wire failure, retry the SAME body in a new conversation (new proof, new MAC), three attempts total with 1 and 2 s pauses. Outcomes:
  * grant or refusal with echo — final outcome; delete pending operation (for a grant, after writing the lease to disk);
  * refusal without echo on the FIRST request under this identity to reach the server (created by this process; no earlier attempt reached writing the activation frame) — identity never previously reached the server: send one old-form request without the field; wire failure after that is NOT retried — unknown outcome, code 6, with text naming the no-echo refusal that triggered the old path;
  * refusal without echo in ANY other case — after an attempt whose activation frame might have arrived, or for a previous process's pending operation — **unknown outcome**: the earlier attempt might have executed, and a no-echo refusal is unauthenticated (in-transit forgery, stripped echo, conversation failure). Keep pending operation, code 6, no request without identity (review of 2026-09-15: previously the old path ran here, issuing twice and making the saved grant unreachable);
  * attempts exhausted — keep pending operation; the next `cc activate` for the same file within 12 hours sends the SAME body (with old clock readings) and receives the stored outcome; later, it is a new operation and this is stated.
  The pending operation remembers the command fingerprint: file, policy, server slot, lease duration, device mechanism and key (everything except clocks). A run with different parameters FIRST resolves the prior operation using its own body: accept a grant under the prior parameters and state this (renewal obtains a new duration without consuming the limit); after a refusal with echo, start a new operation with the new parameters.
  The received lease is marked in the pending operation BEFORE advancing the sequence threshold: the same lease received again after a crash between threshold advance and file write is accepted, not rejected as replayed.
* **Renewal carries no identity.** It has no duplicate effect (§5.1); the viewer renews every few minutes, so identities for every renewal would fill the table in a day. The server parses tag 9 on renewal but does not use it. Replaying a grant whose lease has expired yields refusal advising renewal: that grant already activated the device, and renewal does not consume the grant limit.
* **Author orders and decisions** retry the SAME bytes after wire failure (derived identity), three attempts as for activation. Pending operations are retained for `cc approve`/`cc decline` (`decide-<file_id>-<number>`), `cc revoke`, `cc limits`, `cc coauthors`, `cc approvers`, `cc heir --device`, `cc approve-open`: repeating the same command and parameters within 12 hours sends the previous bytes and receives the previous outcome. Refusal of repeated bytes means they did not execute (execution is recorded), so the command signs a fresh order. Not retained for `cc alive` or `cc panic` — no duplicate effect, and the old issue time would date presence incorrectly — or `cc heir --code`: codes are not written to disk, and old bequests without them are useless.

**Compatibility.**

| Client \ server | old (no table) | with identity |
|---|---|---|
| old | unchanged | unchanged: activation without identity executes without the table; retry means a second grant; old-client orders receive derived identity (same bytes, same outcome) |
| new | parse refusal “unknown critical field 9” without echo → old-form request, no retries | identity |

**What this does not provide.**

* Echo is unauthenticated. After a possibly delivered request, the client treats refusal without echo as unknown and does not take the old path. But on the FIRST delivered request, an active intermediary can forge a no-echo refusal while the server executes the authentic request: the client assumes an old server and sends one request without identity — a second grant consuming the limit. An unauthenticated wire cannot distinguish an old server from forgery; the cost is an active-intermediary attack on the victim's grant limit, not access.
* Availability under flooding: exhausting the protected-grant allocation (above) deprives legitimate activations of grant-limited files of space for a day — explicit refusal, not a second grant.
* Window: retrying the same identity after 12 hours at the client and 24 at the server becomes a new operation.
* Two processes on one device activating a file simultaneously mean two operations and two grants, as before: one pending operation per file.
* Identity does not survive loss of the client's key directory; a server without the table (older build) provides no idempotence — the client does not retry there.

### 9.11. Device-key attestation — proof model (B6a, 2026-09-16)

**What this addresses.** Binding tier `HardwareAttested` (`docs/format.md` §4) was unreachable: the client built an envelope (`cc_keystore::attest`), but the verifier (`cc_authority::attest::verify`) ended every envelope with “verification not implemented.” Checking an EK certificate alone proves nothing about the DEVICE KEY: it establishes that such a TPM exists somewhere, not that the presented key resides in it. Proof is therefore a chain accepted only in full; any unverified link means `attested = false` with a stated reason, not partial trust.

**Links, in verification order.**

1. **Trusted endorsement key (EK).** Two trust levels, named separately because their assertions differ:
   * **vendor certificate** — EK certificate (X.509, DER) chaining to a root in the deployment directory (`TrustAnchors`; empty directory means refusal, decision of 2026-08-24). Asserts: “this EK was issued by a manufacturer trusted by this deployment”;
   * **pinned EK** — public EK recorded by an administrator during machine commissioning. Asserts less: “this is the very TPM the administrator had before them,” nothing about its manufacturer. Needed when no vendor certificate was provisioned (as on the development machine: no EK certificate, measured 2026-08-24).
   The certificate public key must match the envelope public EK: another TPM's certificate beside one's own EK is rejected.
2. **The attestation identity key (AIK) belongs to this EK.** Verified by CREDENTIAL ACTIVATION (TPM2_MakeCredential / TPM2_ActivateCredential): the server encrypts a random secret to EK for the AIK name; only a TPM holding both can return it. This choice follows both sides' capabilities: the Windows platform provider activates credentials through `NCRYPT_PCP_TPM12_IDACTIVATION_PROPERTY` (historical name, unchanged for TPM 2.0); `tpm2-tools` uses `makecredential`/`activatecredential`. A third-party AIK certificate would merely move the same activation to a third party without simplifying verification.
   Credential form: TPM 2.0, part 1, “Credential Protection”: seed encrypted to EK (RSA-OAEP-SHA256, label `"IDENTITY\0"`), symmetric key `KDFa(SHA256, seed, "STORAGE", AIK name, empty, 128)`, credential encrypted with AES-128-CFB and zero IV; integrity is HMAC-SHA256 keyed by `KDFa(SHA256, seed, "INTEGRITY", empty, empty, 256)` over `encIdentity ‖ AIK
   name`. RSA-2048 EK is supported (default TCG template); a curve-based EK gets an explicit refusal until required by a live machine.
3. **TPM assertion about the device key.** AIK-signed `TPMS_ATTEST` of type CERTIFY (magic `0xff544347`, kind `0x8017`): `attested.name` is the device-key name (`nameAlg ‖ SHA-256(TPMT_PUBLIC)`), and `TPMT_PUBLIC` is in the envelope. Its curve point must match the hardware key presented by the device (`--device-tpm-key`, K27 fingerprint). EK in place of device key, another TPM's key, or AIK in place of device key is rejected by name.
4. **Freshness.** The assertion's `extraData` is `SHA-256("CC/v1/attest-qualify" ‖ 0x00 ‖ challenge(32) ‖ device_fpr(32))`, where the challenge is the server's one-time number in this conversation, and `device_fpr` is K27 of the hardware key. A separate label: `"CC/v1/attest-nonce"` already seals the proof-of-possession challenge (§9.4); two uses must not share one label (I-12). An assertion for another challenge or device is rejected.
5. **Decision.** Only with all four links does the server set `HardwareAttested`, stating the basis (vendor certificate or pinned EK). A policy requiring attestation with an incomplete or rejected envelope receives DENIAL WITH A REASON, not silent downgrade to `Hardware` (B6b). The client's local envelope check (`claim_intact`) is not proof and does not change the verdict.

**The verifier is bounded and strict.** DER, not BER (`x509-cert` parsing; the body must re-encode to identical bytes); certificate signature algorithm allowlist: `sha256WithRSAEncryption` (RSA 2048/3072/4096, exponent 65537) and `ecdsa-with-SHA256` on P-256; TPM assertion signatures: RSASSA and ECDSA with SHA-256. RSA-PSS, P-384, and others receive explicit refusals until needed by a live vendor chain: a verifier without a reference has no verification. Check every certificate's validity, including the root; intermediates and root require `basicConstraints cA=TRUE`, `keyCertSign`, and `pathLenConstraint`; EK certificate must not be a CA and must have `keyEncipherment` (TCG profile); critical extensions other than `basicConstraints`, `keyUsage`, and `subjectAltName` are rejected; chain length at most four, certificate size at most 8 KiB; unused certificates, unknown roots, truncation, and extra bytes are rejected. AIK must be a restricted TPM signing key (`restricted`, `sign`, `fixedTPM`, `fixedParent`, `sensitiveDataOrigin`): an unrestricted key could sign a forged `TPMS_ATTEST`. Device key: P-256 with `fixedTPM`, `fixedParent`, `sensitiveDataOrigin`. Verify the assertion signature over raw bytes BEFORE parsing (like I-5). Digest, name, and secret comparisons are constant-time (I-13). The verifier performs no private-key operations; public operations (signature verification, OAEP encryption to EK) use `oc_crypto::rsa`; KDFa and credential integrity tags use `oc_crypto::tpm`; ECDSA uses `p256`; AES uses the `aes` crate. Code: `crates/cc-authority/src/attest/`.

**Fixtures prove mechanics, not compatibility.** Positive and negative chains are reproducibly generated by external tools (`swtpm` + `tpm2-tools` + `openssl` in the test image, `deploy/local/attest-fixtures/`); test CA private keys never enter the tree. The test CA's subject says “NOT A VENDOR” and it is nowhere declared a vendor root. Fixtures prove the verifier implements the model, not compatibility with specific TPM vendors; a live run on this machine's TPM is a separate stage (B6b).

#### 9.11.1. Wire and issuance (B6b, 2026-09-16)

**Three steps, not two messages.** The Windows provider creates AIK TOGETHER with the assertion (`KAST` wrapper, B6b measurement), and the assertion needs a challenge in advance. After proof of possession (§9.4), a conversation may therefore take three steps, each under session MAC (K25; one authenticated-kind table for both sides — `oc_protocol::activation::is_session_sealed`):

| Kind | Request | Kind | Response |
|---|---|---|---|
| 31 | `AttestOpen` — no body | 34 | `AttestNonce` — 32-byte challenge |
| 32 | `AttestEvidence` — TLV: 1 EK `TPM2B_PUBLIC`, 2 EK certificate (optional), 3 intermediates (`u16be len ‖ der`, at most two, optional), 4 AIK `TPM2B_PUBLIC`, 5 `TPMS_ATTEST`, 6 `TPMT_SIGNATURE`, 7 device-key `TPM2B_PUBLIC` | 35 | `AttestCredential` — `TPM2B_ID_OBJECT ‖ TPM2B_ENCRYPTED_SECRET` (layout accepted by the provider's activation property) |
| 33 | `AttestSecret` — 32 bytes of recovered secret | 36 | `Attested` — `u8` basis: 1 vendor certificate, 2 pinned EK |

**Step 1's challenge is DERIVED (since 2026-09-20, K30).** The server draws a 32-byte seed and expands the challenge using K30 with `kind = 1`; the input contains seed, clock reading, and the device fingerprint PROVED in this conversation (not merely named in a message). Rationale: I-1, S-13 — snapshot rollback repeats the generator with server state, so two conversations would receive one challenge and thus one `extraData`. Nothing changes for client or intermediary: the challenge already arrived as 32 bytes read rather than computed by the recipient. Protection boundaries: `docs/format.md`, “SERVER FRESHNESS IS DERIVED 2026-09-20.”

**Step 2's three values are ALSO DERIVED (since 2026-09-21).** The credential secret, its protection seed, and OAEP seed (`TPM2_MakeCredential`) formerly came straight from the generator; now they use the same K30 derivation with purposes `kind = 3, 4, 5`, one seed for all three, separated by purpose number. No wire effect: credentials already arrived as bytes the recipient does not compute. I-1 applies to EVERY value, not just those remembered; a measured risk assessment is in `docs/format.md`, “ECHO BOUND TO THE CONVERSATION 2026-09-21,” subsection “Assessment (1).”

Assertion `extraData` is K29 of step 1's challenge and K27 of the P-256 point being attested. Steps are accepted only in order; a failed step yields `Denied` with reason and does NOT close the conversation: failed attestation does not cancel a grant that needs none. A conversation may attest only the point whose possession was proved in it: the greeting's TPM key or the hardware component of mechanism five (the last 65 bytes of the MLKEM768-P256 public key).

**Issuance decision.** The outcome is stored in the conversation proof. When the author or server profile specifies `min_binding = HardwareAttested`, a grant without accepted attestation is refused as `AttestationRequired` with reason (step verdict or “not completed”), rather than issuing a lease incapable of opening the file. The indicator travels in the lease (version 3, tag 13, §2.3), but only when the attested point is the key sealing the share (mechanism 2 entirely or mechanism 5's hardware component); otherwise one key's attestation would adorn a lease whose share is under another. A per-action requirement (policy tag 7) does not stop issuance: an unmarked lease allows other actions and the evaluator blocks this one.

**Evaluator.** `oc_policy::effective_binding`: the tier reported by the device from its own observations cannot exceed `Hardware`; only a lease indicator raises it to `HardwareAttested`, and only from a hardware tier. The same function is used when opening a container.

**Client.** For a file whose policy requires attestation, a mechanism-five client attests during issuance and renewal: material from `cc_keystore::pcp` (`KAST` → verifier form; EK from the module under TCG L-1 template), activation by loading the opaque AIK blob. An older server answers kind 31 with “message cannot be parsed” and closes the conversation: mandatory attestation yields an explicit refusal without a lease request; partial requirements lead to a new connection and a user notice. Pinning: `cc attest-ek --out <file>` on the machine, `cca attest enroll <file>` on the server; trust directory: `<state directory>/attest/` (`*.der` roots, `*.ekpub` pinned EKs), read when the acceptor starts.

**Live run on this machine (2026-09-16): an honest refusal.** EK pinned, challenge issued, assertion obtained, EK accepted; the provider AIK signs with ECDSA-**SHA-1**, and the server refused: “AIK: attestation key signature hash is not SHA-256.” Control: same recipient, file with `--hardware-binding` — granted and allowed. Furthermore, credential activation from a non-elevated process failed on this machine (`TPM_E_VALUE` via the provider, `TPM_E_COMMAND_BLOCKED` directly; `docs/evidence/local-completion.md`, B6b). Whether to accept SHA-1 AIK signatures: `docs/deferred.md` §30.

### 9.12. Edition registration — decision of 2026-09-17 (D1)

An edit is published only after the server accepts its number (`docs/format.md`, “EDITING IS EXECUTABLE,” item A). The server keeps one pair per file: number and digest of the latest accepted edition; before the first edit, `(0, zeros)`.

**Request** — `RegisterEdition` (kind 37), body: `oc_format::edit::EditionClaimDoc`, nested TLV, all tags critical:

| Tag | Field | Value |
|---|---|---|
| 1 | `file_id` | bytes[16] |
| 2 | `counter` | u64le — new edition number, ≥ 1 |
| 3 | `base_digest` | bytes[32] — base digest; zeros for an unedited file |
| 4 | `digest` | bytes[32] — new edition digest (item A) |
| 5 | `session_head` | bytes[32] — session head (item D) |
| 6 | `certified_by` | edit-key certificate (item B), up to 8 KiB |
| 7 | `at` | i64le — signature time |
| 8 | `signature` | bytes[256] — RSA-PSS-SHA256 using `editor_key` |

```
Transcript::new("CC/v1/edition-claim")
  .field(tags 1–7)
```

**The request requires no proof of possession of the device key**, deliberately: the author's (or co-author's) edit-key certificate grants authority; a signature by that key proves possession. A handshake would prove possession of a DIFFERENT key (device key), unrelated to editing.

**Server checks, in order:** file known, neither revoked nor frozen; certificate issued by the file author or a member of the co-author set, certificate signature valid, matching `file_id`, unexpired **by server time**; claim signature valid under the edit key; `at` within allowed clock skew (as for orders, §9.3); file policy permits `edit`.

**Decision:**

* `counter` and `digest` equal the accepted values — retry: `Accepted`, no second record;
* `counter` = accepted counter + 1 and `base_digest` = accepted digest — edition accepted: update the pair, journal `EditionRegistered` (event 28) with the certificate's device fingerprint, respond `Accepted`;
* otherwise **conflict** (`EditionConflict`, text “edit conflict,” accepted edition number stated): a second editor who edited the same base has nothing to publish — they must open the latest edition and edit it.

Identical-byte retries are recognized by document identity (§9.10) and receive the stored response.

**Client** (`cc edit --url`) assembles and signs the new file, writes a temporary file beside the target, submits the claim, and publishes by replacement only after `Accepted`; refusal or disconnection removes the temporary file, preserving the original. Files unmanaged by the server are edited with explicit `--local`, without registration.

**Journal head through a separate read request, BEFORE signing** (decision of 2026-09-21). `Accepted` has no body or head, and the editor block is signed before registration, so a response head could not enter it at all. The client requests it via `JournalView` (§9.13, `since = 0`, `upto = 0`) from the SAME server where it will register — no new addressee — and verifies the head signature using `chain::accepted_now` keys (header anchor plus accepted succession chain, §9.18). A short, dedicated deadline (`cc_cli::edit::HEAD_TIMEOUT`, 5 s): the head is best-effort and must not leave editing hanging.

No address (`--local`) means no request: offline editing does not access the network. No response or rejected response leaves `journal_head` empty; editing continues and `cc edit` states the reason. An unverified head is never put in the signed block: it is forty bytes dictated by whoever answered at the address.

What the head means: a lower bound on edit time (“edit no older than head H”), verifiable offline against a later checkpoint; what it does not mean: edition registration or an upper bound (`docs/format.md`, item E).

**What this does not provide.** Readers do not query the server: their reference is the device's accepted-history journal (§3.1); the server registry provides complete history only to those editing through it. The registry is stored in the file record (server-state tag 30), identically in both stores.

### 9.13. Journal witness — decision of 2026-09-17 (D3)

A signed journal head (`cca checkpoint`) proves only server self-consistency: a server rewriting the journal rewrites its root too. A witness is a SEPARATE party with its own Ed25519 key and memory, querying journal views in batches (once per interval, not per entry), checking that the new head extends the witnessed head, and co-signing it after the server. Code: `oc_protocol::witness` (bytes and checks), `cc_authority::witness` (memory, observation cycle, network), `cca witness …` (commands).

**Request** — `JournalView` (kind 38), exactly 16 body bytes: `u64le since ‖ u64le upto`. `upto = 0` means current length; `since = 0` means no proof. No handshake or session MAC: head and proof are public, and the query does not change server state (conversation outcome `Read`).

**Response** — `LogView` (kind 39, shared by the event journal and directory §9.14); body is a view:

```
view = head(104) ‖ u64le since ‖ path(32·N),  N ≤ 128
head = u64le size ‖ root(32) ‖ server signature(64)
server signature over Transcript::new("CC/v1/audit-head").u64be(size).fixed(root)
```

The head layout matches the `cca checkpoint --out` file. `since = 0` means an empty path; `since > size` is a parse rejection. The server refuses if the journal is empty, `upto` exceeds its length, or `since > upto`. A head at `upto` below current length is signed afresh — the same assertion about the same immutable history.

**Root and proof.** Leaves are record MACs (K13); root is `oc_crypto::merkle::root_of(size, MTH)`, with `MTH` the RFC 6962 tree hash. The path is an RFC 9162 §2.1.4 consistency proof with one difference: the verifier knows roots rather than tree hashes, so when `since` is a power of two, the old tree hash omitted by the RFC is ALWAYS included as the first node and checked at verification's end through `root_of` against the old head's root. Equal lengths are consistent only with equal roots and an empty path.

**Witnessed head** — 208 bytes:

```
head(104) ‖ i64le at ‖ witness key(32) ‖ witness signature(64)
witness signature over Transcript::new("CC/v1/witness-cosign")
    .u8(journal kind).fixed(server key).u64be(size).fixed(root).fixed(i64be at)
```

The server key is signed: the witness statement concerns a specific server's log. Log kind (1 — events, 2 — directory §9.14) is signed: a witness statement for one log cannot serve another; witness state stores kind (`cca witness init --log journal|directory`). `at` is witness time and never decreases for one witness.

**Witness cycle** (`cca witness observe`): request a view from the witnessed length; if refused, request a head without proof. Decision:

| Head | Decision |
|---|---|
| first (no remembered head) | signed **without comparison** — nothing to compare against |
| unchanged | signed again with new `at` — witness alive |
| longer, proof valid | signed |
| shorter | **rollback**: not signed, evidence |
| same length, different root; or invalid proof | **fork**: not signed, evidence |
| longer without proof; proof starts at wrong length | not signed, no evidence |
| signature by wrong server | not signed |

Evidence (`evidence/<kind>-<time>-<length>.bin`) is the witnessed head and a view contradicting it; both heads bear server signatures. Rejection does not change witness state. No state means the cycle refuses: only `cca witness init` creates it, so loss cannot be confused with a fresh start. `init --from <head>` initializes from a head stored outside the witness (server signature checked; with `--from-witness`, the former witness signature too).

**Verifier** (`cca witness check`) holds a witnessed head and server/witness keys:

* server and witness signatures; a witness with a different key is rejected — this represents both substitution and witness loss;
* `--max-age` — statement older than the limit: the server may be withholding new records, or the witness may be lost;
* `--head` — its own server head: equal length is checked offline; different lengths need a server proof (`--from`). Mismatch means a fork (split view); a server signing different roots at the same length is exposed by two heads — evidence verifiable without the server; a server failing to prove a head it signed indicates rollback or a fork;
* `--needs <number> [--proof <file>]` — the numbered entry is witnessed (`cca proof <number> --size <length>` builds its inclusion proof at that head length). An entry beyond the boundary is “not witnessed”: beyond the witness interval, this is withholding.

`cca witness` exit codes: 0 — verified; 3 — evidence (rollback, fork, wrong signature); 4 — unverified (no connection, no proof); 5 — unwitnessed or stale; 2 — other failure.

**What this does not provide.** Operator independence: a witness run by the same operator signs what it is shown and rolls back with that operator — the test bench puts it in a separate container on the same Docker, proving process and memory separation, not organizational separation. Public time: `at` is the witness clock. Completeness: a server blocking the witness is visible only through statement age. Record contents: a leaf is a MAC under the server key, and inclusion proves “a record with this MAC is here,” not its contents. Public head publication (anchoring) is deferred.

### 9.14. Organization key directory — decision of 2026-09-17 (D4)

The directory is the server's second log: versioned records “key X belongs to member Y of organization T.” Only the operator writes (`cca directory add|withdraw`); clients and the monitor read over the wire without a handshake. Code: `oc_protocol::directory` (bytes and verification), `cc_authority::directory` (rules and tree), `cc_cli::directory` (client checks).

**Record** — TLV, all nine tags critical, required, consecutive:

| Tag | Field | Value |
|---|---|---|
| 1 | `tenant` | organization: `[a-z0-9._-]`, 1–64 bytes |
| 2 | `name` | member: text, up to 128 characters, no characters unsafe for display |
| 3 | `kem` | mechanism byte (1, 2, 4, 5) |
| 4 | `public` | device key, mechanism-dependent length |
| 5 | `fpr` | K27 of `(kem, public)` — **recomputed and checked** during parsing |
| 6 | `version` | u64le, ≥ 1 |
| 7 | `state` | 0 — active, 1 — withdrawn |
| 8 | `origin` | provenance: text up to 512 characters |
| 9 | `at` | i64le — record time |

Parsing is canonical: a record whose fields re-encode differently is rejected — otherwise one record would have two leaves. Record limit: 8 KiB.

**Directory log.** Leaf: `SHA-256(Transcript::new("CC/v1/directory-entry")
.tail(record))`; tree and root as for the event journal (§9.13); head signed by the server key over `Transcript::new("CC/v1/directory-head")
.u64be(size).fixed(root)`. The same witness (§9.13) uses log kind `Directory`; log kind also enters the witness signature (`Transcript::new("CC/v1/witness-cosign").u8(kind)…`: 1 — event journal, 2 — directory), preventing a witness statement for one log from serving the other.

**Server rules** (checked on writes and EVERY store read): consecutive member versions starting at one; first version cannot withdraw a key; withdrawal names the active key; an active key belongs to one member within an organization.

**Requests** without handshake; responses `LogView` (kind 39) or refusal:

| Kind | Request | Body | Response |
|---|---|---|---|
| 40 | `DirectoryView` | `u64le since ‖ u64le upto` | `LogView` — as in §9.13 |
| 41 | `DirectoryLookup` | `u8 length ‖ organization ‖ u16le length ‖ participant ‖ u64le size` | `DirectoryEntry` (42) |
| 43 | `DirectoryRecords` | `u64le from ‖ u32le count`, `1 ≤ count ≤ 256` | `DirectoryRecords` (44): `(u32le length ‖ record)*` |

`DirectoryEntry` is `head(104) ‖ u64le index ‖ u32le length ‖ record ‖
path(32·N)`, `N ≤ 64`: the member's latest record among the first `size` records (`size = 0` means current directory) and its inclusion proof in a head of that length. “No record” is a refusal saying “no directory record…”: **absence is not proved**; the monitor checks completeness.

**Client** compares the response against four things and states its basis:

* head signature — server key from the file header (for approval) or explicitly supplied (`cc directory lookup --server-key`); record for the requested member and organization; inclusion in this head;
* memory (`directory-seen`): directory head no shorter than previously seen and extends it (server proof); member version no lower than seen; same version means same key; “no record” for a previously seen member means concealment;
* witness statement (`--cosigned`, witness pinned by `cc directory witness`): server head extends the witnessed head, and the record in the witnessed head is THE SAME — then basis “proved”; an older record means “new version not yet witnessed”; a newer one means concealment;
* manual verification (`verified-devices`): a different key under the same name means conflict; the directory neither creates nor modifies manual verifications.

Bases: **proved**, **in directory** (without a witness statement), **key withdrawn**, **no record**, **conflict** (exit code 4).

**Directory-based approval** (`cc approve … --directory T/Y --cosigned F`) is an independent basis, incompatible with `--fpr` and `--unverified`: granted only for “proved”; the record key is compared against the queue just like a supplied `--fpr`, and is NOT written to manual-verification memory. Batch approval (`--manifest … --directory T`) still requires the listed pair; the directory only excludes contradictions: a different key under the same name, withdrawn key, conflict.

**Monitor** (`cca directory audit`) reads the entire directory to the witnessed length, reconstructs rules and root, and compares with the head: missing records mean withholding; a different root means a fork.

**Storage.** State file: tag 12 (record stream); PostgreSQL: `directory_records` table (migration 6), runtime has only `SELECT` and `INSERT`; a directory shorter than the stored one causes commit refusal.

**What this does not provide.** A member name is the operator's assertion: a proved record shows everyone sees one directory, not who stands behind the key. Record absence is the server's assertion. Witness independence from the operator is not a code property (§9.13).

### 9.15. Recovery package and state keys — decision of 2026-09-17 (E2, B5)

**Task.** A server restored from backup must either serve the same history with the same keys or refuse to start and state what is missing. Before E2, two things failed this: state did not know its serving keys, and a mixed backup (this server's signing key, another's sealing key) started a server that refused every activation with a cryptographic error; key backups were checked only by recomputing the signing key (`deploy/managed/restore-keys.sh`).

**State keys.** State file tag 13: `sealing key(32) ‖
lease signing key(32)` — public halves. Reads used for server responses compare these with directory keys before assigning state (`StoreError::KeysMismatch`, acceptor does not start, message names the key). State without this tag is from an older build; the first write adds it. A preliminary read asking “was the operation recorded?” (`FileStore::seen`) does not check keys: it signs nothing and answers nobody. PostgreSQL: `SqlStore::open` compares `authorities.sealing_public` with the directory key.

**Package** (`cca recovery pack --out D`) — directory:

| Part | Contents |
|---|---|
| `sealing.key`, `lease-sign.key` | keys as stored: DPAPI-wrapped remain wrapped |
| `authority.pub` | public halves |
| `authority-state.bin` | state (file store only), read once |
| `attest/*` | attestation anchors, if configured |
| `manifest.bin` | manifest, written last |

Manifest: `signature(64) ‖ TLV`: version (1), signing key (2), sealing key (3), time (4), program version (5), store 1 — file, 2 — database (6), state digest (7, file only), signed 104-byte journal head (8), key protection as text (9), parts as a stream `u16le length ‖ name ‖ SHA-256` (10). Signature: lease-signing key over `CC/v1/recovery-manifest ‖ body`. Part name is a path inside the package: no `..`, `.`, empty components, `\`, or `:`; otherwise manifest parsing fails. Codec: `cc_authority::recovery`. Body limited to 64 KiB; with the 64-byte signature, manifest file cannot exceed 64 KiB + 64 bytes. The verifier reads at most the limit plus one byte and rejects larger files before parsing.

A manifest signature proves self-consistency: its verification key is inside it. Trust comes from comparison with the `authority.pub` known to authors (`--expect-authority`); without this, verification prints “WARNING” with the key. A rollback witness is not packaged: an old package would bring an old witness.

**Verification** (`cca recovery verify D [--expect-authority P] [--witness W]`) reports each part as “PASS / FAIL / WARNING”: manifest and signature; keys versus `authority.pub`; mandatory parts present; each part's digest; whether keys open on this machine and match the manifest (“mixed backup”); whether state reads under those keys and its journal matches the manifest head; whether the package extends the witness (“package behind”). Any failure yields nonzero exit status. Database: only keys are checked; the database itself uses `cca store verify` after restoration.

**Restoration** (`cca recovery restore D --home H …`) repeats verification, refuses any failure or a nonempty destination, rechecks every part's digest while copying, and prints a launch command with an outside-package witness. Starting the restored directory performs three comparisons: keys against state (tag 13), journal against saved head, journal against witness.

**What this does not provide.** Key portability: a DPAPI-wrapped key does not open on another machine or under another account, which verification states; on Windows `CC_KEY_STORAGE=portable` still wraps if the platform supports it (`deferred.md` §26.1). Package protection from its holder: it contains server keys. Complete history after capture: the package is a lower bound; only the witness knows newer history.

### 9.16. Server control: binding, intents, and receipts — decision of 2026-09-18 (E2, B2)

**Task.** Before B2, server addresses, durability profile, controller roster, author admission, and service termination changed LOCALLY through a command on the server machine: filesystem access conferred authority, no trace remained, and clients learned of changes only through behavior. Changes now have a signed intent, a signed binding with a revision number, and a signed receipt; clients have a way to detect rollback.

**Binding** (`oc_protocol::control::Binding`) — `signature(64) ‖ TLV`: version (1), organization (2), stable 16-byte identity (3), epoch (4), revision (5), lease-signing key (6), sealing key (7), addresses as a `u16le length ‖ address` stream, 1–8 (8), ascending 32-byte TLS fingerprints, up to 8 (9), durability profile 0/1/2 — local/mirrored/witnessed (10), recovery mode (11), service state 0–3 (12), ascending controller roster, up to 16 (13), threshold (14, zero only for an empty roster), operation that created the revision (15), previous-revision digest (16, zeros only for revision 0), issued (17), valid until (18). Lease-signing-key signature over `CC/v1/authority-binding ‖ body`.

**Verified with a previously known key.** The client takes its anchor from the container HEADER (lease-signing key pinned under the author's signature) and verifies with it; the embedded key field must match the anchor. A document calling itself trusted does not create trust.

**Client revision memory.** A signature cannot distinguish a fresh binding from an old one: both are authentic. The client remembers the latest seen (`<directory>/bindings/<key>.bin`) and compares (`oc_protocol::control::continuity`): identical — `Same`; next revision referring to the remembered one — `Newer`; lower — **ROLLBACK**; same revision with different bytes or adjacent revision without the link — **FORK**. Rollback and fork are evidence (exit code 4); expiry and an address absent from the binding are rule refusals (code 5).

**Intent** (`ControlRequest`) — `u8 n ‖ (key ‖ signature)·n ‖ TLV`, signatures in ascending key order, all over ONE body (`CC/v1/control-request`): version (1), organization (2), authority identity (3), epoch (4), 16-byte operation identity (5), scope = 1 (6), expected revision (7), issued (8), valid until (9, no longer than one day), kind (10), payload (11). Payload kinds: addresses and fingerprints (1), durability profile (2), roster and threshold (3), recovery mode (4), service termination `Stopped`/`ArchiveOnly` with reason (5), author-key admission (6), and removal (7). Wire kind 45 carries intent, 46 a receipt, 47 a binding query, 48 the binding itself.

**Server checks and order.** Scope (organization, identity, epoch) first: another scope's intent neither executes nor leaves a trace in identity memory. Then freshness by intent validity. Then replay: same identity and same body — stored receipt; same identity and different body — `IdConflict`. Then expected revision: mismatch — `StaleRevision`. Then authority: signatures from the CURRENT revision's roster, at least the threshold count — the old roster changes the roster; the new one does not appoint itself. Only then does the binding receive revision +1 linked to its predecessor, all persisted BEFORE responding.

**Receipt** (`Receipt`) — `signature(64) ‖ TLV` (`CC/v1/operation-receipt`): intent-body digest, operation identity, outcome (executed, rejected, awaiting replica confirmation, identity occupied, wrong revision), post-operation revision, committed-binding digest, epoch, achieved durability, reason, time. Refusal gets a receipt too: silence is indistinguishable from response loss. None is issued only when there is nothing valid to receipt — unparseable intent, invalid signature, foreign scope.

**Replay barrier.** Receipts are not retained forever (last 256), but revision grows forever: an intent whose revision has already passed never becomes executable again. Compacting receipt memory therefore does not revive old intents (V11).

**Service termination** (P16). `Stopped` and `ArchiveOnly` block registration (both entry points), access requests, and every lease grant (`Denied::NotServing`). Revocation, revocation notices, file status, journal, and binding remain available: stopping service must not hide history; authors must retain the ability to revoke earlier grants. Previously issued leases last until their expiry, which the client states explicitly.

**Local path.** `cca control init|set` modifies the binding on the server machine: directory access confers authority; this is no weakening (someone with access to the keys already has everything). It advances revisions like a wire intent — otherwise local edits would be invisible to clients.

**Server without a binding versus an older server.** Both refuse binding queries; the client relays their exact messages: “binding not initialized” and “unknown message kind” mean different things, and collapsing them into “none” would let an old server look like one without requirements.

**What this does not provide.** Proof that the server does not show different clients different bindings: that needs a shared witness like the journal (§9.13); here only differences visible within one client's memory are caught. Neither durability profile nor recovery mode enforces itself — each is the server's declaration; enforcement comes from the replica (B4) and recovery package (§9.15).

### 9.17. State replica: push and acknowledgment — decision of 2026-09-18 (E2, B4)

**Task.** A binding's durability profile (§9.16) does not enforce itself. `local` means success after the server's durable write, as always. `mirrored` sends a copy to a replica AFTER success; the tail has nonzero RPO. `witnessed` withholds success until the replica confirms EXACTLY these bytes.

**Push** (`oc_protocol::replica::Push`) — `signature(64) ‖ TLV`: version (1), authority identity (2), epoch (3), commit number (4), previous-snapshot digest (5), snapshot digest (6), “full snapshot” flag (7), time (8), state bytes (9, at most 2 MiB). Lease-signing-key signature over `CC/v1/replica-push ‖ body`. The receiver compares digest against bytes: the signature covers the digest, and a nonmatching snapshot is rejected.

**Acknowledgment** (`Ack`) — `signature(64) ‖ TLV`: version, authority identity, epoch, commit number, snapshot digest, replica key, time; REPLICA-key signature over `CC/v1/replica-ack ‖ body`. The server knows the replica key beforehand (startup flag); the embedded field must match it.

**Continuity.** A replica accepts only an extension of its history: number exactly one higher and matching previous digest. A gap gives `SnapshotRequired` (server resends the same snapshot with “full” set); same number with a different digest gives `HistoryConflict` (evidence: two histories of one server); foreign identity gives `OtherScope`. A “full” snapshot cannot rewind history.

**Replica write order** — snapshot, then cursor. Interruption leaves the cursor at the previous number; the server resends the same snapshot: worst case is repetition, not a lost acknowledgment.

**Server cursor** (`<directory>/replica-cursor.bin`) — latest commit number, its digest, and latest acknowledged number. Stored SEPARATELY from state: inside state it would describe itself. The number advances only when the state digest changes — a conversation changing nothing produces no copy.

**Server behavior per profile.** `local`: nothing. `mirrored`: push snapshot after writing, DO NOT wait; cursor exposes the unacknowledged tail. `witnessed`: push and await acknowledgment; without it, return “awaiting replica confirmation” instead of the prepared response. The change itself is already durable; retrying the same intent (or K28 operation) returns the saved outcome once acknowledgment arrives.

**What this does not provide.** Another machine: a replica in a neighboring process or container survives server-process failure, and only that; disk, machine, and administrator are not covered. Server, replica, and `cca replica status` state this boundary.

**Commands.** `cca replica init --dir <directory> --authority <authority.pub>
--authority-id <hex32>` initializes the replica directory and key; `cca replica serve
--dir … --listen …` receives snapshots (one conversation per snapshot, no sessions or background threads); `cca replica status --dir …` prints what has been acknowledged. Server acceptor flags: `--replica <address> --replica-key <hex64>`; without both, profile `witnessed` refuses to start.

### 9.18. Authority succession: transfer chain — decision of 2026-09-18 (E2, B7)

**Task.** The author pinned ONE server's lease-signing key in the header. A server may move: change keys, address, operator. The old container knows nothing of this, and cannot verify a new server's lease under its key. A way is needed to say “this party now issues leases” WITHOUT making an arbitrary new server trusted.

**Transfer certificate** (`oc_protocol::control::Transfer`) — `u8 n ‖ (key ‖ signature)·n ‖ TLV`, signatures in ascending key order over `CC/v1/authority-transfer ‖ body`: version (1), authority identity (2, UNCHANGED across transfer), “from” epoch (3), “to” epoch (4, exactly +1), previous epoch's lease-signing key (5), transition point (6), old-lease treatment (7: 0 — valid until expiry, 1 — reject if issued after transition), issued (8), valid until (9), signed NEW-epoch binding (10).

**Who may transfer.** The PREVIOUS epoch's controller roster, with signatures meeting its threshold (`Binding::roster`, `threshold`). The successor binding is signed by its own key, which alone means nothing: authority comes from roster signatures on the certificate carrying all its bytes.

**Chain** — a file containing the epoch 0 binding followed by certificates, each `u32le length ‖ document`. Verification (`verify_chain`) starts at the anchor — the container-header key — and at every step requires: same authority identity, certificate epoch equal to the current epoch, matching named previous key, unexpired validity, roster signatures meeting threshold, and successor binding matching the certificate's epoch. No chain document grants itself trust.

**Obtained as a file, not from the server, deliberately.** The trust root is needed precisely when the former server is gone: `cc authority <file.cc> --chain <file>` verifies and remembers the chain in `<directory>/chains/<key>.bin`.

**The chain file is bounded.** It is read on EVERY failed lease verification and resides in the settings directory, writable by everything running under that account. Size is checked before reading; the limit derives from chain rules (sixteen transfers, each containing a binding) and is one mebibyte. Parsing enforces the same limit because chain verification also receives bytes from sources other than files.

**The chain is verified BEFORE any address; the successor address comes from it.** This order is semantic: `cc authority` normally requires a user-specified address; resolving it before the chain would demand the dead epoch's address, the only one the file knows. Therefore the `--chain` branch precedes address resolution and returns directly. Upon accepting the chain, the client remembers the current epoch's first address as the chosen address for this author: a verified-chain address is as trustworthy as its key; without this step the client would have a correct key but no route to its signer. This is recovery without the old DNS: a fresh client that has never contacted any server obtains the current epoch and its address from one file.

**Leases.** Lease verification (`cc_cli::lease::verify_with_chain`, also used by `verify_for`) first tries the header key — the usual path for an unmoved file. If it fails and a verified chain exists, use the keys it permits: current epoch, intermediate epochs, anchor. If verification succeeds but the chain says “reject old leases after transition” and the lease was issued later than the transition point, reject as `AfterTransition`: this blocks the former writer restored from backup beside the successor (V12).

**One entry point, for opening and receiving grants alike.** `cc unprotect`, viewer, and broker ask the same server-trust question as `cc activate` and renewal; until 2026-09-21 they answered differently: grant reception verified with ONE header key, bypassing the chain, so after an honest authority transfer recipients could not open the document at all. Unifying these paths did not change the trust set; it made it one set: a lease signed by a key absent from both the header and accepted chain is rejected at both entry points, each naming the remedy — `cc authority <file.cc>
--chain <chain file>`.

**Binding.** The server binding (§9.16) follows the same rule, with more than one key: before transfers, the container anchor; with a verified chain, ALL permitted keys (`cc_cli::chain::accepted_now`, same order as leases: current epoch, previous epochs, anchor). A single key fails in either direction because BOTH servers are honest. Anchor-only verification would call the successor's self-signed binding a forgery. Current-key-only verification would call the former server a forgery — yet it must answer “authority transferred, ask the successor” precisely to clients unaware of the move who still contact it. “Not our signature” becomes evidence only after every allowed key has been tried.

Trust is no weaker: the chain is quorum-verified from THIS file's anchor on every read, and keys come from it, not server claims. Binding memory is keyed by the MATCHING key: each epoch has its own revision history, so there is nothing to compare across epochs — the meaning of `Continuity::Unrelated`.

The client's final message reflects which key matched: “verified with this file's server key” (no transfers); “with the current epoch key named by the succession chain from this file's anchor” (successor response); or “with a PREVIOUS epoch key: the chain names epoch N as current” (former server response). Saying the second when the third is true would be worse than silence: the user would think they were talking to the issuer.

**Former server.** `cca control apply-transfer <certificate>` verifies by the same rule (our epoch, our key, our quorum) and sets `Transferred`: registration and issuance stop; revocation, revocation notices, status, and journal remain.

**Revocation survives migration and needs no route to the server.** A revocation notice is a document: `cca revoke` writes it to a file, transferable through any channel and placed beside the container as `<container>.revoked`. A reader denies on it even with an active cached lease and no running server. The independence is specifically from the ADDRESS.

**The server PERFORMING REVOCATION signs the notice; after transfer, that may be the successor.** Until 2026-09-21, this said “the previous epoch still signs revocation notices,” relying on the successor not serving old files; `adopt-sealing` (§31 `deferred.md`) changed that, and it now does. Both may revoke: the previous epoch retains revocation, notices, status, and journal after `apply-transfer`; a successor that adopted the file revokes with its own key (`State::revocation_for` signs with the CURRENT epoch's lease-signing key).

A notice therefore uses THE SAME KEY SET AS A LEASE (`cc_cli::revoked::verify_with_chain`): first the header key; on failure, epoch keys named by the accepted chain. Until 2026-09-21, that set contained only the header key; successor notices were never accepted — failure was OPEN: an author-revoked file remained open to its recipient until the cached license expired, without printing any error.

**The transition cutoff does NOT apply to revocation notices, deliberately.** For leases, an old-epoch key after transition is rejected (`OldLeases::RejectAfterTransition`), because leases OPEN files and a displaced operator could keep issuing access. Notices only close; the same cutoff would favor opening: transferring authority would become a way to REMOVE revocation — transfer to oneself in a new epoch, and all old notices stop being accepted. Revocation is final even across epoch changes. There is no appropriate time to compare either: a notice has no issue time, and `at` is the revocation time by server clock, “for journal and reports, not comparison.”

**What this does not provide.** The sealing key BY ITSELF: the chain only says whose signature is valid; share A of previously issued files is sealed to the former key. The pre-2026-09-21 assertion — “without it the successor cannot issue any share, so migration means either moving keys or reissuing files” — became outdated: the key is transferred by one command, `cca control adopt-sealing --key`, after which the successor opens its predecessor's slot and issues the share (`crates/cc-authority/tests/succession_sealing.rs`). The remaining cost is that the transfer must be PERFORMED: without it, `apply-transfer` explicitly states how many files will remain without shares and the remedy.

An old client unaware of the chain accepts neither successor leases nor notices. For a lease this fails closed and names the remedy; for a notice it fails open. A client finding an adjacent notice signed by a server unknown to this file therefore TELLS the user and names the same command. It does not stop opening: internally there is no way to distinguish an authentic successor notice from a forgery; closing on an unverified signature would put other people's documents under the control of anyone able to place a file in a neighboring folder.

### 9.19. Readiness view and three kinds of recovery — decision of 2026-09-18 (E2, B6)

**Task.** Distribution is IRREVERSIBLE: a file may be revoked, but distributed copies cannot be taken back. Before distribution, an author needs one answer but had three views: `cc inspect` parses the file, `cc authority` queries the server binding, and `cc standing` checks the file's standing. Each answered its own question; a human combined them, until the first rush.

**`cc ready <file.cc> [--url <address>]`** combines those same three answers into a verdict. It learns nothing new and has no protocol of its own: `Binding`, `Standing`, and header parsing — the same messages as those three commands.

**Three outcomes, and only three.**

* `МОЖНО РАЗДАВАТЬ` — READY TO DISTRIBUTE: server knows the file, is serving, no revocation or freeze, file has a recipient. Exit code 0.
* `РАЗДАВАТЬ НЕЛЬЗЯ` — MUST NOT DISTRIBUTE: known reason — server does not know the file, file revoked, grants frozen by panic button, server stopped serving or transferred authority, wrong signing key, no recipients in file. Code 5.
* `НЕ ЗНАЮ` — UNKNOWN: nobody available to ask — no address specified or server did not answer. Code 6.

The third outcome is the point of the command. Its verdict BIASES TOWARDS DENIAL, like I-10: unverified does not count as verified; no branch permits silence to mean consent. Two silences are distinguished: a server returning refusal means “must not”; a server not responding means “unknown,” distinguished by refusal code, not text.

**The remembered succession chain appears here too.** If a chain was accepted for this file's anchor (`cc authority --chain`), the readiness view prints the current epoch, its addresses, and transition time; if the queried address is not in the current epoch, a separate line states this. Users consult readiness precisely when something is wrong; if authority moved, they need the CURRENT epoch's address, not an explanation of why the former one is silent. The displayed data is verified: the chain was checked from the file anchor upon acceptance, not upon display.

**Three kinds of recovery that must not be confused.** When service disappears, “what do I do?” has THREE noninterchangeable answers:

1. **Recover content** — open without the server: via the author's device slot, approval, co-author quorum, or bequest to an heir. This does not restore service.
2. **Restore service** — start the server from a recovery package (§9.15), a replica (§9.17), or transfer authority to a successor (§9.18). This does not open a file for someone lacking an opening mechanism.
3. **Issue a new file** — the author reissues from the source. Already distributed copies remain unchanged and continue their own lifecycle.

This choice is printed where service is gone: `cc ready` for an unavailable or stopped server, and `cca recovery restore` after startup. Confusing the three makes a user try whichever comes first; here that is usually the wrong one.
## 10. Access requests: documents and their bytes

This section was written on 2026-08-27 to close a gap: access-request documents had existed in code since F-14, yet had NO normative description whatsoever. Under repository law, the specification wins in a disagreement—but there was nothing to win. The gap was not harmless: BOTH ends of the wire, client and server, enforce the note character-set rule, and they update independently. A rule living only in one side's code is a rule the other side does not know about.

### 10.1. Why the documents exist and who signs them

The system defaults to **requesting access, not seamless access**: a recipient not named during packaging has no slot in the container and cannot open the file. Instead of a rejection, they see an opportunity to ask, and the author an opportunity to approve or deny.

There are three documents, each with its own direction:

| Document | Prepared by | Addressed to | Signature |
|---|---|---|---|
| `AskAccess` | recipient | server | **none** |
| `Pending` | server | author | **none** |
| `Decision` | author | server, then recipient | **present**, using the author's key |

The signature is exactly where it is needed: the author grants access, and only their decision must be unforgeable. The request is deliberately unsigned—the requester was not named during packaging, and there would be no key against which to verify their signature. The queue is protected by a ceiling (§10.6) and fingerprint comparison (§10.8), rather than identity verification.

### 10.2. Common layout

All three documents use the same TLV form as the container header: a `u16` tag, a `u32` length, and a value. Fields appear in **strictly increasing tag order** (I-7), which also rules out duplicates and permutations. All ASSIGNED tags are ≤ `0x7FFF` and thus critical: an unknown tag in this range causes rejection.

An unknown tag > `0x7FFF` is skipped—the general rule in §0.1 (decision of 2026-09-21)—in requests and queue entries. The rule does not apply to the author's DECISION (§10.5): its signature is verified over a reconstructed body (`access::decision_body`), and skipping would make the signed document malleable. The full reasoning is in §0.1 and the parser itself.

The document size limit is `MAX_DOCUMENT` = `MAX_HEADER_LEN` = 1 MiB.

Tag registry (shared by all three documents; numbers are not reused):

| Tag | Name | Type | Length |
|---|---|---|---|
| 1 | `file_id` | bytes | exactly 16 |
| 2 | `device_fpr` | bytes | exactly 32 |
| 3 | `device_public` | bytes | determined by `device_kem`, see §10.8 |
| 4 | `device_kem` | `u8` | exactly 1 |
| 5 | `note` | UTF-8 | at most 256 **bytes**, character set in §10.7 |
| 6 | `seq` | `u64` LE | exactly 8 |
| 7 | `at` | `i64` LE | exactly 8 |
| 8 | `approve` | `u8` (0 or 1) | exactly 1 |
| 9 | `enc` | bytes | Seal ephemeral key |
| 10 | `nonce` | bytes | exactly 24 |
| 11 | `ct` | bytes | share B under AEAD |
| 12 | `author_key` | bytes | exactly 32 |
| 13 | `signature` | bytes | exactly 64 |

### 10.3. `AskAccess`—the recipient's request

Fields: `file_id`(1), `device_fpr`(2), `device_public`(3), `device_kem`(4), `note`(5). All are required.

### 10.4. `Pending`—the request as seen by the author

The `AskAccess` fields plus `seq`(6) and `at`(7). Both are added by the **server**, and both are its own: `seq` is the position in the queue, and `at` is a timestamp from the SERVER's clock. A time supplied by the requester is unsubstantiated and is not included in the document.

### 10.5. `Decision`—the author's decision

Body: `file_id`(1), `device_fpr`(2), `seq`(6), `approve`(8), then—**only for approval**—`enc`(9), `nonce`(10), `ct`(11), and always `author_key`(12). The complete document is the body with a `signature`(13) TLV appended.

Both approval without a share and denial with a share are rejected: the former is permission that cannot be exercised, and the latter is a share delivered contrary to the decision.

**`approve` is exactly `0` or `1`; any other byte is rejected during parsing (2026-09-20).** Previously it was read as “a nonzero byte,” and `5` meant approval just as one did—two representations of one meaning where canonicality (I-7) requires one. On the same day and for the same reason, the `snapshot` flag in a replica push (§9.17) was tightened as well.

**The entire body is signed**, using a transcript with label `"CC/v1/grant"`; the `signature` field is excluded from the signature and must appear last (increasing tag order ensures this). Verification uses `verify_strict` (I-6).

The verification key is taken **from the recipient's container header**, where the author pinned it under their signature, NOT from the supplied document's `author_key` field. `author_key` is carried so that someone who has not yet seen the file can verify the signature, not so that it can be trusted: taking the key from the document being verified would mean asking the subject of verification whether to trust it.

### 10.6. Limits

* `MAX_NOTE` = **256 bytes** (not characters: a Russian note fits half as many letters as a Latin one, correctly so—bytes travel over the wire);
* `MAX_WAITING_PER_FILE` = **256** unresolved requests per file—the ceiling on what the server remembers. A repeated request from the same device takes no additional space and does not hit the ceiling; otherwise, an adversary who filled the queue would deprive a legitimate recipient of the right to ask again;
* `MAX_PENDING_PER_FILE` = **16**—the window: a `Requests` response carries the first sixteen unresolved requests by sequence number, no more, and the client rejects a larger response. A resolved request leaves the window and the next one enters. Until 2026-09-16, the window and ceiling were the same (16), and the seventeenth requester received “queue full”—eighty-four rejections in a mailing to a hundred recipients (`docs/plan.md`, F-22 item 3). Separating them did not change the response format;
* `MAX_DOCUMENT` = 1 MiB.

### 10.7. Note character set—NORMATIVE

A note is a phrase from one person to another, written in their own language. Therefore the restriction to printable US-ASCII that is normative for server addresses (`docs/format.md`, “Server addresses”) **does not and must not apply here**: an address has a wire representation that is ASCII by construction (non-Latin names use punycode), whereas a note does not.

**Categories**, not alphabets, are rejected. The following list is normative; the implementation must match it and lives in `oc_format::text`.

1. **Control characters**—the entire `Cc` category, including `\n` and `\r`. A newline is forbidden JUST LIKE the others: the note is printed as an item in a list of requests, and a newline moves text outside that item—a note containing “No. 2” and “device:” draws a request into the queue that does not exist.
2. **Direction marks and switches**—twelve code points: U+061C, U+200E, U+200F, U+202A…U+202E, U+2066…U+2069. Twelve, not nine: the Trojan Source set (embeddings, PDF, overrides, isolates) does not include direction MARKS themselves, although they reorder text too.
3. **Invisible formatting characters without an orthographic role**—U+00AD, U+180E, U+200B, U+2060, U+FEFF. They do not reorder text; they are not displayed at all, making two different notes appear identical.
4. **Line and paragraph separators**—U+2028, U+2029. Listed separately because their categories are `Zl` and `Zp`, not `Cc`: the control-character check does NOT catch them.
5. **Tag characters**—U+E0000…U+E007F, an invisible copy of ASCII. The cost is explicit: sequences for certain regional flags will not pass this check.

**U+200C and U+200D (ZWNJ and ZWJ) ARE ALLOWED.** They are invisible but orthographically required in Persian, Arabic, and Devanagari, and join composite emoji. Banning them would repeat the mistake of restricting text to ASCII one level deeper.

Combining marks are unrestricted: they are part of the writing systems of half the world. The LENGTH limit addresses “zalgo,” rather than a category ban.

The rule is enforced during both writing and **parsing**—and therefore by the server too. The responses differ: parsing REJECTS the document (`FormatError::BadNoteChar` with the character's code point but not the character itself—printing it would let it reach the screen by precisely the path the check closes), while display REPLACES the character with a dot. Both sides use the same set.

### 10.8. What each party must check

**The server, upon receiving a request:**

* `device_fpr` **equals** `device_fpr(device_kem, device_public)` under K27 (`docs/format.md`, “Device fingerprint for all mechanisms”), compared in constant time; the key length matches the mechanism. Otherwise reject with “fingerprint does not match key.” Until 2026-09-09 this said “`device_kem` = 1, otherwise reject”: the fingerprint-to-key binding was defined only for X25519. The reasoning stayed the same; only the method had been narrower: if the server accepted an inconsistent triple, an outsider could send the victim's fingerprint with their own key, the author would verify the fingerprint through a second channel and see the correct one, and the share would leave sealed to the outsider's key;
* the file is registered and not revoked;
* the queue ceiling (§10.6), checking for a repeat BEFORE the ceiling.

**The requester, preparing a request (F-12 stage 4, 2026-09-14):** choose the mechanism by the file's strength (the author slot), not the recipient slot: a classical file uses X25519, X-Wing uses X-Wing, a hardware hybrid uses only the fifth mechanism; without a TPM key, reject instead of making a request weaker than the file. Print for the person the EXACT identity under which the request was sent: for a hybrid, the K27 identity, not the classical key.

**The author, approving:** independently checks `device_fpr == device_fpr(device_kem, device_public)` before the verification gate and before opening the slot, and again before sealing. Human verification over a second channel remains: it verifies the IDENTITY, while the program verifies that the identity names the supplied key. P-256 (`kem_id = 2`) is rejected: the recipient has no way to unwrap such a share.

**The recipient, collecting a decision:** queries under each of their identities (classical, K27 for X-Wing, K27 for MLKEM768-P256 with a TPM key) in a separate conversation proving that identity; the server releases a decision only under the proven identity (§9.4, `Collect`). Approval under any identity takes precedence over denial under any other; decision numbers across identities are not compared—the server defines the order between the queue and a bequest (§11.5: bequest first).

**The author, receiving the queue:** verifies the **fingerprint** with the requester over a second channel and specifies it in `--fpr`. The server assigns the queue number, and a different requester may already occupy that number by the time approval occurs. The note is a hint, not a credential: its text was chosen by an outsider.

**The recipient, having collected a decision:** verifies the signature with `verify_strict` using the key in THEIR OWN file's header; `file_id` must be their own; `device_fpr` must be one of THEIR OWN identities, compared against all of them in constant time without early exit; the share is unwrapped using the matched identity's mechanism and the same identity in `info`—without iterating through mechanisms or falling back to another on failure. A decision signed by the wrong key is substitution, not someone else's file: it must not be opened.

### 10.9. What this mechanism does NOT provide

* **A request has no proof of possession and cannot have one.** The requester was not named during packaging; they have nothing to present. Anyone who reaches the address may submit a request.
* **Approval is irreversible.** A delivered share cannot be recalled: the recipient already has it. Access can be closed only by revoking the file on the server—the server then stops releasing the second share, and the file cannot be opened.
* **There is no metadata privacy.** An outsider on the channel can see who requests access to which file. Neither the contents nor share B are visible: the share is sealed to the device key, and even the server does not open it.

## 11. Heir and sign of life: decision of 2026-09-04

This section describes the **dead man's switch**. Quorum and coauthors, for which kind numbers 3–6 and tags 7–10 are reserved, are described in the next section.

### 11.1. Orders are no longer a pair

Until 2026-09-04, `oc_protocol::order` knew two kinds: registration and revocation. There are now four, introducing something the pair did not have—a **set of fields dependent on the kind**: registration has its limits, the heir has a timeout and bequest, and a sign of life has its author key.

The field set is checked by **one function in both directions** (`order::check`), and this is not a stylistic preference. If writing and parsing validation diverged by even one field, an order would exist that we refuse to issue yet still execute when it arrives from outside. Previously the “limits on revocation” pair carried exactly the same caveat; now there is one for every kind.

### 11.2. Kind and tag registry

Kinds (`kind`, tag 3, exactly 1 byte):

| Number | Kind | Effect |
|---|---|---|
| 1 | `Register` | reserve a file on the server with the specified limits |
| 2 | `Revoke` | revoke access to a file |
| 3–6 | — | **reserved for quorum**: limits, coauthor membership, approver membership, device vote |
| 7 | `Alive` | author is present: postpone the silence deadline |
| 8 | `SetHeir` | appoint an heir, close after silence, or remove both |

Body tags (all ASSIGNED numbers are critical, appear in increasing order, and are not reused). The `0x8000`–`0xFFFF` range has no assigned fields and is reserved for optional ones: unknown tags in it are skipped (§0.1).

| Tag | Name | Type | Applicable kinds |
|---|---|---|---|
| 1 | `version` | `u16` LE | all, value 1 |
| 2 | `file_id` | bytes, exactly 16 | all; zero means “all files belonging to this key,” only for `Alive` |
| 3 | `kind` | `u8` | all |
| 4 | `at` | `i64` LE | all |
| 5 | `max_devices` | `u32` LE | only `Register`, optional |
| 6 | `max_grants` | `u32` LE | only `Register`, optional |
| 7–10 | — | — | **reserved for quorum** |
| 11 | `silence_seconds` | `u64` LE | required for `SetHeir{Open, Close}`, forbidden otherwise |
| 12 | `heir_mode` | `u8` | required for `SetHeir`, forbidden otherwise |
| 13 | `bequest` | bytes | required for `SetHeir{Open}`, forbidden otherwise |
| 14 | `author_key` | bytes, exactly 32 | required for `Alive` with zero `file_id`, forbidden otherwise |

`heir_mode`: `0`—remove the heir and timeout entirely, `1`—release the bequest to the heir, `2`—close the file to everyone. Zero is **a value, not an absent field**: “remove” is an order the server must execute and record, and it must be distinguished from “the field was forgotten” during parsing, not by guesswork.

### 11.3. Why an heir is appointed through a bequest rather than a slot

A slot would have to be inserted into the header, meaning **repackaging the file**: repackaging changes `file_id` and the signature, and copies already distributed would not acquire the heir. Version 1 also has only one recipient slot, already occupied for files with a partner.

A bequest requires no repackaging. The author's `AuthorDevice` slot contains BOTH shares, so the author can seal share B to the heir's device key on any day after the file is released, without touching the container.

**The receiving side does not change at all.** A bequest is an ordinary `Decision` (§10.5) with reserved number `HEIR_SEQ = u64::MAX`; the recipient does not check the number (`cc_cli::granted::accept_against`), which is not an omission but the reason a bequest is possible without changing the client. The **server** checks the number and uses it to distinguish a bequest from an ordinary decision without introducing a second document kind. The global decision queue starts at zero and grows, so the largest possible number is unreachable for it: reserving it for a bequest takes no number away from the queue.

A bequest travels as **ready-made bytes**, and the parsing side must return them unchanged: the author's signature covers the entire decision, and any reconstruction would disagree with it.

### 11.4. What parsing checks in a bequest

The order parser checks the NESTED decision, not just its presence (I-9: unverified bytes do not leave the crate):

* it parses as a `Decision`;
* its `file_id` matches the order's `file_id`;
* its `seq` equals `HEIR_SEQ`;
* it approves (`approve = 1`) and carries share B.

The first of the four is a necessity, not housekeeping: the author's signature is equally valid on their decision about ANOTHER file, so a signature cannot distinguish an unrelated bequest from the required one; its contents must be checked. The server verifies the decision's own signature upon receipt, using the key recorded for the file.

### 11.5. What the server does

**Any ORDER from the author is a sign of life**, not just `Alive`: revocation, changing limits, changing membership, appointing an heir. Each has an issue timestamp and passes freshness validation, so each DATES the author's presence. One function, `touch_alive`, records the mark, and does so for **all files belonging to this key at once**.

**A decision on a request (`Decision`) is NOT a sign of life**, contrary to the first version of this paragraph. A decision carries no issue timestamp at all, so freshness cannot be checked. An approval signed at any time and withheld would buy a full silence period on the day it finally arrived; an author may accumulate any number of signed but unsent decisions. Corrected following an adversarial review finding on 2026-09-04. Silence is a property of the AUTHOR, not the file: someone who came to approve one document is not dead with respect to the others. If the server measured silence per file, an heir would receive rarely used documents while the author was alive.

The mark moves only **forward**. It must never move backward: a smaller value lengthens the silence and thus brings the irreversible event closer, while callers bring their own view of time, and one of those views will eventually lag.

**The event is evaluated lazily when the file is accessed.** There is and will be no alarm per file: an alarm must survive everything the server survives—restart, migration to another machine, restoring a backup—whereas lazy evaluation survives these by construction because it has no state at all, only a comparison of two already stored numbers.

The cost is explicit: the event “occurs” at the first access after its deadline, not at the deadline itself. This is exactly what the heir needs—they make the access; for the log it means the recorded time is when the event was NOTICED, not when it occurred.

**Without a reference point, the event does not occur.** A file whose author the server has never seen is neither opened to an heir nor closed due to silence. The default preserves the status quo when a field is missing: both changes are irreversible, and an absent value must not trigger either direction. Appointing an heir is itself a sign of life, so an appointed heir always has a reference point.

**A timeout shorter than one day is rejected** (`MIN_SILENCE_SECONDS`). This is protection against a typo in units, not a judgment of the author's preferences: “30” instead of “30d” would mean thirty seconds, and the heir would receive the file half a minute after appointment.

**Log events**: `HeirSet` (16), `HeirReleased` (17), `ClosedBySilence` (18). Numbers 11–15 are reserved for quorum. Appointment, mode change, and removal are ONE event: a log entry carries file, device, epoch, and time, with no space for “what exactly”; extending it would change the MAC transcript and notification length, breaking logs already signed by an older build. The file's standing shows what is configured; the log answers “the author changed the heir configuration at this time.” Release and closure, conversely, are separate: “the file passed to the heir” and “the file is closed forever” are opposite answers to “what happened.”

**Closure due to silence is checked during issuance**—after proof of possession and before any limits. After proof because no limit is consumed and no log entry written before it; before limits because a closed file is never issued, and complaining about an exhausted limit where issuance will not happen would name the wrong reason. It is checked during renewal too: revocation by this mode takes effect no later than the next renewal.

**Replaying an intercepted order changes nothing.** Freshness is insufficient: the wire is open, and `SetHeir`, `SetLimits`, and both membership kinds specify STATE, not an increment—someone intercepting an heir appointment could resend it after removal and restore the heir. The server remembers hashes of executed orders for twice the allowed clock skew (exactly as long as an order can possibly be accepted) and SILENTLY skips a replay, changing nothing: rejection would be worse—a client that receives no response retries the request itself.

**Under quorum too—decision of 2026-09-05 following the F-21 review (N-1, N-2).** The first version remembered replays only on the unilateral path where they had been found; the quorum path remembered nothing—an executed proposal was deleted, and the same N intercepted signatures recreated and executed it again. Under quorum, the **intent fingerprint**, not the body, is remembered: signers' bodies differ by construction, while the intent is what resurrects state. The cost is explicit: the same intent legitimately resubmitted within the same ten minutes silently passes as a replay. Replay memory now **survives restart** (server-state tag 22, written only while nonempty): crashing a server costs an adversary less than an author's signature, and a restart within the window used to erase this memory.

**Signs of life under quorum (N-3, N-4).** The AUTHOR's signature on a proposal—whether first or last—dates their presence just like any of their orders (§11.5); a coauthor's signature does not. Appointing an heir does NOT itself date the author's presence: the first version set the mark regardless of who signed, and a membership excluding the author could postpone silence indefinitely by reappointing the same mode. For a file whose author has not yet been seen, appointment supplies only a REFERENCE POINT; otherwise the event would never occur.

**The heir uses the same door as everyone else.** `Collect` returns the bequest when it has been released and is addressed to this fingerprint; before the deadline, it returns the same “no access yet” seen by anyone waiting. The heir need not know of their special status.

The bequest is queried FIRST, ahead of the decision queue. This is number ordering, not a preference: `HEIR_SEQ` is the largest possible number, hence the newest author decision of all. “Newest decision wins” also applies to the ordinary queue—a device once denied may ask again, and the author's second decision must reach it.

**Server state** stores the heir under tag 18 (nested TLV: mode, timeout, fingerprint and bequest for the opening mode, time noticed), and `last_alive` under tag 19. Both are written **only when nonempty**: a server that has never appointed an heir is read by an older build as before. Once touched, it is not readable, with the same caveat as the allowed-authors list.

### 11.6. Explicit boundaries

* **A released bequest cannot be recalled.** The heir already has it—the same property as a delivered share B (§10.9).
* **Silence is measured by the server's clock.** Moving it forward releases the bequest early. Server state is already outside the perimeter—the same cost as revocation.
* **Presence on another server does not count.** A sign of life is recorded where it arrives.
* **Regular `Alive` messages disclose the rhythm of the author's presence to the server.** This is metadata, like everything else on the server (§4).

### 11.7. There can be several heirs—decision of 2026-09-05

Tag 13 carries a STREAM rather than one decision: `u32le length ‖ Decision`, repeated up to sixteen times. A single heir is a one-entry stream, with no special case.

**The tag number is not retired, and this deserves an explanation.** I-7 forbids reusing a number for a DIFFERENT meaning. The meaning here is, and always was, the same—“who receives what after silence”—now expressed more precisely. Retiring the number would be superstition, not caution: no server with an appointed heir has been released, and protocol documents other than leases are not frozen (§0).

**In server state, the number IS retired, correctly so.** Tag 3 inside the heir record carried a single fingerprint; the stream occupies tag 4. The difference from the previous paragraph is that an older build would read a stream under number 3 AS A FINGERPRINT and fail to notice—the first thirty-two bytes of the stream look just as much like a fingerprint as a real one.

The checks are the same for every bequest: same file, `HEIR_SEQ`, approval, share. Two more apply:

* **a repeated fingerprint is rejected**—two decisions for one device would require the server to choose between them, with no basis for choosing;
* **one invalid bequest invalidates the whole list**—accepting a subset would execute an order differently from what the author signed.

EACH signature is verified separately using the author's key: the parser checked the contents (I-9), but does not know the key, and one valid signature in a list says nothing about the others.

**To each their own.** `Collect` gives an heir the decision sealed to THEIR key; someone else's is useless because they cannot open it. Other recipients retain access: inheritance means “one more recipient,” not “a change of owner” (`docs/deferred.md` §18).

**The release event remains one per file, not per heir.** There are as many events as actually occurred, and only one occurred: the author fell silent. The first fingerprint in the list goes into the log entry—not a choice between equals, but the only thing the entry can carry; extending it would change the MAC transcript and notification length. The file's standing shows who is actually appointed.

### 11.7.1. Heir by CODE—decision of 2026-09-05

The author cannot always name an heir by key. A notary, an executor, “whoever comes with this envelope”—these are people whose device the author does not know during their lifetime, but to whom a code can be handed.

**The code derives a KEY PAIR, not a share.** Here the construction diverges from the `RecipientClaim` slot, and must do so. The slot derives share B directly from the code, correctly in that setting: the recipient share may be arbitrary, provided both sides derive the same one. For the heir, the share is FIXED—it is this file's share B, stored in the author slot—and cannot be derived from an arbitrary code: derivation yields what it yields.

The code therefore derives an X25519 private key (derivative K22, label `"CC/v1/claim-device"`, `salt = file_id`), and the bequest is sealed to its public key with ordinary `seal`—the same operation the author uses to seal a share to any device.

**Direct consequence: neither server nor wire changes at all.** No new request kind, field, or branch. To the server, a code-derived fingerprint is just another fingerprint; an heir using a code greets, proves possession, and collects a decision with the same messages as an ordinary device. Neither server nor container format knows about the code; only two parties know—the author and the person to whom the author gave it.

This **corrects a premise of the plan**. F-21 item 9 assumed that a bequest would be sealed under a code “in the same way as the `RecipientClaim` slot,” with the code commitment serving as fingerprint, and inferred a new wire kind `Claim`. The premise is false: the slot seals nothing (`enc` and `nonce` are zero, `ct` is empty), and the method the plan referred to does not exist. No wire kind was therefore introduced.

**`salt = file_id` in key-pair derivation.** The same code issued twice yields different pairs for different files. Otherwise a leaked code would cost every file for which the author reused it—and reuse will happen: codes are given to people, not files.

**The label is separate and must remain separate.** With label `"CC/v1/slot-b-claim"` over the same `ikm`, derivation would produce a private key equal to the slot share: a code opening one file would reveal the key to which another is addressed.

**The command generates the code and accepts no externally supplied one.** `cc heir <file> --code` is written WITHOUT a value; a human-supplied code is rejected with an explanation. The reason is I-4: the commitment can be checked offline, so a code invented “to remember” can be brute-forced without any server request, and a weak code is equivalent to an open file.

**What the construction does not provide.** An issued code can be revoked only by removing the heir entirely (`cc heir --off`) before the event occurs: the container contains no code, so there is nothing to revoke. A leaked code is equivalent to a leaked device key—exactly the cost for which it is accepted: a code can be handed to a person, a device key cannot.

**The code is needed after collection too.** `cc claim` writes THE DECISION ITSELF to disk (`<file_id>.bequest`), not the unwrapped share: the share is secret and does not belong on disk. The derived pair, hence the code, opens the decision each time the file is opened.

**The viewer also accepts the code—decision of 2026-09-05, closing a hole older than heirs.** Previously only `cc unprotect` accepted codes, and that is an EXPORT path: it writes plaintext to disk and asks the policy for export permission. Nobody could open a view-only file addressed by code—neither a recipient using the `RecipientClaim` slot nor an heir using a code.

The “no access yet” window offers a code field wherever the share is still absent (including an author's denial: the author may have denied the heir as a device). The code is checked through three doors in increasing cost order: slot commitment; bequest on disk; bequest from the server—with the same handshake as a device. The window reports the server's “not yet” response in words and does NOT distinguish “wrong code” from “deadline not reached”: that distinction would be an oracle for “this code belongs to this file.”

The code travels to a new viewer process **through stdin** (`ccview <file> --code-stdin`), and only that way. As an argument it would be visible in the process list; as an environment variable, in any descendant's environment snapshot; as a file, on disk. The flag deliberately has no value. The viewer and `cc unprotect` use the same door order to obtain the share—the library's `granted::share_for`—because two copies of one ordering drift toward “allowed.”

**The heir obtains a license using THEIR OWN device, and the file's rules apply in full** (F-21 review, R-2, stated as a boundary). The code supplies share B; the server supplies share A and the license through ordinary activation of the heir's device, just as for any recipient. Thus the approver quorum, device limit, and closure due to silence also apply: approvers must vote for the heir's MACHINE fingerprint, unknown to the author at appointment (visible in the server log as “issuance held for quorum”). In this case the window says “license not obtained” and leaves a retry button; a code cannot bypass quorum, and that is not unfinished work—otherwise it would bypass the two-person rule.

**Opening a second time leads to the same window** (F-21 review, R-1, fixed the same day). After the first opening, the license and server share are cached, and the session took the cache branch: no code, no device slot—and the person received an exit code in a console that double-clicking does not provide. Now “license present, share absent, no code supplied” is the `NeedsCode` state: the window opens with a code field. A bequest stored on disk leads there as well.

**Device denial does not hide a code-based bequest** (F-21 review, finding N-1, fixed the same day). An author's denial is cached with requests just like an approval, and the first `share_for` stopped at the first device response—including denial. An heir denied as a device during the author's life but later given a code-based bequest could not open the document—precisely the scenario promised here. Now the device door yields a share only on approval; denial there means “check the bequest,” not “no share.” Test: `crates/cc-cli/tests/share_doors.rs`.

**Residuals identified by review and deliberately retained.** The window's code field is `egui::TextEdit`, whose undo history keeps copies of typed text until process exit; `Zeroizing` does not cover them, and `.password(true)` masking affects rendering only. The code string read by the new process from stdin remains in the process's standard-input buffer. Both residuals reside in a process already holding the document plaintext and are mitigated by a wiping allocator for freed blocks. There is one `.bequest` file per `file_id`: two codes for one file on one machine overwrite each other; opening with the first requires the server again.

### 11.11. Ordering between orders—decision of 2026-09-06

Signature and freshness are checked for EVERY order, but nothing checked the order BETWEEN them: `order.at` was used for freshness and replay memory, yet never compared with already applied state. Replay memory remembers the BODY HASH and rejects the same bytes; it does not know about an order INTERCEPTED and not delivered, which rolled state backward when delivered after a newer order.

**One rule for every kind.** An order OLDER than the last accepted command of the same kind changes nothing—silently, with neither event nor rejection, like any replay.

**A command EXECUTED WITHOUT REJECTION raises the barrier**—including one that changed nothing: confirming the existing state raises it just as a change does; otherwise the door remains open to a withheld command (found for freezing, §11.9). A command rejected by validation does NOT raise it. Previously the mark was set before handling cases, and an author's own typo (invalid proposal timeout) locked out their valid order signed a minute earlier: it passed silently, the author saw success, yet the membership was not installed.

**The check is AT THE DOOR, not at execution.** Under coauthor quorum, a proposal is identified by INTENT, and execution is triggered by whichever signature completes quorum—whose timestamp is always fresh. A barrier at execution let the entire quorum path through: a withheld author signature entered the collection without objection, an honest fresh coauthor signature completed quorum, and a decision the author had later canceled returned THROUGH THE SECOND PERSON'S HANDS. This violates the two-person rule: the command carries a signature the author has repudiated. S-1 in the F-21 review had the same shape—replay memory existed on the unilateral path but not the quorum path; a second finding at the same boundary.

**Execution CLEARS the collection for its kind.** Checking at the door is insufficient: the author's proposal signature is honest and fresh at its own time and legitimately enters the collection, but a command of the same kind executed later makes it obsolete—a subsequently submitted coauthor signature would complete quorum for something already canceled. The reasoning is the same as discarding proposals from the previous coauthor membership when that membership changes: they were collected for a state of affairs that no longer exists.

**Per KIND, not per entire file.** Kinds are independent and arrive interleaved; a shared barrier would lock out membership signed before neighboring limits. Server-state tag 25 stores repeated `kind(1) ‖ i64le time`, and is written only when nonempty.

**An approver vote has its own barrier**, per “device, approver” pair, stored as the signed timestamp in the vote record (81 bytes instead of 73; the 73-byte form is read as before, taking its signed timestamp as the receipt time PLUS the allowed clock skew—the upper bound of anything that could have been accepted at that moment. It cannot be taken as equal to receipt time: skew is allowed in both directions, and an approver's clock may lead the server's, which would place the barrier below the real value. The cost is explicit: an honest vote signed within the same five minutes after starting on the new build silently passes and requires a retry). Without this, a withheld “yes” delivered after withdrawal restored access FOREVER: votes do not expire.

**Equal seconds are resolved by kind, with opposite outcomes.** For a vote, DENIAL wins: the server cannot distinguish “replay” from “changed their mind within the same second,” and the safe direction here is not to issue (I-10); repeating “yes” within the same second costs the approver nothing. For thawing, THAWING wins, for the opposite reason: the server responds “done,” and “freezing wins” would show the author success while the freeze remained (§11.9).

For the five state kinds—revocation, heir, limits, both memberships—equality passes, and whichever is DELIVERED LATER wins. These bodies are DIFFERENT: two distinct author commands signed within one second, not a replay of one, with no basis for choosing a “safe” one—memberships and limits have no direction of tightening; a lower limit is stricter for the recipient and weaker for the author. The cost is the same one-second window as thawing, and the adversary controls it only within what the author actually signed that second. It does not affect revocation: revocation is irreversible, and no order can restore a revoked file.

**An order sequence number was rejected.** It would require a new `order.rs` registry tag and a change to `docs/format.md`, hence a format decision. The signed-time rule does not touch the wire at all.

**The attack window is narrower than it looks.** Freshness requires delivery within ±300 s of the signed timestamp: the author or approver must change their mind within the same five minutes. That is what real cancellations look like—“clicked, then realized.”

### 11.10. The SERVER enforces the author's window—decision of 2026-09-06

`issue()` refuses outside `Validity::Window`: `Denied::NotYetValid { starts_at }` before the start, `Denied::Expired { ended_at }` after the end. This sits beside revocation and freezing for the same reason: a closed file is never issued, and citing limits where issuance will not happen would give the wrong reason. Renewal checks it too, so a window ending mid-session closes the document at the next renewal (F-18).

**Why, if the client already checks the window.** Because before this decision, the author's “not before nine on Monday morning” was enforced by ONE evaluator on the recipient's machine—using a clock the recipient can change. The server, whose clock the recipient cannot access, knew nothing of the window and would issue a license with the second half of the key even a month early. Under the ideas collection's end-to-end principle, that made an embargo **client friction**, not a **server guarantee**; for a file distributed before a premiere, the difference is decisive: a patched client could open it whenever it wanted.

**The server does not and cannot check `FromFirstOpen`.** Its period starts at an event on the recipient's machine that the server does not see: opening happens without it. The server cannot judge that event, and a precautionary ban would close the file forever. The client enforces this, a substantive distinction rather than unfinished work.

**What this still does not provide.** Already issued material cannot be recalled—a format property. A recipient who acquired the share within the window retains it after `not_after`; the client and the server's renewal refusal enforce closure. The refusal gives the timestamp in epoch seconds: the client presents it to the person, not the wire.

**The server address is “host:port,” without a scheme.** The address goes directly into `connect`, which does not understand schemes: `http://host:port` is read as an entire hostname and produces “this host is unknown” even with a live server. It is rejected by `servers::check_address`—the same gate used by `--url` in `cc protect`, remembering an address against an author key, and reading the store. Before the fix, a failed command could save a broken address over a working one; renewal and subscription then fell silent, so revocation stopped arriving quickly (media-pilot review, 2026-09-06).

### 11.9. Panic button—decision of 2026-09-05

The `Freeze` order (kind 9): stop issuance for **all files belonging to the key** in one action—or resume it. Tag 16 `FROZEN` (`u8`: 1 freeze, 0 lift) is required; `file_id` **must be zero**, and the signer's key is in tag 14, as for a sign of life: an incident is a property of the author, not a document, and stopping documents one by one would give the adversary time. Freezing one file is revocation, with its own kind.

**What stops.** `issue()` returns `Denied::Frozen` immediately after the revocation check, for the same reason: a closed file is never issued, and complaining about limits or quorum where issuance will not happen would name the wrong reason. Renewal checks it too: an open document closes at the next renewal (F-18), no later than the offline window. Author decisions (`Collect`) are not stopped: share B is useless without share A, and freezing controls issuance of A.

**A new file INHERITS panic.** Freezing is an author property stored on the file: otherwise there would be nowhere for the change timestamp to survive restart. This caused a gap—a registration-created record was unfrozen, so a document packaged AFTER panic could be issued while everything else was stopped. The error points in an unsafe direction: the author clicked “stop everything,” received confirmation, and the very next packaged document went to recipients—with no way for the author to discover this, because each file's individual standing told the truth. Registration takes both state and TIMESTAMP from other files belonging to the same key. The timestamp matters because otherwise a thaw signed before this registration would not thaw the new file: its barrier would be below that thaw, leaving the file frozen forever. Found during assessment on 2026-09-06.

**What freezing does not do.** It neither recalls issued material nor increments the epoch: it is reversible, while revocation is not. Only `Revoke` closes permanently.

**It deliberately bypasses quorum.** Freezing is the safe direction (I-10), and delaying it for coauthor signatures would give the adversary time they must not have. Thawing restores only what the author unilaterally stopped; it does not bypass the two-person rule, which concerns file administration, not the author's presence.

**Replaying an intercepted thaw does not unfreeze.** Directions are ordered by the AUTHOR'S CLOCK: the file stores the timestamp of the last ACCEPTED freeze command (`frozen_at`), and an order OLDER than it changes nothing—with no event or rejection, like any replay. Otherwise an intercepted `--off` could lift a freeze at any point within the freshness window—precisely when the author had just set it. Confirming an existing state raises the timestamp as well, not just a change: if only changes raised it, a withheld thaw would pass after a repeated freeze (external review, 2026-09-06, corrected that day). Equal seconds pass: the author may change their mind within one second, and the one-second replay window is an explicit cost; a thaw signed in the same second as the previous one is byte-for-byte identical, so the server cannot distinguish them by construction. The timestamp survives restart (server-state tags 23 and 24).

**Log:** `Frozen` (20) and `Thawed` (21)—one entry per file belonging to the key, not one per author: the log is per-file, and a reader subscribed to one file must see what happened to it. Only changes are recorded.

**File standing** carries tag 17 `frozen` only when true. A sign of life is recorded: the author has just spoken.

Command: `cc panic [<file.cc>] [--url] [--off]`; in the desktop interface, a two-click button on the “Server” tab.

### 11.8. Proposal timeout is a file setting—decision of 2026-09-05

Tag 15 of `SetCoauthors`: how long a proposal that lacks enough signatures lives. Optional; absence means “server default”—**three days**—not zero. Zero is rejected: the timeout may be changed but not removed, otherwise a proposal would accumulate forever and surface a month later when no longer relevant.

The lower bound is one day, the same as for silence and for the same reason: a typo in units. “3” instead of “3d” would mean three seconds.

A membership change WITHOUT a specified timeout retains the previous one instead of resetting the default: changing membership and changing timeout are different intents.

**An expired proposal is neither displayed nor retained by clock-aware saving** (F-21 review, N-5). Cleanup previously happened only upon a new signature; file standing and the state file knew no clock, so the author's desktop showed a proposal that had expired weeks ago as live. Now `Standing` filters by the file timeout, and saving with the server clock removes expired proposals before assembling bytes. There is no “proposal expired” refusal, nor was one ever reachable: the expired proposal is removed, and a late signature creates a new one—it is its first signature, accurately reflecting the situation.

**At most 64 incomplete proposals per file** (N-6). The intent fingerprint zeroes only the timestamp and key, so `SetLimits` with different limits yields 2³² different intents; one coauthor key could fill state, memory, and every `Standing` response without bound, whereas votes had a limit. The limit applies to new proposals; a signature on an existing one passes even when the table is full, otherwise a full table would lock out quorum.

APPROVER membership has no timeout and cannot have one: approvers have no proposals, so there is nothing to expire. A vote remains effective until withdrawn.

## 12. Quorum: approvers and coauthors—decision of 2026-09-04

There are **two** quorums, enforcing different things. Approvers control OPENING: the server does not release share A until M of N votes are collected. Coauthors control ADMINISTRATION: revocation, limits, memberships, and heir changes execute after M signatures from the membership. Neither touches the key scheme—there are still two shares, and `KEK = HKDF(A‖B)` is unchanged.

### 12.1. Kind, tag, and event registry

Order kinds (in `kind`, in addition to §11.2):

| Number | Kind | Effect |
|---|---|---|
| 3 | `SetLimits` | change device and issuance limits for a reserved file |
| 4 | `SetCoauthors` | configure coauthor membership and signature threshold |
| 5 | `SetApprovers` | configure approver membership and vote threshold |
| 6 | `ApproveDevice` | an approver's vote for a specific device |
| 10 | `ReplaceDevice` | replace a lost device with a new one (F-26, 2026-09-15) |
| 11 | `SetRule` | set the entire file rule based on holder attributes (F-27, B4b, 2026-09-16; §13.5) |
| 12 | `WatchAuthor` | subscription proof for the “author's files” scope; NOT a command, not executed through the `Order` door (B5, 2026-09-16; §9.9) |

Body tags (in addition to §11.2):

| Tag | Name | Type | Applicable kinds |
|---|---|---|---|
| 7 | `keys` | bytes, 32·n, `n ≤ 16` | required for `SetCoauthors`/`SetApprovers`, forbidden otherwise |
| 8 | `threshold` | `u8` | same; `0` with empty membership means “no quorum” |
| 9 | `device_fpr` | bytes, exactly 32 | required for `ApproveDevice`, forbidden otherwise |
| 10 | `approve` | `u8` (0 or 1) | same |
| 17 | `old_devices` | bytes, 32·n, `1 ≤ n ≤ 4` | required for `ReplaceDevice`, forbidden otherwise |
| 18 | `new_devices` | bytes, 32·n, `1 ≤ n ≤ 4` | same |
| 19 | `rule` | file rule, layout in §13.5 | required for `SetRule`, forbidden otherwise |
| 20 | `authority_key` | bytes, exactly 32—the addressee's lease-signing key | required for `WatchAuthor`, forbidden otherwise; this kind has zero `file_id` and requires `signer_key` |

### 12.2. Replacing a lost device—`ReplaceDevice` (kind 10, F-26)

**Who is authorized.** Only the file's author, through the same §9.3 door as revocation, limits, and membership; for a file with pinned coauthor membership, through that membership's quorum. Access codes and claim codes do NOT confer replacement authority: a code holder holds one issuance, not the power to displace someone else's place. A person verifies the identities—the same K27 fingerprints printed by `cc ask` for the requester and `cc keygen` on the device; the server neither guesses them nor obtains them from the network.

**Why several identities.** One device has up to four—X25519, X-Wing, P-256 in TPM, hardware hybrid—and a replacement naming only one would leave the others active. Both old and new devices are therefore named by a LIST of identities (1…4), with no identity appearing on both sides.

**What the server does in one state write** (file storage—one rename; SQL—one transaction):

* removes the old device's identities from activated devices;
* REMEMBERS them as replaced: no new issuance or renewal for them, even after restart and even when space is free. Removal alone would be insufficient—the old device could occupy the freed place through ordinary activation;
* reserves ONE place in the device limit for the new device's identity group. Without reservation, replacement would mean “free it and hope”: whoever arrived first would occupy the place. The first activation under any group identity consumes the reservation.

**What replacement does NOT do.** It does not change the ISSUANCE limit: a device place is freed, not an issuance, and the new device consumes an issuance like any other (if the file has exhausted its limit, the author raises it with `SetLimits`). It does not revoke plaintext or offline leases already received by the previous device—the threat-model boundary is the same as revocation (`docs/threat-model.md` §3, §3.1). It does not supply share B to the new device: that device obtains it like any other—through a code, request approval, or its own slot.

**Rejection reasons:** the old device is not associated with the file; the new identity is already occupied, replaced, or reserved; the file is revoked; the signature is not the author's (or a membership member's). Repeating the SAME bytes receives the response identified by operation identity (`docs/managed-store-contract.md` §5.4), not a second replacement; a new order for the same old device after successful replacement is rejected as “device is not associated with the file.” Log: `DeviceReplaced` (first old identity) and `DeviceReserved` (first new identity).

**Command:** `cc replace-device <file.cc> --old <fingerprint>… --new <fingerprint>…
[--url address]`. Test: `crates/cc-authority/tests/device_replacement.rs` on both stores.

**Tag 14 changed its name but not its number:** `author_key` → `signer_key`, “the key that verifies the signature when it cannot be obtained from the file.” It originated for a sign of life covering all files at once; the approver vote revealed a broader meaning—the signer is a membership member, not the author, and their key cannot be obtained from the file either. `author_key` would have become a lie presented as truth: it would contain someone else's key. I-7 forbids reusing numbers for a DIFFERENT meaning; here the meaning is, and always was, unchanged.

Message kinds: **26 `Endorse`** (`signer's key(32) ‖ signed
order`), **28 `Endorsed{have, need}`** (two bytes). The signer's key travels alongside instead of being found by iterating membership: iteration would let an intermediary burden the server with sixteen signature verifications per message.

Log events: **11 `CoauthorsSet`, 12 `ApproversSet`, 13 `DeviceApproved`, 14 `IssueHeldForQuorum`, 15 `LimitsChanged`, 19 `ProposalEndorsed`.**

### 12.2. Membership rules

Membership contains at most **sixteen** keys: the same as server addresses in the header and requests in the queue, for the same reason—a quantity a person can review by eye.

* **Duplicate keys are rejected.** One vote would count as two, making “two of three” executable with one signature.
* **The threshold must be achievable by the membership** (`1 ≤ M ≤ n`). A threshold above the key count is a rule nobody can ever satisfy: the file freezes forever, and its being frozen would be the only way to notice.
* **Empty membership with a zero threshold is valid** and means “no quorum.” There must be a way to remove quorum, with no reason for a separate kind.
* **Membership is checked WHEN COUNTING, not only on receipt.** A person may have been removed after voting or signing, and their vote must no longer count—otherwise removal would not take effect until everyone else voted again. Votes themselves are not erased: membership may be restored, and the server has no right to erase someone else's expressed intent.
* **The same rules apply when parsing `Standing` (2026-09-20).** The responding side constructs file standing, and “quorum nobody can ever achieve” is as easy to construct from bytes as an honest standing. Also rejected is everything the writer never writes: empty membership, threshold without membership or membership without threshold, zero proposal timeout, empty vote and proposal streams, `frozen = 0`. An unfrozen standing remains valid—it is represented by ABSENCE of tag 17, as before; only a second representation of the same meaning, produced by nobody, is rejected.

### 12.3. Approvers: quorum for opening

Votes are stored by **“device, voter”** pair. With the device alone as key, a second vote would overwrite the first, and one person voting twice could reach the threshold. A vote is effective until withdrawn (`approve = 0`); it has no expiry.

The check occurs during issuance—after proof of device-key possession and before any limits. After proof because no limit is consumed and no log entry written before it; before limits because a file blocked by quorum is never issued, and complaining about an exhausted limit where issuance will not happen would name the wrong reason.

**RENEWAL checks it too.** Otherwise withdrawing a vote would have no effect: an issued lease would renew forever. This way the document closes after the renewal interval (F-18)—issued material cannot be taken back, but renewal stops.

The refusal carries the COUNT (`QuorumPending{have, need}`): a person reads “one of two” as “waiting for one more,” but a bare “denied” as “go away.” The hold is logged: it is a FILE event, and the author must see that someone is knocking and waiting.

The vote table has a ceiling of **64 devices per file**, counted by DISTINCT devices: revoting does not consume another place. Anyone may name a fingerprint, and without a ceiling this is a queue that can be filled for free.

**Approvers do not release share B.** It exists only in the `AuthorDevice` slot, and only the author can seal it to another device. Approvers may HOLD opening, but cannot open access.

### 12.4. Coauthors: quorum for administration

**A proposal is identified by its COMMAND, not its body.** This is a foundational decision, and the first version was wrong.

Coauthors sign from their own machines: each enters the same command, and their client sets its own issue timestamp and signature. The bodies therefore ALWAYS differ. If the server identified proposals by body hash, two people entering one command in different seconds would create two proposals, and quorum could never be reached.

The intent fingerprint (`order::intent_digest`) is computed with the same encoder as the body, but with `at` zeroed and `signer_key` removed. The file, kind, and all parameters must match; who said it and when belong to the signature, not the intent. A second serializer solely for hashing would be a second definition of “the same order,” diverging at the first new line.

**Bodies are not stored on the server.** Each signature is verified when submitted, over its own bytes; the order that brings the count to the threshold is the one executed.

This also determines the command form: people sign their own command, not someone else's document. Signing someone else's bytes means signing what one was shown; entering a command means signing what one said oneself. The server, not the eye, checks equality.

Other rules:

* **The first signature creates a proposal.** The author issues the first `SetCoauthors` unilaterally—there is nobody yet with whom to form quorum; all subsequent ones require quorum of the previous membership.
* **The author is not implicitly a member.** The list fully enumerates whose signatures count. A list omitting one's own key means “I am no longer entitled to administer this file”; the command rejects such a list and requires an explicit statement (`--without-me`). The same rule applies to membership placed in the header during packaging (`cc protect --coauthor … --coauthors-threshold M`); the SDK and WASM wrapper have no `--without-me` expression and reject membership without the author.
* **Membership from the signed header is pinned during wire registration** (`register_by_order`, tag `0x8001`): initial membership comes from the header, not the first order; subsequent changes require that membership's quorum. A zero threshold in the tag (“there will be no coauthors”) is pinned too—unilateral coauthor assignment for that file is rejected. Re-registering the same file does not restore header membership: what quorum changed stays changed. A file without the tag follows the previous path: the author issues the first `SetCoauthors` unilaterally. Test: `crates/cc-authority/tests/coauthors_header.rs` on file storage and SQL.
* **Changing membership discards proposals from the previous membership.** Otherwise a departed member's signature would remain in the collection, and the new threshold would count old signatures.
* **An executed proposal is removed immediately**, not upon timeout: leaving it would let a repeated signature execute the order again.
* **Proposal lifetime defaults to three days; the author can set their own** (§11.8, decision of 2026-09-05; this previously said “seven days”—the pre-decision version). This is not an estimate of coauthor promptness, but a period after which a document stops meaning what it meant: limits, membership, and heirs can become outdated.
* **Revocation with coauthors responds with `Endorsed`, not `Accepted`.** Saying “done” about a proposal would leave the person believing the file had been revoked while it remained open. Delivered share B cannot be recalled here either—a format property.

### 12.5. Explicit boundaries

* **The server counts, and only its state attests to the count.** Server–recipient collusion bypasses both quorums—the same 2-of-2 boundary as everywhere else, nothing new. For an honest server, quorum produces log events visible through subscription.
* **Membership lives on the server.** Whoever controls the server can rewrite it. The anchor will move into the signed header with version 3 tag `0x8001` (`docs/format.md`); until implementation, the cost is stated here.
* **Quorum does not protect against the author.** It protects against one compromised key among several—and only while those keys are not held by one person.

## 13. Server-side attributes—decision of 2026-09-10 (F-27)

The server maintains an **attribute vocabulary**, **device holdings**, and a **file rule**, using them to decide lease ISSUANCE: to whom and for how long. The wire is unaffected: the `Activate`/`Renew` frames and share are unchanged, and attributes do not change the lease; refusal is sent as text like any server refusal, naming the missing attribute's NAME—not values, so as not to tell the recipient what to request.

This previously said “the lease is unchanged (§2.3 is frozen).” Leases have since acquired version 2 (§2.3), and attributes use it: a file rule supports not just ADMISSION but also **action tightening by holding** (§13.2, B4b), carried in the same lease field as the server's strict profile. Attributes introduced no new wire field.

### 13.1. What lives where

| Item | Location | Set by |
|---|---|---|
| vocabulary: name → values in rank order | server state, `VOCABULARY` section | operator, `cca attr define` |
| holdings: fingerprint → attribute → value → expiry | `HOLDINGS` section | operator, `cca attr assign` / `withdraw` |
| file rule: conditions and lease-duration ceiling | file record, `REQUIREMENT` tag | operator, `cca attr require <file.cc>` |
| tightening by holding: exemption condition and profile | same record, nested `R_TIGHTENINGS` tag | operator, `cca attr limit <file.cc>` |
| strict server profile (not an attribute; one per server, §2.3) | server state, `SERVER_POLICY` section | operator, `cca policy set` |

Holdings are bound to the **device fingerprint**, not the file: a holding concerns the person behind the device and applies to every file whose rule asks for it. “Who is behind the fingerprint” is verified through the author's address book (`cc verified --name`), as everywhere else.

**Who defines the meaning.** A URI alone creates no trust: `dept=legal` means something only because someone is responsible for the list of those assigned it. That party is whoever controls the server directory: the same trust as `cca register`, `cca revoke`, and `cca author add`. For a solo author, that is the author; for a hosted server, the operator, with the boundary between them addressed by F-31 and F-29.

**Who sets what—B4b decision (2026-09-16).** Vocabulary and holdings concern the ORGANIZATION; a rule concerns the FILE, and their doors differ:

* the **file rule** is set by the file owner through a signed `SetRule` order (§13.5), using the same door as limits: the author's signature or coauthor quorum. The operator can still set it using `cca attr require`/`limit`—the same server-directory access as `cca revoke`;
* **vocabulary and holdings** are set only by the operator, using logged `cca attr` commands. There is no signed path for them, deliberately: one author's signature changing holdings would change access to OTHER authors' files on the same server. An organization key would carry that authority, but the product has none (F-29, F-31; `docs/deferred.md` §6.3).

Isolation is enforced at the door: a rule order is verified with the key pinned to THIS file, and one file's author cannot close, open, or restrict another (`crates/cc-authority/tests/attributes.rs`, `stand_attributes.rs`).

### 13.2. The rule

A rule is a list of conditions joined by “and,” plus an optional lease-duration ceiling. A condition consists of an attribute, mode, and values:

| Mode | Meaning | Command syntax |
|---|---|---|
| `AnyOf` | the device holds at least one of the values | `name=a\|b` |
| `AllOf` | holds every listed value | `name=a&b` |
| `AtLeast` | holds a value ranked no lower than the specified value, according to vocabulary order | `name>=a` |

A holding is effective while `now < until`; at `until` itself it is no longer effective. An empty rule means no rule: the file is issued as before this section. The duration ceiling is applied as the **minimum** with the duration authorized by the author: the server tightens, never expands (§5).

**Tightening by holding** (B4b, 2026-09-16) is the second part of the rule: an exemption condition and a profile, which is an ordinary policy. Issuance for anyone who does NOT satisfy the condition is narrowed by this profile; those satisfying it are exempt. Multiple tightenings combine by intersection; their recorded order does not affect the result. The result intersects with the strict server profile and reaches the recipient in the version 2 lease's `server_policy` field (§2.3); the client combines it with author policy itself. A client refusal identifies the server, not the author, as the cause (`ActionTightenedByServer`).

The condition describes those EXEMPTED, not those restricted, deliberately choosing the direction of error: holdings can be lost (withdrawal, expiry, state edits), and a lost holding in this representation means “restricted,” not “exempted” (I-10). The command rejects a profile that narrows nothing—it is a typo, not a rule.

**A lease does not outlive the holding on which it was issued.** Issuance duration is cut to the point when the decision stops being valid: expiry of the holding that passed the gate or exempted the device from tightening. For “any of,” the basis is the longest matching holding; for “all,” the shortest; for “at least,” the longest sufficient holding. The lease ends one second before the holding: a holding expires exclusively (`now < until`), a lease inclusively (`now > expires_at` means rejection), so equal deadlines would leave a second during which renewal is already refused but the file still opens. A tightening condition the device does NOT pass sets no expiry: a holding acquired later would only expand rights, which can wait for renewal.

**The vocabulary is law.** Only vocabulary-defined attributes and values may be held or required; unknown ones cause command rejection, not a new word (I-10). A defined attribute cannot silently be redefined or removed while a holding or rule refers to it. When state is loaded, the vocabulary is constructed using the same `define`, and holdings are checked against it: editing the state file cannot introduce an attribute around the command and log.

### 13.3. Where checks occur

In `issue`—**before quorum and limits**, and **during renewal too**. Before quorum because an approver's vote concerns the device while the rule concerns who is behind it; someone without a contract should not have to collect votes to learn they have no contract. Before limits so that refusal names the real reason. During renewal because the rule concerns who the device is NOW: a contract withdrawn while a document is open closes it at the next renewal (§5.1, F-18), while a contract expiring by time closes it even without renewal—the lease does not outlive the holding (§13.2).

Renewal with tightening also invalidates the same device's previous, broader lease: a client that has seen a higher number rejects a lower one as rollback (§3, F-8). Only a lease on a device that did NOT renew lives out its term.

Log events (§7): `AttributesRefused = 22` (file, device), `AttributeRuleSet = 23` (file), `AttributeAssigned = 24` and `AttributeWithdrawn = 25` (device; no file—sixteen zeros, `cca journal --list` prints “file —”). The `tests/kat/journal.kat` vector holds entries of previous kinds and is unchanged.

### 13.4. What this section does NOT provide

* **Attribute-based expansion of rights.** “Lawyers may also print” cannot and will not be expressible: the upper bound is the author's signed file policy, and tightening by holding only narrows it (§13.2). This previously said “no attribute-based action tightening”—it arrived with lease version 2 (B4b).
* **Attributes in the file.** They are deliberately absent (`docs/strategy.md`, “ABAC—on the authority side”): file policy is signed by the author and enforced offline.
* **Proof of possession for a holding.** A holding is assigned by fingerprint; whoever assigns it, not the server, knows that the intended person stands behind that fingerprint.

### 13.5. The rule on the wire—`SetRule` (kind 11, B4b)

The rule travels as the value of author-order tag 19. One codec serves both wire and state file (`oc_protocol::attribute_rule`); the bytes match what storage wrote before B4b, so older state files are read without changes.

TLV, increasing tag order, all critical:

| Tag | Field | Value |
|---|---|---|
| 1 | `max_lease` | `i64le` seconds, `> 0`; optional |
| 2 | `clauses` | condition stream; ALWAYS written, including when empty |
| 3 | `tightenings` | stream of `[condition, profile]` pairs, `1..=8`; only when present |

A stream is consecutive `u32le length ‖ bytes`. A condition is `u8 mode ‖ stream [attribute,
value…]`, mode 1 `AnyOf`, 2 `AllOf`, 3 `AtLeast`. A profile uses the format's §4 policy codec. Parsing itself rejects: a name or value that is not an identifier (Latin letters, digits, `_ . : / -`, up to 64 bytes); a condition without values; “at least” without exactly one value; an unknown mode; more than 16 conditions, 64 values, or 8 tightenings; a nonpositive ceiling; an empty tightening stream; absence of the condition stream. The server checks rule terms against the vocabulary: mismatch returns `RuleRejected` with a reason, leaving the rule unchanged.

**The order specifies the ENTIRE rule.** Not a modification to the previous one: signed state, not an increment—the server recognizes repeated identical bytes (§11.11, replay memory), and two consecutive edits cannot combine into a third rule nobody signed. An empty rule removes the previous one.

**Command:** `cc rule <file.cc> [<condition>…] [--lease <deadline>] [--unless
<condition> --allow <actions>]… [--url address]` and `cc rule <file.cc> --clear`. Condition parsing (`name=a|b`, `name=a&b`, `name>=a`) and the profile baseline (`Policy::no_tightening`) are shared with `cca`: coauthors entering the same command on different machines must obtain byte-for-byte identical intent. Tightening from `cc rule` narrows ACTIONS only; the operator controls other profile settings (`cca attr limit`).

Log: the same `AttributeRuleSet = 23` as the operator command.

## 14. Agent Protocol: agent grant, delegation, chain—decision of 2026-09-21

The design, stage boundaries, and complete model are in `docs/agent-protocol/stage-1-door.md`; this section covers only what travels over the wire and what the server checks. The `AgentGrant` and `Delegation` documents are in `oc_protocol::agent`; their domain labels are in `docs/format.md` §3.6 (`CC/v1/agent-grant`, `CC/v1/delegation`).

Who talks to whom: the AUTHOR deposits a subtree grant (`cc agent grant`), the parent door deposits a delegation link, and the HOLDER collects the chain under their proven identity. The author revokes the grant by an order.

### 14.1. Kind, tag, and event registry

Message kinds:

| Number | Request | Response |
|---|---|---|
| 51 | `PutGrant`—complete grant bytes (`signature(64) ‖ body`) | 54 `ChainStored` (no body) |
| 52 | `PutDelegation`—complete link bytes | 54 `ChainStored` |
| 53 | `FetchChain`—`holder fingerprint(32)` | 55 `Chain`—document stream; 56 `NoChain` (no body) |

The `Chain` body is consecutive `u32le length ‖ document`, always the grant first, then links in order from the root. The layout is written ONCE, in `oc_protocol::activation::join_chain` / `split_chain`; neither side may assemble it by hand. Ceilings are checked during assembly and receipt: at most `MAX_CHAIN_DOCUMENTS` (`1 + MAX_GRANT_DEPTH`) documents, each nonempty and no longer than `MAX_DOCUMENT`; truncation within a record and trailing data after the last record mean rejection, not “almost correct.”

Three numbers instead of one “Agent Protocol document” with an inner kind: the grant and link use DIFFERENT verification keys—the author and parent door—and the server must select the key before parsing the body. A common number would require parsing the body to learn how to verify it, hence parsing unauthenticated bytes (I-5).

Order kinds (in `kind`, in addition to §11.2 and §12.1):

| Number | Kind | Effect |
|---|---|---|
| 13 | `RevokeGrant` | revoke an agent grant: no further issuance anywhere along the chain |

Body tags (in addition to §11.2 and §12.1):

| Tag | Name | Type | Applicable kinds |
|---|---|---|---|
| 21 | `grant_id` | bytes, exactly 16 | required for `RevokeGrant`, forbidden otherwise; this kind has zero `file_id` and requires `signer_key` |

The field set follows the panic button (§11.9): it concerns a grant, not a file. A grant covers a SUBTREE, and revoking it is one order, not N for the number of files; per-file revocation would leave half the chain alive precisely when the author wants it extinguished. `RevokeGrant` travels as an ordinary `Request::Order`.

Log events (§7): `AgentGrantRegistered = 29` (DOOR fingerprint), `DelegationRegistered = 30` (DESCENDANT fingerprint), `AgentGrantRevoked = 31`.

All three are written PER FILE in the document, not as one entry. A log entry carries exactly one `file_id` (its layout is frozen by the MAC transcript), and one entry naming the first file would be deceptive: an author reading the second file's log would not see that the door received it too. This log does have fileless entries (attribute holdings, §13), but they are unsuitable here for the same reason: subscriptions are PER FILE, and a fileless event reaches no subscriber. The cost is explicit: a grant for 256 files writes 256 entries—exactly the number of files the door received.

The third event was not in the plan and was introduced during implementation: without it the log would lie by omission—recording the grant but not its end.

### 14.2. Who proves what

`PutGrant` and `PutDelegation` **do not require** proof of device-key possession, and have no basis for requiring it: a grant is signed with the AUTHOR's key, which the device does not possess at all, and a link with the parent's `door_verify` key, named in the grant under the author's signature. The signature is all that matters; an intermediary delivering the document cannot substitute anything in it. This is the same rule as author decisions (§10) and orders (§9.3).

Both are idempotent by document identity: the same bytes a second time yield the same `ChainStored` response; different bytes under the same `grant_id` are rejected.

`FetchChain` was NOT added to `is_session_sealed` (it does not need a session MAC), but requires `session.proven`: the server compares the named fingerprint with the proven one in constant time, as with `Collect` (§11.7.1). The holder fingerprint is public in the grant, and anyone may name someone else's; links, however, contain shares B sealed to the holder key, and handing them to an outsider would supply material they could retain until the day they acquired the door key.

`NoChain` is not a refusal: not holding a grant is no offense.

### 14.3. What the server checks

When receiving a grant: every `file_id` is registered; ALL files have one author (otherwise one signature would cover someone else's files); the signature verifies with that author's key recorded at registration; `verify_grant_chain` with no links, using the server clock; share B is no weaker than the file (`WeakerThanFile`)—the same E2/B8 rule as decisions and bequests: the holder retains the share forever, and classical delivery for a post-quantum file would weaken the file itself.

When receiving a link: locate the parent chain by `parent_fpr`; run `verify_grant_chain` with the new link; a revoked grant accepts no links; apply the same share-strength check.

**One fingerprint—one chain.** A door already in a chain receives no second grant: otherwise “whose chain belongs to this holder” would have no unique answer, yet the activation gates ask exactly that. Revocation extinguishes the ROOT, not links—a holder's chain always starts with a grant—and only the key under which the grant is recorded may revoke it. Otherwise one file's author could revoke others' grants merely by knowing their identifiers, which are not secret: they appear in the grants themselves.

**Issuance gates.** Share A is opened and resealed in one place—`Authority::issue`—and the gates stand THERE, after proof of possession and before the first log entry. Activation and renewal, both wire protocols, and the operator command `cca activate` therefore pass them. The only bypass path is replay of a recorded operation (§9.10), where the share is returned in a saved response; separate gates are installed on that path. Quorum, bequest, and succession do not have their own issuance of share A.

A fingerprint not belonging to any chain follows the previous path WITHOUT a single change, covered by a dedicated test (`crates/cc-authority/tests/agent_chain.rs`).

A chain holder receives a lease only if the grant is live, unrevoked, and lists the file; the lease's `expires_at` is no later than the chain's `expires_at`, and its `server_policy` is the previous server policy intersected with ALL chain tightenings (`oc_policy::intersect`, monotonic only toward restriction, so an extra link cannot weaken it).

Refusals (all have Russian `Display` text, shown to the person by the door): `ChainRefused { why }`—signature, shape, lifetime, wrong parent, occupied holder identity; `GrantRevoked`; `FileNotInGrant`; `WeakerThanFile`; `ChainTableFull { limit }`. Storage limits: at most 1024 chains and at most 32 links in one chain.

### 14.4. Author side

`cc agent grant --door <fingerprint> --door-key <key> --door-verify <key>
--tree <directory> --until <deadline> [--depth N] [--view-only] [--url address]`.

Only regular `.cc` files are traversed; symbolic links are not followed. The door fingerprint is compared with its key (K27) BEFORE opening the first author slot: rejection of a mistyped identity must not cost even one acquired share copy (I-11). A file belonging to another author or stronger than the door fails the entire command—the person named a directory, and granting part of it without saying which part is worse than granting nothing.

Fingerprint and key are specified SEPARATELY even though they are the same bytes for the classical mechanism: “this fingerprint names this key” is the only check the program is entitled to make here, and the second line makes a transcription mistake visible as a refusal rather than a grant sent to someone else's key. The protocol does not and cannot know who stands behind the door; a person compares the fingerprint with what the door itself printed through a second channel—the same single-identity rule as for people (`docs/format.md`, “Stage 4,” rule 1).

`cc agent revoke <grant name> [--url address]` sends order 13.

### 14.5. Stage 2: action door—decision of 2026-09-22

The design and boundaries are in `docs/agent-protocol/stage-2-actions.md`; this section covers only the wire and server checks. The `ActionGrant`, `ActionRequest`, `ActionLease`, `ActionDecision`, and `PendingAction` documents are in `oc_protocol::action`; their domain labels are in `docs/format.md` §3.6 (`CC/v1/action-grant`, `CC/v1/action-lease`, `CC/v1/action-decision`; the request has NO label and must not have one—it is unsigned).

Who talks to whom: the AUTHOR deposits an action grant; the DOOR requests execution under its proven identity; the SERVER signs the lease with its lease-signing key; the author signs a decision for `confirm`. The same order 13, `RevokeGrant`, revokes everything: the action grant is bound to the file grant, introducing no second revocation entity.

Message kinds:

| Number | Request | Response |
|---|---|---|
| 57 | `PutActionGrant`—complete action-grant bytes (`signature(64) ‖ body`) | 54 `ChainStored` (no body) |
| 58 | `RequestAction`—request bytes (unsigned) | 62 `ActionGranted`—complete lease; 63 `ActionPending`—`u64le seq`; 64 `ActionRefused`—UTF-8 reason |
| 59 | `ReportAction`—`u64le seq ‖ u8 ok ‖ digest(32)`, exactly 41 bytes | 14 `Accepted` |
| 60 | `ActionRequests`—`grant name(16)` | 65 `ActionQueue`—queue window |
| 61 | `DecideAction`—complete owner-decision bytes | 14 `Accepted` |

Five numbers instead of one “stage 2 document” with an inner kind, for the same reason as the three numbers in §14.1: the first byte selects parsing BEFORE it is known whose document arrived, and the verification keys for grant, request, report, and decision differ (author, none, none, author). Responses 54 and 14 are deliberately reused: `PutActionGrant`, `ReportAction`, and `DecideAction` make no new promises, while a new response kind would promise a second entity.

The `ActionQueue` body is consecutive `u32le length ‖ document PendingAction`, as in the access-request queue (§10), parsed by the same technique (`oc_protocol::action::split_action_queue`). The window is 16 entries (`MAX_PENDING_ACTION_WINDOW`); resolved entries leave and the next by number enter. An empty body is valid and means “nobody is waiting.”

The `ActionRefused` body is a textual reason, and it is REQUIRED: the codec itself rejects an empty string at both ends, so our side cannot produce a wordless refusal. The ceiling is 1024 bytes (`MAX_REFUSAL`); rejected character categories are shared with notes (`oc_format::text`). This is separate from `Denied` (7): `Denied` concerns the CONVERSATION (no handshake, wrong identity); `ActionRefused` concerns the action itself, and its answer is final.

**The `Chain` (55) body acquired an envelope.** Before stage 2 it was a bare document stream; now it is TLV: tag 1 `documents` (critical) contains the same stream, and tag `0x8001` `lease_verify_key` (OPTIONAL, 32 bytes) carries this server's lease-signing key. There was nowhere to append a key to the stream: it has neither tags nor room for an optional field, and an appended record is indistinguishable from an extra document. A door granted ACTIONS ONLY needs the key: ordinarily it obtains it from the header of any granted file, pinned by the author's signature, but it has no files. The response adds no trust—the server names its own public key—and a door with at least one file must compare the supplied key with the header. The server ALWAYS sends it: sending it intermittently would introduce a second answer to one question.

**A third tag arrived with the door—decision of 2026-09-22.** Tag `0x8002`, `action_grant` (OPTIONAL), carries the complete action grant for this chain if one has been issued. It was introduced because the stage 2 specification (§5, step 2) requires the door to refuse an agent IN WORDS and BEFORE NETWORK ACCESS, while holder rules reside in the signed action grant—a document the door had no way to obtain: the `documents` stream carries the file chain, and an action grant cannot be appended to it (a stage 1 reader would treat it as an extra link).

The tag adds no trust: the bytes are signed by the author and verified by the door itself (`agent::verify_grant_chain_with_actions`), while decisive verification remains on the server, which issues the lease. Door-side verification RESTRICTS: stale rules it holds can only be previously issued rules, hence harmless, while expanded rules will be rejected by the server.

An empty tag value is rejected during parsing: absence of an action grant is represented by ABSENCE of the tag, and two wire representations of one meaning invite divergence between endpoints.

Log events (§7): `ActionGrantRegistered = 32`, `ActionRequested = 33`, `ActionLeased = 34`, `ActionDone = 35`, `ActionFailed = 36`.

All five are written WITHOUT A FILE (zero `file_id`, like attribute holdings, §13), deliberately: an action has no file—its subject is arguments, not a container. The cost is explicit: subscriptions are PER FILE, so these entries do not reach file subscribers. The owner sees them through the log view and `ActionRequests` queue; the affected grant is reconstructed from the holder fingerprint—one door holds exactly one chain (§14.3).

#### “Log → lease” ordering—a stage invariant

`ActionRequested` is recorded BEFORE ANY GATES, including when no lease is issued. An action absent from the log could not have been executed, and only this ordering sustains that promise: record it after the gates, and an attempt stopped by a gate would leave no trace.

The cost is log growth from requests. Proof of possession bounds it: unlike an access request (§10), an execution request is accepted only under a PROVEN identity, and behind every entry stands the key owner that the entry names.

#### What the server checks

When receiving an action grant: a file grant with this `grant_id` exists and is not revoked; the signature verifies with ITS author's key recorded when registering FILES (an action has no container header, so the anchor is the grant); `expires_at` is no later than the file grant's; action kinds are known (unknown numbers are rejected during parsing). Repeating the same bytes is idempotent; different bytes under the same identifier are rejected.

For a request, IN THIS ORDER: the proven identity equals `door_fpr` (constant-time comparison, as for `Collect`); **record `ActionRequested`**; an action grant exists and the chain is not revoked; the holder has the rule ALONG THE CHAIN (`oc_protocol::agent::verify_grant_chain_with_actions`); arguments satisfy the limiters (`args_within`); remaining `max_uses` exists AT EVERY ANCESTOR; `nonce` has not been seen. Then: for `confirm`, enqueue and return `ActionPending`; otherwise issue `ActionLease` and record `ActionLeased`.

`max_uses` is counted ALONG THE CHAIN: a descendant's execution also consumes a use at every ancestor. Otherwise delegation would multiply the limit. The counter is per “holder—rule” pair; the rule key is the kind and limiter AS BYTES (`oc_protocol::action::limiter_key`): two `tree.remove` rules for two subtrees are an ordinary grant, and confusing them would debit the wrong limit. A use is consumed at lease ISSUANCE, not reporting: a lease already authorizes execution, and otherwise a door submitting no report would spend nothing.

`nonce` is remembered until the `expires_at` of the lease issued for it—thirty seconds (`ACTION_LEASE_SECONDS`). The lease window is checked during PARSING too: a document claiming a week is rejected at the crate boundary.

#### `confirm`: how the door obtains a lease after approval

A request under a rule with `confirm` enters the queue, and the door receives `ActionPending { seq }`. The owner sees it through `ActionRequests` and decides via `DecideAction`. Approval does NOT issue a lease immediately: **the door repeats `RequestAction` with THE SAME `nonce`**; the server locates the approved request by this `nonce` and issues a lease without enqueueing it again.

This is done instead of “the server issues a lease and holds it until the next query” for two reasons. First, a lease lives thirty seconds; issued upon approval, it could expire while the owner closes their laptop. Second, issuance passes the gates AGAIN using the clock at that instant: grant revocation and expiry may intervene between approval and execution, and approval converted to a lease in advance would bypass them.

A repeat with the same `nonce` but DIFFERENT arguments is rejected: otherwise approval to “push this branch” could be redeemed by pushing another.

An owner's denial becomes `ActionRefused` with their note. The denial note is the reason the agent sees.

A `ReportAction` report is accepted only under the proven identity of that lease's HOLDER: another party's report would log the outcome of someone else's action. Repeating the same report is idempotent; a report with a different outcome for the same number is rejected.

Refusals (all have Russian `Display` text): `NoActionGrant`, `ActionNotGranted { why }`, `ActionUsesExhausted { limit }`, `ActionNonceSeen`, `ActionQueueFull { limit }`, `ActionDeclined { why }`, `NoSuchActionRequest`, and the existing `GrantRevoked`, `ChainRefused { why }`, `NotTheAuthor`, `NotServing`. Storage limits: at most 64 requests awaiting “yes” per grant (`MAX_PENDING_ACTIONS`), at most 256 remembered issued leases per grant (`MAX_ISSUED_ACTIONS`), remembered for one hour (`ACTION_REPORT_WINDOW_SECONDS`): the door reports AFTER execution, for which the lease's thirty-second lifetime is insufficient.
