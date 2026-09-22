# The `.cc` container format: version 5 is produced and read; versions 1–4 are retired

Specification. Everything described here is mandatory for both sides; anything absent from this document must not be implemented. This document is the exit criterion for phase 0.

**Versions 1–4 are no longer read — decision of 2026-09-19, section “VERSIONS 1–4 RETIRED”.**
Their rules remain in this document as the history of the design on which version five rests; the reader accepts only `container_version = 5`.

Versions 1–4 are frozen (2026-08-17, 2026-09-07, 2026-09-08, 2026-09-08).
**Version 5 was cut on 2026-09-08**: the writer produces it (`CONTAINER_VERSION = 5`). There are NO version 1–4 witnesses in the repository: the renaming of 2026-09-08 removed them together with the old magic — the reason is in “RENAMING 2026-09-08”. Version 5 carries ONE item — the hardware hybrid `kem_id = 5` (MLKEM768-P256), the only mechanism that combines post-quantum protection and a key that cannot be extracted from the TPM. Version 3 carried exactly one item — nonce seeding with AAD (item 13); version 4 carries the other twelve: hybrid KEM `kem_id = 4`, the editing device's signature, `action_binding`, and the coauthor roster in the header. Below §1, the rules of versions 1–4 apply unless explicitly stated otherwise.

Conventions: integers are little-endian unless otherwise specified; `‖` means byte concatenation; `u32be(x)` is the big-endian representation; lengths are in bytes.

## FROZEN 2026-08-17

Version 2 was frozen on 2026-09-07.

**Version 1 is frozen. Its bytes no longer change.**

What this means in practice. Until this date, the document said “the format is not frozen”, and any byte representation could be corrected by reissuing vectors and reference files. From this date, the rule is reversed: **any** wire-byte change requires a new format version (`container_version = 2`), and frozen artifacts — `tests/kat/*.kat` and `tests/golden/*.cc` — change only together with it. “A test failed → fix the vector” ceases to be prohibited merely by agreement and becomes prohibited by its consequences: containers produced after this date must remain readable by future clients.

What is frozen: the file layout (§1), the header and all nested registries (§2, §2.0), key scheme K1–K20 with all domain labels (§3.5, §3.6), policy bytes (§4), the signature transcript and both hash transcripts (§4.0, §5), the tree leaf preimage (§6.3), the chunk frame, and the rule for deriving boundaries (§6.1).

What supports this. Every normative wire value has a **vector** checked by `cargo test`: `tests/kat/{derivations,chunk_aad,tree,policy,header,seal}.kat`. The list of missing vectors maintained in `tests/kat/README.md` since their introduction is empty. Three golden containers (one per addressing method) are compared byte for byte. Parsing order and opening order are specified as normative lists (§5.1, §5.4), rather than reconstructed by the reader from different sections.

**What freezing does not mean.** It does not mean the format has undergone an external audit: the sealing construction (§3.5, K10) was written by hand following RFC 9180 and remains the first candidate for such review. Nor does it mean the product is complete — there is no license server, and the recipient path has not shipped (§3.4). The **bytes** are frozen, not the functionality.

For precision about fuzzing: a campaign **has been run**. One hour for each of eight parsing targets, eight parallel processes, **1 151 627 358 executions**, no crashes and no artifacts. The fuzzer was configured natively, without `cargo-fuzz` (that utility cannot be installed on the development machine for a reason unrelated to Rust); the recipe is recorded in `fuzz/README.md`.

What this does **not** mean. One hour per target is a campaign rather than reconnaissance, but not a proof: a fuzzer shows the presence of bugs, not their absence. More informative than the execution count is the behavior of the coverage curve. Three targets did not move at all during the hour (`tlv` — 50 points, `prologue` — 42, `content_desc` — 168): their input space is small and apparently exhausted. The other five were still growing at the end of the hour — `signed_header` 1826 → 1870, `container` 1437 → 1485, `header` 846 → 896, `policy` 229 → 280, `content_desc_authenticated` 219 → 246. This means the deeper targets still have unexplored space, and the next campaign is useful work, not a ritual.

## VERSION 2 OPENED 2026-08-18

**The decision was made before the code and recorded here before a single byte changed.** There is one reason: a slot sealed to a TPM key. Microsoft Platform Crypto Provider does not provide X25519 — TPM 2.0 provides ECDH P-256 and RSA — so hardware device binding requires a slot with `kem_id = 2`.

**Why version 1 was insufficient.** The temptation existed: there is not a single container with a P-256 slot, so defining its shape seems to break nothing. The argument is wrong, and deserves examination because it sounds convincing. Version 1 §2.0 does not remain silent about the field shapes for `kem_id` 2 and 3 — it **states** that version 1 does not define them. Replacing “version 1 does not define the shapes” with “version 1 defines 65 bytes” changes version 1's normative content, creating two different version 1s. This is exactly what freezing prevents, and bypassing it because the product has not shipped would make the freeze decorative the first time it became inconvenient.

**Magic does not change.** §2.1 item 1 reserves a `Magic` change (`CLOSECR2`) for breaking changes, and this is not one: a version 1 reader rejects a version 2 container **cleanly**, under the range rule in `2.1` item 3 — `container_version` exceeds the highest readable version. Rejection is clear and occurs in the right place; no silent misreading occurs. `Magic` will need to change when the prologue itself changes.

**What changes in version 2, and only this:**

1. The lengths of `enc` and `key_fpr` become functions of `kem_id` — and are specified **separately**, not by one measure. They happen to coincide for X25519 and P-256 (both fields carry a curve point), but in RSA-OAEP `enc` is an encapsulation and `key_fpr` is a key; one measure would be wrong from its first use. Separation is introduced now, while its cost is zero, not when the third mechanism breaks against it.
2. `kem_id = 2` (P-256+HKDF-SHA256) becomes **executable**: `enc` and `key_fpr` are each 65 bytes, an uncompressed SEC1 point `0x04 ‖ X(32) ‖ Y(32)`.
3. `key_fpr` ceases to be a fixed-length field in parsing structures.
4. The version 2 writer **always** declares `min_reader_version = 2`, including containers whose slots are all X25519 and whose bytes would be identical to version 1. Version 2 changes **container** parsing rules, not those of an individual slot, and the reader must learn this before encountering a slot. Deriving the field from the actual slot set was rejected: a version 1 client would reject on `container_version` anyway, and a one in this field would be a misleading declaration with no benefit.
5. A claim-code slot (`kind = 3`) **always** declares `kem_id = 1`, and its zero `enc` and `nonce` have lengths 32 and 24. Without this line, the length of the zero `enc` would start depending on an unrelated choice of default mechanism, silently shifting the bytes of `claim.cc`.

**Why 65 bytes rather than 33.** The shape is dictated by the provider, not our preference: PCP returns the public key as a `BCRYPT_ECCKEY_BLOB` and offers no compressed form. Storing a compressed point would require decompressing it on every use — a field square-root extraction, extra code on the hostile-input parsing path to save thirty-two bytes. Thirty-two bytes are not worth it.

**What remains unchanged.** Version 1 remains **readable**: `container_version` is checked against a range, whose lower bound is still one. Everything frozen above and not named in the change list is frozen in version 2 as well — the key scheme, labels, hash and signature transcripts, leaf preimage, chunk frame, and policy bytes. Version 2 does not revise the format; it fills exactly one gap left in it.

**Artifacts.** `tests/kat/*.kat` and `tests/golden/*.cc` are reissued together with this decision — I-14 permits precisely and only this: together with a decision recorded here, not in response to a failing test. Reissuance must be complete and simultaneous; version 1 artifacts are retained separately, because otherwise there is nothing with which to check version 1 readability.

---

## VERSION 3 OPENED 2026-08-24

**Version 3 is cut on 2026-09-07 with ONE item — 13.** Items 1–12 move to version 4 without changing the historical text below. Customer authorization of 2026-09-07: “choose the best solutions; if reissuance is needed, I authorize it”. Both answers to `F-15`: “why cut now” — “for seeding”; “what else to put in version 3 while it costs nothing” — “nothing”. Rule 4 requires the semantics to be executable: hybrid KEM and editing are not yet executable. A second bump is cheaper than waiting indefinitely for a fix.

**The decision was made before the code and recorded here before a single byte changed** — the same procedure used to open version 2. There are two reasons, and both change wire bytes.

1. **Post-quantum hybrid KEM.** Numbers `kem_id` 1 (X25519), 2 (P-256), and 3 (RSA-OAEP) are occupied; the hybrid receives **`kem_id = 4`**. Version 2 does not define its shapes.
2. **The editing device's signature.** Phase 6 (container editing) requires a place for the editor's signature. None exists today: `oc-crypto` declares the label `"CC/v1/editor-sig"`, but it has no tag, structure, or consumer — in other words, it is completely absent from the format.

**Why version 2 was insufficient, and why the argument is stronger than for version 1.**

The version 1 case was simpler: §2.0 **stated** that version 1 did not define shapes for `kem_id` 2 and 3, and replacing that statement created two different version 1s. There is no such statement here — version 2 simply **says nothing** about number 4; no row exists in the length table. The resulting temptation is direct: silence does not contradict adding a row, so a row can be added.

**The argument is rejected for the following reason.** The lengths of `enc` and `key_fpr` are a function of the **pair** (`container_version`, `kem_id`); §3.3 does not say this for decoration: without a version dependency, a version 1 container with a `kem_id = 2` slot would retroactively acquire a shape it never had. A function defined on a pair is specified by its values, not by omissions: “version 2 is undefined for number 4” is its value. Adding the row changes the function itself, and therefore version 2's normative content — exactly what freezing prevents.

The chosen criterion is stated explicitly: **behavioral, not textual**. A version is not a set of paragraphs; it is a set of bytes it can read. A textual criterion (“what the version says about this”) would distinguish silence from assertion and thereby make freezing depend on how thoroughly the previous document was written. That rewards incompleteness.

Under the same criterion, the editor's signature requires a new version independently of the hybrid: a new tag in the mutable region means new bytes in a region that a version 2 reader parses under its own rules.

**Magic does not change.** The rationale is the same as for version 2: a version 2 reader rejects a version 3 container **cleanly**, under the range rule in §2.1 item 3 — `container_version` exceeds the highest readable version. Rejection is clear and occurs in the right place. `Magic` will need to change when the prologue itself changes.

**What changes in version 3, and only this.**

1. **`kem_id = 4` — a hybrid of X25519 and ML-KEM.** The slot carries both encapsulations; the shared secret is derived from both. Slots with different `kem_id` values coexist in one container as before: `kem_id` is specified per slot, not per file.

   **CONSTRUCTION — X-Wing, decided 2026-09-08.** Normative source: `draft-connolly-cfrg-xwing-kem-10` (2 March 2026), §5.2–5.5; text sha256 `530900ac0519e28eb1ff50bf80ecdb7648add22e500db72b465bab4fb6b6a5ec`. The construction was checked against the draft's vectors — `spikes/ml-kem-cost/`, binary `xwing`, twelve comparisons, zero discrepancies.

   The private half is **32 bytes**, from which SHAKE256 expands both pairs:

   ```
   expanded = SHAKE256(sk, 96)
   (pk_M, sk_M) = ML-KEM-768.KeyGen_internal(expanded[0:32], expanded[32:64])
   sk_X = expanded[64:96];  pk_X = X25519(sk_X, BASEPOINT)
   ```

   The public half is `pk = pk_M(1184) ‖ pk_X(32)`; the ciphertext is `ct = ct_M(1088) ‖ ct_X(32)`. Exactly the 1216 and 1120 already recorded in §3.3; choosing the construction confirmed them rather than defining them.

   The shared secret is **not HKDF**, but one SHA3-256 invocation, and the label comes LAST:

   ```
   Combiner(ss_M, ss_X, ct_X, pk_X) = SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ XWingLabel)
   XWingLabel = 5c 2e 2f 2f 5e 5c   (six ASCII bytes: "\./" and "/^\")
   ```

   > **The label order is stated explicitly because the very first reading from memory got it wrong.** A label at the beginning yields a different secret from the same inputs — silently: two sides making the same mistake agree with each other and disagree with the rest of the world. This is exactly the “derive by analogy” approach that has already produced the wrong result three times in this repository (the TPM 1.2 attestation constant, the TPM clock model, Word's single-window behavior).

   **Why X-Wing, rather than our own combiner in K10.** Three options were examined in `deferred.md` §1.1. The existing `x-wing` crate is not used — measurements on the actual dependency tree showed that it requires `sha3 ^0.12`, while the `ml-kem` it pulls in requires `^0.11`, causing `cargo deny check bans` to fail on the duplicate. A custom combiner directly in K10 was rejected under this file's rule: cryptographic schemes are not casually “improved” when a construction examined by specialists exists. Moreover, K10 uses HKDF, whereas X-Wing deliberately does not (draft §1: with SHA3-256, an HMAC construction is unnecessary). The third option remains: X-Wing implemented locally on top of `ml-kem`. Five new crates; `cargo deny` is clean; `SHA3-256` and `SHAKE256` come from the same `sha3`.

   **The parameter set is 768, specified by the same construction.** X-Wing is defined over ML-KEM-768 and nothing else; 1024 is a different KEM, not a different parameter, and therefore requires a **new `kem_id`** (see the inset in §3.3). The same decision closes `deferred.md` §1.2.

   **`DEFAULT_SEALING_KEM` DOES NOT CHANGE, and that is a separate decision.** The hybrid does not become the default now or on the day version 4 is cut: it addresses an X25519 key, a SOFTWARE key. Making it the default would silently trade a protection that works today — a key that never leaves the TPM — for protection against an adversary that does not exist today. The author selects the hybrid explicitly, per slot.

   **THE AUTHOR SLOT MUST BE NO WEAKER THAN THE RECIPIENT SLOT. Corrected 2026-09-08 after rechecking.** The first code revision did not enforce this, making the hybrid decorative: the author slot carries BOTH shares together, so an adversary able to solve the discrete logarithm could take that slot, obtain `A‖B`, derive KEK, and open the file without touching ML-KEM. Container strength equals the strength of its weakest SUFFICIENT path to CEK, and the author path is always sufficient. Therefore, a recipient with `kem_id = 4` requires an author slot with `kem_id = 4`; if the author has no hybrid half, construction FAILS rather than silently downgrading.

   **The hybrid private half is its OWN key with fresh entropy, not a derivation.** The first revision derived it from the device seed (derivation K26, label `"CC/v1/xwing-seed"`); both the derivation and the label are WITHDRAWN. HKDF domain separation protects the output from knowledge of a key, but does not protect the input from recovery: the device seed is the X25519 private scalar, its public half is published, and the adversary for whom the hybrid is introduced recovers the input and recomputes the derivation. The broader rule is: **the post-quantum half must not depend on a classical secret through any derivation.** The key lives in `device-hybrid.key`.

   **Hardware hybrid — a version 5 decision verified by a separate probe on 2026-09-08.** Version 4 has no combination of TPM and X-Wing in one slot. This is an implementation limitation, not an impossibility of combining P-256 and ML-KEM. Two independent slots do not replace a hybrid: a sufficient classical recovery path bypasses post-quantum protection.

   The earlier justifications were wrong twice: first, “a custom construction is needed” was inferred by analogy with X-Wing without checking the source; then the TLS group `SecP256r1MLKEM768` from RFC 10024 was called a ready-made KEM for files. But [RFC 10024 §6](https://www.rfc-editor.org/rfc/rfc10024.html#section-6) explicitly limits its rationale to the TLS transcript. IANA 4587 is a TLS group number, not a KEM identifier for our container.

   The next version is based on **MLKEM768-P256**, the CG construction from [draft-irtf-cfrg-concrete-hybrid-kems-03 §4.1, A.1](https://www.ietf.org/archive/id/draft-irtf-cfrg-concrete-hybrid-kems-03.html#section-4.1). This is a pinned revision of a CFRG DRAFT, not a finished RFC. Byte order: `pk = pk_M(1184) || pk_P256(65)`, `enc = ct_M(1088) || eph_P256(65)`; the combiner result is `SHA3-256(ss_M || ss_P256 || eph_P256 || pk_P256 || "MLKEM768-P256")`. This is a separate KEM; the outer K10 does not replace its combiner. `kem_id = 5`, `key_fpr` length 1249 and `enc` length 1153. **Cut as version 5 on 2026-09-08**: the mechanism is executable (`oc_crypto::mlkem_p256`, vectors `tests/kat/mlkem_p256.kat`), the reader accepts it, and the writer produces version 5. Versions 1–4 do not define shapes for number five and skip such a slot — length tables are gated by the pair (version, `kem_id`).

   **Hardware identity.** [The general construction §5.2](https://www.ietf.org/archive/id/draft-irtf-cfrg-hybrid-kems-12.html#section-5.2) permits separate generation and key handles. The hybrid uses a NEW ECDH P-256 key inside the TPM and an independent ML-KEM half in protected storage. The old classical TPM key and components of other hybrids are not reused. A shared software seed that can recover the TPM scalar is forbidden. This method has a weaker binding property (LEAK rather than MAL), as the source states; in the shipped implementation both public halves, the hardware key name, the algorithm, and the identity are bound by one record. Substitution or disagreement causes rejection, not creation of a new pair over the old one.

   **Recovery is a planned mode, and its name was corrected on 2026-09-08.** This text previously said “backup RECIPIENT”, which was incorrect: a recipient slot carries only share B (`oc-engine/src/lib.rs:435`) and is useless without share A from the server, so it does not solve the stated task at all. Only an `AuthorDevice` slot carries both shares; the design therefore concerns a SECOND AUTHOR — a holder on a different physical device with a separate hybrid identity, not a recipient with special privileges.

   This also defines the real cost: that holder receives the complete author path. `open_as_author` does not ask for PERMISSION (§4.1), so no open limit, time window, or revocation applies to it; viewer obligations — watermark, capture shield — remain, because they do not concern admission. This is an additional trusted holder and a deliberately introduced FOURTH sufficient path to `CEK`. It is permitted only when named, no weaker than the recipient slot (otherwise packing rejects), and visible in `cc inspect`.

   The mode without a second author is selected explicitly and warns that loss of the last sufficient path is irreversible. There is no silent fallback to a software or classical slot. The product owner makes the decision — `deferred.md` §26. Testing on separate physical devices, the approval ceremony, and the complete recovery flow have not yet been performed.

   **Boundaries.** A copy of the software ML-KEM half combined with a future break of P-256 yields both halves: protection against each of two threats individually does not protect against their combination. An ordinary hybrid adds no isolation from a process running under the same account. The post-quantum profile must check ALL sufficient paths to CEK, including author and backup paths; the length of a public point cannot certify hardware key provenance.

   **Since 2026-09-09, the READER enforces this rule, not only the writer.** Before that date, rejection existed only in `oc_engine`: it prevented US from making weak files while saying nothing about other people's files. Our reader accepted and opened a container with “recipient `kem 5`, author `kem 4`” made by another build or by hand, considering it protected. A rule enforced only on the writer protects against one's own mistake, not an adversary. Now `cc_cli::container` rejects such a file on EVERY opening, through both the author and recipient paths: the weakness is a property of the FILE, not of the person opening it.

   **Feasibility evidence:** `spikes/p256-mlkem-tpm/README.md`, ten external KATs, negative controls, and live PCP. The probe is not the version 5 implementation and does not justify declaring the product profile complete.

2. **Editor signature — tag 6 of the mutable region, in the critical range.** Tags 1–5 are occupied (`total_len`, `chunk_count`, `tree_root`, `version_counter`, `footer_offset`); six is free.

   Why in the mutable region rather than the footer: the signature must be next to what it authenticates. Editing changes `tree_root` and `version_counter`, and both live here. The footer has not been defined at all; its offset is discussed in item 6 below.

   **Why the critical range, even though it breaks compatibility.** An optional tag would allow a client unaware of editing to open an edited file silently: the edit becomes invisible precisely to the client unable to verify it. The strict choice costs compatibility with all released clients; today that cost is near zero because there are no released clients. It rises with the first delivered client: **this decision only gets cheaper looking backward** — postponing it means paying more for the same answer.

3. **The editor signature covers the mutable region excluding THE SIGNATURE VALUE ITSELF** — the tag, length, and value of the `signature` subfield inside record 6 are removed, not all of record 6.

   > **There was an error here, and it survived from item 2 to item 8.** The text said “the entire record is removed, like records 10 and 17 when computing `core_hash` (I-3)”, which was correct only while tag 6 meant ONE signature. Item 8 added four more values — algorithm identifier, session chain head, journal head, key certificate — and removing the entire record would have left them **outside the signature**. The journal head could then be replaced without invalidating the signature, defeating the gossip linkage through the very field intended to create it.
   >
   > The error mechanism is the same as discussed in `D-gates`: the rule was correct for a construction that later changed, but the rule was not reread.

   The reason for exclusion remains unchanged: otherwise the value would depend on itself. Leaving the tag and length would permit changing the content without changing the signature — the same defect discussed for `core_hash`.

4. **The mutable-region MAC covers the ENTIRE region, including the signature record**, and is verified first — I-5 is not weakened. The mandatory order is: MAC over raw body bytes first, TLV parsing next, editor signature verification last. Verifying the signature before the MAC would mean parsing unauthenticated bytes, precisely what I-5 forbids.

5. **`version_counter` becomes active.** Before version 3 it was written but never incremented. With editing it grows, and checking it becomes protection against content rollback.

   > **NOT YET NORMATIVE.** The source of the reference counter value used during verification (server, lease, or local state), and its relationship to the existing F-8 rollback protection, require a separate decision recorded here before editing code.
   >
   > **Decided 2026-09-17** — “EDITING IS EXECUTABLE”, item A: the reader uses the accepted-device journal as its reference; the server uses the revision registry.

6. **`footer_offset`: mutable-region tag 5 is authoritative. Signed-header tag 16 is RETIRED.** This value had been declared **twice**, with no rule defining which declaration wins. While the footer is unused, the discrepancy is harmless; once needed, two sources for one value would yield two different answers.

   The deciding factor is **mutability**, not security. The footer lies AFTER the payload, and version 3 makes the payload mutable: editing changes `total_len` and `chunk_count`, moving the footer. Only the author can sign the new offset, and the author is absent during editing. Thus an offset in the signed header either forbids editing forever or silently becomes wrong — there is no third possibility. The value belongs beside `total_len` and `chunk_count`, which describe the same thing: “what the file looks like now”.

   **The security objection was examined, not dismissed.** Tag 5 is protected by a MAC under a key derived from `CEK`, so a `CEK` holder can replace the offset, unlike a signed offset. For two of the three planned uses, this gains nothing: an RFC 3161 token carries the timestamp authority's signature; a countersignature carries the server's signature. Both authenticate themselves, so a wrong offset causes verification FAILURE rather than acceptance of a forgery. The offset is never read from unauthenticated bytes: I-5 requires checking the region MAC before parsing its TLV.

   > **A reconsideration condition, and not a cosmetic one.** The third use — a tag table — does NOT authenticate itself. If the footer contained such a table, a `CEK` holder could supply any table to the reader, and the decision above would become a vulnerability in exactly the way described in `D-gates`: the code did not deteriorate; the promise became stronger. Therefore: **the footer may carry only self-authenticating content** while its offset is under a MAC. If a table is needed there, THIS decision must be reconsidered, rather than inventing separate protection for the table.

   **And what a signed offset never provided.** The author signs the header BEFORE the footer exists: the timestamp token and countersignature appear later. A signed offset was a prediction, not an observation, protecting a value that did not yet exist when signed.

   > **The decision is recorded; bytes are untouched.** Version 3 has not been cut, tag 16 has not been removed from `Header`, and it MUST NOT be removed today: no released file carries it, but versions 1 and 2 are frozen together with another implementation's right to write it. The field will be removed when version 3 is cut, when critical tag 16 begins to mean rejection. Recording the decision now costs nothing; after cutting, it would cost version 4.

   This is recorded here rather than in the byte-change list because version 3 does not introduce a footer — it introduces the editor signature **instead**.

7. **The editor signature is RSA-PSS-SHA256, NOT ECDSA.** The choice was made on failure behavior, not taste.
   ECDSA uses an ephemeral `k` for each signature. Two signatures of different messages with the same `k` yield `k = (H(m₁) − H(m₂))/(s₁ − s₂)`, and from it `d`: the private key is recovered by **arithmetic**. This is not a theoretical caveat — rolling back a virtual-machine snapshot repeats the generator state, and the binding ladder already warns about vTPM.

   With RSA-PSS, the salt enters the **message encoding**, not the exponent. Reusing a salt yields two valid signatures and nothing more; PSS with a zero-length salt is standardized and has a security proof. This class of attack is not mitigated here; it **ceases to exist**.

   PSS still permits signing two divergent histories after rollback. That is equivocation, detected by a journal consistency proof: the risk moves into a mechanism already being built, instead of requiring a separate caveat.

   **Registry number: `sig_alg = 2` — RSA-PSS-SHA256, MGF1-SHA256, 32-byte salt, exponent 65537.** All four parameters are fixed by the number and cannot be negotiated in the file: a suite with a field-selected salt or mask introduces a second degree of freedom where one is needed — exactly how “algorithm declared but not obeyed” would enter the registry.

   The identifier is used by **tag 6**, and only tag 6. The author's signature remains Ed25519 (`sig_alg = 1`) and does not change: `suite.sig_alg` was frozen by version 1, and version 3 has no right to alter it. Thus two signatures using different schemes coexist in the file — author and editor — as a separation of roles, not agility: they have different signers, different keys, and different times.

   **Verified on real hardware, not inferred from documentation** (`spikes/rsa-pss-tpm/`, 2026-08-29): PCP created RSA-2048 in 0.7 s, refused private-part export, signed PSS-SHA256 in 90 ms, with a 256-byte signature and 32-byte salt; twenty signatures of the same message differed. This rule was learned at a cost: reasoning by analogy gave the wrong answer here three times — the TPM 1.2 attestation constant, TPM clock model, and Word's single-window behavior.

   The verifier is **local**, built on `crypto-bigint` (already in the tree through `p256`): modular exponentiation with a public exponent plus PSS encoding parsing. The operation contains no secrets, so constant time is unnecessary; a local implementation is permitted for exactly that reason. The exponent is **fixed at 65537**: small exponents have historically enabled forgeries, and the verifier has no reason to support them.

   A consequence for reference artifacts that must be understood in advance: the salt is random, so **editor-signature bytes are not reproducible**. They cannot be frozen in a golden container; the reference must check signature verifiability, not its bytes.

8. **Tag 6 carries four values, not just one signature.**

   * `sig_alg` — otherwise the edit-signature algorithm is unspecified;
   * **the session chain head**, not a signature for every save. Word saves several times a minute; the mutable region is limited to 64 KiB. A signature per save reaches the ceiling after a day and a half of editing. Saves are hash-linked; the signature covers the chain head;
   * **the journal head most recently seen by the signer.** A gossip-style linkage inspired by Certificate Transparency: containers already travel between people, so any two clients exchanging them inevitably compare their views of history. A server showing two different branches is caught by the first file to cross between them, not only by a client that carefully pinned its head;
   * `certified_by` — the signing-key certificate. Without it, rotating a key would require another out-of-band comparison with everyone, recreating exactly the pain that caused the shared key to be rejected.

9. **The binding requirement becomes PER ACTION.** Today `min_binding` applies to the policy as a whole. Viewing from the software tier is possible; editing is not: an edit signature cannot be stronger than the machine's binding tier. This does not remove `Binding::Software`; it uses it for its intended purpose — a tier exists to decide what is allowed.

10. **The signing-key trust root.** A key-agreement key **cannot** certify a signing key: PCP fixes key usage at creation and it cannot change, and the TPM will not sign with a key created for agreement. Therefore:

    * **root** — the author's certificate issued during device approval. The author has already compared the fingerprint over a second channel and is already approving; at that moment the author signs “device X has signing key S”. This works today and requires no new cryptography;
    * **rotation** — the new signing key is certified by the previous one;
    * **later** — `TPM2_Certify`: a TPM-authenticated statement that “S resides in the same TPM as the agreement key and is non-extractable”. The repository already constructs the `KAST` envelope; the missing verifier is the same component blocked by X.509 parsing and a decision about vendor roots.

11. **BYTE LAYOUTS OF THE NEW FIELDS.** Items 7–10 and 13 made decisions but did not specify layouts. Without layouts, a version cannot be cut: a frozen version consists of bytes, not paragraphs. Item 13 was added here on 2026-09-07 with the decision itself: a list that fails to enumerate everything missing is worse than no list — it could cause a version to be cut under the belief that it is complete.

    **Mutable-region tag 6 is a nested TLV**, with strictly ascending tags as everywhere else. It is not one value: there are five quantities, and joining them at fixed offsets would introduce a second encoding system alongside the existing one.

    | Tag | Field | Value |
    |---|---|---|
    | 1 | `sig_alg` | u8, identifier from the signature-algorithm registry; must be **2** for version 3 |
    | 2 | `session_head` | bytes[32]: head of the save hash chain covered by the signature |
    | 3 | `journal_head` | `u64le(size) ‖ bytes[32](root)` = 40 bytes, **or an empty value** = “no head was seen”; the field is always written |
    | 4 | `certified_by` | signing-key certificate, variable length |
    | 5 | `signature` | bytes[256]: RSA-PSS-SHA256 |

    `journal_head` is always written; “not seen” is expressed by an **empty value**, the same technique used for `max_opens` (§4). An absent record would mean the signature does not cover the fact that “the editor has not seen the server”; a device that never submitted edits would become indistinguishable from one that concealed its head.

    All five tags are **critical**. An optional `sig_alg` would let a client accept a signature without knowing its scheme — exactly JWS `alg: none`.

    **Policy tag 7 is `action_binding`**, a nested TLV: tag = action number (§4, the same numbers as `actions`), value = u8 binding tier encoded as `min_binding`. **All** known actions are written, as with `actions`.

    An action's effective requirement is `max(min_binding, its entry)`. Thus tag 7 can only **tighten** requirements, which is not a convenience but the monotonicity condition of I-10: `intersect(author, server)` remains monotone only toward greater strictness.

    Tag 7 is deliberately in the **critical** range, more important than it appears. If optional, a version 2 client would silently skip it and permit software-tier editing where the author required hardware. An optional policy field that tightens a requirement is a contradiction: a client skipping it executes a DIFFERENT policy from the one signed by the author.

    **`kem_id = 4` — field shapes defined, execution deferred.** `enc` = 1120 bytes, `key_fpr` = 1216 bytes (§1.1 `docs/deferred.md`: all three constructions considered have identical lengths, so the FORMAT decision is independent of the construction choice and precedes it).

    > **These lengths CLOSE the ML-KEM parameter-set question, and this must be said explicitly.** 1120 = 1088 + 32, 1216 = 1184 + 32: ML-KEM-**768** ciphertext and key alongside X25519. `docs/deferred.md` §1.2 kept “768 or 1024” open, and 1024 “requires its own numbers”; by specifying these lengths, version 3 chose 768. A silent decision is worse than a disputed one: it cannot be discussed because it is invisible.
    >
    > If 1024 is ever needed, it requires a **new `kem_id`**, not different lengths for number four: length is a function of (`container_version`, `kem_id`), and changing it for an occupied number creates two incompatible fours. The construction choice (X-Wing or a custom combiner) remains independent — all three candidates have the same components and lengths.

    The build **parses these lengths and rejects execution**, under the same rule that currently rejects `aead_id` 2 and 3: an identifier the build cannot execute is rejected during parsing, not at first use. Without the lengths specified here, version 3 would repeat the defect for which version 1 paid: a registry number with no shape.

12. **Header tag `0x8001` is `coauthors`: the roster of those authorized to administer the file.** The first **optional** signed-header tag, and its optionality is deliberate, not an oversight.

    Today the coauthor roster and signature threshold live only on the **server** (`docs/protocol.md` §11), with the cost stated explicitly: server state vouches for the roster, not the document. The server holder can rewrite it; the header knows nothing about this and cannot know.

    The tag moves the anchor into the signed header. Its layout is nested TLV, like mutable-region tag 6 and for the same reason: there are two values, and joining them at fixed offsets would introduce a second encoding system alongside the existing one.

    | Tag | Field | Value |
    |---|---|---|
    | 1 | `threshold` | u8, required number of roster signatures; `0` means “no quorum” |
    | 2 | `keys` | bytes[32·n], consecutive keys, `1 ≤ n ≤ 16`; absent when `threshold = 0` |

    The sixteen-key limit is the same as for server addresses and the request-queue window, and for the same reason: a quantity a person can inspect visually. Duplicate keys are forbidden: one vote would count as two, and one signature would satisfy “two of three”. The roster must be able to meet the threshold (`1 ≤ threshold ≤ n`): a rule no one can ever satisfy freezes the file forever, discoverable only when it freezes.

    **Server rule on registration:** a file with this tag receives its initial roster FROM THE HEADER; unilateral `SetCoauthors` is rejected for that file. Otherwise the tag would be decorative: the author would sign a fixed roster only for the first instruction to overwrite it.

    **Why OPTIONAL, despite the general rule that “a field tightening a requirement must be critical”.** Because it tightens nothing for the READER. Policy tag 7 would permit editing at a weak tier where the author required a strong one, meaning a client skipping it would execute the wrong policy. Here a client skipping the tag opens the file **entirely correctly**: the coauthor roster changes neither keys nor access rules; it changes only whose instructions the SERVER executes. The server knows this tag; it is not addressed to the recipient at all.

    The converse is worth stating: a critical tag here would make an old viewer refuse a file because it has two administrators rather than one. An unjustified refusal is exactly the cost the optional range exists to avoid.

    **There is NO approver roster (`approvers`) in the header, and none is planned.** The two rosters differ in what they control, not in importance. Coauthors control ADMINISTRATION, which the author fixes once for the long term; approvers control EVERY OPENING, and their roster changes with circumstances: today a lawyer approves, tomorrow a department head. Embedding that list in the signed header would require repacking a file for a personnel change, changing `file_id` for copies already distributed.

**What remains unchanged.** Versions 1 and 2 remain **readable**: `container_version` is range-checked, with the lower bound still one. Everything frozen above and not named in the change list is frozen in version 3 as well — the key scheme, labels, hash and signature transcripts, leaf preimage, chunk frame, policy bytes, author's signature and its strict verification (I-6).

**What version 3 does NOT do.** It does not revise share separation: `KEK` is still derived from exactly 64 bytes of `secret_A‖secret_B`, and K1 does not change. “Author approval” mode is deferred to a separate decision.

Version 3 **does not touch** the server's role, and that statement survived an attempt to overturn it. For several hours on 2026-08-27, the opposite appeared here: the “right of first opening” decision gave both shares to the server, and the paragraph was changed with it. That decision was replaced the same day (“Access request” below), leaving the server as it was: an intermediary that cannot see the content. The original wording was deliberately restored: it is correct, and there is no reason to erase the fact that it was once considered wrong; the error analysis is recorded below as well.

13. **Nonce seeds K17–K20 include AAD.** Before version 3, seeding takes `HKDF-Extract(salt = 24 random bytes, ikm = plaintext)`, excluding AAD from the derivation. The consequence is stated next to the K17–K20 table and confirmed by a probe (cryptographic review 2026-09-06, E5): after generator rollback, two sealings of the SAME plaintext under DIFFERENT AAD produce one `(key, nonce)` and two different Poly1305 tags. An observer of the two files can therefore recover the one-time tag key and forge tags for that pair.

**What changes.** `ikm` is no longer just the plaintext; it includes AAD. The salt remains random generator bytes: it provides hedging, and there is no reason to change it.

**Concatenation here IS NOT UNAMBIGUOUS, and that is the item's main trap.** Both plaintext and AAD are variable-length, so `plaintext ‖ AAD` is a source of collisions rather than a combiner: another pair with the same concatenated representation produces the same nonce. The same argument already appears at K1, where `HKDF-Extract` over concatenation is called correct **only** when both shares have fixed lengths. Length must therefore appear explicitly in the preimage, as `u32be(len) ‖ value` for each part. The normative form from version 3 is `ikm = u32be(len(pt)) ‖ pt ‖ u32be(len(aad)) ‖ aad`. Both lengths must fit u32; otherwise the operation rejects. AAD is the associated data supplied to that same AEAD invocation:

| Seed | AAD in ikm |
|---|---|
| K17 `seal-nonce` | sealing `aad`: `policy_hash` for slots (§3.3), `device_fpr` for the challenge and wire shares (`derivations_wire.kat`) |
| K18 `wrap-nonce` | `core_hash` (§3.2) |
| K19 `frame-nonce` | chunk associated data (§6.1, `chunk_aad.kat`) |
| K20 `meta-nonce` | private-metadata associated data (`aead::metadata_aad`) |

**What this is NOT.** This is not SIV and does not provide SIV properties: full SIV would put the key into the salt, whereas the key does not participate here. Only the demonstrated collision is closed — nonce equality under different AAD. Equality after a complete repeat of generator state AND identical plaintext and AAD remains: the nonce is deterministic by construction, an accepted cost of hedging (model S-13). This item does not reopen migration to AES-GCM-SIV: the `aes-gcm-siv` promise was removed from the specification on 2026-08-28 (`docs/plan.md`, `D-measurement`) precisely because seeding provides the required property.

**Cost.** Writer-produced bytes change, requiring reissuance of `tests/kat/nonce_seeds.kat` and every reference artifact whose nonce is seeded, together with cutting version 3 (I-14). The reader does not change at all: it takes a ready-made nonce from the file and never computes it (I-1).

## RENAMING 2026-09-08: Shape Shifter → Close Crate, Open Crate core

The only change in format history that **adds no semantics yet changes every key byte**. It has its own section for exactly that reason: in six months, “why are the labels `CC/v1/` when the core is called Open Crate?” would otherwise have no recorded answer.

**What changed.**

| | Before | After |
|---|---|---|
| Magic (first 8 bytes) | `SSHIFTR1` | `CLOSECR1` |
| Domain labels (§3.6) | `SS/v1/…` | `CC/v1/…`, all 38 |
| Extension | `.ss` | `.cc` |
| Core crates | `ss-format`, `ss-crypto`, `ss-policy`, `ss-engine` | `oc-*` |
| Product crates | `ss-*` | `cc-*` |
| Programs | `ss`, `ssa`, `ssview`, `ssbroker`, `ssengined` | `cc`, `cca`, `ccview`, `ccbroker`, `ccengined` |
| Environment variables | `SS_HOME`, `SS_DEVICE_BINDING`, … | `CC_HOME`, `CC_DEVICE_BINDING`, … |
| Key directory | `%USERPROFILE%\.shapeshifter` | `%USERPROFILE%\.closecrate` |

**Why labels, not just filenames.** A domain label is not decoration: it enters `info` for every derivation, hence EVERY derived key. Keeping `SS/v1/kek` in a format named Close Crate would permanently freeze a fossil of the old name into it: anyone opening the file in a hex editor would see it, and every other implementation would have to reproduce it without knowing its origin.

**Why now, the key point.** No container in the old format was ever released. Today, changing a label is renaming; after the first released file, it would become an unrepairable compatibility break: a key derived under the old label cannot be derived under the new one, and no one can open the file. The inexpensive window for this step is “today exactly”, not merely “before it is too late”.

The last three rows do not concern format bytes at all, but belong in the same table: someone reading `cc --help` and setting `SS_HOME` gets no error, but SILENTLY A DIFFERENT key directory. This is precisely where half-renaming is more dangerous than no renaming.

**The cost, paid openly.** ALL vectors `tests/kat/*.kat` and all reference artifacts `tests/golden/` were reissued. This is legitimate reissuance under I-14: the decision is recorded here and precedes the bytes rather than justifying them afterward.

**Lesson applied 2026-09-09: the version 5 witness was captured immediately.** `tests/golden/v5/` was created while the writer still produced version five, rather than postponed until version six was cut. Postponement would repeat what happened to witnesses 1–4: by the day they were needed, nothing could produce them. Today's check is tautological; it becomes meaningful the first time the writer advances.

**Versions 1–4 have no witnesses anymore, and here is why this is not a loss.** Archives `tests/golden/v1/`…`v4/` held old-format files with the old magic and keys under old labels. The current reader does not open them, nor should it: magic differs from the first byte. Nothing can reissue them: no writer for versions 1–4 exists; there is one writing constant.

Nor do they have anything to witness. Their purpose is to prove that a file produced by an older version opens in a newer reader, but no such file was released to anyone. Keeping four tests that must fail is worse than recording the reason. The property “the reader accepts `container_version` in 1–5” remains and is checked structurally without artifacts: it concerns the range, not particular bytes.

**Version numbering is NOT reset; this is a decision.** Starting `.cc` at version 1 is tempting: new magic, new labels — apparently a new format. Rejected because the version counts DESIGN, not names: `FIRST_EDITING_VERSION`, `FIRST_COAUTHORS_VERSION`, `FIRST_ACTION_BINDING_VERSION` are four, `FIRST_HARDWARE_HYBRID_VERSION` is five, and each boundary means “semantics that did not exist before”. Resetting the counter would collapse every boundary to one, losing the very purpose of versions: answering “what appeared when”. The name changed; design history did not.

**Open Crate and Close Crate.** The core consists of five pure crates (`oc-format`, `oc-protocol`, `oc-crypto`, `oc-policy`, `oc-engine`): no I/O, clocks, or generator; building for `wasm32-unknown-unknown` is the control check. This is Open Crate. Everything else — viewer, broker, server, platform wrappers — is Close Crate, the product built on that core. The boundary is not new: the purity gate already guarded it; now it has a name visible in every `use` line.

## VERSIONS 1–4 RETIRED 2026-09-19

**Decision.** The reader accepts `container_version` in `MIN_READABLE_CONTAINER_VERSION..=MAX_READABLE_CONTAINER_VERSION`; today both bounds are five. Containers numbered 1–4 are rejected just like 0 or 6: `UnsupportedContainerVersion`. Numbers 1–4 are retired and never reused; numbering is not reset — a version still counts design, not names.

**Why.** The promise that “versions 1–4 are readable” applied to an empty set. The renaming section states explicitly that no old-format container was ever released, and renaming and cutting version 5 occurred on the same day. Nobody has a version 1–4 file with magic `CLOSECR1`. Moreover, the promise was checked only by the NUMBER RANGE: a probe built a header with today's encoder and changed its number. Nothing checked version 1–4 layouts; there are no witnesses and nothing can produce them. An unverifiable promise is worse than no promise: it looks like compatibility and becomes a hole the first day someone relies on it.

**What this decision does NOT do.** Version 5 bytes do not change; KATs and golden files are untouched. Version branches in codecs (`v >= 2` for P-256, `FIRST_HYBRID_VERSION`, `FIRST_EDITING_VERSION`, policy versions) and their constants REMAIN: frozen vectors call those codecs directly, and collapsing the branches would touch the vectors (I-14). There is one boundary — the range check in `verify_and_parse`. Everything below it no longer receives versions 1–4 from files but remains executable for vectors. The version 1–4 rules in this document remain the normative description of the components of version five.

**The resulting rule and its duration.** Until the first externally distributed file, the reader supports only the writer's version. Pre-release versions are internal design history, not obligations to anyone: if version 6 is needed, it is cut and version 5 reading is removed in the same way. I-14 remains fully in force: bytes change only with a recorded decision and version number. **This rule ceases on the day of the first external file, and that day must be recorded here** — from then on, the lower readable bound must never rise again.

## VERSION 5 CUT 2026-09-08

One item: **`kem_id = 5`, MLKEM768-P256**. The construction, source, and selection rationale are in version 4 item 1, subsection “Hardware hybrid”; this section describes what version 5 does to bytes and promises.

**Lengths.** `key_fpr` = 1249 (`pk_M(1184) ‖ pk_P256(65)`), `enc` = 1153 (`ct_M(1088) ‖ eph_P256(65)`). Both are functions of (version, `kem_id`), as for predecessors: versions 1–4 do not define shapes for number five and skip such a slot rather than read it against another mechanism's measure.

**Purpose of this version.** The classical half resides INSIDE the TPM (P-256 is the only ECDH provided by Platform Crypto Provider), the post-quantum half in a file alongside it. An adversary needs both: disk theft yields only the second, a quantum computer only the first. No previous mechanism offered this: X-Wing's classical half is X25519, which the TPM cannot perform.

**The hardware identity is SEPARATE.** The hybrid gets a new P-256 key in the TPM (`cc_keystore::pcp::hybrid_key_name`, a suffix to the device-key name) and an independent ML-KEM seed (`device-mlkem.key`). The previous classical TPM key is not reused; the halves share no seed: recovering the hardware scalar from software would negate non-extractability.

**The reported tier is the actual tier.** A `kem_id = 5` slot opens only with a real TPM key and yields `Binding::Hardware`; without a TPM, the slot is skipped. No software substitution exists: it would present something as a hardware hybrid that is not one, making the reported tier false.

**What version 5 does NOT do, which must be understood before use.**

Shares reach people through more than slots. A bequest to an heir and author approval issue share B THROUGH THE SERVER; before 2026-09-14 both entry points were hardwired to classical cryptography (`device_kem` literally 1); server share A was classical too. **Since stage 4 (below, “Stage 4 COMPLETED 2026-09-14”), both entry points support X-Wing and MLKEM768-P256**. Paragraphs before the stage 4 marker are decision history, retained because they explain the resulting design. The coauthor quorum never emits share B and is unaffected by the recipient's mechanism.

**THE REASON FOR REJECTION WAS MISIDENTIFIED BEFORE 2026-09-09, and this deserves an explicit correction.** The text said “activation and request frames are frozen and cannot carry thousands of bytes”. Both halves are false. The request ENVELOPE is frozen (transcript `u8(kind) ‖ body` and tail `MAC(32)`, vector `derivations_wire.kat`), while its body is ordinary TLV; the device public-key field is declared VARIABLE length and checked by mechanism (`oc_protocol::activation`, `DEVICE_PUBLIC`). The message limit is 2 MiB (`cc-authority::serve::MAX_MESSAGE`), leaving roughly a thousandfold margin for a key of just over a thousand bytes.

The fifth mechanism is rejected by a **VALIDATION RULE**: the server requires `device_kem` = 1 for activation and requests (`serve.rs:596`, `:728`); the client requires it during approval (`decide.rs:399`). The rule is not arbitrary: for X25519, the fingerprint IS the key; for other mechanisms, the server establishes the relationship — the very intermediary against whom inheritance and out-of-band fingerprint comparison protect. Until 2026-09-09, the actual blocker was the absence of a normative answer to WHAT constitutes a hybrid-key fingerprint. The answer is below (K27); mechanism-aware handshaking remains.

Thus these entry points were CLOSED for version 5 containers, not downgraded. An open classical entry point would reduce the hybrid to decoration — exactly the error version 4 had already made and corrected.

**This text previously concluded: “by packing a version 5 file today, the author chooses irrecoverability PERMANENTLY: the header is signed, slots are not repacked, and lifting the restriction tomorrow does not affect an already released file”. This was REMOVED on 2026-09-14 as false, even under its own premises.** Three lines earlier, the same paragraph said these entry points do not affect format bytes and need no version 6 to open. The opposite conclusion follows: an author's decision and a bequest are documents (`docs/protocol.md` §10, §11) issued for `file_id` and signed by the key in the header. They require no header repacking; an opened entry point works for EVERY previously produced file whose author slot remains intact. Irrecoverability of existing version 5 files was a property of the PROGRAM, not the files, and stage 4 removed it; a probe on the frozen reference `tests/golden/v5/basic.cc` confirms this (`granted.rs`, `an_approval_on_a_hybrid_name_is_accepted_for_a_frozen_earlier_container`). What is truly irreversible is loss of the author's device without a second author slot (`deferred.md` §26, F-26); stage 4 neither changes nor promises to change that.

These entry points were closed by the server and client revisions, plus — before 2026-09-09 — the missing fingerprint definition. The definition is now supplied (K27 below); mechanism-aware handshaking is stages 2–3, and the client entry points are stage 4.

#### Device fingerprint for every mechanism — DECIDED 2026-09-09, derivation K27

**Decision.** Device fingerprint `device_fpr` is defined for EVERY key-agreement mechanism, not just X25519:

| `kem_id` | `device_fpr` |
|---|---|
| 1, X25519 | the public key itself, 32 bytes, unchanged; frozen by K11, K21, K23, K24, and the `Hello` layout |
| 2, 4, 5 | `SHA-256("CC/v1/device-fpr" ‖ 0x00 ‖ u8(kem_id) ‖ device_public)` |
| 3, RSA-OAEP | undefined: variable-length key, reserved mechanism |

Code: `oc_crypto::kdf::device_fpr`; vectors: `tests/kat/derivations_wire.kat` (`device_fpr_p256`, `device_fpr_xwing`, `device_fpr_mlkem_p256` — ADDED, not reissued: I-14 forbids changing frozen material, not introducing new material). The label `"CC/v1/device-fpr"` is added to §3.6. Number K26 is retired (the withdrawn X-Wing seed derivation, version 4 item 1) and is never reused — the same rule as for K2.

**The rule for which the fingerprint exists.** A fingerprint is a COMMITMENT to a key. Anyone receiving `(device_fpr, device_kem, device_public)` must check `device_fpr == device_fpr(device_kem, device_public)` BEFORE using any of the three: before request-queue insertion, share sealing, or journal recording. For X25519 this is the comparison already present in `request_access` and `serve.rs` under `device_kem == 1`; the condition is removed, the comparison remains — one for every mechanism. Key length is checked by mechanism, not accepted “as received” (I-8).

**What this closes.** Findings N-1 and N-4 from the 2026-09-06 review generalize to every mechanism: an intermediary sending another person's fingerprint with its OWN key fails the comparison — its key does not hash to the other fingerprint. A person still compares ONE 32-byte string over a second channel, printed by `cc keygen`; it now commits to a specific key of any length.

**Why the shape is asymmetric, deliberately.** A uniform hash for all mechanisms would be cleaner — and would require reissuing K11, K21, K23, K24, and the `Hello` layout without adding a single security fact: the X25519 key is already 32 bytes and already commits to itself. Asymmetry is the price of obeying I-14, explicitly named here rather than hidden in code.

#### Stages 2 and 3 COMPLETED 2026-09-09

**Stage 2 — mechanism-aware handshaking.** `Hello` gains a field pair — `device_hybrid_kem` (tag 4) and `device_hybrid_public` (tag 5) — and `Challenge` gains a third half (tag 3). Parsing requires the complete pair: a mechanism without a key is a claim without a presentation; a key without a mechanism is bytes with no reference length. Length is checked BY mechanism (I-8): 1216 for X-Wing, 1249 for MLKEM768-P256.

There is ONE challenge secret across all halves, and the echo is computed over their concatenation. The key consequence: opening only one of two halves does not prove the device's possession. Possession of the hybrid key becomes inseparable from possession of the classical key — precisely why the hybrid is placed in the handshake rather than declared in a request. The classical pair remains mandatory: `device_fpr` enters the frozen lease and journal formats; the hybrid supplements it rather than replacing it.

The SERVER derives the hybrid key's name using K27 instead of taking anyone's word for it. `Proven` carries both proven names; `Proven::proves` compares a supplied name to both in constant time, without returning early on the first match (I-13).

**Stage 3 — entry points take the mechanism from the triple.** The `device_kem != 1` rejections are removed for activation and requests. Two MANDATORY checks replace them; one is insufficient: the fingerprint must name the supplied key (K27), and it must be PROVEN in this conversation. The first detects an inconsistent triple; the second detects a consistent but foreign triple. Requests intentionally lack proof, as before (anyone may ask), so only the first check remains there, and it is sufficient: it is precisely what closes N-4.

Share A is sealed using the hybrid (`seal_xwing`, `seal_mlkem_p256` in K11). The earlier argument that “the key arrives in an activation frame whose shapes are frozen and cannot carry thousands of bytes” was doubly wrong and has been removed — see version 4 item 1 above.

No classical downgrade occurs anywhere: that would be the entry point through which a post-quantum container lost its protection.

**Neither stage changed container bytes.** Slot `key_fpr` under the author's signature remains the complete public key, as §3.3 specifies. Changes concerned the `Hello` body, `Challenge` body, and validation rules — all outside the header and the frozen request envelope.

**This is not the same as “broken recovery”.** Irrecoverability can be a property, and here it is: a document someone can always retrieve is a document someone can retrieve. The distinction to preserve is not “recovery or no recovery”, but this: explicitly chosen irrecoverability is protection; recovery that silently downgrades encryption is a vulnerability. The latter is what is closed here.

What remained, and why this was not a stopgap: these entry points were hardwired to classical cryptography by address shape, not by wire encoding. `cc heir --device` accepted X25519, where FINGERPRINT AND KEY are the same value; the author entered one string without consulting the server. In a hybrid they differ, solved just as for a recipient: the key is passed in a FILE (written by `cc keygen`), the server is still uninvolved, and the instruction travels in variable-length TLV, not a frozen frame. Sealing to a hybrid requires only its public half; the heir needs the TPM when opening, not the author when packing. Completed in stage 4 below.

#### Stage 4 COMPLETED 2026-09-14 — mechanism-aware approval and bequest entry points

**What is enabled.** Author approval (`cc approve`, viewer panel, SDK `grant`) and a device bequest (`cc heir --device`) emit share B to the recipient key using the SAME mechanism in which it was presented: X25519, X-Wing (`kem_id = 4`), MLKEM768-P256 (`kem_id = 5`). The recipient collects the decision and opens the share under its own name. Container bytes, tag registry, domain labels, and vectors did not change: `golden` comparison is byte-for-byte; `derivations_wire.kat` is untouched.

**The implementation rules are normative for clients.**

1. *Device name and comparison (K27).* Anyone emitting share B to `(fpr, kem, public)` compares `fpr == device_fpr(kem, public)` in constant time BEFORE sealing (`cc-cli/src/decide.rs`, `seal_share_b`; approval checks again before the comparison gate and slot opening, so substitution rejection costs neither a verified-fingerprint record nor an extracted share). A person compares ONE name over a second channel: the name `cc ask` prints to the requester as “Your fingerprint”, the name `cc requests` shows the author, and the name addressed by the decision. For a hybrid this is the K27 name, not the classical key.
2. *Request mechanism follows file strength, not someone else's slot.* File strength is author-slot strength (the rule above that “the author slot is no weaker than the recipient slot”): a classical file is requested classically, X-Wing via X-Wing, hardware hybrid only via mechanism five. A device without a TPM key receives an explicit REJECTION for a mechanism-five file, not a request weaker than the file: the specification permits four where four is required, and only five where five is required. Falling back to classical share A during activation (`activate.rs`) concerns one issuance under one lease; it does not extend to share B, which remains with the recipient forever. The recipient and heir need not appear in the header: no step reads a recipient slot (`cc-cli/src/granted.rs`, `ask_kem`, `file_strength`).
3. *Collecting decisions under each own name.* A device has up to three names: classical key, K27 of X-Wing, K27 of MLKEM768-P256 (the last only with a TPM key: substituting a software half would falsely claim to be a hardware hybrid). `cc collect` queries the server under each name in a separate conversation PROVING THAT name (classical or hybrid handshake; the server returns a decision only under the proven name). Answer selection: approval under any name outranks denial under any other — denial is not revocation; `revoke` performs revocation. Decision numbers across names are not compared (the queue has its own numbers; the bequest has `HEIR_SEQ`; the server orders them, bequest first). Every approval carries the same share B, so distinguishing them is unnecessary (`granted::pick_answer`).
4. *Opening a share uses the named identity's mechanism, not trial and error.* The addressee is compared against all of the device's names in constant time without early exit (I-13); the mechanism and fingerprint in `info` come from the matching name. The former “try until it opens” loop always built `info` with the classical key and could never open a hybrid share; rejection would look like “share cannot be unwrapped”. An opening error is rejection, not fallback to another mechanism.
5. *A lease under the same name.* A lease is issued to the name under which the device activated (K27 for a hybrid file), and the decision engine compares it to the device name as a single value (`oc_policy`, “lease issued to another device”). The decision context names the device using whichever of its names appears in the lease (`access::device_facts_for`), selecting among its OWN names in constant time. A foreign lease name is not accepted; the decision engine rejects it itself. Before stage 4, the context always named the classical key, so `cc activate` on a hybrid file issued a lease that `cc unprotect` rejected on that same device — discovered by the stage's end-to-end probe.
6. *P-256 (`kem_id = 2`) is not partially enabled.* The build can seal to it but cannot unwrap it for the recipient, and no request uses it; approval rejects explicitly before the gate and slot. The recipient's TPM P-256 key operates through mechanism five.

**What is confirmed, and how — three distinct evidence levels that must not be conflated.**

* **X-Wing approval — the full end-to-end path is confirmed** by a probe through binaries and a live socket (`crates/cc-authority/tests/hybrid_doors.rs`): a new recipient absent from the slots, `ask → approve → collect → unprotect`, with controls “closed before approval”, “closed again in a clean environment without the decision”, and “the queue name, `cc ask` name, and `--fpr` name agree”. X25519 and code-path heir regressions use the same suites.
* **X-Wing bequest — the full end-to-end binary path (2026-09-15).** Through binaries: designation using a key file, the provision with its K27 name, and the heir's `collect` under its own name before the deadline (`hybrid_doors.rs`). The silence interval in days, bequest issuance, collection, and file opening by the heir also run through binaries on a stand with controlled process clocks (`crates/cc-authority/tests/stand_heir_hybrid.rs`, accelerated single-host stand run): restarts before and after the deadline; an unrelated hybrid-key holder gets nothing from the server; classical denial does not hide a hybrid bequest; ordinary approval does not suppress it; controls “closed before deadline” and “same profile without the decision is closed”. In-process `dead_hand.rs` probes remain as fast checks.
* **MLKEM768-P256 — in software and on one machine's live TPM (2026-09-15):** the full share B path with the classical `KeyAgreement` half in memory (`granted.rs`, `the_hardware_hybrid_share_path_holds_with_a_software_p256_half`); probes `hybrid_doors.rs::a_newcomer_with_a_hardware_hybrid_is_approved_collects_and_opens` and `dod_scenario.rs::a_recipient_with_a_hardware_hybrid_opens_a_foreign_file` (under `#[ignore]`, require TPM) ran on Intel PTT, TPM 2.0, firmware 700.19.5.2098. Before running, the first was not executable: the author packed with software binding, while the engine requires the author's hardware hybrid for a hardware recipient — the probe was fixed, not the rule. Other TPMs are unverified.

**What the stage does NOT do.** It does not touch editing, attestation, recovery of a lost author key (F-26), or a second author slot (below). It does not change the share A activation mechanism. It does not enable P-256.

A **second `AuthorDevice` slot on another physical device** could replace closed entry points — not a “backup recipient”, as this text said before 2026-09-08: a recipient slot carries only share B and is useless without the server. Such a path must carry BOTH shares, introducing another sufficient path to `CEK`.

It MUST NOT be counted as a “third door” under `crates/cc-cli/tests/share_doors.rs`. This caveat is needed because the first revision counted it that way: that probe counts ways to issue share B OUTSIDE the container, not paths to `CEK`. The object and the count differ.

It is NOT IMPLEMENTED and is not unfinished work belonging to this version: it is a separate decision to record in the threat model (`deferred.md` §26.2, `threat-model.md`). The argument that “a hybrid key has no ADDRESS SHAPE”, previously given here as the reason for closed entry points, was removed by stage 4: the address shape is a key file plus a K27 name. A second author slot solves a DIFFERENT problem — loss of the author's device — and opening these entry points does not solve it: they issue share B, and without server share A and without the author there is no one to issue it.

## VERSION 4 FROZEN 2026-09-08 (opened 2026-09-07)

Its contents are [items 1–12 of the former version 3 decision](#version-3-opened-2026-08-24), without copying or changing that text. All mentions of version 3 in those items and the corresponding registries now mean version 4. The rule holds: **a version is the set of bytes it can read**. Version 3 does not accept non-executable editing, hybrid, or `action_binding` semantics.

**Cut on 2026-09-08; here is how it differs from cutting version 3.** Version three was cut with ONE item because the others were not executable — “rule 4 requires executable semantics: hybrid KEM and editing are not yet executable”. Here all twelve are executable, which is a condition for cutting, not a consequence:

* **`kem_id = 4`** — `oc_crypto::xwing` constructs X-Wing on `ml-kem`; `tests/kat/xwing.kat` compares it to the draft's vectors; `seal_xwing` and `open_xwing` seal and open a slot;
* **editor signature** (items 2–8, 11) — mutable-region tag 6, `oc_format::content`, with RSA-PSS-SHA256 and exclusion of only the `signature` subfield;
* **`action_binding`** (items 9, 11) — policy tag 7, `oc_format::policy_codec`, and `oc_policy::Policy::binding_for`;
* **coauthor roster** (item 12) — header tag `0x8001`, `oc_format::header::Coauthors`.

**The writer has produced tag `0x8001` since 2026-09-15** (local-plan task B2). Previously it was parsed and encoded, but the writer set `coauthors: None`. The roster is packing-request field `oc_engine::PackRequest::coauthors`; sources are `cc protect
--coauthor <key>… --coauthors-threshold M [--without-me]`, `cc_sdk::Protect::coauthors`, and WASM wrapper `PackOptions::coauthors`. One roster rule applies — `Coauthors::validate`, as in encoder and parser: threshold zero only without keys (“there will be no coauthors”); otherwise 1 through `MAX_COAUTHORS` distinct keys and a threshold no greater than their count. The author's key must belong to a nonzero-threshold roster; self-exclusion is possible only with the command-line option (`--without-me`); the SDK and wrapper have no such option and reject it. Version bytes did not change: the tag has been normative since version 4, and containers without a roster remain byte-identical. **A reference was added, not reissued (I-14):** `tests/golden/coauthors.cc` and its witness `tests/golden/v5/coauthors.cc` are `basic.cc` with the roster “reference author and signing key with seed `0x06`, threshold 2”; other reference files are untouched.

Version 3 references were captured before switching the writer and lived in `tests/golden/v3/`; the 2026-09-08 renaming removed them — nothing could produce version 3 anyway, since there is one writing constant.

**What cutting did NOT do, explicitly stated.** Item 5 (“where the reference `version_counter` value comes from during verification”) remains non-normative: the field format is defined and frozen, but where the reader gets its comparison value is a VALIDATION decision belonging to the editing phase, not the bytes. Sealing a share to a DEVICE using a hybrid (K11, K12) is outside this version: the key arrives in an activation or request frame. The argument present here before 2026-09-09 that “their shapes are frozen and cannot carry 1216 bytes” was wrong (analysis above, version 4 item 1). The actual reason is the same elsewhere: the `device_kem` = 1 rule and the undefined hybrid fingerprint. The P-256 hybrid for TPM-key recipients is `kem_id = 5` under RFC 10024, hence version 5 (`docs/threat-model.md` §2).

### Multiple CEKs and per-chunk keys — NOT PART OF VERSION 3

**Decided 2026-08-25, before cutting artifacts.** The question was raised now because version 3 artifacts had not been reissued: while that remains true, an addition costs nothing; on the day of cutting it costs version 4. The answer was recorded before cutting as required: “no”.

The mechanism would enable three wishes at once: permissions on parts of a file, a “false bottom” (different content for different readers), and progressive key issuance. None is included.

**1. The mechanism has no consumer.** Two paragraphs above, this document names the defect for which version 1 paid: “a registry number with no shape”. Freezing an unused key-scheme branch is the same defect at a larger scale: a shape without an executor, testable only by our own tests against our own invention.

**2. The main wish is wrongly attributed to the format.** A “false bottom” is not a container task. A container frames ONE plaintext of ONE length, and that length is public (§9, decision S-9: `total_len` is explicitly public). Multiple CEKs give a recipient the first reading with visible holes of known size, not a second reading: the recipient sees exactly where content was withheld and how much. This is censorship announcing itself, not another document.

A true second reading is produced by a shadow generator on the author's machine — another document assembled anew, not redacted. It costs the format no bytes; that is the difference between “expensive and wrong” and “free and right”.

**3. This changes the key scheme.** CLAUDE.md forbids changing the cryptographic scheme incidentally to another task: only a separate decision permits it. Version 3 already carries two things, neither yet normative — the hybrid construction is unchosen, the editor-signature layout unspecified. A third, larger change would delay both.

**4. The window argument is weaker than it appears, the central point.** It is true that adding this after cutting costs version 4. But versions here are a range, not a burden: versions 1 and 2 are declared readable forever, the reader checks a range, and two bumps have already occurred. The third bump's cost is bounded and known.

The cost of a frozen unused key-scheme branch is unbounded: every future reader, every other implementation, and every audit bears it forever. Trading a known bounded cost for an unknown unbounded one to save one bump costs more.

**When to reopen:** when any of the three wishes has a WORKING consumer — code that would use per-chunk keys today if the format had them. Code, not an intention or plan item.

### K6 remains derived from CEK

**Decided 2026-08-25 by the same procedure.** The question was whether to detach the mutable-region MAC key (K6) from `CEK` so someone unable to read the content could verify the region.

**The answer is no; the premise is wrong.** A MAC is symmetric: the verification key is also the forgery key. Giving K6 to an unrelated party would confer the ability to rewrite and reauthenticate the mutable region, not merely verify it. “Third-party verifiability” cannot follow from a MAC under any key derivation — from `CEK` or anything else.

Authenticity of edits comes from the **editor signature**, already version 3 item 2. It is asymmetric: anyone can verify, no one can forge. That is precisely the requested property, already present.

**Rollback protection does not need detachment either.** A reader has `CEK` by construction because it reads; it checks the MAC, takes `version_counter`, and compares it with the value signed by the server in the lease. No party lacking `CEK` but needing to verify the mutable region exists in this scheme.

Detachment would additionally introduce a second integrity mechanism alongside the signature — two ways to say the same thing, diverging on the first edit.

**When to reopen:** when a named party needs to establish that the mutable region is undamaged without permission to read AND without needing authenticity, and neither the author's header signature nor the editor's region signature suffices.

### Access request — the product default

**Decided by the product owner on 2026-08-27.** This REPLACES the decision recorded here several hours earlier (“right of first opening”, where the server held share B). That decision was short-lived and replaced because it was worse, not because it was incorrectly implemented. The analysis below is complete rather than summarized because its mistake is instructive.

**What is introduced.** A recipient lacking the share sees an invitation to REQUEST access rather than a refusal. The request goes to the author. The author approves or denies. Approval supplies share B sealed to the requesting device's key.

A second path serves “no time to ask”: the author supplies a claim code in advance, and the recipient opens immediately without asking anyone.

Both paths are defaults. Other addressing methods (named key, author only) remain available but require explicit selection.

#### Why this is better than everything previously considered

Previously the reasoning here seemed exhaustive: three wishes are incompatible; choose two.

> **(a)** the recipient is not named in advance; **(b)** nothing travels over a second channel; **(c)** the server cannot decrypt.
>
> If nothing travels over a second channel and no recipient is named, everything needed for opening lies either in the container or on the server. It must not all lie in the container. Therefore the server holds what is missing.

The reasoning is correct — and **incomplete**. It had a fourth premise, unstated and thus invisible: **the author is offline**. While that premise remained silent, the conclusion looked like arithmetic.

An access request removes that premise. The author participates and always holds both shares (the `AuthorDevice` slot, §3.3, carries `secret_A‖secret_B`). The author can give share B to anyone at any time without touching the container. All three wishes are satisfied simultaneously.

The lesson worth recording beside the conclusion: **“impossible” almost always means “impossible under premises I have not listed”**. Those premises must be stated explicitly.

#### What this costs the format — precisely nothing

No new slot kind, version, or artifact reissuance. The default container is the same one the build produces today: a `Server` slot with share A, an `AuthorDevice` slot with both shares, and no recipient slot.

Access is issued OUTSIDE the container as a separate sealed block of the same shape already returned by the server (`enc ‖ nonce ‖ ct`, §3.5). The recipient stores it beside the lease, exactly as share A is stored today.

This also answers item D-scheme-3, where the build and product plan disagreed on the default: **the build was right**. The plan's “seamless mode by default” is replaced by access requests. The build did not need rewriting to match the plan; the plan needed rewriting.

#### Derivation

Share B sent from author to device is sealed with label `"CC/v1/b-to-device"`, prefix-free relative to `"CC/v1/a-to-device"` (server share A) and every other label (I-12).

```
info = "CC/v1/b-to-device" ‖ u8(kem_id) ‖ file_id(16) ‖ device_fpr(32)
```

There is NO lease number here, a significant distinction from K11. The K11 number checks blob/lease CONSISTENCY, not enforcement: secret A is identical across every lease for a file and resides unwrapped on the device after the first opening, so “unusable under another lease” is true of the blob, not the secret. Effective revocation rests on the client's honest decision engine and the server refusing renewal (F-18). The former wording “and this makes revocation effective” exceeded the truth (cryptographic review 2026-09-06, N-7). Share B is not lease-bound because it is the AUTHOR'S decision, not the server's, and must survive lease changes: otherwise every renewal would require fresh approval, turning one-time consent into a subscription to interruptions.

A consequence that must be stated: **an issued share B cannot be revoked.** Revocation acts through the server, which stops issuing share A, preventing file opening. This is the same property as a claim code, with the same honest formulation: the file is not destroyed; it stops opening.

#### What the server sees

It is an intermediary, and its mediation is blind. It carries the file identifier, requester's public key and fingerprint, request time, author's decision, and an **opaque sealed block** it cannot open: the block is sealed to the device's key, not its own.

It sees metadata: who requested access to which file and when. That is the price of mediation, identical to activation (`docs/protocol.md` §9.2). It sees content in no mode — now an UNCONDITIONAL statement, with no mode caveat.

#### What happens while the author remains silent

The request waits. The recipient sees “awaiting approval”, not a denial or an error. Waiting has no deadline: the author may choose not to answer, and “did not answer” is not “denied”.

An author who loses the device key can no longer approve anything — exactly the same situation in which the author cannot open their own files, addressed by the same measure: preserving the key directory (see `cc uninstall`, which deliberately leaves it untouched).

#### Seamless mode — question closed

A mode in which the server holds both shares is NOT part of the product, either as a default or a flag. The case motivating it — “no second channel at all” — is covered by access requests without that cost. There is no reason to retain a mode that cancels the product's central promise: a flag that makes life easier at the expense of security eventually becomes someone's default, discovered during incident analysis.

**The product promise is therefore unconditional: the server cannot read the document.** No “if”, no footnotes, in every shipped mode.

**Artifacts.** `tests/kat/*.kat` and `tests/golden/*.cc` are reissued together with version 3's normative values — **not now**, but once the hybrid construction and editor-signature layout are specified above. I-14 permits reissuance precisely and only this way: with a decision recorded here, not following a failing test. Version 2 artifacts are retained separately, as version 1 artifacts were retained in `tests/golden/v1/`, for the same reason: nothing will be able to reissue them. (Retrospectively: the renaming on 2026-09-08 itself invalidated this procedure — a snapshot under the old magic ceased to open. The rule of capturing a witness BEFORE switching the writer remains; no snapshot survived it.)

## EDITING IS EXECUTABLE 2026-09-17 (D1): tag 6 of versions 4–5 gains meaning

Local-completion plan decision, item D1. Tag 6 bytes have been normative since version 4 (item 11 of the version 3 decision); until today, the pieces making them **executable** were missing: the counter reference source, the contents of `certified_by`, what is signed, and what a session head means. All are specified here, **without changing the version number**. There are three reasons; the first is decisive.

1. **An editor cannot change the file version.** `container_version` is in the signed header; editing does not and must not touch it. A new version would mean only files produced afterward could be edited, leaving version 4–5 files forever with a parsed but non-executable tag — precisely the “number without implementation” forbidden by rule 4 (“How to change the format”).
2. **No released file carries tag 6.** No version 4 writer exists; the version 5 writer sets `editor: None` and `version_counter = 0`. Giving the tag meaning today changes no existing file's meaning.
3. **The transition is explicit, not silent.** Before this decision the reader rejects every nonzero counter (`ContentEditedByUnknownParty`): it refuses an edited file rather than misreading it. Writing an edit requires a certificate the author issues in a SEPARATE action after this decision (item B): an `edit` permission previously placed in the policy does not by itself enable editing.

The writer of fresh files is unchanged: KATs and golden files for versions 1–5 are untouched. New vectors cover only new constructions (`tests/kat/edit.kat`).

### A. The `version_counter` reference (closes item 5's “NOT YET NORMATIVE”)

* An unedited file has counter 0 and no tag 6. Tag 6 with a zero counter is rejected: an editor signature in a file nobody edited means a foreign region transplanted with a MAC.
* Each edit raises the counter **by exactly one** from the revision on which it is based (the base).
* **The reader's reference is this device's acceptance journal** (`docs/protocol.md` §3.1, “revision” kind). A counter below the highest accepted for the file is rejected (content rollback). The same counter with a different revision digest is rejected (two revisions under one number). Otherwise the revision is accepted and recorded before releasing the first byte, in the same order as a lease. Counter 0 is checked too: an unedited file after an accepted edit is a return to the old text.
* **The server's reference is the revision registry** (`docs/protocol.md` §9.12). An edit is published only after the server accepts its number: the successor to the last accepted number, on the same base. A second editor working on that same base receives “conflict” and has nothing to publish; it rereads the new base. If the server is unavailable, the edit remains unpublished with the editor (`cc edit --resume`), leaving the previous file intact.
* On first encountering a file, a reader accepts any correctly signed revision — explicitly trust on first encounter. History completeness comes from the server, not the reader.

The **revision digest** is `SHA-256` of the editor-signature transcript bytes (item C). It excludes the signature: PSS salt is random, and one revision must have one digest.

### B. `certified_by` — the edit-key certificate

Nested TLV, strictly ascending tags, all critical.

| Tag | Field | Value |
|---|---|---|
| 1 | `cert_version` | u8 = 1 |
| 2 | `file_id` | bytes[16] — the certificate is issued for a FILE, like device approval |
| 3 | `device` | bytes[32] — editing-device fingerprint (K27 for hybrid mechanisms, otherwise the key) |
| 4 | `editor_key` | bytes[256] — RSA-2048 modulus, exponent fixed at 65537 (item 7) |
| 5 | `not_after` | i64le, epoch seconds: the certificate is invalid after this instant |
| 6 | `issuer` | bytes[32] — issuer's Ed25519 key |
| 7 | `signature` | bytes[64] — Ed25519 `verify_strict` |

```
Transcript::new("CC/v1/editor-cert")
  .field(certificate body WITHOUT record 7)     u32le(length) ‖ raw bytes of tags 1–6
```

The issuer is the **author** (header `author_key`) or a key in the coauthor roster (tag `0x8001`); any other key is rejected regardless of signature validity. A certificate for another file is rejected.

**Expiry is judged by the acceptance journal, not a signature alone.** An expired certificate (by the reader's clock, with the same monotonic floor as a lease) does not admit a **new** revision, one absent from the device journal; this is what “old certificate” means. A revision accepted before expiry remains openable afterward: otherwise every edit would die with its editor certificate, while signature time without a timestamp (D3) cannot be proven. The cost is explicit: a device first seeing a revision after certificate expiry will not open it even if it was signed in time; the server (§9.12), not the reader, provides complete history. The server checks its own expiry at registration using its own clock.

“New key certified by the previous key” rotation and `TPM2_Certify` (item 10) are **not implemented**: replacing a key requires a new certificate from the author.

### C. Editor signature

```
Transcript::new("CC/v1/editor-sig")
  .fixed(core_hash)                          32 bytes (§3.2)
  .field(mutable-region body WITHOUT the signature subfield)
```

Exactly subfield 5 of record 6 is removed — its tag, length, and value (6 + 256 bytes). Record 6's own length remains unchanged in the resulting bytes; this is not a vulnerability: subfield 5 is mandatory and fixed-length, so its presence and size are unambiguous from the retained bytes. `core_hash` binds the signature to THIS header: a region transplanted to another file matches neither the certificate (`file_id`) nor the signature.

The signature is RSA-PSS-SHA256 (item 7) under certificate key `editor_key`.

### D. Session head

```
H₀ = SHA-256( Transcript::new("CC/v1/edit-session")
                .fixed(file_id).u64be(base counter).fixed(base root) )
Hᵢ = SHA-256( Transcript::new("CC/v1/edit-session")
                .fixed(Hᵢ₋₁).u64be(i).fixed(root of save i).u64be(length of save i) )
session_head = Hₙ,  n ≥ 1;  the file's tree_root and total_len are from save n
```

The session head binds a revision to its base: an edit made on another base has a different signature. The reader does not recompute the head (it lacks intermediate saves); the server checks it at registration (§9.12).

### E. Journal head

`journal_head` is the server-signed journal head **seen by the device BEFORE constructing the edit** (decision of 2026-09-21). The client requests it using read-only `JournalView` from the same server where it will register the revision, and verifies its signature with the same keys used to verify this file's leases (header anchor and accepted succession chain, §9.18 `docs/protocol.md`). An unverified head is never put into the signed block.

It asserts a LOWER BOUND on edit time — “the edit is no older than head H” — and the reader checks it offline against any later checkpoint from that server. It is NOT evidence of revision registration (registration follows signing), nor an upper bound. Without a head, the value is empty (item 11): no address specified, server did not respond, or response rejected. The edit is not canceled, and `cc edit` states the reason. Field bytes have not changed.

The previous wording was “returned by this device's previous revision registration”. That was false about the wire: the registration response (`Accepted`) has no body and reports no head.

### F. Opening order — replacement for §5.4 step 13

```
13. version_counter = 0: tag 6 must be absent; then step 14 is unchanged.
    version_counter ≠ 0:
      a) container_version ≥ 4, otherwise reject (as before);
      b) tag 6 is present, otherwise reject;
      c) the author's policy permits edit, otherwise reject;
      d) certified_by: parse; issuer is the author or a coauthor; Ed25519 signature;
         file_id matches; not_after has not expired OR the edition is already
         in the accepted-edition journal (item B);
      e) verify the editor's signature (item C) using editor_key;
      f) replace step 14: tree_root is authenticated by the editor and is not
         compared with original_root.
13a. Reference counter from the accepted-edition journal (item A), before releasing the first byte.
```

The order MAC → TLV parsing → editor signature (item 4) remains: items d) and e) follow step 11.

### G. Edit writer

* A frame whose plaintext has not changed is **copied unchanged**: the same nonce, ciphertext, and tag. Repeating the triple does not reuse a nonce on different text.
* A changed or new frame is sealed **only** with `seal_chunk_hedged`: nonce derives from a fresh seed AND plaintext (`frame-nonce`, I-1), so different text at the same index receives a different nonce even if the generator repeats. AAD is unchanged (`file_id`, index, algorithm).
* The tree, `total_len`, and `chunk_count` are recomputed; `version_counter` = base + 1, with overflow checking (no edit at `u64::MAX`).
* The entire file is written to a temporary file and published by replacement after server registration. Until replacement, the previous file remains intact and usable.
* **Editing requires the hardware binding tier**, regardless of policy: the editing key resides in the TPM (RSA-2048, PSS signature; items 7, 10). No TPM means no editing; viewing remains possible.

### Labels

`"CC/v1/editor-cert"` and `"CC/v1/edit-session"` are added; `"CC/v1/editor-sig"` moves from reserved to used. Prefix freedom is preserved: none of the three extends another.

---

## FOOTER AND TIMESTAMP 2026-09-17 (D3): mutable-region tag 5 gains meaning

Local-completion plan decision, item D3. The footer offset — mutable-region tag 5 — has been authoritative since the version 3 decision (item 6). Until today no footer existed and the reader rejected any tail after the last frame. A footer now **exists**, carrying exactly what item 6 permits: self-authenticating content, an RFC 3161 timestamp. The version number does not change, for the same reasons as editing (“EDITING IS EXECUTABLE”): no released file carries tag 5; the pre-decision reader rejects a file with a tail after its frames — it refuses the timestamp rather than accepting it incorrectly.

**Reconsidering the earlier rejection** (`docs/deferred.md` §7: “no CMS parsing dependency”). The arguments then concerned dependencies and parsing; today `x509-cert` and `der` are already in the tree (server attestation), `der` accepts only DER (rejecting indefinite lengths and nonminimal encodings), and our own `oc_crypto::rsa` verifies RSA PKCS#1 v1.5. No custom CMS parsing beyond the necessary subset is written; the `cms` crate is not used because its parser is broader than timestamp verification requires. Strictness and licensing requirements remain.

### A. Layout

```
... mutable region ‖ frames ‖ footer
footer = TLV, tags in strictly increasing order, at most 32 KiB
  tag 1  timestamp   TimeStampToken (RFC 3161, DER), at most 16 KiB
```

`footer_offset` is the **absolute** offset of the footer's first byte from the start of the file. Frames end exactly there; the footer extends exactly to EOF. The offset is read only from an authenticated body (after MAC, I-5) and compared to the frame end derived from authenticated `chunk_count` and `total_len`: any discrepancy is rejected. An unknown critical footer tag is rejected (I-7).

### B. Imprint

```
imprint = SHA-256( Transcript::new("CC/v1/footer-imprint")
                     .fixed(core_hash).fixed(tree_root)
                     .u64be(total_len).u64be(version_counter) )
```

The timestamp covers the whole file: header (through `core_hash`, I-3) and current content revision. A timestamp transplanted to another file or revision fails the imprint comparison and is rejected.

### C. Timestamp verification

In order; any mismatch rejects:

1. `ContentInfo` is `signedData`; `SignedData` version is 3, `eContentType` is `id-ct-TSTInfo`; exactly one `SignerInfo`; the signer's certificate is embedded (`certReq`);
2. `TSTInfo`: version 1, imprint hash SHA-256, imprint equals item B; `genTime` is parsed;
3. signed attributes: `contentType` = `id-ct-TSTInfo`, `messageDigest` = SHA-256 of `eContent`; `signingCertificateV2` (if present) refers to the signer's certificate;
4. signature: RSA PKCS#1 v1.5 SHA-256 over DER signed attributes (with the `SET` tag), using the signer certificate's key (2048/3072/4096);
5. signer certificate: `extendedKeyUsage` is critical and contains exactly `id-kp-timeStamping`; valid at `genTime`;
6. **trust** is a separate value: a chain to a root pinned on the device (`cc timestamp trust`), RSA-SHA256 certificate signatures, depth at most three. Without a chain, the timestamp is “authority signature valid, authority not pinned”; this is not rejection, just as an unpinned author is not rejection (§5.2).

This build **does not execute** ECDSA timestamp-authority signatures: such a timestamp is rejected with a reason.

### D. Who attaches the footer, and when

The author of an unedited file (`cc timestamp query` → any timestamp authority → `cc timestamp attach`). Attachment rewrites the mutable region with a new `footer_offset` and MAC; the author's header signature is unaffected. **An edited file does not receive a timestamp**: tag 5 lies under the editor signature, and attachment afterward would break it. A revision timestamp requires attachment before signing; this is not implemented.

The product has no timestamp-authority transport (HTTP rejected, `docs/protocol.md` §9.2): request and response are DER files.

### E. What a timestamp does not provide

A local authority's timestamp (stand) tests the program, not time: it provides no independent public time. Timestamps do not control access; “secured by blockchain” remains forbidden.

### Label

`"CC/v1/footer-imprint"` is added, prefix-free with the others.

---

## SERVER FRESHNESS IS DERIVED 2026-09-20 (K30)

**Container bytes do not change.** The format version and `tests/golden/**` remain untouched. What changes is WHERE the server obtains two freshness values, not their wire representation: they already appeared to the recipient as random numbers, never recomputed by it.

### Previous state

Two places took values directly from the generator:

1. attestation challenge — `crates/cc-authority/src/serve.rs`, `Request::AttestOpen` branch: 32 bytes from `fill_bytes`, then into the TPM assertion's `extraData` (K29, `docs/protocol.md` §9.11.1);
2. proof-of-possession secret — `crates/cc-authority/src/lib.rs`, `Authority::challenge`: 32 bytes per presented key from `fill_bytes`, then sealed to the device keys and used to derive the echo (K23) and session MAC key (K24, §9.4).

Under argument S-13 (I-1), a generator repeats after VM snapshot rollback, image cloning, and restoration from backup. This hurts the server more than the client: server state rolls back with the generator, making a spent challenge unissued again, with nobody noticing the repeat.

### Decision

Both values are derived by **K30** (§3.5):

```
prk   = SHA-256("CC/v1/server-fresh" ‖ 0x00 ‖ seed(32) ‖ u8(kind) ‖ i64be(now) ‖ device_fpr(32))
K30   = HKDF-Expand(prk, info = "CC/v1/server-fresh", L)
kind  : 1 — attestation challenge, 2 — proof-of-possession secret
```

Random bytes feed the **seed**, not the value. Vector: `tests/kat/server_fresh.kat`; label `"CC/v1/server-fresh"` is added to §3.6, prefix-free with the others.

### Why time rather than request data

Nonce seeds (K17–K20) distinguish repeats through plaintext: the same seed with different data gives different nonces. Here there IS no plaintext — both the attestation challenge and possession secret are pure freshness. Seeding from request data alone would distinguish different DEVICES while leaving repeats for the same device, precisely the dangerous case: two conversations by one device would get one secret, hence one echo and one session MAC key.

Time separates them. The server is not a pure crate; it has a clock, and `now` already reaches the handler as a parameter. It is threaded into `Authority::challenge` as the second argument. The fingerprint enters the preimage as a SECOND separator, not instead of time: within one second, two devices must receive different values.

Expansion uses `HKDF-Expand`, not appended hashes with a counter: the secret consists of 32-byte halves, one per presented key, so its length is known only at runtime. Expand's counter is the same counter, standardized. Even a 32-byte output therefore goes through Expand: one shape for both uses.

### Honest risk assessment — separately for each use

**Attestation challenge (1) — almost no risk, which must be stated plainly.** A repeated challenge means repeated `extraData`, so a TPM assertion captured in a previous conversation could fit the current one. But not everyone can present it: only a point whose possession was proven IN THIS conversation can be attested (`serve.rs`, `proven.proves_hardware`), and possession proof is a separate gate. Replaying someone else's assertion without the TPM key fails. The adversary's benefit is limited to replaying its OWN old assertion, which it is already allowed to do.

**Proof-of-possession secret (2) — no conversation binding at all.** The echo is `HMAC(secret, "CC/v1/prove-echo" ‖ device_fpr)` (`oc_crypto::kdf::prove_echo`), containing neither the session ephemeral pair, connection number, nor transcript. Therefore a wire observer who recorded a previous echo passes `Authority::prove` WITHOUT the key if the secret repeats.

It then reaches a barrier: everything worth impersonating a device for is authenticated by session MAC K24, and K24 derives from the secret itself, not the echo. The echo, an HMAC, does not reveal the secret; activation, renewal, and all three attestation steps (`oc_protocol::activation::is_session_sealed`) remain inaccessible. Requests needing no MAC also need no proof. Today, then, replay grants the `Proven` marker and nothing more.

The margin is one code change thick: the day any request admits `Proven` without a session MAC, replay becomes full device impersonation. The decision closes the hole before that day, not afterward.

A second, costlier form also exists: under snapshot rollback, the secret did not depend on WHO greeted the server — the same position in the generator stream yielded the same bytes to anyone. A device legitimately opening its sealed copy of a repeated secret would learn the secret assigned to someone else's fingerprint and derive both its echo and K24. With K30, different fingerprints diverge even under one seed.

### What this decision does NOT provide

Snapshot rollback TOGETHER with the clock is not separated by anything: `now` returns to its old value, the seed repeats, the value repeats. This protects against generator repetition, not an adversary controlling the server clock. Such an adversary cannot fundamentally be addressed here, and the opposite must not be promised.

Neither does it prevent a collision within one second when the seed completely repeats: the clock is integer-valued with one-second resolution. The combination works, not time alone — the seed remains random and normally separates everything itself; time merely prevents the generator from deciding alone.

Other values in the same handler — `secret`, `seed`, and `oaep_seed` of `AttestEvidence` (`serve.rs`) — were NOT covered by this decision and came from the generator. **They are covered by the next decision, “ECHO BOUND TO THE CONVERSATION 2026-09-21”**: the same K30 derivation, purposes `kind = 3, 4, 5`, vector `tests/kat/server_fresh_credential.kat`. The risk assessment is there too; it is modest and recorded as such.

## ECHO BOUND TO THE CONVERSATION 2026-09-21 (K31)

**Container bytes do not change.** The format version and `tests/golden/**` remain untouched. The wire changes: the proof-of-possession echo preimage (`docs/protocol.md` §9.4). This change is inexpensive precisely today — the product is unreleased, client and server ship together (rule R-3), and there are no external parties.

### Previous state

The echo used derivation **K23**: `HMAC(challenge secret, "CC/v1/prove-echo" ‖ device_fpr)`. Its preimage contained only the fingerprint: no ephemeral pair, connection number, or transcript. The echo was therefore a FUNCTION OF SECRET AND NAME, not of the conversation. A recorded echo worked in any other conversation for the same device where the secret repeated.

The server secret repeats under VM snapshot rollback, image cloning, and restoration from backup (I-1, argument S-13). “SERVER FRESHNESS IS DERIVED 2026-09-20” (K30) addressed secret REPETITION but left the echo construction unchanged.

The safety margin rested on one fact: everything worth impersonating a device for is authenticated by a session MAC (K24, K25), and K24 derives from the secret, not the echo. Replay therefore granted `Proven` and nothing else. **This margin is one code change thick**: the day any request admits `Proven` without a session MAC, a recorded echo becomes device impersonation. This must be closed before that day, not after.

### Decision

The echo uses derivation **K31** (§3.5) over the CONVERSATION TRANSCRIPT, in two stages:

```
transcript = "CC/v1/echo-transcript" ‖ 0x00 ‖
             u32le(len(hello)) ‖ hello ‖ u32le(len(challenge)) ‖ challenge
handshake  = SHA-256(transcript)
echo       = HMAC-SHA256(key = challenge secret,
                         "CC/v1/echo-transcript" ‖ device_fpr ‖ handshake)
```

`hello` is the RAW device-greeting frame bytes (`kind ‖ TLV`) as received by the server; `challenge` is the RAW challenge-frame bytes (`kind ‖ TLV`) as sent by the server. The order is normative: greeting, then challenge, in wire order.

Label `"CC/v1/echo-transcript"` is added to §3.6, prefix-free with the others. **Its name deliberately does not extend `"CC/v1/prove-echo"`**: the set is prefix-free, and `"CC/v1/prove-echo-bound"` would extend an occupied label, violating I-12. One label appears in both stages; this is NOT a second domain: the domain is one, “transcript-based echo”. The HMAC message needs the label so the new echo cannot collide with the old one under the same key.

Vector: `tests/kat/echo_transcript.kat`, computed outside Rust by a separate `hashlib`/`hmac` script from this section's text, and only then compared with `oc_crypto::kdf::handshake_transcript` and `oc_crypto::kdf::echo_transcript`.

### What enters the transcript, and why

Each piece must satisfy three conditions: BOTH parties have it at echo time, an adversary cannot impose it without consequences, and it distinguishes conversations.

* **Greeting frame.** Carries `device_fpr`, `device_public`, the hardware key, and the hybrid pair with mechanism number. An adversary may construct it, but its own greeting yields a challenge sealed to its OWN keys and proves possession of its own name, not someone else's (finding K-1, `Authority::challenge`).
* **Challenge frame.** Carries the complete sealed halves: `enc`, nonce, ciphertext. This distinguishes conversations: `Seal` has a fresh ephemeral pair for every sealing, so two conversations differ in bytes even with the same secret.
* **Operation kind.** No separate field is introduced: the kind byte is each frame's first byte, and both frames are included in full.

What is NOT in the transcript, and why: connection number, known only to the server; clock readings, which differ between parties. A value known to one party cannot by definition be a transcript.

**Raw bytes, not reconstructed values** — the same reasoning as I-5. Reconstruction from parsed values could produce one byte sequence for a canonical document and another for a document whose canonical form is checked only by our own encoder. A frame-modifying intermediary diverges from the honest party only when the hash uses bytes exactly as transmitted.

**Lengths, not adjacency.** `Transcript::field` prefixes each piece with its length. Without it, pairs (`ab`, `c`) and (`a`, `bc`) yield one hash, allowing an adversary to move bytes from greeting to challenge without changing the echo. Vector row `k31_handshake_shifted_boundary` freezes this property.

### K24 is NOT bound; this is a decision, not an omission

The question was explicit: include `handshake` in the session MAC key preimage too, tying the session to the handshake? **No.**

Cost: K24 is frozen by vector `k24_session_mac_key` in `tests/kat/derivations_wire.kat`; I-14 forbids changing its preimage. This would require another new derivation with a new label, followed by changes everywhere K25 is computed or checked on both sides of the wire.

Benefit: zero, verifiably. K24 derives FROM THE SECRET, available only to the device private-key holder: it travels sealed, and the HMAC echo does not reveal it. An adversary unable to construct a bound echo also cannot derive K24. The converse is an honest device in two conversations with a repeated secret and thus the same K24: an authenticated request from the first passes the MAC in the second. But that is REQUEST REPLAY, handled by operation identity (K28, §9.10) and the server outcome table, not K24's preimage. Binding K24 cannot address complete rollback (generator and clock) either: the transcript repeats too.

The result would be a second lock on a door already secured by the first, at the cost of reissuing a frozen derivation. Not done.

### What this decision does NOT provide

* **No protection against an adversary holding the device private key.** That adversary proves possession legitimately; no echo binding changes this.
* **Not attestation.** KEY possession is proven, not TPM residency; §9.11 and `HardwareAttested` address that.
* **No remedy for full snapshot rollback together with clocks.** The secret repeats (clock time is part of K30's preimage), as does the sealing ephemeral pair, hence the entire transcript. The recorded echo works again. An adversary controlling the server clock cannot fundamentally be addressed here.
* **No removal of session MACs.** `Proven` remains no admission ticket: K25 remains on `Activate`, `Renew`, and the three attestation steps.

### Old derivation K23 — unused, but retained

`"CC/v1/prove-echo"` and `oc_crypto::kdf::prove_echo` remain in the registry and code, marked “unused by the protocol since 2026-09-21, retained for the vector”. Their bytes are frozen by row `k23_prove_echo` in `tests/kat/derivations_wire.kat`; the vector remains passing and is NOT changed (I-14). Removing the derivation would leave the vector without its subject.

The retained derivation is dangerous because it looks usable, so a guard exists: `the_old_unbound_echo_has_no_callers_outside_its_vector` (`crates/cc-cli/tests/repository_hygiene.rs`) enforces zero product-code callers. The server **rejects** old-form echoes rather than accepting them “during a transition”: there is no transition period; the product is unreleased.

### Assessment (1): three `AttestEvidence` values are derived under the same decision

`randomness.secret`, `randomness.seed`, and `randomness.oaep_seed` (`crates/cc-authority/src/serve.rs`) previously came bare from the generator. They now use derivation **K30** with purposes `kind = 3, 4, 5`: the label and function are unchanged; only inputs are new. One seed serves all three; `kind` separates them. Vector: `tests/kat/server_fresh_credential.kat`; `server_fresh.kat` is untouched.

**Risk assessment, without exaggeration.** These three values protect `TPM2_MakeCredential` credentials packed to a SPECIFIC device's endorsement key (EK). What repetition after snapshot rollback provides:

* *to the same device* — almost nothing: it legitimately learns the secret anyway by decrypting the credentials with its EK. Repetition makes the previous conversation's secret work in the current one; however, the conversation's attestation marker is still issued only after `ActivateCredential`, hence only to the EK holder;
* *to another device* — nothing: credentials are packed to someone else's EK, and the repeated secret remains ciphertext to it. Before this decision, the secret did NOT depend on its recipient (the same generator-stream position gave anyone the same bytes), the same second, costlier case as for the possession secret: a device legitimately activating its copy could learn the secret assigned to someone else. The fingerprint is now in the preimage;
* *to a wire observer* — nothing: credentials were already visible, their secret is not visible, and repeated ciphertext reveals nothing new.

The risk is therefore NOT large; I-1 nevertheless applies to EVERY value, not only those remembered. This has happened twice already: two of four nonce seeds remained generator-only for two stages, and the attestation challenge was derived before these three values.

### Assessment (2): length `L` in the K30 preimage — echo binding closes the question

`server_fresh` does not include requested length in its preimage: a 96-byte secret begins with exactly the same 32 bytes as a 32-byte secret under identical inputs. Vector `server_fresh.kat` freezes this as a PROPERTY, so the K30 preimage cannot change (I-14).

**What an adversary gains in practice.** The DEVICE chooses the number of halves: one for each key presented in the greeting. An adversary may therefore present fewer keys and obtain a secret whose first half matches the first half of a “larger” conversation's secret for the same fingerprint in the same second. But:

* it obtains that half only by decrypting with its key; the half is sealed to the greeting's named key, hence its own. It learns no one else's secret (finding K-1: the fingerprint must be that very key, checked by `Authority::challenge`);
* it cannot learn someone else's first half, regardless of the number of halves;
* still less can it construct another conversation's echo from it: **under this decision the echo includes the transcript**, and that transcript carries the other conversation's challenge with its own ephemeral pair. Previously, equality of the first 32 bytes would imply equal echoes for an equal fingerprint; now it does not.

The question is thus closed without introducing `L` into the preimage. Vector row `k30_proof_secret_96` continues to record this as a DELIBERATE property, not an oversight: it ensures a one-key device and a three-key device open the same first half.

---
## 1. Layout

```
offset     size              field
0          8                 Magic = "CLOSECR1"
8          4                 HeaderLen : u32le
12         HeaderLen         Header    : TLV fields, tags strictly increasing
12+HL      64                HeaderSig : Ed25519
76+HL      4                 ContentDescLen : u32le  (BODY length ONLY)
80+HL      ContentDescLen    ContentDesc    : TLV fields, tags increasing
80+HL+CDL  32                ContentMac     : HMAC-SHA256 under K6
112+HL+CDL variable          Payload : chunk sequence
...        variable          Footer (reserved, see header.footer_offset)
```

The mutable-region row previously combined `ContentDescLen(4) + ContentDesc` without the 32-byte MAC, although every adjacent row stated its size. The region occupies `4 + ContentDescLen + 32` bytes. Section §1.2, two sections below, specifically warns about being off by exactly these 32 bytes: the table was making the very mistake the document warned against.

Three regions have different authentication owners:

| Region | Authenticated by | Changes after packaging |
|---|---|---|
| `Header` | Author's Ed25519 signature | Never |
| `ContentDesc` | MAC under a key derived from CEK (K6) | On every edit |
| `Payload` | Each chunk's AEAD tag | When that chunk is edited |

This separation exists because editing occurs without the author, who cannot sign something they have not seen. The CEK holder can recompute `ContentDesc`; nobody else can. Editing is not implemented until phase 6, but the region is reserved from version 1: adding it later would be an incompatible format change.

### 1.1 Parsing limits

These are checked at the structural level **before** any decoding:

```
MAX_HEADER_LEN        = 1 MiB
MAX_KEY_SLOTS         = 1024
MAX_CONTENT_DESC_LEN  = 64 KiB
MAX_URLS              = 16        // server addresses in authority
MAX_URL_LEN           = 2048      // bytes per address
chunk_size ∈ { 4 KiB, 8 KiB, …, 1 MiB }   // must be a power of two
```

**Ordinal tags in nested TLVs are numbered from zero.** This applies to `urls` (§2.0) and slot records: “slots are numbered by position” means zero-based position. This does not affect reading, which ignores those tags, but directly affects byte-for-byte reproducibility in another implementation.

### 1.2 Mutable region

```
ContentDescLen  u32le   BODY length ONLY, excluding this prefix and the MAC
body            TLV     tags in strictly increasing order
mac             32      HMAC-SHA256 under K6
```

The region occupies `4 + ContentDescLen + 32` bytes. The payload begins immediately after it; its offset must use this entire expression. `4 + ContentDescLen` is off by 32 bytes.

Body fields: `total_len` (tag 1, u64), `chunk_count` (2, u32, `= max(1, ⌈total_len / chunk_size⌉)`), `tree_root` (3, 32 bytes), `version_counter` (4, u64), and optional `footer_offset` (5, u64). Tag numbers are stated here for the same reason as the transcript itself: the MAC covers raw body bytes, so another implementation that numbers the fields differently would produce different bytes and silently diverge. The range rule in §2 also applies to the body: an unknown tag ≤ `0x7FFF` causes rejection; a tag > `0x7FFF` is skipped.

The MAC transcript is specified here because, without it, a second implementation—a server or editor—would diverge **silently**: MACs would simply fail to match, requiring byte comparisons to locate the cause.

```
Transcript::new("CC/v1/content-mac")     label ‖ 0x00
  .fixed(file_id)                        16 bytes
  .field(body)                          u32le(body length) ‖ RAW body bytes
```

The MAC covers the **raw body bytes**, not decoded field values. This is the same decision as for the header signature (§5), for the same reason: recomputing over a re-encoding of a parsed structure produces the family of canonicalization errors familiar from JWS and XML-DSig—parsing one thing and authenticating another.

Contrary to first impressions, this does not obstruct version compatibility. A MAC over raw bytes **always** matches across versions: the reader has exactly the bytes authenticated by the writer, without reconstruction in between. A version 2 writer adding an optional tag unknown to the reader authenticates it along with the rest of the body. A version 1 reader verifies the MAC over the same bytes successfully and skips the tag while parsing. A transcript over decoded values would instead require both sides to know **all** fields, failing precisely where it promised compatibility.

The main practical consequence is that the MAC is checked **before** parsing the body. Otherwise, distinguishable error codes—missing required field, invalid length, unknown tag—would be reported for unauthenticated bytes, and tampering with the mutable region would look like file truncation instead of forgery.

Three properties of this transcript require explanation.

`file_id` is first and mandatory: without it, a content description could be moved between files and a substituted `total_len` would go undetected.

The body's length is bound by the `field` prefix rather than a separate field. The body is the transcript's only variable-length entry; without the prefix, its boundary would be determined by the end of the buffer. This also prevents moving the payload's start: the length used to calculate that offset is authenticated by the same MAC.

“No footer” and “footer at offset 0” are distinguishable without a separate presence byte. In the first case, the body's TLV record with that tag is absent; in the second it exists and contains zeros. Different body bytes imply a different MAC. A presence flag that had to be explicit in a value-based transcript follows directly from the encoding here.

`version_counter` is in the body and therefore covered by the MAC. That is why it exists: otherwise, an older but correctly authenticated content version could be substituted undetected.

**Counter lifecycle before the editing phase.** This version has no editing: `ContentDesc` is written once, at packaging, with no update function. The reader must therefore reject **every** nonzero `version_counter`, rather than compare it with anything. A nonzero value means not “the file was edited according to the rules” but “someone edited this file and there is no way to verify those edits.” The CEK holder can rewrite and re-MAC the entire mutable region; the only link between the author's signature and the content is the comparison of `tree_root` with `original_root`.

This statement is true only because **the root binds the ciphertext** (§6.3). Before fix R-1, a leaf covered `nonce ‖ tag` without ciphertext, making the statement false: someone who knows the key can forge a Poly1305 tag, so the CEK holder could change the content while retaining the tag, leaf and root. Nothing then stood between the author's signature and arbitrary content. The promise and implementation silently diverged; only an external review caught it. The guarantee depends on §6.3, and the leaf preimage must not be changed without rereading this paragraph.

The comparison must be **unconditional**. Previously the condition was `version_counter == 0 && tree_root ==
original_root`, which undermined precisely the protection it was meant to provide: the CEK holder could set the counter to one and disable the root comparison, placing arbitrary content under a header “signed by Ivanov.”

When editing arrives, this condition becomes **stricter**, rather than disappearing: verification of the editing devices' signature chain replaces unconditional rejection.

**Editing became available on 2026-09-17** (the “EDITING IS EXECUTABLE” section). The condition became stricter as promised: a nonzero counter is accepted only with tag 6, an author or coauthor certificate for this file, and the editor's signature over the region. For such an edition, comparison with `original_root` is replaced by the editor's signature over `tree_root`. A zero counter still requires a matching `original_root` and the absence of tag 6.

---

## 2. Header

A sequence of `tag(u16le) ‖ length(u32le) ‖ value` fields. One strict rule applies: **tags are in strictly increasing order**. Compound values (`suite`, `authority`, `policy`, slot records) are nested sequences of the same form, with their own tag sets.

CBOR was deliberately rejected. The format is closed and does not need to be read by third-party developers, so CBOR's self-description adds nothing while introducing canonicalization questions and a large parser. Increasing tag order provides everything for which other formats introduce canonical encoding: duplicate tags are impossible, fields cannot be reordered, and two different byte sequences cannot mean the same thing. Checking requires one comparison per field; the parser is total and straightforward to fuzz.

Critical and optional fields are distinguished **by tag range**, not separate containers: tags ≤ `0x7FFF` are critical, and an unknown tag in that range means refusing to open the file; tags > `0x7FFF` are optional and skipped if unknown. Without this distinction, each significant field introduced in a later format version would make every existing client fail.

The value length must match its type exactly: a short value is not zero-padded and a long value is not truncated. Otherwise an adversary controls which bytes become part of a key or fingerprint.

| Tag | Field | Type | Note |
|---|---|---|---|
| 1 | `container_version` | u16 | = 1 |
| 2 | `min_reader_version` | u16 | = 1 for a version 1 writer; a client with lower support **refuses** to open it |
| 3 | `file_id` | bytes[16] | 16 random bytes. **Not UUIDv7**: it embeds creation time and would reveal the date to someone who cannot yet open the file |
| 4 | `suite` | map | Exactly three members: `sig_alg`(1), `aead_id`(2), `tree_hash_id`(3). Neither `kdf_id` nor `kem_id`; the reasons are below |
| 5 | `author_key` | bytes[32] | Author's public Ed25519 key. **Not** a map with a claimed identity: a name stated in the header proves no more than the header itself (§5.2); identity comes from the lease |
| 6 | `header_salt` | bytes[32] | Random, **for each packaging operation** |
| 7 | `chunk_size` | u32 | See §1.1 |
| 8 | `original_root` | bytes[32] | Tree root at packaging time |
| 9 | `policy` | map | §4 |
| 10 | `key_slots` | array | §3, at most `MAX_KEY_SLOTS` |
| 11 | `authority` | map | URL list, sealing-key `kid`, **pinned lease-signing key** |
| 12 | `private_meta` | bytes | AEAD block under K5: real filename and informational size |
| 13 | `prev_header_hash` | bytes[32]? | Provenance: repackaging, removing and reapplying protection, edit chains |
| 14 | `org_id` | bytes | Tenant |
| 15 | `class` | u8 | **Only 0** = local; other values are reserved and rejected during parsing |
| 16 | `footer_offset` | u64? | **RETIRED by the version 3 decision** (see “VERSION 3 OPENED,” item 6): this value was declared both here and as mutable-region tag 5; tag 5 is authoritative. The tag remains readable in versions 1 and 2, which were frozen together with another implementation's right to write it. No released file carries it |
| 17 | `wrapped_cek` | bytes[72] | Content key wrapped under KEK, §3.1. **Required**; absence causes rejection |
| 0x8001 | `coauthors` | TLV | **VERSION 3, NOT PRODUCED** (see “VERSION 3 OPENED,” item 12): the set of parties allowed to administer the file and their signature threshold. Optional: a reader unaware of coauthors still opens the file correctly; the set changes neither keys nor policy, only whose orders the server executes |
| ≤ 0x7FFF | *Critical range* | — | **An unknown tag here is a hard error** |
| > 0x7FFF | *Optional range* | — | An unknown tag here is skipped |

`authority` must contain the lease-signing key or its fingerprint. Pinning only a URL is trust on first use: without a key named in the author-signed header, a counterfeit server can issue its own leases.

**A zero key in `authority` is a hard error on both writing and parsing.** Both `sealing_kid` and `lease_verify_key` must be nonzero. A zero value passes all structural checks—the length is correct and the field exists—so it looks filled while being substantively absent. For `lease_verify_key`, this directly defeats the field's purpose: pinning the lease-signing key. The risk is not that a zero key accepts anything today (signature verification fails: 0x00…00 is not a valid Ed25519 point), but that an implementation unable to verify the signature might one day interpret zeros as “verification unnecessary.” The prohibition removes that choice. A zero `sealing_kid` is a low-order X25519 point that `Seal` would reject anyway, but later and with a less clear reason.

`wrapped_cek` is in the header, not a key slot: a file has one KEK and therefore one wrapped CEK regardless of slot count. A copy in each slot would be another place recording the same thing, and thus another place that could diverge. The field is required and critical: without it, the file cannot be decrypted. A client skipping it as unknown could not open a single byte, but would report corruption instead. From `core_hash`, the `wrapped_cek` record is **removed**, together with the slot record: the wrapper is bound to this hash through associated data, and including it would make the value depend on itself (§3.2).

Neither `kdf_id` nor `kem_id` appears in `suite`, deliberately.

`kem_id` is specified **per slot** (§3.3). KEMs will change over the product's lifetime, and slots using different KEMs must coexist in one file—that is why slots exist. A file-wide field would either prohibit coexistence or become a second source of truth for the same fact, and two sources of truth diverge.

`kdf_id` is absent because there is no choice to make: the entire key schedule in §3.5 uses HKDF-SHA256, and every row explicitly names the function. A field with one permitted value can only be checked (a dead branch) or ignored (silently accepting a critical field, which the format prohibits). Changing the KDF changes the whole algorithm suite, requiring a new `suite`/format version rather than an in-file switch; a switch controlled by the file's author would be a downgrade lever.

### 2.0 Nested-structure registries

Compound values are the same `tag ‖ length ‖ value` sequences with their own tag sets. These numbers are as normative as top-level numbers: `suite` and `authority` are signed, `policy` is also hashed independently, and `ContentDesc` is MACed over raw bytes. An implementation assigning different field numbers would produce different bytes and diverge **silently**. Previously these numbers existed only in code, making code rather than the document the de facto normative source.

`suite` (tag 4):

| Tag | Field | Type |
|---|---|---|
| 1 | `sig_alg` | u8: 1 Ed25519 |
| 2 | `aead_id` | u8: 1 XChaCha20-Poly1305, 2 AES-256-GCM, 3 AES-256-GCM-SIV |
| 3 | `tree_hash_id` | u8: 1 BLAKE3, 2 SHA-256 |

Identifiers 2 and 3 for `aead_id` and 2 for `tree_hash_id` are allocated in the registry, but **not implemented** by this build. It rejects them **during parsing**, not on first use. Recognizing a number and being able to execute its mechanism are different things. Accepting an unimplemented identifier turns the algorithm declaration into decoration—the same class of defect as `alg: none` in JWS.

**K21 and K11 differ by MORE THAN their labels; the difference must be understood.** K11's `info` includes `u64be(lease.seq)`; K21's does not. The sequence in K11 binds the BLOB to the lease for consistency, not enforcement: secret A is shared across all leases for the file and remains unwrapped on the device after the first opening. Revocation works through the client's evaluator and the server's refusal to renew (F-18), not through this sequence number. Share B is not bound to a lease because it is the AUTHOR's decision, not the server's, and must survive lease replacement. Otherwise every renewal would require a new approval, turning one-time consent into repeated interruptions.

The direct consequence must be explicit: **an issued share B cannot be revoked.** Revocation operates through the server ceasing to issue share A. This is the same property as for a claim code, with the same honest description: the file is not destroyed; it stops opening.

`authority` (tag 11):

| Tag | Field | Type |
|---|---|---|
| 1 | `urls` | Nested TLV: tag = ordinal number, value = **printable US-ASCII**, `0x21..=0x7E` |
| 2 | `sealing_kid` | bytes[32], nonzero. **Recorded, not checked:** equals the key to which the `Server` slot is sealed, but nobody compares them; the binding holds because a different key cannot open the slot (`oc_format::header::Authority::sealing_kid`) |
| 3 | `lease_verify_key` | bytes[32], nonzero |

#### Server addresses: character set and permitted reader behavior

**The character set is normative: printable US-ASCII excluding space, `0x21..=0x7E`.** Any byte outside this range causes rejection on both writing and parsing. This is not a warning or permission to skip the string: parsing the entire header fails.

The restriction may appear disproportionate for a field the format does not interpret, which is precisely why it needs explanation. The reader only **prints** this field so a person can compare the author's stated addresses with the destination they intend to use. Human consent is the protective mechanism here. But the printed string is chosen by the file author, potentially an adversary. Three things undermine this comparison while remaining valid UTF-8:

* `ESC` (0x1B) starts a control sequence: an address printed below can erase a line printed above. “Connecting to…” remains visible after ceasing to be true;
* U+202E RIGHT-TO-LEFT OVERRIDE displays `moc.dab` as `bad.com`;
* Cyrillic `а` (U+0430) is indistinguishable from Latin `a` in any font.

All three affect presentation and are prevented by one restriction at the source. Checking happens **during parsing**, not in every printing site: checking at output would require every caller to remember it, and the first omission would restore the whole vulnerability.

Non-Latin names are not excluded: they have a wire form, punycode (`xn--…`), required by DNS itself. The restriction matches what is transmitted anyway, excluding precisely the Unicode form whose rendering is the attack.

**The reader DOES NOT automatically connect to these addresses.** The author's signature authenticates exactly one fact: the author chose the address. It says nothing about whether it should be visited. Automatic connections would turn opening a received file into an outbound connection to the sender's chosen destination. Therefore a person supplies the address (`cc activate --url`), and the list is printed alongside as reference.

The resulting limitation must be stated explicitly: **in versions 1–3, `authority.urls` is a human-facing label, not a connection address.** It has no transport representation: the product uses framed TCP without HTTP (`docs/protocol.md` §9), while this field stores URLs containing a scheme and path. Neither is translated into a connection, and readers must not invent such a translation: two readers would invent different ones. A coherent connection-address format belongs in a later version and a separate field here, rather than reinterpreting this one.

**What the reader may do beyond printing—clarification dated 2026-09-02, with unchanged bytes.** The address may be printed TOGETHER with a command accepting it: “the file names X; repeat with `--url X`.” A person still supplies the address by copying it; the reader does not turn the field into a connection. The reader may REMEMBER a person-supplied address and avoid asking next time, but must associate it with the **author key**, not the organization. An organization name in the header proves nothing; the key signs the header containing the label, and consent bound to that key cannot be transferred through forgery. An explicitly supplied address overrides a remembered address and anything written in the file. A reader with neither a supplied nor remembered address does not connect anywhere. This is tested behaviorally (`crates/cc-cli/tests/authority_urls_are_not_followed.rs`): a label alone causes no traffic; supply an address once and the next request needs no flag; the same label under another key causes no traffic again.

A slot record (inside `key_slots`, tag 10; slots are numbered by **position**, with their kind inside the record):

| Tag | Field | Type |
|---|---|---|
| 1 | `kind` | u16: 1 Server, 2 RecipientIdentity, 3 RecipientClaim, 4 AuthorDevice |
| 2 | `kem_id` | u8: 1 X25519+HKDF-SHA256, 2 P-256+HKDF-SHA256, 3 RSA-OAEP-SHA256, 4 X-Wing (X25519+ML-KEM-768, version 4), 5 MLKEM768-P256 (P-256+ML-KEM-768, version 5) |
| 3 | `enc` | Ephemeral public key; its length is a **function of `kem_id`**, see below |
| 4 | `ct` | Ciphertext with tag |
| 5 | `commitment` | bytes[32], K9 |
| 6 | `key_fpr` | Public key to which the slot is sealed; length is a function of `kem_id`; optional |
| 7 | `nonce` | bytes[24], **stored**, not derived |
| 8 | `claim_commit` | bytes[32], K8; **only** for `kind = 3` |

**The mechanism determines the lengths of `enc` and `key_fpr`, SEPARATELY. They are not fixed by the format.**

Length is a function of the **pair** (`container_version`, `kem_id`), not of the mechanism alone:

| Version | `kem_id` | `enc` | `key_fpr` |
|---|---|---|---|
| 1 | 1 X25519 | 32 | 32 |
| 1 | 2, 3 | **Undefined → skip the slot** | Undefined |
| 2 | 1 X25519 | 32 | 32 |
| 2 | 2 P-256 | 65 | 65 |
| 2 | 3 RSA-OAEP | Undefined → skip the slot | Undefined |

Depending on the version is not pedantry. Without it, a version 1 container with a `kem_id = 2` slot would retroactively become openable, giving version 1 semantics it never had. Freezing also prevents that: version 1 remains exactly what it was on its freeze date, including what it **cannot** do.

The matching lengths in the first two mechanisms are **coincidental**: both fields contain a curve point. In RSA-OAEP, `enc` is an encapsulation and `key_fpr` is a key, so one size rule would be wrong. The lengths are therefore represented by two functions rather than one, even before the third mechanism requires it. An RSA-OAEP encapsulation is hundreds of bytes; an ML-KEM-768 hybrid exceeds a thousand.

**P-256's 65 bytes encode an uncompressed SEC1 point** `0x04 ‖ X(32) ‖ Y(32)`, not a 33-byte compressed point. The provider determines the representation: PCP returns a public key as `BCRYPT_ECCKEY_BLOB` and does not offer a compressed form. Storing it compressed would require decompression on every read—a field square root in the hostile-input parsing path, to save thirty-two bytes.

**No** version defines a representation for `kem_id = 3`: its registry number is allocated, its mechanism is not implemented, and its slots are skipped according to the rule below.

Previously the specification stated `bytes[32]` unconditionally. This was an internal contradiction, not a minor inaccuracy: the same table declared `kem_id` 2 and 3, and the following section promised that an unknown `kem_id` would cause **the slot to be skipped rather than the file rejected**. Both statements could not be satisfied: 65 bytes cannot fit a 32-byte field. A reader checking length before identifying the mechanism rejected the entire container even if another slot was usable. Agility was only a decorative promise; this was invisible in the format because all issued slots used X25519.

Version 2 closes this gap for P-256 **by defining its representation**, not by removing the skip rule. The rule remains and now applies to `kem_id = 3`: agility is demonstrated by retaining a mechanism whose representation the reader does not know.

The normative reading rule follows: **skip a slot whose mechanism the reader does not parse without examining its field lengths.** Applying one's own representation requirements to an unknown mechanism would reject the file merely for being newer. For a mechanism whose representation the reader defines, lengths must still match **exactly**: no zero-padding of short values and no truncation of long ones (I-8). In practice, slot parsing has two passes: kind and mechanism first, everything else second.

The slot kind determines its field set. A mismatch causes rejection during parsing, not skipping. The full rule is:

| `kind` | `ct` | `claim_commit` | `key_fpr` | `enc`, `nonce` |
|---|---|---|---|---|
| 1 Server, 2 RecipientIdentity, 4 AuthorDevice | Nonempty | Absent | Key to which sealed (optional) | According to mechanism |
| 3 RecipientClaim | **Empty** | Required | **Absent** | **Zeros** |

The entire table is enforced in both directions: writing and parsing. This must be explicit because previously only two of its four columns were enforced: `ct` and `claim_commit` were checked, while kind-specific `key_fpr` rules and zeroed `enc`/`nonce` were not. A claim-code slot could carry a 32-byte fingerprint and 56 arbitrary bytes in `enc` and `nonce`, pass verification, and sit unread **inside the author-signed header**—precisely the covert-channel space the table is intended to prevent. The prohibition covered only one of three fields.

The `key_fpr` check is **one-sided**: the field is forbidden in claim-code slots but optional in sealing slots. It is forbidden because there is nothing to identify: no key receives a sealed value, the code identifies the recipient, and the field would mean nothing. It is optional because §2 (tag 6) declares it optional; requiring it would reject openable files. The table column means “when present, this is the key to which the slot is sealed.”

That asymmetry concerns **parsing**, not freedom for writers. A writer emits `key_fpr` in every sealing slot—`Server`, `RecipientIdentity`, `AuthorDevice`—and omits it only for claim-code slots, where it is forbidden. Without this rule, a slot without `key_fpr` would be equally conformant, and two implementations could emit records of different lengths for the same recipient. Their headers, `core_hash` values and signatures would differ even though both files opened.

Both sides of the distinction are checked; otherwise fields become optional “on average,” and a slot that both seals a secret and carries a code commitment becomes structurally valid despite having no defined meaning. The reader would silently choose one interpretation. A sealing slot with empty `ct` would look usable while providing nothing; a claim-code slot with nonempty `ct` would hold unaccountable bytes the reader never opens—a covert channel inside an author-signed header. `enc` and `nonce` remain structurally present and contain zeros for `kind = 3`: there is nothing to seal, and introducing another form of “absent value” costs more than zeroing two fields.

`private_meta` (tag 12) is an AEAD block `nonce(24) ‖ ct ‖ tag` whose plaintext contains:

| Tag | Field | Type |
|---|---|---|
| 1 | `name` | UTF-8, **last component** of the path—a filename, not a path |
| 2 | `size` | u64le, **informational**; the normative length is in MAC-protected `total_len` |

```
block AAD = "CC/v1/private-meta" ‖ file_id(16)          // 34 bytes
nonce     = HKDF(salt=seed, ikm=plaintext, info="CC/v1/meta-nonce")[..24]
```

The associated data is specified here because, before the second review round, it was **entirely absent** from the specification—not even one line—although chunk AAD was defined in §6.1 and frozen by a vector. Its label deliberately differs from the chunk label: otherwise a metadata block could be presented as chunk zero, or vice versa, even under the same key.

`size` is a **second** copy of the file length and is not normative. The real length is in `total_len`, protected by the mutable-region MAC, and determines framing (§6.1). `size` exists for applications needing the filename and size before reading the payload. Readers need not compare the two. The rule identifying the authoritative copy is stated here so another implementation does not invent its own.

**`name` is untrusted input, and the reader must treat it as a filename rather than a path.** The author's signature authenticates the field's origin, not its harmlessness. An adversarial author could use `..\..\Startup\x.lnk` as an arbitrary-location write primitive rather than a filename, carried inside an encrypted block invisible to gateways. Reject empty values; path separators `/` and `\`; colons; entire names `.` and `..`; trailing dots or spaces; Windows device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`…`LPT9`); and control characters. Reject rather than silently repair: repairing a name means writing somewhere other than where the author specified without anyone knowing.

This rule is recorded here because previously it existed **nowhere**: the specification devoted one line to the field, “UTF-8, real filename.” An implementation strictly following it would permit directory traversal, while our client rejected those names without a specification basis, appearing to users as “file corruption.”

MIME is **not written** in version 1, and number 3 remains free for it. “Real name, MIME, size” appeared in §2 and two code doc comments—an error that outlived the decision. The field exists in neither the registry nor the code.

`ContentDesc` body tags are numbered in §1.2; policy tags are in §4.

**The range rule applies inside nested structures just as at the top level:** tags ≤ `0x7FFF` are critical; tags > `0x7FFF` are skipped. There is exactly one exception, identified in §4: policy has no optional range. Previously `suite` and `authority` unconditionally rejected any unknown tag, making the range rule a property of an individual decoder rather than the format, and permanently closing those structures to extensions.

**An unknown critical tag inside a slot record makes the SLOT unusable, not the file.** Preserve the slot as `Unknown` and do not use it, just as with an unknown kind or `kem_id`. Both extremes would be wrong: silently skipping the field is invalid because a slot yields key material and a future-version field changes **how** to retrieve it. Rejecting the entire container is also invalid because any future slot kind would make the file unreadable to a client with its own usable slot, eliminating the extension point for which slots exist.

### 2.1 Version negotiation and downgrade protection

A version 3 writer always declares `min_reader_version = 3`. This field is not derived from the file's contents, for the same reason given in item 4 of the version 2 decision.

1. Breaking format changes change `Magic` (`CLOSECR2`); a version 1 client rejects it.
2. If `min_reader_version` exceeds supported capability, reject even when everything else parses.
3. **`container_version` must be within the reader's supported range: no earlier than the first version that existed, and no later than the greatest readable version.** Check both boundaries, not just the upper one.
4. Separating critical and optional tag ranges is the format's most valuable extension point. Without it, each significant version 2 field causes existing clients to fail.
5. A version 2 client reading a version 1 file applies version 2 rules: **any missing policy field means denial**. A property test enumerates combinations of absent fields and asserts that `Allow` never arises.
6. The client maintains allowlists for `sig_alg`, `aead_id` and `tree_hash_id`, rejecting an unimplemented identifier **during parsing**. Thus retiring XChaCha or SHA-256 requires a client update rather than a format change. Previously this text referred to an “allowlist of `suite_id`” that corresponded to nothing: validity is checked separately for each of the three identifiers, while `suite_id` is one byte in the signature (§5), not a suite catalog number.

**The two version fields occupy different namespaces and must not be confused.** Item 3 was previously absent. The document implied that `min_reader_version` provided forward compatibility, allowing readers to infer that a version 2 writer adding only optional tags could set `min_reader_version = 1` and remain readable. That is not true, for an important reason.

`min_reader_version` is **the writer's claim** that a client of the named version will understand its file. The claim is signed, but the signer may be an adversary. They can declare `container_version = 999` together with `min_reader_version = 1`, claiming a future-format file is readable under current rules. Believing this would apply version 1 rules to version 999 semantics. An unknown format version therefore causes rejection regardless of the writer's claim.

This does not impair forward compatibility, which is provided by the **optional tag range** (§2.0), allowing fields to be added without changing the format version. Changing `container_version` specifically means something changed that the old reader cannot understand; rejection is then the correct outcome, not an obstacle.

The lower boundary is necessary for the same reason as the upper one and is easier to overlook. Checking only `>` admitted version 0—a format that never existed—and read it under version 1 rules. A version lower than any released version is more dangerous than a higher one: it seems unsurprising (“just an old file”) while meaning the same thing—semantics the reader does not possess.

Finally, the “greatest readable format version” and “client version” are **different quantities** even when their numbers happen to match. A version 3 client that reads formats 1 and 2 cannot be described by one constant. Diagnostics conflating them are misleading: a file with `container_version = 999` produced “file requires client version 999,” placing a format-version number in a field intended for the client version.

---


## 3. Key scheme

### 3.1 Wrapping, not derivation

```
CEK  = 32 random bytes                         // independent of every slot
KEK  = HKDF(salt=file_id, ikm=secret_A‖secret_B, info="CC/v1/kek"‖org_id‖file_id)
seed = 24 random bytes                         // never stored
wrap_nonce  = HKDF(salt=seed, ikm=CEK, info="CC/v1/wrap-nonce")[..24]   // STORED
CEK_wrapped = wrap_nonce ‖ XChaCha20-Poly1305(key=KEK, nonce=wrap_nonce, pt=CEK, aad=core_hash)
slot_commit = HMAC-SHA256(KEK, "CC/v1/slot-commit"‖core_hash)
```

`CEK_wrapped` is exactly **72 bytes**: 24 nonce + 32 key + 16 tag. The format fixes this length (tag 17, §2): an extra byte would shift everything following the field.

The wrapping nonce is **stored, not derived from KEK**. Derived from KEK, it is safe only while there is one (KEK, CEK) pair per file, a condition enforced by nothing: the interface does not prevent wrapping two different CEKs under one KEK—repackaging, content-key rotation. Then both key and nonce match, hence the keystream matches: `wrapped₁ ⊕ wrapped₂ = CEK₁ ⊕ CEK₂`, exposing both content keys and repeating the Poly1305 one-time key, which enables forgery. Twenty-four bytes buy safety by construction rather than caller discipline. This is the same rule as for chunks (§6.1) and slots (§3.3): **throughout the format, nonces are stored, not derived**.

**Random bytes seed a derivation rather than becoming the nonce directly.** A purely random nonce is safe only insofar as the generator does not repeat, a condition enforced by nothing: rolling back a virtual-machine snapshot, cloning a disk image, or restoring a backup returns the generator to its previous state. Repackaging the same file with a new content key then produces identical KEK and nonce for two different plaintexts—exactly the catastrophe a stored nonce was meant to prevent. The plaintext (the CEK itself) enters the seed material, so two different content keys receive different nonces even if the generator repeats completely.

This does not contradict “nonces are stored, not derived,” and the distinction matters. The rule forbids deriving a nonce from values **available to the reader**: such a nonce would always repeat when those values repeat. Here the nonce is derived from what the reader lacks—the seed and plaintext—and placed in the file; the reader still takes it ready-made and never computes it. The seed is never stored anywhere.

The guarantee's boundary is explicit: if the generator repeats **and** the plaintext matches, the ciphertext will match too. This reveals only that the inputs are equal. Eliminating even that would require a source independent of both generator and data—a monotonic counter in persistent storage or a TPM; a pure crate has no such source by construction, and will acquire one no earlier than the phase that introduces TPM.

An adversary can substitute the stored nonce, but gains nothing: the nonce participates in tag computation, and substitution breaks authentication before anything is decrypted.

The slot commitment binds to `core_hash`, not `file_id`; §3.2 explains why.

`CEK = HKDF(A‖B)` would permanently hardwire exactly one slot into the format: the first customer requesting two recipients, a recovery key, or rotation would break every released file.

`secret_A` and `secret_B` are strictly 32 bytes each, with the type fixing the length. HKDF-Extract over concatenation is a valid combiner **only** with fixed lengths: variable lengths would create ambiguous encoding.

### 3.2 Slot commitment

XChaCha20-Poly1305 is not key-committing. Without a constant-time check of `slot_commit` **before** opening the AEAD, a partitioning oracle appears: an adversary builds a wrapper opening under many candidate KEKs and recovers a low-entropy claim code substantially faster than exhaustive search. This also explains the code's entropy floor: **at least 128 bits**. A six-digit code is unacceptable.

The commitment binds to `core_hash`, not `file_id`: the header-core hash already contains `file_id`, making this binding strictly stronger, and it is available where the wrapper is computed. There is no circular dependency—`core_hash` is computed over the header excluding **both** records themselves bound to that hash: the key-slot record (tag 10) and `wrapped_cek` record (tag 17, §2). Slots contain `slot_commit`; the wrapper binds to the hash through associated data. Including either would make the value depend on itself.

```
core_hash = SHA-256( "CC/v1/core-hash" ‖ 0x00 ‖ Header without records tagged 10 and 17 )
```

The **entire record**—tag, length, and value—is removed, not just the value. Leaving the tag and length would allow slot and wrapper contents to change without changing the core hash, precisely what the binding protects against. Bytes on either side of the cut are concatenated without a separator: increasing tag order and the §2 table fix both record lengths, so no ambiguous concatenation arises. Boundaries are specified here for the same reason as the §1.2 transcript: a second implementation removing only the value would compute a different `core_hash`, and the sides would diverge **silently**—the CEK wrapper would stop opening, appearing to be file corruption.

The commitment is identical for every slot of a file: the file has one KEK. It is stored in every slot rather than once per file so that future schemes with different KEKs per slot will not require a format change.

### 3.3 Slots

Slots are numbered by **position**, not kind: the kind resides inside the record. If the slot kind were the tag, two recipients in one file could not be encoded—tags must strictly increase—yet that is why slots were introduced.

```
slot record    kind(1, u16)  kem_id(2, u8)  enc(3, 32)  ct(4)  commitment(5, 32)
               key_fpr(6, 32, optional)  nonce(7, 24)  claim_commit(8, 32, only kind=3)

Server         Seal(srv_pub,           secret_A,          info=slot_info("CC/v1/slot-server"))
RecipientIdentity
               Seal(rid_pub,           secret_B,          info=slot_info("CC/v1/slot-recipient"))
RecipientClaim secret_B = K7(claim_secret); only commitment K8 is in the container
AuthorDevice   Seal(author_device_pub, secret_A‖secret_B, info=slot_info("CC/v1/slot-author-device"))

slot_info(label) = label ‖ u8(kem_id) ‖ file_id
in all cases aad = policy_hash
Unknown{kind,raw} is preserved unchanged and ignored by a reader that does not know the kind
```

`slot_info` is written separately because this section and §3.5 (K10) previously specified **different** `info` values: here, label and `file_id`; there, label, `u8(kem_id)`, and `file_id`. Both lines belonged to one contract document, and a second implementation was entitled to read either; the sides would silently diverge—the slot would simply stop opening, appearing to be file corruption. The version including `kem_id` is normative: without it, §3.3 promises slots with different KEMs can coexist, but cryptography does not support that promise—relabeling a slot with another `kem_id` would give the adversary the same key, leaving the declared mechanism decorative (the same defect class that produced `alg: none` in JWS).

`Seal` is the §3.5 (K10) construction: an ephemeral X25519 pair, an AEAD key from the shared secret and **both** public keys, and XChaCha20-Poly1305. It is a handwritten construction modeled on RFC 9180, not an off-the-shelf HPKE implementation, and the first candidate for external review; why not a crate is explained beneath the §3.5 table.

The slot `nonce` is **stored** (24 bytes in the record), not derived from the shared secret—the same rule as chunks (§6.1) and the CEK wrapper (§3.1), but with the severest consequences here. A nonce derived from the shared secret would be determined entirely by the ephemeral pair and repeat with it. Repetition of the author's generator state—VM snapshot rollback, disk-image clone, backup restore—would produce two blobs with identical key and nonce, hence one keystream. Then `ct₁ ⊕ ct₂ = pt₁ ⊕ pt₂`, and the plaintexts here are secret shares: from `secret_A` and `secret_A‖secret_B` one recovers `secret_B`, KEK from both, and the content key from KEK. A complete bypass without a single private key.

Storage alone is **insufficient**, worth stating separately because the wrong conclusion is tempting. The ephemeral pair and nonce are drawn consecutively from one generator, so repeating its state would repeat both values together—the same scenario and cost. Random bytes therefore go into a seed:

```
seed  = 24 random bytes                                        // never stored
nonce = HKDF(salt=seed, ikm=plaintext, info="CC/v1/seal-nonce")[..24]
```

Plaintext participates in derivation, so different secret shares yield different nonces even if the generator repeats. The ephemeral pair still repeats—it is computed before the plaintext—and that is acceptable: uniqueness of (key, nonce) is sufficient; key equality alone is not keystream equality. The guarantee's boundaries are the same as §3.1.

The recipient-key fingerprint is deliberately absent from `info`: the recipient public key already enters the AEAD-key derivation's `ikm` (§3.5, K10), so identity binding already exists there. A second encoding of the same thing creates a second point of possible divergence. The slot record (`key_fpr`) stores **the public key itself**, without hashing: no fingerprint is computed anywhere, no function exists for it, and no domain label has been assigned. “Fingerprint” throughout this document and the code means exactly the 32-byte key (likewise in `cc keygen` output and the device facts' `fingerprint` field). This remains unambiguous only while there is one mechanism: for `kem_id` 2 or 3, the key is longer than 32 bytes, and the mechanism determines field length (§2.0). The value is covered by the author's signature: the server supplies recipient keys and is therefore a key directory—without an author-pinned fingerprint, it could substitute its own recipient key and collect both shares.

Reading rule: understand at least one usable slot and ignore the rest. A slot of unknown kind, or known kind with unknown `kem_id`, is skipped rather than causing file rejection: another slot in the same file may be openable.

`kem_id` is specified **per slot**, and only here—it is absent from `suite` (§2). KEM will change during the product's lifetime (X25519 → hybrid with ML-KEM-768), and slots with different KEMs must coexist in one file: server and author-device slots already target different KEMs today because TPM does not offer X25519 (§3.5, K11).

**Slot order produced by the writer**: `Server`, then the recipient slot if present, then `AuthorDevice`. Order does not matter for reading—the reader finds its own slot, not the first—and is maintained for golden-file reproducibility and for `slot_ordinal` should it ever enter associated data. Version 1 has at most one recipient: the container has one recipient share, and two recipient slots would mean either a shared share (each could then open a file addressed to the other) or two different CEKs—a separate decision for which the format has room but no decision yet exists.

`AuthorDevice` is required and always present. The machine requesting packaging is registered as a device with unlimited rights, so the author opens their own files offline and indefinitely, and `cc unprotect` works without a network. Without this slot the product would create precisely the risk of losing one's own files that it is meant to prevent.

### 3.4 Access modes

| Mode | Recipient needs | Security |
|---|---|---|
| Seamless (default) | nothing | First device claims the file. `secret_B` is available to anyone with the file, reducing the scheme to “key sealed to the server” |
| Claim code | a one-time code ≥128 bits through a second channel | Both server key and recipient secret are needed |
| Partner key | an SS-ID supplied in advance | The same, plus no trust in the server as a key directory |

The cost of seamlessness is explicit: server compromise together with a container copy yields plaintext. This is the right tradeoff for most files, but it is not free.

**Local packaging without a server.** `authority.urls` may be **empty**, meaning “no license server specified,” not “field forgotten”: the address tag is optional when parsing, whereas `sealing_kid` and `lease_verify_key` must be present and nonzero.

This optionality is **one-way**, and half is easily mistaken for the whole. During parsing the tag may be absent; during writing the writer **always** emits it—as an empty six-byte nested TLV when there are no addresses. Otherwise `authority` would be six bytes shorter, changing the header, `core_hash`, and signature: an implementation naturally omitting an empty field would emit a file our reader accepts, but neither implementation could reproduce byte for byte.

The `Server` slot is still written, sealed to a pair generated by **this same client** in the profile directory beside the author's keys (its private halves reside in files honestly named `dev-authority-NOT-A-REAL-SERVER.key`). The direct consequence must be explicit: **this slot provides no escrow guarantee**—the server share is accessible to whoever can access the author's key directory. This does not enlarge the compromise surface: the `AuthorDevice` slot on the same machine already yields both shares using a key from that directory.

Migration to a real server (phase F-7) means importing this pair or repackaging the container with a new `Server` slot; the format already has `prev_header_hash` (tag 13) for the latter path. Without a recorded rule, the §3.4 promise that “containers issued today will open in a later client” would not hold for recipient modes.

**What is actually issued today.** The table describes the format, not the current build, a significant distinction—otherwise readers might think seamless access is the default.

| Mode | Status |
|---|---|
| Author only (default) | issued. Absent from the table above because it is not an access mode: the file simply has no slot releasing `secret_B`, so only the author's device can open it |
| Partner key | the slot is **written** and checked; recipient opening awaits the license server because the second share is sealed to it |
| Claim code | likewise: the slot is written, the code printed, and K8 placed in the file; opening awaits the server |
| Seamless | **not issued**. It requires a slot releasing `secret_B` to anyone presenting the file, and no writer produces such a slot |

The writing half deliberately precedes the reading half: containers issued today must open in a later client. A share or commitment error discovered a version later means already distributed files, not merely a code change.

**Claim code: the canonical form is normative.** The recipient share is derived from the code, making its text part of the contract rather than an interface detail: divergent canonicalization would let the author print a code the recipient could not enter, appearing as “wrong code.”

```
alphabet     Base32 without I, L, O, U — 0123456789ABCDEFGHJKMNPQRSTVWXYZ  (5 bits/character)
length       30 characters = 150 bits; printed in groups of 5 separated by "-"
canonicalize discard "-", spaces and tabs; convert to UPPERCASE;
             a character outside the alphabet means REJECT, not substitute; length ≠ 30 means reject
claim_secret = BLAKE3("CC/v1/claim-code" ‖ 0x00 ‖ 30 canonical characters)  → 32 bytes  // K14
```

At the text-input boundary, the client also accepts Unicode whitespace, BOM U+FEFF, invisible separator U+200B, and typographic hyphens U+2010, U+2011, U+2013, U+2014 as group separators. This accommodates delivery through editors and email: the canonical 30 characters, K14, and container bytes remain unchanged. Other symbols, including lookalike Cyrillic letters, are still rejected.

The **text** is hashed, not bits assembled from the characters: assembling bits is a second encoding of the same thing, and divergence would give the sides different secrets for one code. Characters outside the alphabet are rejected, not “intelligently” corrected: `I` typed instead of `1` must yield a clear error, otherwise the recipient sees “wrong code” where “the code has no letter I” would be the correct advice.

The length exceeds `MIN_CLAIM_BITS = 128` with margin and also yields six equal groups: 26 characters would give 130 bits and a final one-character group, while codes are dictated aloud. A generator, not a person, creates the code: commitment K8 is plaintext in the container, brute force against it is offline, and attempts cannot be limited—they are not made against us. The boundary is checked when compiling the client because runtime offers nowhere to check it: `claim_secret` does not reveal its entropy.

The commitment lets the recipient discover a mistyped code **before** expensive work: K8 is compared in constant time before deriving KEK. The container carries the recipient share in no form—otherwise intercepting the file would replace knowing the code, and the second channel would cease to be a second channel.

### 3.5 All key derivations

No domain label is used twice anywhere in the system.

| # | Purpose | Function | salt | ikm | info | bytes |
|---|---|---|---|---|---|---|
| K1 | file KEK | HKDF-SHA256 | `file_id` | `secret_A‖secret_B` | `"CC/v1/kek"‖org_id‖file_id` | 32 |
| K3 | payload key | HKDF-SHA256 | `header_salt` | `CEK` | `"CC/v1/payload"‖file_id‖u32be(chunk_size)‖u8(aead_id)` | 32 |
| K4 | nonce base (AES profile only) | HKDF-Expand | prk(K3) | — | `"CC/v1/nonce-base"` | 8 |
| K5 | private metadata key | HKDF-SHA256 | `header_salt` | `CEK` | `"CC/v1/private-meta"‖file_id` | 32 |
| K6 | mutable-region MAC key | HKDF-SHA256 | `header_salt` | `CEK` | `"CC/v1/content-mac"‖file_id` | 32 |
| K7 | claim code → `secret_B` | HKDF-SHA256 | `file_id` | `claim_secret` | `"CC/v1/slot-b-claim"` | 32 |
| K8 | code commitment | HKDF-SHA256 | `file_id` | `claim_secret` | `"CC/v1/slot-b-commit"` | 32 |
| K23 | proof echo—**unused by the protocol since 2026-09-21** (“ECHO BOUND TO THE CONVERSATION” section), retained for vector `k23_prove_echo` | HMAC-SHA256 | — | key = secret challenge | `"CC/v1/prove-echo"‖device_fpr` | 32 |
| K31 | conversation-bound proof echo (“ECHO BOUND TO THE CONVERSATION 2026-09-21” section) | SHA-256 + HMAC-SHA256 | — | step 1: `handshake = SHA-256("CC/v1/echo-transcript"‖0x00‖u32le(len(hello))‖hello‖u32le(len(challenge))‖challenge)`, where `hello` and `challenge` are raw frame bytes; step 2: key = secret challenge | `"CC/v1/echo-transcript"‖device_fpr‖handshake` | 32 |
| K24 | session MAC key | HKDF-SHA256 | empty | secret challenge (32 or 64 bytes) | `"CC/v1/session-mac"‖device_fpr` | 32 |
| K25 | request MAC | HMAC-SHA256 | — | key = K24 | `u8(kind)‖encoded request` without trailing MAC | 32 |
| K27 | device fingerprint for `kem_id ≠ 1` | SHA-256 | — | — | `"CC/v1/device-fpr"‖0x00‖u8(kem_id)‖device_public`; for `kem_id = 1` the fingerprint equals the key (unhashed, frozen) | 32 |
| K28 | wire operation identity (`docs/protocol.md` §9.10) | SHA-256 | — | — | `"CC/v1/operation-id"‖0x00‖seed(32 random bytes)‖u8(kind)‖request body without the operation-id field` | 32 |
| K29 | qualifying data for the TPM statement about the device key (`docs/protocol.md` §9.11) | SHA-256 | — | — | `"CC/v1/attest-qualify"‖0x00‖server challenge(32)‖device_fpr(32)` | 32 |
| K30 | fresh server value: attestation challenge (`kind = 1`), proof-of-possession secret (`kind = 2`), and three TPM credential values—secret, protection seed, OAEP seed (`kind = 3, 4, 5`, decision of 2026-09-21) | SHA-256 + HKDF-Expand | — | prk = `SHA-256("CC/v1/server-fresh"‖0x00‖seed(32 random bytes)‖u8(kind)‖i64be(now)‖device_fpr(32))` | `"CC/v1/server-fresh"` | N: 32 for all except the proof secret, which has 32 per presented key |
| K22 | claim code → heir-device X25519 private key | HKDF-SHA256 | `file_id` | `claim_secret` | `"CC/v1/claim-device"` | 32 |
| K9 | slot commitment | HMAC-SHA256 | — | key = KEK | `"CC/v1/slot-commit"‖core_hash` | 32 |
| K10 | slot-sealing AEAD key: author→server, author→recipient, author→device | HKDF-SHA256 over X25519 | empty | `DH‖enc‖pk_recipient` (3×32) | `"CC/v1/seal-key"‖slot label from §3.3‖u8(kem_id)‖file_id` | 32 |
| K11 | server→device sealing | HKDF-SHA256 over ECDH by `kem_id` | empty | agreement shared secret | `"CC/v1/a-to-device"‖u8(kem_id)‖file_id‖device_fpr‖u64be(lease.seq)` | 32 |
| K21 | author→device sealing (share B) | HKDF-SHA256 over ECDH by `kem_id` | empty | agreement shared secret | `"CC/v1/b-to-device"‖u8(kem_id)‖file_id‖device_fpr` | 32 |
| K12 | access-state witness MAC key | HKDF-SHA256 | empty | device secret (X25519) | `"CC/v1/cached-lease"` | 32 |
| K13 | log chain | HMAC-SHA256 | — | key = previous MAC | canonical entry bytes | 32 |
| K14 | claim-code text → `claim_secret` | BLAKE3 | — | — | `"CC/v1/claim-code"‖0x00‖canonical characters` | 32 |
| K15 | header-core hash | SHA-256 | — | — | `"CC/v1/core-hash"‖0x00‖Header without records 10 and 17` | 32 |
| K16 | policy hash | SHA-256 | — | — | `"CC/v1/policy-hash"‖0x00‖value of record 9` | 32 |
| K17 | slot-sealing nonce seed | HKDF-SHA256 | 24 random bytes | plaintext (before version 3); `u32be(len)‖pt‖u32be(len)‖aad` (from version 3) | `"CC/v1/seal-nonce"` | 24 |
| K18 | CEK-wrapping nonce seed | HKDF-SHA256 | 24 random bytes | plaintext (before version 3); `u32be(len)‖pt‖u32be(len)‖aad` (from version 3) | `"CC/v1/wrap-nonce"` | 24 |
| K19 | frame nonce seed | HKDF-SHA256 | 24 random bytes | plaintext (before version 3); `u32be(len)‖pt‖u32be(len)‖aad` (from version 3) | `"CC/v1/frame-nonce"` | 24 |
| K20 | private-metadata nonce seed | HKDF-SHA256 | 24 random bytes | plaintext (before version 3); `u32be(len)‖pt‖u32be(len)‖aad` (from version 3) | `"CC/v1/meta-nonce"` | 24 |

**Before version 3, seeds K17–K20 excluded AAD and key—a historical decision with an explicit cost (cryptographic review, 2026-09-06).** Under generator rollback (model S-13), sealing ONE plaintext under DIFFERENT AADs yields one `(key, nonce)` and two different Poly1305 tags: an observer of two such files recovers the one-time tag key and can forge tags for that pair. The practical cost is zero: the blobs are under the author's signature (I-6), and tag forgery gives neither the key nor the keystream. Full SIV would use `ikm = plaintext ‖ AAD`, placing the key in the salt; changing the seed changes writer-produced bytes, requiring reissued reference artifacts and a new version (I-14). Reopen with the next format version.

**Criterion met on 2026-09-07:** the decision is recorded in “VERSION 3 OPENED,” item 13. Implemented on 2026-09-08 under the decision of 2026-09-07; item 13 gives the normative form.

**K12 WAS CORRECTED ON 2026-08-25, aligning the SPECIFICATION to code, not vice versa.** It previously read: “lease-cache key (software path), machine salt, ikm—unwrapped DPAPI, info—`"CC/v1/cached-lease"‖user_sid`.” The code derives something else: the access-state witness MAC key, empty salt, device secret as ikm, and a single label without `user_sid` as info (`oc_crypto::kdf::derive_witness_key`). Two different keys under one number are exactly what this table exists to prevent.

“The specification wins in a conflict” is not violated here but FULFILLED: it forbids silently aligning the document to code and requires a recorded decision. This is that recorded decision.

*Why change the document, not the code.* What the old row described **does not exist**: the product has no DPAPI-encrypted lease cache and none is planned—the lease's own fields and rollback witness enforce the offline window (F-8). The row described an unrealized design; rewriting code to match would create a derivation for a nonexistent consumer, repeating the “registry number exists, form does not” defect this specification already corrected in itself.

Moreover, the old form is unimplementable where it lives: `oc-crypto` is a pure crate; DPAPI and `user_sid` are platform values it cannot see.

*Why the label remains.* `"CC/v1/cached-lease"` names what it protects, not the mechanism—the state of a locally cached license. That is exactly what the witness attests to. Changing the label would alter the key with no security gain, and K12 has no vector, so the cost of an error here is not wire bytes but a second edit to the same files.

*What remained correct in the old row:* nothing except number, length, and algorithm.

Rows K15–K20 were added in the second review round (R-10, R-2). Previously the table declared itself complete—“a domain label used outside it is the discrepancy the table exists to prevent”—while omitting six derivations whose labels §3.6 marks as used. The document contradicted itself in precisely the way it warned against.

K14 appears even though it is not HKDF: the table lists **all** derivations, and a domain label used outside it is exactly the discrepancy it exists to prevent. BLAKE3 is used because there is neither salt nor an extract/expand split—just compression of variable-length input into 32 bytes; the `0x00` separator is required precisely because length varies. Canonicalizing the code is the interface's job (§3.4), while the derivation resides in `oc-crypto` with the rest of the scheme.

Number **K2 is deliberately not reused**. It belonged to the CEK-wrapping nonce derived **from KEK**, and that construction truly disappeared: a nonce the reader could compute from the key was replaced by one stored in the file. “There is no derived nonce anymore” was inaccurate and removed: the derivation remains but uses **seed and plaintext** (§3.1), values unavailable to the reader. Assigning the freed number to another derivation is still forbidden: it would silently invalidate previous references to “K2” in code comments, tests, and correspondence—the exact divergence class the table exists to prevent.

The mechanism identifier enters K10's `info` and therefore key derivation. Without it, §3.3 promises different KEMs can coexist without cryptographic support: relabeling a slot with another `kem_id` yields exactly the same key, making the declared algorithm decorative—the same defect class that produced `alg: none` in JWS. RFC 9180 addresses this with `suite_id`; here one byte suffices because the mechanism is the only variable part of a slot suite.

A reader encountering a slot whose mechanism it does not implement **skips the slot**, not the file: §3.3 allows different KEMs in one container, and a neighboring slot may open.

K10's salt is deliberately empty: the parties have no shared random value at this step, so domain separation rests entirely on `info`. **Both** public keys—ephemeral and recipient—enter `ikm`. Without the recipient key the scheme permits binding the same ciphertext to someone else's identity: an adversary knowing their private key chooses a public key yielding the same shared secret and passes off another party's blob as addressed to them. All three components are fixed at 32 bytes, so concatenation is unambiguous and needs no separators. An all-zero shared secret (a small-order point used as public key) causes rejection before any AEAD work: otherwise the key would cease to depend on the recipient's private key and anyone could open the blob.

The nonce for K10 and K11 is **not computed by the reader**—it is stored in the slot record (§3.3). The sender does derive it from seed, plaintext, and AAD (from version 3), and label `"CC/v1/seal-nonce"` exists in the set (row K17, §3.6). The previous wording—“the label is absent, no derivation exists to own it”—survived decision S-13 and contradicted the normative label list the same document declares byte-for-byte identical to code.

**`u8(kem_id)` in K11's `info` is a version 2 correction made before first use.**

When K11 was written, a device had exactly one mechanism and nothing needed binding. It now has two: P-256 in TPM and X25519 at the software tier. `info` without a mechanism would let a slot relabeled with another `kem_id` yield **the same** key. This is exactly the defect already analyzed and closed for K10 (§3.3): an algorithm declaration affecting nothing—a miniature “alg: none.”

Why this is legitimate with a frozen key scheme. **Wire bytes** are frozen, and K11 has produced none: the server that computes it has not been written, and the `Server` slot does not use it. Correcting `info` before first use costs zero; after the first lease release it would change keys for all issued files. Version 1 froze a K11 nobody computed; version 2 defines the one that will be computed.

Why K10 and K11 are separate: **NCrypt with Microsoft Platform Crypto Provider does not provide X25519.** TPM 2.0 offers ECDH/ECDSA P-256 and RSA. The private key never leaves TPM, so derivation operates on the raw `NCryptSecretAgreement` result behind the `KeyAgreement` trait; such a key cannot be supplied to an off-the-shelf HPKE crate—which is also why sealing was handwritten after RFC 9180 instead of taken ready-made.

### 3.6 Domain labels

```
"CC/v1/header-sig"    "CC/v1/revocation"    "CC/v1/grant"        "CC/v1/lease"
"CC/v1/activate-req"  "CC/v1/audit-entry"   "CC/v1/audit-head"    "CC/v1/attest-nonce"
"CC/v1/content-mac"   "CC/v1/editor-sig"    "CC/v1/chunk"
"CC/v1/leaf"          "CC/v1/node"          "CC/v1/kek"
"CC/v1/payload"       "CC/v1/nonce-base"    "CC/v1/private-meta" "CC/v1/slot-b-claim"
"CC/v1/slot-b-commit" "CC/v1/slot-commit"   "CC/v1/a-to-device"  "CC/v1/b-to-device"
"CC/v1/cached-lease"
"CC/v1/seal-key"      "CC/v1/seal-nonce"    "CC/v1/wrap-nonce"
"CC/v1/frame-nonce"   "CC/v1/meta-nonce"
"CC/v1/core-hash"     "CC/v1/policy-hash"
"CC/v1/slot-server"   "CC/v1/slot-recipient"  "CC/v1/slot-author-device"
"CC/v1/claim-code"    "CC/v1/author-order"  "CC/v1/claim-device"
"CC/v1/prove-echo"    "CC/v1/session-mac"   "CC/v1/device-fpr"
"CC/v1/echo-transcript"
"CC/v1/operation-id"  "CC/v1/attest-qualify"
"CC/v1/editor-cert"   "CC/v1/edit-session"  "CC/v1/edition-claim"
"CC/v1/footer-imprint" "CC/v1/witness-cosign"
"CC/v1/directory-entry" "CC/v1/directory-head"
"CC/v1/mark-layout"    "CC/v1/mark-choice"
"CC/v1/recovery-manifest"
"CC/v1/authority-binding" "CC/v1/control-request" "CC/v1/operation-receipt"
"CC/v1/replica-push"     "CC/v1/replica-ack"
"CC/v1/authority-transfer"
"CC/v1/server-fresh"
"CC/v1/package-manifest"
"CC/v1/agent-grant"      "CC/v1/delegation"
"CC/v1/action-grant"     "CC/v1/action-lease"  "CC/v1/action-decision"
```

The list is complete and must match the code's set byte for byte: a label present in one place but missing in another is either an unseparated domain or a dead string, both discovered only by attack or byte comparison.

**Status of each label.** A list matching the code does not mean every label serves a purpose today. A declared but unused label is a dead string, called a defect by this very section; status is therefore explicit instead of left to the reader's guesses.

| Label | Status |
|---|---|
| `header-sig`, `chunk`, `leaf`, `node`, `kek`, `payload`, `private-meta`, `content-mac`, `slot-commit`, `claim-code`, `slot-b-claim`, `slot-b-commit`, `claim-device`, `seal-key`, `seal-nonce`, `wrap-nonce`, `frame-nonce`, `meta-nonce`, `core-hash`, `policy-hash`, `slot-server`, `slot-recipient`, `slot-author-device` | in use |
| `nonce-base` | reserved: AES-GCM profile nonce base (K4). The build has no such profile |
| `a-to-device` (K11), `cached-lease` (K12), `audit-entry` (K13) | server: server→device sealing, access-state witness, log chain |
| `audit-head` | signed log head: size and tree root over entries. Separate from `audit-entry` because a head and an entry are different statements; a signature on one must not work for the other |
| `lease` | in use: lease-document signature (`oc_protocol::lease::signing_transcript`), frozen by vector `tests/kat/lease.kat` |
| `revocation`, `grant`, `activate-req`, `attest-nonce` | reserved: protocol signatures |
| `editor-sig`, `editor-cert`, `edit-session` | in use: editor signature over the mutable region, editing-key certificate, session head (“EDITING IS IMPLEMENTABLE” section, decision of 2026-09-17, D1); frozen by vector `tests/kat/edit.kat` |
| `edition-claim` | in use: editing-key signature on an edition claim to the server (`docs/protocol.md` §9.12, D1). Does not affect the container: the protocol changes |
| `footer-imprint` | in use: file imprint for the footer's RFC 3161 timestamp (“FOOTER AND TIMESTAMP” section, D3) |
| `witness-cosign` | in use: witness signature on the server log head (`docs/protocol.md` §9.13, D3). Does not affect the container: the protocol changes |
| `directory-entry`, `directory-head` | in use: key-directory log leaf (entry hash) and server signature on its head (`docs/protocol.md` §9.14, D4). Do not affect the container: the protocol changes |
| `mark-layout`, `mark-choice` | in use: semantic-mark layout fingerprint and variant selection using the organization's marking key (`crates/cc-cli/src/semantic_mark.rs`, `oc_crypto::kdf::mark_choice`, D5). Do not affect the container: the mark is a choice of words in plaintext before packaging |
| `recovery-manifest` | in use: server-recovery-package manifest signature with the lease-signing key (`cca recovery`, `docs/protocol.md` §9.15, E2 B5). Does not affect the container: an operator file |
| `authority-binding`, `control-request`, `operation-receipt` | in use: server-binding signature, controller's intent signature, operation-receipt signature (`oc_protocol::control`, `cc_authority::control`, `docs/protocol.md` §9.16, E2 B2). Do not affect the container: the protocol changes |
| `replica-push`, `replica-ack` | in use: signature on a state snapshot sent to a replica and the replica's signature on the received snapshot (`oc_protocol::replica`, `docs/protocol.md` §9.17, E2 B4). Do not affect the container: the protocol changes |
| `authority-transfer` | in use: previous-epoch controllers' signature on transfer of authority to a successor (`oc_protocol::control::Transfer`, `docs/protocol.md` §9.18, E2 B7). Does not affect the container: the anchor is unchanged and the client verifies the chain |
| `session-mac` | in use: protocol, `docs/protocol.md` §9.4 (K24); K25 has no label because K24 is dedicated solely to it |
| `prove-echo` | **unused by the protocol since 2026-09-21** (“ECHO BOUND TO THE CONVERSATION” section): K31 computes the echo. The label and derivation remain for frozen vector `k23_prove_echo` in `derivations_wire.kat`—I-14 forbids changing frozen material, and removal would leave the vector without the domain it checks. Guard `the_old_unbound_echo_has_no_callers_outside_its_vector` enforces zero production-code callers |
| `echo-transcript` | in use: K31, handshake-transcript proof-of-possession echo (`oc_crypto::kdf::handshake_transcript`, `oc_crypto::kdf::echo_transcript`, `docs/protocol.md` §9.4); frozen by vector `echo_transcript.kat` (decision of 2026-09-21, below). One label for both stages of one derivation: the domain is one, and the HMAC message includes the label so the new echo cannot collide with the old one under the same key. The name does not extend `prove-echo`: `"CC/v1/prove-echo-bound"` would extend an occupied label (I-12). Does not affect the container: format version unchanged, protocol changed |
| `author-order` | in use: signature on an author's order to the server—wire registration and revocation (`oc_protocol::order`, `docs/protocol.md` §9.3) |
| `device-fpr` | in use: K27, device fingerprint for mechanisms with keys longer than 32 bytes (`oc_crypto::kdf::device_fpr`); frozen by `derivations_wire.kat` vectors (decision of 2026-09-09, version 5, “Device fingerprint”) |
| `attest-qualify` | in use: K29, qualifying data for a TPM statement about the device key (`extraData` in `TPMS_ATTEST`, `docs/protocol.md` §9.11, decision of 2026-09-16, B6a). Separate from `attest-nonce`, already used for challenge sealing (§9.4). Does not affect the container: format version unchanged, protocol changed |
| `server-fresh` | in use: K30, fresh server-generated values—attestation challenge (`docs/protocol.md` §9.11.1) and proof-of-possession secret (§9.4); `oc_crypto::kdf::server_fresh`, frozen by vector `server_fresh.kat` (decision of 2026-09-20, below). One label for two purposes: `kind` in the preimage separates them, as with `operation-id`. Does not affect the container: format version unchanged, wire values are random to the recipient |
| `package-manifest` | in use: delivery-package inventory (`manifest.txt`) signed with the publisher key, verified by `cc install` before checksum verification and the first copy (`cc_cli::install::check_manifest_signature`). Does not affect the container: format version unchanged, label absent from the header. It is in the registry because only here can prefix-freedom be proven |
| `agent-grant`, `delegation` | in use: author's signature on an agent grant and parent-door signature on delegation to a descendant—Agent Protocol documents, `oc-protocol/src/agent.rs` (`docs/agent-protocol/stage-1-door.md` §3). **The container does not contain them**: format version unchanged, absent from the header, and not one byte of them is in `.cc`. They are in the registry because only here can prefix-freedom be proven (I-12). Separate from `grant`, which marks author approval of one request for one file, while an agent grant distributes shares for a whole tree; separate from each other because the author signs the grant and the door signs delegation with its ephemeral key, and neither signature must work as the other |
| `action-grant`, `action-lease` | in use: author's signature on an ACTION grant and server signature on a one-time action lease—Agent Protocol stage 2 documents, `oc-protocol/src/action.rs` (`docs/agent-protocol/stage-2-actions.md` §4.1, §4.3). **The container does not contain them**, like the pair above: format version unchanged, absent from the header. Separate from `agent-grant`, which distributes shares B for READING a subtree, while an action grant distributes rights to act outside the cage; a reading grant signature must not work as a `git push` grant signature. Separate from `lease`: the server signing key is the same (`authority.lease_verify_key`), so only the label separates domains—otherwise permission to open a file would serve as permission to execute an action. The `ActionRequest` request carries no signature at all (the door key is for key agreement), and thus has no label |
| `action-decision` | in use: author's signature on a decision about an execution request (`oc_protocol::action::ActionDecision`, `docs/agent-protocol/stage-2-actions.md` §5 step 3)—the owner's live “yes” to an action with `confirm`. **The container does not contain it**, like the three labels above. Separate from `grant`, which signs an ACCESS-request decision; both use the same key, the one in the file header. If domains matched, two distinct author statements would share one signature: “give this device share B” and “have this door execute `git push` to this branch.” Relying on different tag numbers to separate them is unacceptable: both bodies are TLV, and matching numbers are a matter of time, not construction |
| `operation-id` | in use: K28, operation identity in activation and renewal requests (`oc_crypto::kdf::operation_id`, `docs/protocol.md` §9.10); frozen by vector `operation_id.kat` (decision of 2026-09-15, “Operation identity”). Does not affect the container: format version unchanged, protocol changed |

Reservation here is not decorative: a label added later is a new string in a prefix-free set that must be reconciled with all released labels; reserving it now is cheaper than proving prefix-freedom retrospectively.

The statement “there are no nonce-derivation labels in the list” was wrong and removed. There are five: `nonce-base` (AES-GCM counter scheme, §6.1—absent from the build along with the AES profile) and four seeds—`seal-nonce` (§3.3), `wrap-nonce` (§3.1), `frame-nonce` (§6.1), and `meta-nonce` (§2.0).

The last two appeared after the other three, and why matters more than the fact itself. The seed decision (S-13) was applied to slot sealing and CEK wrapping—where people were looking—while frame and private-metadata nonces continued taking bytes directly from the generator. The hole was identical; it was found only when the item was checked for **completeness**, not correctness. Metadata had a higher cost than frames: `CEK` and `header_salt` come from the same generator, so repeating its state repeated both K5 and the nonce, while plaintexts (name, size) differed—one keystream over two different texts inside the author-signed header.

The frame label is `frame-nonce`, not `chunk-nonce`, for the same reason the lease-cache key is `cached-lease`: `"CC/v1/chunk-nonce"` would extend `"CC/v1/chunk"`, while labels also prefix `info` without a separator. A prefix-freedom test caught this, not review.

The precise rule is: **no nonce is derived from values available to the reader, and no reader computes a nonce**—all are stored ready-made in the file. `seal-nonce` and `wrap-nonce` participate in **sender-side** derivation from seed and plaintext, unavailable to the reader; the result goes in the file. This enforces the rule by different means rather than weakening it: a directly random nonce also satisfied the rule but broke under generator-state repetition.

Without a label, an author's signature made in another context (revocation record, activation request, grant) can be replayed as a header signature if the encodings can be made to collide.

The label set must be **prefix-free**, enforced by a test. The transcript puts a zero byte after the label, but labels also prefix HKDF `info` without a separator: there, `"CC/v1/lease"‖X` and `"CC/v1/lease-cache"‖Y` would match for `X = "-cache"‖Y`. The lease-cache key is therefore called `"CC/v1/cached-lease"`, not an extension of the lease label.

---

## 4. Policy

Numerically tagged fields. **An absent field means denial**, in every client version.

Policy tag registry. Numbers are normative: `policy_hash` hashes the policy's **raw bytes**, so an implementation numbering fields differently would produce a different hash and silently diverge from the first.

| Tag | Field | Value |
|---|---|---|
| 1 | `actions` | nested TLV: tag = action number, value = `u8` (1 Allow, everything else Deny); **all** known actions are written, see below |
| 2 | `validity` | kind `u8` ‖ fields, see below |
| 3 | `network` | kind `u8` ‖ fields, see below |
| 4 | `min_binding` | u8: **1** Software, **2** Hardware, **3** HardwareAttested |
| 5 | `max_opens` | u32le, or **empty value** = “no limit”; field always written |
| 6 | `watermark` | u8: `0x00`—no mark, any other value—mark required |
| 7 | `action_binding` | **version 4**: nested TLV, tag = action number, value = tier u8 as in `min_binding`; effective requirement = `max(min_binding, record)`. Neither produced nor accepted by versions 1–3: the tag is critical, so their clients reject such policy, correctly—skipping it would enforce a different policy from the one the author signed. Layout and rationale: “VERSION 3 OPENED,” item 11 |

**Byte layout of `validity` and `network`.** First byte is the kind, followed by its fields, all `i64` little-endian. For kinds without fields, the value must end there: an extra byte is rejection, not “skip the tail.”

```
validity: 0x01                                    Always
          0x02 ‖ i64le(not_before) ‖ i64le(not_after)   Window
          0x03 ‖ i64le(seconds)                    FromFirstOpen
network:  0x01                                    StrictOnline
          0x02 ‖ i64le(seconds) ‖ i64le(max_offline_seconds)   Lease
```

All this previously lived only in code, although §4 itself declares its numbers normative: `policy_hash` hashes raw policy bytes and `policy_hash` is an interoperability surface (the client compares it with the lease hash). Reconstructing identical bytes from the document was **impossible**: it listed only variant names.

**`min_binding` numbers start at one, not zero.** The document said `0 Software, 1 Hardware,
2 HardwareAttested`; code wrote and read `1/2/3`, and both directions of this offset are harmful. Our reader rejected a file written to the document entirely—“file corrupted” to the user. Meanwhile the document's `1 = Hardware` would read as `Software`: **silent weakening of the very field** this section insists must never be weakened. The decision favored code, not because “code is superior”: zero is deliberately unassigned. A zeroed or truncated field must be rejected rather than read as the weakest binding—the same doctrine by which absent `max_opens` means one opening rather than “unlimited.”

**The distinction between “absent field” and “present but empty field” is normative** for `max_opens`. An empty value is the author's explicit “I set no limit”; absence means their intent is unknown and is read as one opening (below). The writer must therefore **always** emit tag 5, even without a limit. An implementation simply omitting the field yields `max_opens = 1` in our reader, allowing one opening.

**The writer emits all six known actions, including denied ones.** Denial is byte `0x00` within tag 1, not an absent entry. Both forms mean the same to a reader—it inserts only entries valued `1` into the policy—which is exactly why this rule addresses writers: a shorter permissions-only encoding yields **different bytes for the same policy**. In frozen vector `tests/kat/policy.kat`, tag 1 has length 42 = 6 × (6 + 1): six entries.

What diverges must be named precisely because the cost differs from §4.0. The file remains internally consistent: both sides compute `policy_hash` from **actual file bytes**, so another implementation's container opens and no slot suffers. Divergence occurs wherever the hash comes from the **parsed structure**, not the file: server lease issuance under the author's signed rules; any header reconstruction after parsing; byte-for-byte vector reproducibility. This also violates §2's promise that “two different byte sequences do not mean the same thing”: here they would.

Action numbers inside `actions`: 1 View, 2 Edit, 3 Print, 4 Clipboard, 5 Export, 6 Screenshot. Future actions (`ai_ingest`, `ocr`, `forward`, `annotate`, `print_to_pdf`, `remote_desktop`, `screen_share`) occupy subsequent numbers and must be denied by older clients too—handled by `unknown_actions`, where a reader records everything unknown, granting nothing by itself.

**An unrecognized action returns to the wire as denial.** A writer rebuilding a parsed policy must emit unfamiliar tags again—with value `0x00`, not the author's preserved byte—and place them in overall increasing tag order rather than append them. It cannot preserve the foreign byte: a client ignorant of an action may not pass on a permission whose meaning it does not understand. It cannot lose the tag for the same reason it remembers it: once gone, the tag ceases to be grounds for rejection by the next reader.

**Absence of `max_opens` means “one opening,” not “unlimited.”** This follows directly from “an absent field means denial” and must be understood: a file produced by a future implementation unable for some reason to write this field opens exactly once.

**Absence of tag 6 means “mark required.”** This third form of the truncated-field doctrine belongs beside the other two: zeroed `min_binding` is rejected; absent `max_opens` means one opening; absent `watermark` requires a mark. All point in one direction: unknown author intent is interpreted more strictly, never more weakly. The writer always emits tag 6.

This is §4's only item where divergence is invisible **in any bytes**: hashes match, signatures match, the file opens, and only the on-screen mark differs. The format offers no way to verify this, so this line is the entire protection.

**Policy has no optional tag range.** Every unknown tag is a hard rejection, unlike the header (§2), which skips `> 0x7FFF`. This asymmetry is deliberate: skipping an unknown policy field means opening under incompletely understood rules, exactly what `unknown_actions` prevents. The cost is explicit: **a policy field cannot be added after freezing**—it would cause rejection for every released client. Policy expands only through new action numbers inside tag 1, where `unknown_actions` works.

### 4.0 `policy_hash` transcript

```
policy_hash = SHA-256( "CC/v1/policy-hash" ‖ 0x00 ‖ VALUE of the record tagged 9 )
```

**Only the value is hashed.** The tag and length—the six-byte record prefix (`u16le` tag, `u32le` length)—are **excluded**.

Read this carefully because the convention is **opposite** to `core_hash` (§3.2), which removes **entire** records, prefixes included. A second implementation reasoning by analogy with §3.2—the first thing an attentive reader would do—gets the **wrong** answer. The previous wording “raw bytes” and “byte range” could not distinguish the cases: it never said whether the range belonged to the record or the value.

The algorithm is **SHA-256**, which also must be explicit: it cannot be inferred elsewhere because K14 uses BLAKE3, as does the tree. The `0x00` separator follows the label under §3.6's general rule.

The cost of disagreement is unusually high: `policy_hash` enters **every** slot's associated data, so a wrong hash looks like “slot will not open, file corrupted,” not “we disagree about what to hash.” It is an interoperability surface: the server must compute the same value to issue a lease under the author's signed rules.

**`class` is rejected during parsing if nonzero.** A registry reservation and accepting a value while reading are different things; the latter without the former would be exactly the defect disallowed for `aead_id` and `tree_hash_id`: a number parses but the build cannot implement it, making the declared protection class decorative. The class determines the file's processing rules; accepting an unknown class and continuing under class zero applies someone else's rules.

`devices` (FirstOpenWins / Allowlist) and `apps` (signature fingerprint and image hashes) are **absent** from version 1: no tag numbers or decision-structure fields. They were previously listed here as existing—a document error, not a code omission. They can appear only with a format version (above), and belong to the server and native-application phases.

The server must be **structurally incapable** of expanding policy: `intersect(author, lease)` is monotonic, operating only toward restriction for **every** field. Verified by a property test.

> **The mechanism has been active since 2026-09-16.** This previously said “requirement in force, mechanism inactive”: the function existed and was monotonic but had no callers outside tests. Now the server calls it for each issuance; the operator sets the profile (`cca policy set`), and it reaches the recipient in a version 2 lease (`docs/protocol.md` §2.3). Field-by-field composition is defined in §4.3 below. A heterogeneous validity pair (window versus duration from first opening) cannot be expressed by conjunction in one `validity` member, and choosing either would expand access relative to the other, so such a pair yields rejection, not a choice. The client additionally compares the lease's `policy_hash` against the hash of the author-signed policy byte range.

### 4.1 Where policy applies and where it does not

`evaluate` decides access, called by the **recipient client**: the viewer and later the native-application broker.

`cc unprotect` has **two paths**, with different policy application. The distinction arrived with the recipient path (F-7), while this section continued describing only the first—and unconditionally: “`cc unprotect` does not consult policy.” That was false for the second path.

**The author path** (without `--lease`/`--share`) does not consult policy, as a property of the operation, not a missing check. It opens through `AuthorDevice`, sealed to the author's device key and openable by nobody else. Successfully opening that slot **is** cryptographic proof that the author is operating on their own machine—and the author owns the plaintext by definition: they packaged it. Asking policy to permit showing someone what they encrypted an hour ago would simulate protection where there is nobody to protect against.

This is recorded because externally it looks like a hole: policy is parsed, cryptographically bound to slots through `policy_hash` in `aad`, and printed to the user, yet decides nothing on the author path.

**The recipient path** (`--lease` together with `--share`) consults policy, specifically for **`Action::Export`**, not viewing. The action follows what the operation DOES: writes the decrypted file to disk, creating a persistent copy outside the container. That is export under both §4's vocabulary and common sense.

The distinction is practical and was once a bug: the command asked about viewing but exported, giving recipients a permanent unprotected copy of a view-only container. The author denied export through default `deny_all`; the policy field existed, the encoder wrote it, the evaluator could check it—and nobody asked.

Hence a rule broader than one command: **a consumer must ask about the action it performs.** Permission for one thing followed by another is not a minor inaccuracy but a policy bypass, appearing internally as a working check.

A view-only file's recipient is entitled to no copy at all: the viewer shows contents without writing them to disk. An author wishing to provide a copy explicitly permits export.

**The second consumer of this rule is the native-application broker** (`ccbroker`, §7). It opens the document in real Word or Acrobat, which read from disk and cannot do otherwise: the application creates a section object, which cannot be built over data absent from disk. Decrypted content therefore resides on disk for the session—exactly “creates a persistent copy outside the container,” except for a limited lifetime.

The broker therefore asks for **`Action::Export`**, not viewing, under the same rule: ask about the action performed. The unpleasant consequence is explicit: **a view-only file cannot be opened in a native application.** The viewer remains available, enforcing rather than circumventing the restriction. Letting such a file into the broker by asking for viewing would falsify the promise above and repeat the exact bug already described as found and fixed.

**The recipient-side decision consumer is `cc check`.** It answers “may I perform this action right now,” returns a distinct denial exit code, and prints the reason; the viewer will ask the same question before every action. It is a separate command, not an `unprotect` flag, precisely because this is the **recipient's** question, not the author's.

What it can say today deserves precision—otherwise “policy is applied” will be read as “policy works.” `evaluate` checks the lease **before** validity and the specific action, so the user learns “access revoked” rather than “printing forbidden.”

> **The paragraph above once silently became outdated, worth remembering.** It said “leases do not exist: the server issues them” and “validity rejection becomes reachable only with the server.” The server arrived in F-7 (`cc-authority`, binary `cca`), leases are issued, and validity and action refusals are observable through the process—yet the text remained. In this repository the specification prevails over code in a conflict, making stale specification more dangerous than stale comments: people use it as truth.

The client labels time as what it is, and now has **two** sources.

The system clock (`TimeSource::Wall`) provides `now`. A persisted monotonic floor—the greatest timestamp the client has ever seen—protects against turning it back; stored beside the keys, it survives restart, otherwise closing the program would suffice for an adversary.

The TPM hardware clock has participated since 2026-08-20 and does **two different things**. First, it catches direction: a reading below the lease-bound reading means snapshot rollback together with a virtual TPM. Second, more importantly and added later, reading differences measure **elapsed time**, closing “copy profile, restore it, turn back the system clock”: resetting the clock cannot lengthen a quantity that profile restoration does not touch.

The monotonic floor remains and cannot be removed: the TPM clock advances only while the machine is powered on, so hardware time alone would admit an expired lease on a machine left off for a week. Rejection by either source is strictly stronger than either alone.

### 4.2 What `online` means and what it does NOT mean

`Context.online` feeds two rules: `Network::StrictOnline` (network on every opening) and `Validity::FromFirstOpen` without a first-opening record (until recorded, opening requires online access and the server records the time). Both reject for `online = false` and proceed for `online = true`. Thus `online` is neither a diagnostic nor a convenience: it is **decision input**, and whatever sets it is part of protection.

**Normatively, `online = true` means the client received a FRESH verified lease, and may mean nothing else.** Fresh means issued no more than `FRESH_LEASE_SECONDS = 60` ago. Verified means its signature matches `authority.lease_verify_key` from OUR container header, where the author pinned it under their signature.

Three seemingly natural things that **must not** set `online`:

1. **An established connection.** An open socket proves somebody answered on our port, not that it is the server or that the server permitted this device to access this file. The cheapest mistake in the class, it cancels `StrictOnline` entirely.
2. **An unexpired lease.** Leases last hours; `StrictOnline` requires network on every opening. A file once opened with a network would then open for eight hours without it—the very offline window `StrictOnline` exists to remove.
3. **Wall-clock freshness.** The person opening the file controls “now minus issue time”: turning the clock back to issuance makes a year-old lease fresh. Freshness is a statement about time and is not a statement without trustworthy clocks (`TimeSource::TpmClock` or `ServerAsserted`).

A future lease (`issued_at > now`—clock disagreement or forgery; either prevents measuring freshness) and an expired lease (freshly issued yet expired is contradictory; accepting it would count as connectivity something the server already canceled) are also rejected.

**What `online = true` does not promise.** Connectivity at decision time: the network may fail between issuance and decision. This difference is inherently unavoidable—“online” is a statement about the past, however recent—and must be explicit so the rule is not mistaken for a delivery guarantee.

The rule is enforced by **type and acceptance rule**, not convention. `access::Online` has two “yes” constructors, both constrained. `from_fresh_lease` requires `lease::VerifiedLease` and trustworthy clocks—the freshness in item 3. `just_received` asserts connectivity from an EVENT in this process (“the server just responded with a signed lease”), independent of the machine clock: without it, an online-only file would open only with a TPM clock—an ordinary machine always has an “untrustworthy” time source and would never become online.

The second constructor's truth depends on the **acceptance rule**: accept a lease only if its number is STRICTLY HIGHER than the greatest already accepted for the file, raising the floor AT ACCEPTANCE (`cc-cli/src/activate.rs`, `store_from`). A replayed conversation therefore cannot become connectivity: its signature is genuine, but its number already accepted. Signature alone is insufficient by construction—signed bytes are always the same, and a recipient directing remembered addresses to their own listener could present yesterday's lease as today's. The evaluator does not catch this: it rejects `seq < highest_seq_seen`, strictly smaller, while replay presents equality.

A comment cannot enforce this: while the parameter was `bool`, three neighboring comments silently became stale, continuing to justify hardcoded `false` by the server's nonexistence.

---

### 4.3 Composition: author ∩ server, field by field

Recorded on 2026-09-16 with lease version 2 (`docs/protocol.md` §2.3). Before then, “the server can only tighten” was a general sentence with nothing to check it against: each policy field has its own lattice, and “minimum” tightens one field while loosening another.

Composition is computed by `oc_policy::intersect(author, server)`; its result is the decision policy. It must be **monotonic toward denial for every field**: no server profile may broaden access beyond what the author granted. This is I-10, checked by property tests over random pairs, not case analysis.

| Field | Composition | Rationale |
|---|---|---|
| `actions` | **intersection**: an action remains only if both allow it | the map stores only permissions; absence means denial; union would add rights |
| `max_opens` | **minimum**, with `None` (“unlimited”) yielding to any number | `None` is no restriction, not zero; treating it as zero would close a file nobody closed |
| `network` | either side's `StrictOnline` wins; two `Lease` values take the **minimum** of both periods | `StrictOnline` is stricter than any offline allowance by definition |
| `min_binding` | **maximum** in `Software < Hardware < HardwareAttested` order | order represents binding strength; minimum would permit weaker hardware |
| `action_binding` | **maximum** per action; a requirement specified **only by the server** enters the result | “editing only at hardware tier” tightens policy and must not disappear because the author said nothing |
| `watermark` | **logical OR** | a mark is an obligation, not a right: either party's requirement is enforced |
| `validity` | `Always` yields to the other member; two windows take the maximum start and minimum end; two first-opening durations take minimum duration; **heterogeneous pair means denial** | a window and first-opening duration are independent, `Validity` cannot carry both, and choosing either expands relative to the other |
| `unknown_actions` | **union** | something unknown to either side means policy is incompletely understood, and `evaluate` refuses on that basis |

Two table rules deserve explicit repetition because both are easy to implement backward.

**`None` in `max_opens` is not zero.** Policy fields divide into limits and permissions with opposite defaults: absent permission means denial (I-10), absent limit means no limit was set. They cannot share a default in either direction.

**Heterogeneous validity periods yield denial, not a choice.** Choosing the “stricter” one is impossible: whether a window is stricter than three hours from first opening depends on when opening occurs. Any choice broadens access relative to the discarded member, which composition must not do—this sustains the promise that even a compromised server cannot weaken author policy. If such a pair is needed in practice, the right answer is a `Validity` member carrying both restrictions, hence a policy-format change and separate decision, not a silent choice within the function.

**Where composition runs.** Inside `oc_policy::evaluate`, before the first check, not in callers. The evaluator has four callers—`cc check`, `cc unprotect`, the viewer (`Session::permit`), and the broker—and one would eventually forget manually applied tightening. The server profile arrives in lease facts (`LeaseFacts::server_policy`), so forgetting it requires failing to pass the lease itself.

**An absent profile is not an empty profile.** `server_policy: None` means “the server tightens nothing,” and the decision matches author policy byte for byte. An empty policy (`Policy::deny_all`, `cca policy set --allow none`) means “I permit nothing” and closes the file. Confusing them would either close every server file or silently remove tightening.

---

## 5. Header signature

```
sig_input = "CC/v1/header-sig" ‖ 0x00 ‖ u8(suite_id) ‖ Magic ‖ u32le(HeaderLen) ‖ Header
```

**`suite_id` is the `sig_alg` value** (tag 1 inside `suite`, §2.0), one byte; for version 1, `0x01` = Ed25519. It **includes neither** `aead_id` nor `tree_hash_id`: those are already in header bytes, and the signature covers the entire header; encoding one value twice introduces a second point of divergence.

This definition arrived late, for a reason worth stating: the term appeared at three places without a definition, while §2.0 defines `suite` as **three** independent bytes—so a specification reader was entitled to interpret `suite_id` as a registry number for the triple. The defect was masked because the only executable suite had `sig_alg = aead_id = tree_hash_id = 1`: almost any wrong guess yields the same `0x01`, and compatibility appears sound. Divergence would emerge with a second identifier—after freezing and issuing files—as “signature mismatch,” without a cause (the format deliberately does not distinguish key-parsing failure from an invalid signature).

Exactly one zero byte follows the label, supplied by the transcript constructor; `Header` is last and **has no length prefix**—its length is already bound by the preceding `u32le(HeaderLen)`. RFC 9180's `suite_id` mentioned in §3.5 is **a different** byte: that discussion concerns `kem_id` in K10's `info`.

**Raw bytes** are signed, not a reserialized parsed structure. Reserialization causes the entire family of JWS and XML-DSig canonicalization errors. Consequently, the parser API must preserve the parsed byte range, and each hash (`policy_hash`, `core_hash`) is computed over that range, never re-encoding. The header has no separate `policy_hash` field—that would hash its own signed contents.

### 5.1 Parsing order

```
1. compare Magic
2. read HeaderLen; reject if > MAX_HEADER_LEN or the file is shorter than 8+4+len+64
3. split the buffer into header and signature       ← no cryptography
4. decode the header FOR TWO VALUES: author_key and suite
5. VERIFY Ed25519 over the raw header bytes using the transcript (§5)
6. check min_reader_version and container_version
7. everything else happens only after step 5
```

The 4 step must precede the signature verification: both the author’s public key and the set of algorithms are contained
**within** the header, and without them, there is nothing to use to verify the signature. The order “verify first,
then parse” is literally unfeasible for any format that carries the signer’s key within itself.

This deviation is safe only to the extent that the decoder is **total**: it does not panic, does not loop indefinitely,
and does not allocate memory based on an unverified length. This requirement exists independently of the order—§5.2
explicitly states that anyone can sign a malicious header—so the 4 step does not add
any work to the decoder that it would not already be required to do after the 5. step

The cost of this concession is explicitly stated: a decoding error takes precedence over a signature error. A file with an unknown
critical field and a garbage signature results in an “unknown critical field,” not a signature failure. Externally,
this returns a single bit (“header parsed”), and the attacker obtains this bit anyway by signing
its own header with its own key.

Ed25519 is verified against **`verify_strict`**, not `verify`: otherwise, malleability is inherited via the cofactor and a non-canonical `A`, and the “one signature—one file” property is lost.

### 5.2 A verified signature does not imply a trusted signer

Taking the author’s public key **from the header itself**, verifying the signature with that same key, and calling the result
“verified” amounts to self-signing, which proves exactly nothing: a malicious header is signed
with its own key. Therefore, `verify_and_parse` returns trust as a separate value; `cc inspect`, by
default, displays “signature is valid—signer UNKNOWN,” and the viewer shows a prominent
banner until the key is pinned to a trusted store.

Signature verification does not make the decoder secure: anyone can sign a malicious header.
Fuzzing the decoder is mandatory, and the harness maintains its own signing key and its own MAC key—
otherwise, deep branches (parsing after signature verification, parsing the body of the modifiable area after MAC verification)
are unreachable.

**Key pinning on first use.** The only thing to which pinning can be tied is—
`org_id`: there is no author name in the header (§2, 5 tag). The “organization, author key” pair is pinned
after **successfully opening** the file, not after parsing: any sent container can be parsed,
and pinning upon parsing would allow one to claim the record before the actual sender, without having a single
key. Only the recipient can open the file.

A second key for a known organization results in a **rejection**, not a second entry or a warning. Multiple
keys per organization would mean that a key swap is always “known,” i.e., the binding does not verify
anything. An honest key change is indistinguishable from a key swap (the signature is valid in both cases),
so the default is a rejection, and removing the binding is an explicit human action.

The boundary is stated explicitly: it catches key substitution by a known organization, but not an attacker who has posed as a new organization—the attacker will remain unknown. True key binding to an identity requires a key directory with a transparent log and pertains to the server phase.

---

## 5.3 Packing Order

The order of calculation is the reverse of the order in the file, and this is not an implementation detail: the header comes first, and
depends on what follows it.

1. Generate `file_id` (16), `header_salt` (32), `CEK`, `secret_A`, `secret_B`.
2. Output `K3` and encrypt the payload in chunks, accumulating the tree leaves. The result goes to the
   **intermediate storage**, not to a file: the header does not yet exist, and it is written first.
3. Get the root of the tree.
4. Assemble the **frame** of the header: all fields except for the slots and `wrapped_cek`. Calculate `core_hash` and
   `policy_hash`.
5. Output `KEK`, wrap `CEK` (`wrapped_cek`), calculate the slot commitment, and seal the slots.
6. Assemble the entire header. **Recalculate `core_hash` and verify against 4**—the assumption on which the entire two-pass process relies must be verified, not simply assumed: if the core hash does, after all, depend on the key material, the file will be unreadable, and this must be detected here,
   not by the recipient.
7. Sign the header (§5), assemble the modifiable region with the MAC at `K6`.
8. Write: `Magic`, `HeaderLen`, `Header`, `HeaderSig`, `ContentDesc`, and the payload from
   the temporary storage.

The temporary storage must be a file, not memory. Keeping ciphertext in memory means
imposing the limit that “the document must fit into RAM”—when working with
4-gigabyte files, this is not a limit but a refusal to operate.

The write operation is **atomic**: temporary file, `fsync`, renaming. An interruption—such as a power outage, a full disk, or process termination—must leave behind either a finished container or nothing at all. A file with the
extension `.cc`, half-written, appears to be a container but is not; the recipient learns of this only when opening the file, while the sender never does.

## 5.4 Opening Procedure

The standard checklist, symmetrical to §5.3., did not exist until the second round of the review: §5.1 describes the analysis of the
**prologue** and ends with “everything else—only after the 5 step,” while the remaining requirements were
scattered across five sections. The order of checks is precisely where the second implementation improvises, and
the spec did not require the three steps from the list below at all.

```
 1. Structure: Magic; bounded HeaderLen; file length at least 8+4+HeaderLen+64.
    No cryptography.
 2. Parse the entire header: TLV, strictly increasing tags, reject an unknown
    critical tag. The departure from "signature first" is explained in §5.1.
 3. Verify the author's signature: verify_strict, transcript §5, over RAW bytes.
 4. Versions: min_reader_version ≤ supported; container_version is within the
    readable range (§2.1).
 5. Return signer trust separately, for the key used to verify the signature.
    Success at step 3 does not establish trust (§5.2).
 6. Compute policy_hash (§4.0) and core_hash (§3.2) over byte ranges.
 7. Select a slot. For each slot of the reader's kind, BEFORE key agreement:
    a) compare key_fpr, if present, with the reader's key in constant time;
       a mismatch skips the slot rather than rejecting the file;
    b) skip a slot whose kem_id the reader does not parse WITHOUT EXAMINING
       its field lengths (§3.3);
    c) construct slot_info from the kem_id DECLARED in the slot (§3.5, K10);
    d) bound the number of expensive attempts.
    Open the slot: aad = policy_hash.
 8. Split the opened blob into shares and derive KEK (K1).
 9. Compare the slot commitment (K9) in CONSTANT TIME, then and only then
    open the CEK wrapper (aad = core_hash). §3.2.
10. Derive the mutable-region MAC key (K6) from CEK.
11. Mutable region: length prefix → limit → bounds → constant-time MAC
    verification → ONLY THEN parse the TLV body (§1.2). Take the region's
    offset from the prologue split, not a recomputed header length.
12. Check the relationship of chunk_count to total_len and chunk_size (§6.1).
13. Reject version_counter ≠ 0 (§1.2). REPLACED 2026-09-17: editing is executable;
    see "EDITING IS EXECUTABLE", item F (editor signature; reference counter
    from the accepted-edition journal).
14. tree_root == original_root, constant time, UNCONDITIONALLY (§1.2), for
    counter zero; for an edit, the editor's signature authenticates the root (item F).
15. Derive framing ONLY from authenticated quantities; recompute the root
    from frames (leaf = nonce ‖ tag ‖ ct, no key needed), compare with tree_root
    BEFORE decrypting the first chunk. Reject missing frames, a mismatch in
    covered length or trailing bytes after the last frame.
16. Decryption: verify each chunk's tag before releasing bytes (§6.5).
    Private metadata (K5) comes afterwards.
17. The private-metadata name is untrusted input: validate it as a NAME,
    not a path, before any disk write (§2.0, tag 1). Reject rather than repair.
```

Three steps are worth highlighting: the code performs them, but the spec has not required them so far, and the second implementation,
which reads it literally, was entitled not to perform them.

**Step 15: Verify the root before decryption.** §6.5 requires only a tag for each chunk, while §6.3 explicitly removes
the responsibility for truncation from the tree—it follows that the implementation is entitled to stream the unencrypted
text and verify the root at the end. This was the case in this repository, and it was addressed as a separate item.

**Step 7, verifying `key_fpr` before key reconciliation.** §3.3 explains why the field exists, but does not
require it to be checked.

**Step 12: Linking the number of chunks to the length.** The formula has only just appeared in §6.1 (-11).

---

## 6. Payload

### 6.1 Chunk frame

```
nonce(24) ‖ ciphertext(len_i) ‖ tag(16)
AAD_i = "CC/v1/chunk" ‖ file_id(16) ‖ u32be(i) ‖ u8(aead_id)
```

**Frame boundaries are derived, not read from the file.** The complete rule:

```
chunk_count = max(1, ⌈total_len / chunk_size⌉)          // relationship between two authenticated numbers
len_i       = chunk_size                for i < chunk_count − 1
len_last    = total_len − (chunk_count − 1) · chunk_size
frame_i occupies 24 + len_i + 16 bytes
```

All chunks except the last are therefore **full**, and the last brings the total to exactly `total_len`. An empty file is a special case included by the formula: `total_len = 0` gives `chunk_count = 1` and `len_0 = 0`, one 40-byte frame. This cannot be written as inequality `(chunk_count−1)·chunk_size < total_len`, which specifically rejects an empty file.

Both numbers come **only** from authenticated values: `chunk_size` from the signed header, `total_len` and `chunk_count` from the mutable region under its MAC. No boundary is read from payload bytes themselves—otherwise the adversary would control where frames fall.

The rule was recorded during the second review round (R-11); previously the specification said only `ciphertext(≤ chunk_size)`—a range, not a derivation. A second implementation could not locate frame boundaries **at all**: “no greater than chunk_size” does not determine a particular frame's length. Half of §6.4's truncation argument also depends on this rule and had rested on an unwritten premise.

**The nonce is stored, not derived.** Overhead is 24 bytes per 64 KiB—0.037%.

A 192-bit width addresses **accidental collisions**: probability after 2⁶⁴ chunks is roughly 2⁻⁶⁵. This previously said “a 192-bit nonce exists precisely to make random values safe,” contradicting §3.1 where the same width is declared insufficient. The contradiction was resolved in favor of §3.1 because width addresses only one of two scenarios. The other is **generator-state repetition**: VM snapshot rollback, disk-image cloning, backup restoration. Width does nothing against it because the entire generator repeats, not merely a value, and the payload key repeats with the nonce—`CEK` and `header_salt` come from the same source.

Random bytes therefore enter the derivation's **seed**, not the nonce directly:

```
seed    = 24 random bytes                                           // never stored
nonce_i = HKDF(salt=seed, ikm=chunk plaintext, info="CC/v1/frame-nonce")[..24]
```

Plaintext participates in derivation, so different chunks produce different nonces when the generator repeats. This does not contradict “nonces are stored, not derived”: the **sender** derives it from values unavailable to the reader and places the result in the file—the reader still takes a ready-made nonce. The boundaries match §3.1: generator repetition with **identical** plaintext also yields identical ciphertext, revealing only that the inputs are equal.

Deriving a nonce from `(file_id, chunk index)` is fatal: `file_id` must remain constant (file identity, log key, revocation key), so rewriting a chunk under the same CEK would reuse the nonce with different plaintext—recovery of both texts through XOR and recovery of the one-time Poly1305 key, hence forgery.

The AES-256-GCM profile must use counter nonce `N_base(K4) ‖ u32be(i)` with a hard chunk-count limit: a 96-bit nonce cannot be random at these volumes, and AES-GCM containers are effectively write-once. This rule is **conditionally** normative, should `aead_id = 2` ever become executable. Today parsing rejects it (§4), and no issued container carries it.

**`aes-gcm-siv` does NOT apply to editable files**, and the word “applies” that appeared here was
incorrect. The phrase originated from the first snapshot of the repository (`f29a800`) and survived a mechanism that stripped
its meaning: SIV was named for its resistance to nonce repetition when rewriting a chunk, and this resistance is provided by
a seed from plaintext—described in the paragraph above and introduced later (`ef3e055`, section P-2).
The guarantees are identical right down to the wording: in the event of a repeated input, only the fact of
equality between the inputs is revealed. Creating a second profile for a property that already exists would mean introducing a new
dependency and a second branch at every point in the analysis for no new value.

Editable files are therefore encrypted using the same `aead_id = 1` as all others. The 3 identifier
remains occupied and non-executable in the registry: it cannot be reused (§4).

### 6.2 Size of the bucket

Default **64 KiB**. Word, Excel, and Photoshop access OLE and ZIP directories through a multitude of small,
scattered reads, and with a 4-kilobyte read from a megabyte-sized chunk, a 256-fold increase in read operations—
this results in noticeable lag, not just an effect on a microbenchmark.

| chunk | 4 KiB increase | overlay | 4 GiB of leaves |
|---|---|---|---|
| 16 KiB | 4× | 0.24% | 262 144 |
| **64 KiB** | **16×** | **0.061%** | **65 536** |
| 1 MiB | 256× | 0.004% | 4 096 |

`cc protect` selects the size based on the content type: 64 KiB by default, 1 MiB for video and large
sequential reads, and 16 KiB for database-type files.

### 6.3 Tree

```
leaf_i = H(0x00 ‖ "CC/v1/leaf" ‖ u32be(i) ‖ u64be(len(ct_i)) ‖ nonce_i ‖ tag_i ‖ ct_i)
node   = H(0x01 ‖ "CC/v1/node" ‖ left ‖ right)
apex   = MTH according to RFC 6962 over the leaves
root   = H(0x02 ‖ "CC/v1/node" ‖ u32be(leaf_count) ‖ apex)
```

`ct_i` is the ciphertext of a frame **without a tag**, that is, exactly `len_i` bytes between the nonce and the tag (§6.1).

Hash — BLAKE3 (`tree_hash_id`), which is tree-based and 5–10 times faster than SHA-256. SHA-256
is still used for header and policy hashes.

#### Why ciphertext is included in the list

This addresses a defect found during the second round of review (`docs/plan.md`, P-1), and, more importantly, it’s essential to
understand the role of the tree.

Before the fix, the list only bound `index ‖ nonce ‖ tag`. It seemed that the tag was sufficient: it is calculated from the ciphertext. But **the tag binds the content only for someone who does not know the key.** Poly1305 is a
universal hash function, not a collision-resistant one: given a known key, forgery is not a search but
solving a linear equation. The CEK holder derives the payload key, takes `(r, s)` as block 0 of the
ChaCha20 on `(key, nonce)`—the nonce is stored in the file in plaintext—and computes a second ciphertext with the same
tag in a single modular operation. The tag is truncated to 2^128 when p = 2^130−5, so a single tag corresponds to
approximately four accumulator values, and the solution is found in a matter of a few attempts. The cost of forgery is 16 bytes of
garbage in an aligned block **of the attacker’s choice**.

Verified by execution, not by theory: a 64 KiB chank forgery with a bit-for-bit identical tag was
accepted by the reference implementation of XChaCha20-Poly1305.

Why did this specifically break the promise in §1.2? The CEK owner overwrites the entire modifiable region, including
`tree_root`, `total_len`, and `version_counter`: the MAC is stored in K6, and K6 is derived from the CEK. The only value
they cannot tamper with is `original_root` in the signed header. This means that **all**
protection of the content against them depended on this single value, and it did not depend on a single byte
of the ciphertext. Additionally, the length turned out to be malleable: the message length is included in the final block of the
Poly1305, but the key holder solves the equation even with a new length, and the frame boundaries are derived from the
`total_len`, which lies under the same MAC—that is, the tail of the document shifted within the limits of a single chunk.

BLAKE3 is collision-resistant regardless of what the adversary knows, so including `ct_i` in the leaf
restores its original meaning to the signed root: it once again binds every byte of the content.

What **has not** changed: the frame layout (`nonce ‖ ct ‖ tag`, §6.1), the tree structure, the rule for
advancement, and the order of checks. Only the values of the leaves and roots have changed. The property “the root
is verified before decryption” is fully preserved—hashing the ciphertext does not require a key, and the first
pass of the reader remains keyless; the cost is one BLAKE3 pass on the payload instead of forty bytes per
chunk, and this cost is justified precisely by the reason BLAKE3 was chosen in the first place. The O(log n) incremental update is also
preserved: the leaf’s prototype is updated, not the tree’s structure.

`u64be(len(ct_i))` is explicitly defined, even though `ct_i` comes last and the encoding is unambiguously lengthless.
Injectivity should not rely on the reasoning that “the tag is always the last 16 bytes of the frame, so
the boundary is visible”: this is true today but will silently break at the first change to the frame layout.

**The format version has not been incremented with this change.** `docs/plan.md` I-14 requires incrementing it along with the
re-release of frozen vectors, and here this decision was made deliberately and in the opposite direction:
`container_version = 1` was never released—there are no containers outside the repository—and
`tests/golden/*.cc` and `tests/kat/tree.kat` were re-released in the same commit. Incrementing to 2 would have left a phantom version in the registry that did not exist in reality, and would have forced `min_reader_version` to be incremented as well.
The decision was made on 2026-08-17; it cannot be reused—once version 1 is released externally,
any modification to the prototype requires a new version.

An odd node is **advanced**, as in RFC 6962, rather than duplicated: duplicating the last node
reproduces the CVE-2012-2459 vulnerability class, where different sets of leaves yield the same root.

**`root` is passed to the outside, not `apex`,** and this is the third mandatory step, not an implementation detail. Specifically,
`root` is contained in `original_root` under the author’s signature and in `tree_root` under the MAC of the modifiable region.
Reason: the proof verification chain sees only the sequence “a neighbor appended on the left or right,”
and the advanced level adds nothing to it—therefore, the same path format corresponds to
many pairs (index, number of leaves). For the pairs (0, 3) and (0, 4), the forms match bit-for-bit; for (1, 2), they match with
(2, 3), (4, 5), (8, 9), and so on; by enumerating up to 20 leaves, there are 43 such classes out of 47. There is no distinguishing
information in the form does not exist and cannot exist, so the number of leaves must be included in the hash: otherwise, a path,
honestly generated for the leaf `i` of a tree consisting of `n` leaves, would also serve as a confirmation of another location in a
tree of a different size. RFC 6962 addresses the same issue externally—the tree size is included in the signed
STH; here, it is included in the root itself.

The binding based on the number of leaves does not prevent appending to the end: adding a chunk changes the entire root anyway—
unlike the `chunk_count` in AAD, which §6.4 prohibits precisely because it would
invalidate all chunks at once.

Domains are separated by a **prefix byte**, not by a third tag: `0x00` leaf, `0x01` internal node, `0x02`
root. The `"CC/v1/node"` tag therefore appears in two constructions, and this does not violate the rule in §3.6
“no tag is used twice”: the rule refers to the separation of domains, and the separation here is
provided by a byte that comes **before** the tag and has a fixed width. Introducing
`"CC/v1/root"` would require an entry in the prefix-free tag registry—for the sake of a domain that is already
unambiguously separated. The fixed width of `u32be(leaf_count)` prevents the parser from “going off track.”

The tree is responsible for O(log n) random reads, incremental updates during
writes, and the root for anchoring. It **is not** responsible for detecting truncation—this is handled in §6.4.

### 6.4 Truncation and Order

`total_len` and `chunk_count` reside **only** in the MAC-protected `ContentDesc`. This detects truncation
immediately upon opening, whereas the STREAM structure’s terminal marker would detect it only when
reading the tail—and the virtual file system may never reach the tail.

`chunk_count` and the last chunk indicator **must not** be placed in the chunk’s AAD. This would allow detection of
truncation at every chunk, but appending to the end would invalidate all existing chunks, and
every save from the application would turn into a complete file overwrite.

Swapping and substitution from another file are detected because the `file_id` and chunk number are included in the AAD.

### 6.5 A Rule That Must Not Be Broken

Unverified bytes are never returned to the outside. The chunk’s AEAD tag is verified before copying the data to the caller; if an error occurs, the buffer is overwritten, and the caller must treat it as invalid.

---

## 7. Known Plaintext Leaks

**The exact file length is visible to any container holder.** `ContentDesc` is MAC-verified but **is not
encrypted**, so `total_len` can be read without a single key. This is by design and cannot be done any other way:
the length is needed before the key is extracted—the reader uses it to frame the stream and detect truncation
immediately upon opening, rather than when the read reaches the end (for a virtual file system, “reaching the end” may never happen, §6.4).

The cost is stated explicitly: the exact size is a strong fingerprint. Anyone with a set of candidate documents can
compare the size with byte-level precision and often guess the document without opening it. Padding
would solve the problem, but it requires that the true length be embedded within the ciphertext—that is, that framing
and truncation detection cease to function until the key is obtained. In Version 1, truncation detectability was chosen;
a revision involves changing the layout of the modifiable region, not a flag.

Plaintext leaves controlled memory via the swap file, hibernation file, and crash
dumps. Therefore, the cache of decrypted chunks must be protected with `VirtualLock` along with an extension of the working set,
and the process requires `WerRegisterExcludedMemoryBlock` and dump suppression. Without this, the acceptance criterion—
“searching the disk for a canary string after a session yields no matches”—will fail, and
it will fail in substance, not just formally.

**The scope of this criterion is a VIEWER session.** This clarification is not a relaxation but a correction:
the criterion is stated unconditionally, and in this form, it would declare the path described below to be nonexistent.

**The open text is written to disk when the document is opened with its NATIVE application.** The broker
(`ccbroker`, §4.1) displays the document to the actual Word or Acrobat via the Cloud Filter API, and those applications
read the file from disk: the application constructs a section object, and a section over data missing from disk
is not constructed. This has been verified in a live Word instance, not merely inferred from the documentation, and there is no streaming alternative—
it was, in fact, the first attempt.

The promise that “open text does not touch the disk,” which is true for a viewer, is **incorrect** in this context, and
it should be phrased this way, rather than as “the file does not leave the protected area.” The cost is limited to three
things, and each is a mechanism, not an intention:

* **window**—from the driver’s first read until dehydration via `NOTIFY_FILE_CLOSE_COMPLETION`, that is,
  until the application closes the document;
* **list of applications**—the file is hydrated only by the specified application; the indexer, antivirus, and
  backup service receive `STATUS_CLOUD_FILE_ACCESS_DENIED`, not the contents. This does not protect against the machine’s owner, nor can it;
* **cleanup on startup** — the broker bypasses its synchronization roots and dehydrates what remains
  from the interrupted session: terminating the process and powering down leave the file hydrated, and
  there is no other moment when we are definitely alive and know our roots.

This path requires a separate permission: `Action::Export`, not viewing (§4.1). A file with only a single
view cannot be opened by its native application.

`zeroize` does not erase values that the compiler has copied, moved, or pushed onto the stack:
secrets remain with their sole owner.

---

## 8. What Is Reserved for the Future

Extension points that cannot be added later without breaking compatibility, which is why they are included
in version 1, even though the code does not yet use them: `container_version` and `min_reader_version`;
the separation of critical and optional tag ranges; algorithm identifiers and `kem_id` for each slot;
wrapping the CEK in a separate header field;
`KeySlot::Unknown`; separation of immutable and mutable regions with `version_counter`; `chunk_size`
as a validatable field; stored nonces; a byte of flags per chunk (compression, sparsity, daily
profile); numeric policy tags with a default prohibition; `authority` as a list with a pinned
leasing signature key; `min_binding`; rollback protection fields in leasing; `private_meta` under a
private key; `prev_header_hash`; `org_id` in each `info` line; `footer_offset`; `class`.
