//! Key schedule: derivations K1…K9 from `docs/format.md`, section 3.5.
//!
//! Each function corresponds to exactly one table row. No label is
//! used twice, and each derivation includes `file_id` to prevent keys from
//! matching across files even when the initial secrets match.

use crate::secret::{
    Cek, ClaimSecret, Kek, MacKey, MetaKey, PayloadKey, SecretA, SecretB, SessionMacKey, SECRET_LEN,
};
use crate::{label, AeadAlg, CryptoError};

use hkdf::Hkdf;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// K1 ikm length: exactly two 32-byte shares.
///
/// Hardcoded as a constant rather than derived from argument lengths because
/// fixed length is a condition of the combiner's correctness, not an
/// implementation detail.
const KEK_IKM_LEN: usize = 64;

/// Expand HKDF-SHA256 into a buffer whose length is specified by its type.
///
/// `expand` fails in only one case: requesting more than 255×32
/// bytes; here the array type specifies output length, at most 32 bytes,
/// so the error branch is unreachable. K1…K8 therefore return a key rather than `Result`:
/// threading an impossible variant through every key-schedule call would
/// train callers to use `?` where nothing can fail.
/// Returns a wiping wrapper rather than a bare array.
///
/// This function outputs key material. A bare `[u8; N]` remains on the stack until
/// the calling function ends and can enter the pagefile with it, without an owner
/// to wipe it on destruction. The wrapper makes wiping
/// a property of the type: previously every caller had to remember it individually,
/// and not all did.
fn hkdf_sha256<const N: usize>(salt: &[u8], ikm: &[u8], info: &[&[u8]]) -> Zeroizing<[u8; N]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = Zeroizing::new([0u8; N]);
    // Результат игнорируется осознанно: альтернатива — паника, запрещённая в
    // этом крейте. Вырождение буфера в нули поймал бы тест
    // `every_derivation_of_the_schedule_is_domain_separated`, который сравнивает
    // все производные схемы между собой.
    let _ = hk.expand_multi_info(info, okm.as_mut_slice());
    okm
}

/// A nonce not wholly dependent on RNG state (hedged nonce).
///
/// **Why.** A random nonce is safe only while the RNG does not
/// repeat, and nothing guarantees that: virtual-machine snapshot rollback,
/// disk-image cloning, and backup restoration return
/// the RNG to a previous state. A separate random value does not
/// help: it comes from the same RNG and repeats with it,
/// repeating the entire keystream. For slot sealing the cost is
/// maximal: plaintexts are shares of a 2-of-2 secret-sharing scheme, and repetition gives
/// `ct₁ ⊕ ct₂ = pt₁ ⊕ pt₂`, hence both shares, the KEK, and the content key without a single
/// private key.
///
/// **How.** Since version 3, `HKDF-Extract(salt = RNG seed,
/// ikm = u32be(len(pt)) ‖ pt ‖ u32be(len(aad)) ‖ aad)`, then `Expand(info = label)`.
/// AAD is exactly what AEAD receives: with a repeated RNG, identical plaintext
/// in a different context gets a different nonce. This is hedging, not SIV:
/// the key is not part of the seed; fully repeated inputs still repeat the nonce.
/// Both lengths are mandatory because the parts have variable widths (the K1 argument).
/// Lengths unrepresentable as u32 and excessive output lengths return BadLength.
///
/// **This does not contradict "nonces are stored, not derived".** The rule
/// exists to prevent a nonce being a function of values available to the reader:
/// derived from the shared secret, it would match whenever that secret matched.
/// Here, conversely, the nonce derives from what the reader lacks (seed,
/// plaintext) and **is stored in the file**; the reader still takes it
/// ready-made and never computes it.
///
/// The seed is never stored anywhere: it is needed only during computation.
///
/// The label has type [`label::Label`]: nonce hedging is also a domain, and
/// its four labels (K17–K20) are registered alongside the others. Passing a
/// fifth label invented on the spot would derive a nonce in a domain
/// unknown to §3.6.
pub fn hedged_nonce<const N: usize>(
    label: label::Label,
    seed: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<[u8; N], CryptoError> {
    let pt_len = u32::try_from(plaintext.len()).map_err(|_| CryptoError::BadLength)?;
    let aad_len = u32::try_from(aad.len()).map_err(|_| CryptoError::BadLength)?;
    // Потоковый Extract не создаёт вторую копию открытого текста в куче (И-11).
    let mut extract = hkdf::HkdfExtract::<Sha256>::new(Some(seed));
    extract.input_ikm(&pt_len.to_be_bytes());
    extract.input_ikm(plaintext);
    extract.input_ikm(&aad_len.to_be_bytes());
    extract.input_ikm(aad);
    let (_, hk) = extract.finalize();
    let mut out = [0u8; N];
    hk.expand(label.as_bytes(), &mut out).map_err(|_| CryptoError::BadLength)?;
    Ok(out)
}
/// `HMAC-SHA256` over a sequence of message pieces.
///
/// Pieces are fed sequentially rather than concatenated into a buffer: concatenation would
/// allocate memory for a message needed nowhere else.
fn hmac_sha256(key: &[u8], message: &[&[u8]]) -> [u8; 32] {
    let mut tag = [0u8; 32];
    // `new_from_slice` у HMAC принимает ключ любой длины (длинный хешируется,
    // короткий дополняется нулями), поэтому ошибка недостижима.
    if let Ok(mut mac) = <Hmac<Sha256> as KeyInit>::new_from_slice(key) {
        for part in message {
            mac.update(part);
        }
        // Выход HMAC-SHA256 всегда 32 байта, длины совпадают по построению.
        tag.copy_from_slice(mac.finalize().into_bytes().as_slice());
    }
    tag
}

/// K23: proof of opening the challenge without revealing the secret itself.
/// The challenge remains secret between two parties: the public echo cannot derive K24.
/// All 64 bytes of the hardware challenge enter the HMAC key; output is always 32 bytes.
///
/// **NOT USED by the protocol since 2026-09-21.** [`echo_transcript`] computes the echo
/// (K31): the old form bound nothing but the
/// secret to the conversation, so a recorded echo worked in any conversation repeating that secret.
/// For the decision and its limits, see `docs/format.md`, section "ECHO BOUND TO THE CONVERSATION
/// 2026-09-21".
///
/// Retained for the frozen `k23_prove_echo` vector
/// (`tests/kat/derivations_wire.kat`): I-14 forbids changing frozen artifacts, and
/// removing the derivation would leave the vector without the operation it checks.
/// It must acquire no new callers; the guard
/// `the_old_unbound_echo_has_no_callers_outside_its_vector` enforces that.
pub fn prove_echo(challenge: &[u8], device_fpr: &[u8; 32]) -> [u8; 32] {
    hmac_sha256(challenge, &[label::PROVE_ECHO.as_bytes(), device_fpr])
}

/// K31, step 1: handshake transcript hash (`docs/protocol.md` §9.4).
///
/// `SHA-256("CC/v1/echo-transcript" ‖ 0x00 ‖ u32le(len(hello)) ‖ hello ‖
/// u32le(len(challenge)) ‖ challenge)`.
///
/// # What is included and why
///
/// Exactly two frames, both available in full to BOTH parties by echo time:
/// the device hello (`kind ‖ TLV`: presented keys, `device_fpr`,
/// mechanism number) and server challenge (`kind ‖ TLV`: sealed halves with
/// their `enc`, nonces, and ciphertexts). Neither connection numbers nor clock
/// readings are included deliberately: only the server knows the number, the parties have different clocks,
/// and a value known to only one party cannot be a transcript.
///
/// # Why RAW bytes rather than reconstructed values
///
/// The same argument as I-5: reconstructing parsed data would yield one byte sequence for
/// a canonical document and another for one whose canonicality is checked
/// by nothing except our own encoder. An intermediary modifying a frame in transit
/// must diverge from the honest party, which happens only when the hash
/// covers what actually traveled over the wire.
///
/// # Why lengths are included
///
/// [`Transcript::field`](crate::transcript::Transcript::field) prefixes
/// each piece with its length: otherwise ("ab", "c") and ("a", "bc") would give
/// one hash, allowing an attacker to move bytes between hello and challenge
/// without changing the echo.
#[must_use]
pub fn handshake_transcript(hello_framed: &[u8], challenge_framed: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    let mut t = crate::transcript::Transcript::new(label::ECHO_TRANSCRIPT);
    t.field(hello_framed).field(challenge_framed);
    Sha256::digest(t.as_bytes()).into()
}

/// K31, step 2: proof-of-possession echo bound to the conversation.
///
/// `HMAC-SHA256(key = challenge secret, "CC/v1/echo-transcript" ‖ device_fpr ‖
/// handshake)`, where `handshake` is the output of [`handshake_transcript`].
///
/// # What this fixes
///
/// K23 included only the fingerprint in the message. An echo recorded from the wire worked in
/// ANY conversation with the same device whenever the secret repeated, and the server
/// secret repeats after snapshot rollback (I-1, argument C-13; K30 addressed repetition,
/// but not the construction itself). The safety margin depended on the server currently issuing
/// nothing on `Proven` without a session MAC, making it just one edit thick.
/// The echo is now a function of the conversation: the server seals anew
/// in each conversation, with its own ephemeral `Seal` pair, so challenge bytes differ.
///
/// # What this does NOT provide
///
/// It does not fix full snapshot rollback TOGETHER with the clock: then both
/// the secret (time is in K30's preimage) and the ephemeral sealing pair repeat,
/// repeating the entire transcript. It does not address an attacker possessing
/// the device private key: that attacker legitimately proves possession.
#[must_use]
pub fn echo_transcript(
    challenge: &[u8],
    device_fpr: &[u8; 32],
    handshake: &[u8; 32],
) -> [u8; 32] {
    hmac_sha256(challenge, &[label::ECHO_TRANSCRIPT.as_bytes(), device_fpr, handshake])
}

/// K24: a separate key authenticating requests in this conversation.
pub fn derive_session_mac_key(challenge: &[u8], device_fpr: &[u8; 32]) -> SessionMacKey {
    SessionMacKey::from_bytes(*hkdf_sha256::<SECRET_LEN>(
        &[], challenge, &[label::SESSION_MAC.as_bytes(), device_fpr],
    ))
}

/// K27: device fingerprint for ANY agreement mechanism.
///
/// The fingerprint is the single 32-byte value a person checks
/// through a second channel and to which the author later seals a share. For X25519 these two
/// roles coincide in the key itself: it is 32 bytes, and its fingerprint equals the key.
/// This is exactly what the bequest, quorum, and approval doors relied on, and precisely
/// why they were closed to anything longer: for P-256 (65 bytes) and
/// hybrids (1216, 1249), the fingerprint was UNDEFINED, and an intermediary presenting
/// someone else's fingerprint with its own key could receive the share under its key
/// in someone else's name (review 2026-09-06, N-1 and N-4).
///
/// This definition closes the gap for every mechanism at once: the fingerprint becomes
/// a COMMITMENT to the key. Whoever receives `(fpr, kem, public)` must
/// check `fpr == device_fpr(kem, public)` BEFORE using any of
/// the three; for X25519 this is the same comparison as before.
///
/// **The form is deliberately asymmetric.** For `kem_id = 1`, it returns the key itself,
/// not its hash: K11, K21, K23, K24 vectors and the `Hello` layout freeze that behavior,
/// and unifying the fingerprints would require reissuing them without a single
/// new security fact. For the other mechanisms:
/// `SHA-256("CC/v1/device-fpr" ‖ 0x00 ‖ u8(kem_id) ‖ public)`. The mechanism number
/// is in the preimage: the same key bytes under two numbers produce different
/// fingerprints, so relabeling a mechanism changes the device name.
///
/// Key length is checked against the mechanism, not taken "as received" (I-8): a fingerprint
/// of an incorrectly sized key would do no harm, but one rule applies everywhere,
/// and making an exception here would cost more than the check.
///
/// # Errors
/// `public` length does not match the mechanism, or the mechanism defines no length
/// (RSA-OAEP: variable-length keys, with no defined fingerprint).
pub fn device_fpr(kem: crate::KemAlg, public: &[u8]) -> Result<[u8; 32], CryptoError> {
    use crate::KemAlg;
    // Исполнимость спрашивается ОДНИМ именем, а не вторым `match` рядом с
    // таблицей длин. Раньше ответ «RSA-OAEP не умеем» стоял прямо в этой
    // таблице, и таких ответов по репозиторию было четыре: разойтись они могли
    // только в сторону «механизм, которого сборка не исполняет, где-то сочли
    // исполнимым».
    kem.ensure_supported()?;
    let Some(expected) = public_key_len(kem) else {
        // Недостижимо: пробел таблицы длин совпадает с неисполнимым механизмом,
        // и совпадение это не на памяти — его держит проба
        // `the_length_table_has_a_hole_exactly_where_the_build_has_no_mechanism`.
        return Err(CryptoError::UnsupportedAlgorithm);
    };
    if public.len() != expected {
        return Err(CryptoError::BadLength);
    }
    if kem == KemAlg::X25519HkdfSha256 {
        // Отпечаток И ЕСТЬ ключ — заморожено, см. выше.
        return <[u8; 32]>::try_from(public).map_err(|_| CryptoError::BadLength);
    }
    use sha2::Digest as _;
    let mut h = Sha256::new();
    h.update(label::DEVICE_FPR.as_bytes());
    h.update([0x00]);
    h.update([kem as u8]);
    h.update(public);
    Ok(h.finalize().into())
}

/// A mechanism's public-key length is a DIFFERENT question from executability.
///
/// `None` means "this mechanism defines no key shape", currently exactly
/// unimplemented RSA-OAEP: its keys have variable length and no defined
/// fingerprint. Agreement between the two tables, a gap here and `false` in
/// [`crate::seal::supports_kem`], is tested rather than assumed:
/// length is a property of shape, executability of a build; tomorrow a
/// mechanism may have a known shape that the build cannot yet execute.
///
/// `match` without `_`: a new [`crate::KemAlg`] member must break the build here.
fn public_key_len(kem: crate::KemAlg) -> Option<usize> {
    use crate::KemAlg;
    match kem {
        KemAlg::X25519HkdfSha256 => Some(32),
        KemAlg::P256HkdfSha256 => Some(65),
        KemAlg::XWing => Some(crate::xwing::PUBLIC_KEY_LEN),
        KemAlg::MlKem768P256 => Some(crate::mlkem_p256::PUBLIC_KEY_LEN),
        KemAlg::RsaOaepSha256 => None,
    }
}

/// K25: MAC of raw frame bytes including kind, but excluding the trailing MAC.
/// No label: K24 is dedicated to K25, and the kind inside the message separates requests.
pub fn request_mac(key: &SessionMacKey, framed: &[u8]) -> [u8; 32] {
    hmac_sha256(key.expose(), &[framed])
}

/// K28: wire operation identity (`docs/protocol.md` §9.10).
///
/// `SHA-256("CC/v1/operation-id" ‖ 0x00 ‖ seed(32) ‖ u8(kind) ‖ body)`, where body is
/// the encoded request WITHOUT the identity field itself (for an activation request, without
/// tag 9: a value cannot include itself).
///
/// # Why not bare random bytes
///
/// By the C-13 argument (I-1): RNGs repeat after VM snapshot rollback, image
/// cloning, and backup restoration. A bare random identifier could match for
/// two DIFFERENT requests, giving the second request the stored outcome of the first:
/// "issued" for someone else's request or "already used" rejection for its own. Including the body in the seed
/// separates different requests even when the RNG repeats; only identical
/// requests remain identical, and sharing an outcome is correct for them.
///
/// No secret is present or needed: the identifier travels openly on the wire,
/// and requires uniqueness rather than unpredictability. An intermediary observing
/// the wire already learns it; there is nothing to forge: replay with a different body
/// is rejected by the server's body hash, and activation bodies carry a session MAC.
///
/// The kind enters the seed because activation and renewal have the same body:
/// without it, one seed would give two different operations one identity.
#[must_use]
pub fn operation_id(seed: &[u8; 32], kind: u8, body: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    let mut h = Sha256::new();
    h.update(label::OPERATION_ID.as_bytes());
    h.update([0x00]);
    h.update(seed);
    h.update([kind]);
    h.update(body);
    h.finalize().into()
}

/// Purpose of a fresh server value: attestation challenge (`docs/protocol.md`
/// §9.11.1, step 1).
pub const FRESH_ATTEST_NONCE: u8 = 1;

/// Purpose of a fresh server value: proof-of-possession secret
/// (`docs/protocol.md` §9.4).
pub const FRESH_PROOF_SECRET: u8 = 2;

/// Purpose of a fresh server value: TPM credential secret
/// (`TPM2_MakeCredential`, `docs/protocol.md` §9.11.1, step 2).
pub const FRESH_CREDENTIAL_SECRET: u8 = 3;

/// Purpose of a fresh server value: TPM credential protection seed.
pub const FRESH_CREDENTIAL_SEED: u8 = 4;

/// Purpose of a fresh server value: OAEP seed for credential protection
/// with an RSA EK.
pub const FRESH_CREDENTIAL_OAEP: u8 = 5;

/// K30: a fresh value generated by the SERVER (`docs/format.md`, section
/// "SERVER FRESHNESS IS DERIVED 2026-09-20").
///
/// `prk = SHA-256("CC/v1/server-fresh" ‖ 0x00 ‖ seed(32) ‖ u8(kind) ‖
/// i64be(now) ‖ device_fpr(32))`, then `HKDF-Expand(prk, info = label)` into a buffer
/// of the required length.
///
/// # Why not bare random bytes
///
/// By the C-13 argument (I-1): RNGs repeat after VM snapshot rollback, image
/// cloning, and backup restoration. This is worse on the server than on the client: its state
/// rolls back together with the RNG, so an "already issued" value
/// becomes unissued again, and nobody notices the repetition.
///
/// # Why TIME separates values rather than request data
///
/// NONE of the consumers has plaintext capable of distinguishing repeats:
/// an attestation challenge is pure freshness, as is a proof secret, and so are the three
/// TPM credential values (`kind` 3–5, added 2026-09-21).
/// A seed based only on
/// request data (the device fingerprint) would separate DIFFERENT devices but still
/// repeat for the same device, which is precisely the danger: two conversations with one
/// device would receive one secret, hence one echo and one session MAC key.
/// The server has a clock, and `now` already enters the handler as a parameter.
///
/// The fingerprint is a second separator rather than a replacement for time: within one
/// second, two devices must receive different values.
///
/// # What this does NOT provide
///
/// Snapshot rollback TOGETHER with the clock cannot be distinguished: `now` returns to its old value,
/// and the value repeats. This protects against RNG repetition, not an adversary
/// controlling the server clock.
///
/// # Why Expand rather than a second hash with a counter
///
/// The proof-of-possession secret consists of several 32-byte halves, one per
/// presented key, and its length is known only at runtime. Appending
/// counter-based hashes would introduce a homemade KDF beside an existing one:
/// `HKDF-Expand` uses the same counter, but standardized and already verified.
/// Thus `N = 32` is no exception: even the attestation challenge gets its 32 bytes
/// through Expand, giving one form for both applications.
///
/// # Errors
/// [`CryptoError::BadLength`]: more than 255×32 bytes requested.
pub fn server_fresh(
    seed: &[u8; 32],
    kind: u8,
    now: i64,
    device_fpr: &[u8; 32],
    out: &mut [u8],
) -> Result<(), CryptoError> {
    use sha2::Digest as _;
    let mut h = Sha256::new();
    h.update(label::SERVER_FRESH.as_bytes());
    h.update([0x00]);
    h.update(seed);
    h.update([kind]);
    h.update(now.to_be_bytes());
    h.update(device_fpr);
    // Секрет доказательства владения — ключевой материал, и prk его порождает.
    // Голый массив на стеке уехал бы в файл подкачки без владельца, который его
    // затрёт (И-11).
    let prk = Zeroizing::new(<[u8; 32]>::from(h.finalize()));
    let hk = Hkdf::<Sha256>::from_prk(prk.as_slice()).map_err(|_| CryptoError::BadLength)?;
    hk.expand(label::SERVER_FRESH.as_bytes(), out).map_err(|_| CryptoError::BadLength)
}

/// K29: qualifying data for the TPM statement about a device key
/// (`docs/protocol.md` §9.11, link 4): `extraData` in `TPMS_ATTEST`.
///
/// The challenge binds the statement to the conversation and the fingerprint to the device:
/// a statement taken for another challenge or about another key will not match.
/// No secret: the challenge travels openly on the wire; uniqueness is required.
#[must_use]
pub fn attest_qualify(challenge: &[u8; 32], device_fpr: &[u8; 32]) -> [u8; 32] {
    use sha2::Digest as _;
    let mut h = Sha256::new();
    h.update(label::ATTEST_QUALIFY.as_bytes());
    h.update([0x00]);
    h.update(challenge);
    h.update(device_fpr);
    h.finalize().into()
}

/// K1: file wrapping key.
///
/// `HKDF-SHA256(salt=file_id, ikm=secret_A‖secret_B, info="CC/v1/kek"‖org_id‖file_id)`.
///
/// `HKDF-Extract` over concatenation is a valid combiner **only** when
/// both shares have fixed lengths; types guarantee that here.
pub fn derive_kek(file_id: &[u8; 16], org_id: &[u8], a: &SecretA, b: &SecretB) -> Kek {
    // Ровно 64 байта, по 32 на долю. При переменной длине пара (A‖B) стала бы
    // неоднозначной: другая пара с тем же склеенным представлением дала бы тот
    // же KEK, и схема «2 из 2» перестала бы быть схемой «2 из 2».
    let mut ikm = [0u8; KEK_IKM_LEN];
    let (first, second) = ikm.split_at_mut(SECRET_LEN);
    first.copy_from_slice(a.expose());
    second.copy_from_slice(b.expose());

    // `org_id` входит в `info` в каждой строке схемы: без него два арендатора с
    // совпавшими долями получили бы один ключ, а разделение арендаторов должно
    // держаться на криптографии, а не на проверке поля при чтении.
    let okm = hkdf_sha256::<SECRET_LEN>(file_id, &ikm, &[label::KEK.as_bytes(), org_id, file_id]);

    // Обе доли лежали на стеке в открытом виде. Затираем немедленно, а не
    // полагаемся на выход из функции: у копии нет владельца, который затрёт её
    // при уничтожении.
    ikm.zeroize();
    Kek::from_bytes(*okm)
}

/// K3: payload key.
///
/// `header_salt` is random for each packing operation, so repacking
/// the same content with the same CEK yields a different stream key and does not
/// produce matching ciphertexts.
pub fn derive_payload_key(
    cek: &Cek,
    header_salt: &[u8; 32],
    file_id: &[u8; 16],
    chunk_size: u32,
    aead: AeadAlg,
) -> PayloadKey {
    // `chunk_size` и `aead_id` входят в `info` потому, что оба задают способ
    // кадрирования потока. Тот же ключ при другом размере чанка означал бы, что
    // один и тот же поток ключей применён к другой разбивке открытого текста, а
    // при другом AEAD — к другой схеме nonce; и то, и другое ведёт к повторному
    // использованию ключевого потока на разных данных.
    PayloadKey::from_bytes(*hkdf_sha256::<SECRET_LEN>(
        header_salt,
        cek.expose(),
        &[
            label::PAYLOAD.as_bytes(),
            file_id.as_slice(),
            &chunk_size.to_be_bytes(),
            &[aead as u8],
        ],
    ))
}

/// K5: private-metadata key (the real filename and informational size).
///
/// A separate key lets metadata grow without affecting the payload.
pub fn derive_private_meta_key(cek: &Cek, header_salt: &[u8; 32], file_id: &[u8; 16]) -> MetaKey {
    MetaKey::from_bytes(*hkdf_sha256::<SECRET_LEN>(
        header_salt,
        cek.expose(),
        &[label::PRIVATE_META.as_bytes(), file_id.as_slice()],
    ))
}

/// K6: mutable-region MAC key.
pub fn derive_content_mac_key(cek: &Cek, header_salt: &[u8; 32], file_id: &[u8; 16]) -> MacKey {
    // Изменяемая область заверяется MAC на ключе от CEK, а не подписью автора:
    // правка происходит без автора, подписать он может только то, что видел.
    MacKey::from_bytes(*hkdf_sha256::<SECRET_LEN>(
        header_salt,
        cek.expose(),
        &[label::CONTENT_MAC.as_bytes(), file_id.as_slice()],
    ))
}

/// K12: access-state witness key.
///
/// Authenticates the lease-cache head stored in two places: inside and outside the profile. The label
/// `"CC/v1/cached-lease"` was reserved in the §3.6 registry in advance and until now
/// existed only as a constant; here it gains a consumer.
///
/// Derived from the DEVICE secret rather than a file key: there is one witness per
/// machine, unrelated to any container. Otherwise a head would be needed
/// for every file, defeating the meaning of "one number outside the profile".
///
/// The salt is deliberately empty. HKDF salt is optional, and none is available here:
/// there is no file identifier or header salt, only a device. The label
/// in `info` sets the domain, which suffices: separation comes from it, not
/// from salt.
///
/// What this key does NOT provide: protection against the machine's owner. The device secret is in
/// their profile, so they can derive the key too. Authentication here addresses a fellow machine user
/// with write access to a shared directory, and accidental corruption, not
/// whoever owns the profile.
pub fn derive_witness_key(device: &crate::secret::X25519Secret) -> MacKey {
    MacKey::from_bytes(*hkdf_sha256::<SECRET_LEN>(
        &[],
        device.expose(),
        &[label::CACHED_LEASE.as_bytes()],
    ))
}

/// Semantic-mark variant selection (D5): `HMAC(organization key,
/// "CC/v1/mark-choice" ‖ layout ‖ u64be(copy mark) ‖ u32be(point))`,
/// the first eight bytes interpreted as `u64be`, modulo the variant count.
///
/// The key is a SEPARATE organization marking key, not a device or
/// author key: selection must be unpredictable for the recipient and reproducible for
/// whoever investigates a leak; this key serves no other purpose. The layout is
/// MAC-covered: one copy mark in two documents yields independent choices.
/// For up to sixteen variants, modulo bias is on the order of 2^-60 and
/// requires no correction.
///
/// # Errors
/// [`CryptoError::BadLength`]: zero variants.
pub fn mark_choice(key: &MacKey, layout: &[u8; 32], token: u64, point: u32, variants: u32) -> Result<u32, CryptoError> {
    if variants == 0 {
        return Err(CryptoError::BadLength);
    }
    let mut t = crate::Transcript::new(label::MARK_CHOICE);
    t.fixed(layout);
    t.u64be(token);
    t.u32be(point);
    let tag = crate::mac::compute(key, &t)?;
    let head: [u8; 8] = tag.get(..8).and_then(|h| h.try_into().ok()).ok_or(CryptoError::BadLength)?;
    let value = u64::from_be_bytes(head).checked_rem(u64::from(variants)).ok_or(CryptoError::BadLength)?;
    u32::try_from(value).map_err(|_| CryptoError::BadLength)
}

/// K14: claim-code secret derived from its canonical text.
///
/// Input is the code's **canonical characters**: no separators, uppercase
/// (§3.4). Canonicalization belongs to the interface rather than the key schedule:
/// alphabet, grouping, and whitespace tolerance determine how easily a code can
/// be dictated, without affecting any key byte. Transforming text into a
/// secret, however, affects everything and therefore lives here with the rest of the schedule and its
/// domain label.
///
/// Hashes the text rather than bits assembled from the characters. The distinction matters:
/// assembling bits is a second encoding of the same thing, and even a bit-order discrepancy
/// would make the code printed by the author differ from the code
/// entered by the recipient. Text is unambiguous by construction.
///
/// BLAKE3 rather than HKDF: there is neither salt nor a division into extract and
/// expand; there is exactly one compression of variable-length input into 32 bytes. The separator
/// `0x00` follows the label because text length is not predetermined;
/// without it, `label‖code` would parse ambiguously.
///
/// Input entropy is **not checked here and cannot be**: the code is already
/// text by this point, and its original randomness is not visible. The
/// [`crate::MIN_CLAIM_BITS`] boundary is checked where the code is generated.
pub fn claim_secret_from_code(canonical: &[u8]) -> ClaimSecret {
    let mut hasher = blake3::Hasher::new();
    hasher.update(label::CLAIM_CODE.as_bytes());
    hasher.update(&[0x00]);
    hasher.update(canonical);
    ClaimSecret::from_bytes(*hasher.finalize().as_bytes())
}

/// K7 and K8: recipient share derived from the claim code, and the code's commitment.
///
/// Returns `(secret_B, commitment)`. Only the commitment enters the
/// container; the code itself is delivered through a second channel.
/// Heir-device X25519 private key derived from the code.
///
/// # Why a keypair rather than a share
///
/// The heir's share is FIXED: this file's share B, which cannot be derived from
/// an arbitrary code. The code therefore derives a pair, and the bequest
/// is sealed to its public key with ordinary `seal`: to the server and wire,
/// such an heir is indistinguishable from a device, and neither side
/// knows anything about the code.
///
/// `salt = file_id`, just as for the code-derived share, for the same reason: the same
/// code issued twice produces different pairs for different files; shared tables cannot
/// be constructed.
///
/// X25519 scalar multiplication "accepts" any 32 bytes: `from_bytes` performs
/// clamping itself, so no special validation of KDF output is required.
#[must_use]
pub fn device_secret_from_claim(file_id: &[u8; 16], claim: &ClaimSecret) -> [u8; 32] {
    *hkdf_sha256::<SECRET_LEN>(file_id, claim.expose(), &[label::CLAIM_DEVICE.as_bytes()])
}

pub fn secret_b_from_claim(file_id: &[u8; 16], claim: &ClaimSecret) -> (SecretB, [u8; 32]) {
    // Две разные метки над одним ikm дают независимые выходы, поэтому
    // обязательство не выдаёт ничего о доле. Обязательство вида `H(secret_B)`
    // связало бы их: кто угадал одно, получил бы проверку и для другого.
    let share = hkdf_sha256::<SECRET_LEN>(file_id, claim.expose(), &[label::SLOT_B_CLAIM.as_bytes()]);
    // `salt = file_id` не даёт строить общие таблицы: один и тот же код,
    // выданный дважды, в разных файлах превращается в разные доли.
    let commitment = hkdf_sha256::<SECRET_LEN>(file_id, claim.expose(), &[label::SLOT_B_COMMIT.as_bytes()]);
    // Обязательство секретом не является — оно и так уходит в контейнер, — а
    // доля является, и её транзитная копия исчезает вместе с обёрткой.
    (SecretB::from_bytes(*share), *commitment)
}

/// K9: slot commitment, `HMAC-SHA256(KEK, "CC/v1/slot-commit"‖core_hash)`.
///
/// Checked in constant time **before** opening AEAD. Without it, the claim code
/// becomes a partitioning oracle: XChaCha20-Poly1305 is not
/// key-committing, and an attacker constructs a wrapper that opens under many
/// candidate KEKs.
///
/// Bound to `core_hash`, not `file_id`, for two reasons. First:
/// the binding is strictly stronger: the header-core hash already includes `file_id` and changes
/// when any other author-signed field is substituted. Second: `core_hash`
/// is available where the CEK wrapper is computed, whereas `file_id` is not
/// passed in its signature.
///
/// No circular dependency: `core_hash` covers the header **without** the key-slot
/// record, precisely why that record is excluded.
///
/// There is exactly one function. Previously there were two, bound to `file_id` and
/// `core_hash`, violating "no domain label is used
/// twice": one label served two distinct bindings, meaning a tag from one
/// context could be presented in the other.
pub fn slot_commitment(kek: &Kek, core_hash: &[u8; 32]) -> [u8; 32] {
    hmac_sha256(kek.expose(), &[label::SLOT_COMMIT.as_bytes(), core_hash.as_slice()])
}

/// Constant-time commitment comparison.
pub fn verify_commitment(expected: &[u8; 32], actual: &[u8; 32]) -> Result<(), CryptoError> {
    // Только `ct_eq`. Сравнение `==` выходит на первом различающемся байте, и по
    // времени ответа обязательство подбирается побайтово — за 32×256 попыток
    // вместо 2¹²⁸.
    if bool::from(expected.ct_eq(actual)) {
        Ok(())
    } else {
        // Тот же вариант ошибки, что и у неудачного тега AEAD: различить, что
        // именно не сошлось, вызывающий не должен.
        Err(CryptoError::Authentication)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    const FILE_ONE: [u8; 16] = [0x11; 16];
    const FILE_TWO: [u8; 16] = [0x12; 16];
    const SALT_ONE: [u8; 32] = [0x21; 32];
    const SALT_TWO: [u8; 32] = [0x22; 32];
    const ORG_ONE: &[u8] = b"acme";
    const ORG_TWO: &[u8] = b"acme-eu";

    fn shares() -> (SecretA, SecretB) {
        (SecretA::from_bytes([0xa1; 32]), SecretB::from_bytes([0xb2; 32]))
    }

    fn cek() -> Cek {
        Cek::from_bytes([0xc3; 32])
    }

    #[test]
    fn the_kek_follows_rfc5869_with_the_file_id_as_salt_and_the_shares_as_ikm() {
        // Перепутать местами `salt` и `ikm` — классическая ошибка применения
        // HKDF: она ничем не проявляется, кроме несовместимости с чужой
        // реализацией того же формата, а обнаружится уже после выпуска файлов.
        // Поэтому K1 пересчитывается вручную по RFC 5869: Extract с солью в роли
        // ключа HMAC, затем один блок Expand с суффиксом 0x01.
        let (a, b) = shares();
        let mut ikm = [0u8; KEK_IKM_LEN];
        let (first, second) = ikm.split_at_mut(SECRET_LEN);
        first.copy_from_slice(a.expose());
        second.copy_from_slice(b.expose());

        let prk = hmac_sha256(&FILE_ONE, &[&ikm]);
        let expected = hmac_sha256(&prk, &[label::KEK.as_bytes(), ORG_ONE, &FILE_ONE, &[0x01]]);

        assert_eq!(derive_kek(&FILE_ONE, ORG_ONE, &a, &b).expose(), &expected);
    }


    #[test]
    fn the_same_shares_in_two_files_never_yield_the_same_kek() {
        // Иначе одна вскрытая пара долей открывала бы все файлы арендатора, а не
        // один: `file_id` — единственное, что делает ключи файла его личными.
        let (a, b) = shares();
        let one = derive_kek(&FILE_ONE, ORG_ONE, &a, &b);
        let two = derive_kek(&FILE_TWO, ORG_ONE, &a, &b);
        assert_ne!(one.expose(), two.expose());
    }

    #[test]
    fn two_tenants_never_share_a_kek() {
        // Разделение арендаторов обязано держаться на криптографии: проверка
        // поля `org_id` при чтении — это решение, принимаемое клиентом, которого
        // противник контролирует.
        let (a, b) = shares();
        let one = derive_kek(&FILE_ONE, ORG_ONE, &a, &b);
        let two = derive_kek(&FILE_ONE, ORG_TWO, &a, &b);
        assert_ne!(one.expose(), two.expose());
    }

    #[test]
    fn swapping_the_two_shares_yields_a_different_kek() {
        // Проверяет порядок конкатенации: A‖B и B‖A — разные ikm. Если бы
        // порядок «поплыл» при рефакторинге, все ранее выпущенные файлы
        // перестали бы открываться, и заметить это надо на сборке, а не в поле.
        let straight = derive_kek(
            &FILE_ONE,
            ORG_ONE,
            &SecretA::from_bytes([0xa1; 32]),
            &SecretB::from_bytes([0xb2; 32]),
        );
        let swapped = derive_kek(
            &FILE_ONE,
            ORG_ONE,
            &SecretA::from_bytes([0xb2; 32]),
            &SecretB::from_bytes([0xa1; 32]),
        );
        assert_ne!(straight.expose(), swapped.expose());
    }

    #[test]
    fn an_org_id_boundary_cannot_be_shifted_into_the_file_id() {
        // `info` — конкатенация без разделителей, поэтому пара (org_id, file_id)
        // обязана оставаться однозначной. `file_id` фиксирован типом в 16 байт,
        // и сдвинуть границу можно только вместе с изменением `org_id`, что и
        // проверяется: два разных арендатора не сходятся к одному ключу.
        let (a, b) = shares();
        let long = derive_kek(&FILE_ONE, b"acme\x11\x11", &a, &b);
        let short = derive_kek(&FILE_ONE, b"acme", &a, &b);
        assert_ne!(long.expose(), short.expose());
    }

    #[test]
    fn a_repack_with_a_new_header_salt_changes_the_payload_key() {
        // Повторная упаковка того же содержимого тем же CEK не должна давать
        // совпадающих шифротекстов: иначе видно, что два контейнера содержат
        // одно и то же, без единого ключа.
        let key_one =
            derive_payload_key(&cek(), &SALT_ONE, &FILE_ONE, 65536, AeadAlg::XChaCha20Poly1305);
        let key_two =
            derive_payload_key(&cek(), &SALT_TWO, &FILE_ONE, 65536, AeadAlg::XChaCha20Poly1305);
        assert_ne!(key_one.expose(), key_two.expose());
    }

    #[test]
    fn the_payload_key_changes_with_the_chunk_size() {
        // Размер чанка задаёт разбивку открытого текста. Тот же ключ при другой
        // разбивке — это тот же ключевой поток на других данных.
        let small =
            derive_payload_key(&cek(), &SALT_ONE, &FILE_ONE, 16384, AeadAlg::XChaCha20Poly1305);
        let large =
            derive_payload_key(&cek(), &SALT_ONE, &FILE_ONE, 65536, AeadAlg::XChaCha20Poly1305);
        assert_ne!(small.expose(), large.expose());
    }

    #[test]
    fn the_payload_key_changes_with_the_aead_id() {
        // Смена профиля меняет схему nonce: у XChaCha он случайный и хранится, у
        // AES-GCM — счётчиковый. Общий ключ между профилями означал бы
        // повторное использование пары (ключ, nonce) в двух разных схемах.
        let xchacha =
            derive_payload_key(&cek(), &SALT_ONE, &FILE_ONE, 65536, AeadAlg::XChaCha20Poly1305);
        let gcm = derive_payload_key(&cek(), &SALT_ONE, &FILE_ONE, 65536, AeadAlg::Aes256Gcm);
        let siv = derive_payload_key(&cek(), &SALT_ONE, &FILE_ONE, 65536, AeadAlg::Aes256GcmSiv);
        assert_ne!(xchacha.expose(), gcm.expose());
        assert_ne!(gcm.expose(), siv.expose());
        assert_ne!(xchacha.expose(), siv.expose());
    }

    #[test]
    fn the_same_cek_in_two_files_never_yields_the_same_payload_key() {
        let one =
            derive_payload_key(&cek(), &SALT_ONE, &FILE_ONE, 65536, AeadAlg::XChaCha20Poly1305);
        let two =
            derive_payload_key(&cek(), &SALT_ONE, &FILE_TWO, 65536, AeadAlg::XChaCha20Poly1305);
        assert_ne!(one.expose(), two.expose());
    }

    #[test]
    fn private_metadata_and_content_mac_never_share_a_key_with_the_payload() {
        // Три ключа от одного CEK и одной соли. Совпадение любых двух означало
        // бы, что тег изменяемой области можно подделать ключом полезной
        // нагрузки или наоборот.
        let payload =
            derive_payload_key(&cek(), &SALT_ONE, &FILE_ONE, 65536, AeadAlg::XChaCha20Poly1305);
        let meta = derive_private_meta_key(&cek(), &SALT_ONE, &FILE_ONE);
        let mac = derive_content_mac_key(&cek(), &SALT_ONE, &FILE_ONE);
        assert_ne!(payload.expose(), meta.expose());
        assert_ne!(meta.expose(), mac.expose());
        assert_ne!(payload.expose(), mac.expose());
    }

    #[test]
    fn the_same_claim_code_in_two_files_yields_two_different_shares() {
        // Код-претензия может быть выдан повторно (тот же генератор, та же
        // длина). Соль `file_id` не даёт одному коду открыть два файла.
        let claim = ClaimSecret::from_bytes([0x7c; 32]);
        let (share_one, commit_one) = secret_b_from_claim(&FILE_ONE, &claim);
        let (share_two, commit_two) = secret_b_from_claim(&FILE_TWO, &claim);
        assert_ne!(share_one.expose(), share_two.expose());
        assert_ne!(commit_one, commit_two);
    }

    #[test]
    fn a_claim_commitment_never_equals_the_share_it_commits_to() {
        // Обязательство лежит в контейнере открытым текстом. Совпади оно с
        // долей — контейнер раздавал бы secret_B каждому, кто его прочитал.
        let claim = ClaimSecret::from_bytes([0x7c; 32]);
        let (share, commitment) = secret_b_from_claim(&FILE_ONE, &claim);
        assert_ne!(share.expose(), &commitment);
    }


    #[test]
    fn a_single_flipped_bit_in_a_commitment_is_refused() {
        let expected = [0x9a; 32];
        let mut actual = expected;
        if let Some(byte) = actual.get_mut(31) {
            *byte ^= 0x01;
        }
        assert_eq!(verify_commitment(&expected, &expected), Ok(()));
        assert_eq!(
            verify_commitment(&expected, &actual),
            Err(CryptoError::Authentication)
        );
    }

    #[test]
    fn every_derivation_of_the_schedule_is_domain_separated() {
        // Все производные получают максимально одинаковый вход: одни и те же 32
        // байта в роли долей, CEK, кода-претензии, KEK и соли. При таком входе
        // единственное, что разводит выходы, — метки домена. Совпадение любых
        // двух означало бы, что ключ одного назначения принимается вместо
        // другого: тег изменяемой области подделывается ключом метаданных,
        // обязательство слота подставляется как обязательство кода.
        let material = [0x55u8; 32];
        let file_id = [0x55u8; 16];
        let salt = material;

        let a = SecretA::from_bytes(material);
        let b = SecretB::from_bytes(material);
        let cek = Cek::from_bytes(material);
        let claim = ClaimSecret::from_bytes(material);
        let kek = Kek::from_bytes(material);

        let (share, claim_commitment) = secret_b_from_claim(&file_id, &claim);
        let derived: Vec<(&str, Vec<u8>)> = vec![
            ("K1 kek", derive_kek(&file_id, &material, &a, &b).expose().to_vec()),
            (
                "K3 payload",
                derive_payload_key(&cek, &salt, &file_id, 65536, AeadAlg::XChaCha20Poly1305)
                    .expose()
                    .to_vec(),
            ),
            (
                "K5 private-meta",
                derive_private_meta_key(&cek, &salt, &file_id).expose().to_vec(),
            ),
            (
                "K6 content-mac",
                derive_content_mac_key(&cek, &salt, &file_id).expose().to_vec(),
            ),
            ("K7 slot-b-claim", share.expose().to_vec()),
            ("K8 slot-b-commit", claim_commitment.to_vec()),
            ("K9 slot-commit", slot_commitment(&kek, &salt).to_vec()),
        ];

        for (index, (left_name, left)) in derived.iter().enumerate() {
            for (right_name, right) in derived.iter().skip(index.saturating_add(1)) {
                // Сравниваются общие префиксы, иначе K2 длиной 24 байта прошёл бы
                // тест «бесплатно», просто из-за другой длины.
                let common = left.len().min(right.len());
                let left_prefix: Vec<u8> = left.iter().copied().take(common).collect();
                let right_prefix: Vec<u8> = right.iter().copied().take(common).collect();
                assert_ne!(
                    left_prefix, right_prefix,
                    "{left_name} и {right_name} совпали: разделение доменов не работает"
                );
            }
        }

        // Заодно ловит вырождение буфера в нули: ни одна производная не должна
        // быть пустым ключом, даже если бы `expand` когда-нибудь отказал.
        for (name, value) in &derived {
            assert!(value.iter().any(|byte| *byte != 0), "{name} выродился в нули");
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod device_fpr_tests {
    use super::*;
    use crate::KemAlg;

    /// For X25519, the fingerprint IS the key: frozen by wire vectors.
    #[test]
    fn x25519_fingerprint_is_the_key_itself() {
        let key = [0x5a; 32];
        assert_eq!(device_fpr(KemAlg::X25519HkdfSha256, &key).unwrap(), key);
    }

    /// The mechanism number enters the preimage: identical bytes under another number mean
    /// a different device name. Otherwise relabeling the mechanism would preserve the name.
    #[test]
    fn the_mechanism_number_is_part_of_the_name() {
        let xw = crate::xwing::public_key(&[0x4d; 32]).unwrap();
        let a = device_fpr(KemAlg::XWing, &xw).unwrap();
        // Тот же префикс байтов, но заявленный как P-256 — длина не сходится.
        assert!(device_fpr(KemAlg::P256HkdfSha256, &xw[..65]).is_ok());
        assert_ne!(a, device_fpr(KemAlg::P256HkdfSha256, &xw[..65]).unwrap());
        assert_ne!(&a[..], &xw[..32], "хеш не должен совпадать с началом ключа");
    }

    /// Length is checked against the mechanism (I-8), not taken "as received".
    #[test]
    fn a_key_of_the_wrong_length_is_refused_not_hashed() {
        assert_eq!(device_fpr(KemAlg::X25519HkdfSha256, &[0; 31]), Err(CryptoError::BadLength));
        assert_eq!(device_fpr(KemAlg::P256HkdfSha256, &[4; 64]), Err(CryptoError::BadLength));
        assert_eq!(device_fpr(KemAlg::XWing, &[0; 1215]), Err(CryptoError::BadLength));
        assert_eq!(device_fpr(KemAlg::MlKem768P256, &[0; 1250]), Err(CryptoError::BadLength));
        assert_eq!(device_fpr(KemAlg::RsaOaepSha256, &[0; 256]), Err(CryptoError::UnsupportedAlgorithm));
    }

    /// The length table has a gap exactly where the build cannot execute a mechanism.
    ///
    /// The two tables answer DIFFERENT questions, "what shape is the key" and "can
    /// we execute this mechanism"; nothing guarantees their agreement except
    /// today's coincidence. Since `device_fpr` needs that agreement (otherwise the
    /// "no length" branch would have reachable meaning), it must be tested rather than
    /// assumed. Enumerate ALL members, not a list recalled from memory: a new
    /// mechanism will be included automatically.
    #[test]
    fn the_length_table_has_a_hole_exactly_where_the_build_has_no_mechanism() {
        // Члены берутся ИЗ РАЗБОРА, а не списком: список по памяти устареет в
        // день, когда реестр пополнят, и проба промолчит именно о новом номере.
        let all: Vec<KemAlg> = (0u8..=255).filter_map(|v| KemAlg::from_u8(v).ok()).collect();
        assert_eq!(all.len(), 5, "реестр механизмов изменился — проверьте таблицы");
        for kem in all {
            assert_eq!(
                public_key_len(kem).is_some(),
                kem.ensure_supported().is_ok(),
                "таблица длин разошлась с исполнимостью на {kem:?}"
            );
        }
    }

    /// A hashed fingerprint does not start with the label: the label is in the preimage, not the
    /// output. This guards against "fingerprint = label ‖ key" during refactoring.
    #[test]
    fn the_label_is_in_the_preimage_not_in_the_output() {
        let p = [0x04; 65];
        let f = device_fpr(KemAlg::P256HkdfSha256, &p).unwrap();
        assert!(!f.starts_with(b"CC/v1"));
    }
}
