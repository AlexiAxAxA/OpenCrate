// SPDX-License-Identifier: MPL-2.0
//! Lease signature: round trip from issuance to verification, and every way to reject it.
//!
//! A separate file rather than a module: these tests need a real signing key,
//! meaning the complete `oc-crypto`, whereas format unit tests do without it.

// Индексирование и срезы разрешены ЗДЕСЬ и только здесь: тест перебирает байты
// заведомо известной длины и читает вектор, отсутствие ключа в котором обязано
// уронить прогон, а не тихо пройти. В продуктовом коде эти литы остаются в силе.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    // Чтение файла разрешено ЗДЕСЬ и только здесь, тем же порядком, что в
    // crates/oc-crypto/tests/kat.rs: вектор лежит вне кода намеренно, чтобы
    // вторая реализация могла свериться, не читая наш Rust. Запрет часов, файлов
    // и сети остаётся в силе для самого крейта — он и проверяется отдельным
    // прогоном clippy по трём крейтам.
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

use oc_crypto::sign::Signer as _;
use oc_format::FormatError;
use oc_format::tlv::TlvWriter;
use oc_protocol::lease::{self, Lease};
use oc_policy::{LeaseFacts, Timestamp, TpmClock};

fn sample() -> Lease {
    Lease {
        file_id: [0x11; 16],
        facts: LeaseFacts {
            device_fingerprint: [0x22; 32],
            policy_hash: [0x33; 32],
            seq: 7,
            epoch: 2,
            issued_at: Timestamp(1_700_000_000),
            expires_at: Timestamp(1_700_086_400),
            opens_remaining: Some(5),
            revoked: false,
            tpm_clock: Some(TpmClock { reset_count: 3, clock_ms: 123_456 }),
            server_policy: None,
            attested: None,
        },
    }
}

fn server() -> oc_crypto::sign::Ed25519Signer {
    oc_crypto::sign::Ed25519Signer::from_seed(&[0x5a; 32])
}

/// A server-signed lease verifies with that server's key.
#[test]
fn a_lease_signed_by_the_server_verifies_with_its_key() {
    let body = lease::encode(&sample()).unwrap();
    let signer = server();
    let sig = signer.sign(&lease::signing_transcript(&body)).unwrap();

    lease::verify(&body, &sig, &signer.public_key()).expect("своя подпись не принята");
    assert_eq!(lease::decode(&body).unwrap(), sample());
}

/// A DIFFERENT server's signature is rejected.
///
/// This protects against a fake server: the verification key resides in the header under
/// the author's signature and cannot be replaced without replacing the header.
#[test]
fn a_lease_signed_by_another_server_is_refused() {
    let body = lease::encode(&sample()).unwrap();
    let sig = server().sign(&lease::signing_transcript(&body)).unwrap();

    let stranger = oc_crypto::sign::Ed25519Signer::from_seed(&[0x77; 32]);
    assert!(
        lease::verify(&body, &sig, &stranger.public_key()).is_err(),
        "лизинг принят по ключу другого сервера"
    );
}

/// Changing ANY body byte breaks the signature.
///
/// Every position is tested, not a sample: the signature must cover the entire
/// body, and "covers almost everything" is a hole exactly where no check was made.
/// Missing the tail is most costly: the clock field is optional and comes last.
#[test]
fn flipping_any_byte_of_the_body_breaks_the_signature() {
    let body = lease::encode(&sample()).unwrap();
    let signer = server();
    let sig = signer.sign(&lease::signing_transcript(&body)).unwrap();

    for i in 0..body.len() {
        let mut damaged = body.clone();
        damaged[i] ^= 0x01;
        assert!(
            lease::verify(&damaged, &sig, &signer.public_key()).is_err(),
            "подпись пережила правку байта {i}: он не покрыт"
        );
    }
}

/// One lease's signature cannot be transferred to another.
///
/// The cheapest possible attack: take your own legitimate permission and substitute
/// someone else's file_id or device. Both substitutions are checked separately,
/// because the same protection applies to them, but each must be tested.
#[test]
fn a_signature_does_not_travel_to_another_file_or_device() {
    let signer = server();
    let original = sample();
    let body = lease::encode(&original).unwrap();
    let sig = signer.sign(&lease::signing_transcript(&body)).unwrap();

    let mut other_file = original.clone();
    other_file.file_id = [0x99; 16];
    let other_body = lease::encode(&other_file).unwrap();
    assert!(
        lease::verify(&other_body, &sig, &signer.public_key()).is_err(),
        "подпись перенесена на другой файл"
    );

    let mut other_device = original;
    other_device.facts.device_fingerprint = [0x99; 32];
    let other_body = lease::encode(&other_device).unwrap();
    assert!(
        lease::verify(&other_body, &sig, &signer.public_key()).is_err(),
        "подпись перенесена на другое устройство"
    );
}

/// Build the COMPLETE document: `signature(64) ‖ body`.
///
/// A separate function because this is precisely the layout accepted by
/// [`lease::verify_signed`], whereas the tests above operate on halves: body and
/// signature separately. For that very reason none of them called the combinator:
/// the mutation "remove signature verification entirely from `verify_signed`" went
/// undetected, although the product (`cc_cli::lease`) uses only that path.
fn signed(lease: &Lease, signer: &oc_crypto::sign::Ed25519Signer) -> Vec<u8> {
    let body = lease::encode(lease).unwrap();
    let sig = signer.sign(&lease::signing_transcript(&body)).unwrap();
    let mut out = sig.to_vec();
    out.extend_from_slice(&body);
    out
}

/// A legitimate document passes the combinator and parses into what was signed.
#[test]
fn the_lease_combinator_accepts_the_servers_own_document() {
    let signer = server();
    let bytes = signed(&sample(), &signer);
    assert_eq!(
        lease::verify_signed(&bytes, &signer.public_key()).unwrap(),
        sample(),
        "своя выдача не прошла комбинатор"
    );
}

/// Wrong key, corrupt signature or corrupt body: rejected specifically as a SIGNATURE failure.
///
/// Every byte of the signature and EVERY byte of the body is tested, not three
/// selected positions: "covers almost everything" is a hole exactly where no
/// check was made. The specific error code is checked, not `is_err()`: a combinator that
/// responds to forgery with a PARSING error reveals unauthenticated byte contents
/// to the adversary, precisely what I-5 forbids.
#[test]
fn the_lease_combinator_refuses_a_foreign_key_a_broken_signature_and_a_broken_body() {
    let signer = server();
    let stranger = oc_crypto::sign::Ed25519Signer::from_seed(&[0x77; 32]);
    let bytes = signed(&sample(), &signer);

    assert!(
        matches!(
            lease::verify_signed(&bytes, &stranger.public_key()),
            Err(FormatError::BadHeaderSignature)
        ),
        "лизинг принят по ключу другого сервера"
    );

    for i in 0..lease::SIGNATURE_LEN {
        let mut damaged = bytes.clone();
        damaged[i] ^= 0x01;
        assert!(
            matches!(
                lease::verify_signed(&damaged, &signer.public_key()),
                Err(FormatError::BadHeaderSignature)
            ),
            "правка байта подписи {i} не отвергнута как несошедшаяся подпись"
        );
    }

    for i in lease::SIGNATURE_LEN..bytes.len() {
        let mut damaged = bytes.clone();
        damaged[i] ^= 0x01;
        assert!(
            matches!(
                lease::verify_signed(&damaged, &signer.public_key()),
                Err(FormatError::BadHeaderSignature)
            ),
            "правка байта тела {i} не отвергнута как несошедшаяся подпись"
        );
    }
}

/// EVERY truncation is rejected as an invalid signature, not as truncation.
///
/// All lengths from zero to full are tested. Shorter than a signature means there is no
/// document at all; longer than a signature but shorter than the whole document means the signature
/// does not verify over the shortened body. Both must look identical: a distinction
/// would reveal exactly how far the adversary guessed correctly.
#[test]
fn the_lease_combinator_refuses_every_truncation_as_a_signature_failure() {
    let signer = server();
    let bytes = signed(&sample(), &signer);
    for cut in 0..bytes.len() {
        assert!(
            matches!(
                lease::verify_signed(&bytes[..cut], &signer.public_key()),
                Err(FormatError::BadHeaderSignature)
            ),
            "обрубок длины {cut} принят или отвергнут не как подпись"
        );
    }
}

/// THE SIGNATURE IS VERIFIED BEFORE BODY PARSING: a guard on the order of two lines.
///
/// The body is deliberately UNPARSEABLE and the signature deliberately WRONG. There is exactly
/// one correct answer: `BadHeaderSignature`; any parsing error means the body
/// was read before authentication, yielding distinguishable rejections
/// for bytes nobody signed (the I-5 rationale, also documented in
/// `revocation::verify_signed`).
///
/// Before this test, ordering relied on a comment: moving `decode` before
/// `verify` broke no tests. Parsing-error tests called `decode`
/// directly, signature tests supplied parseable bodies, and nobody tested the case
/// combining both conditions.
#[test]
fn the_lease_signature_is_checked_before_the_body_is_parsed() {
    let signer = server();
    let stranger = oc_crypto::sign::Ed25519Signer::from_seed(&[0x77; 32]);

    // Два разных способа быть неразбираемым, потому что ветки разбора разные:
    // нет обязательного поля и незнакомый критичный тег.
    let empty = TlvWriter::new().finish().to_vec();
    let mut w = TlvWriter::new();
    w.put(0x7FFF, &[0xab; 4]).unwrap();
    let unknown_critical = w.finish().to_vec();

    for (what, body) in [("пустое тело", empty), ("чужой критичный тег", unknown_critical)] {
        assert!(
            lease::decode(&body).is_err(),
            "{what}: предпосылка пробы неверна, тело разбирается"
        );

        // Подпись настоящая, но ЧУЖАЯ: подделать документ противник умеет, а
        // подписать ключом сервера — нет.
        let sig = stranger.sign(&lease::signing_transcript(&body)).unwrap();
        let mut bytes = sig.to_vec();
        bytes.extend_from_slice(&body);

        let outcome = lease::verify_signed(&bytes, &signer.public_key());
        assert!(
            matches!(outcome, Err(FormatError::BadHeaderSignature)),
            "{what}: разбор произошёл до проверки подписи, ответ {outcome:?} — \
             подделка сообщает о себе кодом разбора незаверенных байтов"
        );
    }
}

/// Parsing arbitrary bytes does not panic.
///
/// A lease arrives over the network, hence from an adversary; a panic here is denial
/// of service exactly where input is hostile by definition.
#[test]
fn decoding_arbitrary_bytes_never_panics() {
    let body = lease::encode(&sample()).unwrap();

    for cut in 0..body.len() {
        let _ = lease::decode(&body[..cut]);
    }
    let mut seed = 0x5eed_u64;
    for _ in 0..20_000 {
        seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        let len = (seed >> 33) as usize % 96;
        let mut junk = vec![0u8; len];
        for (i, b) in junk.iter_mut().enumerate() {
            *b = (seed >> (i % 8 * 8)) as u8;
        }
        let _ = lease::decode(&junk);
    }
}

/// The lease matches the frozen vector: body, signature and key.
///
/// The signature is frozen too, not just the body, and this matters: the body by itself
/// means nothing; a lease is a server assertion. Leaving the transcript unfrozen
/// would leave exactly WHAT is signed unfrozen; divergence there
/// is silent: the signature fails to verify, making it look as though "the server broke".
#[test]
fn the_lease_matches_its_frozen_vector() {
    let v = load_kat("lease.kat");
    let body = lease::encode(&sample()).unwrap();
    assert_eq!(hex(&body), v["lease_body"], "байты тела лизинга разошлись с вектором");

    let signer = server();
    assert_eq!(hex(&signer.public_key()), v["lease_verify_key"]);

    let sig: [u8; 64] = hex_bytes(&v["lease_signature"]).try_into().unwrap();
    lease::verify(&body, &sig, &signer.public_key())
        .expect("замороженная подпись не принята: транскрипт разошёлся");

    // И обратно: подпись, снятая сейчас, совпадает с замороженной. Ed25519
    // детерминирован, поэтому это законное требование, а не удача.
    let fresh = signer.sign(&lease::signing_transcript(&body)).unwrap();
    assert_eq!(hex(&fresh), v["lease_signature"]);
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hex_bytes(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

fn load_kat(name: &str) -> std::collections::BTreeMap<String, String> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/kat")
        .join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{name}: {e}"));
    text.lines()
        .filter_map(|l| l.split_once('='))
        .filter(|(k, _)| !k.trim_start().starts_with('#'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

/// Generate the lease vector. A tool, not a test.
#[test]
#[ignore = "инструмент перевыпуска векторов, а не проверка"]
fn print_lease_vector() {
    let body = lease::encode(&sample()).unwrap();
    let signer = server();
    let sig = signer.sign(&lease::signing_transcript(&body)).unwrap();
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    println!("lease_verify_key = {}", hex(&signer.public_key()));
    println!("lease_body = {}", hex(&body));
    println!("lease_signature = {}", hex(&sig));
}
