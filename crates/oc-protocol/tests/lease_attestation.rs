// SPDX-License-Identifier: MPL-2.0
//! Lease version 3: device key attestation flag under the server signature (B6b).
//!
//! The flag raises the evaluator's binding level to `HardwareAttested`, so
//! the same properties as for the server profile are checked: version and field set agree in
//! both directions, the basis comes only from the registry, and the signature covers the flag.

#![allow(
    clippy::unwrap_used,
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use oc_crypto::sign::Signer as _;
use oc_protocol::lease::{self, Lease, LEASE_VERSION, LEASE_VERSION_WITH_ATTESTATION, LEASE_VERSION_WITH_SERVER_POLICY, tag};
use oc_format::FormatError;
use oc_policy::{Action, Attestation, LeaseFacts, Policy, Timestamp, TpmClock};

fn facts(attested: Option<Attestation>, server_policy: Option<Policy>) -> LeaseFacts {
    LeaseFacts {
        device_fingerprint: [0x22; 32],
        policy_hash: [0x33; 32],
        seq: 7,
        epoch: 2,
        issued_at: Timestamp(1_700_000_000),
        expires_at: Timestamp(1_700_086_400),
        opens_remaining: Some(5),
        revoked: false,
        tpm_clock: Some(TpmClock { reset_count: 3, clock_ms: 123_456 }),
        server_policy,
        attested,
    }
}

fn lease(attested: Option<Attestation>, server_policy: Option<Policy>) -> Lease {
    Lease { file_id: [0x11; 16], facts: facts(attested, server_policy) }
}

fn server() -> oc_crypto::sign::Ed25519Signer {
    oc_crypto::sign::Ed25519Signer::from_seed(&[0x5a; 32])
}

fn set_version(body: &mut [u8], version: u16) {
    // Первое поле — версия: тег (2) ‖ длина (4) ‖ u16le.
    assert_eq!(&body[..2], &tag::VERSION.to_le_bytes());
    body[6..8].copy_from_slice(&version.to_le_bytes());
}

#[test]
fn an_attested_lease_round_trips_with_and_without_a_profile() {
    for attested in [Attestation::VendorCertificate, Attestation::EnrolledEk] {
        for profile in [None, Some(Policy::deny_all().allow(Action::View))] {
            let original = lease(Some(attested), profile);
            let body = lease::encode(&original).unwrap();
            assert_eq!(u16::from_le_bytes([body[6], body[7]]), LEASE_VERSION_WITH_ATTESTATION);
            assert_eq!(lease::decode(&body).unwrap(), original);
        }
    }
    // Без признака байты прежние: версия 1 или 2, как было.
    let plain = lease::encode(&lease(None, None)).unwrap();
    assert_eq!(u16::from_le_bytes([plain[6], plain[7]]), LEASE_VERSION);
}

/// Version and flag agree in both directions; the basis comes only from the registry.
#[test]
fn the_version_and_the_attestation_field_must_agree() {
    let mut claimed = lease::encode(&lease(Some(Attestation::EnrolledEk), None)).unwrap();
    set_version(&mut claimed, LEASE_VERSION);
    assert_eq!(
        lease::decode(&claimed).unwrap_err(),
        FormatError::UnknownCriticalField { tag: tag::ATTESTED }
    );
    set_version(&mut claimed, LEASE_VERSION_WITH_SERVER_POLICY);
    assert!(lease::decode(&claimed).is_err(), "версия 2 с признаком разобрана");

    let mut empty = lease::encode(&lease(None, None)).unwrap();
    set_version(&mut empty, LEASE_VERSION_WITH_ATTESTATION);
    assert_eq!(lease::decode(&empty).unwrap_err(), FormatError::MissingField { tag: tag::ATTESTED });

    let mut odd = lease::encode(&lease(Some(Attestation::EnrolledEk), None)).unwrap();
    let last = odd.len() - 1;
    for basis in [0u8, 3, 0xff] {
        odd[last] = basis;
        assert!(lease::decode(&odd).is_err(), "основание {basis} принято");
    }
}

/// The flag is signed: its basis cannot be replaced, nor the flag removed.
#[test]
fn the_attestation_is_covered_by_the_signature() {
    let signer = server();
    let body = lease::encode(&lease(Some(Attestation::EnrolledEk), None)).unwrap();
    let sig = signer.sign(&lease::signing_transcript(&body)).unwrap();
    lease::verify(&body, &sig, &signer.public_key()).unwrap();

    let mut other = body.clone();
    let last = other.len() - 1;
    other[last] = 1;
    assert!(lease::verify(&other, &sig, &signer.public_key()).is_err(), "подменённое основание принято");

    // Подпись лизинга без признака к лизингу с признаком не подходит — и наоборот.
    let plain = lease::encode(&lease(None, None)).unwrap();
    let plain_sig = signer.sign(&lease::signing_transcript(&plain)).unwrap();
    assert!(lease::verify(&body, &plain_sig, &signer.public_key()).is_err());
    assert!(lease::verify(&plain, &sig, &signer.public_key()).is_err());
}

/// Lease version 3 matches its own frozen vector.
///
/// A separate file: `lease.kat` and `lease-v2.kat` are frozen with their
/// documents (I-14); a new document gets a new witness.
#[test]
fn the_version_three_lease_matches_its_frozen_vector() {
    let v = load_kat("lease-v3.kat");
    let body = lease::encode(&lease(Some(Attestation::EnrolledEk), None)).unwrap();
    assert_eq!(hex(&body), v["lease_body"], "байты тела лизинга версии 3 разошлись с вектором");
    let signer = server();
    assert_eq!(hex(&signer.public_key()), v["lease_verify_key"]);
    let sig: [u8; 64] = hex_bytes(&v["lease_signature"]).try_into().unwrap();
    lease::verify(&body, &sig, &signer.public_key()).expect("замороженная подпись версии 3 не принята");
    let fresh = signer.sign(&lease::signing_transcript(&body)).unwrap();
    assert_eq!(hex(&fresh), v["lease_signature"]);
}

/// Generate the lease version 3 vector. A tool, not a test.
#[test]
#[ignore = "инструмент выпуска вектора, а не проверка"]
fn print_version_three_lease_vector() {
    let body = lease::encode(&lease(Some(Attestation::EnrolledEk), None)).unwrap();
    let signer = server();
    let sig = signer.sign(&lease::signing_transcript(&body)).unwrap();
    println!("lease_verify_key = {}", hex(&signer.public_key()));
    println!("lease_body = {}", hex(&body));
    println!("lease_signature = {}", hex(&sig));
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hex_bytes(s: &str) -> Vec<u8> {
    s.as_bytes().chunks(2).map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap()).collect()
}

fn load_kat(name: &str) -> std::collections::BTreeMap<String, String> {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/kat").join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{name}: {e}"));
    text.lines()
        .filter_map(|l| l.split_once('='))
        .filter(|(k, _)| !k.trim_start().starts_with('#'))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}
