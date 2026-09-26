// SPDX-License-Identifier: MPL-2.0
#![allow(clippy::unwrap_used, clippy::panic)]

use oc_crypto::{seal, secret::X25519Secret};
use oc_engine::{PackRequest, PublicKeys, Recipient, SealedInfo};
use oc_policy::Policy;

struct Fixed;
impl rand_core::TryRng for Fixed {
    type Error = core::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(0x42424242)
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(0x4242424242424242)
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Self::Error> {
        bytes.fill(0x42);
        Ok(())
    }
}
impl rand_core::TryCryptoRng for Fixed {}

fn request() -> PackRequest<'static> {
    PackRequest {
        original_name: "private.txt",
        policy: Policy::deny_all(),
        chunk_size: 4096,
        org_id: b"org".to_vec(),
        authority_urls: vec![],
        recipient: Recipient::None,
        coauthors: None,
    }
}

fn keys() -> PublicKeys<'static> {
    let public = seal::x25519_public(&X25519Secret::from_bytes([0x31; 32]));
    PublicKeys {
        author: [0x42; 32],
        authority_sealing: public,
        authority_lease_verify: [0x53; 32],
        device: public,
        device_hardware_hybrid: None,
        device_hybrid: None,
        device_tpm: None,
    }
}

#[test]
fn changed_chunk_size_cannot_assemble_a_header_with_a_different_payload_key() {
    let mut request = request();
    let (session, plan) = oc_engine::plan(&request, &mut Fixed);
    request.chunk_size = 8192;
    let result = session.assemble(
        &request,
        &keys(),
        SealedInfo { total_len: 6, chunk_count: 1, tree_root: [0x64; 32] },
        &mut Fixed,
    );
    if let Ok(assembled) = &result {
        // The recipient recovers CEK but derives a different payload key from the header.
        let parsed = oc_format::header::Header::decode(&assembled.header).unwrap();
        let header = &parsed.header;
        let core = oc_format::header::Header::core_hash(&assembled.header, &parsed.spans).unwrap();
        let policy =
            oc_format::header::Header::policy_hash(&assembled.header, &parsed.spans).unwrap();
        let slot = header
            .key_slots
            .iter()
            .find_map(|s| match s {
                oc_format::header::KeySlot::Known(s)
                    if s.kind == oc_format::header::SlotKind::AuthorDevice =>
                {
                    Some(s)
                }
                _ => None,
            })
            .unwrap();
        let secret = X25519Secret::from_bytes([0x31; 32]);
        let info = seal::slot_info(oc_crypto::label::SLOT_AUTHOR_DEVICE, slot.kem, &header.file_id);
        let opened = seal::open(
            &secret,
            &seal::SealedBlob { enc: slot.enc.clone(), nonce: slot.nonce, ct: slot.ct.clone() },
            &info,
            &policy,
        )
        .unwrap();
        let (a, b) = opened.split_at(32);
        let kek = oc_crypto::kdf::derive_kek(
            &header.file_id,
            &header.org_id,
            &oc_crypto::SecretA::from_bytes(a.try_into().unwrap()),
            &oc_crypto::SecretB::from_bytes(b.try_into().unwrap()),
        );
        let cek = oc_crypto::wrap::unwrap_cek(&kek, &header.wrapped_cek, &slot.commitment, &core)
            .unwrap();
        let reader_key = oc_crypto::kdf::derive_payload_key(
            &cek,
            &header.header_salt,
            &header.file_id,
            header.chunk_size,
            header.suite.aead,
        );
        assert!(
            reader_key.expose() != plan.payload_key.expose(),
            "probe did not reproduce key mismatch"
        );
    }
    assert!(result.is_err(), "assemble accepts metadata inconsistent with the payload KDF");
}

#[test]
fn pack_request_debug_redacts_private_filename() {
    let first = request();
    let mut other = request();
    other.original_name = "another.txt";
    assert!(format!("{first:?}") == format!("{other:?}"), "private filename affects Debug");
    assert!(
        format!("{first:#?}") == format!("{other:#?}"),
        "private filename affects pretty Debug"
    );
}

#[test]
fn editing_piece_debug_redacts_plaintext_and_nonce_seed() {
    let first = oc_engine::edit::Piece::Seal { plaintext: &[0x51; 32], seed: [0x62; 24] };
    let second = oc_engine::edit::Piece::Seal { plaintext: &[0xa7; 32], seed: [0xb8; 24] };
    assert!(format!("{first:?}") == format!("{second:?}"), "plaintext or seed affects Debug");
    assert!(
        format!("{first:#?}") == format!("{second:#?}"),
        "plaintext or seed affects pretty Debug"
    );
}

#[test]
fn wire_plan_debug_redacts_private_filename() {
    let first = oc_engine::wire::PlanArgs::from_parts(&request(), &keys());
    let mut second = first.clone();
    second.original_name = "another.txt".into();
    assert!(format!("{first:?}") == format!("{second:?}"), "filename affects wire Debug");
    assert!(format!("{first:#?}") == format!("{second:#?}"), "filename affects wire pretty Debug");
}

#[test]
fn changed_recipient_cannot_silently_seal_to_the_previous_recipient() {
    let old = X25519Secret::from_bytes([0x64; 32]);
    let intended = X25519Secret::from_bytes([0x75; 32]);
    let mut request = request();
    request.recipient = Recipient::Identity { public_key: seal::x25519_public(&old) };
    let (session, _) = oc_engine::plan(&request, &mut Fixed);
    request.recipient = Recipient::Identity { public_key: seal::x25519_public(&intended) };
    let result = session.assemble(
        &request,
        &keys(),
        SealedInfo { total_len: 6, chunk_count: 1, tree_root: [0x64; 32] },
        &mut Fixed,
    );
    if let Ok(assembled) = &result {
        let parsed = oc_format::header::Header::decode(&assembled.header).unwrap();
        let header = &parsed.header;
        let policy =
            oc_format::header::Header::policy_hash(&assembled.header, &parsed.spans).unwrap();
        let slot = header
            .key_slots
            .iter()
            .find_map(|s| match s {
                oc_format::header::KeySlot::Known(s)
                    if s.kind == oc_format::header::SlotKind::RecipientIdentity =>
                {
                    Some(s)
                }
                _ => None,
            })
            .unwrap();
        let info = seal::slot_info(oc_crypto::label::SLOT_RECIPIENT, slot.kem, &header.file_id);
        let blob =
            seal::SealedBlob { enc: slot.enc.clone(), nonce: slot.nonce, ct: slot.ct.clone() };
        assert!(
            seal::open(&old, &blob, &info, &policy).is_ok(),
            "probe did not reproduce old recipient access"
        );
        assert!(
            seal::open(&intended, &blob, &info, &policy).is_err(),
            "probe did not reproduce intended recipient failure"
        );
    }
    assert!(result.is_err(), "assemble silently uses the earlier recipient");
}

#[test]
fn claim_secret_and_recipient_kind_must_match_the_plan() {
    let mut planned = request();
    planned.recipient =
        Recipient::Claim { secret: oc_crypto::secret::ClaimSecret::from_bytes([0x86; 32]) };
    for (recipient, should_match) in [
        (planned.recipient.clone(), true),
        (
            Recipient::Claim { secret: oc_crypto::secret::ClaimSecret::from_bytes([0x97; 32]) },
            false,
        ),
        (Recipient::None, false),
        (Recipient::Identity { public_key: keys().device }, false),
    ] {
        let (session, _) = oc_engine::plan(&planned, &mut Fixed);
        let mut assembled_request = request();
        assembled_request.recipient = recipient;
        let result = session.assemble(
            &assembled_request,
            &keys(),
            SealedInfo { total_len: 6, chunk_count: 1, tree_root: [0x64; 32] },
            &mut Fixed,
        );
        if should_match {
            assert!(result.is_ok(), "unchanged claim must assemble");
        } else {
            assert!(result.is_err(), "changed claim or recipient kind must fail before sealing");
        }
    }
}
