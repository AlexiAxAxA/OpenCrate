// SPDX-License-Identifier: MPL-2.0
// Key-schedule regression and misuse probes.
// Test-local lint allowances permit adversarial inputs. Checks cover stored
// wrapper nonces, slot commitments and distinct key types. The low-entropy
// claim-code probe records a caller-side requirement the primitive cannot enforce.
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use oc_crypto::kdf::{
    derive_content_mac_key, derive_kek, derive_payload_key, derive_private_meta_key,
    secret_b_from_claim, slot_commitment,
};
use oc_crypto::secret::{Cek, ClaimSecret, Kek, SecretA};
use oc_crypto::wrap::wrap_cek;
use oc_crypto::{label, AeadAlg, MIN_CLAIM_BITS};

const FILE_ID: [u8; 16] = [0x11; 16];
const CORE_HASH: [u8; 32] = [0x0c; 32];
const SALT: [u8; 32] = [0x21; 32];
const ORG: &[u8] = b"acme";

/// Deterministic RNG. Reproducibility matters more than strength: the probe
/// must fail identically on every machine.
struct SeedRng([u8; 32]);

impl SeedRng {
    fn seeded(seed: u8) -> Self {
        Self([seed; 32])
    }
}

impl rand_core::TryRng for SeedRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for out in dst.chunks_mut(32) {
            self.0 = blake3::hash(&self.0).into();
            for (o, s) in out.iter_mut().zip(self.0.iter()) {
                *o = *s;
            }
        }
        Ok(())
    }
}

impl rand_core::TryCryptoRng for SeedRng {}

fn hmac256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key).unwrap();
    for p in parts {
        mac.update(p);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(mac.finalize().into_bytes().as_slice());
    out
}

// ---------------------------------------------------------------------------
// 1. Два CEK под одним KEK не делят поток ключей (регрессия)
// ---------------------------------------------------------------------------

/// BUG (fixed): the wrapping nonce derived from KEK, so two different CEKs
/// wrapped under one KEK received one keystream. Then
/// `wrapped₁ ⊕ wrapped₂ = CEK₁ ⊕ CEK₂`: a legitimate recipient of the first file
/// could recover the second content key without knowing any private key.
/// Repacking and content-key rotation are normal operations; nothing in the API
/// prevented calling `wrap_cek` twice with one KEK.
///
/// Fixed by a stored random nonce (§3.1); number K2, formerly assigned to the
/// derived nonce, is burned and never reused. Retained as a regression test:
/// it checks the XOR relation itself, not "nonces differ", because
/// that property can break without restoring nonce derivation.
#[test]
fn two_different_ceks_wrapped_under_one_kek_do_not_share_a_keystream() {
    let kek = Kek::from_bytes([0x5e; 32]);
    let cek_one = Cek::from_bytes([0x01; 32]);
    let cek_two = Cek::from_bytes([0xfe; 32]);

    // Генератор ОДИН И ТОТ ЖЕ намеренно: после С-13 разные CEK обязаны получать
    // разные nonce даже при полностью повторившемся состоянии генератора —
    // именно этот случай (переупаковка того же файла с новым ключом содержимого
    // после отката снапшота) и был опасен.
    let (wrapped_one, _) =
        wrap_cek(&kek, &cek_one, &CORE_HASH, &mut SeedRng::seeded(3)).unwrap();
    let (wrapped_two, _) =
        wrap_cek(&kek, &cek_two, &CORE_HASH, &mut SeedRng::seeded(3)).unwrap();

    // Первые 24 байта обёртки — хранимый nonce, дальше шифротекст с тегом.
    assert_ne!(wrapped_one[..24], wrapped_two[..24], "nonce обёрток совпал");

    // Ключевое соотношение: XOR шифротекстов не равен XOR открытых текстов.
    let ct_xor: Vec<u8> = wrapped_one[24..56]
        .iter()
        .zip(wrapped_two[24..56].iter())
        .map(|(a, b)| a ^ b)
        .collect();
    let pt_xor: Vec<u8> = cek_one
        .expose()
        .iter()
        .zip(cek_two.expose().iter())
        .map(|(a, b)| a ^ b)
        .collect();

    assert_ne!(
        ct_xor, pt_xor,
        "повтор потока ключей: зная один CEK, противник восстанавливает второй"
    );
}

// ---------------------------------------------------------------------------
// 2. Обязательство слота: одна формула, а не две
// ---------------------------------------------------------------------------

/// BUG (fixed): §3.1 and §3.5 specified DIFFERENT HMAC messages for the
/// slot commitment, `‖ file_id` and `‖ core_hash`. Both formulas appeared in one
/// contract document, and a second implementation could legitimately read either;
/// the parties would silently diverge, the wrapper simply failing to open,
/// appearing as file corruption.
///
/// Both sections now specify `‖ core_hash`, a strictly stronger binding: the core hash
/// already includes `file_id` and changes if any other signed
/// field is substituted.
#[test]
fn the_slot_commitment_follows_one_formula_and_not_the_abandoned_one() {
    let kek = Kek::from_bytes([0x5e; 32]);

    let by_spec = hmac256(kek.expose(), &[label::SLOT_COMMIT.as_bytes(), &CORE_HASH]);
    assert_eq!(
        slot_commitment(&kek, &CORE_HASH),
        by_spec,
        "обязательство слота разошлось с формулой §3.1/§3.5"
    );

    // И прежняя формула не должна совпадать: иначе тест выше проходил бы при
    // любой из двух реализаций и не отличал бы их.
    let abandoned = hmac256(kek.expose(), &[label::SLOT_COMMIT.as_bytes(), &FILE_ID]);
    assert_ne!(
        slot_commitment(&kek, &CORE_HASH),
        abandoned,
        "обязательство считается по заброшенной формуле с file_id"
    );
}

// ---------------------------------------------------------------------------
// 3. MIN_CLAIM_BITS: граница держится сборкой `cc-cli`, а не типом `ClaimSecret`
// ---------------------------------------------------------------------------

/// PIN encoding in 32 bytes: ASCII, zero-padded.
fn claim_from_pin(pin: u32) -> ClaimSecret {
    let text = format!("{pin:04}");
    let mut bytes = [0u8; 32];
    bytes[..text.len()].copy_from_slice(text.as_bytes());
    ClaimSecret::from_bytes(bytes)
}

/// Demonstrate offline guessing of a low-entropy claim code.
///
/// A known server share plus the public slot commitment lets a caller test guesses
/// without networking. `ClaimSecret::from_bytes` cannot infer the original code's
/// entropy after hashing; generators must enforce at least `MIN_CLAIM_BITS`.
/// The product generator supplies 150 random bits; this probe deliberately uses a PIN.
#[test]
fn a_low_entropy_claim_code_is_still_brute_forcible_known_limitation() {
    assert_eq!(MIN_CLAIM_BITS, 128);

    // Автор выпускает четырёхзначный код — около 13 бит вместо 128.
    let true_pin = 9137u32;
    let (secret_b, _commitment) = secret_b_from_claim(&FILE_ID, &claim_from_pin(true_pin));

    let secret_a = SecretA::from_bytes([0xa1; 32]);
    let kek = derive_kek(&FILE_ID, ORG, &secret_a, &secret_b);
    let (_wrapped, commitment) = wrap_cek(
        &kek,
        &Cek::from_bytes([0xc3; 32]),
        &CORE_HASH,
        &mut SeedRng::seeded(11),
    )
    .unwrap();

    let mut found = None;
    for candidate in 0..10_000u32 {
        let (guess_b, _) = secret_b_from_claim(&FILE_ID, &claim_from_pin(candidate));
        let guess_kek = derive_kek(&FILE_ID, ORG, &secret_a, &guess_b);
        if slot_commitment(&guess_kek, &CORE_HASH) == commitment {
            found = Some(candidate);
            break;
        }
    }

    assert_eq!(
        found,
        Some(true_pin),
        "перебор не сошёлся — похоже, нижняя граница энтропии стала проверяться \
         на пути от текста кода к `ClaimSecret`. Если так, удали этот тест и \
         обнови docs/format.md §3.2"
    );
}

// ---------------------------------------------------------------------------
// 4. Разделение назначений ключей типами
// ---------------------------------------------------------------------------

/// K3 and K5 derive different values and return different key types.
/// `MetaKey` cannot be passed where a payload key is required:
///
/// ```compile_fail
/// let meta = derive_private_meta_key(&cek, &SALT, &FILE_ID);
/// seal_chunk(&meta, AeadAlg::XChaCha20Poly1305, &FILE_ID, 0, &nonce, b"x", &mut out);
/// ```
#[test]
fn every_purpose_in_the_schedule_gets_its_own_value() {
    let cek = Cek::from_bytes([0xc3; 32]);

    let payload = derive_payload_key(&cek, &SALT, &FILE_ID, 65536, AeadAlg::XChaCha20Poly1305);
    let meta = derive_private_meta_key(&cek, &SALT, &FILE_ID);
    let mac = derive_content_mac_key(&cek, &SALT, &FILE_ID);

    // Один и тот же CEK, одна и та же соль, один и тот же файл — и три разных
    // ключа. Совпадение любых двух означало бы, что метка домена не разделяет.
    assert_ne!(payload.expose(), meta.expose());
    assert_ne!(payload.expose(), mac.expose());
    assert_ne!(meta.expose(), mac.expose());
}
