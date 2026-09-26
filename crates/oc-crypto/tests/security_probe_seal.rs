// SPDX-License-Identifier: MPL-2.0
// Файл-проба состязательной проверки безопасности. Линтерные запреты рабочего
// кода к пробам не применяются — проба вправе делать то, чего продукт делать не
// должен.
//
// ИСТОРИЯ. Проба была выведена из сборки переименованием в `.rs.txt` и лежала в
// docs/security-review, то есть не компилировалась и не исполнялась. При этом
// именно эту конструкцию docs/format.md §3.3 называет «первым кандидатом на
// внешнюю проверку». Тест, вынесенный из дерева сборки, — это удалённый тест с
// видом сохранённого. Возвращена пунктом Д-13.
//
// Две проверки при возврате оказались красными, и обе переписаны на то, что есть
// на самом деле, а не на то, чего хотел автор прежней редакции: расхождение с
// RFC 9180 (осознанное, см. §3.3) и повтор потока ключей при полном повторе
// состояния генератора (известное ограничение, решение — С-13 в docs/plan.md).
#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]
//! Track 1 probe: hand-written sealing construction in `oc-crypto/src/seal.rs`.
//!
//! Each test states a **required property**. A failing test is
//! evidence of a defect, not a broken build.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

use oc_crypto::seal::{open, seal, x25519_public, SealedBlob, PUBLIC_KEY_LEN};
use oc_crypto::secret::X25519Secret;
use oc_crypto::{label, CryptoError};

// ---------------------------------------------------------------------------
// Инструментарий
// ---------------------------------------------------------------------------

/// Deterministic RNG. Reproducibility matters more than strength: the test must
/// fail identically on every machine.
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

fn hex32(text: &str) -> [u8; 32] {
    let bytes = text.as_bytes();
    assert_eq!(bytes.len(), 64, "нужны ровно 32 байта в hex");
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = (bytes[i * 2] as char).to_digit(16).unwrap() as u8;
        let lo = (bytes[i * 2 + 1] as char).to_digit(16).unwrap() as u8;
        *slot = (hi << 4) | lo;
    }
    out
}

const INFO: &[u8] = b"CC/v1/slot-author-device\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11";
const AAD: &[u8] = b"policy-hash-32-bytes-placeholder";
const PT: &[u8] = b"secret_A||secret_B: 64 bytes of key material for the author device";

fn recipient(seed: u8) -> X25519Secret {
    X25519Secret::from_bytes([seed; 32])
}

// ---------------------------------------------------------------------------
// 1. Полнота отсечения точек малого порядка
// ---------------------------------------------------------------------------

/// All publicly known X25519 small-order points, including noncanonical
/// encodings (`u`, `u + p`, `u` with the high bit set). Each must
/// cause rejection rather than a predictable AEAD key.
const LOW_ORDER: &[&str] = &[
    // порядок 1 — нейтральный элемент
    "0000000000000000000000000000000000000000000000000000000000000000",
    // порядок 4
    "0100000000000000000000000000000000000000000000000000000000000000",
    // порядок 8
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
    // порядок 2 (p-1) и неканонические p, p+1
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
    // те же значения со взведённым старшим битом: RFC 7748 велит его
    // игнорировать, поэтому это вторая кодировка тех же точек.
    "0000000000000000000000000000000000000000000000000000000000000080",
    "0100000000000000000000000000000000000000000000000000000000000080",
    "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880",
    "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7",
    "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
];

#[test]
fn every_known_low_order_point_is_refused_both_on_seal_and_on_open() {
    let sk = recipient(7);
    for (index, text) in LOW_ORDER.iter().enumerate() {
        let point = hex32(text);

        let mut rng = SeedRng::seeded(index as u8);
        let sealed = seal(&point, INFO, AAD, PT, &mut rng);
        assert_eq!(
            sealed.err(),
            Some(CryptoError::BadKey),
            "точка малого порядка #{index} принята в seal: ключ AEAD стал бы общеизвестным"
        );

        let blob = SealedBlob { enc: point.to_vec(), nonce: [0x01; 24], ct: vec![0u8; 32] };
        assert_eq!(
            open(&sk, &blob, INFO, AAD).err(),
            Some(CryptoError::BadKey),
            "точка малого порядка #{index} принята в open"
        );
    }
}

// ---------------------------------------------------------------------------
// 2. Разделение доменов seal-key / seal-nonce при произвольном info
// ---------------------------------------------------------------------------

#[test]
fn no_info_can_make_two_slot_purposes_derive_the_same_key() {
    // Проверяемых пар здесь две, и обе живы.
    //
    // Первая — исходная: `"CC/v1/seal-key"‖info1 == "CC/v1/seal-nonce"‖info2`
    // означало бы равенство ключа и nonce. Метка `CC/v1/seal-nonce` НА МЕСТЕ
    // (`oc_crypto::label::SEAL_NONCE`, format.md §3.6, строка K17): nonce
    // читателем не вычисляется — он лежит в записи слота готовым, — но
    // отправитель его выводит, чтобы значение перестало быть чистой функцией
    // состояния генератора (решение С-13). Метка, которую кто-то выводит, — это
    // метка, которую надо держать беспрефиксной.
    //
    // Вторая пара — та же опасность, переехавшая на назначения слотов. `info`
    // приклеивается к метке БЕЗ разделителя (`expand_info`), а
    // сам `info` — это `метка назначения слота ‖ kem_id ‖ file_id`. Значит
    // столкнуть можно уже не ключ с nonce, а назначение слота с назначением
    // другого слота: блоб, адресованный серверу, открылся бы как блоб,
    // адресованный устройству автора. Условие ровно то же — беспрефиксность.
    assert!(
        !label::SEAL_NONCE.as_bytes().starts_with(label::SEAL_KEY.as_bytes()),
        "метка nonce — расширение метки ключа: подобрав хвост info, отправитель \
         вывел бы nonce, равный ключу AEAD"
    );
    assert!(
        !label::SEAL_KEY.as_bytes().starts_with(label::SEAL_NONCE.as_bytes()),
        "метка ключа — расширение метки nonce: то же столкновение с другой стороны"
    );

    // Сравниваются БАЙТЫ меток: беспрефиксность — свойство строк, и тип
    // `Label` его не проверяет, он лишь запрещает строку вне реестра.
    let purposes =
        [label::SLOT_SERVER, label::SLOT_RECIPIENT, label::SLOT_AUTHOR_DEVICE].map(|l| l.as_bytes());
    for left in purposes {
        for right in purposes {
            if left == right {
                continue;
            }
            assert!(
                !right.starts_with(left),
                "метка назначения {:?} — префикс {:?}: подобрав хвост info, \
                 противник получил бы тот же ключ для другого назначения слота",
                core::str::from_utf8(left).unwrap_or("<не utf8>"),
                core::str::from_utf8(right).unwrap_or("<не utf8>")
            );
        }
    }

    // И то же для самой метки ключа: её тоже склеивают с info без разделителя.
    for purpose in purposes {
        assert!(!purpose.starts_with(label::SEAL_KEY.as_bytes()));
        assert!(!label::SEAL_KEY.as_bytes().starts_with(purpose));
    }
}

// ---------------------------------------------------------------------------
// 3. Неподатливость enc
// ---------------------------------------------------------------------------

#[test]
fn a_non_canonical_enc_that_yields_the_same_dh_still_fails_to_open() {
    // Старший бит `u` игнорируется реализацией X25519, поэтому `enc` и
    // `enc | 0x80` дают один и тот же общий секрет. Блоб не должен быть
    // податлив: неканоническая форма отвергается до DH и вывода ключа.
    let mut rng = SeedRng::seeded(21);
    let sk = recipient(7);
    let mut blob = seal(&x25519_public(&sk), INFO, AAD, PT, &mut rng).unwrap();
    assert!(open(&sk, &blob, INFO, AAD).is_ok());

    blob.enc[31] |= 0x80;
    assert_eq!(
        open(&sk, &blob, INFO, AAD).err(),
        Some(CryptoError::BadKey),
        "неканоническая перекодировка enc открыла блоб: конструкция податлива"
    );
}

// ---------------------------------------------------------------------------
// 4. Соответствие RFC 9180 DHKEM(X25519, HKDF-SHA256)
// ---------------------------------------------------------------------------

/// Exact copy of key derivation from `seal.rs` (lines 133–173). First
/// prove the copy matches the original byte for byte, then
/// compare it with RFC 9180.
fn implementation_derivation(
    dh: &[u8; 32],
    enc: &[u8; PUBLIC_KEY_LEN],
    pk_r: &[u8; PUBLIC_KEY_LEN],
    info: &[u8],
) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(96);
    ikm.extend_from_slice(dh);
    ikm.extend_from_slice(enc);
    ikm.extend_from_slice(pk_r);

    let hk = Hkdf::<Sha256>::new(None, &ikm);

    let mut key_info = Vec::from(label::SEAL_KEY.as_bytes());
    key_info.extend_from_slice(info);
    let mut key = [0u8; 32];
    hk.expand(&key_info, &mut key).unwrap();

    // Nonce из этой функции не выводится: он хранится в блобе. Прежняя редакция
    // выводила его второй меткой из того же prk — конструкция, которой больше нет.
    key
}

const HPKE_VERSION: &[u8] = b"HPKE-v1";
/// `"KEM" ‖ I2OSP(0x0020, 2)`: DHKEM(X25519, HKDF-SHA256).
const KEM_SUITE_ID: &[u8] = b"KEM\x00\x20";
/// `"HPKE" ‖ kem_id ‖ kdf_id ‖ aead_id`. kdf_id = HKDF-SHA256,
/// aead_id = ChaCha20Poly1305 (the closest defined by RFC 9180; the specific
/// choice does not affect derivation, since divergence occurs at the KEM level).
const HPKE_SUITE_ID: &[u8] = b"HPKE\x00\x20\x00\x01\x00\x03";

fn labeled_extract(salt: &[u8], suite: &[u8], label_text: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut labeled = Vec::new();
    labeled.extend_from_slice(HPKE_VERSION);
    labeled.extend_from_slice(suite);
    labeled.extend_from_slice(label_text);
    labeled.extend_from_slice(ikm);
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), &labeled);
    let mut out = [0u8; 32];
    out.copy_from_slice(prk.as_slice());
    out
}

fn labeled_expand(prk: &[u8; 32], suite: &[u8], label_text: &[u8], info: &[u8], out: &mut [u8]) {
    let mut labeled = Vec::new();
    labeled.extend_from_slice(&u16::try_from(out.len()).unwrap().to_be_bytes());
    labeled.extend_from_slice(HPKE_VERSION);
    labeled.extend_from_slice(suite);
    labeled.extend_from_slice(label_text);
    labeled.extend_from_slice(info);
    Hkdf::<Sha256>::from_prk(prk).unwrap().expand(&labeled, out).unwrap();
}

/// RFC 9180 §4.1 `Encap` plus §5.1 `KeyScheduleS` in Base mode.
fn rfc9180_derivation(
    dh: &[u8; 32],
    enc: &[u8; PUBLIC_KEY_LEN],
    pk_r: &[u8; PUBLIC_KEY_LEN],
    info: &[u8],
) -> ([u8; 32], [u8; 24]) {
    // DHKEM: eae_prk = LabeledExtract("", "eae_prk", dh)
    let eae_prk = labeled_extract(b"", KEM_SUITE_ID, b"eae_prk", dh);
    // kem_context = enc ‖ pkRm; shared_secret = LabeledExpand(..., "shared_secret", ...)
    let mut kem_context = Vec::new();
    kem_context.extend_from_slice(enc);
    kem_context.extend_from_slice(pk_r);
    let mut shared_secret = [0u8; 32];
    labeled_expand(
        &eae_prk,
        KEM_SUITE_ID,
        b"shared_secret",
        &kem_context,
        &mut shared_secret,
    );

    // KeySchedule, mode_base = 0x00, psk = psk_id = ""
    let psk_id_hash = labeled_extract(b"", HPKE_SUITE_ID, b"psk_id_hash", b"");
    let info_hash = labeled_extract(b"", HPKE_SUITE_ID, b"info_hash", info);
    let mut context = Vec::new();
    context.push(0x00);
    context.extend_from_slice(&psk_id_hash);
    context.extend_from_slice(&info_hash);

    let secret = labeled_extract(&shared_secret, HPKE_SUITE_ID, b"secret", b"");
    let mut key = [0u8; 32];
    labeled_expand(&secret, HPKE_SUITE_ID, b"key", &context, &mut key);
    let mut nonce = [0u8; 24];
    labeled_expand(&secret, HPKE_SUITE_ID, b"base_nonce", &context, &mut nonce);

    (key, nonce)
}

/// The sealing construction DELIBERATELY DIFFERS from RFC 9180.
///
/// `docs/format.md` §3.3 says "a hand-written construction **following** RFC 9180,
/// not off-the-shelf HPKE", giving the reason there: NCrypt with Microsoft Platform
/// Crypto Provider lacks X25519, so TPM agreement uses P-256
/// over the raw `NCryptSecretAgreement` result, and such a key cannot be passed to an
/// existing HPKE crate.
///
/// An earlier version of this test demanded byte-for-byte RFC 9180 agreement and
/// failed. That requirement was its own invention: the specification never promised agreement.
/// The test was rewritten to do something valuable: record divergence
/// as fact and retain a reference RFC 9180 implementation showing
/// exactly where it occurs. Suddenly matching values would mean the
/// construction had silently been rewritten as HPKE, which must be noticed.
#[test]
fn the_sealing_construction_deliberately_diverges_from_rfc9180() {
    let mut rng = SeedRng::seeded(33);
    let sk = recipient(7);
    let pk_r = x25519_public(&sk);
    let blob = seal(&pk_r, INFO, AAD, PT, &mut rng).unwrap();

    // Общий секрет DH, как его считает получатель.
    let static_sk = StaticSecret::from(*sk.expose());
    // Длина проверяется здесь же: `enc` стал переменной длины вместе с
    // версией 2 формата, а этот пробник — про X25519, где она ровно 32.
    let enc: [u8; 32] = blob.enc.as_slice().try_into().expect("enc не 32 байта");
    let dh = static_sk.diffie_hellman(&PublicKey::from(enc)).to_bytes();

    // Шаг 1: копия вывода ключа действительно совпадает с реализацией —
    // расшифровываем ею настоящий блоб. Nonce берётся ИЗ БЛОБА: он хранится.
    let key = implementation_derivation(&dh, &enc, &pk_r, INFO);
    let cipher = XChaCha20Poly1305::new((&key).into());
    let recovered = cipher
        .decrypt((&blob.nonce).into(), Payload { msg: &blob.ct, aad: AAD })
        .expect("копия вывода ключа обязана совпадать с seal.rs");
    assert_eq!(recovered.as_slice(), PT);

    // Шаг 2: та же величина по RFC 9180.
    let (rfc_key, rfc_nonce) = rfc9180_derivation(&dh, &enc, &pk_r, INFO);

    assert_ne!(
        key, rfc_key,
        "ключ AEAD совпал с RFC 9180 DHKEM(X25519,HKDF-SHA256). Спека (§3.3) \
         описывает конструкцию как рукописную ПО ОБРАЗЦУ RFC 9180, а не \
         совместимую с ним; совпадение означает, что схему переписали — обнови \
         format.md §3.5 (K10) или верни прежний вывод"
    );

    // А вот `base_nonce` из RFC 9180 конструкция намеренно НЕ использует, и это
    // расхождение задокументировано (format.md §3.3): выведенный nonce целиком
    // определяется эфемерной парой и совпадает вместе с ней. Утверждение теста —
    // именно расхождение: совпади они, значит nonce стал выводиться, и правило
    // «во всём формате nonce хранятся» нарушено молча.
    assert_ne!(
        rfc_nonce, blob.nonce,
        "nonce блоба совпал с base_nonce RFC 9180: похоже, он снова выводится, \
         а не берётся из генератора"
    );
}

// ---------------------------------------------------------------------------
// 5. Nonce выводится из того же prk, что и ключ
// ---------------------------------------------------------------------------

/// A full RNG-state repeat does not expose plaintexts (C-13).
///
/// A realistic, ordinary scenario: virtual-machine snapshot rollback, disk-image
/// cloning, and backup restoration return the RNG to
/// its previous state. Previously this repeated BOTH ephemeral pair AND nonce, taken
/// consecutively from one RNG, repeating the entire keystream and
/// making two ciphertexts reveal `ct₁ ⊕ ct₂ = pt₁ ⊕ pt₂`. These plaintexts
/// are 2-of-2 secret shares, exposing both shares, KEK, and the content
/// key without a single private key.
///
/// Random bytes now seed a derivation that also includes plaintext,
/// so repeated RNG state with **different** secrets produces different nonces.
/// The ephemeral pair still repeats, as it must, since it is computed
/// before plaintext. Hence this check's structure: require
/// the premise (the RNG repeated) to hold while XOR still
/// fails to yield plaintext.
#[test]
fn a_full_generator_repeat_no_longer_reuses_the_keystream() {
    let pt_one = b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let pt_two = b"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";

    let sk = recipient(7);
    let pk = x25519_public(&sk);

    let mut rng_one = SeedRng::seeded(44);
    let mut rng_two = SeedRng::seeded(44);
    let first = seal(&pk, INFO, AAD, pt_one, &mut rng_one).unwrap();
    let second = seal(&pk, INFO, AAD, pt_two, &mut rng_two).unwrap();

    // Предпосылка: генератор действительно повторился. Без неё тест проходил бы
    // просто потому, что что-то где-то разошлось, и ничего бы не измерял.
    assert_eq!(first.enc, second.enc, "предпосылка: генератор повторился, пара совпала");
    assert_ne!(
        first.nonce, second.nonce,
        "nonce совпал при повторе генератора: подмешивание открытого текста не работает"
    );

    // Попытка восстановить открытый текст ровно тем способом, который работал
    // раньше: XOR шифротекстов, скомпенсированный известным вторым текстом.
    let recovered: Vec<u8> = first
        .ct
        .iter()
        .zip(second.ct.iter())
        .zip(pt_two.iter())
        .map(|((a, b), known)| a ^ b ^ known)
        .take(pt_one.len())
        .collect();

    assert_ne!(
        recovered.as_slice(),
        pt_one.as_slice(),
        "повтор генератора выдал открытый текст целиком"
    );
}

/// Identical input with a repeated RNG yields identical output, revealing
/// only that fact.
///
/// The guarantee's boundary, explicitly stated. Mixing in plaintext makes the nonce
/// a function of (seed, plaintext); when both match, ciphertext matches.
/// Only equality of inputs is revealed, not their contents; it cannot be
/// otherwise because a pure crate has no source independent of both RNG
/// and data by construction.
#[test]
fn identical_input_under_a_repeated_generator_is_deterministic_and_that_is_the_limit() {
    let sk = recipient(7);
    let pk = x25519_public(&sk);

    let mut rng_one = SeedRng::seeded(44);
    let mut rng_two = SeedRng::seeded(44);
    let first = seal(&pk, INFO, AAD, PT, &mut rng_one).unwrap();
    let second = seal(&pk, INFO, AAD, PT, &mut rng_two).unwrap();

    assert_eq!(first, second, "тот же вход и тот же генератор обязаны дать тот же блоб");
}

// ---------------------------------------------------------------------------
// 6. Привязка к личности получателя
// ---------------------------------------------------------------------------

#[test]
fn a_stranger_cannot_rebind_a_blob_to_his_own_identity() {
    // Классический identity misbinding: противник со своим приватным ключом
    // пытается выдать чужой блоб за адресованный ему. pk_R в ikm обязан это
    // закрывать.
    let mut rng = SeedRng::seeded(55);
    let victim = recipient(7);
    let blob = seal(&x25519_public(&victim), INFO, AAD, PT, &mut rng).unwrap();

    for seed in [1u8, 2, 3, 9, 200] {
        let intruder = recipient(seed);
        assert!(
            open(&intruder, &blob, INFO, AAD).is_err(),
            "блоб открылся чужим ключом (seed={seed})"
        );
    }
}
