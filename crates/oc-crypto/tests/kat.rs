#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::manual_is_multiple_of,
    clippy::disallowed_methods,
    clippy::disallowed_types
)]
//! Frozen key-schedule known-answer tests (KAT).
//!
//! Vectors live **outside** code, in the repository-root `tests/kat/`; this is not
//! an organizational detail. Their purpose is to let a second format implementation
//! (server, editor, third-party client) compare results without reading our Rust. A vector
//! encoded as a test constant cannot provide that.
//!
//! **Change rule.** `tests/kat/*.kat` files change only alongside
//! a decision recorded in `docs/format.md` and a format-version increase. "Test
//! failed → fix the vector" is forbidden: the vector would stop being
//! evidence and become a reflection of code, making the test tautological.
//!
//! The file format is deliberately primitive: `name = hexadecimal bytes`, with
//! `#` comments. Twenty dependency-free parsing lines leave an implementer
//! no excuse not to compare.

use std::collections::BTreeMap;
use std::path::PathBuf;

use oc_crypto::aead::chunk_aad;
use oc_crypto::kdf::{
    derive_content_mac_key, derive_kek, derive_payload_key, derive_private_meta_key,
    claim_secret_from_code, secret_b_from_claim, slot_commitment,
};
use oc_crypto::merkle::{Leaf, MerkleTree, leaf_of, node_of, root_of};
use oc_crypto::secret::{Cek, ClaimSecret, SecretA, SecretB};
use oc_crypto::AeadAlg;

// --------------------------------------------------------------------------
// Входные данные векторов. Значения произвольные, но ФИКСИРОВАННЫЕ навсегда.
// --------------------------------------------------------------------------

const FILE_ID: [u8; 16] = [0x11; 16];
const ORG_ID: &[u8] = b"acme";
const SECRET_A: [u8; 32] = [0xa1; 32];
const SECRET_B: [u8; 32] = [0xb2; 32];
const HEADER_SALT: [u8; 32] = [0x21; 32];
const CEK: [u8; 32] = [0xc3; 32];
const CLAIM: [u8; 32] = [0x44; 32];
const CORE_HASH: [u8; 32] = [0x0c; 32];
const CHUNK_SIZE: u32 = 65536;
/// Canonical claim-code text: 30 characters from the §3.4 alphabet, no separators.
///
/// This is derivation K14 INPUT, not a human-facing example: people see the code
/// in hyphen-separated groups, but the canonical form enters the hash, so that
/// is what must be frozen.
const CLAIM_CODE: &[u8] = b"7K3QM9XBTZ4HVND2PRWC6JSFG8YKM0";
const NONCE: [u8; 24] = [0x01; 24];
const TAG: [u8; 16] = [0x02; 16];
/// Chunk ciphertext for tree vectors. Included in the leaf preimage (§6.3), so
/// it must be frozen alongside nonce and tag.
///
/// Thirty-three bytes, not a round number: length enters the preimage as `u64be`,
/// and a vector of an unaligned length detects length-field width substitution.
const CT: [u8; 33] = [0x03; 33];

fn kat_path(name: &str) -> PathBuf {
    // CARGO_MANIFEST_DIR — это crates/oc-crypto; векторы лежат в корне репозитория.
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/kat").join(name)
}

/// Parse a vector file: `name = hex`; skip empty lines and `#` comments.
fn load(name: &str) -> BTreeMap<String, Vec<u8>> {
    let path = kat_path(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!("{}: {e}. Векторы KAT обязаны лежать в репозитории", path.display())
    });

    let mut out = BTreeMap::new();
    for (number, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .unwrap_or_else(|| panic!("{}:{}: строка не вида «имя = hex»", path.display(), number + 1));
        out.insert(key.trim().to_string(), unhex(value.trim()));
    }
    out
}

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len() % 2 == 0, "нечётная длина hex: {text}");
    let bytes = text.as_bytes();
    (0..text.len() / 2)
        .map(|i| {
            let hi = (bytes[i * 2] as char).to_digit(16).expect("не hex") as u8;
            let lo = (bytes[i * 2 + 1] as char).to_digit(16).expect("не hex") as u8;
            (hi << 4) | lo
        })
        .collect()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Compare a value with the frozen vector.
///
/// The error message is deliberately long: the first reader will want to
/// "fix the vector", and only the text can stop them.
fn check(vectors: &BTreeMap<String, Vec<u8>>, name: &str, actual: &[u8]) {
    let expected = vectors
        .get(name)
        .unwrap_or_else(|| panic!("в файле векторов нет строки «{name}». Ожидалось: {}", hex(actual)));
    assert_eq!(
        hex(actual),
        hex(expected),
        "\nВЕКТОР {name} НЕ СОШЁЛСЯ.\n\
         Это изменение байтов формата. Поправить вектор под новый код можно ТОЛЬКО\n\
         вместе с решением в docs/format.md и подъёмом версии формата — иначе ранее\n\
         выпущенные контейнеры перестанут читаться, а вектор перестанет что-либо\n\
         доказывать.\n"
    );
}

/// Recompute all vectors and print them in the file format.
///
/// Marked `#[ignore]` because it is a tool, not a check. Run
/// manually:
///
/// ```text
/// cargo test -p oc-crypto --test kat -- --ignored --nocapture
/// ```
///
/// Exists because reissuing vectors is sometimes legitimate: a deliberate format
/// change, documented in `docs/format.md`, with a version increase.
/// A tool is better than editing thirty lines manually: by hand people
/// would fix only the failing lines and silently leave the others
/// inconsistent.
#[test]
#[ignore = "инструмент перевыпуска векторов, а не проверка"]
fn print_all_vectors_for_regeneration() {
    let a = SecretA::from_bytes(SECRET_A);
    let b = SecretB::from_bytes(SECRET_B);
    let cek = Cek::from_bytes(CEK);
    let kek = derive_kek(&FILE_ID, ORG_ID, &a, &b);
    let (share, commitment) = secret_b_from_claim(&FILE_ID, &ClaimSecret::from_bytes(CLAIM));

    println!("\n===== derivations.kat =====");
    println!("k1_kek = {}", hex(kek.expose()));
    println!(
        "k3_payload = {}",
        hex(derive_payload_key(&cek, &HEADER_SALT, &FILE_ID, CHUNK_SIZE, AeadAlg::XChaCha20Poly1305)
            .expose())
    );
    println!(
        "k5_private_meta = {}",
        hex(derive_private_meta_key(&cek, &HEADER_SALT, &FILE_ID).expose())
    );
    println!(
        "k6_content_mac = {}",
        hex(derive_content_mac_key(&cek, &HEADER_SALT, &FILE_ID).expose())
    );
    println!("k14_claim_secret_from_code = {}", hex(claim_secret_from_code(CLAIM_CODE).expose()));
    println!("k7_secret_b_from_claim = {}", hex(share.expose()));
    println!("k8_claim_commitment = {}", hex(&commitment));
    println!("k9_slot_commitment = {}", hex(&slot_commitment(&kek, &CORE_HASH)));

    println!("\n===== chunk_aad.kat =====");
    println!("index_0 = {}", hex(&chunk_aad(&FILE_ID, 0, AeadAlg::XChaCha20Poly1305)));
    println!("index_7 = {}", hex(&chunk_aad(&FILE_ID, 7, AeadAlg::XChaCha20Poly1305)));
    println!("index_max = {}", hex(&chunk_aad(&FILE_ID, u32::MAX, AeadAlg::XChaCha20Poly1305)));

    println!("\n===== tree.kat =====");
    println!("leaf_index_0 = {}", hex(&leaf_of(0, &NONCE, &TAG, &CT).0));
    println!("leaf_index_7 = {}", hex(&leaf_of(7, &NONCE, &TAG, &CT).0));
    println!(
        "node = {}",
        hex(&node_of(&leaf_of(0, &NONCE, &TAG, &CT).0, &leaf_of(1, &NONCE, &TAG, &CT).0))
    );
    println!("root_of_single = {}", hex(&root_of(1, &leaf_of(0, &NONCE, &TAG, &CT).0)));
    for count in [1u32, 2, 3, 5] {
        let leaves: Vec<Leaf> = (0..count).map(deterministic_leaf).collect();
        let tree = MerkleTree::build(&leaves).unwrap();
        println!("apex_{count}_leaves = {}", hex(&tree.apex()));
        println!("root_{count}_leaves = {}", hex(&tree.root()));
    }
    println!();
}

// --------------------------------------------------------------------------
// Производные ключей (docs/format.md §3.5)
// --------------------------------------------------------------------------

#[test]
fn the_key_schedule_matches_its_frozen_vectors() {
    let v = load("derivations.kat");

    let a = SecretA::from_bytes(SECRET_A);
    let b = SecretB::from_bytes(SECRET_B);
    let cek = Cek::from_bytes(CEK);

    let kek = derive_kek(&FILE_ID, ORG_ID, &a, &b);
    check(&v, "k1_kek", kek.expose());

    let payload = derive_payload_key(&cek, &HEADER_SALT, &FILE_ID, CHUNK_SIZE, AeadAlg::XChaCha20Poly1305);
    check(&v, "k3_payload", payload.expose());

    let meta = derive_private_meta_key(&cek, &HEADER_SALT, &FILE_ID);
    check(&v, "k5_private_meta", meta.expose());

    let mac = derive_content_mac_key(&cek, &HEADER_SALT, &FILE_ID);
    check(&v, "k6_content_mac", mac.expose());

    check(&v, "k14_claim_secret_from_code", claim_secret_from_code(CLAIM_CODE).expose());

    let (share, commitment) = secret_b_from_claim(&FILE_ID, &ClaimSecret::from_bytes(CLAIM));
    check(&v, "k7_secret_b_from_claim", share.expose());
    check(&v, "k8_claim_commitment", &commitment);

    check(&v, "k9_slot_commitment", &slot_commitment(&kek, &CORE_HASH));
}

// --------------------------------------------------------------------------
// Связанные данные чанка (§6.1)
// --------------------------------------------------------------------------

#[test]
fn the_chunk_aad_matches_its_frozen_vectors() {
    let v = load("chunk_aad.kat");
    check(&v, "index_0", &chunk_aad(&FILE_ID, 0, AeadAlg::XChaCha20Poly1305));
    check(&v, "index_7", &chunk_aad(&FILE_ID, 7, AeadAlg::XChaCha20Poly1305));
    check(&v, "index_max", &chunk_aad(&FILE_ID, u32::MAX, AeadAlg::XChaCha20Poly1305));
}

// --------------------------------------------------------------------------
// Дерево целостности (§6.3)
// --------------------------------------------------------------------------

/// Leaf `i`, derived deterministically: nonce and tag derive from
/// the index, keeping the vector independent of the RNG.
fn deterministic_leaf(index: u32) -> Leaf {
    let seed = *blake3::hash(&index.to_be_bytes()).as_bytes();
    let mut nonce = [0u8; 24];
    let mut tag = [0u8; 16];
    nonce.copy_from_slice(&seed[..24]);
    tag.copy_from_slice(&seed[8..24]);
    // Шифротекст — то же семя целиком: лист обязан от него зависеть, и вектор
    // обязан это фиксировать.
    leaf_of(index, &nonce, &tag, &seed)
}

#[test]
fn the_tree_matches_its_frozen_vectors() {
    let v = load("tree.kat");

    // Одиночные величины: лист и внутренний узел на фиксированных входах.
    check(&v, "leaf_index_0", &leaf_of(0, &NONCE, &TAG, &CT).0);
    check(&v, "leaf_index_7", &leaf_of(7, &NONCE, &TAG, &CT).0);
    check(&v, "node", &node_of(&leaf_of(0, &NONCE, &TAG, &CT).0, &leaf_of(1, &NONCE, &TAG, &CT).0));
    check(&v, "root_of_single", &root_of(1, &leaf_of(0, &NONCE, &TAG, &CT).0));

    // Корни деревьев из 1, 2, 3 и 5 листьев: размеры выбраны так, чтобы
    // продвижение нечётного узла (§6.3) сработало и один раз, и на нескольких
    // уровнях сразу.
    for count in [1u32, 2, 3, 5] {
        let leaves: Vec<Leaf> = (0..count).map(deterministic_leaf).collect();
        let tree = MerkleTree::build(&leaves).unwrap();
        check(&v, &format!("root_{count}_leaves"), &tree.root());
        check(&v, &format!("apex_{count}_leaves"), &tree.apex());
    }
}

// --------------------------------------------------------------------------
// Запечатывание слота (K10) и связанные данные (§3.3, §3.5, §2.0)
// --------------------------------------------------------------------------

/// Vector recipient's private key. Fixed forever.
const SEAL_RECIPIENT_SECRET: [u8; 32] = [0x5e; 32];
/// Sealing associated data: `policy_hash` in the format.
const SEAL_AAD: [u8; 32] = [0x9d; 32];

/// The `Seal` vector is frozen as an **opening** vector, not a sealing vector.
///
/// Not a simplification, but the only honest form. Sealing is random by
/// construction: the ephemeral pair comes from an RNG, the nonce from a seed
/// (§3.1), and a second implementation cannot and should not reproduce identical bytes.
/// Opening is fully deterministic, and every container reader
/// performs it: the server opens its slot, the recipient theirs.
///
/// Thus the vector says: "here are the private key, blob, `info`, and `aad`; you
/// must recover exactly this plaintext". It checks the entire construction
/// at once: X25519 agreement, K10 derivation including `info`, parsing
/// of the stored nonce, and AEAD with associated data. A separate vector for the intermediate
/// K10 key is unnecessary and worse: it would freeze an internal value
/// an implementation may compute differently provided results agree.
#[test]
fn the_slot_sealing_matches_its_frozen_vectors() {
    use oc_crypto::seal::{SealedBlob, open, slot_info, x25519_public};
    use oc_crypto::secret::X25519Secret;
    use oc_crypto::{KemAlg, label};

    let v = load("seal.kat");
    let secret = X25519Secret::from_bytes(SEAL_RECIPIENT_SECRET);

    // `info` — нормативная строка, и её стоит заморозить отдельно: разойдись она,
    // ключ разошёлся бы молча, а выглядело бы это как «слот не открывается».
    let info = slot_info(label::SLOT_SERVER, KemAlg::X25519HkdfSha256, &FILE_ID);
    check(&v, "slot_info_server", &info);
    check(&v, "recipient_public", &x25519_public(&secret));

    // Связанные данные приватных метаданных — соседнее нормативное значение того
    // же класса. У AAD чанка вектор был с самого начала, у этого не было.
    check(&v, "metadata_aad", &oc_crypto::aead::metadata_aad(&FILE_ID));

    let blob = SealedBlob {
        enc: v.get("seal_enc").expect("нет seal_enc").clone(),
        nonce: <[u8; 24]>::try_from(v.get("seal_nonce").expect("нет seal_nonce").as_slice())
            .unwrap(),
        ct: v.get("seal_ct").expect("нет seal_ct").clone(),
    };
    let opened = open(&secret, &blob, &info, &SEAL_AAD).expect(
        "замороженный блоб не открылся: конструкция запечатывания разошлась с той, \
         которой блоб был создан",
    );
    check(&v, "seal_plaintext", &opened);

    // Контроль: те же байты под другими связанными данными открываться НЕ должны.
    // Без него вектор доказывал бы лишь то, что AEAD что-то возвращает.
    assert!(
        open(&secret, &blob, &info, &[0u8; 32]).is_err(),
        "блоб открылся с чужими связанными данными: привязка к policy_hash не работает"
    );
    assert!(
        open(&secret, &blob, label::SLOT_RECIPIENT.as_bytes(), &SEAL_AAD).is_err(),
        "блоб открылся с чужим info: назначение слота не разделяет ключи"
    );
}

/// Generate a blob for `seal.kat`. Run manually when reissuing.
///
/// The RNG is deterministic here, but that does **not** make sealing
/// a reproducibility contract: it only makes vector reissuance independent
/// of system entropy, which this crate does not have at all.
#[test]
#[ignore = "инструмент перевыпуска векторов, а не проверка"]
fn print_seal_vector() {
    use oc_crypto::seal::{seal, slot_info, x25519_public};
    use oc_crypto::secret::X25519Secret;
    use oc_crypto::{KemAlg, label};

    struct SeedRng([u8; 32]);
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
                self.0 = *blake3::hash(&self.0).as_bytes();
                for (o, s) in out.iter_mut().zip(self.0.iter()) {
                    *o = *s;
                }
            }
            Ok(())
        }
    }
    impl rand_core::TryCryptoRng for SeedRng {}

    let secret = X25519Secret::from_bytes(SEAL_RECIPIENT_SECRET);
    let info = slot_info(label::SLOT_SERVER, KemAlg::X25519HkdfSha256, &FILE_ID);
    let plaintext = SECRET_A;
    let blob = seal(&x25519_public(&secret), &info, &SEAL_AAD, &plaintext, &mut SeedRng([0x11; 32]))
        .unwrap();

    println!("\n===== seal.kat =====");
    println!("recipient_public = {}", hex(&x25519_public(&secret)));
    println!("slot_info_server = {}", hex(&info));
    println!("metadata_aad = {}", hex(&oc_crypto::aead::metadata_aad(&FILE_ID)));
    println!("seal_enc = {}", hex(&blob.enc));
    println!("seal_nonce = {}", hex(&blob.nonce));
    println!("seal_ct = {}", hex(&blob.ct));
    println!("seal_plaintext = {}", hex(&plaintext));
}

/// A P-256 slot opens from a frozen vector.
///
/// Wire-format version 2 check: 65-byte `enc`, mechanism in `info`,
/// stored nonce, AEAD with associated data. Failure means
/// bytes promised immutable changed; fix the code, not the vector.
///
/// This is K10 with `kem_id = 2`, NOT K11. Plan F-6 promised a K11 vector with
/// the wrong number: K11 is a server→device message containing `lease.seq` in `info`,
/// belonging to the lease path. Implementing K11 instead of K10 would make the slot
/// fail to open, appearing as file corruption.
/// THE MLKEM768-P256 HYBRID MATCHES EXTERNAL VECTORS.
///
/// Ten vectors from CFRG draft appendix A.1, five checks each:
/// ML-KEM seed from the common seed, P-256 scalar (checked via its public point),
/// composite public half, deterministic encapsulation, and decapsulation
/// with both halves.
///
/// Negative controls live beside it in module probes: this tests
/// MATCHING external bytes; those test that substituting a half breaks the match.
#[test]
fn the_mlkem_p256_hybrid_matches_the_drafts_own_vectors() {
    use oc_crypto::agreement::KeyAgreement as _;
    use oc_crypto::mlkem_p256;

    let v = load("mlkem_p256.kat");
    for n in 1..=10 {
        let get = |name: &str| {
            v.get(&format!("mlkem_p256_{name}_{n}"))
                .unwrap_or_else(|| panic!("нет поля {name} у вектора {n}"))
        };
        let seed: [u8; 32] = get("seed").as_slice().try_into().unwrap();

        let pair = mlkem_p256::keypair_from_seed(&seed).unwrap();
        assert_eq!(pair.ml_kem_seed.as_slice(), get("decapsulation_key_pq"), "вектор {n}: семя ML-KEM");
        assert_eq!(pair.public_key.as_slice(), get("encapsulation_key"), "вектор {n}: открытая половина");

        // Скаляр сверяется по ОТКРЫТОЙ точке: приватный наружу не выдаётся, а
        // равенство точек означает равенство скаляров при том же генераторе.
        let expected_scalar: [u8; 32] = get("decapsulation_key_t").as_slice().try_into().unwrap();
        let expected = oc_crypto::agreement::P256Agreement::from_be_bytes(&expected_scalar).unwrap();
        assert_eq!(pair.classical.public_key(), expected.public_key(), "вектор {n}: скаляр P-256");

        let randomness: [u8; 160] = get("randomness").as_slice().try_into().unwrap();
        let (shared, ciphertext) = mlkem_p256::encapsulate_derand(&pair.public_key, &randomness).unwrap();
        assert_eq!(ciphertext.as_slice(), get("ciphertext"), "вектор {n}: шифротекст");
        assert_eq!(shared.as_slice(), get("shared_secret"), "вектор {n}: секрет инкапсуляции");

        let back = mlkem_p256::decapsulate_with(&pair.ml_kem_seed, &pair.classical, &ciphertext).unwrap();
        assert_eq!(back.as_slice(), get("shared_secret"), "вектор {n}: секрет декапсуляции");
    }
}

/// THE X-WING HYBRID MATCHES EXTERNAL VECTORS, NOT ITS OWN.
///
/// Three draft appendix C vectors, four checks each: pair expansion
/// from seed, deterministic encapsulation (ciphertext and secret), and
/// decapsulation. A vector taken from our code would show only
/// that the code had not changed; these show agreement with another implementation.
#[test]
fn the_xwing_hybrid_matches_the_drafts_own_vectors() {
    use oc_crypto::xwing;

    let v = load("xwing.kat");
    for n in 1..=3 {
        let secret: [u8; 32] =
            v.get(&format!("xwing_secret_{n}")).expect("нет семени").as_slice().try_into().unwrap();
        let public = v.get(&format!("xwing_public_{n}")).expect("нет открытой половины");
        let seed: [u8; 64] =
            v.get(&format!("xwing_eseed_{n}")).expect("нет семени инкапсуляции").as_slice().try_into().unwrap();
        let ciphertext = v.get(&format!("xwing_ciphertext_{n}")).expect("нет шифротекста");
        let shared = v.get(&format!("xwing_shared_{n}")).expect("нет общего секрета");

        assert_eq!(
            xwing::public_key(&secret).unwrap().as_slice(),
            public.as_slice(),
            "вектор {n}: открытая половина разошлась — рост пары из семени изменился"
        );

        let (sent, produced) = xwing::encapsulate_derand(public, &seed).unwrap();
        assert_eq!(produced.as_slice(), ciphertext.as_slice(), "вектор {n}: шифротекст");
        assert_eq!(sent.as_slice(), shared.as_slice(), "вектор {n}: секрет при инкапсуляции");

        assert_eq!(
            xwing::decapsulate(&secret, ciphertext).unwrap().as_slice(),
            shared.as_slice(),
            "вектор {n}: секрет при декапсуляции"
        );
    }
}

#[test]
fn a_p256_slot_opens_from_its_frozen_vector() {
    use oc_crypto::agreement::{KeyAgreement, P256Agreement};
    use oc_crypto::seal::{SealedBlob, open_with, slot_info};
    use oc_crypto::{KemAlg, label};

    let v = load("seal_p256.kat");
    let recipient = P256Agreement::from_be_bytes(&SEAL_RECIPIENT_SECRET).unwrap();

    check(&v, "p256_recipient_public", &recipient.public_key());

    let info = slot_info(label::SLOT_AUTHOR_DEVICE, KemAlg::P256HkdfSha256, &FILE_ID);
    check(&v, "p256_slot_info_device", &info);

    let blob = SealedBlob {
        enc: v.get("p256_seal_enc").expect("нет p256_seal_enc").clone(),
        nonce: <[u8; 24]>::try_from(
            v.get("p256_seal_nonce").expect("нет p256_seal_nonce").as_slice(),
        )
        .unwrap(),
        ct: v.get("p256_seal_ct").expect("нет p256_seal_ct").clone(),
    };
    assert_eq!(blob.enc.len(), 65, "эфемерный ключ P-256 на проводе обязан быть 65 байт");

    let opened = open_with(&recipient, &blob, &info, &SEAL_AAD).expect(
        "замороженный блоб P-256 не открылся: конструкция запечатывания разошлась с той, \
         которой блоб был создан",
    );
    check(&v, "p256_seal_plaintext", &opened);
}

/// Issue a P-256 sealing vector. A tool, not a check.
///
/// `#[ignore]` for the same reason as its neighbors: reissuance is legitimate only
/// alongside a decision recorded in `docs/format.md`.
#[test]
#[ignore = "инструмент перевыпуска векторов, а не проверка"]
fn print_p256_seal_vector() {
    use oc_crypto::agreement::{KeyAgreement, P256Agreement};
    use oc_crypto::seal::{seal_p256, slot_info};
    use oc_crypto::{KemAlg, label};

    struct SeedRng([u8; 32]);
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
                self.0 = *blake3::hash(&self.0).as_bytes();
                for (o, s) in out.iter_mut().zip(self.0.iter()) {
                    *o = *s;
                }
            }
            Ok(())
        }
    }
    impl rand_core::TryCryptoRng for SeedRng {}

    let recipient = P256Agreement::from_be_bytes(&SEAL_RECIPIENT_SECRET).unwrap();
    let info = slot_info(label::SLOT_AUTHOR_DEVICE, KemAlg::P256HkdfSha256, &FILE_ID);
    let mut rng = SeedRng([0x77; 32]);
    let plaintext = [0xa1u8; 32];
    let blob = seal_p256(&recipient.public_key(), &info, &SEAL_AAD, &plaintext, &mut rng)
        .unwrap();

    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    println!("p256_recipient_public = {}", hex(&recipient.public_key()));
    println!("p256_slot_info_device = {}", hex(&info));
    println!("p256_seal_enc = {}", hex(&blob.enc));
    println!("p256_seal_nonce = {}", hex(&blob.nonce));
    println!("p256_seal_ct = {}", hex(&blob.ct));
    println!("p256_seal_plaintext = {}", hex(&plaintext));
}

/// Editing-device signature: vector captured from a LIVE TPM.
///
/// The only vector in this directory our code neither produced nor can produce:
/// the private key remained in the development machine's TPM and was deleted after the run.
/// It therefore proves something no other vector proves: the pure
/// verifier agrees with an INDEPENDENT implementation rather than itself.
///
/// Reissuance requires rerunning `spikes/rsa-pss-tpm/` on a TPM-equipped
/// machine, producing a DIFFERENT vector: PSS salt is random; twenty signatures of one
/// message differ. Thus "failed, so reissue" cannot work here even
/// technically, which is fortunate.
#[test]
fn the_editor_signature_vector_from_a_real_tpm_verifies() {
    let v = load("rsa_pss.kat");
    let modulus: [u8; oc_crypto::rsa::MODULUS_LEN] =
        v["modulus"].as_slice().try_into().expect("модуль обязан быть 256 байт");
    assert_eq!(v["exponent"], vec![0x01, 0x00, 0x01], "показатель прибит к 65537");
    assert_eq!(
        oc_crypto::rsa::verify_pss_sha256(&modulus, &v["message"], &v["signature"]),
        Ok(()),
        "подпись живого TPM обязана проверяться нашим проверяющим"
    );
}

/// The verifier must REJECT, more importantly than accept.
///
/// Historically verifiers broke: Bleichenbacher's `e = 3` attack concerned
/// careless padding parsing, not RSA strength. The vector therefore tests
/// not only acceptance: every corruption must fail with **its proper
/// code**, since "wrong length" and "mismatch" are different failures.
#[test]
fn every_corruption_of_the_editor_signature_is_refused() {
    let v = load("rsa_pss.kat");
    let modulus: [u8; oc_crypto::rsa::MODULUS_LEN] = v["modulus"].as_slice().try_into().unwrap();
    let message = &v["message"];
    let signature = &v["signature"];

    // Края и середина подписи: перебирать все 256 байт незачем, сходимость
    // ломается любым.
    for at in [0usize, 1, 127, 254, 255] {
        let mut bad = signature.clone();
        bad[at] ^= 0x01;
        assert_eq!(
            oc_crypto::rsa::verify_pss_sha256(&modulus, message, &bad),
            Err(oc_crypto::CryptoError::BadSignature),
            "испорченный байт {at} подписи принят"
        );
    }

    let mut other = message.clone();
    other[0] ^= 0x01;
    assert_eq!(
        oc_crypto::rsa::verify_pss_sha256(&modulus, &other, signature),
        Err(oc_crypto::CryptoError::BadSignature),
        "подпись принята для чужого сообщения"
    );

    // Чужой модуль. Младший байт трогать нельзя — модуль обязан остаться
    // нечётным, иначе отказ придёт по длине, а проверяется здесь сходимость.
    let mut wrong = modulus;
    wrong[0] ^= 0x02;
    assert_eq!(
        oc_crypto::rsa::verify_pss_sha256(&wrong, message, signature),
        Err(oc_crypto::CryptoError::BadSignature),
        "подпись принята под чужим модулем"
    );

    // Длина — ДРУГОЙ код возврата: это ошибка вызывающего или обрезанный файл, а
    // не подделка.
    for len in [signature.len() - 1, signature.len() + 1] {
        let mut wrong_len = signature.clone();
        wrong_len.resize(len, 0);
        assert_eq!(
            oc_crypto::rsa::verify_pss_sha256(&modulus, message, &wrong_len),
            Err(oc_crypto::CryptoError::BadLength),
            "подпись длины {len} не отвергнута по длине"
        );
    }
}

// --------------------------------------------------------------------------
// Производные провода: K11, K12, K21, K22 (docs/format.md §3.5) — derivations_wire.kat
// --------------------------------------------------------------------------

/// Fingerprint of the device receiving shares A and B. For `kem_id = 1`, the fingerprint
/// is the public key itself, so this private key matches
/// `seal.kat`: one pair for all opening vectors.
const DEVICE_SECRET: [u8; 32] = SEAL_RECIPIENT_SECRET;
/// Lease sequence in share-A `info`. Nonzero: zero would not detect byte-order
/// swapping between `u64be` and `u64le`.
const LEASE_SEQ: u64 = 0x0102_0304_0506_0708;
/// Nonce-hedging plaintext: 33 bytes, unaligned as in the tree vectors.
const SEED_PLAINTEXT: [u8; 33] = [0x7e; 33];
/// AAD of another length, so the vector distinguishes both variable parts.
const SEED_AAD: [u8; 17] = [0x4a; 17];
/// Seed: 24 random bytes per specification, fixed here.
const NONCE_SEED: [u8; 24] = [0x5d; 24];

/// Share-A `info` per §3.5: label ‖ u8(kem) ‖ file_id ‖ device_fpr ‖ u64be(seq).
///
/// Constructed HERE from the specification, not taken from [`oc_crypto::seal`], even though
/// construction now lives in this crate, tempting reuse. Forbidden: the probe
/// would compare a function with itself. The former argument "the crate is pure and cannot see the server"
/// reached the right conclusion for the wrong reason:
/// the SECOND implementation is the substance of this probe. The server
/// checks its construction against the same vector separately
/// (`crates/cc-authority/tests/kat_journal.rs`), making implementations of one string
/// agree through a file rather than shared code.
fn a_to_device_info_by_spec(device_fpr: &[u8; 32], seq: u64) -> Vec<u8> {
    let mut info = oc_crypto::label::A_TO_DEVICE.as_bytes().to_vec();
    info.push(oc_crypto::KemAlg::X25519HkdfSha256 as u8);
    info.extend_from_slice(&FILE_ID);
    info.extend_from_slice(device_fpr);
    info.extend_from_slice(&seq.to_be_bytes());
    info
}

/// Share-B `info` per §3.5: label ‖ u8(kem) ‖ file_id ‖ device_fpr, without sequence.
fn b_to_device_info_by_spec(device_fpr: &[u8; 32]) -> Vec<u8> {
    let mut info = oc_crypto::label::B_TO_DEVICE.as_bytes().to_vec();
    info.push(oc_crypto::KemAlg::X25519HkdfSha256 as u8);
    info.extend_from_slice(&FILE_ID);
    info.extend_from_slice(device_fpr);
    info
}

fn blob_from(v: &BTreeMap<String, Vec<u8>>, prefix: &str) -> oc_crypto::seal::SealedBlob {
    oc_crypto::seal::SealedBlob {
        enc: v.get(&format!("{prefix}_enc")).unwrap_or_else(|| panic!("нет {prefix}_enc")).clone(),
        nonce: <[u8; 24]>::try_from(
            v.get(&format!("{prefix}_nonce")).unwrap_or_else(|| panic!("нет {prefix}_nonce")).as_slice(),
        )
        .unwrap(),
        ct: v.get(&format!("{prefix}_ct")).unwrap_or_else(|| panic!("нет {prefix}_ct")).clone(),
    }
}

#[test]
fn the_wire_derivations_match_their_frozen_vectors() {
    use oc_crypto::kdf::{derive_witness_key, device_secret_from_claim};
    use oc_crypto::seal::{open, x25519_public};
    use oc_crypto::secret::X25519Secret;

    let v = load("derivations_wire.kat");
    let device = X25519Secret::from_bytes(DEVICE_SECRET);
    let fpr = x25519_public(&device);
    check(&v, "device_fpr", &fpr);
    // K27: отпечаток для механизмов, чей ключ длиннее 32 байт. Входы — те же
    // фиксированные величины, что у остальных векторов провода: секрет
    // получателя P-256 и семя 0x4d для гибридов. X25519 здесь нет намеренно —
    // для него отпечаток и есть ключ (строка `device_fpr` выше).
    {
        use oc_crypto::KemAlg;
        use oc_crypto::agreement::{KeyAgreement as _, P256Agreement};
        let p256 = P256Agreement::from_be_bytes(&SEAL_RECIPIENT_SECRET).unwrap();
        check(&v, "device_fpr_p256", &oc_crypto::kdf::device_fpr(KemAlg::P256HkdfSha256, &p256.public_key()).unwrap());
        let xw = oc_crypto::xwing::public_key(&[0x4d; 32]).unwrap();
        check(&v, "device_fpr_xwing", &oc_crypto::kdf::device_fpr(KemAlg::XWing, &xw).unwrap());
        let seed = oc_crypto::mlkem_p256::ml_kem_seed_from_stored(&[0x4d; 32]);
        let mp = oc_crypto::mlkem_p256::public_key_from_parts(&seed, &p256.public_key()).unwrap();
        check(&v, "device_fpr_mlkem_p256", &oc_crypto::kdf::device_fpr(KemAlg::MlKem768P256, &mp).unwrap());
    }
    let session = oc_crypto::kdf::derive_session_mac_key(&[0xc3; 32], &fpr);
    let framed = [&[3u8][..], &[0x7a; 41][..]].concat();
    check(&v, "k23_prove_echo", &oc_crypto::kdf::prove_echo(&[0xc3; 32], &fpr));
    check(&v, "k24_session_mac_key", session.expose());
    check(&v, "k25_request_mac", &oc_crypto::kdf::request_mac(&session, &framed));

    // K12: ключ свидетеля состояния — из секрета устройства, соль пуста.
    check(&v, "k12_witness_key", derive_witness_key(&device).expose());

    // K22: пара наследника по коду — из кода и file_id.
    let heir_secret = device_secret_from_claim(&FILE_ID, &ClaimSecret::from_bytes(CLAIM));
    check(&v, "k22_claim_device_secret", &heir_secret);
    check(&v, "k22_claim_device_public", &x25519_public(&X25519Secret::from_bytes(heir_secret)));

    // K11 и K21 — как `seal.kat`: векторы ОТКРЫТИЯ. `info` заморожен отдельно:
    // разойдись он, ключ разошёлся бы молча.
    let a_info = a_to_device_info_by_spec(&fpr, LEASE_SEQ);
    check(&v, "k11_info", &a_info);
    let a_blob = blob_from(&v, "k11");
    // AAD доли A — policy_hash (тот же, что у seal.kat).
    let opened = open(&device, &a_blob, &a_info, &SEAL_AAD).expect("доля A не открылась замороженным блобом");
    check(&v, "k11_plaintext", &opened);
    // Под другим номером лизинга та же доля не открывается: номер в info несущий.
    assert!(
        open(&device, &a_blob, &a_to_device_info_by_spec(&fpr, LEASE_SEQ + 1), &SEAL_AAD).is_err(),
        "доля A открылась под чужим номером лизинга"
    );

    let b_info = b_to_device_info_by_spec(&fpr);
    check(&v, "k21_info", &b_info);
    let b_blob = blob_from(&v, "k21");
    // AAD доли B — отпечаток устройства (см. `decide::seal_share_b`).
    let opened = open(&device, &b_blob, &b_info, &fpr).expect("доля B не открылась замороженным блобом");
    check(&v, "k21_plaintext", &opened);
    assert!(
        open(&device, &b_blob, &a_info, &fpr).is_err(),
        "доля B открылась под info доли A: метки не разделяют ключи"
    );
}

// --------------------------------------------------------------------------
// Засевы nonce: K17–K20 (§3.1, §3.5) — nonce_seeds.kat
// --------------------------------------------------------------------------

#[test]
fn the_nonce_seeds_match_their_frozen_vectors() {
    use oc_crypto::kdf::hedged_nonce;
    use oc_crypto::label;
    let v = load("nonce_seeds.kat");
    for (name, label) in [
        ("k17_seal_nonce", label::SEAL_NONCE),
        ("k18_wrap_nonce", label::WRAP_NONCE),
        ("k19_frame_nonce", label::FRAME_NONCE),
        ("k20_meta_nonce", label::META_NONCE),
    ] {
        check(&v, name, &hedged_nonce::<24>(label, &NONCE_SEED, &SEED_PLAINTEXT, &SEED_AAD).unwrap());
    }
    // Одинаковый засев и текст в другом AEAD-контексте не повторяют nonce.
    assert_ne!(
        hedged_nonce::<24>(label::SEAL_NONCE, &NONCE_SEED, &SEED_PLAINTEXT, &SEED_AAD).unwrap(),
        hedged_nonce::<24>(label::SEAL_NONCE, &NONCE_SEED, &SEED_PLAINTEXT, &[0x4b; 17]).unwrap(),
    );
    // Контроль: другой открытый текст — другой nonce, иначе засев не защищал бы от
    // повтора при откате генератора (С-13).
    assert_ne!(
        hedged_nonce::<24>(label::SEAL_NONCE, &NONCE_SEED, &SEED_PLAINTEXT, &SEED_AAD).unwrap(),
        hedged_nonce::<24>(label::SEAL_NONCE, &NONCE_SEED, &[0x7f; 33], &SEED_AAD).unwrap(),
    );
}

/// Lengths separate parts: identical plaintext/AAD concatenations do not collide.
#[test]
fn nonce_seed_lengths_separate_plaintext_from_aad() {
    use oc_crypto::{kdf::hedged_nonce, label};
    for domain in [label::SEAL_NONCE, label::WRAP_NONCE, label::FRAME_NONCE, label::META_NONCE] {
        let first = hedged_nonce::<24>(domain, &NONCE_SEED, b"ab", b"c").unwrap();
        let second = hedged_nonce::<24>(domain, &NONCE_SEED, b"a", b"bc").unwrap();
        let other_aad = hedged_nonce::<24>(domain, &NONCE_SEED, b"ab", b"d").unwrap();
        assert_ne!(first, second);
        assert_ne!(first, other_aad);
    }
    assert_eq!(
        hedged_nonce::<8161>(label::SEAL_NONCE, &NONCE_SEED, b"", b""),
        Err(oc_crypto::CryptoError::BadLength),
    );
}
/// Deterministic RNG for printing wire vectors. Separate from
/// `print_seal_vector`, whose RNG is correctly scoped inside the function:
/// reissuance RNGs must not be visible to checks.
struct WireRng([u8; 32]);
impl rand_core::TryRng for WireRng {
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
            self.0 = *blake3::hash(&self.0).as_bytes();
            for (o, s) in out.iter_mut().zip(self.0.iter()) {
                *o = *s;
            }
        }
        Ok(())
    }
}
impl rand_core::TryCryptoRng for WireRng {}

/// Generate wire and hedging vectors. Run manually when reissuing:
///
/// ```text
/// cargo test -p oc-crypto --test kat print_wire -- --ignored --nocapture
/// ```
#[test]
#[ignore = "инструмент перевыпуска векторов, а не проверка"]
fn print_wire_and_seed_vectors() {
    use oc_crypto::kdf::{derive_witness_key, device_secret_from_claim, hedged_nonce};
    use oc_crypto::label;
    use oc_crypto::seal::{seal, x25519_public};
    use oc_crypto::secret::X25519Secret;

    let device = X25519Secret::from_bytes(DEVICE_SECRET);
    let fpr = x25519_public(&device);
    let heir_secret = device_secret_from_claim(&FILE_ID, &ClaimSecret::from_bytes(CLAIM));
    let mut rng = WireRng([0x61; 32]);

    println!("\n===== derivations_wire.kat =====");
    println!("device_fpr = {}", hex(&fpr));
    {
        use oc_crypto::KemAlg;
        use oc_crypto::agreement::{KeyAgreement as _, P256Agreement};
        let p256 = P256Agreement::from_be_bytes(&SEAL_RECIPIENT_SECRET).unwrap();
        println!("device_fpr_p256 = {}", hex(&oc_crypto::kdf::device_fpr(KemAlg::P256HkdfSha256, &p256.public_key()).unwrap()));
        let xw = oc_crypto::xwing::public_key(&[0x4d; 32]).unwrap();
        println!("device_fpr_xwing = {}", hex(&oc_crypto::kdf::device_fpr(KemAlg::XWing, &xw).unwrap()));
        let seed = oc_crypto::mlkem_p256::ml_kem_seed_from_stored(&[0x4d; 32]);
        let mp = oc_crypto::mlkem_p256::public_key_from_parts(&seed, &p256.public_key()).unwrap();
        println!("device_fpr_mlkem_p256 = {}", hex(&oc_crypto::kdf::device_fpr(KemAlg::MlKem768P256, &mp).unwrap()));
    }
    let session = oc_crypto::kdf::derive_session_mac_key(&[0xc3; 32], &fpr);
    let framed = [&[3u8][..], &[0x7a; 41][..]].concat();
    println!("k23_prove_echo = {}", hex(&oc_crypto::kdf::prove_echo(&[0xc3; 32], &fpr)));
    println!("k24_session_mac_key = {}", hex(session.expose()));
    println!("k25_request_mac = {}", hex(&oc_crypto::kdf::request_mac(&session, &framed)));
    println!("k12_witness_key = {}", hex(derive_witness_key(&device).expose()));
    println!("k22_claim_device_secret = {}", hex(&heir_secret));
    println!("k22_claim_device_public = {}", hex(&x25519_public(&X25519Secret::from_bytes(heir_secret))));
    let a_info = a_to_device_info_by_spec(&fpr, LEASE_SEQ);
    println!("k11_info = {}", hex(&a_info));
    let a = seal(&fpr, &a_info, &SEAL_AAD, &SECRET_A, &mut rng).unwrap();
    println!("k11_enc = {}", hex(&a.enc));
    println!("k11_nonce = {}", hex(&a.nonce));
    println!("k11_ct = {}", hex(&a.ct));
    println!("k11_plaintext = {}", hex(&SECRET_A));
    let b_info = b_to_device_info_by_spec(&fpr);
    println!("k21_info = {}", hex(&b_info));
    let b = seal(&fpr, &b_info, &fpr, &SECRET_B, &mut rng).unwrap();
    println!("k21_enc = {}", hex(&b.enc));
    println!("k21_nonce = {}", hex(&b.nonce));
    println!("k21_ct = {}", hex(&b.ct));
    println!("k21_plaintext = {}", hex(&SECRET_B));

    println!("\n===== nonce_seeds.kat =====");
    println!("k17_seal_nonce = {}", hex(&hedged_nonce::<24>(label::SEAL_NONCE, &NONCE_SEED, &SEED_PLAINTEXT, &SEED_AAD).unwrap()));
    println!("k18_wrap_nonce = {}", hex(&hedged_nonce::<24>(label::WRAP_NONCE, &NONCE_SEED, &SEED_PLAINTEXT, &SEED_AAD).unwrap()));
    println!("k19_frame_nonce = {}", hex(&hedged_nonce::<24>(label::FRAME_NONCE, &NONCE_SEED, &SEED_PLAINTEXT, &SEED_AAD).unwrap()));
    println!("k20_meta_nonce = {}", hex(&hedged_nonce::<24>(label::META_NONCE, &NONCE_SEED, &SEED_PLAINTEXT, &SEED_AAD).unwrap()));
    println!();
}

// --------------------------------------------------------------------------
// K28 — тождество операции на проводе (docs/protocol.md §9.10) — operation_id.kat
// --------------------------------------------------------------------------

/// Operation identity per specification and crate function, against one vector.
///
/// The transcript is constructed HERE from specification bytes rather than by calling the function:
/// a probe comparing a function only with itself would pass after any field
/// reordering. The vector was computed by an independent script outside Rust (file header).
#[test]
fn the_operation_id_matches_its_frozen_vector() {
    let v = load("operation_id.kat");
    let seed: [u8; 32] = v.get("seed").expect("нет seed").as_slice().try_into().expect("seed не 32 байта");
    let body = v.get("activate_body_without_id").expect("нет тела").clone();

    let by_spec = |kind: u8| {
        let mut transcript = b"CC/v1/operation-id".to_vec();
        transcript.push(0x00);
        transcript.extend_from_slice(&seed);
        transcript.push(kind);
        transcript.extend_from_slice(&body);
        oc_crypto::sha256(&transcript)
    };
    check(&v, "k28_operation_id", &by_spec(3));
    check(&v, "k28_operation_id", &oc_crypto::kdf::operation_id(&seed, 3, &body));
    // Вид разводит активацию и продление с одним телом и одним засевом.
    check(&v, "k28_renew_operation_id", &oc_crypto::kdf::operation_id(&seed, 22, &body));
    assert_ne!(v["k28_operation_id"], v["k28_renew_operation_id"], "вид не вошёл в тождество");
    // Хеш тела, по которому сервер отличает повтор: вид ‖ тело С тегом 9.
    check(&v, "request_digest", &oc_crypto::sha256(&v["activate_request_with_id"]));
}

// --------------------------------------------------------------------------
// K30 — свежее значение сервера (docs/format.md, «СВЕЖЕСТЬ СЕРВЕРА ВЫВОДИТСЯ
// 2026-09-20») — server_fresh.kat
// --------------------------------------------------------------------------

/// HMAC-SHA256 constructed HERE from a single hash.
///
/// The probe has no `hmac` crate; `oc-crypto` has no `[dev-dependencies]` at all.
/// That is beneficial: a second RFC 2104 implementation beside the first costs exactly
/// what is necessary for the vector to check the specification rather than a shared primitive.
/// The key is always 32 bytes, shorter than the block; the "key longer than block" branch
/// is unnecessary and omitted.
fn spec_hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for (index, byte) in key.iter().enumerate() {
        ipad[index] ^= *byte;
        opad[index] ^= *byte;
    }
    let mut inner = ipad.to_vec();
    inner.extend_from_slice(message);
    let inner = oc_crypto::sha256(&inner);
    let mut outer = opad.to_vec();
    outer.extend_from_slice(&inner);
    oc_crypto::sha256(&outer)
}

/// `HKDF-Expand` per RFC 5869 §2.3, following the specification literally.
fn spec_hkdf_expand(prk: &[u8; 32], info: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut block = Vec::new();
    let mut counter = 1u8;
    while out.len() < len {
        let mut message = block.clone();
        message.extend_from_slice(info);
        message.push(counter);
        block = spec_hmac_sha256(prk, &message).to_vec();
        out.extend_from_slice(&block);
        counter += 1;
    }
    out.truncate(len);
    out
}

/// K30 preimage per specification: label ‖ 0x00 ‖ seed ‖ kind ‖ i64be(now) ‖ fingerprint.
fn spec_k30_prk(seed: &[u8], kind: u8, now: i64, device_fpr: &[u8]) -> [u8; 32] {
    let mut transcript = b"CC/v1/server-fresh".to_vec();
    transcript.push(0x00);
    transcript.extend_from_slice(seed);
    transcript.push(kind);
    transcript.extend_from_slice(&now.to_be_bytes());
    transcript.extend_from_slice(device_fpr);
    oc_crypto::sha256(&transcript)
}

/// Fresh server value per specification and crate function, against one vector.
///
/// The vector was computed outside Rust (file header); here it is recomputed a SECOND time,
/// using specification bytes, our own HMAC, and our own Expand, before comparison with
/// `server_fresh`. A probe calling one function and comparing it with itself
/// would pass after any preimage-field reordering.
#[test]
fn the_server_freshness_value_matches_its_frozen_vector() {
    let v = load("server_fresh.kat");
    let seed: [u8; 32] = v["seed"].as_slice().try_into().expect("засев не 32 байта");
    let fpr: [u8; 32] = v["device_fpr"].as_slice().try_into().expect("отпечаток не 32 байта");
    // Момент зафиксирован вектором: 2026-09-20T00:00:00Z.
    let now: i64 = 1_789_862_400;

    // 1. Прообраз.
    check(&v, "prk_attest", &spec_k30_prk(&seed, 1, now, &fpr));

    // 2. Развёртка по спеке.
    let by_spec = |kind: u8, when: i64, len: usize| {
        spec_hkdf_expand(&spec_k30_prk(&seed, kind, when, &fpr), b"CC/v1/server-fresh", len)
    };
    check(&v, "k30_attest_nonce", &by_spec(1, now, 32));
    check(&v, "k30_attest_nonce_next_second", &by_spec(1, now + 1, 32));
    check(&v, "k30_proof_secret_32", &by_spec(2, now, 32));
    check(&v, "k30_proof_secret_96", &by_spec(2, now, 96));

    // 3. Функция крейта — те же байты.
    let mut out = [0u8; 32];
    oc_crypto::kdf::server_fresh(&seed, oc_crypto::kdf::FRESH_ATTEST_NONCE, now, &fpr, &mut out)
        .unwrap();
    check(&v, "k30_attest_nonce", &out);
    oc_crypto::kdf::server_fresh(&seed, oc_crypto::kdf::FRESH_ATTEST_NONCE, now + 1, &fpr, &mut out)
        .unwrap();
    check(&v, "k30_attest_nonce_next_second", &out);
    oc_crypto::kdf::server_fresh(&seed, oc_crypto::kdf::FRESH_PROOF_SECRET, now, &fpr, &mut out)
        .unwrap();
    check(&v, "k30_proof_secret_32", &out);
    let mut three = [0u8; 96];
    oc_crypto::kdf::server_fresh(&seed, oc_crypto::kdf::FRESH_PROOF_SECRET, now, &fpr, &mut three)
        .unwrap();
    check(&v, "k30_proof_secret_96", &three);

    // 4. Свойства, на которых держится решение, — не «подмечены», а проверены.
    // Время разводит значения при ТОМ ЖЕ засеве: ради этого производная заведена.
    assert_ne!(
        v["k30_attest_nonce"], v["k30_attest_nonce_next_second"],
        "время не вошло в прообраз — решение 2026-09-20 не исполнено"
    );
    // Вид разводит два назначения одной метки.
    assert_ne!(
        v["k30_attest_nonce"], v["k30_proof_secret_32"],
        "вид не вошёл в прообраз: один засев дал бы одно значение двум назначениям"
    );
    // Число половин не меняет первую: счётчик Expand дописывает, а не переиначивает.
    assert_eq!(
        v["k30_proof_secret_96"][..32], v["k30_proof_secret_32"][..],
        "развёртка зависит от запрошенной длины"
    );
    // Отпечаток разводит устройства внутри одной секунды.
    let other = [0x60u8; 32];
    let mut theirs = [0u8; 32];
    oc_crypto::kdf::server_fresh(&seed, oc_crypto::kdf::FRESH_PROOF_SECRET, now, &other, &mut theirs)
        .unwrap();
    assert_ne!(theirs.as_slice(), v["k30_proof_secret_32"].as_slice(), "отпечаток не разделяет");
}

// --------------------------------------------------------------------------
// K31 — эхо, привязанное к разговору (docs/format.md, «ЭХО ПРИВЯЗАНО К
// РАЗГОВОРУ 2026-09-21») — echo_transcript.kat
// --------------------------------------------------------------------------

/// Handshake-transcript bytes per specification, constructed HERE.
///
/// Without `Transcript`: the crate's type is exactly what this vector must test;
/// using it for construction would compare code with itself. The label, zero
/// byte, and two length prefixes are therefore written manually.
fn spec_k31_transcript(hello: &[u8], challenge: &[u8]) -> Vec<u8> {
    let mut out = b"CC/v1/echo-transcript".to_vec();
    out.push(0x00);
    out.extend_from_slice(&u32::try_from(hello.len()).expect("кадр длиннее u32").to_le_bytes());
    out.extend_from_slice(hello);
    out.extend_from_slice(&u32::try_from(challenge.len()).expect("кадр длиннее u32").to_le_bytes());
    out.extend_from_slice(challenge);
    out
}

/// Echo per specification: HMAC keyed by the secret over label, fingerprint, and transcript hash.
fn spec_k31_echo(secret: &[u8], device_fpr: &[u8], handshake: &[u8]) -> [u8; 32] {
    let mut message = b"CC/v1/echo-transcript".to_vec();
    message.extend_from_slice(device_fpr);
    message.extend_from_slice(handshake);
    spec_hmac_sha256_any(secret, &message)
}

/// HMAC-SHA256 with a key of ANY length up to one block.
///
/// `spec_hmac_sha256` above fixes key length at 32 bytes; the echo uses
/// the concatenated challenge secret, 32 bytes for one presented key and 64
/// for two. The "key longer than block" branch remains unnecessary: 64 equals one block.
fn spec_hmac_sha256_any(key: &[u8], message: &[u8]) -> [u8; 32] {
    assert!(key.len() <= 64, "вектор не покрывает ключ длиннее блока");
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for (index, byte) in key.iter().enumerate() {
        ipad[index] ^= *byte;
        opad[index] ^= *byte;
    }
    let mut inner = ipad.to_vec();
    inner.extend_from_slice(message);
    let inner = oc_crypto::sha256(&inner);
    let mut outer = opad.to_vec();
    outer.extend_from_slice(&inner);
    oc_crypto::sha256(&outer)
}

/// Conversation-bound echo per specification and crate functions.
///
/// The vector was computed outside Rust (file header); here a second
/// independent path recomputes it using specification bytes and our own HMAC before comparison with
/// `handshake_transcript` and `echo_transcript`.
#[test]
fn the_transcript_bound_echo_matches_its_frozen_vector() {
    let v = load("echo_transcript.kat");
    let hello = v["hello"].clone();
    let challenge = v["challenge"].clone();
    let fpr: [u8; 32] = v["device_fpr"].as_slice().try_into().expect("отпечаток не 32 байта");

    // 1. Транскрипт и его хеш — по спеке.
    let handshake = oc_crypto::sha256(&spec_k31_transcript(&hello, &challenge));
    check(&v, "k31_handshake", &handshake);

    // 2. Эхо — по спеке, для одной половины и для двух.
    check(&v, "k31_echo_32", &spec_k31_echo(&v["secret_32"], &fpr, &handshake));
    check(&v, "k31_echo_64", &spec_k31_echo(&v["secret_64"], &fpr, &handshake));

    // 3. Функции крейта — те же байты.
    let by_crate = oc_crypto::kdf::handshake_transcript(&hello, &challenge);
    check(&v, "k31_handshake", &by_crate);
    check(&v, "k31_echo_32", &oc_crypto::kdf::echo_transcript(&v["secret_32"], &fpr, &by_crate));
    check(&v, "k31_echo_64", &oc_crypto::kdf::echo_transcript(&v["secret_64"], &fpr, &by_crate));

    // 4. ГРАНИЦА КАДРОВ ОДНОЗНАЧНА. Пара со сдвинутой границей даёт тот же
    // склеенный поток байтов; без длин в транскрипте хеш совпал бы, и противник
    // переносил бы байты из приветствия в вызов, не меняя эха.
    let shift_hello = &hello[..hello.len() - 1];
    let mut shift_challenge = vec![hello[hello.len() - 1]];
    shift_challenge.extend_from_slice(&challenge);
    let mut joined_a = hello.clone();
    joined_a.extend_from_slice(&challenge);
    let mut joined_b = shift_hello.to_vec();
    joined_b.extend_from_slice(&shift_challenge);
    assert_eq!(joined_a, joined_b, "контроль собран неверно: потоки обязаны совпасть");
    check(
        &v,
        "k31_handshake_shifted_boundary",
        &oc_crypto::kdf::handshake_transcript(shift_hello, &shift_challenge),
    );
    assert_ne!(
        v["k31_handshake"], v["k31_handshake_shifted_boundary"],
        "длины не вошли в транскрипт: граница кадров неоднозначна"
    );

    // 5. РАЗГОВОР ВХОДИТ В ЭХО. Тот же секрет и тот же отпечаток в разговоре с
    // другим вызовом дают другое эхо — ровно то, ради чего решение принято.
    let mut other_challenge = challenge.clone();
    other_challenge[0] ^= 0x01;
    let other = oc_crypto::kdf::handshake_transcript(&hello, &other_challenge);
    assert_ne!(
        oc_crypto::kdf::echo_transcript(&v["secret_32"], &fpr, &other).as_slice(),
        v["k31_echo_32"].as_slice(),
        "эхо не зависит от вызова: привязки к разговору нет"
    );

    // 6. СТАРАЯ ФОРМА — ДРУГИЕ БАЙТЫ. K23 остаётся в крейте ради своего вектора,
    // и совпасть с K31 она не вправе: совпадение означало бы, что записанное
    // старое эхо по-прежнему годится.
    assert_ne!(
        oc_crypto::kdf::prove_echo(&v["secret_32"], &fpr).as_slice(),
        v["k31_echo_32"].as_slice(),
        "старое эхо совпало с новым"
    );
}

/// Fresh TPM credential values (K30, kinds 3–5), against their own vector.
///
/// Same specification computation as `server_fresh.kat`, with the SAME inputs: with one
/// seed, time, and fingerprint, all five purposes must diverge.
#[test]
fn the_credential_freshness_values_match_their_frozen_vector() {
    let v = load("server_fresh_credential.kat");
    let seed: [u8; 32] = v["seed"].as_slice().try_into().expect("засев не 32 байта");
    let fpr: [u8; 32] = v["device_fpr"].as_slice().try_into().expect("отпечаток не 32 байта");
    let now: i64 = 1_789_862_400;

    // 1. По спеке.
    let by_spec = |kind: u8| {
        spec_hkdf_expand(&spec_k30_prk(&seed, kind, now, &fpr), b"CC/v1/server-fresh", 32)
    };
    check(&v, "k30_credential_secret", &by_spec(3));
    check(&v, "k30_credential_seed", &by_spec(4));
    check(&v, "k30_credential_oaep", &by_spec(5));

    // 2. Функцией крейта, по именам назначений — не по числам: разойдись
    // константа с вектором, проба обязана это увидеть.
    let mut out = [0u8; 32];
    for (name, kind) in [
        ("k30_credential_secret", oc_crypto::kdf::FRESH_CREDENTIAL_SECRET),
        ("k30_credential_seed", oc_crypto::kdf::FRESH_CREDENTIAL_SEED),
        ("k30_credential_oaep", oc_crypto::kdf::FRESH_CREDENTIAL_OAEP),
    ] {
        oc_crypto::kdf::server_fresh(&seed, kind, now, &fpr, &mut out).unwrap();
        check(&v, name, &out);
    }

    // 3. ПЯТЬ НАЗНАЧЕНИЙ — ПЯТЬ ЗНАЧЕНИЙ. Один засев, одно время, один
    // отпечаток: разводит только вид. Совпадение любых двух означало бы, что
    // одно значение годится вместо другого.
    let mut all = Vec::new();
    for kind in 1u8..=5 {
        oc_crypto::kdf::server_fresh(&seed, kind, now, &fpr, &mut out).unwrap();
        all.push(out);
    }
    all.sort_unstable();
    all.dedup();
    assert_eq!(all.len(), 5, "виды не разводят значения");
}
