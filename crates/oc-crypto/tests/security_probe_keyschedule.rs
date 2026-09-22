// Файл-проба состязательной проверки безопасности. Линтерные запреты рабочего
// кода к пробам не применяются — проба вправе делать то, чего продукт делать не
// должен.
//
// ИСТОРИЯ. Проба была выведена из сборки переименованием в `.rs.txt` и лежала в
// docs/security-review, то есть не компилировалась и не исполнялась. Возвращена
// пунктом Д-13 и переписана: три её находки из пяти с тех пор ИСПРАВЛЕНЫ, и
// прежний текст описывал конструкции, которых больше нет.
//
// Что стало с каждой находкой:
//   1. Повтор nonce обёртки CEK — исправлено: nonce стал храниться, а не
//      выводиться из KEK; номер K2 в таблице производных сожжён. Тест переписан
//      как регрессионный.
//   2. «K2 разворачивает не тот PRK» — исчезло вместе с самим K2.
//   3. Расхождение §3.1 и §3.5 по обязательству слота — исправлено в спеке: обе
//      секции теперь говорят `‖ core_hash`. Тест сторожит это и проверяет, что
//      прежняя формула (`‖ file_id`) НЕ совпадает.
//   4. MIN_CLAIM_BITS не проверяется — ЖИВО. Оставлено как зафиксированное
//      ограничение, см. комментарий у теста.
//   5. K3 и K5 — один тип — исправлено введением `MetaKey`. Перепутать их
//      теперь ошибка компиляции, и тест это фиксирует.
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

/// Детерминированный генератор. Воспроизводимость важнее стойкости: проба
/// обязана падать одинаково на любой машине.
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

/// ДЕФЕКТ (исправлен): nonce обёртки выводился из KEK, поэтому два разных CEK,
/// завёрнутых под одним KEK, получали один поток ключей. Тогда
/// `wrapped₁ ⊕ wrapped₂ = CEK₁ ⊕ CEK₂`: легальный получатель первого файла
/// восстанавливал ключ содержимого второго, не зная ни одного приватного ключа.
/// Переупаковка и ротация ключа содержимого — обычные операции, ничто в API не
/// мешало вызвать `wrap_cek` дважды с одним KEK.
///
/// Исправлено хранимым случайным nonce (§3.1); номер K2, принадлежавший
/// выведенному nonce, сожжён и не переиспользуется. Тест оставлен регрессионным:
/// он проверяет именно XOR-соотношение, а не «nonce различаются», — потому что
/// сломать это можно и не возвращая вывод nonce.
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

/// ДЕФЕКТ (исправлен): §3.1 и §3.5 задавали РАЗНЫЕ сообщения HMAC для
/// обязательства слота — `‖ file_id` и `‖ core_hash`. Обе формулы лежали в одном
/// документе-контракте, и вторая реализация формата вправе была прочитать любую;
/// разошлись бы стороны молча — обёртка просто перестала бы открываться, и это
/// выглядело бы как повреждение файла.
///
/// Сейчас обе секции говорят `‖ core_hash`, и привязка строго сильнее: хеш ядра
/// уже содержит `file_id` и ломается при подмене любого другого подписанного
/// поля.
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

/// Кодировка PIN в 32 байта: ASCII, остальное — нули.
fn claim_from_pin(pin: u32) -> ClaimSecret {
    let text = format!("{pin:04}");
    let mut bytes = [0u8; 32];
    bytes[..text.len()].copy_from_slice(text.as_bytes());
    ClaimSecret::from_bytes(bytes)
}

/// ИЗВЕСТНОЕ ОГРАНИЧЕНИЕ, зафиксированное тестом, а не спрятанное.
///
/// `MIN_CLAIM_BITS = 128` объявлена единственной защитой кода-претензии от
/// оракула разбиения — и никакой тип её не держит: `ClaimSecret::from_bytes`
/// принимает любые 32 байта. Обязательство слота лежит в контейнере открытым
/// текстом и работает оффлайн-оракулом: противник, знающий долю сервера
/// (скомпрометированный сервер лицензий с копией контейнера), перебирает
/// четырёхзначный код за десять тысяч попыток по несколько HMAC каждая, не
/// обращаясь к сети. По замыслу §3.4 доли сервера для этого недостаточно.
///
/// Сегодня продукт в эту дыру не проваливается, но не потому, что она закрыта.
/// Код-претензия выпускается (`cc protect --claim`), слот `RecipientClaim`
/// производится и открывается, `secret_b_from_claim` вызывается из
/// `cc_cli::container` — Ф-3 закрыт. Граница держится ОДНИМ местом:
/// `cc_cli::claim` порождает ровно 30 символов пятибитного алфавита, то есть
/// 150 бит, и это закреплено `const _: () = assert!(...)` — короткий код там не
/// упадёт в тесте, а не скомпилируется.
///
/// Ниже уровнем границы по-прежнему нет: `ClaimSecret::from_bytes` принимает
/// любые 32 байта и обязан — к этому моменту код уже сжат хешем, и энтропии в
/// результате не видно. Поэтому тест и оставлен: он показывает, во что обойдётся
/// второй способ породить `ClaimSecret` в обход `cc_cli::claim` — код,
/// придуманный человеком, код из чужого поля, код из будущего API. Этот тест
/// обязан упасть, когда такой способ появится, а `MIN_CLAIM_BITS` перестанет
/// проверяться на сборке.
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

/// ДЕФЕКТ (исправлен): K3 и K5 возвращали один тип `PayloadKey`, и ключ
/// приватных метаданных молча принимался на месте ключа полезной нагрузки —
/// вопреки обещанию `secret.rs`, что перепутать их «становится ошибкой
/// компиляции».
///
/// Исправлено введением `MetaKey`. Проверить это тестом в обычном смысле нельзя:
/// код, который проба ловила, теперь просто не компилируется. Поэтому тест
/// фиксирует наблюдаемую часть — что производные дают разные значения, — а
/// невозможность перепутать держится типами и закреплена здесь комментарием:
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
