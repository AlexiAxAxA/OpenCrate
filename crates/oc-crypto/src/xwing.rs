//! X-Wing: гибрид X25519 и ML-KEM-768 — механизм слота `kem_id = 4`.
//!
//! Нормативный источник — `draft-connolly-cfrg-xwing-kem-10` (2 марта 2026),
//! §5.2–5.5; решение о выборе именно этого построения и его обоснование —
//! `docs/format.md`, «ВЕРСИЯ 3 ОТКРЫТА», пункт 1 (сам пункт живёт в версии 4).
//! Замеры, на которых решение стоит, — `spikes/ml-kem-cost/`.
//!
//! # Что здесь важно знать читателю кода
//!
//! **Приватная половина — 32 байта, а не 2400.** Обе пары растут из одного
//! семени через SHAKE256, поэтому `device.key` остаётся файлом в тридцать два
//! байта, каким он был до гибрида. Это свойство конструкции, а не наша
//! оптимизация, и терять его нельзя: храня развёрнутый ключ ML-KEM, мы завели бы
//! второй формат ключевого файла.
//!
//! **Метка комбинатора идёт ПОСЛЕДНЕЙ.** Написанная по памяти реализация ставила
//! её в начало — и это молчаливая ошибка: две стороны, ошибшиеся одинаково,
//! сходятся между собой и расходятся со всем остальным миром. Поймано векторами
//! черновика (`tests/kat/xwing.kat`), а не рассуждением.
//!
//! **Гибрид адресуется X25519, то есть ПРОГРАММНОМУ ключу.** Ключ в TPM — P-256,
//! и X-Wing на нём не определён. Постквантовая защита и аппаратная привязка
//! получателя сегодня взаимоисключающи; разбор — `docs/threat-model.md` §2.

use crate::CryptoError;
use ml_kem::array::{Array, ArrayN};
use ml_kem::{Decapsulate, DecapsulationKey768, EncapsulationKey768, FromSeed, KeyExport};
use ml_kem::{MlKem768, TryKeyInit};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Sha3_256, Shake256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Семя приватной половины: из него растут ОБЕ пары.
pub const SECRET_LEN: usize = 32;

/// Открытая половина на проводе: `pk_M(1184) ‖ pk_X(32)`.
pub const PUBLIC_KEY_LEN: usize = 1216;

/// Шифротекст на проводе: `ct_M(1088) ‖ ct_X(32)`.
pub const CIPHERTEXT_LEN: usize = 1120;

/// Общий секрет — выход SHA3-256.
pub const SHARED_LEN: usize = 32;

/// Семя инкапсуляции: `m(32)` для ML-KEM и `ek_X(32)` для X25519.
pub const ENCAPS_SEED_LEN: usize = 64;

const ML_KEM_PUBLIC_LEN: usize = 1184;
const ML_KEM_CIPHERTEXT_LEN: usize = 1088;
const EXPANDED_LEN: usize = 96;

/// Шесть байт ASCII: `\./` и `/^\`.
///
/// Записана байтами, а не строковым литералом, и это не педантизм: в литерале
/// обратная косая черта требует экранирования, и `"\./"` в Rust не то, чем
/// выглядит. Значение из черновика прямо: `5c2e2f2f5e5c`.
const XWING_LABEL: [u8; 6] = [0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c];

/// Комбинатор X-Wing (§5.3 черновика).
///
/// Не HKDF и не HMAC — один вызов SHA3-256, и это решение черновика, а не наше
/// упрощение: с губкой SHA3 конструкция на HMAC не нужна.
///
/// Порядок входов несущий, и метка ЗАВЕРШАЕТ его. Перестановка даёт другой
/// секрет при тех же величинах, ничего при этом не ломая на своей стороне.
fn combiner(ss_m: &[u8], ss_x: &[u8], ct_x: &[u8], pk_x: &[u8]) -> Zeroizing<[u8; SHARED_LEN]> {
    let mut h = Sha3_256::new();
    Digest::update(&mut h, ss_m);
    Digest::update(&mut h, ss_x);
    Digest::update(&mut h, ct_x);
    Digest::update(&mut h, pk_x);
    Digest::update(&mut h, XWING_LABEL);
    Zeroizing::new(h.finalize().into())
}

/// Развёрнутая приватная половина. Наружу не выходит: обе пары выводятся из
/// семени заново при каждом употреблении.
///
/// Черновик разрешает кешировать разворачивание (§5.5.1), и мы этого НЕ делаем.
/// Причина не в скорости: развёрнутый ключ — это 2400 байт секрета, живущих
/// столько, сколько живёт кеш, тогда как семя в тридцать два байта затирается
/// сразу. Цена — одно разворачивание на открытие файла, порядка сорока
/// микросекунд (замер в `spikes/ml-kem-cost/`), то есть незаметная.
struct Expanded {
    ml_kem: DecapsulationKey768,
    x25519: StaticSecret,
    ml_kem_public: [u8; ML_KEM_PUBLIC_LEN],
    x25519_public: [u8; 32],
}

/// `expandDecapsulationKey(sk)` — §5.2 черновика.
fn expand(secret: &[u8; SECRET_LEN]) -> Result<Expanded, CryptoError> {
    let mut xof = Shake256::default();
    Update::update(&mut xof, secret);
    let mut expanded = Zeroizing::new([0u8; EXPANDED_LEN]);
    xof.finalize_xof().read(expanded.as_mut_slice());

    // Первые 64 байта — это ровно `(d, z)` из `ML-KEM.KeyGen_internal`, то есть
    // семя в понимании `ml_kem::FromSeed`. Резать их на две половины и склеивать
    // обратно незачем.
    let seed_bytes = expanded.get(..64).ok_or(CryptoError::BadLength)?;
    let seed = ArrayN::<u8, 64>::try_from(seed_bytes).map_err(|_| CryptoError::BadLength)?;
    let (ml_kem, ml_kem_ek) = MlKem768::from_seed(&seed);

    let x_bytes: [u8; 32] = expanded
        .get(64..EXPANDED_LEN)
        .ok_or(CryptoError::BadLength)?
        .try_into()
        .map_err(|_| CryptoError::BadLength)?;
    let x25519 = StaticSecret::from(x_bytes);
    let x25519_public = PublicKey::from(&x25519).to_bytes();

    let ml_kem_public: [u8; ML_KEM_PUBLIC_LEN] =
        ml_kem_ek.to_bytes().as_slice().try_into().map_err(|_| CryptoError::BadLength)?;

    Ok(Expanded { ml_kem, x25519, ml_kem_public, x25519_public })
}

/// Открытая половина по семени: `pk_M ‖ pk_X`, 1216 байт.
///
/// # Errors
/// Только на несоответствии длин, которого при исправной библиотеке не бывает;
/// проверки оставлены потому, что паниковать этому крейту запрещено.
pub fn public_key(secret: &[u8; SECRET_LEN]) -> Result<[u8; PUBLIC_KEY_LEN], CryptoError> {
    let expanded = expand(secret)?;
    let mut out = [0u8; PUBLIC_KEY_LEN];
    let (head, tail) = out.split_at_mut(ML_KEM_PUBLIC_LEN);
    head.copy_from_slice(&expanded.ml_kem_public);
    tail.copy_from_slice(&expanded.x25519_public);
    Ok(out)
}

/// Инкапсуляция по названному семени — `EncapsulateDerand` (§5.4.1 черновика).
///
/// Отдельно от [`encapsulate`] по той же причине, по какой у соседей отдельно
/// живёт всё детерминированное: KAT обязан быть воспроизводим, а генератор в
/// этом крейте запрещён.
///
/// # Errors
/// Открытая половина не той длины либо не разбирается как ключ ML-KEM.
pub fn encapsulate_derand(
    public_key: &[u8],
    seed: &[u8; ENCAPS_SEED_LEN],
) -> Result<(Zeroizing<[u8; SHARED_LEN]>, [u8; CIPHERTEXT_LEN]), CryptoError> {
    if public_key.len() != PUBLIC_KEY_LEN {
        return Err(CryptoError::BadLength);
    }
    let pk_m = public_key.get(..ML_KEM_PUBLIC_LEN).ok_or(CryptoError::BadLength)?;
    let pk_x: [u8; 32] = public_key
        .get(ML_KEM_PUBLIC_LEN..PUBLIC_KEY_LEN)
        .ok_or(CryptoError::BadLength)?
        .try_into()
        .map_err(|_| CryptoError::BadLength)?;

    // Эфемерная половина X25519. Первые 32 байта семени уходят в ML-KEM, вторые
    // сюда — порядок задан черновиком, а не удобством.
    let ek_x_bytes: [u8; 32] =
        seed.get(32..ENCAPS_SEED_LEN).ok_or(CryptoError::BadLength)?.try_into().map_err(|_| CryptoError::BadLength)?;
    let ek_x = StaticSecret::from(ek_x_bytes);
    let ct_x = PublicKey::from(&ek_x).to_bytes();
    let ss_x = ek_x.diffie_hellman(&PublicKey::from(pk_x));

    let m_bytes = seed.get(..32).ok_or(CryptoError::BadLength)?;
    let m = ArrayN::<u8, 32>::try_from(m_bytes).map_err(|_| CryptoError::BadLength)?;
    // Ключ ML-KEM разбирается ЗДЕСЬ, а не принимается на веру: `public_key`
    // приходит из подписанного заголовка, но подпись автора не обещает, что
    // байты образуют исполнимый ключ.
    let ek_m =
        EncapsulationKey768::new_from_slice(pk_m).map_err(|_| CryptoError::BadKey)?;
    let (ct_m, ss_m) = ek_m.encapsulate_deterministic(&m);

    let shared = combiner(&ss_m, ss_x.as_bytes(), &ct_x, &pk_x);

    let mut ciphertext = [0u8; CIPHERTEXT_LEN];
    let (head, tail) = ciphertext.split_at_mut(ML_KEM_CIPHERTEXT_LEN);
    head.copy_from_slice(&ct_m);
    tail.copy_from_slice(&ct_x);
    Ok((shared, ciphertext))
}

/// Инкапсуляция на открытую половину получателя.
///
/// Генератор приходит параметром — правило крейта. Шестьдесят четыре байта
/// берутся ОДНИМ обращением: два подряд сдвинули бы порядок расхода генератора,
/// от которого зависят эталоны (тот же довод, что у `seal::seal_p256`).
///
/// # Errors
/// Открытая половина не той длины либо не разбирается как ключ ML-KEM.
pub fn encapsulate<R: rand_core::CryptoRng + ?Sized>(
    public_key: &[u8],
    rng: &mut R,
) -> Result<(Zeroizing<[u8; SHARED_LEN]>, [u8; CIPHERTEXT_LEN]), CryptoError> {
    let mut seed = Zeroizing::new([0u8; ENCAPS_SEED_LEN]);
    rng.fill_bytes(seed.as_mut_slice());
    encapsulate_derand(public_key, &seed)
}

/// Декапсуляция — §5.5 черновика.
///
/// Отказа по «неверному шифротексту» здесь нет и быть не может: ML-KEM на
/// испорченном шифротексте отвечает НЕЯВНЫМ ОТКАЗОМ — выводит секрет из `z` и
/// возвращает его как ни в чём не бывало. Это свойство схемы, а не недосмотр:
/// различимый отказ был бы оракулом. Ложность секрета обнаруживает вызывающий —
/// обязательством слота (И-4) и тегом AEAD, оба константным временем.
///
/// # Errors
/// Шифротекст не той длины. Всё остальное — молча другой секрет.
pub fn decapsulate(
    secret: &[u8; SECRET_LEN],
    ciphertext: &[u8],
) -> Result<Zeroizing<[u8; SHARED_LEN]>, CryptoError> {
    if ciphertext.len() != CIPHERTEXT_LEN {
        return Err(CryptoError::BadLength);
    }
    let expanded = expand(secret)?;

    let ct_m_bytes = ciphertext.get(..ML_KEM_CIPHERTEXT_LEN).ok_or(CryptoError::BadLength)?;
    let ct_m = Array::try_from(ct_m_bytes).map_err(|_| CryptoError::BadLength)?;
    let ct_x: [u8; 32] = ciphertext
        .get(ML_KEM_CIPHERTEXT_LEN..CIPHERTEXT_LEN)
        .ok_or(CryptoError::BadLength)?
        .try_into()
        .map_err(|_| CryptoError::BadLength)?;

    let ss_m = expanded.ml_kem.decapsulate(&ct_m);
    let ss_x = expanded.x25519.diffie_hellman(&PublicKey::from(ct_x));
    Ok(combiner(&ss_m, ss_x.as_bytes(), &ct_x, &expanded.x25519_public))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// КРУГ ЗАМЫКАЕТСЯ: что запечатано инкапсуляцией, то же выходит декапсуляцией.
    #[test]
    fn what_is_encapsulated_comes_back_out_of_decapsulation() {
        let secret = [0x3a_u8; SECRET_LEN];
        let public = public_key(&secret).unwrap();
        let (sent, ciphertext) = encapsulate_derand(&public, &[0x5c_u8; ENCAPS_SEED_LEN]).unwrap();
        let received = decapsulate(&secret, &ciphertext).unwrap();
        assert_eq!(sent.as_slice(), received.as_slice(), "секрет не сошёлся с обеих сторон");
    }

    /// ИСПОРЧЕННЫЙ ШИФРОТЕКСТ ДАЁТ ДРУГОЙ СЕКРЕТ, А НЕ ОТКАЗ.
    ///
    /// Проба стережёт именно это свойство. Появись здесь отказ — значит кто-то
    /// добавил различимую ветвь по враждебным байтам, то есть оракул.
    #[test]
    fn a_corrupted_ciphertext_yields_a_different_secret_rather_than_an_error() {
        let secret = [0x3a_u8; SECRET_LEN];
        let public = public_key(&secret).unwrap();
        let (sent, mut ciphertext) =
            encapsulate_derand(&public, &[0x5c_u8; ENCAPS_SEED_LEN]).unwrap();

        for spot in [0_usize, 1087, 1088, 1119] {
            let mut broken = ciphertext;
            if let Some(byte) = broken.get_mut(spot) {
                *byte ^= 1;
            }
            let received = decapsulate(&secret, &broken).expect("отказ вместо неявного");
            assert_ne!(sent.as_slice(), received.as_slice(), "байт {spot} не повлиял на секрет");
        }

        // И обратное: нетронутый шифротекст по-прежнему сходится.
        ciphertext[0] ^= 0;
        assert_eq!(decapsulate(&secret, &ciphertext).unwrap().as_slice(), sent.as_slice());
    }

    /// ДЛИНЫ НА ПРОВОДЕ — ТЕ, ЧТО ОБЕЩАНЫ ФОРМАТОМ.
    ///
    /// Тут стоит не «проверить арифметику», а поймать смену глубины ML-KEM:
    /// 1024 дал бы другие числа, а формат задаёт длину как функцию пары
    /// (версия, `kem_id`) — менять её у занятого номера нельзя.
    #[test]
    fn the_wire_lengths_are_the_ones_the_format_promises() {
        let secret = [0x01_u8; SECRET_LEN];
        let public = public_key(&secret).unwrap();
        assert_eq!(public.len(), 1216);
        let (_, ciphertext) = encapsulate_derand(&public, &[0x02_u8; ENCAPS_SEED_LEN]).unwrap();
        assert_eq!(ciphertext.len(), 1120);
    }

    /// ЧУЖАЯ ДЛИНА ОТВЕРГАЕТСЯ ДО ВСЯКОЙ РАБОТЫ.
    #[test]
    fn foreign_lengths_are_refused_before_any_work() {
        let secret = [0x01_u8; SECRET_LEN];
        assert!(encapsulate_derand(&[0u8; 1215], &[0u8; ENCAPS_SEED_LEN]).is_err());
        assert!(encapsulate_derand(&[0u8; 1217], &[0u8; ENCAPS_SEED_LEN]).is_err());
        assert!(decapsulate(&secret, &[0u8; 1119]).is_err());
        assert!(decapsulate(&secret, &[0u8; 1121]).is_err());
    }

    /// МЕТКА СТОИТ В КОНЦЕ, И ЭТО ПРОВЕРЯЕТСЯ, А НЕ ПОДРАЗУМЕВАЕТСЯ.
    ///
    /// Отдельная проба, потому что ошибка была настоящей: реализация по памяти
    /// ставила метку в начало. Здесь комбинатор сверяется с независимым счётом
    /// того же хеша — если кто-нибудь переставит входы, разойдётся именно тут, а
    /// не через год у второй реализации.
    #[test]
    fn the_label_terminates_the_combiner_input() {
        let (ss_m, ss_x, ct_x, pk_x) = ([1_u8; 32], [2_u8; 32], [3_u8; 32], [4_u8; 32]);
        let mut expected = Sha3_256::new();
        Digest::update(&mut expected, [1_u8; 32]);
        Digest::update(&mut expected, [2_u8; 32]);
        Digest::update(&mut expected, [3_u8; 32]);
        Digest::update(&mut expected, [4_u8; 32]);
        Digest::update(&mut expected, [0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c]);
        let expected: [u8; 32] = expected.finalize().into();
        assert_eq!(combiner(&ss_m, &ss_x, &ct_x, &pk_x).as_slice(), expected);
    }
}
