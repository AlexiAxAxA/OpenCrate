//! MLKEM768-P256: гибрид ML-KEM-768 и ECDH P-256 — механизм слота `kem_id = 5`.
//!
//! Нормативный источник — `draft-irtf-cfrg-concrete-hybrid-kems-03`, §4.1 и A.1.
//! Это ЧЕРНОВИК CFRG, а не завершённый RFC, и так он и назван в решении
//! (`docs/format.md`, версия 4, пункт 1). Доказательство реализуемости и живая
//! проба с настоящим TPM — `spikes/p256-mlkem-tpm/`.
//!
//! # Зачем он рядом с X-Wing, а не вместо
//!
//! X-Wing определён на X25519, а Platform Crypto Provider даёт только ECDH
//! P-256. Пока гибрид был один, приходилось выбирать: либо постквантовая
//! защита, либо ключ, не покидающий TPM. Здесь выбирать не надо — классическая
//! половина ложится в TPM, постквантовая живёт рядом, и противнику нужны ОБЕ:
//! кража диска даёт только вторую, квантовая машина только первую.
//!
//! # Почему не TLS-группа `SecP256r1MLKEM768` (RFC 10024)
//!
//! Потому что её обоснование опирается на транскрипт TLS (§6 того же RFC), и
//! перенести его на самостоятельный KEM внутри файла нельзя. Номер IANA 4587 —
//! это идентификатор группы TLS, а не нашего механизма. Ошибка была записана в
//! спеку и исправлена там же.
//!
//! # Что здесь важно знать читателю кода
//!
//! **Комбинатор свой, и внешний K10 его не подменяет.** Общий секрет считается
//! одним вызовом SHA3-256 над пятью величинами, последняя из которых — метка.
//! Порядок несущий: перестановка даёт другой секрет, ничего не ломая на своей
//! стороне.
//!
//! **Скаляр P-256 берётся ОТБРАКОВКОЙ.** У X25519 законен любой набор из
//! тридцати двух байт, у P-256 — нет: скаляр обязан лежать в порядке группы.
//! Поэтому и семя ключа, и семя инкапсуляции несут запас байтов, из которого
//! берётся первый годный кусок. Без запаса конструкция была бы недетерминированной
//! по числу попыток, а с ним — задана байтами.

use crate::CryptoError;
use crate::agreement::{KeyAgreement, P256Agreement};
use ml_kem::array::{Array, ArrayN};
use ml_kem::{Decapsulate, DecapsulationKey768, EncapsulationKey768, FromSeed, KeyExport};
use ml_kem::{MlKem768, TryKeyInit};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::{Digest, Sha3_256, Shake256};
use zeroize::Zeroizing;

/// Открытая половина на проводе: `pk_M(1184) ‖ pk_P256(65)`.
pub const PUBLIC_KEY_LEN: usize = 1249;

/// Шифротекст на проводе: `ct_M(1088) ‖ eph_P256(65)`.
pub const CIPHERTEXT_LEN: usize = 1153;

/// Общий секрет — выход SHA3-256.
pub const SHARED_LEN: usize = 32;

/// Семя ML-KEM: `d‖z` в понимании `ML-KEM.KeyGen_internal`.
pub const ML_KEM_SEED_LEN: usize = 64;

/// Семя инкапсуляции: 32 байта для ML-KEM и 128 на отбраковку скаляра P-256.
pub const ENCAPS_SEED_LEN: usize = 160;

/// Семя пары целиком — только для векторов и программного пути.
///
/// В поставке пара так НЕ создаётся: половины заводятся врозь, чтобы приватная
/// часть P-256 могла остаться внутри TPM. Общее семя восстанавливало бы
/// аппаратный скаляр программно и тем обесценивало бы неизвлекаемость.
pub const KEYPAIR_SEED_LEN: usize = 32;

const ML_KEM_PUBLIC_LEN: usize = 1184;
const ML_KEM_CIPHERTEXT_LEN: usize = 1088;
const P256_POINT_LEN: usize = 65;
const SCALAR_LEN: usize = 32;
/// Запас на отбраковку: четыре куска по тридцать два байта.
const SCALAR_TRIES_LEN: usize = 128;
/// Семя ML-KEM плюс запас на скаляр. Выражено суммой, а не числом: связь
/// величин здесь и есть смысл раскладки, а `192` её прячет.
const EXPANDED_LEN: usize = ML_KEM_SEED_LEN + SCALAR_TRIES_LEN;

/// Метка конструкции, тринадцать байт ASCII.
const LABEL: &[u8] = b"MLKEM768-P256";

/// Комбинатор (§4.1 черновика).
///
/// Пять величин подряд, метка последней. Порядок задан источником, а не
/// удобством: переставь метку вперёд — и получишь другой секрет при тех же
/// входах, причём молча, как это уже случилось с X-Wing.
fn combine(
    ss_pq: &[u8],
    ss_t: &[u8],
    ct_t: &[u8],
    pk_t: &[u8],
) -> Zeroizing<[u8; SHARED_LEN]> {
    let mut h = Sha3_256::new();
    Digest::update(&mut h, ss_pq);
    Digest::update(&mut h, ss_t);
    Digest::update(&mut h, ct_t);
    Digest::update(&mut h, pk_t);
    Digest::update(&mut h, LABEL);
    Zeroizing::new(h.finalize().into())
}

/// Первый годный скаляр P-256 из запаса байтов.
///
/// Отбраковка, а не приведение по модулю: приведение сместило бы распределение,
/// и это тот дефект, за который ругают самодельные реализации ECDSA. Запас
/// конечен, поэтому исчерпание — отказ, а не бесконечный цикл.
fn scalar_from(bytes: &[u8]) -> Result<P256Agreement, CryptoError> {
    for part in bytes.chunks_exact(SCALAR_LEN) {
        let candidate: [u8; SCALAR_LEN] =
            part.try_into().map_err(|_| CryptoError::BadLength)?;
        if let Ok(pair) = P256Agreement::from_be_bytes(&candidate) {
            return Ok(pair);
        }
    }
    Err(CryptoError::BadKey)
}

/// Пара, выросшая из одного семени.
///
/// Отдельным типом, а не тройкой: три величины разного смысла в кортеже
/// вызывающий различает только по порядку, и перепутать семя ML-KEM с открытой
/// половиной — ошибка, которую компилятор так не поймает.
#[derive(Debug)]
pub struct Keypair {
    /// Семя ML-KEM — `d‖z`.
    pub ml_kem_seed: Zeroizing<[u8; ML_KEM_SEED_LEN]>,
    /// Классическая половина. В поставке её место занимает ключ из TPM.
    pub classical: P256Agreement,
    /// Составная открытая половина, 1249 байт.
    pub public_key: [u8; PUBLIC_KEY_LEN],
}

/// Пара из одного семени — путь векторов и программной стороны.
///
/// # Errors
/// Запас байтов не дал годного скаляра либо длины не сошлись.
pub fn keypair_from_seed(seed: &[u8; KEYPAIR_SEED_LEN]) -> Result<Keypair, CryptoError> {
    let mut xof = Shake256::default();
    Update::update(&mut xof, seed);
    let mut expanded = Zeroizing::new([0u8; EXPANDED_LEN]);
    xof.finalize_xof().read(expanded.as_mut_slice());

    let pq_seed: [u8; ML_KEM_SEED_LEN] = expanded
        .get(..ML_KEM_SEED_LEN)
        .ok_or(CryptoError::BadLength)?
        .try_into()
        .map_err(|_| CryptoError::BadLength)?;
    let pq_seed = Zeroizing::new(pq_seed);
    let classical =
        scalar_from(expanded.get(ML_KEM_SEED_LEN..EXPANDED_LEN).ok_or(CryptoError::BadLength)?)?;

    let public_key = public_key_from_parts(&pq_seed, &classical.public_key())?;
    Ok(Keypair { ml_kem_seed: pq_seed, classical, public_key })
}

/// Семя ML-KEM из тридцати двух хранимых байт.
///
/// ML-KEM требует шестидесяти четырёх (`d‖z`), а ключевые файлы репозитория —
/// тридцать два: на этой длине держатся замок создания, заворачивание DPAPI и
/// перезаворачивание `cc keygen --wrap`. Растяжение SHAKE256 примиряет одно с
/// другим и повторяет приём самого X-Wing (§5.2 его черновика), где `d‖z` тоже
/// вырастает из тридцати двух байт.
///
/// Метки домена здесь НЕТ, и это решение, а не пропуск. Метка разделяет ДВА
/// употребления одного секрета; здесь употребление одно — файл заведён под
/// постквантовую половину и больше ни во что не входит. Пустая метка в реестре
/// §3.6 была бы записью о разделении, которого не существует.
///
/// Хранимые байты обязаны быть СВОИМИ: выводить их из классического семени
/// нельзя — разбор в докстроке `HYBRID_KEY_FILE` крейта `cc-cli`.
#[must_use]
pub fn ml_kem_seed_from_stored(stored: &[u8; 32]) -> Zeroizing<[u8; ML_KEM_SEED_LEN]> {
    let mut xof = Shake256::default();
    Update::update(&mut xof, stored);
    let mut out = Zeroizing::new([0u8; ML_KEM_SEED_LEN]);
    xof.finalize_xof().read(out.as_mut_slice());
    out
}

/// Составная открытая половина из ДВУХ независимых половин.
///
/// Это и есть путь поставки: приватная часть P-256 живёт в TPM и наружу не
/// выходит, поэтому здесь принимается только её ОТКРЫТАЯ точка, а семя ML-KEM —
/// своё, заведённое отдельно.
///
/// # Errors
/// Точка не той длины либо семя не разбирается как ключ ML-KEM.
pub fn public_key_from_parts(
    ml_kem_seed: &[u8; ML_KEM_SEED_LEN],
    p256_public: &[u8],
) -> Result<[u8; PUBLIC_KEY_LEN], CryptoError> {
    if p256_public.len() != P256_POINT_LEN {
        return Err(CryptoError::BadLength);
    }
    let seed = ArrayN::<u8, ML_KEM_SEED_LEN>::try_from(ml_kem_seed.as_slice())
        .map_err(|_| CryptoError::BadLength)?;
    let (_, ek) = MlKem768::from_seed(&seed);

    let mut out = [0u8; PUBLIC_KEY_LEN];
    let (head, tail) = out.split_at_mut(ML_KEM_PUBLIC_LEN);
    head.copy_from_slice(ek.to_bytes().as_slice());
    tail.copy_from_slice(p256_public);
    Ok(out)
}

/// Инкапсуляция по названному семени — путь векторов.
///
/// Отдельно от [`encapsulate`] по той же причине, что у соседей: KAT обязан быть
/// воспроизводим, а генератор в этом крейте запрещён.
///
/// # Errors
/// Открытая половина не той длины, ключ ML-KEM не разбирается либо запас байтов
/// не дал годного эфемерного скаляра.
pub fn encapsulate_derand(
    public_key: &[u8],
    seed: &[u8; ENCAPS_SEED_LEN],
) -> Result<(Zeroizing<[u8; SHARED_LEN]>, [u8; CIPHERTEXT_LEN]), CryptoError> {
    if public_key.len() != PUBLIC_KEY_LEN {
        return Err(CryptoError::BadLength);
    }
    let pk_pq = public_key.get(..ML_KEM_PUBLIC_LEN).ok_or(CryptoError::BadLength)?;
    let pk_t = public_key.get(ML_KEM_PUBLIC_LEN..PUBLIC_KEY_LEN).ok_or(CryptoError::BadLength)?;

    // Ключ ML-KEM разбирается ЗДЕСЬ, а не принимается на веру: открытая половина
    // приходит из подписанного заголовка, но подпись автора не обещает, что
    // байты образуют исполнимый ключ.
    let ek = EncapsulationKey768::new_from_slice(pk_pq).map_err(|_| CryptoError::BadKey)?;
    let m_bytes = seed.get(..SCALAR_LEN).ok_or(CryptoError::BadLength)?;
    let m = ArrayN::<u8, SCALAR_LEN>::try_from(m_bytes).map_err(|_| CryptoError::BadLength)?;
    let (ct_pq, ss_pq) = ek.encapsulate_deterministic(&m);

    let ephemeral =
        scalar_from(seed.get(SCALAR_LEN..ENCAPS_SEED_LEN).ok_or(CryptoError::BadLength)?)?;
    let ct_t = ephemeral.public_key();
    // Точка получателя проверяется на принадлежность кривой внутри `agree` —
    // для P-256 это защита от атаки invalid-curve, а не формальность.
    let ss_t = ephemeral.agree(pk_t)?;

    let shared = combine(&ss_pq, ss_t.expose(), &ct_t, pk_t);

    let mut ciphertext = [0u8; CIPHERTEXT_LEN];
    let (head, tail) = ciphertext.split_at_mut(ML_KEM_CIPHERTEXT_LEN);
    head.copy_from_slice(&ct_pq);
    tail.copy_from_slice(&ct_t);
    Ok((shared, ciphertext))
}

/// Инкапсуляция на открытую половину получателя.
///
/// Генератор приходит параметром — правило крейта. Сто шестьдесят байт берутся
/// ОДНИМ обращением: два подряд сдвинули бы порядок расхода генератора, от
/// которого зависят эталоны.
///
/// # Errors
/// Те же, что у [`encapsulate_derand`].
pub fn encapsulate<R: rand_core::CryptoRng + ?Sized>(
    public_key: &[u8],
    rng: &mut R,
) -> Result<(Zeroizing<[u8; SHARED_LEN]>, [u8; CIPHERTEXT_LEN]), CryptoError> {
    let mut seed = Zeroizing::new([0u8; ENCAPS_SEED_LEN]);
    rng.fill_bytes(seed.as_mut_slice());
    encapsulate_derand(public_key, &seed)
}

/// Декапсуляция ОБЕИМИ половинами, классическая — за трейтом.
///
/// Трейт здесь и есть весь смысл механизма: приватный ключ P-256 может лежать в
/// TPM и не покидать его, и подставляется он сюда вместо программного, не меняя
/// ни байта в выводе секрета.
///
/// Открытая точка берётся У САМОЙ стороны, а не аргументом: она входит в
/// комбинатор, и принятая снаружи сделала бы общий секрет управляемым извне.
///
/// Отказа по «неверному шифротексту» здесь нет и быть не может: ML-KEM отвечает
/// на испорченный шифротекст неявным отказом — выводит секрет из `z` и
/// возвращает его как ни в чём не бывало. Ложность секрета обнаруживает
/// вызывающий: обязательством слота (И-4) и тегом AEAD, оба константным
/// временем. Отвергается только то, что структурно не является входом: чужая
/// длина и точка вне кривой.
///
/// # Errors
/// Шифротекст не той длины, семя ML-KEM не разбирается либо эфемерная точка не
/// лежит на кривой.
pub fn decapsulate_with(
    ml_kem_seed: &[u8; ML_KEM_SEED_LEN],
    classical: &dyn KeyAgreement,
    ciphertext: &[u8],
) -> Result<Zeroizing<[u8; SHARED_LEN]>, CryptoError> {
    // Длина проверяется ДО согласования: считать ECDH ради заведомо негодного
    // входа значит дарить противнику измеримую работу на каждом мусорном байте.
    if ciphertext.len() != CIPHERTEXT_LEN {
        return Err(CryptoError::BadLength);
    }
    let seed = ArrayN::<u8, ML_KEM_SEED_LEN>::try_from(ml_kem_seed.as_slice())
        .map_err(|_| CryptoError::BadLength)?;
    let (dk, _) = MlKem768::from_seed(&seed);

    let ct_pq_bytes = ciphertext.get(..ML_KEM_CIPHERTEXT_LEN).ok_or(CryptoError::BadLength)?;
    let ct_pq = Array::try_from(ct_pq_bytes).map_err(|_| CryptoError::BadLength)?;
    let ct_t = ciphertext.get(ML_KEM_CIPHERTEXT_LEN..CIPHERTEXT_LEN).ok_or(CryptoError::BadLength)?;

    let ss_pq = DecapsulationKey768::decapsulate(&dk, &ct_pq);
    let ss_t = classical.agree(ct_t)?;
    let pk_t = classical.public_key();
    Ok(combine(&ss_pq, ss_t.expose(), ct_t, &pk_t))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// КРУГ ЗАМЫКАЕТСЯ ОБЕИМИ ПОЛОВИНАМИ.
    #[test]
    fn what_is_encapsulated_comes_back_out_of_decapsulation() {
        let pair = keypair_from_seed(&[0x31; KEYPAIR_SEED_LEN]).unwrap();
        let (pq_seed, classical, public) = (pair.ml_kem_seed, pair.classical, pair.public_key);
        let (sent, ciphertext) =
            encapsulate_derand(&public, &[0x5c; ENCAPS_SEED_LEN]).unwrap();
        let received = decapsulate_with(&pq_seed, &classical, &ciphertext).unwrap();
        assert_eq!(sent.as_slice(), received.as_slice(), "секрет не сошёлся с обеих сторон");
    }

    /// ПОДМЕНА ЛЮБОЙ ИЗ ПОЛОВИН НЕ ДАЁТ ТОТ ЖЕ СЕКРЕТ.
    ///
    /// Проба стережёт главное свойство гибрида: он не сводится ни к одной из
    /// половин. Испорченная постквантовая даёт другой секрет неявным отказом
    /// ML-KEM; подменённая классическая — другой ECDH.
    #[test]
    fn substituting_either_half_yields_a_different_secret() {
        let pair = keypair_from_seed(&[0x31; KEYPAIR_SEED_LEN]).unwrap();
        let (pq_seed, classical, public) = (pair.ml_kem_seed, pair.classical, pair.public_key);
        let (sent, ciphertext) =
            encapsulate_derand(&public, &[0x5c; ENCAPS_SEED_LEN]).unwrap();

        // Постквантовая половина.
        let mut broken = ciphertext;
        if let Some(byte) = broken.get_mut(0) {
            *byte ^= 1;
        }
        let got = decapsulate_with(&pq_seed, &classical, &broken).unwrap();
        assert_ne!(got.as_slice(), sent.as_slice(), "порча ML-KEM не повлияла на секрет");

        // Классическая: другая ЗАКОННАЯ точка, а не мусор.
        let other = P256Agreement::from_be_bytes(&[0x42; SCALAR_LEN]).unwrap();
        let mut swapped = ciphertext;
        if let Some(tail) = swapped.get_mut(ML_KEM_CIPHERTEXT_LEN..) {
            tail.copy_from_slice(&other.public_key());
        }
        let got = decapsulate_with(&pq_seed, &classical, &swapped).unwrap();
        assert_ne!(got.as_slice(), sent.as_slice(), "подмена точки не повлияла на секрет");
    }

    /// ТОЧКА ВНЕ КРИВОЙ И ЧУЖАЯ ДЛИНА ОТВЕРГАЮТСЯ, А НЕ МОЛЧА СЧИТАЮТСЯ.
    ///
    /// Это отличие от X-Wing, и оно существенное: у X25519 законна любая
    /// строка, у P-256 точка вне кривой открывает атаку invalid-curve, а
    /// шифротекст приходит из враждебного файла.
    #[test]
    fn an_off_curve_point_and_a_foreign_length_are_refused() {
        let pair = keypair_from_seed(&[0x31; KEYPAIR_SEED_LEN]).unwrap();
        let (pq_seed, classical, public) = (pair.ml_kem_seed, pair.classical, pair.public_key);
        let (_, ciphertext) = encapsulate_derand(&public, &[0x5c; ENCAPS_SEED_LEN]).unwrap();

        let mut zeroed = ciphertext;
        if let Some(tail) = zeroed.get_mut(ML_KEM_CIPHERTEXT_LEN..) {
            tail.fill(0);
        }
        assert!(decapsulate_with(&pq_seed, &classical, &zeroed).is_err(), "нулевая точка принята");
        assert!(
            decapsulate_with(&pq_seed, &classical, ciphertext.get(..1152).unwrap()).is_err(),
            "короткий шифротекст принят"
        );
    }

    /// ДЛИНЫ НА ПРОВОДЕ — ТЕ, ЧТО ОБЕЩАНЫ ФОРМАТОМ.
    #[test]
    fn the_wire_lengths_are_the_ones_the_format_promises() {
        let public = keypair_from_seed(&[0x01; KEYPAIR_SEED_LEN]).unwrap().public_key;
        assert_eq!(public.len(), 1249);
        let (_, ciphertext) = encapsulate_derand(&public, &[0x02; ENCAPS_SEED_LEN]).unwrap();
        assert_eq!(ciphertext.len(), 1153);
    }

    /// МЕТКА ЗАВЕРШАЕТ ВХОД КОМБИНАТОРА, И ЭТО ПРОВЕРЯЕТСЯ.
    ///
    /// Отдельная проба по той же причине, что у X-Wing: там реализация по памяти
    /// уже ставила метку в начало, и ошибка была молчаливой.
    #[test]
    fn the_label_terminates_the_combiner_input() {
        let mut expected = Sha3_256::new();
        Digest::update(&mut expected, [1_u8; 32]);
        Digest::update(&mut expected, [2_u8; 32]);
        Digest::update(&mut expected, [3_u8; 65]);
        Digest::update(&mut expected, [4_u8; 65]);
        Digest::update(&mut expected, b"MLKEM768-P256");
        let expected: [u8; 32] = expected.finalize().into();
        assert_eq!(
            combine(&[1_u8; 32], &[2_u8; 32], &[3_u8; 65], &[4_u8; 65]).as_slice(),
            expected
        );
    }

    /// РАЗДЕЛЬНЫЕ ПОЛОВИНЫ ДАЮТ ТУ ЖЕ ОТКРЫТУЮ ЧАСТЬ, ЧТО И ОБЩЕЕ СЕМЯ.
    ///
    /// Путь поставки — раздельный: P-256 создаётся в TPM, ML-KEM заводится сам
    /// по себе. Проба показывает, что это ТОТ ЖЕ механизм, а не похожий.
    #[test]
    fn parts_assembled_separately_give_the_same_public_half() {
        let pair = keypair_from_seed(&[0x77; KEYPAIR_SEED_LEN]).unwrap();
        let from_parts =
            public_key_from_parts(&pair.ml_kem_seed, &pair.classical.public_key()).unwrap();
        assert_eq!(pair.public_key, from_parts);
    }
}
