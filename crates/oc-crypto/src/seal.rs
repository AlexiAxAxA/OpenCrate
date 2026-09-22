//! Запечатывание секретов на публичный ключ получателя слота.
//!
//! Конструкция — Base-режим DHKEM(X25519, HKDF-SHA256) с AEAD
//! XChaCha20-Poly1305, по образцу RFC 9180. Готовый крейт HPKE не используется
//! сознательно: он потянул бы вторую версию curve25519-dalek и несовместимый по
//! трейтам генератор, а путь через TPM в фазе 1 всё равно требует собственной
//! абстракции согласования ключей — Microsoft Platform Crypto Provider не даёт
//! X25519, и приватный ключ оттуда невозможно передать в чужой код.
//!
//! **Это рукописная конструкция, и она первый кандидат на внешнюю проверку.**
//!
//! В вывод ключа входят оба публичных ключа — эфемерный и получателя. Без этого
//! возможна привязка одного и того же шифротекста к чужой личности.

use crate::{CryptoError, KemAlg};
use crate::label::Label;
use crate::secret::X25519Secret;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305};
use hkdf::Hkdf;
use rand_core::CryptoRng;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

/// Длина публичного ключа X25519.
pub const PUBLIC_KEY_LEN: usize = 32;

/// KEM, которым эта сборка запечатывает по умолчанию.
///
/// Раньше константа звалась `DEFAULT_SEALING_KEM` и это было верно: исполнялся ровно
/// один механизм. С версией 2 формата исполняются два, и прежнее имя стало
/// утверждать неправду — а на вопрос «умеем ли» отвечает [`supports_kem`], а не
/// константа. Переименование здесь не косметическое: имя, переросшее свой смысл,
/// опаснее отсутствующего.
///
/// Умолчание — X25519, и оно остаётся им сознательно. P-256 нужен там, где ключ
/// живёт в TPM: провайдер не даёт X25519. Выбирать P-256 без этой причины значило
/// бы платить 65 байтами на слот и более медленной кривой ни за что.
pub const DEFAULT_SEALING_KEM: KemAlg = KemAlg::X25519HkdfSha256;

/// Умеет ли эта сборка открыть слот объявленным механизмом.
///
/// Без этой проверки идентификатор KEM в слоте не управляет ничем: слот,
/// переразмеченный с X25519 на P-256, открывался бы всё тем же X25519 — то есть
/// объявление алгоритма было бы украшением. Тот же класс дефекта, из-за которого
/// в JWS появилось `alg: none`.
///
/// Спецификация (§3.3) обещает сосуществование слотов с разными KEM в одном
/// файле, поэтому неизвестный KEM — не отказ читать файл целиком, а повод
/// пропустить конкретный слот: другой слот того же файла может быть открываем.
/// Решение «пропустить или отвергнуть» принимает вызывающий, здесь только ответ
/// «умеем или нет».
///
/// `match` намеренно без `_`: добавление члена в [`KemAlg`] обязано ломать
/// сборку здесь, рядом с реализацией, а не проходить молча. Ровно поэтому
/// таблица живёт тут, а не на самом типе: реализации запечатывания и открытия —
/// соседние функции этого файла.
///
/// Это ЕДИНСТВЕННЫЙ ответ на вопрос «исполним ли механизм» во всём
/// репозитории; [`KemAlg::ensure_supported`] — та же таблица в форме `Result`,
/// а не второе мнение. Таблицы длин (`oc_format::header`, [`crate::kdf`])
/// отвечают на ДРУГОЙ вопрос — «какой формы поля», — и согласованность их
/// пробелов с этой таблицей держится пробой, а не памятью.
pub fn supports_kem(kem: KemAlg) -> bool {
    match kem {
        KemAlg::X25519HkdfSha256 => true,
        // P-256 исполняется с версии 2 формата: Microsoft Platform Crypto
        // Provider не даёт X25519, поэтому ключ, живущий в TPM, обязан быть
        // P-256. Согласование идёт за трейтом [`crate::agreement::KeyAgreement`],
        // и аппаратная реализация подставляется вместо программной, не меняя
        // ничего в выводе ключа.
        KemAlg::P256HkdfSha256 => true,
        // RSA-OAEP: номер в реестре занят, формы полей не задаёт ни одна версия
        // формата, механизм не исполняется. Слот с ним пропускается.
        KemAlg::RsaOaepSha256 => false,
        // Гибрид X-Wing исполняется с версии 4 формата. Здесь ответ «умеем» без
        // оговорки о версии намеренно: версию знает разбор заголовка, и таблица
        // длин в `oc_format` уже отвергает четвёртый номер у версий 1–3. Две
        // проверки версии в двух крейтах разошлись бы — а расходятся такие пары
        // всегда в сторону «слот открылся там, где не должен был».
        KemAlg::XWing => true,
        // Аппаратный гибрид исполняется с версии 5. Оговорки о версии здесь нет
        // по той же причине, что у четвёртого: версию знает разбор заголовка, и
        // таблица длин в `oc_format` уже отвергает пятый номер у версий 1–4.
        // Две проверки версии в двух крейтах разошлись бы, а расходятся такие
        // пары всегда в сторону «слот открылся там, где не должен был».
        KemAlg::MlKem768P256 => true,
    }
}

/// Собрать `info` запечатывания слота.
///
/// Одна функция на обе стороны, а не две одинаковые: писательская и
/// читательская сборки, разойдясь хоть на байт, дали бы файл, который наш же
/// упаковщик запечатал, а наш распаковщик не открыл, — и причину пришлось бы
/// искать сравнением байтов.
///
/// Идентификатор KEM входит в `info` и потому в вывод ключа. Без этого §3.3
/// обещает сосуществование слотов с разными механизмами, а криптография этого
/// обещания не подкрепляет: переразметив слот другим `kem_id`, противник получал
/// бы ровно тот же ключ. RFC 9180 закрывает то же самое своим `suite_id`, и по
/// той же причине — как только механизмов становится больше одного, их
/// смешение обязано быть невозможным, а не просто нежелательным.
///
/// Назначение приходит типом [`Label`], а не байтами: слоты различаются именно
/// им, и строка, сочинённая мимо реестра, завела бы четвёртый вид слота, о
/// котором не знает ни спека §3.6, ни одна проба И-12.
pub fn slot_info(purpose: Label, kem: KemAlg, file_id: &[u8; 16]) -> Vec<u8> {
    let purpose = purpose.as_bytes();
    let mut info = Vec::with_capacity(purpose.len().saturating_add(17));
    info.extend_from_slice(purpose);
    // Один байт фиксированной ширины между меткой и `file_id`: длина всех трёх
    // частей известна, поэтому конкатенация однозначна и разделители не нужны.
    info.push(kem as u8);
    info.extend_from_slice(file_id);
    info
}

/// `info` производной K11: сервер → устройство (`docs/format.md` §3.5).
///
/// ```text
/// info = "CC/v1/a-to-device" ‖ u8(kem_id) ‖ file_id(16) ‖ device_fpr(32) ‖ u64be(seq)
/// ```
///
/// # Почему в ядре, хотя это сообщение сервера
///
/// По той же причине, что и [`slot_info`]: байты собирают ДВОЕ — сервер, который
/// печатает долю, и устройство, которое её разворачивает. До переноса функция
/// стояла дословной копией в `cc-authority` и `cc-cli`, и каждая копия
/// объясняла, почему копия допустима: клиент не вправе зависеть от сервера.
/// Довод верен и остаётся в силе, неверен был вывод из него — общая зависимость
/// снимается ЯДРОМ, от которого зависят обе стороны, а не вторым экземпляром
/// нормативных байтов.
///
/// Цена расхождения копий названа точно: другой `info` даёт другой ключ, и
/// выглядит это как «доля не разворачивается» — то есть как поломка крипты там,
/// где поломки нет.
///
/// Номер лизинга идёт `u64be`, а не `u64le`: порядок заморожен вектором K11.
#[must_use]
pub fn a_to_device_info(
    kem: KemAlg,
    file_id: &[u8; 16],
    device_fpr: &[u8; 32],
    seq: u64,
) -> Vec<u8> {
    let mut info = Vec::with_capacity(64);
    info.extend_from_slice(crate::label::A_TO_DEVICE.as_bytes());
    info.push(kem as u8);
    info.extend_from_slice(file_id);
    info.extend_from_slice(device_fpr);
    info.extend_from_slice(&seq.to_be_bytes());
    info
}

/// `info` производной K21: автор → устройство просителя (`docs/format.md`,
/// «Запрос доступа»).
///
/// ```text
/// info = "CC/v1/b-to-device" ‖ u8(kem_id) ‖ file_id(16) ‖ device_fpr(32)
/// ```
///
/// Номера лизинга здесь НЕТ, и это не забывчивость: доля A выдаётся под правила
/// и живёт от выдачи до выдачи, доля B выдаётся человеку раз и переживает любое
/// продление. Номер в `info` привязал бы её к одному лизингу.
///
/// В ядре по тому же доводу, что [`a_to_device_info`]: собирают эти байты
/// ДВОЕ — автор, который печатает долю, и устройство, которое открывает.
#[must_use]
pub fn b_to_device_info(kem: KemAlg, file_id: &[u8; 16], device_fpr: &[u8; 32]) -> Vec<u8> {
    let mut info =
        Vec::with_capacity(crate::label::B_TO_DEVICE.len().saturating_add(49));
    info.extend_from_slice(crate::label::B_TO_DEVICE.as_bytes());
    info.push(kem as u8);
    info.extend_from_slice(file_id);
    info.extend_from_slice(device_fpr);
    info
}

/// `info` вызова аттестации: метка домена и отпечаток устройства.
///
/// ```text
/// info = "CC/v1/attest-nonce" ‖ device_fpr(32)
/// ```
///
/// Отпечаток входит в `info`, а не только в AAD, чтобы вызов, выданный одному
/// устройству, не открывался ключом другого при совпавшем ключе согласования.
///
/// Механизма в `info` НЕТ, в отличие от долей A и B. Это не пропуск, а
/// замороженная форма рукопожатия: вызов открывается обеими половинами
/// гибридного ключа подряд, и обе используют один `info`. Добавить сюда
/// `kem_id` значило бы сменить байты на проводе.
///
/// В ядре потому же: собирают их ДВОЕ — сервер, который печатает вызов, и
/// устройство, которое его открывает. Руками эта строка складывалась трижды.
#[must_use]
pub fn challenge_info(device_fpr: &[u8; 32]) -> Vec<u8> {
    let mut info = Vec::with_capacity(crate::label::ATTEST_NONCE.len().saturating_add(32));
    info.extend_from_slice(crate::label::ATTEST_NONCE.as_bytes());
    info.extend_from_slice(device_fpr);
    info
}

/// Длина nonce XChaCha20-Poly1305.
const NONCE_LEN: usize = 24;

/// Длина тега Poly1305. Шифротекст короче тега структурно невозможен.
const TAG_LEN: usize = 16;

/// Длина общего секрета X25519 и выводимого ключа AEAD.
const SHARED_LEN: usize = 32;

/// Запечатанный секрет: эфемерный публичный ключ, nonce и шифротекст с тегом.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedBlob {
    /// Эфемерный публичный ключ отправителя.
    ///
    /// Переменной длины: у X25519 это 32 байта, у P-256 — 65. Массив
    /// фиксированной длины стоял здесь до версии 2 формата и делал слот на
    /// P-256 невыразимым. Функция [`open`] проверяет длину точно и до всякой
    /// крипты — переменная длина в типе не означает, что длина не проверяется.
    pub enc: Vec<u8>,
    /// Nonce AEAD.
    ///
    /// **Хранится, а не выводится** — то же правило, что и для чанков полезной
    /// нагрузки (§6.1 спецификации), и по той же причине, только последствия
    /// здесь тяжелее.
    ///
    /// Выведенный из общего PRK nonce целиком определялся бы эфемерной парой, а
    /// значит совпадал бы вместе с ней. Повтор состояния генератора — откат
    /// снапшота виртуальной машины, клон образа диска, восстановление из
    /// резервной копии — давал бы два блоба с одинаковыми ключом и nonce, то
    /// есть с одним потоком ключей. Тогда `ct₁ ⊕ ct₂ = pt₁ ⊕ pt₂`, а открытые
    /// тексты здесь — это доли секрета: из `secret_A` и `secret_A‖secret_B`
    /// восстанавливается `secret_B`, из них обоих KEK, из KEK ключ содержимого.
    /// Полный обход защиты без единого приватного ключа. Двадцать четыре байта
    /// рядом с уже хранимыми тридцатью двумя закрывают это целиком: ключ при
    /// повторе совпадёт, поток ключей — нет.
    pub nonce: [u8; NONCE_LEN],
    /// Шифротекст с приписанным тегом.
    pub ct: Vec<u8>,
}

/// Публичный ключ из приватного.
pub fn x25519_public(secret: &X25519Secret) -> [u8; PUBLIC_KEY_LEN] {
    // `StaticSecret` сам зажимает скаляр при использовании, поэтому произвольные
    // 32 байта из генератора — корректный приватный ключ, и отдельная проверка
    // формы здесь не нужна.
    let sk = StaticSecret::from(*secret.expose());
    PublicKey::from(&sk).to_bytes()
}

/// Запечатать на публичный ключ.
///
/// `info` разделяет назначение слота, `aad` привязывает к контексту файла —
/// обычно к хешу политики, чтобы шифротекст нельзя было перенести в контейнер с
/// другими правилами.
pub fn seal<R: CryptoRng + ?Sized>(
    recipient_public: &[u8; PUBLIC_KEY_LEN],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    rng: &mut R,
) -> Result<SealedBlob, CryptoError> {
    // Эфемерная пара на каждый вызов даёт уникальность ключа AEAD.
    let mut eph_bytes = Zeroizing::new([0u8; SHARED_LEN]);
    rng.fill_bytes(eph_bytes.as_mut_slice());
    let eph_sk = StaticSecret::from(*eph_bytes);
    let eph_pk = PublicKey::from(&eph_sk).to_bytes();

    // Nonce хранится в блобе и **не выводится из общего секрета** — выведенный,
    // он определялся бы эфемерной парой и совпадал бы всегда, когда совпала она.
    //
    // Но и просто взять его из генератора недостаточно, и это стоило отдельного
    // решения (С-13). Эфемерная пара и nonce приходят из ОДНОГО генератора
    // подряд, поэтому полный повтор его состояния — откат снапшота виртуальной
    // машины, клон образа диска, восстановление из резервной копии — повторял бы
    // оба значения разом, а с ними и поток ключей. Здесь это дороже всего:
    // открытые тексты — доли секрета схемы 2-из-2.
    //
    // Поэтому случайные байты идут не в nonce, а в засев производной, куда
    // входит ещё и открытый текст: при повторе генератора и разных секретах
    // nonce расходятся. Подробности и границы гарантии — у `hedged_nonce`.
    let mut nonce_seed = Zeroizing::new([0u8; NONCE_LEN]);
    rng.fill_bytes(nonce_seed.as_mut_slice());
    let nonce = crate::kdf::hedged_nonce::<NONCE_LEN>(
        crate::label::SEAL_NONCE,
        nonce_seed.as_slice(),
        plaintext,
        aad,
    )?;

    let shared = eph_sk.diffie_hellman(&PublicKey::from(*recipient_public));
    let shared = crate::agreement::SharedSecret::from_be_bytes(*shared.as_bytes());

    seal_core(&shared, &eph_pk, recipient_public, info, aad, plaintext, nonce)
}

/// Запечатать на ключ P-256 — для получателя, чей ключ живёт в TPM.
///
/// Отдельная функция, а не параметр у [`seal`], и причина в порядке расхода
/// генератора. У X25519 он **заморожен**: golden-контейнеры собираются на
/// засеянном RNG, и сдвинь порядок обращений к нему хоть на один вызов — байты
/// эталонов поедут, хотя ни один алгоритм не изменится. Поэтому объединяется всё,
/// что после согласования (`seal_core`), а генерация эфемерной пары остаётся у
/// каждого механизма своя.
pub fn seal_p256<R: CryptoRng + ?Sized>(
    recipient_public: &[u8],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    rng: &mut R,
) -> Result<SealedBlob, CryptoError> {
    use crate::agreement::KeyAgreement as _;

    let eph = crate::agreement::P256Agreement::generate(rng);
    let eph_pk = eph.public_key();

    let mut nonce_seed = Zeroizing::new([0u8; NONCE_LEN]);
    rng.fill_bytes(nonce_seed.as_mut_slice());
    let nonce = crate::kdf::hedged_nonce::<NONCE_LEN>(
        crate::label::SEAL_NONCE,
        nonce_seed.as_slice(),
        plaintext,
        aad,
    )?;

    // Согласование через трейт: точка получателя проверяется на принадлежность
    // кривой внутри. Для P-256 это обязательно — `recipient_public` приходит из
    // заголовка, то есть из файла.
    let shared = eph.agree(recipient_public)?;

    seal_core(&shared, &eph_pk, recipient_public, info, aad, plaintext, nonce)
}

/// Общая часть запечатывания: вывод ключа и AEAD.
///
/// Вынесена затем, чтобы у двух механизмов не оказалось двух похожих, но
/// разошедшихся реализаций одного и того же. Расходятся такие копии не сразу и не
/// заметно — и обнаруживается это как «слот не открывается».
fn seal_core(
    shared: &crate::agreement::SharedSecret,
    eph_public: &[u8],
    recipient_public: &[u8],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    nonce: [u8; NONCE_LEN],
) -> Result<SealedBlob, CryptoError> {
    let key = derive_key(shared, eph_public, recipient_public, info)?;

    let cipher = XChaCha20Poly1305::new((&*key).into());
    let ct = cipher
        .encrypt((&nonce).into(), Payload { msg: plaintext, aad })
        // Единственная причина отказа шифрования — открытый текст, не влезающий в
        // адресуемый буфер. Это ошибка длины вызывающего, а не аутентификации.
        .map_err(|_| CryptoError::BadLength)?;

    Ok(SealedBlob { enc: eph_public.to_vec(), nonce, ct })
}

/// Запечатать слот ГИБРИДОМ X-Wing — `kem_id = 4`.
///
/// Отдельная функция рядом с [`seal`] и [`seal_p256`] по той же причине, что и
/// они друг рядом с другом: у механизма свой порядок расхода генератора, а у
/// X25519 он заморожен эталонами. Здесь расход — шестьдесят четыре байта одним
/// обращением на инкапсуляцию, потом двадцать четыре на засев nonce.
///
/// Общий секрет X-Wing входит в ту же схему вывода ключа, что и общий секрет DH,
/// и это не подгонка: `derive_key` связывает с ним ОБА публичных значения —
/// шифротекст и ключ получателя. X-Wing связывает свою половину сам (§5.3
/// черновика), но вторая привязка бесплатна, а разные схемы для разных
/// механизмов означали бы две ключевые схемы вместо одной.
///
/// # Errors
/// Открытая половина не той длины либо не разбирается как ключ ML-KEM.
pub fn seal_xwing<R: CryptoRng + ?Sized>(
    recipient_public: &[u8],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    rng: &mut R,
) -> Result<SealedBlob, CryptoError> {
    let (shared, ciphertext) = crate::xwing::encapsulate(recipient_public, rng)?;

    let mut nonce_seed = Zeroizing::new([0u8; NONCE_LEN]);
    rng.fill_bytes(nonce_seed.as_mut_slice());
    let nonce = crate::kdf::hedged_nonce::<NONCE_LEN>(
        crate::label::SEAL_NONCE,
        nonce_seed.as_slice(),
        plaintext,
        aad,
    )?;

    let shared = crate::agreement::SharedSecret::from_be_bytes(*shared);
    seal_core(&shared, &ciphertext, recipient_public, info, aad, plaintext, nonce)
}

/// Открыть слот, запечатанный гибридом.
///
/// Своя открытая половина ПЕРЕСЧИТЫВАЕТСЯ из семени, а не принимается снаружи:
/// она входит в `ikm`, и принятая аргументом сделала бы вывод ключа управляемым
/// извне. Тот же довод, что у [`open`].
///
/// Испорченный шифротекст отказом здесь не оборачивается — ML-KEM отвечает на
/// него неявным отказом, и ложность секрета ловится тегом AEAD ниже, константным
/// временем. Разбор — в докстроке [`crate::xwing::decapsulate`].
///
/// # Errors
/// Длины не сошлись либо тег AEAD не проверился.
pub fn open_xwing(
    recipient_secret: &[u8; crate::xwing::SECRET_LEN],
    blob: &SealedBlob,
    info: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if blob.ct.len() < TAG_LEN {
        return Err(CryptoError::BadLength);
    }
    let shared = crate::xwing::decapsulate(recipient_secret, &blob.enc)?;
    let own_public = crate::xwing::public_key(recipient_secret)?;
    let shared = crate::agreement::SharedSecret::from_be_bytes(*shared);
    let key = derive_key(&shared, &blob.enc, &own_public, info)?;
    open_core(&key, blob, aad)
}

/// Запечатать слот АППАРАТНЫМ ГИБРИДОМ MLKEM768-P256 — `kem_id = 5`.
///
/// Отдельная функция рядом с [`seal_xwing`] по той же причине, что и все
/// соседи: у механизма свой порядок расхода генератора, а у X25519 он заморожен
/// эталонами. Здесь расход — сто шестьдесят байт одним обращением на
/// инкапсуляцию, потом двадцать четыре на засев nonce.
///
/// # Errors
/// Открытая половина не той длины либо не разбирается как ключ ML-KEM.
pub fn seal_mlkem_p256<R: CryptoRng + ?Sized>(
    recipient_public: &[u8],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    rng: &mut R,
) -> Result<SealedBlob, CryptoError> {
    let (shared, ciphertext) = crate::mlkem_p256::encapsulate(recipient_public, rng)?;

    let mut nonce_seed = Zeroizing::new([0u8; NONCE_LEN]);
    rng.fill_bytes(nonce_seed.as_mut_slice());
    let nonce = crate::kdf::hedged_nonce::<NONCE_LEN>(
        crate::label::SEAL_NONCE,
        nonce_seed.as_slice(),
        plaintext,
        aad,
    )?;

    let shared = crate::agreement::SharedSecret::from_be_bytes(*shared);
    seal_core(&shared, &ciphertext, recipient_public, info, aad, plaintext, nonce)
}

/// Открыть слот аппаратного гибрида.
///
/// Классическая половина приходит ЗА ТРЕЙТОМ, и в этом весь смысл механизма:
/// приватный ключ P-256 может лежать в TPM и не покидать его. Постквантовая
/// половина — семя рядом, в защищённом хранилище.
///
/// Своя открытая половина ПЕРЕСЧИТЫВАЕТСЯ из обеих половин, а не принимается
/// аргументом: она входит в `ikm`, и принятая снаружи сделала бы вывод ключа
/// управляемым извне. Тот же довод, что у [`open`].
///
/// # Errors
/// Длины не сошлись, точка вне кривой либо тег AEAD не проверился.
pub fn open_mlkem_p256(
    ml_kem_seed: &[u8; crate::mlkem_p256::ML_KEM_SEED_LEN],
    classical: &dyn crate::agreement::KeyAgreement,
    blob: &SealedBlob,
    info: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if blob.ct.len() < TAG_LEN {
        return Err(CryptoError::BadLength);
    }
    let shared = crate::mlkem_p256::decapsulate_with(ml_kem_seed, classical, &blob.enc)?;
    let own_public =
        crate::mlkem_p256::public_key_from_parts(ml_kem_seed, &classical.public_key())?;
    let shared = crate::agreement::SharedSecret::from_be_bytes(*shared);
    let key = derive_key(&shared, &blob.enc, &own_public, info)?;
    open_core(&key, blob, aad)
}

/// Открыть запечатанный секрет.
pub fn open(
    recipient_secret: &X25519Secret,
    blob: &SealedBlob,
    info: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    // Шифротекст короче тега — структурная ошибка ввода, и отсечь её надо до
    // согласования ключей: считать DH ради заведомо неоткрываемого блоба значит
    // дарить противнику измеримую работу на каждом мусорном байте.
    if blob.ct.len() < TAG_LEN {
        return Err(CryptoError::BadLength);
    }

    // Длина эфемерного ключа проверяется здесь же, до согласования, и по той же
    // причине. Эта функция реализует X25519 и только его: `enc` иной длины —
    // не «чужой механизм, разберёмся ниже», а несоответствие входа контракту.
    // Решение «пропустить слот или отвергнуть файл» принимает вызывающий,
    // который знает версию контейнера; здесь ответ один — не наш вход.
    let enc: [u8; PUBLIC_KEY_LEN] =
        blob.enc.as_slice().try_into().map_err(|_| CryptoError::BadLength)?;

    let sk = StaticSecret::from(*recipient_secret.expose());
    // Свой публичный ключ пересчитывается, а не принимается снаружи: он входит в
    // ikm, и подставленное значение сделало бы вывод ключа управляемым извне.
    let own_pk = PublicKey::from(&sk).to_bytes();

    let shared = sk.diffie_hellman(&PublicKey::from(enc));
    let shared = crate::agreement::SharedSecret::from_be_bytes(*shared.as_bytes());
    let key = derive_key(&shared, &enc, &own_pk, info)?;
    open_core(&key, blob, aad)
}

/// Открыть блоб СТОРОНОЙ СОГЛАСОВАНИЯ, какой бы она ни была.
///
/// Это и есть та точка, ради которой заведён трейт: приватный ключ может лежать в
/// TPM и не покидать его. Аппаратная реализация подставляется здесь вместо
/// программной, и вывод ключа от этого не меняется ни на байт — он считается по
/// общему секрету, а не по ключу.
///
/// Свой публичный ключ берётся у самой стороны, а не из аргумента: он входит в
/// `ikm`, и принять его снаружи значило бы сделать вывод ключа управляемым извне.
pub fn open_with(
    agreement: &dyn crate::agreement::KeyAgreement,
    blob: &SealedBlob,
    info: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    if blob.ct.len() < TAG_LEN {
        return Err(CryptoError::BadLength);
    }

    // Согласование первым: оно же проверяет чужую точку. Длину `enc` проверяет
    // реализация трейта — своей мерой для своего механизма.
    let shared = agreement.agree(&blob.enc)?;
    let own_pk = agreement.public_key();
    let key = derive_key(&shared, &blob.enc, &own_pk, info)?;
    open_core(&key, blob, aad)
}

/// Общая часть открытия: AEAD и порядок проверки тега.
fn open_core(
    key: &[u8; SHARED_LEN],
    blob: &SealedBlob,
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let cipher = XChaCha20Poly1305::new(key.into());
    // Nonce берётся из блоба. Подменить его противник может, но это ничего не
    // даёт: он входит в вычисление тега, и любая подмена ломает аутентификацию.
    let plaintext = cipher
        .decrypt((&blob.nonce).into(), Payload { msg: &blob.ct, aad })
        .map_err(|_| CryptoError::Authentication)?;

    // Открытый текст отдаётся только после проверки тега — `decrypt` не
    // возвращает ничего до неё — и сразу под владельцем, затирающим буфер.
    Ok(Zeroizing::new(plaintext))
}

/// Общая ключевая схема seal и open: из общего секрета DH и обоих публичных
/// ключей выводится ключ AEAD.
///
/// Nonce здесь **не** выводится — он хранится в блобе, см. [`SealedBlob::nonce`].
///
/// В `ikm` входят **оба** публичных ключа. Без эфемерного ключа получателя и без
/// ключа получателя в отдельности схема допускает привязку одного и того же
/// шифротекста к чужой личности: противник, знающий свой приватный ключ,
/// подбирает публичный ключ, дающий тот же общий секрет, и выдаёт чужой блоб за
/// адресованный ему. Все три поля фиксированной длины по 32 байта, поэтому
/// конкатенация кодируется однозначно и разделители не нужны.
///
/// Соль HKDF пуста намеренно: у сторон нет общего случайного значения на этом
/// шаге, а разделение доменов целиком лежит на `info`.
fn derive_key(
    shared: &crate::agreement::SharedSecret,
    eph_public: &[u8],
    recipient_public: &[u8],
    info: &[u8],
) -> Result<Zeroizing<[u8; SHARED_LEN]>, CryptoError> {
    let shared = shared.expose();
    // Нулевой общий секрет — признак точки малого порядка в роли публичного
    // ключа. Продолжив, обе стороны получили бы один и тот же ключ AEAD,
    // независимый от приватного ключа получателя: открыть блоб смог бы кто
    // угодно. Сравнение в постоянном времени, чтобы не давать оракул по времени.
    let zero = [0u8; SHARED_LEN];
    if bool::from(shared.as_slice().ct_eq(zero.as_slice())) {
        return Err(CryptoError::BadKey);
    }

    // `ikm = DH ‖ enc ‖ pk_получателя`. Конкатенация без разделителей и без длин,
    // и её однозначность держится НЕ на том, что все три по 32 байта: у P-256
    // ключи по 65. Держится она на том, что внутри одного `kem_id` все три длины
    // фиксированы, а сам `kem_id` входит в `info` (см. [`slot_info`]) и потому в
    // вывод ключа. Разобрать склейку двумя способами можно было бы только сменив
    // механизм — а смена механизма меняет ключ.
    let mut ikm = Zeroizing::new(Vec::with_capacity(
        shared.len().saturating_add(eph_public.len()).saturating_add(recipient_public.len()),
    ));
    ikm.extend_from_slice(shared);
    ikm.extend_from_slice(eph_public);
    ikm.extend_from_slice(recipient_public);

    let hk = Hkdf::<Sha256>::new(None, &ikm);

    let mut key = Zeroizing::new([0u8; SHARED_LEN]);
    hk.expand(&expand_info(crate::label::SEAL_KEY.as_bytes(), info), key.as_mut_slice())
        .map_err(|_| CryptoError::BadLength)?;

    Ok(key)
}

/// `info` для HKDF: метка домена и аргумент вызывающего.
fn expand_info(label: &[u8], info: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(label.len().saturating_add(info.len()));
    out.extend_from_slice(label);
    out.extend_from_slice(info);
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::arithmetic_side_effects)]
mod moved_info_tests {
    use super::*;

    /// Вход, на котором заморожены байты трёх сборок `info`.
    ///
    /// Значения не «красивые» и не повторяющиеся: `[0x11; 16]` не поймал бы
    /// перестановку `file_id` с его же куском, а возрастающий ряд поймает.
    const FILE_ID: [u8; 16] = [
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f,
    ];
    const DEVICE_FPR: [u8; 32] = [
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
        0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d,
        0x3e, 0x3f,
    ];
    /// Номер лизинга. Не ноль и не палиндром: различает `u64be` и `u64le`.
    const SEQ: u64 = 0x0102_0304_0506_0708;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// БАЙТЫ ТРЁХ ПЕРЕЕХАВШИХ СБОРОК — ТЕ ЖЕ, ЧТО ДО ПЕРЕЕЗДА.
    ///
    /// Эталоны напечатаны СТАРЫМ кодом до переноса: `a_to_device_info` — обеими
    /// копиями сразу (`cc-authority` и `cc-cli` давали совпадающую строку),
    /// `challenge_info` — сборкой сервера, `b_to_device_info` — сборкой клиента.
    /// Сверять новое с новым было бы тавтологией: переезд нормативных байтов
    /// проверяется только против значения, снятого ДО него.
    ///
    /// Эти строки входят в `info` вывода ключа, то есть в БАЙТЫ НА ПРОВОДЕ.
    /// Расхождение на байт даёт другой ключ, а выглядит как «доля не
    /// разворачивается» — поломка крипты там, где поломки нет.
    #[test]
    fn the_moved_derivation_inputs_are_byte_for_byte_what_they_were() {
        assert_eq!(
            hex(&a_to_device_info(KemAlg::P256HkdfSha256, &FILE_ID, &DEVICE_FPR, SEQ)),
            "43432f76312f612d746f2d64657669636502101112131415161718191a1b1c1d1e1f\
             202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\
             0102030405060708",
        );
        assert_eq!(
            hex(&b_to_device_info(KemAlg::XWing, &FILE_ID, &DEVICE_FPR)),
            "43432f76312f622d746f2d64657669636504101112131415161718191a1b1c1d1e1f\
             202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        );
        assert_eq!(
            hex(&challenge_info(&DEVICE_FPR)),
            "43432f76312f6174746573742d6e6f6e6365\
             202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        );
    }

    /// МЕХАНИЗМ ВХОДИТ В ОБЕ ДОЛИ, А В ВЫЗОВ — НЕТ.
    ///
    /// Первое — свойство: слот, переразмеченный чужим `kem_id`, обязан давать
    /// другой ключ. Второе — замороженная форма рукопожатия: вызов открывается
    /// половинами разных механизмов подряд, и `info` у них один. Проба стоит
    /// затем, чтобы «единообразие» не дописали сюда четвёртым байтом.
    #[test]
    fn the_mechanism_binds_both_shares_and_deliberately_not_the_challenge() {
        assert_ne!(
            a_to_device_info(KemAlg::X25519HkdfSha256, &FILE_ID, &DEVICE_FPR, SEQ),
            a_to_device_info(KemAlg::P256HkdfSha256, &FILE_ID, &DEVICE_FPR, SEQ),
        );
        assert_ne!(
            b_to_device_info(KemAlg::X25519HkdfSha256, &FILE_ID, &DEVICE_FPR),
            b_to_device_info(KemAlg::XWing, &FILE_ID, &DEVICE_FPR),
        );
        assert_eq!(
            challenge_info(&DEVICE_FPR).len(),
            crate::label::ATTEST_NONCE.len() + 32,
            "в вызов добавился байт — это смена байтов на проводе",
        );
    }

    /// Доля B НЕ несёт номера лизинга, доля A несёт. Разница нормативна:
    /// одобрение автора не должно требоваться заново на каждое продление.
    #[test]
    fn only_the_a_share_is_tied_to_a_lease_number() {
        let b = b_to_device_info(KemAlg::X25519HkdfSha256, &FILE_ID, &DEVICE_FPR);
        assert_eq!(b.len(), crate::label::B_TO_DEVICE.len() + 1 + 16 + 32);
        let a = a_to_device_info(KemAlg::X25519HkdfSha256, &FILE_ID, &DEVICE_FPR, SEQ);
        assert_eq!(a.len(), crate::label::A_TO_DEVICE.len() + 1 + 16 + 32 + 8);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod kem_binding_tests {
    use super::*;

    const FILE_ID: [u8; 16] = [0x5a; 16];

    #[test]
    fn relabelling_a_slot_with_another_kem_changes_the_key_it_derives() {
        // Свойство, ради которого идентификатор механизма вообще попал в `info`.
        //
        // §3.3 обещает, что слоты с разными KEM сосуществуют в одном файле.
        // Пока идентификатор не входил в вывод ключа, обещание не было
        // подкреплено ничем: слот, переразмеченный с X25519 на P-256, выводил
        // тот же самый ключ, и объявленный алгоритм оставался украшением.
        let as_x25519 = slot_info(crate::label::SLOT_SERVER, KemAlg::X25519HkdfSha256, &FILE_ID);
        let as_p256 = slot_info(crate::label::SLOT_SERVER, KemAlg::P256HkdfSha256, &FILE_ID);
        assert_ne!(as_x25519, as_p256, "переразметка KEM не меняет info");
    }

    #[test]
    fn a_blob_sealed_under_one_kem_label_does_not_open_under_another() {
        struct Fixed(u8);
        impl rand_core::TryRng for Fixed {
            type Error = core::convert::Infallible;
            fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
                Ok(u32::from(self.0))
            }
            fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
                Ok(u64::from(self.0))
            }
            fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
                for b in dst.iter_mut() {
                    self.0 = self.0.wrapping_add(1);
                    *b = self.0;
                }
                Ok(())
            }
        }
        impl rand_core::TryCryptoRng for Fixed {}

        let recipient = X25519Secret::from_bytes([0x11; 32]);
        let public = x25519_public(&recipient);
        let honest = slot_info(crate::label::SLOT_SERVER, KemAlg::X25519HkdfSha256, &FILE_ID);
        let forged = slot_info(crate::label::SLOT_SERVER, KemAlg::P256HkdfSha256, &FILE_ID);

        let blob = seal(&public, &honest, b"aad", b"share", &mut Fixed(1)).unwrap();
        assert!(open(&recipient, &blob, &honest, b"aad").is_ok());
        assert_eq!(
            open(&recipient, &blob, &forged, b"aad").err(),
            Some(CryptoError::Authentication),
            "слот открылся под чужой меткой механизма"
        );
    }

    /// Умеет ли сборка исполнить объявленный механизм — вопрос отдельный от того,
    /// разбирает ли она его форму.
    ///
    /// Утверждение про P-256 здесь поменялось, и поменялось **по решению**,
    /// записанному в `docs/format.md` («ВЕРСИЯ 2 ОТКРЫТА»), а не вслед за кодом.
    /// До версии 2 механизм был объявлен в реестре, но не исполнялся, и слот с
    /// ним полагалось пропускать. Теперь исполняется — потому что ключ в TPM
    /// иначе не адресовать: Platform Crypto Provider не даёт X25519.
    ///
    /// RSA-OAEP остаётся неисполнимым, и это не «руки не дошли», а проверяемое
    /// свойство: в формате обязан оставаться механизм, объявленный номером и не
    /// исполняемый, иначе ветка «пропустить слот, а не отвергнуть файл» перестаёт
    /// проверяться вовсе.
    #[test]
    fn the_build_executes_exactly_the_mechanisms_it_claims() {
        assert!(supports_kem(DEFAULT_SEALING_KEM));
        assert!(supports_kem(KemAlg::X25519HkdfSha256));
        assert!(supports_kem(KemAlg::P256HkdfSha256), "P-256 объявлен версией 2 и обязан исполняться");
        assert!(!supports_kem(KemAlg::RsaOaepSha256), "неисполнимый механизм обязан остаться");
    }

    /// Запечатывание на P-256 и открытие его же стороной согласования сходятся.
    ///
    /// Проверяется весь путь целиком: эфемерная пара, согласование за трейтом,
    /// вывод ключа с 65-байтовыми ключами в `ikm`, AEAD. Программной стороной, а
    /// не TPM, — именно ради этого программная реализация и заведена: иначе путь
    /// проверялся бы только на машине с подходящим железом.
    #[test]
    fn a_p256_slot_seals_and_opens_through_the_agreement_trait() {
        use crate::agreement::{KeyAgreement as _, P256Agreement};

        let recipient = P256Agreement::from_be_bytes(&[0x5e; 32]).unwrap();
        let recipient_public = recipient.public_key();
        assert_eq!(recipient_public.len(), 65);

        // Свой детерминированный генератор: воспроизводимость теста важнее
        // стойкости, а стойкость здесь и не проверяется.
        struct Counter(u8);
        impl rand_core::TryRng for Counter {
            type Error = core::convert::Infallible;
            fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
                Ok(u32::from(self.0))
            }
            fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
                Ok(u64::from(self.0))
            }
            fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
                for b in dst.iter_mut() {
                    self.0 = self.0.wrapping_add(1);
                    *b = self.0;
                }
                Ok(())
            }
        }
        impl rand_core::TryCryptoRng for Counter {}

        let info = slot_info(crate::label::SLOT_AUTHOR_DEVICE, KemAlg::P256HkdfSha256, &[0x11; 16]);
        let blob = seal_p256(&recipient_public, &info, b"aad", b"share", &mut Counter(7)).unwrap();
        assert_eq!(blob.enc.len(), 65, "эфемерный ключ P-256 на проводе — 65 байт");

        let opened = open_with(&recipient, &blob, &info, b"aad").unwrap();
        assert_eq!(opened.as_slice(), b"share");

        // Чужая сторона не открывает: проверка не только на то, что сошлось.
        let stranger = P256Agreement::from_be_bytes(&[0x77; 32]).unwrap();
        assert_eq!(
            open_with(&stranger, &blob, &info, b"aad").err(),
            Some(CryptoError::Authentication),
            "слот открылся чужим ключом"
        );
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    /// АППАРАТНЫЙ ГИБРИД: ЗАПЕЧАТАНО ПРОГРАММНО — ОТКРЫТО ОБЕИМИ ПОЛОВИНАМИ.
    ///
    /// Классическая половина подставляется ЗА ТРЕЙТОМ, и в пробе это
    /// программный P-256; в поставке на его место встаёт ключ из TPM, не меняя
    /// ни байта в выводе. Ради этой подстановки трейт и существует.
    #[test]
    fn a_hardware_hybrid_slot_opens_with_both_halves() {
        let pair = crate::mlkem_p256::keypair_from_seed(&[0x2f; 32]).unwrap();
        let info = slot_info(crate::label::SLOT_RECIPIENT, crate::KemAlg::MlKem768P256, &[7u8; 16]);
        let aad = [0x9d_u8; 32];

        let mut rng = TestRng::seeded(0x51);
        let blob = seal_mlkem_p256(&pair.public_key, &info, &aad, b"secret share", &mut rng).unwrap();
        assert_eq!(blob.enc.len(), 1153, "enc аппаратного гибрида не 1153 байта");

        let opened =
            open_mlkem_p256(&pair.ml_kem_seed, &pair.classical, &blob, &info, &aad).unwrap();
        assert_eq!(opened.as_slice(), b"secret share");
    }

    /// ОДНОЙ ПОЛОВИНЫ НЕ ХВАТАЕТ — НИ ТОЙ, НИ ДРУГОЙ.
    ///
    /// Это и есть обещание гибрида, и проба проверяет обе стороны: чужая
    /// постквантовая половина и чужая классическая по отдельности не открывают
    /// слот. Без этой пробы «гибрид» держался бы на честном слове.
    #[test]
    fn neither_half_alone_opens_a_hardware_hybrid_slot() {
        let pair = crate::mlkem_p256::keypair_from_seed(&[0x2f; 32]).unwrap();
        let other = crate::mlkem_p256::keypair_from_seed(&[0x88; 32]).unwrap();
        let info = slot_info(crate::label::SLOT_RECIPIENT, crate::KemAlg::MlKem768P256, &[7u8; 16]);

        let mut rng = TestRng::seeded(0x51);
        let blob = seal_mlkem_p256(&pair.public_key, &info, &[0u8; 32], b"share", &mut rng).unwrap();

        // Своя классическая, чужая постквантовая.
        assert!(
            open_mlkem_p256(&other.ml_kem_seed, &pair.classical, &blob, &info, &[0u8; 32]).is_err(),
            "слот открылся без своей постквантовой половины"
        );
        // Своя постквантовая, чужая классическая.
        assert!(
            open_mlkem_p256(&pair.ml_kem_seed, &other.classical, &blob, &info, &[0u8; 32]).is_err(),
            "слот открылся без своей классической половины"
        );
    }

    /// ГИБРИДНЫЙ СЛОТ ЗАПЕЧАТЫВАЕТСЯ И ОТКРЫВАЕТСЯ ТЕМ ЖЕ СЕМЕНЕМ.
    #[test]
    fn a_hybrid_slot_seals_and_opens_with_the_same_seed() {
        let secret = [0x2f_u8; crate::xwing::SECRET_LEN];
        let public = crate::xwing::public_key(&secret).unwrap();
        let info = slot_info(crate::label::SLOT_RECIPIENT, crate::KemAlg::XWing, &[7u8; 16]);
        let aad = [0x9d_u8; 32];

        let mut rng = TestRng::seeded(0x51);
        let blob = seal_xwing(&public, &info, &aad, b"secret share", &mut rng).unwrap();
        assert_eq!(blob.enc.len(), crate::xwing::CIPHERTEXT_LEN, "enc гибрида не 1120 байт");

        let opened = open_xwing(&secret, &blob, &info, &aad).unwrap();
        assert_eq!(opened.as_slice(), b"secret share");
    }

    /// ЧУЖОЙ `info` ГИБРИД НЕ ОТКРЫВАЕТ.
    ///
    /// В `info` входит `u8(kem_id)`, поэтому слот, переразмеченный чужим
    /// механизмом, не откроется даже тем же ключом. Ровно то свойство, ради
    /// которого механизм вообще попал в вывод ключа.
    #[test]
    fn a_hybrid_slot_relabelled_with_another_mechanism_does_not_open() {
        let secret = [0x2f_u8; crate::xwing::SECRET_LEN];
        let public = crate::xwing::public_key(&secret).unwrap();
        let honest = slot_info(crate::label::SLOT_RECIPIENT, crate::KemAlg::XWing, &[7u8; 16]);
        let forged = slot_info(crate::label::SLOT_RECIPIENT, crate::KemAlg::X25519HkdfSha256, &[7u8; 16]);

        let mut rng = TestRng::seeded(0x51);
        let blob = seal_xwing(&public, &honest, &[0u8; 32], b"share", &mut rng).unwrap();
        assert!(open_xwing(&secret, &blob, &forged, &[0u8; 32]).is_err());
    }

    /// ИСПОРЧЕННЫЙ ШИФРОТЕКСТ ГИБРИДА — ОТКАЗ AEAD, А НЕ ОТКРЫТЫЙ ТЕКСТ.
    ///
    /// Неявный отказ ML-KEM даёт другой общий секрет, и поймать его обязан тег
    /// AEAD. Эта проба стережёт стык двух механизмов: молчаливый отказ снизу
    /// обязан стать громким наверху.
    #[test]
    fn a_corrupted_hybrid_ciphertext_is_caught_by_the_aead_tag() {
        let secret = [0x2f_u8; crate::xwing::SECRET_LEN];
        let public = crate::xwing::public_key(&secret).unwrap();
        let info = slot_info(crate::label::SLOT_RECIPIENT, crate::KemAlg::XWing, &[7u8; 16]);

        let mut rng = TestRng::seeded(0x51);
        let mut blob = seal_xwing(&public, &info, &[0u8; 32], b"share", &mut rng).unwrap();
        if let Some(byte) = blob.enc.get_mut(0) {
            *byte ^= 1;
        }
        assert!(matches!(
            open_xwing(&secret, &blob, &info, &[0u8; 32]),
            Err(CryptoError::Authentication)
        ));
    }

    use super::*;

    /// Детерминированный генератор: воспроизводимость теста важнее стойкости, а
    /// настоящая случайность сделала бы падение неповторяемым.
    struct TestRng([u8; 32]);

    impl TestRng {
        fn seeded(seed: u8) -> Self {
            Self([seed; 32])
        }
    }

    impl rand_core::TryRng for TestRng {
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

    impl rand_core::TryCryptoRng for TestRng {}

    const INFO: &[u8] = b"CC/v1/slot-A\x01\x02\x03";
    const AAD: &[u8] = b"policy-hash";
    const PT: &[u8] = b"secret_A: 32 bytes worth of key ";

    fn recipient(seed: u8) -> X25519Secret {
        X25519Secret::from_bytes([seed; 32])
    }

    /// Ошибка открытия без требования `Debug`/`PartialEq` от открытого текста.
    fn open_err(r: Result<Zeroizing<Vec<u8>>, CryptoError>) -> CryptoError {
        match r {
            Ok(_) => panic!("открытие должно было провалиться, но вернуло открытый текст"),
            Err(e) => e,
        }
    }

    #[test]
    fn a_sealed_secret_opens_only_under_the_matching_private_key() {
        let mut rng = TestRng::seeded(1);
        let sk = recipient(7);
        let pk = x25519_public(&sk);

        let blob = seal(&pk, INFO, AAD, PT, &mut rng).unwrap();
        assert_eq!(blob.ct.len(), PT.len().saturating_add(TAG_LEN), "тег обязан быть приписан");

        let opened = open(&sk, &blob, INFO, AAD).unwrap();
        assert_eq!(opened.as_slice(), PT);
    }

    #[test]
    fn a_foreign_private_key_never_opens_the_blob() {
        // Это базовое свойство схемы: без приватного ключа получателя общий
        // секрет другой, ключ AEAD другой, тег не сходится.
        let mut rng = TestRng::seeded(2);
        let sk = recipient(7);
        let blob = seal(&x25519_public(&sk), INFO, AAD, PT, &mut rng).unwrap();

        let stranger = recipient(9);
        assert_eq!(open_err(open(&stranger, &blob, INFO, AAD)), CryptoError::Authentication);
    }

    #[test]
    fn a_blob_sealed_for_one_slot_does_not_open_under_another_slots_info() {
        // Разделение назначения слотов: секрет A из слота сервера не должен
        // открываться кодом, ожидающим секрет B получателя, даже если ключ тот же.
        let mut rng = TestRng::seeded(3);
        let sk = recipient(7);
        let blob = seal(&x25519_public(&sk), INFO, AAD, PT, &mut rng).unwrap();

        let other_info = b"CC/v1/slot-B\x01\x02\x03";
        assert_eq!(open_err(open(&sk, &blob, other_info, AAD)), CryptoError::Authentication);
    }

    #[test]
    fn a_blob_does_not_open_under_a_different_aad() {
        // Привязка к контексту файла: перенос шифротекста в контейнер с другой
        // политикой обязан проваливаться, иначе правила подменяются вокруг того
        // же ключа.
        let mut rng = TestRng::seeded(4);
        let sk = recipient(7);
        let blob = seal(&x25519_public(&sk), INFO, AAD, PT, &mut rng).unwrap();

        assert_eq!(open_err(open(&sk, &blob, INFO, b"other-policy")), CryptoError::Authentication);
    }

    #[test]
    fn substituting_the_encapsulated_public_key_breaks_the_blob() {
        // Эфемерный ключ входит в ikm, поэтому подмена enc меняет ключ AEAD, а не
        // только общий секрет: склеить чужой enc со своим шифротекстом нельзя.
        let mut rng = TestRng::seeded(5);
        let sk = recipient(7);
        let mut blob = seal(&x25519_public(&sk), INFO, AAD, PT, &mut rng).unwrap();

        let intruder = recipient(11);
        blob.enc = x25519_public(&intruder).to_vec();

        assert_eq!(open_err(open(&sk, &blob, INFO, AAD)), CryptoError::Authentication);
    }

    #[test]
    fn flipping_a_single_ciphertext_bit_is_detected() {
        let mut rng = TestRng::seeded(6);
        let sk = recipient(7);
        let mut blob = seal(&x25519_public(&sk), INFO, AAD, PT, &mut rng).unwrap();

        let flipped = blob.ct.first_mut().map(|b| {
            *b ^= 0x01;
        });
        assert!(flipped.is_some(), "шифротекст не может быть пустым");

        assert_eq!(open_err(open(&sk, &blob, INFO, AAD)), CryptoError::Authentication);
    }

    #[test]
    fn two_seals_of_the_same_input_never_repeat_enc_or_ciphertext() {
        // Эфемерность — не украшение: одинаковый enc означал бы одинаковый ключ
        // AEAD при выводимом nonce, то есть повторное использование пары
        // (ключ, nonce) и потерю конфиденциальности обоих открытых текстов.
        let mut rng = TestRng::seeded(8);
        let sk = recipient(7);
        let pk = x25519_public(&sk);

        let first = seal(&pk, INFO, AAD, PT, &mut rng).unwrap();
        let second = seal(&pk, INFO, AAD, PT, &mut rng).unwrap();

        assert_ne!(first.enc, second.enc, "эфемерный ключ повторился");
        assert_ne!(first.ct, second.ct, "шифротекст повторился при том же входе");

        // И обе версии всё ещё открываются — эфемерность не ломает схему.
        assert_eq!(open(&sk, &first, INFO, AAD).unwrap().as_slice(), PT);
        assert_eq!(open(&sk, &second, INFO, AAD).unwrap().as_slice(), PT);
    }

    #[test]
    fn a_low_order_public_key_is_refused_before_any_aead_work() {
        // Нулевая точка даёт нулевой общий секрет: ключ AEAD перестал бы зависеть
        // от приватного ключа получателя, и блоб открыл бы кто угодно.
        let mut rng = TestRng::seeded(10);
        let zero_pk = [0u8; PUBLIC_KEY_LEN];

        let sealed = seal(&zero_pk, INFO, AAD, PT, &mut rng);
        assert_eq!(sealed.err(), Some(CryptoError::BadKey));

        let sk = recipient(7);
        let blob = SealedBlob { enc: zero_pk.to_vec(), nonce: [0x01; 24], ct: vec![0u8; 48] };
        assert_eq!(open_err(open(&sk, &blob, INFO, AAD)), CryptoError::BadKey);
    }

    #[test]
    fn a_ciphertext_shorter_than_the_tag_is_a_length_error() {
        let sk = recipient(7);
        let blob = SealedBlob { enc: x25519_public(&recipient(3)).to_vec(), nonce: [0x01; 24], ct: vec![0u8; TAG_LEN - 1] };
        assert_eq!(open_err(open(&sk, &blob, INFO, AAD)), CryptoError::BadLength);
    }

    #[test]
    fn an_empty_plaintext_still_produces_an_authenticated_blob() {
        // Пустая полезная нагрузка — вырожденный, но допустимый случай: блоб
        // состоит из одного тега и обязан оставаться проверяемым.
        let mut rng = TestRng::seeded(12);
        let sk = recipient(7);
        let blob = seal(&x25519_public(&sk), INFO, AAD, b"", &mut rng).unwrap();

        assert_eq!(blob.ct.len(), TAG_LEN);
        assert!(open(&sk, &blob, INFO, AAD).unwrap().is_empty());
    }
}
