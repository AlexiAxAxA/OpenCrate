//! Шифрование чанков полезной нагрузки.
//!
//! Кадр на диске: `nonce(24) ‖ шифротекст ‖ тег(16)`.
//!
//! Nonce **хранится, а не выводится читателем**. Вывод его из `(file_id, номер
//! чанка)` смертелен: `file_id` обязан оставаться постоянным при правке, поэтому
//! перезапись чанка тем же ключом дала бы повторное использование nonce с разным
//! открытым текстом — восстановление обоих текстов через XOR и восстановление
//! одноразового ключа Poly1305.
//!
//! Ширины 192 бита достаточно против случайных коллизий, но НЕ против повтора
//! состояния генератора, поэтому nonce выводится ОТПРАВИТЕЛЕМ через засев (§6.1
//! и §3.1). Раньше здесь стояло, что ширина существует «именно для того, чтобы
//! случайные значения были безопасны», — формулировка, противоречившая §3.1 и
//! пережившая решение С-13.
//!
//! Из этого следует форма поверхности крейта, и она здесь главная: продуктовые
//! пути запечатывания принимают ЗАСЕВ, а не nonce, — [`seal_chunk_hedged`] и
//! [`seal_metadata_hedged`]. Передать готовый nonce им нечем, и это свойство
//! подписи, а не дисциплины вызывающего. Формы с nonce-аргументом
//! (`seal_chunk`, `seal_metadata`) остались только под признаком
//! `explicit-nonce`, которого в продуктовой сборке нет.
//!
//! Правило, нарушать которое нельзя: непроверенные байты не покидают функцию.
//! При ошибке выходной буфер затирается.

use crate::merkle::{leaf_of, Leaf};
use crate::secret::{MetaKey, PayloadKey, SecretBuf};
use crate::{label, AeadAlg, CryptoError};
use chacha20poly1305::{
    aead::{Aead, AeadInOut, Payload},
    KeyInit, XChaCha20Poly1305,
};
use zeroize::Zeroizing;

/// Длина хранимого nonce.
pub const NONCE_LEN: usize = 24;
/// Длина тега аутентификации.
pub const TAG_LEN: usize = 16;
/// Длина связанных данных чанка: метка(11) + file_id(16) + номер(4) + алгоритм(1).
pub const CHUNK_AAD_LEN: usize = 32;

/// Длина связанных данных приватных метаданных: метка(18) + file_id(16).
pub const META_AAD_LEN: usize = label::PRIVATE_META.len().saturating_add(16);

/// Раскладка AAD проверяется на этапе сборки, а не тестом.
///
/// Иначе правка метки домена (или её версии) тихо разъехалась бы с
/// [`CHUNK_AAD_LEN`]: буфер заполняется до конца, лишние байты остались бы
/// нулями, и два разных чанка получили бы одинаковый AAD. Сложение через
/// `saturating_add` — чтобы выражение не считалось арифметикой с побочным
/// эффектом.
const _: () = assert!(
    label::CHUNK
        .len()
        .saturating_add(16)
        .saturating_add(4)
        .saturating_add(1)
        == CHUNK_AAD_LEN,
    "метка \"CC/v1/chunk\" разъехалась с CHUNK_AAD_LEN"
);

/// Связанные данные чанка: `"CC/v1/chunk" ‖ file_id ‖ u32be(index) ‖ u8(alg)`.
///
/// Привязывают чанк к файлу и к его месту в файле, поэтому перестановка чанков и
/// подстановка чанка из другого файла не расшифровываются.
///
/// `chunk_count` и признак последнего чанка сюда **не входят**: это дало бы
/// обнаружение обрезания на каждом чанке, но дописывание в конец инвалидировало
/// бы все существующие чанки, и каждое сохранение превращалось бы в перезапись
/// файла целиком.
pub fn chunk_aad(file_id: &[u8; 16], index: u32, alg: AeadAlg) -> [u8; CHUNK_AAD_LEN] {
    // Транскрипт здесь не годится: он ставит после метки нулевой байт, а
    // спецификация (§6.1) задаёт голую конкатенацию ровно в 32 байта.
    // Однозначность обеспечена иначе — все поля после метки фиксированной длины.
    let index_be = index.to_be_bytes();
    let alg_id = alg as u8;
    let source = label::CHUNK
        .as_bytes()
        .iter()
        .chain(file_id.iter())
        .chain(index_be.iter())
        .chain(core::iter::once(&alg_id));

    let mut aad = [0u8; CHUNK_AAD_LEN];
    for (slot, byte) in aad.iter_mut().zip(source) {
        *slot = *byte;
    }
    aad
}

/// Связанные данные приватных метаданных: `"CC/v1/private-meta" ‖ file_id`.
///
/// Метка отличается от чанковой, поэтому блок метаданных нельзя выдать за чанк
/// нулевого номера и наоборот — даже под одним и тем же ключом.
///
/// Публична по той же причине, что [`chunk_aad`]: это **нормативное значение на
/// проводе**, его обязана собрать вторая реализация, и оно заморожено вектором.
/// Пока функция была приватной, AAD метаданных не был ни выписан в спеке, ни
/// заморожен — при том что AAD чанка рядом имел и строку в §6.1, и вектор.
pub fn metadata_aad(file_id: &[u8; 16]) -> [u8; META_AAD_LEN] {
    let source = label::PRIVATE_META.as_bytes().iter().chain(file_id.iter());
    let mut aad = [0u8; META_AAD_LEN];
    for (slot, byte) in aad.iter_mut().zip(source) {
        *slot = *byte;
    }
    aad
}

/// Умеет ли эта сборка шифровать объявленным профилем AEAD.
///
/// Второй рубеж для `aead_id`, симметричный [`crate::merkle::ensure_supported`]
/// для хеша дерева. Без него идентификатор в подписанном заголовке разбирался
/// успешно, а отказ приходил только на первом чанке — то есть уже после проверки
/// подписи, разбора слота, согласования ключей и разворота CEK. Разобрать номер и
/// суметь его исполнить — разные вещи, и решаться они должны в одном месте, на
/// разборе.
///
/// Профили AES заявлены форматом (docs/format.md §6.1), но их крейты в сборку не
/// подключены: счётчиковый nonce AES-GCM в 24-байтный аргумент не укладывается и
/// потребует собственного пути, а не ветки в `match`.
///
/// `match` намеренно без `_`: добавление члена в [`AeadAlg`] обязано ломать
/// сборку здесь, рядом с шифром, а не проходить молча.
pub fn ensure_supported(alg: AeadAlg) -> Result<(), CryptoError> {
    match alg {
        AeadAlg::XChaCha20Poly1305 => Ok(()),
        AeadAlg::Aes256Gcm | AeadAlg::Aes256GcmSiv => Err(CryptoError::UnsupportedAlgorithm),
    }
}

/// Единственное место выбора профиля AEAD при шифровании.
///
/// AES-профили заявлены форматом, но их крейты в сборку не подключены, поэтому
/// клиент честно отвечает «алгоритм не поддерживается» вместо подстановки
/// другого шифра. Тихая замена профиля — это молчаливое понижение стойкости.
/// Сверх того, счётчиковый nonce AES-GCM (`N_base ‖ u32be(i)`, §6.1) в
/// 24-байтный аргумент этой функции не укладывается: его подключение потребует
/// собственного пути, а не ветки в этом `match`.
/// Ключ здесь — сырые байты, а не тип назначения: внутренняя функция общая для
/// полезной нагрузки (K3) и приватных метаданных (K5), а различать назначение
/// обязана публичная поверхность, где это и делается типами `PayloadKey` и
/// `MetaKey`.
fn seal_with(
    key: &[u8; 32],
    alg: AeadAlg,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    match alg {
        AeadAlg::XChaCha20Poly1305 => XChaCha20Poly1305::new(key.into())
            .encrypt(nonce.into(), Payload { msg: plaintext, aad })
            // Единственная причина отказа при шифровании — слишком длинный вход.
            .map_err(|_| CryptoError::BadLength),
        AeadAlg::Aes256Gcm | AeadAlg::Aes256GcmSiv => Err(CryptoError::UnsupportedAlgorithm),
    }
}

/// Единственное место выбора профиля AEAD при расшифровании ЧАНКА.
///
/// Расшифровывает на месте: на входе в `buffer` шифротекст, на выходе — открытый
/// текст той же длины, тег отдельным аргументом.
///
/// Существует ради того, чтобы открытый текст не заводил собственной копии в
/// куче: см. развёрнутое объяснение в [`open_chunk_inner`]. Отказ выглядит
/// одинаково для подставного чанка, чужого файла и испорченного байта — по той
/// же причине, что и в [`open_with`].
///
/// Что остаётся в `buffer` при отказе, здесь не определено, и полагаться на это
/// нельзя: реализация вправе оставить там частично расшифрованные байты.
/// Затирание гарантирует обёртка [`open_chunk`], и гарантирует структурно.
fn open_in_place(
    key: &[u8; 32],
    alg: AeadAlg,
    nonce: &[u8; NONCE_LEN],
    buffer: &mut [u8],
    tag: &[u8; TAG_LEN],
    aad: &[u8],
) -> Result<(), CryptoError> {
    match alg {
        AeadAlg::XChaCha20Poly1305 => XChaCha20Poly1305::new(key.into())
            .decrypt_inout_detached(nonce.into(), aad, buffer.into(), tag.into())
            .map_err(|_| CryptoError::Authentication),
        AeadAlg::Aes256Gcm | AeadAlg::Aes256GcmSiv => Err(CryptoError::UnsupportedAlgorithm),
    }
}

/// Расшифрование с выделением вектора — остаток для приватных метаданных.
///
/// Чанки через неё больше не идут: их открытый текст обязан оставаться в
/// буфере вызывающего, чтобы не проходить через незапертую кучу. Метаданные —
/// это имя файла и справочный размер, десятки байт на весь документ; ради них
/// перестраивать разбор TLV на чтение из чужого буфера незачем, а размер такой,
/// что «уехало в подкачку» и «не уехало» одинаково недоказуемы. Разница названа
/// вслух, чтобы следующий читатель не решил, будто про метаданные забыли.
fn open_with(
    key: &[u8; 32],
    alg: AeadAlg,
    nonce: &[u8; NONCE_LEN],
    ct_and_tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    match alg {
        AeadAlg::XChaCha20Poly1305 => XChaCha20Poly1305::new(key.into())
            .decrypt(nonce.into(), Payload { msg: ct_and_tag, aad })
            // Причина провала не раскрывается: подставной чанк, чужой файл и
            // испорченный байт обязаны быть неразличимы для противника.
            .map_err(|_| CryptoError::Authentication),
        AeadAlg::Aes256Gcm | AeadAlg::Aes256GcmSiv => Err(CryptoError::UnsupportedAlgorithm),
    }
}

/// Запечатать чанк, ВЫВЕДЯ nonce внутри, и вернуть его вместе с листом дерева.
///
/// # Почему эта функция вообще существует
///
/// Потому что она физически не даёт передать nonce — а именно это и требуется,
/// когда чанк ПЕРЕЗАПИСЫВАЕТСЯ. Повтор nonce на одном ключе смертелен (И-1):
/// два разных открытых текста под одним потоком ключей раскрываются XOR-ом, а
/// одноразовый ключ Poly1305 позволяет подделать тег. Самый же естественный
/// приём при правке документа — «сохранить nonce, который уже лежит в кадре» —
/// ведёт ровно туда.
///
/// Сегодня перезапись безопасна не по замыслу, а по СЛЕДСТВИЮ хеджирования:
/// nonce выводится из засева и открытого текста, поэтому другой текст даёт
/// другой nonce сам собой. Свойство настоящее, но держится на том, что вызывающий
/// не станет умничать. Комментарием такое не удержать — удержать может только
/// подпись функции, в которой места для nonce нет.
///
/// Засев приходит параметром: в этом крейте нет генератора и не должно быть
/// (И-1 требует хранимых nonce, а не выведенных читателем, но выводит их
/// ОТПРАВИТЕЛЬ — из случайного засева ПЛЮС открытого текста, чтобы повтор
/// состояния генератора при откате снапшота не повторял nonce).
///
/// # Errors
/// Отдаёт [`CryptoError`] при отказе шифрования или неверной длине результата.
pub fn seal_chunk_hedged(
    key: &PayloadKey,
    alg: AeadAlg,
    file_id: &[u8; 16],
    index: u32,
    nonce_seed: &[u8; NONCE_LEN],
    plaintext: &[u8],
    out: &mut Vec<u8>,
) -> Result<([u8; NONCE_LEN], Leaf), CryptoError> {
    let aad = chunk_aad(file_id, index, alg);
    let nonce = crate::kdf::hedged_nonce::<NONCE_LEN>(crate::label::FRAME_NONCE, nonce_seed, plaintext, &aad)?;
    let leaf = seal_chunk_with_aad(key, alg, index, &nonce, plaintext, &aad, out)?;
    Ok((nonce, leaf))
}

/// Зашифровать чанк, дописав `шифротекст ‖ тег` в `out`, и вернуть лист дерева.
///
/// `out` очищается перед записью.
///
/// # Nonce здесь передаётся аргументом, и это ОПАСНАЯ форма
///
/// Она оставлена ради замороженных векторов и проб, которым нужен ровно тот
/// nonce, что записан в артефакте. Продуктовый путь ею не пользуется: там стоит
/// [`seal_chunk_hedged`], где nonce вывести можно, а передать нельзя.
///
/// Если вы пишете новый вызов и он не про KAT — вам нужна не эта функция.
/// Перезапись чанка с уже лежащим в кадре nonce уничтожает конфиденциальность
/// обоих текстов сразу (И-1).
///
/// # Почему за признаком, а не просто с предупреждением в докстроке
///
/// Потому что докстрока — не граница. Пока функция видна продукту, «опасная
/// форма» держится на том, что следующий вызывающий прочитает абзац выше;
/// признак `explicit-nonce` выключен по умолчанию и включён ТОЛЬКО через
/// `[dev-dependencies]`, поэтому продуктовая сборка этой функции не видит
/// вовсе — вызов не компилируется. Границу, видимую компилятору, нельзя
/// проглядеть в спешке.
#[cfg(any(test, feature = "explicit-nonce"))]
pub fn seal_chunk(
    key: &PayloadKey,
    alg: AeadAlg,
    file_id: &[u8; 16],
    index: u32,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    out: &mut Vec<u8>,
) -> Result<Leaf, CryptoError> {
    let aad = chunk_aad(file_id, index, alg);
    seal_chunk_with_aad(key, alg, index, nonce, plaintext, &aad, out)
}

// Один AAD используется и засевом, и AEAD; второй сборки контекста здесь нет.
fn seal_chunk_with_aad(
    key: &PayloadKey,
    alg: AeadAlg,
    index: u32,
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8; CHUNK_AAD_LEN],
    out: &mut Vec<u8>,
) -> Result<Leaf, CryptoError> {
    // Здесь достаточно `clear`: в `out` лежит шифротекст предыдущего чанка, а не
    // секрет. Затирание нужно на пути расшифрования, где в буфере открытый текст.
    out.clear();

    let sealed = seal_with(key.expose(), alg, nonce, plaintext, aad)?;
    // Тег — последние 16 байт: крейт возвращает `ct ‖ tag` одним вектором.
    // Разрезается он здесь потому, что в лист входят ОБЕ части, и по отдельности:
    // шифротекст связывает содержимое, тег — ключ и связанные данные.
    let (ct, tag) = sealed.split_last_chunk::<TAG_LEN>().ok_or(CryptoError::BadLength)?;
    let leaf = leaf_of(index, nonce, tag, ct);

    out.extend_from_slice(&sealed);
    Ok(leaf)
}

/// Расшифровать чанк в `out` и вернуть лист дерева, вычисленный по тегу.
///
/// При любой ошибке `out` очищается и затирается: вызывающий не должен иметь
/// возможности прочитать непроверенные байты.
pub fn open_chunk(
    key: &PayloadKey,
    alg: AeadAlg,
    file_id: &[u8; 16],
    index: u32,
    nonce: &[u8; NONCE_LEN],
    ct_and_tag: &[u8],
    out: &mut SecretBuf,
) -> Result<Leaf, CryptoError> {
    // Тип буфера, а не обычный `Vec<u8>`: гарантия затирания обязана держаться на
    // сигнатуре, а не на дисциплине вызывающего. Обычный вектор уносил бы
    // расшифрованный чанк в кучу при каждом уничтожении и при каждом росте.
    //
    // Затирание на входе и на выходе, а не только на входе: правило §6.5 обязано
    // держаться и после будущих правок тела, которые начнут писать в `out`
    // раньше проверки тега. Обёртка гарантирует его структурно.
    out.wipe();
    match open_chunk_inner(key, alg, file_id, index, nonce, ct_and_tag, out) {
        Ok(leaf) => Ok(leaf),
        Err(err) => {
            out.wipe();
            Err(err)
        }
    }
}

/// Тело расшифрования, вынесенное ради обёртки с затиранием: любая ошибка
/// возвращается наружу через [`open_chunk`], который гарантированно чистит `out`.
fn open_chunk_inner(
    key: &PayloadKey,
    alg: AeadAlg,
    file_id: &[u8; 16],
    index: u32,
    nonce: &[u8; NONCE_LEN],
    ct_and_tag: &[u8],
    out: &mut SecretBuf,
) -> Result<Leaf, CryptoError> {
    let (ct, tag) = ct_and_tag
        .split_last_chunk::<TAG_LEN>()
        .ok_or(CryptoError::BadLength)?;
    let aad = chunk_aad(file_id, index, alg);

    // Расшифровка идёт НА МЕСТЕ, в буфере вызывающего, и это не оптимизация.
    //
    // Раньше здесь выделялся `Zeroizing<Vec<u8>>` под открытый текст, и он
    // затирался при уничтожении — то есть защищал от того, что блок достанется
    // аллокатору читаемым. От второй беды он не защищал вовсе: блок обычной кучи
    // может уехать в файл подкачки, пока живёт. Просмотрщик запирает свою память
    // (`VirtualLock`) именно затем, чтобы этого не случилось, и промежуточная
    // копия в незапертой куче сводила бы всю меру на нет — на каждый чанк.
    //
    // Порядок операций здесь единственно возможный: сначала объявить длину, потом
    // скопировать шифротекст, потом расшифровать. Затирать буфер перед копией
    // нельзя не по соображениям скорости — `as_declared_mut` не затирает
    // намеренно: стереть буфер после копии значило бы стереть вход.
    let room = out.as_capacity_mut().get_mut(..ct.len()).ok_or(CryptoError::BadLength)?;
    room.copy_from_slice(ct);
    out.declare_len(ct.len())?;
    open_in_place(key.expose(), alg, nonce, out.as_declared_mut(), tag, &aad)?;

    // Лист считается по тем же величинам, что и при запечатывании, — по nonce,
    // тегу и **шифротексту**, — поэтому читатель сверяет чанк с деревом, не имея
    // исходного открытого текста и не имея ключа.
    Ok(leaf_of(index, nonce, tag, ct))
}

/// Запечатать приватные метаданные, ВЫВЕДЯ nonce внутри, и вернуть его рядом.
///
/// # Почему эта функция существует
///
/// По той же причине, что и [`seal_chunk_hedged`], и заведена она позже него не
/// потому, что метаданные безопаснее: хеджирование здесь было, но собирал его
/// ВЫЗЫВАЮЩИЙ — движок выводил nonce у себя и передавал сюда готовым. Пока шаг
/// вывода стоит снаружи, его можно не сделать, и подпись функции этому не
/// мешает: она принимает любые 24 байта. Повтор же здесь обходится дороже
/// всего — `CEK` и `header_salt` приходят из того же генератора, поэтому откат
/// снапшота ВМ повторял бы и ключ K5, и nonce, а открытые тексты (имя и размер
/// другого документа) различались бы.
///
/// Засев приходит параметром: генератора в этом крейте нет и быть не должно.
///
/// Возвращается пара `(nonce, шифротекст)`: nonce не секрет, но без него блок
/// не расшифровать, и в файл он кладётся готовым (И-1).
///
/// # Errors
/// Отдаёт [`CryptoError`] при отказе вывода nonce или шифрования.
pub fn seal_metadata_hedged(
    key: &MetaKey,
    file_id: &[u8; 16],
    nonce_seed: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<([u8; NONCE_LEN], Vec<u8>), CryptoError> {
    let aad = metadata_aad(file_id);
    // Метка своя (`"CC/v1/meta-nonce"`), а не чанковая: И-12 требует, чтобы два
    // разных вывода не совпали ни при каком совпадении остальных входов.
    let nonce =
        crate::kdf::hedged_nonce::<NONCE_LEN>(label::META_NONCE, nonce_seed, plaintext, &aad)?;
    let ct = seal_with(key.expose(), AeadAlg::XChaCha20Poly1305, &nonce, plaintext, &aad)?;
    Ok((nonce, ct))
}

/// Зашифровать приватные метаданные заголовка под собственным ключом K5.
///
/// # Nonce здесь передаётся аргументом, и это ОПАСНАЯ форма
///
/// Та же оговорка и тот же признак `explicit-nonce`, что у `seal_chunk`: форма
/// оставлена векторам и пробам, которым нужен ровно тот nonce, что записан в
/// артефакте. Продуктовый путь ходит через [`seal_metadata_hedged`], где nonce
/// вывести можно, а передать нельзя.
#[cfg(any(test, feature = "explicit-nonce"))]
pub fn seal_metadata(
    key: &MetaKey,
    file_id: &[u8; 16],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // Профиль здесь не выбирается: K5 определён спецификацией как XChaCha, а
    // поле `private_meta` лежит в заголовке, который подписан до всякого выбора.
    let aad = metadata_aad(file_id);
    seal_with(key.expose(), AeadAlg::XChaCha20Poly1305, nonce, plaintext, &aad)
}

/// Расшифровать приватные метаданные.
pub fn open_metadata(
    key: &MetaKey,
    file_id: &[u8; 16],
    nonce: &[u8; NONCE_LEN],
    ct_and_tag: &[u8],
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let aad = metadata_aad(file_id);
    // Настоящее имя файла и его размер — те самые данные, ради сокрытия
    // которых поле вообще существует, поэтому наружу они уходят только в
    // затирающей обёртке.
    let plaintext = open_with(key.expose(), AeadAlg::XChaCha20Poly1305, nonce, ct_and_tag, &aad)?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    const FILE_ID: [u8; 16] = [0x11; 16];
    const OTHER_FILE_ID: [u8; 16] = [0x12; 16];
    const NONCE: [u8; NONCE_LEN] = [0x21; NONCE_LEN];
    const CHUNK_64_KIB: usize = 65536;

    /// Ключ метаданных с ТЕМИ ЖЕ байтами, что и ключ полезной нагрузки.
    ///
    /// Совпадение намеренное: тест
    /// `private_metadata_never_opens_as_a_chunk` проверяет, что блок метаданных
    /// не подменяет чанк даже при совпавших ключе и nonce, то есть что защиту
    /// даёт разделение доменов в AAD, а не различие ключей. После разделения
    /// типов (`MetaKey` против `PayloadKey`) выразить «тот же ключ» иначе нельзя
    /// — и это ровно то, ради чего типы и разделены.
    fn meta_key() -> MetaKey {
        MetaKey::from_bytes([0x33; 32])
    }

    fn key() -> PayloadKey {
        PayloadKey::from_bytes([0x33; 32])
    }

    /// Наполнитель без повторяющегося блока: одинаковые блоки скрыли бы ошибку
    /// в раскладке кадра.
    fn payload(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8).collect()
    }

    #[test]
    fn chunk_aad_is_exactly_the_bytes_the_format_prescribes() {
        // Раскладка AAD — часть формата на диске: разъедься она с §6.1, файлы
        // одной сборки перестанут открываться другой.
        let aad = chunk_aad(&FILE_ID, 7, AeadAlg::XChaCha20Poly1305);
        let mut expected = Vec::new();
        expected.extend_from_slice(b"CC/v1/chunk");
        expected.extend_from_slice(&FILE_ID);
        expected.extend_from_slice(&7u32.to_be_bytes());
        expected.push(1);
        assert_eq!(expected.len(), CHUNK_AAD_LEN, "сумма полей AAD не 32 байта");
        assert_eq!(aad.as_slice(), expected.as_slice());
        assert_eq!(label::CHUNK.len(), 11, "метка чанка обязана быть 11 байт");
    }

    #[test]
    fn a_chunk_round_trips_at_every_boundary_length() {
        // Границы: пустой чанк (файл нулевой длины всё равно имеет чанк),
        // однобайтовый, неполный и полный чанк размера по умолчанию.
        for len in [0usize, 1, 65535, CHUNK_64_KIB] {
            let pt = payload(len);
            let mut frame = Vec::new();
            let sealed_leaf =
                seal_chunk(&key(), AeadAlg::XChaCha20Poly1305, &FILE_ID, 3, &NONCE, &pt, &mut frame)
                    .unwrap();
            assert_eq!(frame.len(), len.saturating_add(TAG_LEN), "кадр не равен ct‖tag");

            let mut got = SecretBuf::with_capacity(1 << 17);
            let opened_leaf =
                open_chunk(&key(), AeadAlg::XChaCha20Poly1305, &FILE_ID, 3, &NONCE, &frame, &mut got)
                    .unwrap();
            assert_eq!(got.as_slice(), pt.as_slice(), "длина {len}");
            assert_eq!(sealed_leaf, opened_leaf);
        }
    }

    #[test]
    fn the_leaf_from_sealing_equals_the_leaf_from_opening() {
        // Иначе читатель не смог бы сверить чанк с деревом, не расшифровав и не
        // перешифровав его заново.
        let pt = payload(1000);
        let mut frame = Vec::new();
        let sealed =
            seal_chunk(&key(), AeadAlg::XChaCha20Poly1305, &FILE_ID, 9, &NONCE, &pt, &mut frame)
                .unwrap();
        let mut got = SecretBuf::with_capacity(1 << 17);
        let opened =
            open_chunk(&key(), AeadAlg::XChaCha20Poly1305, &FILE_ID, 9, &NONCE, &frame, &mut got)
                .unwrap();
        assert_eq!(sealed, opened);
        // И лист действительно зависит от места чанка: иначе перестановка была бы
        // невидима дереву.
        let mut other = Vec::new();
        let neighbour =
            seal_chunk(&key(), AeadAlg::XChaCha20Poly1305, &FILE_ID, 10, &NONCE, &pt, &mut other)
                .unwrap();
        assert_ne!(sealed, neighbour);
    }

    #[test]
    fn a_chunk_offered_as_its_neighbour_does_not_open() {
        // Перестановка чанков внутри файла ловится тем, что номер входит в AAD.
        let pt = payload(4096);
        let mut frame = Vec::new();
        seal_chunk(&key(), AeadAlg::XChaCha20Poly1305, &FILE_ID, 4, &NONCE, &pt, &mut frame)
            .unwrap();

        let mut got = SecretBuf::with_capacity(1 << 17);
        let err =
            open_chunk(&key(), AeadAlg::XChaCha20Poly1305, &FILE_ID, 5, &NONCE, &frame, &mut got)
                .unwrap_err();
        assert_eq!(err, CryptoError::Authentication);
        assert!(got.is_empty());
    }

    #[test]
    fn a_chunk_from_another_file_does_not_open() {
        // Подстановка чанка из другого контейнера ловится тем, что file_id входит
        // в AAD, — при том что ключ у двух файлов теоретически может совпасть.
        let pt = payload(4096);
        let mut frame = Vec::new();
        seal_chunk(&key(), AeadAlg::XChaCha20Poly1305, &FILE_ID, 4, &NONCE, &pt, &mut frame)
            .unwrap();

        let mut got = SecretBuf::with_capacity(1 << 17);
        let err = open_chunk(
            &key(),
            AeadAlg::XChaCha20Poly1305,
            &OTHER_FILE_ID,
            4,
            &NONCE,
            &frame,
            &mut got,
        )
        .unwrap_err();
        assert_eq!(err, CryptoError::Authentication);
        assert!(got.is_empty());
    }

    #[test]
    fn flipping_any_byte_of_ciphertext_or_tag_is_caught() {
        let pt = payload(64);
        let mut frame = Vec::new();
        seal_chunk(&key(), AeadAlg::XChaCha20Poly1305, &FILE_ID, 0, &NONCE, &pt, &mut frame)
            .unwrap();

        for (pos, _) in frame.iter().enumerate() {
            let mut broken = frame.clone();
            *broken.get_mut(pos).unwrap() ^= 1;
            let mut got = SecretBuf::with_capacity(1 << 17);
            let err = open_chunk(
                &key(),
                AeadAlg::XChaCha20Poly1305,
                &FILE_ID,
                0,
                &NONCE,
                &broken,
                &mut got,
            )
            .unwrap_err();
            assert_eq!(err, CryptoError::Authentication, "байт {pos} прошёл проверку");
        }
    }

    #[test]
    fn a_failed_open_leaves_no_bytes_in_the_output_buffer() {
        // §6.5: непроверенные байты не покидают функцию. Проверяем на буфере,
        // который до вызова был непустым, — иначе тест прошёл бы и без затирания.
        let pt = payload(2048);
        let mut frame = Vec::new();
        seal_chunk(&key(), AeadAlg::XChaCha20Poly1305, &FILE_ID, 1, &NONCE, &pt, &mut frame)
            .unwrap();
        *frame.get_mut(0).unwrap() ^= 0xff;

        // Буфер намеренно непустой до вызова: проверяем, что неудача не только
        // не пишет новое, но и стирает то, что лежало раньше.
        let mut got = SecretBuf::with_capacity(4096);
        got.fill_from(&[0xaa; 4096]).unwrap();
        let err =
            open_chunk(&key(), AeadAlg::XChaCha20Poly1305, &FILE_ID, 1, &NONCE, &frame, &mut got)
                .unwrap_err();
        assert_eq!(err, CryptoError::Authentication);
        assert!(got.is_empty(), "в буфере осталось {} байт", got.len());

        // Слишком короткий кадр — тоже ошибка, и тоже с пустым буфером.
        let mut short = SecretBuf::with_capacity(32);
        let err = open_chunk(
            &key(),
            AeadAlg::XChaCha20Poly1305,
            &FILE_ID,
            1,
            &NONCE,
            &[0u8; 4],
            &mut short,
        )
        .unwrap_err();
        assert_eq!(err, CryptoError::BadLength);
        assert!(short.is_empty());
    }

    #[test]
    fn the_same_plaintext_under_different_nonces_never_repeats_a_ciphertext() {
        // Ради этого свойства nonce и хранится, а не выводится из (file_id, i):
        // при правке чанка nonce обязан смениться, иначе XOR двух шифротекстов
        // выдаёт оба открытых текста.
        let pt = payload(1024);
        let nonce_b: [u8; NONCE_LEN] = [0x22; NONCE_LEN];

        let mut first = Vec::new();
        seal_chunk(&key(), AeadAlg::XChaCha20Poly1305, &FILE_ID, 2, &NONCE, &pt, &mut first)
            .unwrap();
        let mut second = Vec::new();
        seal_chunk(&key(), AeadAlg::XChaCha20Poly1305, &FILE_ID, 2, &nonce_b, &pt, &mut second)
            .unwrap();

        assert_ne!(first, second, "тот же ключ и nonce дал бы повторное использование");
    }

    #[test]
    fn sealing_overwrites_whatever_the_output_buffer_held_before() {
        // Иначе кадр чанка склеился бы с предыдущим и файл стал бы нечитаемым.
        let pt = payload(10);
        let mut out = vec![0xcc; 100];
        seal_chunk(&key(), AeadAlg::XChaCha20Poly1305, &FILE_ID, 0, &NONCE, &pt, &mut out).unwrap();
        assert_eq!(out.len(), pt.len().saturating_add(TAG_LEN));
    }

    #[test]
    fn metadata_round_trips_under_its_own_key() {
        let meta = b"secret-report.docx\0application/pdf".to_vec();
        let sealed = seal_metadata(&meta_key(), &FILE_ID, &NONCE, &meta).unwrap();
        assert_eq!(sealed.len(), meta.len().saturating_add(TAG_LEN));
        let opened = open_metadata(&meta_key(), &FILE_ID, &NONCE, &sealed).unwrap();
        assert_eq!(opened.as_slice(), meta.as_slice());

        // Чужой file_id не открывает метаданные: заголовок нельзя перенести в
        // другой контейнер вместе с настоящим именем файла.
        let err = open_metadata(&meta_key(), &OTHER_FILE_ID, &NONCE, &sealed).unwrap_err();
        assert_eq!(err, CryptoError::Authentication);
    }

    #[test]
    fn private_metadata_never_opens_as_a_chunk() {
        // Разные метки домена: блок метаданных не подменяет чанк нулевого номера
        // даже при совпавшем ключе и nonce.
        let meta = payload(64);
        let sealed = seal_metadata(&meta_key(), &FILE_ID, &NONCE, &meta).unwrap();
        let mut got = SecretBuf::with_capacity(1 << 17);
        let err =
            open_chunk(&key(), AeadAlg::XChaCha20Poly1305, &FILE_ID, 0, &NONCE, &sealed, &mut got)
                .unwrap_err();
        assert_eq!(err, CryptoError::Authentication);
        assert!(got.is_empty());
    }

    #[test]
    fn unsupported_aead_profiles_are_refused_not_silently_substituted() {
        // Молчаливая подстановка другого шифра — понижение стойкости без следа в
        // формате. Отказ обязан быть явным на обоих направлениях.
        let pt = payload(32);
        for alg in [AeadAlg::Aes256Gcm, AeadAlg::Aes256GcmSiv] {
            let mut out = Vec::new();
            let err = seal_chunk(&key(), alg, &FILE_ID, 0, &NONCE, &pt, &mut out).unwrap_err();
            assert_eq!(err, CryptoError::UnsupportedAlgorithm);
            assert!(out.is_empty());

            let mut got = SecretBuf::with_capacity(1 << 17);
            let err =
                open_chunk(&key(), alg, &FILE_ID, 0, &NONCE, &[0u8; 48], &mut got).unwrap_err();
            assert_eq!(err, CryptoError::UnsupportedAlgorithm);
            assert!(got.is_empty());
        }
    }

    /// ОДИН ЗАСЕВ НА ДВА РАЗНЫХ ТЕКСТА ДАЁТ РАЗНЫЕ NONCE.
    ///
    /// # Ради чего этот тест стоит
    ///
    /// Ради перезаписи чанка, которой ещё нет. Когда она появится (фаза 6),
    /// самым естественным приёмом будет «взять nonce, который уже лежит в
    /// кадре» — и это уничтожило бы конфиденциальность обоих текстов сразу:
    /// один поток ключей на два разных открытых текста раскрывается XOR-ом, а
    /// одноразовый ключ Poly1305 позволяет подделать тег (И-1).
    ///
    /// Здесь проверяется, что защита от этого — СВОЙСТВО ВЫВОДА, а не
    /// дисциплина вызывающего: даже при полностью совпавшем засеве, то есть при
    /// откате снапшота ВМ, другой текст даёт другой nonce.
    #[test]
    fn the_same_seed_still_yields_different_nonces_for_different_plaintexts() {
        let seed = [0x33u8; NONCE_LEN];
        let mut first = Vec::new();
        let mut second = Vec::new();

        let (nonce_a, _) =
            seal_chunk_hedged(&key(), AeadAlg::XChaCha20Poly1305, &FILE_ID, 0, &seed, b"one", &mut first)
                .unwrap();
        let (nonce_b, _) =
            seal_chunk_hedged(&key(), AeadAlg::XChaCha20Poly1305, &FILE_ID, 0, &seed, b"two", &mut second)
                .unwrap();

        assert_ne!(nonce_a, nonce_b, "разный текст обязан дать разный nonce при том же засеве");
        assert_ne!(first, second);
    }

    /// А ОДИНАКОВЫЙ ТЕКСТ ПРИ ОДИНАКОВОМ ЗАСЕВЕ СОВПАДЁТ — И ЭТО ГРАНИЦА.
    ///
    /// Утверждается прямо, потому что это и есть остаток риска, названный в
    /// README: полный повтор состояния генератора ПРИ СОВПАДАЮЩЕМ открытом
    /// тексте даёт совпадающий шифротекст, раскрывая факт равенства входов.
    /// Тест сторожит, чтобы эта граница не уехала молча ни в одну сторону.
    #[test]
    fn the_same_seed_and_the_same_plaintext_repeat_and_that_is_the_known_limit() {
        let seed = [0x44u8; NONCE_LEN];
        let mut first = Vec::new();
        let mut second = Vec::new();

        let (nonce_a, _) =
            seal_chunk_hedged(&key(), AeadAlg::XChaCha20Poly1305, &FILE_ID, 0, &seed, b"same", &mut first)
                .unwrap();
        let (nonce_b, _) =
            seal_chunk_hedged(&key(), AeadAlg::XChaCha20Poly1305, &FILE_ID, 0, &seed, b"same", &mut second)
                .unwrap();

        assert_eq!(nonce_a, nonce_b);
        assert_eq!(first, second);
    }
}
