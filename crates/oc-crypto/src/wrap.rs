//! Content-key wrapping.
//!
//! CEK is random and **wrapped** under KEK, not derived from it. The distinction
//! is decisive: deriving `CEK = HKDF(A‖B)` would permanently hardwire exactly one key slot into
//! the format; the first customer asking for a second recipient, recovery key,
//! or rotation would break every previously issued file.

use crate::kdf::{slot_commitment, verify_commitment};
use rand_core::CryptoRng;
use crate::secret::{Cek, Kek, SECRET_LEN};
use crate::CryptoError;

use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305,
};
use zeroize::{Zeroize, Zeroizing};

/// Wrapping nonce length.
pub const WRAP_NONCE_LEN: usize = 24;

/// Wrapped CEK length: nonce, key, and tag.
///
/// The nonce is **stored, not derived**. Derived from KEK, it would be safe only
/// while each file had one (KEK, CEK) pair, an unenforced condition:
/// the public API does not prevent wrapping two different CEKs under one KEK,
/// repeating both key and nonce, with `wrapped₁ ⊕ wrapped₂ = CEK₁ ⊕ CEK₂`:
/// both content keys are exposed, and the one-time Poly1305 key is
/// reused, enabling forgery.
///
/// Twenty-four bytes are the cost of security resting on
/// construction rather than caller discipline.
pub const WRAPPED_CEK_LEN: usize = WRAP_NONCE_LEN + SECRET_LEN + 16;

/// Wrap CEK. Returns `(wrapped key, slot commitment)`.
///
/// `core_hash` enters associated data, so the wrapped key cannot move
/// to a container with another header.
pub fn wrap_cek<R: CryptoRng + ?Sized>(
    kek: &Kek,
    cek: &Cek,
    core_hash: &[u8; 32],
    rng: &mut R,
) -> Result<([u8; WRAPPED_CEK_LEN], [u8; 32]), CryptoError> {
    // Nonce хранится в файле. Подменить его противник может, но это ничего не
    // даёт: он входит в вычисление тега, и подмена ломает аутентификацию раньше,
    // чем что-либо расшифруется.
    //
    // Случайные байты идут в засев производной, а не прямо в nonce (С-13). Здесь
    // это нужно не меньше, чем при запечатывании слота: KEK у файла один, и
    // повтор состояния генератора при переупаковке того же файла с новым CEK дал
    // бы одинаковые ключ и nonce на двух разных открытых текстах, то есть
    // `wrapped₁ ⊕ wrapped₂ = CEK₁ ⊕ CEK₂`. Открытый текст здесь — сам ключ
    // содержимого, и он же входит в засев, поэтому два разных CEK получают
    // разные nonce даже при полностью повторившемся генераторе.
    let mut nonce_seed = Zeroizing::new([0u8; WRAP_NONCE_LEN]);
    rng.fill_bytes(nonce_seed.as_mut_slice());
    let nonce = crate::kdf::hedged_nonce::<WRAP_NONCE_LEN>(
        crate::label::WRAP_NONCE,
        nonce_seed.as_slice(),
        cek.expose().as_slice(),
        core_hash,
    )?;

    let cipher = XChaCha20Poly1305::new(kek.expose().into());
    let sealed = cipher
        .encrypt(
            (&nonce).into(),
            Payload {
                msg: cek.expose().as_slice(),
                aad: core_hash.as_slice(),
            },
        )
        .map_err(|_| CryptoError::Authentication)?;

    // Ровно nonce, ключ и тег. Длина проверяется, а не подразумевается: срез
    // другой длины дальше пошёл бы в заголовок как «завёрнутый CEK» и
    // обнаружился бы только при попытке открыть файл.
    let mut wrapped = [0u8; WRAPPED_CEK_LEN];
    let (head, tail) = wrapped.split_at_mut(WRAP_NONCE_LEN);
    head.copy_from_slice(&nonce);
    if tail.len() != sealed.len() {
        return Err(CryptoError::BadLength);
    }
    tail.copy_from_slice(&sealed);

    Ok((wrapped, slot_commitment(kek, core_hash)))
}

/// Unwrap CEK.
///
/// The slot commitment is checked in constant time **before** opening AEAD.
/// Order is essential: XChaCha20-Poly1305 is not key-committing; without
/// this check a low-entropy claim code can be recovered through a partitioning
/// oracle substantially faster than exhaustive search.
pub fn unwrap_cek(
    kek: &Kek,
    wrapped: &[u8; WRAPPED_CEK_LEN],
    commitment: &[u8; 32],
    core_hash: &[u8; 32],
) -> Result<Cek, CryptoError> {
    // Первым делом и только потом всё остальное. Противник, подбирающий
    // код-претензию, строит обёртку, которая открывается под многими
    // кандидатами KEK; обязательство — единственное, что делает кандидата
    // отличимым от правильного ключа ценой одного HMAC.
    verify_commitment(&slot_commitment(kek, core_hash), commitment)?;

    // Nonce из первых байтов обёртки, шифротекст с тегом — из остальных.
    let (nonce, sealed) = wrapped.split_at(WRAP_NONCE_LEN);
    let nonce: [u8; WRAP_NONCE_LEN] =
        nonce.try_into().map_err(|_| CryptoError::BadLength)?;

    let cipher = XChaCha20Poly1305::new(kek.expose().into());
    let mut opened = cipher
        .decrypt(
            (&nonce).into(),
            Payload { msg: sealed, aad: core_hash.as_slice() },
        )
        .map_err(|_| CryptoError::Authentication)?;

    let converted: Result<[u8; SECRET_LEN], _> = opened.as_slice().try_into();
    // Открытый CEK успел полежать в куче. Затираем до возврата, независимо от
    // того, сошлась длина или нет: непроверенные и уже ненужные байты наружу не
    // уходят.
    opened.zeroize();

    let mut bytes = converted.map_err(|_| CryptoError::BadLength)?;
    let cek = Cek::from_bytes(bytes);
    // `from_bytes` копирует массив, а копия секрета на стеке не имеет владельца,
    // который затрёт её при уничтожении, — затираем руками.
    bytes.zeroize();
    Ok(cek)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    const CORE_HASH: [u8; 32] = [0x0c; 32];
    const OTHER_CORE_HASH: [u8; 32] = [0x0d; 32];

    /// Deterministic RNG: the test must reproduce byte for byte.
    struct TestRng(u64);

    impl TestRng {
        fn step(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        }
    }

    impl rand_core::TryRng for TestRng {
        type Error = core::convert::Infallible;
        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(self.step() as u32)
        }
        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(self.step())
        }
        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            for chunk in dst.chunks_mut(8) {
                let word = self.step().to_le_bytes();
                for (out, src) in chunk.iter_mut().zip(word.iter()) {
                    *out = *src;
                }
            }
            Ok(())
        }
    }
    impl rand_core::TryCryptoRng for TestRng {}

    #[test]
    fn two_different_ceks_under_one_kek_never_share_a_keystream() {
        // Дефект, ради которого nonce стал храниться. При выведенном из KEK
        // nonce два CEK под одним KEK давали один поток ключей, и XOR обёрток
        // раскрывал оба ключа содержимого. Теперь nonce независим, и XOR не даёт
        // ничего.
        let other_cek = Cek::from_bytes([0x77; 32]);
        let (first, _) = wrap_cek(&kek(), &cek(), &CORE_HASH, &mut TestRng(1)).unwrap();
        let (second, _) = wrap_cek(&kek(), &other_cek, &CORE_HASH, &mut TestRng(2)).unwrap();

        let expected: Vec<u8> = cek()
            .expose()
            .iter()
            .zip(other_cek.expose().iter())
            .map(|(a, b)| a ^ b)
            .collect();
        let actual: Vec<u8> = first
            .iter()
            .skip(WRAP_NONCE_LEN)
            .take(SECRET_LEN)
            .zip(second.iter().skip(WRAP_NONCE_LEN).take(SECRET_LEN))
            .map(|(a, b)| a ^ b)
            .collect();

        assert_ne!(actual, expected, "XOR обёрток раскрывает XOR ключей: nonce повторился");
    }

    fn kek() -> Kek {
        Kek::from_bytes([0x5e; 32])
    }

    fn cek() -> Cek {
        Cek::from_bytes([0xc3; 32])
    }

    #[test]
    fn a_wrapped_cek_round_trips_under_the_same_kek() {
        let (wrapped, commitment) = wrap_cek(&kek(), &cek(), &CORE_HASH, &mut TestRng(7)).unwrap();
        let opened = unwrap_cek(&kek(), &wrapped, &commitment, &CORE_HASH).unwrap();
        assert_eq!(opened.expose(), cek().expose());
    }

    #[test]
    fn the_wrapped_cek_is_the_key_plus_an_authentication_tag() {
        // 72 байта — не украшение: длина закреплена в формате, и лишний байт
        // сместил бы всё, что лежит за слотом.
        //
        // Здесь стояло «48», и это была дозасевная раскладка: 32 байта ключа плюс
        // 16 тега, без nonce. Nonce переехал В ОБЁРТКУ пунктом С-13 — прежняя
        // конструкция выводила его из KEK, то есть читатель мог его вычислить, и
        // номер производной K2 за это сожжён. Число в комментарии осталось от
        // сожжённой конструкции и утверждало неправду с видом истины.
        let (wrapped, _) = wrap_cek(&kek(), &cek(), &CORE_HASH, &mut TestRng(7)).unwrap();
        assert_eq!(wrapped.len(), WRAPPED_CEK_LEN);
        assert_eq!(WRAPPED_CEK_LEN, WRAP_NONCE_LEN + SECRET_LEN + 16, "nonce, ключ и тег");
        // И это шифротекст, а не сам ключ: совпадение первых 32 байт с CEK
        // означало бы, что ключ лежит в контейнере открытым.
        assert!(wrapped.iter().skip(WRAP_NONCE_LEN).take(SECRET_LEN).ne(cek().expose().iter()));
    }

    #[test]
    fn a_tampered_commitment_is_refused_even_though_the_aead_would_open() {
        // ЧТО ЭТА ПРОБА ДОКАЗЫВАЕТ: испорченное обязательство отвергается, хотя
        // всё остальное во входе честно и AEAD открылся бы. То есть проверка
        // обязательства ЕСТЬ и она несущая, а не украшение.
        //
        // ЧЕГО ОНА НЕ ДОКАЗЫВАЕТ — и здесь стояло обратное. Комментарий называл
        // её «ключевым тестом порядка проверок» и утверждал, что перестановка
        // проверки после открытия AEAD её уронит. Это неправда, и проверено
        // мутацией: при переставленных строках проба остаётся зелёной. Причина
        // в том, что коды ошибок у обеих проверок УРАВНЕНЫ НАМЕРЕННО (см.
        // соседнюю `a_wrong_commitment_and_a_wrong_tag_are_indistinguishable`),
        // а при верном KEK оба порядка дают одно и то же значение. Порядок
        // поведением НЕ РАЗЛИЧИМ — ни этой пробой, ни какой-либо другой.
        //
        // КТО СТЕРЕЖЁТ ПОРЯДОК: сторож по тексту
        // `the_order_of_checks_is_the_one_the_invariants_require` в
        // `crates/cc-cli/tests/repository_hygiene.rs`. Он читает тело
        // `unwrap_cek` и требует, чтобы вызов `verify_commitment` стоял РАНЬШЕ
        // вызова `.decrypt(`. Текстовый сторож здесь не лень, а предел метода:
        // доказать порядок поведением нечем, пока коды ошибок одинаковы, а
        // делать их разными нельзя — это и был бы оракул.
        let (wrapped, commitment) = wrap_cek(&kek(), &cek(), &CORE_HASH, &mut TestRng(7)).unwrap();
        let mut tampered = commitment;
        if let Some(byte) = tampered.get_mut(0) {
            *byte ^= 0x01;
        }
        // Сравнивается `err()`, а не сам `Result`: у `Cek` намеренно нет
        // `PartialEq`, чтобы ключи не сравнивались обычным `==` в переменном
        // времени.
        assert_eq!(
            unwrap_cek(&kek(), &wrapped, &tampered, &CORE_HASH).err(),
            Some(CryptoError::Authentication)
        );
        // И тот же вход с настоящим обязательством открывается — значит отказ
        // выше дало именно обязательство, а не что-то ещё во входных данных.
        assert!(unwrap_cek(&kek(), &wrapped, &commitment, &CORE_HASH).is_ok());
    }

    #[test]
    fn a_slot_moved_to_another_header_is_refused_by_the_commitment() {
        // ЧТО ДОКАЗАНО: перенос слота целиком — обёртка и обязательство из
        // одного контейнера, `core_hash` из другого — отвергается.
        //
        // ЧЕМ ИМЕННО отвергается: обязательством. Оно считается от `core_hash`,
        // поэтому при чужом заголовке расходится и отказ приходит из
        // `verify_commitment`, ДО AEAD. Проба называлась
        // `a_wrapped_cek_does_not_move_to_a_container_with_another_core_hash` и
        // читалась как проверка связанных данных — а до связанных данных
        // исполнение не доходило вовсе. Мутация «AAD пуст» оставалась
        // незамеченной здесь и падала только этажом выше, на golden-контейнерах.
        // Связанные данные проверяет соседняя проба, где обязательство СОШЛОСЬ.
        let (wrapped, commitment) = wrap_cek(&kek(), &cek(), &CORE_HASH, &mut TestRng(7)).unwrap();
        assert_eq!(
            unwrap_cek(&kek(), &wrapped, &commitment, &OTHER_CORE_HASH).err(),
            Some(CryptoError::Authentication)
        );
    }

    #[test]
    fn the_core_hash_is_bound_by_the_aead_itself_and_not_only_by_the_commitment() {
        // Случай, которого не хватало: обязательство СХОДИТСЯ, а `core_hash` у
        // AEAD другой. Тогда первая проверка пропускает, и отказать может
        // только связывание по AAD (И-2) — больше нечему.
        //
        // Собирается это без всяких приватных уловок: `slot_commitment` — часть
        // публичной поверхности крейта (`oc_crypto::kdf::slot_commitment`), и
        // ровно так же обязательство считает `oc-engine`, собирая слот. Проба
        // живёт рядом с остальными пробами обёртки только потому, что это её
        // место по смыслу.
        //
        // ЧТО ДОКАЗАНО: байты обёртки, снятые под одним заголовком, не
        // открываются под другим, даже если противник пересчитал обязательство
        // под новый заголовок — а пересчитать его он может, KEK у него есть, он
        // законный получатель этого слота. Именно поэтому одного обязательства
        // мало и AAD несёт `core_hash`.
        let (wrapped, _) = wrap_cek(&kek(), &cek(), &CORE_HASH, &mut TestRng(7)).unwrap();

        // Обязательство ПОД ДРУГОЙ заголовок, тем же KEK.
        let recomputed = slot_commitment(&kek(), &OTHER_CORE_HASH);
        // Предпосылка пробы: первая проверка эти байты пропускает. Без этой
        // строки проба не отличала бы «отказал AEAD» от «отказало обязательство».
        assert!(
            verify_commitment(&slot_commitment(&kek(), &OTHER_CORE_HASH), &recomputed).is_ok(),
            "предпосылка неверна: обязательство не сходится, до AEAD дело не дойдёт"
        );

        assert_eq!(
            unwrap_cek(&kek(), &wrapped, &recomputed, &OTHER_CORE_HASH).err(),
            Some(CryptoError::Authentication),
            "обёртка открылась под чужим core_hash: связанных данных нет"
        );
    }

    #[test]
    fn a_foreign_kek_never_unwraps() {
        let (wrapped, commitment) = wrap_cek(&kek(), &cek(), &CORE_HASH, &mut TestRng(7)).unwrap();
        let foreign = Kek::from_bytes([0x5f; 32]);
        assert_eq!(
            unwrap_cek(&foreign, &wrapped, &commitment, &CORE_HASH).err(),
            Some(CryptoError::Authentication)
        );
    }

    #[test]
    fn a_flipped_bit_in_the_wrapped_key_is_refused() {
        let (wrapped, commitment) = wrap_cek(&kek(), &cek(), &CORE_HASH, &mut TestRng(7)).unwrap();
        for position in [0usize, SECRET_LEN, 47] {
            let mut broken = wrapped;
            if let Some(byte) = broken.get_mut(position) {
                *byte ^= 0x80;
            }
            assert_eq!(
                unwrap_cek(&kek(), &broken, &commitment, &CORE_HASH).err(),
                Some(CryptoError::Authentication),
                "правка байта {position} осталась незамеченной"
            );
        }
    }

    #[test]
    fn a_wrong_commitment_and_a_wrong_tag_are_indistinguishable() {
        // Разные варианты ошибки дали бы противнику бит информации о том, какая
        // именно проверка не прошла, и вернули бы оракул через сообщение об
        // ошибке вместо тайминга.
        let (wrapped, commitment) = wrap_cek(&kek(), &cek(), &CORE_HASH, &mut TestRng(7)).unwrap();
        let mut tampered_commitment = commitment;
        if let Some(byte) = tampered_commitment.get_mut(0) {
            *byte ^= 0x01;
        }
        let mut tampered_tag = wrapped;
        if let Some(byte) = tampered_tag.get_mut(47) {
            *byte ^= 0x01;
        }
        let by_commitment = unwrap_cek(&kek(), &wrapped, &tampered_commitment, &CORE_HASH).err();
        let by_tag = unwrap_cek(&kek(), &tampered_tag, &commitment, &CORE_HASH).err();
        assert_eq!(by_commitment, Some(CryptoError::Authentication));
        assert_eq!(by_commitment, by_tag);
    }

    #[test]
    fn wrapping_is_deterministic_in_the_injected_generator_and_only_in_it() {
        // Комментарий этого теста утверждал обратное тому, что делает код:
        // «nonce выводится из KEK, поэтому повтор упаковки детерминирован… это
        // позволяет переписать слот, не храня nonce». Nonce берётся из
        // генератора (см. `wrap_cek`) и **хранится** в обёртке — это инвариант
        // всего формата (docs/format.md §3.1). Текст пережил смену дизайна и
        // утверждал опасную неправду с видом истины: следуй ему вторая
        // реализация, она перестала бы хранить nonce и получила бы его повтор
        // при первой же переупаковке.
        //
        // Детерминизм здесь есть, но у него другой источник и другой смысл: он
        // держится ровно на том, что генератор инжектируется, и нужен для
        // golden-контейнеров.
        let first = wrap_cek(&kek(), &cek(), &CORE_HASH, &mut TestRng(7)).unwrap();
        let second = wrap_cek(&kek(), &cek(), &CORE_HASH, &mut TestRng(7)).unwrap();
        assert_eq!(first, second, "при одном сиде обёртка обязана совпадать побайтно");

        // И обратное: другой сид — другая обёртка. Без этой половины тест
        // проходил бы и на выведенном из KEK nonce, то есть не отличал бы
        // текущую конструкцию от той, которую описывал прежний комментарий.
        let third = wrap_cek(&kek(), &cek(), &CORE_HASH, &mut TestRng(9)).unwrap();
        assert_ne!(first, third, "nonce не зависит от генератора — значит, выводится");
    }

    #[test]
    fn two_containers_never_share_a_slot_commitment() {
        // Обязательство лежит в контейнере открытым текстом. Совпадение у двух
        // файлов сделало бы его меткой связности: видно, что файлы завёрнуты
        // одним KEK.
        let (_, first) = wrap_cek(&kek(), &cek(), &CORE_HASH, &mut TestRng(7)).unwrap();
        let (_, second) = wrap_cek(&kek(), &cek(), &OTHER_CORE_HASH, &mut TestRng(9)).unwrap();
        assert_ne!(first, second);
    }
}
