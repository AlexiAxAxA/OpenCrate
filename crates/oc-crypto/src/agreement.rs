//! Согласование ключей за трейтом: X25519 в коде, P-256 в коде или в TPM.
//!
//! Модуль существует ради одного свойства: приватный ключ может не покидать
//! железо. `NCryptSecretAgreement` возвращает общий секрет, но не ключ, поэтому
//! вывести ключ AEAD «взяв приватный ключ и посчитав DH» нельзя в принципе —
//! операция согласования обязана быть точкой расширения, а не деталью функции
//! запечатывания. Именно поэтому конструкция запечатывания написана вручную по
//! образцу RFC 9180, а не взята готовым HPKE-крейтом: готовый требует ключ.
//!
//! Крейт при этом остаётся чистым. Здесь только абстракция и программные
//! реализации; TPM живёт в `cc-keystore`, который зависит от этого трейта, а не
//! наоборот.

use zeroize::Zeroizing;

use crate::CryptoError;

/// Длина общего секрета: 32 байта и у X25519, и у P-256.
///
/// Совпадение не случайно и не обязано сохраниться: у X25519 это результат
/// умножения точки, у P-256 — координата X общей точки, обе по 32 байта для
/// 256-битных кривых. Механизм с другим размером поля даст другое число, и тогда
/// эта константа станет функцией механизма.
pub const SHARED_SECRET_LEN: usize = 32;

/// Общий секрет согласования, в **big-endian**.
///
/// ## Почему конструктор один и почему он назван по порядку байтов
///
/// Спайк `spikes/tpm-ecdh` обнаружил то, что стоило бы пропустить молча:
/// `NCryptSecretAgreement` с Microsoft Platform Crypto Provider отдаёт общий
/// секрет **little-endian**, тогда как все чистые реализации P-256 — включая
/// `p256` — работают с big-endian представлением координаты X, и RFC 5903 (ECDH
/// для IKE) предписывает именно его.
///
/// Порядок байтов, оставленный комментарием, — это ошибка, ждущая своего дня:
/// перевёрнутый секрет даёт другой ключ AEAD, слот не открывается, и выглядит это
/// как «файл повреждён». Ошибку нашли бы, но не там, где она есть.
///
/// Поэтому конструктор здесь **ровно один**, и он называет порядок в своём имени.
/// Реализация, получившая байты от NCrypt, обязана их развернуть, чтобы вызвать
/// его не соврав; забыть об этом молча нельзя — другого входа в тип нет.
#[derive(Clone)]
pub struct SharedSecret(Zeroizing<[u8; SHARED_SECRET_LEN]>);

impl SharedSecret {
    /// Единственный конструктор. Байты обязаны быть big-endian.
    #[must_use]
    pub fn from_be_bytes(bytes: [u8; SHARED_SECRET_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Секрет для вывода ключа. Внутри крейта: наружу общий секрет не отдаётся.
    pub(crate) fn expose(&self) -> &[u8; SHARED_SECRET_LEN] {
        &self.0
    }

    /// Сравнить два секрета константным временем.
    ///
    /// Именованный метод, а не производный `PartialEq`: производный сравнивал бы
    /// байты обычным способом, то есть с ранним выходом на первом расхождении, — а
    /// это оракул подбора (И-13). Тип, у которого `==` небезопасен, не должен его
    /// иметь вовсе.
    ///
    /// Нужен снаружи: аппаратная реализация согласования обязана быть сверена с
    /// программной на одних и тех же ключах, и сверять их иначе как сравнением
    /// секретов нечем.
    #[must_use]
    pub fn ct_eq(&self, other: &Self) -> bool {
        use subtle::ConstantTimeEq as _;
        bool::from(self.0.ct_eq(&*other.0))
    }
}

// `Debug` печатает заглушку: секрет не попадает в логи и тексты ошибок (И-11).
impl core::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SharedSecret(<скрыт>)")
    }
}

/// Сторона согласования: своя половина известна, чужая приходит на вход.
///
/// Трейт умышленно узкий — две операции. Всё, что нужно от TPM, это отдать
/// публичный ключ и согласовать с чужим; приватного ключа в трейте нет и быть не
/// может, иначе аппаратная реализация его не удовлетворит, а ради неё трейт и
/// заведён.
pub trait KeyAgreement {
    /// Публичный ключ этой стороны — в той форме, в которой он идёт на провод.
    ///
    /// Возвращает `Vec`, а не массив: у X25519 это 32 байта, у P-256 — 65
    /// (несжатая точка SEC1). Форму задаёт механизм, и проверяет её `oc-format`
    /// по таблице длин, а не этот трейт.
    fn public_key(&self) -> Vec<u8>;

    /// Согласовать общий секрет с публичным ключом другой стороны.
    ///
    /// Реализация обязана отвергнуть чужой ключ, не лежащий на кривой, и точку
    /// малого порядка. Для P-256 это существенно иначе, чем для X25519: у
    /// X25519 любая 32-байтовая строка — законный публичный ключ, а у P-256
    /// точка, не лежащая на кривой, открывает атаку invalid-curve, и `enc`
    /// приходит из **враждебного файла**. Полагаться на то, что проверку
    /// выполнит библиотека внутри, нельзя — она обязана быть названа контрактом.
    fn agree(&self, peer_public: &[u8]) -> Result<SharedSecret, CryptoError>;
}

/// X25519 в коде: сторона, у которой приватный ключ есть.
///
/// Обёртка вокруг существующего секрета, а не новый способ хранить ключ. Нужна
/// затем, чтобы путь X25519 и путь P-256 проходили через один и тот же трейт, —
/// иначе у одного механизма была бы абстракция, а у другого прямой вызов, и
/// разойтись они могли бы незаметно.
pub struct X25519Agreement<'a> {
    secret: &'a crate::secret::X25519Secret,
}

// `Debug` вручную и без ключа: производный напечатал бы приватный ключ, а секреты
// не попадают ни в логи, ни в `Debug`, ни в тексты ошибок (И-11). Публичный ключ
// тоже не печатается — он вычисляется, и `Debug` не место для вычислений.
impl core::fmt::Debug for X25519Agreement<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("X25519Agreement(<ключ скрыт>)")
    }
}

impl<'a> X25519Agreement<'a> {
    #[must_use]
    pub fn new(secret: &'a crate::secret::X25519Secret) -> Self {
        Self { secret }
    }
}

impl KeyAgreement for X25519Agreement<'_> {
    fn public_key(&self) -> Vec<u8> {
        let sk = x25519_dalek::StaticSecret::from(*self.secret.expose());
        x25519_dalek::PublicKey::from(&sk).to_bytes().to_vec()
    }

    fn agree(&self, peer_public: &[u8]) -> Result<SharedSecret, CryptoError> {
        let peer: [u8; 32] = peer_public.try_into().map_err(|_| CryptoError::BadLength)?;
        let sk = x25519_dalek::StaticSecret::from(*self.secret.expose());
        let shared = sk.diffie_hellman(&x25519_dalek::PublicKey::from(peer));
        // Нулевой секрет — точка малого порядка. Отсекается не здесь, а в выводе
        // ключа: проверка там одна на оба механизма, и дублировать её значило бы
        // однажды поправить только одну из двух копий.
        Ok(SharedSecret::from_be_bytes(*shared.as_bytes()))
    }
}

/// P-256 в коде: пара, живущая в памяти процесса.
///
/// Нужна для двух вещей, и обе обязательны. Первая — проверяемость: без неё весь
/// путь к слоту на P-256 тестировался бы только на машине с TPM, то есть не
/// тестировался бы в CI вовсе. Вторая — программная ступень привязки: устройство
/// без пригодного TPM обязано работать, честно объявив привязку программной, а не
/// отказывать в запуске.
pub struct P256Agreement {
    secret: p256::SecretKey,
}

impl core::fmt::Debug for P256Agreement {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("P256Agreement(<ключ скрыт>)")
    }
}

impl P256Agreement {
    /// Создать пару из генератора, переданного параметром.
    ///
    /// Генератор именно параметром: RNG в этом крейте запрещён как зависимость —
    /// `getrandom` однажды уже протекал сюда транзитивно и был выловлен сборкой
    /// под wasm32, — а тесты обязаны быть детерминированными.
    ///
    /// `generate_from_rng`, а не `SecretKey::random`: второй объявлен устаревшим.
    /// Первая попытка звала `generate`, которого не существует, и сборка это
    /// поймала — метод трейта называется полным именем.
    pub fn generate<R: rand_core::CryptoRng + ?Sized>(rng: &mut R) -> Self {
        use p256::elliptic_curve::Generate as _;

        Self { secret: p256::SecretKey::generate_from_rng(rng) }
    }

    /// Восстановить пару из байтов приватного ключа (big-endian скаляр).
    pub fn from_be_bytes(bytes: &[u8; 32]) -> Result<Self, CryptoError> {
        let secret = p256::SecretKey::from_slice(bytes).map_err(|_| CryptoError::BadKey)?;
        Ok(Self { secret })
    }
}

impl KeyAgreement for P256Agreement {
    fn public_key(&self) -> Vec<u8> {
        // Несжатая точка: `0x04 ‖ X ‖ Y`, 65 байт. Форма на проводе задана
        // форматом (§2.0) и продиктована PCP, который сжатой не отдаёт.
        use p256::elliptic_curve::sec1::ToSec1Point as _;

        // `to_sec1_point(false)` — несжатая форма ЯВНО, а не по умолчанию
        // библиотеки: значение уходит на провод, и его форма задана форматом.
        // Смена умолчания в зависимости была бы сменой байтов контейнера.
        self.secret.public_key().to_sec1_point(false).to_bytes().to_vec()
    }

    fn agree(&self, peer_public: &[u8]) -> Result<SharedSecret, CryptoError> {
        // Разбор точки — он же проверка того, что она лежит на кривой:
        // `from_sec1_bytes` отвергает и точку вне кривой, и точку в
        // бесконечности. Для P-256 это не формальность, а защита от атаки
        // invalid-curve: `enc` приходит из ВРАЖДЕБНОГО файла, и точка вне кривой
        // позволяет вытягивать приватный ключ по частям. У X25519 такой проблемы
        // нет — там законна любая 32-байтовая строка, — и именно поэтому проверку
        // нельзя было оставить общей на два механизма.
        let peer =
            p256::PublicKey::from_sec1_bytes(peer_public).map_err(|_| CryptoError::BadKey)?;

        let shared = p256::ecdh::diffie_hellman(self.secret.to_nonzero_scalar(), peer.as_affine());

        // `raw_secret_bytes` отдаёт координату X в big-endian — то же
        // представление, которое требует RFC 5903 и которое обещает
        // `SharedSecret::from_be_bytes`. NCrypt на этом месте отдаёт
        // little-endian, и разворот — обязанность аппаратной реализации.
        let bytes: [u8; SHARED_SECRET_LEN] =
            shared.raw_secret_bytes().as_slice().try_into().map_err(|_| CryptoError::BadLength)?;
        Ok(SharedSecret::from_be_bytes(bytes))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// Ключи задаются байтами, а не генератором: тест обязан быть
    /// детерминированным, а RNG в этом крейте приходит только параметром.
    fn p256_pair(byte: u8) -> P256Agreement {
        P256Agreement::from_be_bytes(&[byte; 32]).expect("скаляр в диапазоне")
    }

    #[test]
    fn a_p256_public_key_is_sixty_five_bytes_of_uncompressed_point() {
        let pk = p256_pair(0x11).public_key();
        assert_eq!(pk.len(), 65, "форма на проводе задана форматом: несжатая точка");
        assert_eq!(pk.first(), Some(&0x04), "префикс несжатой точки SEC1");
    }

    /// Обе стороны обязаны прийти к одному секрету — иначе слот не откроется, и
    /// выглядеть это будет как повреждённый файл.
    #[test]
    fn both_sides_of_a_p256_agreement_reach_the_same_secret() {
        let a = p256_pair(0x11);
        let b = p256_pair(0x22);

        let from_a = a.agree(&b.public_key()).unwrap();
        let from_b = b.agree(&a.public_key()).unwrap();
        assert_eq!(from_a.expose(), from_b.expose());
    }

    #[test]
    fn both_sides_of_an_x25519_agreement_reach_the_same_secret() {
        let sa = crate::secret::X25519Secret::from_bytes([0x33; 32]);
        let sb = crate::secret::X25519Secret::from_bytes([0x44; 32]);
        let a = X25519Agreement::new(&sa);
        let b = X25519Agreement::new(&sb);

        let from_a = a.agree(&b.public_key()).unwrap();
        let from_b = b.agree(&a.public_key()).unwrap();
        assert_eq!(from_a.expose(), from_b.expose());
    }

    /// Точка, не лежащая на кривой, отвергается — а не скармливается умножению.
    ///
    /// Это защита от атаки invalid-curve, и она нужна именно P-256: `enc`
    /// приходит из враждебного файла, а точка вне кривой позволяет вытягивать
    /// приватный ключ по частям, наблюдая результаты согласования. У X25519
    /// проверки нет и не нужно — там законна любая 32-байтовая строка, и это
    /// свойство кривой, а не поблажка.
    #[test]
    fn a_point_off_the_curve_is_refused_rather_than_multiplied() {
        let a = p256_pair(0x11);

        // Правильная длина и правильный префикс, но координаты выдуманы.
        let mut bogus = vec![0x04u8];
        bogus.extend_from_slice(&[0xab; 64]);
        assert_eq!(bogus.len(), 65, "длина верна: отказ обязан быть по кривой");
        assert!(a.agree(&bogus).is_err(), "точка вне кривой принята");

        // Точка в бесконечности — отдельный случай, тоже отказ.
        assert!(a.agree(&[0x00]).is_err(), "точка в бесконечности принята");
    }

    /// Длина, не соответствующая механизму, отвергается обеими реализациями.
    #[test]
    fn a_public_key_of_the_wrong_length_is_refused() {
        let p = p256_pair(0x11);
        // Тридцать три байта с префиксом НЕсжатой точки — не форма SEC1 вообще:
        // ни одна из двух форм так не выглядит. Сообщение называет именно это,
        // а не «сжатую форму»: см. пробу ниже, где разобрано, почему прежняя
        // формулировка была неправдой.
        assert!(p.agree(&[0x04; 33]).is_err(), "P-256 принял 33 байта с префиксом 0x04");
        assert!(p.agree(&[0x00; 32]).is_err(), "P-256 принял 32 байта");

        let s = crate::secret::X25519Secret::from_bytes([0x55; 32]);
        let x = X25519Agreement::new(&s);
        assert!(x.agree(&[0x00; 65]).is_err(), "X25519 принял 65 байт");
    }

    /// Сжатую точку `agree` ПРИНИМАЕТ, и запрет сжатой формы живёт не здесь.
    ///
    /// Прежняя редакция соседней пробы утверждала обратное — «P-256 принял сжатую
    /// форму» — и кормила `agree` тридцатью тремя байтами `0x04`. Это не сжатая
    /// точка: сжатая начинается с `0x02` или `0x03`, а `0x04` — префикс несжатой.
    /// Отказ приходил от разбора SEC1, то есть проба зеленела по посторонней
    /// причине, а свойства, о котором она говорила, у `agree` нет вовсе:
    /// `from_sec1_bytes` разбирает обе формы, и обе дают один и тот же секрет.
    ///
    /// Свойство, которого требует спека (§3.3: `enc` при `kem_id = 2` — ровно 65
    /// байт, несжатая точка), исполняется таблицей ТОЧНЫХ ДЛИН в `oc-format`, и
    /// разделение здесь намеренное: оно записано в докстроке
    /// [`KeyAgreement::agree`] — форму на проводе проверяет формат, а не трейт
    /// согласования. Иначе аппаратная реализация обязана была бы повторить
    /// таблицу длин у себя, и две копии одной таблицы разошлись бы.
    ///
    /// Проба закрепляет фактическое поведение слоя, а не желаемое: заявление о
    /// сжатой форме, которое можно проверить, — в `oc-format`.
    #[test]
    fn a_compressed_p256_point_is_accepted_here_and_yields_the_same_secret() {
        use p256::elliptic_curve::sec1::ToSec1Point as _;

        let a = p256_pair(0x11);
        let b = p256_pair(0x22);

        let uncompressed = b.public_key();
        let compressed = b.secret.public_key().to_sec1_point(true).to_bytes().to_vec();
        assert_eq!(compressed.len(), 33, "сжатая точка SEC1 — 33 байта");
        assert!(
            matches!(compressed.first(), Some(0x02 | 0x03)),
            "префикс сжатой точки: {:?}",
            compressed.first()
        );

        let from_uncompressed = a.agree(&uncompressed).expect("несжатая форма отвергнута");
        let from_compressed =
            a.agree(&compressed).expect("сжатая форма отвергнута: поведение слоя изменилось");
        assert!(
            from_compressed.ct_eq(&from_uncompressed),
            "сжатая и несжатая формы одного ключа дали разные секреты"
        );
    }

    /// Секрет не печатается: ни в логи, ни в текст ошибки (И-11).
    #[test]
    fn a_shared_secret_never_prints_itself() {
        let secret = SharedSecret::from_be_bytes([0xab; 32]);
        let shown = format!("{secret:?}");
        assert!(!shown.contains("ab"), "секрет попал в Debug: {shown}");
        assert!(shown.contains("скрыт"));
    }
}
