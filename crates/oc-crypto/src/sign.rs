// SPDX-License-Identifier: MPL-2.0
//! Domain-separated signatures over [`Transcript`] values.
//!
//! Transcript construction requires a registry label. Verification uses
//! `verify_strict` to reject small-order points and noncanonical representations.
//! The [`Signer`] trait also supports providers that retain their private key.

use crate::transcript::Transcript;
use crate::{CryptoError, SigAlg};
use rand_core::CryptoRng;
use zeroize::Zeroize;

/// Ed25519 signature length.
pub const SIGNATURE_LEN: usize = 64;
/// Ed25519 public-key length.
pub const PUBLIC_KEY_LEN: usize = 32;

/// Something capable of signing. Implemented by software keys now and
/// TPM keys in phase 1.
pub trait Signer {
    /// Algorithm used by this implementation.
    fn alg(&self) -> SigAlg;
    /// Public verification key.
    fn public_key(&self) -> [u8; PUBLIC_KEY_LEN];
    /// Sign a transcript.
    fn sign(&self, transcript: &Transcript) -> Result<[u8; SIGNATURE_LEN], CryptoError>;
}

/// Software Ed25519 signer.
pub struct Ed25519Signer {
    key: ed25519_dalek::SigningKey,
}

impl core::fmt::Debug for Ed25519Signer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Ed25519Signer(<приватный ключ скрыт>)")
    }
}

impl Ed25519Signer {
    /// Construct from a seed.
    ///
    /// Input is specifically a seed (32 bytes before SHA-512 expansion), not a ready-made scalar.
    /// All serialization formats store keys this way, as does the
    /// hardware's output, so moving signing to a TPM in phase 1 leaves
    /// this function's input unchanged.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self { key: ed25519_dalek::SigningKey::from_bytes(seed) }
    }

    /// Generate using the supplied RNG.
    ///
    /// The RNG is an argument, not an environmental `OsRng`. Otherwise tests cease
    /// to be deterministic and call sites cease to be verifiable: substituting the
    /// entropy source for an author signature could not be caught by a test.
    pub fn generate<R: CryptoRng + ?Sized>(rng: &mut R) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let signer = Self::from_seed(&seed);
        // Семя — это и есть приватный ключ целиком; копия на стеке живёт до
        // конца функции и попадёт в файл подкачки вместе с ней. Затирание не
        // спасает от копий, сделанных компилятором (§7 спецификации), но
        // сокращает окно, и стоит это одну инструкцию.
        seed.zeroize();
        signer
    }
}

impl Signer for Ed25519Signer {
    fn alg(&self) -> SigAlg {
        SigAlg::Ed25519
    }

    fn public_key(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.key.verifying_key().to_bytes()
    }

    fn sign(&self, transcript: &Transcript) -> Result<[u8; SIGNATURE_LEN], CryptoError> {
        // Подписываются ровно байты транскрипта, без единого дополнительного
        // префикса. Метка домена уже стоит в начале транскрипта, и второй слой
        // разделения дал бы два разных ответа на вопрос «что именно подписано» —
        // ту самую неоднозначность, на которой построено семейство ошибок
        // канонизации JWS и XML-DSig.
        //
        // `try_sign`, а не `sign`: у `sign` внутри `expect`, и хотя для Ed25519
        // подписание не отказывает, в крейте не должно быть путей, ведущих к
        // панике на данных.
        let signature = ed25519_dalek::Signer::try_sign(&self.key, transcript.as_bytes())
            .map_err(|_| CryptoError::BadSignature)?;
        Ok(signature.to_bytes())
    }
}

/// Verify a signature.
///
/// Returns only signature validity. **Trust in the signer is a separate
/// decision** taken above: a signature checked with a key from the same
/// header is self-signed and proves nothing.
pub fn verify(
    public_key: &[u8; PUBLIC_KEY_LEN],
    transcript: &Transcript,
    signature: &[u8; SIGNATURE_LEN],
) -> Result<(), CryptoError> {
    // Публичный ключ приходит из непроверенного заголовка, то есть от
    // противника. Некорректная точка кривой — это отказ, а не паника: разбор
    // враждебного ввода не имеет права уронить процесс.
    let key = ed25519_dalek::VerifyingKey::from_bytes(public_key)
        .map_err(|_| CryptoError::BadSignature)?;

    // Ошибка разбора ключа и ошибка проверки подписи намеренно неразличимы
    // снаружи: разный ответ выдал бы противнику лишний бит о том, какая именно
    // часть заголовка не сошлась.
    let signature = ed25519_dalek::Signature::from_bytes(signature);

    // Только `verify_strict`. Обычный `verify` принимает подпись при `A` или `R`
    // малого порядка и при неканоническом кодировании `A`, из-за чего одну и ту
    // же подпись удаётся заставить пройти под несколькими ключами. Для формата,
    // где подпись заголовка и есть идентичность файла, свойство «одна подпись —
    // один файл» обязано выполняться буквально, иначе отзыв и журнал перестают
    // однозначно указывать на файл.
    key.verify_strict(transcript.as_bytes(), &signature).map_err(|_| CryptoError::BadSignature)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::label;

    /// Deterministic test RNG: SplitMix64. Real entropy is
    /// unnecessary and harmful here: the test must reproduce byte for byte.
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

    /// A "label plus one data field" transcript: the minimal carrier of the property
    /// checked by the tests below.
    fn transcript_of(domain: crate::label::Label, data: &[u8]) -> Transcript {
        let mut t = Transcript::new(domain);
        t.field(data);
        t
    }

    #[test]
    fn a_signature_verifies_under_the_key_that_produced_it() {
        let mut rng = TestRng(1);
        let signer = Ed25519Signer::generate(&mut rng);
        let t = transcript_of(label::HEADER_SIG, b"canonical header bytes");

        let signature = signer.sign(&t).unwrap();

        assert_eq!(signer.alg(), SigAlg::Ed25519);
        assert_eq!(verify(&signer.public_key(), &t, &signature), Ok(()));
    }

    #[test]
    fn a_signature_never_verifies_under_a_foreign_public_key() {
        let mut rng = TestRng(2);
        let author = Ed25519Signer::generate(&mut rng);
        let stranger = Ed25519Signer::generate(&mut rng);
        assert_ne!(author.public_key(), stranger.public_key());

        let t = transcript_of(label::HEADER_SIG, b"canonical header bytes");
        let signature = author.sign(&t).unwrap();

        assert_eq!(
            verify(&stranger.public_key(), &t, &signature),
            Err(CryptoError::BadSignature),
            "подпись обязана быть привязана к своему ключу"
        );
    }

    #[test]
    fn a_signature_does_not_carry_over_to_another_domain_label() {
        // Свойство, ради которого вообще существует Transcript. Без метки
        // подпись автора над заголовком принималась бы как его же подпись под
        // записью отзыва или под выдачей права: данные те же, контекст другой.
        let mut rng = TestRng(3);
        let author = Ed25519Signer::generate(&mut rng);
        let data = b"same bytes in both contexts";

        let header = transcript_of(label::HEADER_SIG, data);
        let revocation = transcript_of(label::REVOCATION, data);
        let signature = author.sign(&header).unwrap();

        assert_eq!(verify(&author.public_key(), &header, &signature), Ok(()));
        assert_eq!(
            verify(&author.public_key(), &revocation, &signature),
            Err(CryptoError::BadSignature),
            "подпись из одного домена не должна приниматься в другом"
        );
    }

    #[test]
    fn flipping_a_single_data_byte_breaks_verification() {
        let mut rng = TestRng(4);
        let author = Ed25519Signer::generate(&mut rng);
        let mut data = *b"header bytes";

        let signature = author.sign(&transcript_of(label::HEADER_SIG, &data)).unwrap();

        // Индексация запрещена линтом даже в тестах — берём через get_mut.
        if let Some(byte) = data.get_mut(5) {
            *byte ^= 0x01;
        }
        assert_eq!(
            verify(&author.public_key(), &transcript_of(label::HEADER_SIG, &data), &signature),
            Err(CryptoError::BadSignature)
        );
    }

    #[test]
    fn flipping_a_single_signature_byte_breaks_verification() {
        let mut rng = TestRng(5);
        let author = Ed25519Signer::generate(&mut rng);
        let t = transcript_of(label::HEADER_SIG, b"header bytes");
        let signature = author.sign(&t).unwrap();

        for position in [0usize, 31, 63] {
            let mut broken = signature;
            if let Some(byte) = broken.get_mut(position) {
                *byte ^= 0x80;
            }
            assert_eq!(
                verify(&author.public_key(), &t, &broken),
                Err(CryptoError::BadSignature),
                "испорченный байт подписи №{position} прошёл проверку"
            );
        }
    }

    #[test]
    fn a_garbage_public_key_yields_an_error_and_never_panics() {
        // Публичный ключ читается из заголовка, который контролирует противник.
        // `[0u8; 32]` — это корректная точка кривой малого порядка (её `verify`
        // без `strict` пропустил бы), `[0xff; 32]` — неканоническое кодирование.
        // Оба обязаны дать Err по общему пути, а не панику и не Ok.
        let mut rng = TestRng(6);
        let author = Ed25519Signer::generate(&mut rng);
        let t = transcript_of(label::HEADER_SIG, b"header bytes");
        let signature = author.sign(&t).unwrap();

        for junk in [[0u8; PUBLIC_KEY_LEN], [0xffu8; PUBLIC_KEY_LEN]] {
            assert_eq!(
                verify(&junk, &t, &signature),
                Err(CryptoError::BadSignature),
                "мусорный публичный ключ {junk:?} не должен ни проходить, ни ронять процесс"
            );
        }

        // И мусорная подпись при честном ключе — тоже отказ, а не паника.
        assert_eq!(
            verify(&author.public_key(), &t, &[0xffu8; SIGNATURE_LEN]),
            Err(CryptoError::BadSignature)
        );
    }

    /// Strict verification rejects a small-order forgery that lax verification accepts.
    ///
    /// The vector uses identity points for `A` and `R` (`01` then 31 zeroes), with
    /// `S = 0`. The equation `[0]B = R + h·A` reduces to `identity = identity` for
    /// any message. The lax dependency check is the positive control; without it,
    /// rejection would not distinguish strict verification from generic invalid input.
    #[test]
    fn a_small_order_forgery_is_refused_although_the_lax_check_would_take_it() {
        // Нейтральный элемент в сжатом виде: y = 1, то есть `01` и 31 ноль.
        let mut public_key = [0u8; PUBLIC_KEY_LEN];
        if let Some(byte) = public_key.get_mut(0) {
            *byte = 1;
        }
        // Подпись: R — тот же нейтральный элемент, S — нули.
        let mut signature = [0u8; SIGNATURE_LEN];
        if let Some(byte) = signature.get_mut(0) {
            *byte = 1;
        }

        // Сообщение здесь неважно — в том и беда, — но домен берётся настоящий:
        // проба должна говорить о нашем пути, а не о голой кривой. Сообщений
        // два, потому что «годна для ЛЮБОГО сообщения» и есть свойство этой
        // подделки: на одном сообщении совпадение можно было бы счесть удачей.
        for data in [b"header bytes".as_slice(), b"entirely different bytes".as_slice()] {
            let t = transcript_of(label::HEADER_SIG, data);

            // Половина первая: НЕСТРОГАЯ проверка этот вектор ПРИНИМАЕТ.
            let lax_key = ed25519_dalek::VerifyingKey::from_bytes(&public_key).unwrap();
            let lax_signature = ed25519_dalek::Signature::from_bytes(&signature);
            assert!(
                ed25519_dalek::Verifier::verify(&lax_key, t.as_bytes(), &lax_signature).is_ok(),
                "нестрогая проверка отвергла вектор малого порядка: различителя между \
                 `verify` и `verify_strict` через эту зависимость больше нет, и \
                 поведенческий сторож за И-6 надо признать невозможным, а не чинить"
            );

            // Половина вторая: наш путь его ОТВЕРГАЕТ.
            assert_eq!(
                verify(&public_key, &t, &signature),
                Err(CryptoError::BadSignature),
                "подпись под ключом малого порядка принята: это `verify` вместо \
                 `verify_strict`, и «одна подпись — один файл» больше не выполняется (И-6)"
            );
        }
    }

    #[test]
    fn the_same_seed_always_yields_the_same_public_key() {
        // Детерминизм — не удобство, а условие воспроизводимости: тот же seed
        // обязан давать тот же ключ на другой машине и в другой сборке, иначе
        // резервная копия семени перестаёт быть резервной копией ключа.
        let seed = [0x42u8; 32];
        let a = Ed25519Signer::from_seed(&seed);
        let b = Ed25519Signer::from_seed(&seed);

        assert_eq!(a.public_key(), b.public_key());

        // И подписи совпадают: Ed25519 детерминирован по построению, поэтому
        // здесь нет скрытой зависимости от источника случайности.
        let t = transcript_of(label::HEADER_SIG, b"header bytes");
        assert_eq!(a.sign(&t).unwrap(), b.sign(&t).unwrap());
    }

    #[test]
    fn generate_takes_all_its_randomness_from_the_supplied_generator() {
        // Два генератора одного состояния дают один и тот же ключ. Если бы
        // `generate` подмешивала энтропию из окружения, тест бы упал — а вместе
        // с ним рухнула бы и возможность прогнать тестовые векторы через
        // собственные места вызова.
        let mut first = TestRng(7);
        let mut second = TestRng(7);
        assert_eq!(
            Ed25519Signer::generate(&mut first).public_key(),
            Ed25519Signer::generate(&mut second).public_key()
        );

        // И подряд идущие вызовы дают разные ключи: генератор действительно
        // продвигается, а не переиспользует одно состояние.
        assert_ne!(
            Ed25519Signer::generate(&mut first).public_key(),
            Ed25519Signer::generate(&mut first).public_key()
        );
    }

    #[test]
    fn debug_never_leaks_the_private_key() {
        // Приватный ключ в логе или в отчёте о панике утекает так же, как
        // записанный на диск.
        let signer = Ed25519Signer::from_seed(&[0xabu8; 32]);
        let rendered = format!("{signer:?}");
        assert!(!rendered.contains("ab"), "Debug выдал байты ключа: {rendered}");
        assert!(rendered.contains("скрыт"));
    }
}
