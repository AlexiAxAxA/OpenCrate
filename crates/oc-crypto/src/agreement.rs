// SPDX-License-Identifier: MPL-2.0
//! Software and hardware key agreement behind one trait.
//!
//! A provider can perform agreement without releasing its private key to Seal.
//! Software X25519/P-256 live here; platform TPM adapters implement the trait
//! outside this pure crate.

use zeroize::Zeroizing;

use crate::CryptoError;

/// Shared-secret length: 32 bytes for both X25519 and P-256.
///
/// The equality is not accidental and need not last: X25519 returns a
/// point multiplication result, P-256 the shared point's X coordinate, both 32 bytes for
/// 256-bit curves. A mechanism with a different field size would give a different value,
/// turning this constant into a function of the mechanism.
pub const SHARED_SECRET_LEN: usize = 32;

/// Shared secret bytes, with an explicit big-endian constructor.
///
/// P-256 providers supply the big-endian X coordinate. Microsoft Platform
/// Crypto Provider returns NCrypt agreement bytes in little-endian order;
/// its adapter must reverse them before calling the constructor.
#[derive(Clone)]
pub struct SharedSecret(Zeroizing<[u8; SHARED_SECRET_LEN]>);

impl SharedSecret {
    /// The only constructor. Bytes must be big-endian.
    #[must_use]
    pub fn from_be_bytes(bytes: [u8; SHARED_SECRET_LEN]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// Secret for key derivation. Crate-internal: the shared secret is not exposed externally.
    pub(crate) fn expose(&self) -> &[u8; SHARED_SECRET_LEN] {
        &self.0
    }

    /// Compare two secrets in constant time.
    ///
    /// A named method rather than derived `PartialEq`: derivation would compare
    /// bytes conventionally, returning early at the first difference,
    /// which is a guessing oracle (I-13). A type for which `==` is unsafe should not
    /// provide it at all.
    ///
    /// Needed externally: the hardware agreement implementation must be checked against
    /// the software implementation using identical keys, and comparing
    /// secrets is the only way to do that.
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

/// An agreement party: its own half is known; the peer's half is input.
///
/// The trait is deliberately narrow: two operations. All we need from a TPM is
/// its public key and agreement with a peer; no private key appears in the trait, nor
/// can one appear, or hardware implementations could not implement the very trait
/// introduced for them.
pub trait KeyAgreement {
    /// This party's public key, in its wire representation.
    ///
    /// Returns a `Vec`, not an array: X25519 uses 32 bytes and P-256 uses 65
    /// (an uncompressed SEC1 point). The mechanism determines the form, which `oc-format`
    /// validates against the length table; this trait does not.
    fn public_key(&self) -> Vec<u8>;

    /// Agree on a shared secret with the other party's public key.
    ///
    /// Implementations must reject peer keys off the curve and points
    /// of small order. This is materially different for P-256 and X25519:
    /// any 32-byte string is a valid X25519 public key, whereas a P-256
    /// point off the curve enables an invalid-curve attack, and `enc`
    /// comes from a **hostile file**. Relying on the underlying library to perform
    /// this check is insufficient; it must be stated as a contract.
    fn agree(&self, peer_public: &[u8]) -> Result<SharedSecret, CryptoError>;
}

/// Software X25519: a party that possesses its private key.
///
/// Wraps an existing secret rather than introducing another key storage method.
/// Ensures X25519 and P-256 paths pass through the same trait;
/// otherwise one mechanism would have an abstraction and the other a direct call,
/// allowing them to diverge unnoticed.
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

/// Software P-256: a keypair living in process memory.
///
/// Required for two reasons, both essential. First, testability: without it the entire
/// P-256 slot path could only be tested on a TPM-equipped machine, meaning
/// not at all in CI. Second, software binding: a device
/// without a suitable TPM must work, honestly declaring software binding rather than
/// refusing to start.
pub struct P256Agreement {
    secret: p256::SecretKey,
}

impl core::fmt::Debug for P256Agreement {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("P256Agreement(<ключ скрыт>)")
    }
}

impl P256Agreement {
    /// Create a pair using an RNG passed as a parameter.
    ///
    /// The RNG must be a parameter: RNG dependencies are forbidden in this crate;
    /// `getrandom` once leaked in transitively and was caught by a wasm32
    /// build. Tests must also be deterministic.
    ///
    /// `generate_from_rng`, not `SecretKey::random`: the latter is deprecated.
    /// The first attempt called nonexistent `generate`, caught by compilation;
    /// the trait method uses its full name.
    pub fn generate<R: rand_core::CryptoRng + ?Sized>(rng: &mut R) -> Self {
        use p256::elliptic_curve::Generate as _;

        Self { secret: p256::SecretKey::generate_from_rng(rng) }
    }

    /// Restore a pair from private-key bytes (a big-endian scalar).
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

    /// Keys are specified as bytes rather than generated: the test must be
    /// deterministic, and RNGs enter this crate only as parameters.
    fn p256_pair(byte: u8) -> P256Agreement {
        P256Agreement::from_be_bytes(&[byte; 32]).expect("скаляр в диапазоне")
    }

    #[test]
    fn a_p256_public_key_is_sixty_five_bytes_of_uncompressed_point() {
        let pk = p256_pair(0x11).public_key();
        assert_eq!(pk.len(), 65, "форма на проводе задана форматом: несжатая точка");
        assert_eq!(pk.first(), Some(&0x04), "префикс несжатой точки SEC1");
    }

    /// Both parties must reach the same secret, or the slot will not open,
    /// appearing as file corruption.
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

    /// An off-curve point is rejected rather than fed into multiplication.
    ///
    /// This protects against invalid-curve attacks and is specifically needed for P-256: `enc`
    /// comes from a hostile file, and an off-curve point allows extracting
    /// parts of the private key by observing agreement results. X25519 needs
    /// no such check: any 32-byte string is valid, a property
    /// of the curve rather than a concession.
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

    /// Both implementations reject lengths inconsistent with the mechanism.
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

    /// Low-level P-256 agreement accepts compressed and uncompressed SEC1 points.
    /// Both represent the same point and yield the same secret. Seal separately
    /// requires the canonical 65-byte uncompressed form for its wire/KDF context.
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

    /// The secret is never printed, in logs or error text (I-11).
    #[test]
    fn a_shared_secret_never_prints_itself() {
        let secret = SharedSecret::from_be_bytes([0xab; 32]);
        let shown = format!("{secret:?}");
        assert!(!shown.contains("ab"), "секрет попал в Debug: {shown}");
        assert!(shown.contains("скрыт"));
    }
}
