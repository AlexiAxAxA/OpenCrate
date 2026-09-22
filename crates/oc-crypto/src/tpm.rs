//! Защита учётных данных TPM 2.0 — вычислимая часть `TPM2_MakeCredential`
//! (B6a, `docs/protocol.md` §9.11).
//!
//! # Зачем это в ядре
//!
//! Сервер привязывает ключ удостоверителя к ключу подтверждения активацией
//! учётных данных: шифрует секрет так, что открыть его может только TPM, в
//! котором живут оба ключа. Всё, кроме блочного шифра, — хеш-вычисления без
//! ввода-вывода, часов и генератора: засев приходит параметром, как всякая
//! случайность в этом крейте, и каждый тест детерминирован.
//!
//! # Форма — не наша
//!
//! TPM 2.0, часть 1, «Credential Protection», и KDFa из той же части (SP 800-108
//! в режиме счётчика на HMAC). Метки `"STORAGE"`, `"INTEGRITY"`, `"IDENTITY"`
//! принадлежат спецификации TPM и в реестр меток домена (И-12) не входят: их
//! выбирали не мы и поменять их нельзя. Метка передаётся ВМЕСТЕ с завершающим
//! нулём — так её хеширует эталонная реализация TPM, и так её ждёт настоящий
//! TPM; расхождение здесь молча давало бы учётные данные, которые ни один TPM не
//! откроет. Поэтому форма подтверждена не чтением спецификации, а активацией
//! программным TPM (`crates/cc-authority/tests/attest/`).

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

/// Длина засева: дайджест SHA-256 — `nameAlg` ключа подтверждения.
pub const SEED_LEN: usize = 32;
/// Длина симметричного ключа учётных данных: AES-128.
pub const STORAGE_KEY_LEN: usize = 16;
/// Метка OAEP при шифровании засева на ключ подтверждения — с нулём.
pub const IDENTITY_LABEL: &[u8] = b"IDENTITY\0";

const STORAGE: &[u8] = b"STORAGE\0";
const INTEGRITY: &[u8] = b"INTEGRITY\0";

/// KDFa(SHA-256): `K(i) = HMAC(key, u32(i) ‖ label ‖ contextU ‖ contextV ‖ u32(L))`.
///
/// Метка приходит уже с нулём на конце. Длина выхода — целое число байтов, и
/// длины здесь только две (128 и 256 бит), поэтому хвостовой маски нет.
fn kdfa(key: &[u8], label: &[u8], context_u: &[u8], context_v: &[u8], out: &mut [u8]) {
    let bits = u32::try_from(out.len().saturating_mul(8)).unwrap_or(u32::MAX).to_be_bytes();
    for (counter, chunk) in (1u32..).zip(out.chunks_mut(32)) {
        // `new_from_slice` у HMAC принимает ключ любой длины: ошибка недостижима.
        if let Ok(mut mac) = <Hmac<Sha256> as KeyInit>::new_from_slice(key) {
            mac.update(&counter.to_be_bytes());
            mac.update(label);
            mac.update(context_u);
            mac.update(context_v);
            mac.update(&bits);
            let block = Zeroizing::new(mac.finalize().into_bytes());
            let take = chunk.len();
            if let Some(head) = block.get(..take) {
                chunk.copy_from_slice(head);
            }
        }
    }
}

/// Ключ AES-128 учётных данных: `KDFa(seed, "STORAGE", имя объекта, пусто, 128)`.
#[must_use]
pub fn storage_key(seed: &[u8; SEED_LEN], object_name: &[u8]) -> Zeroizing<[u8; STORAGE_KEY_LEN]> {
    let mut key = Zeroizing::new([0u8; STORAGE_KEY_LEN]);
    kdfa(seed, STORAGE, object_name, &[], key.as_mut_slice());
    key
}

/// Целостность учётных данных: `HMAC(KDFa(seed, "INTEGRITY", пусто, пусто, 256),
/// encIdentity ‖ имя объекта)`.
///
/// Имя объекта входит сюда, и именно это делает учётные данные адресными: TPM
/// считает тег по имени того ключа, которым его просят активировать, и чужой
/// ключ получает несовпадение, а не секрет.
#[must_use]
pub fn integrity_tag(seed: &[u8; SEED_LEN], enc_identity: &[u8], object_name: &[u8]) -> [u8; 32] {
    let mut hmac_key = Zeroizing::new([0u8; 32]);
    kdfa(seed, INTEGRITY, &[], &[], hmac_key.as_mut_slice());
    let mut tag = [0u8; 32];
    if let Ok(mut mac) = <Hmac<Sha256> as KeyInit>::new_from_slice(hmac_key.as_slice()) {
        mac.update(enc_identity);
        mac.update(object_name);
        tag.copy_from_slice(mac.finalize().into_bytes().as_slice());
    }
    tag
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// Ключ и тег зависят от имени объекта и от засева — иначе учётные данные
    /// не были бы ни адресными, ни одноразовыми.
    #[test]
    fn keys_depend_on_the_seed_and_the_name() {
        let seed = [7u8; SEED_LEN];
        let name_a = [1u8; 34];
        let name_b = [2u8; 34];
        assert_ne!(*storage_key(&seed, &name_a), *storage_key(&seed, &name_b));
        assert_ne!(*storage_key(&seed, &name_a), *storage_key(&[8u8; SEED_LEN], &name_a));
        assert_ne!(integrity_tag(&seed, b"x", &name_a), integrity_tag(&seed, b"x", &name_b));
        assert_ne!(integrity_tag(&seed, b"x", &name_a), integrity_tag(&seed, b"y", &name_a));
    }

    /// Метки несут завершающий ноль: без него KDFa даёт другой ключ, и TPM
    /// учётные данные не откроет. Сторожит правку «уберём лишний ноль».
    #[test]
    fn tpm_labels_carry_their_terminating_zero() {
        for label in [STORAGE, INTEGRITY, IDENTITY_LABEL] {
            assert_eq!(label.last(), Some(&0u8));
            assert_eq!(label.iter().filter(|b| **b == 0).count(), 1);
        }
    }

    /// Выход длиннее одного блока HMAC склеивается из блоков со счётчиком 1, 2…
    #[test]
    fn kdfa_counter_starts_at_one_and_advances() {
        let mut long = [0u8; 40];
        kdfa(b"key", b"L\0", b"u", b"v", &mut long);
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(b"key").unwrap();
        mac.update(&1u32.to_be_bytes());
        mac.update(b"L\0uv");
        mac.update(&320u32.to_be_bytes());
        assert_eq!(&long[..32], mac.finalize().into_bytes().as_slice());
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(b"key").unwrap();
        mac.update(&2u32.to_be_bytes());
        mac.update(b"L\0uv");
        mac.update(&320u32.to_be_bytes());
        assert_eq!(&long[32..], &mac.finalize().into_bytes()[..8]);
    }
}
