//! Секреты чужих крейтов затираются при уничтожении — а не только наши.
//!
//! `seal::open` делает КОПИЮ долговременного секрета устройства в
//! `x25519_dalek::StaticSecret` ради `diffie_hellman`, и результат согласования
//! живёт в `SharedSecret`. Обе живут на стеке, и затирающий аллокатор их не
//! касается: затирает только сам тип при `Drop`. У `x25519-dalek` это фича
//! `zeroize`, и с `default-features = false` она снимается вместе с остальными —
//! ровно так и было (ревью 2026-09-06): `Drop` был пуст, копия секрета
//! устройства оставалась в кадре стека как есть.
//!
//! Проверка — на уровне типов: без фичи `ZeroizeOnDrop` у `StaticSecret` нет, и
//! этот файл не собирается. Собрался — значит, фича стоит.

fn zeroizes_on_drop<T: zeroize::ZeroizeOnDrop>() {}

#[test]
fn foreign_secret_types_zeroize_on_drop() {
    zeroizes_on_drop::<x25519_dalek::StaticSecret>();
    zeroizes_on_drop::<x25519_dalek::EphemeralSecret>();
    zeroizes_on_drop::<oc_crypto::secret::X25519Secret>();
    zeroizes_on_drop::<oc_crypto::secret::SecretA>();
    zeroizes_on_drop::<oc_crypto::secret::SecretB>();
}
