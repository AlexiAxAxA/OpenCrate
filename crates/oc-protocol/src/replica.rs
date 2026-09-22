//! Реплика состояния сервера: толчок и подтверждение (E2, B4;
//! `docs/protocol.md` §9.17).
//!
//! # Что это и чего это не даёт
//!
//! Реплика — отдельный процесс, который принимает снимки состояния сервера и
//! подтверждает КОНКРЕТНЫЕ байты своей подписью. Профиль `witnessed` означает,
//! что сервер не отдаёт успех, пока такого подтверждения нет; `mirrored` —
//! что копия уходит после успеха и у хвоста ненулевой RPO.
//!
//! Чего это не даёт: другой машины. Реплика в соседнем процессе или контейнере
//! переживает падение сервера, но не диск, не машину и не человека с правами
//! администратора. Обещание профиля — ровно «подтверждённые операции переживут
//! потерю СЕРВЕРА», и границу эту называет и сервер, и реплика.
//!
//! # Непрерывность
//!
//! Толчок несёт номер фиксации и отпечаток ПРЕДЫДУЩЕГО снимка. Реплика
//! принимает только продолжение своей истории: разрыв — `SnapshotRequired`,
//! тот же номер с другим отпечатком — `HistoryConflict`. Первое — повод
//! послать снимок заново, второе — улика: две истории одного сервера.

use oc_format::FormatError;
use oc_format::tlv::{TlvReader, TlvWriter};
use oc_crypto::sign::Signer;
use oc_crypto::transcript::Transcript;
use oc_crypto::{label, sha256};

/// Версия раскладки обоих документов.
pub const VERSION: u8 = 1;
/// Предел снимка состояния: столько же, сколько сообщение провода.
pub const MAX_STATE: usize = 2 * 1024 * 1024;

const SIG: usize = oc_crypto::sign::SIGNATURE_LEN;
const KEY: usize = oc_crypto::sign::PUBLIC_KEY_LEN;

fn bad(tag: u16, len: usize) -> FormatError {
    FormatError::BadFieldLength { tag, len }
}

mod push_tag {
    pub const VERSION: u16 = 1;
    pub const AUTHORITY_ID: u16 = 2;
    pub const EPOCH: u16 = 3;
    pub const SEQ: u16 = 4;
    pub const PREVIOUS: u16 = 5;
    pub const STATE_HASH: u16 = 6;
    pub const SNAPSHOT: u16 = 7;
    pub const AT: u16 = 8;
    pub const STATE: u16 = 9;
}

mod ack_tag {
    pub const VERSION: u16 = 1;
    pub const AUTHORITY_ID: u16 = 2;
    pub const EPOCH: u16 = 3;
    pub const SEQ: u16 = 4;
    pub const STATE_HASH: u16 = 5;
    pub const REPLICA: u16 = 6;
    pub const AT: u16 = 7;
}

/// Снимок состояния, посланный реплике.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Push {
    pub authority_id: [u8; 16],
    pub epoch: u64,
    /// Номер фиксации: растёт на единицу с каждой записью состояния.
    pub seq: u64,
    /// Отпечаток предыдущего снимка; нули у первого и у снимка «с нуля».
    pub previous: [u8; 32],
    /// Отпечаток снимка — он же то, что подтверждает реплика.
    pub state_hash: [u8; 32],
    /// Снимок «с нуля»: реплика принимает его, не сверяя непрерывность.
    /// Посылается ТОЛЬКО в ответ на `SnapshotRequired` самой реплики.
    pub snapshot: bool,
    pub at: i64,
    /// Сами байты состояния.
    pub state: Vec<u8>,
}

impl Push {
    /// Тело без подписи. Байты состояния в тело входят, но подпись покрывает
    /// их через отпечаток — сверять его обязан принимающий.
    ///
    /// # Errors
    /// [`FormatError`] — снимок больше предела или поле не кодируется.
    pub fn body(&self) -> Result<Vec<u8>, FormatError> {
        use push_tag as t;
        if self.state.len() > MAX_STATE {
            return Err(bad(t::STATE, self.state.len()));
        }
        if !oc_crypto::digest_eq(&sha256(&self.state), &self.state_hash) {
            return Err(bad(t::STATE_HASH, self.state.len()));
        }
        let mut w = TlvWriter::new();
        w.put(t::VERSION, &[VERSION])?;
        w.put(t::AUTHORITY_ID, &self.authority_id)?;
        w.put(t::EPOCH, &self.epoch.to_le_bytes())?;
        w.put(t::SEQ, &self.seq.to_le_bytes())?;
        w.put(t::PREVIOUS, &self.previous)?;
        w.put(t::STATE_HASH, &self.state_hash)?;
        w.put(t::SNAPSHOT, &[u8::from(self.snapshot)])?;
        w.put(t::AT, &self.at.to_le_bytes())?;
        w.put(t::STATE, &self.state)?;
        Ok(w.finish().to_vec())
    }

    /// Подписать ключом подписи лизингов сервера.
    ///
    /// # Errors
    /// [`FormatError`] — тело или подпись.
    pub fn sign(&self, signer: &dyn Signer) -> Result<Vec<u8>, FormatError> {
        let body = self.body()?;
        let sig = signer
            .sign(&transcript(label::REPLICA_PUSH, &body))
            .map_err(|_| FormatError::BadHeaderSignature)?;
        let mut out = sig.to_vec();
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Разобрать и проверить подпись ключом сервера, которому реплика служит.
    ///
    /// # Errors
    /// [`FormatError`] — раскладка, подпись или отпечаток снимка.
    pub fn open(bytes: &[u8], authority: &[u8; KEY]) -> Result<Self, FormatError> {
        use push_tag as t;
        let (sig, body) = bytes.split_at_checked(SIG).ok_or(bad(0, bytes.len()))?;
        let sig: [u8; SIG] = sig.try_into().map_err(|_| bad(0, SIG))?;
        oc_crypto::sign::verify(authority, &transcript(label::REPLICA_PUSH, body), &sig)
            .map_err(|_| FormatError::BadHeaderSignature)?;
        let mut r = TlvReader::new(body);
        let (mut version, mut id, mut epoch, mut seq) = (None, None, None, None);
        let (mut previous, mut hash, mut snapshot, mut at, mut state) = (None, None, None, None, None);
        while let Some(f) = r.next_field()? {
            match f.tag {
                t::VERSION => version = Some(one(f.value, f.tag)?),
                t::AUTHORITY_ID => id = Some(array(f.value, f.tag)?),
                t::EPOCH => epoch = Some(number(f.value, f.tag)?),
                t::SEQ => seq = Some(number(f.value, f.tag)?),
                t::PREVIOUS => previous = Some(array(f.value, f.tag)?),
                t::STATE_HASH => hash = Some(array(f.value, f.tag)?),
                // СТРОГО 0 ИЛИ 1. Признак «снимок с нуля» отменяет сверку
                // непрерывности истории, то есть ровно ту проверку, ради которой
                // у снимка есть `previous`; читать его как «байт не ноль»
                // значило бы иметь 255 разных байтов, отменяющих её одинаково, и
                // терять каноничность (И-7) на самом дорогом признаке документа.
                t::SNAPSHOT => {
                    snapshot = Some(match one(f.value, f.tag)? {
                        0 => false,
                        1 => true,
                        _ => return Err(bad(f.tag, 1)),
                    });
                }
                t::AT => at = Some(moment(f.value, f.tag)?),
                t::STATE => {
                    if f.value.len() > MAX_STATE {
                        return Err(bad(f.tag, f.value.len()));
                    }
                    state = Some(f.value.to_vec());
                }
                other => crate::unknown::refuse_if_critical(other)?,
            }
        }
        if version != Some(VERSION) {
            return Err(bad(t::VERSION, 1));
        }
        let push = Self {
            authority_id: id.ok_or(FormatError::MissingField { tag: t::AUTHORITY_ID })?,
            epoch: epoch.ok_or(FormatError::MissingField { tag: t::EPOCH })?,
            seq: seq.ok_or(FormatError::MissingField { tag: t::SEQ })?,
            previous: previous.ok_or(FormatError::MissingField { tag: t::PREVIOUS })?,
            state_hash: hash.ok_or(FormatError::MissingField { tag: t::STATE_HASH })?,
            snapshot: snapshot.ok_or(FormatError::MissingField { tag: t::SNAPSHOT })?,
            at: at.ok_or(FormatError::MissingField { tag: t::AT })?,
            state: state.ok_or(FormatError::MissingField { tag: t::STATE })?,
        };
        // Отпечаток сверяется ЗДЕСЬ: подпись покрывает его, а не байты, и
        // принявший обязан убедиться, что подписанное описывает присланное.
        if !oc_crypto::digest_eq(&sha256(&push.state), &push.state_hash) {
            return Err(bad(t::STATE_HASH, push.state.len()));
        }
        Ok(push)
    }
}

/// Подтверждение реплики: она сохранила ИМЕННО эти байты.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ack {
    pub authority_id: [u8; 16],
    pub epoch: u64,
    pub seq: u64,
    pub state_hash: [u8; 32],
    /// Ключ реплики: кто подтвердил.
    pub replica: [u8; KEY],
    pub at: i64,
}

impl Ack {
    /// Тело без подписи.
    ///
    /// # Errors
    /// [`FormatError`] — поле не кодируется.
    pub fn body(&self) -> Result<Vec<u8>, FormatError> {
        use ack_tag as t;
        let mut w = TlvWriter::new();
        w.put(t::VERSION, &[VERSION])?;
        w.put(t::AUTHORITY_ID, &self.authority_id)?;
        w.put(t::EPOCH, &self.epoch.to_le_bytes())?;
        w.put(t::SEQ, &self.seq.to_le_bytes())?;
        w.put(t::STATE_HASH, &self.state_hash)?;
        w.put(t::REPLICA, &self.replica)?;
        w.put(t::AT, &self.at.to_le_bytes())?;
        Ok(w.finish().to_vec())
    }

    /// Подписать ключом реплики, названным в самом подтверждении.
    ///
    /// # Errors
    /// [`FormatError`] — ключ подписанта не тот или подпись не удалась.
    pub fn sign(&self, signer: &dyn Signer) -> Result<Vec<u8>, FormatError> {
        if signer.public_key() != self.replica {
            return Err(bad(ack_tag::REPLICA, KEY));
        }
        let body = self.body()?;
        let sig = signer
            .sign(&transcript(label::REPLICA_ACK, &body))
            .map_err(|_| FormatError::BadHeaderSignature)?;
        let mut out = sig.to_vec();
        out.extend_from_slice(&body);
        Ok(out)
    }

    /// Разобрать и проверить подпись ключом реплики, известным заранее.
    ///
    /// Ключ берётся снаружи — из настройки сервера, — а поле внутри обязано с
    /// ним совпасть: подтверждение, называющее доверенным себя, не годится.
    ///
    /// # Errors
    /// [`FormatError`] — раскладка, подпись или чужой ключ.
    pub fn open(bytes: &[u8], replica: &[u8; KEY]) -> Result<Self, FormatError> {
        use ack_tag as t;
        let (sig, body) = bytes.split_at_checked(SIG).ok_or(bad(0, bytes.len()))?;
        let sig: [u8; SIG] = sig.try_into().map_err(|_| bad(0, SIG))?;
        oc_crypto::sign::verify(replica, &transcript(label::REPLICA_ACK, body), &sig)
            .map_err(|_| FormatError::BadHeaderSignature)?;
        let mut r = TlvReader::new(body);
        let (mut version, mut id, mut epoch, mut seq, mut hash, mut who, mut at) =
            (None, None, None, None, None, None, None);
        while let Some(f) = r.next_field()? {
            match f.tag {
                t::VERSION => version = Some(one(f.value, f.tag)?),
                t::AUTHORITY_ID => id = Some(array(f.value, f.tag)?),
                t::EPOCH => epoch = Some(number(f.value, f.tag)?),
                t::SEQ => seq = Some(number(f.value, f.tag)?),
                t::STATE_HASH => hash = Some(array(f.value, f.tag)?),
                t::REPLICA => who = Some(array(f.value, f.tag)?),
                t::AT => at = Some(moment(f.value, f.tag)?),
                other => crate::unknown::refuse_if_critical(other)?,
            }
        }
        if version != Some(VERSION) {
            return Err(bad(t::VERSION, 1));
        }
        let ack = Self {
            authority_id: id.ok_or(FormatError::MissingField { tag: t::AUTHORITY_ID })?,
            epoch: epoch.ok_or(FormatError::MissingField { tag: t::EPOCH })?,
            seq: seq.ok_or(FormatError::MissingField { tag: t::SEQ })?,
            state_hash: hash.ok_or(FormatError::MissingField { tag: t::STATE_HASH })?,
            replica: who.ok_or(FormatError::MissingField { tag: t::REPLICA })?,
            at: at.ok_or(FormatError::MissingField { tag: t::AT })?,
        };
        if !oc_crypto::public_key_eq(&ack.replica, replica) {
            return Err(bad(t::REPLICA, KEY));
        }
        Ok(ack)
    }
}

/// Почему реплика снимок не приняла.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Refusal {
    /// Разрыв истории: нужен снимок «с нуля».
    SnapshotRequired = 1,
    /// Тот же номер фиксации с другим отпечатком: две истории.
    HistoryConflict = 2,
    /// Снимок другого сервера или другой эпохи.
    OtherScope = 3,
}

impl Refusal {
    /// Из байта; незнакомый — `None` (И-10).
    #[must_use]
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::SnapshotRequired),
            2 => Some(Self::HistoryConflict),
            3 => Some(Self::OtherScope),
            _ => None,
        }
    }
}

impl core::fmt::Display for Refusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SnapshotRequired => write!(
                f,
                "реплика отстала: её история не продолжается этим снимком, нужен снимок целиком"
            ),
            Self::HistoryConflict => write!(
                f,
                "РАЗВИЛКА ИСТОРИИ: у реплики тот же номер фиксации с другим отпечатком. \
                 Так выглядят два сервера, писавшие одно состояние"
            ),
            Self::OtherScope => write!(f, "снимок другого сервера или другой эпохи"),
        }
    }
}

fn transcript(label: oc_crypto::Label, body: &[u8]) -> Transcript {
    let mut t = Transcript::new(label);
    t.field(body);
    t
}

fn one(value: &[u8], tag: u16) -> Result<u8, FormatError> {
    match value {
        [b] => Ok(*b),
        _ => Err(bad(tag, value.len())),
    }
}

fn number(value: &[u8], tag: u16) -> Result<u64, FormatError> {
    Ok(u64::from_le_bytes(value.try_into().map_err(|_| bad(tag, value.len()))?))
}

fn moment(value: &[u8], tag: u16) -> Result<i64, FormatError> {
    Ok(i64::from_le_bytes(value.try_into().map_err(|_| bad(tag, value.len()))?))
}

fn array<const N: usize>(value: &[u8], tag: u16) -> Result<[u8; N], FormatError> {
    value.try_into().map_err(|_| bad(tag, value.len()))
}

#[cfg(test)]
// `expect_used` и `panic` — ради пробы, которая обязана НАЗЫВАТЬ, что именно
// прошло: `is_err()` одинаково истинно и у нужного отказа, и у случайного, а
// сообщение с полученным значением — единственное, что отличает одно от
// другого. Проверяемый код на этих путях не исполняется.
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use oc_crypto::sign::Ed25519Signer;

    fn push(state: &[u8], seq: u64) -> Push {
        Push {
            authority_id: [0x0a; 16],
            epoch: 0,
            seq,
            previous: [0x11; 32],
            state_hash: sha256(state),
            snapshot: false,
            at: 1_800_000_000,
            state: state.to_vec(),
        }
    }

    /// ТОЛЧОК ПРОВЕРЯЕТСЯ КЛЮЧОМ СЕРВЕРА, А СНИМОК — СВОИМ ОТПЕЧАТКОМ.
    #[test]
    fn a_push_is_bound_to_the_authority_key_and_to_its_own_bytes() {
        let server = Ed25519Signer::from_seed(&[0x21; 32]);
        let other = Ed25519Signer::from_seed(&[0x22; 32]);
        let p = push(b"state bytes", 3);
        let bytes = p.sign(&server).unwrap();
        assert_eq!(Push::open(&bytes, &server.public_key()).unwrap(), p);
        assert!(Push::open(&bytes, &other.public_key()).is_err(), "толчок чужого ключа принят");
        for i in 0..bytes.len() {
            let mut spoiled = bytes.clone();
            spoiled[i] ^= 1;
            assert!(Push::open(&spoiled, &server.public_key()).is_err(), "порча байта {i} не замечена");
        }
        // Отпечаток, не описывающий снимок, не подписывается и не принимается.
        let mut lying = p;
        lying.state_hash = [0; 32];
        assert!(lying.sign(&server).is_err());
    }

    /// ПОДТВЕРЖДЕНИЕ ПРИВЯЗАНО К КЛЮЧУ РЕПЛИКИ, ИЗВЕСТНОМУ ЗАРАНЕЕ.
    #[test]
    fn an_ack_is_bound_to_the_replica_key_known_in_advance() {
        let replica = Ed25519Signer::from_seed(&[0x31; 32]);
        let stranger = Ed25519Signer::from_seed(&[0x32; 32]);
        let ack = Ack {
            authority_id: [0x0a; 16],
            epoch: 0,
            seq: 3,
            state_hash: [0x44; 32],
            replica: replica.public_key(),
            at: 1_800_000_000,
        };
        let bytes = ack.sign(&replica).unwrap();
        assert_eq!(Ack::open(&bytes, &replica.public_key()).unwrap(), ack);
        assert!(Ack::open(&bytes, &stranger.public_key()).is_err());
        // Подписать можно только своим ключом, названным внутри.
        assert!(ack.sign(&stranger).is_err());

        // ПОДПИСЬ ПРОВЕРЯЕТСЯ, а не подразумевается.
        //
        // Три строки выше держались НЕ на ней: отказ чужому ключу даёт сверка
        // поля `replica` с ожидаемым в самом конце `open`, а отказ подписанту —
        // проверка внутри `sign`. Снятие `oc_crypto::sign::verify` из `open` не
        // роняло ни одной из них, и подтверждение принималось бы без подписи
        // вовсе. Ниже тело ЧЕСТНОЕ и поле `replica` сходится с ожидаемым —
        // отличает подделку только подпись.
        let body = ack.body().unwrap();
        let forged = stranger.sign(&transcript(label::REPLICA_ACK, &body)).unwrap();
        let mut spliced = forged.to_vec();
        spliced.extend_from_slice(&body);
        assert!(
            Ack::open(&spliced, &replica.public_key()).is_err(),
            "подтверждение с чужой подписью под честным телом принято: подпись не проверяется"
        );

        // И порча ЛЮБОГО байта документа — отказ, как у толчка выше. Перебор, а
        // не три позиции: «покрывает почти всё» — дыра там, где не проверили.
        for i in 0..bytes.len() {
            let mut spoiled = bytes.clone();
            spoiled[i] ^= 1;
            assert!(
                Ack::open(&spoiled, &replica.public_key()).is_err(),
                "порча байта {i} подтверждения не замечена"
            );
        }
    }

    /// ПРИЗНАК «СНИМОК С НУЛЯ» — РОВНО 0 ИЛИ 1.
    ///
    /// До 2026-09-20 он читался как «байт не ноль»: 255 разных байтов отменяли
    /// сверку непрерывности истории одинаково, и перекодирование приводило их
    /// всех к единице (И-7). Подделка здесь ПОДПИСЫВАЕТСЯ ключом сервера — иначе
    /// проба зеленела бы на отказе подписи и о разборе не говорила бы ничего.
    #[test]
    fn the_snapshot_flag_is_exactly_zero_or_one() {
        let server = Ed25519Signer::from_seed(&[0x24; 32]);
        let body = push(b"state bytes", 3).body().unwrap();

        // Смещение ищется по заголовку поля: перед ним есть поля переменной
        // длины, и считать его руками значило бы вписать в пробу второй разбор.
        let mut head = Vec::with_capacity(6);
        head.extend_from_slice(&push_tag::SNAPSHOT.to_le_bytes());
        head.extend_from_slice(&1u32.to_le_bytes());
        let at = body
            .windows(head.len())
            .position(|w| w == head.as_slice())
            .map(|p| p + head.len())
            .expect("поле признака на месте");

        for (byte, want) in
            [(0u8, Some(false)), (1, Some(true)), (2, None), (5, None), (255, None)]
        {
            let mut forged = body.clone();
            forged[at] = byte;
            let sig = server.sign(&transcript(label::REPLICA_PUSH, &forged)).unwrap();
            let mut document = sig.to_vec();
            document.extend_from_slice(&forged);
            match (want, Push::open(&document, &server.public_key())) {
                (Some(flag), Ok(parsed)) => {
                    assert_eq!(parsed.snapshot, flag, "байт {byte} прочитан не так");
                }
                (None, Err(FormatError::BadFieldLength { tag, .. })) => {
                    assert_eq!(tag, push_tag::SNAPSHOT, "отказ назвал не то поле");
                }
                (_, other) => panic!("байт признака {byte} дал {other:?}"),
            }
        }
    }

    /// СНИМОК БОЛЬШЕ ПРЕДЕЛА НЕ КОДИРУЕТСЯ И НЕ РАЗБИРАЕТСЯ.
    #[test]
    fn a_state_above_the_limit_is_refused() {
        let server = Ed25519Signer::from_seed(&[0x23; 32]);
        let big = vec![0u8; MAX_STATE + 1];
        let p = push(&big, 1);
        assert!(p.sign(&server).is_err(), "снимок больше предела подписан");
    }
}
