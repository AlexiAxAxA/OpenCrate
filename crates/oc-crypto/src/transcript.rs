//! Транскрипт — единственный способ получить байты под подпись или MAC.
//!
//! Тип существует ради одного инварианта: **подписать неразделённые по домену
//! байты невозможно**. Конструктор требует метку, а функции подписи принимают
//! только [`Transcript`], поэтому забыть метку нельзя — код просто не
//! скомпилируется.
//!
//! Без этого подпись автора, сделанная в одном контексте (запись отзыва, запрос
//! активации, выдача права), становится воспроизводимой в другом, если
//! кодировки удастся столкнуть. Ошибка тихая и обнаруживается только атакой.

use crate::label::Label;

/// Байты, подготовленные к подписи или к MAC, с обязательной меткой домена.
#[derive(Clone, PartialEq, Eq)]
pub struct Transcript {
    buf: Vec<u8>,
}

impl core::fmt::Debug for Transcript {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Transcript({} байт)", self.buf.len())
    }
}

impl Transcript {
    /// Начать транскрипт с метки домена.
    ///
    /// Метка приходит типом [`Label`], а не `&'static [u8]`, и разница здесь не
    /// косметическая: значение `Label` невозможно сочинить — его отдают только
    /// константы реестра [`crate::label`]. Пока принимались байты, проверки И-12
    /// смотрели на реестр, а вызывающий был вправе передать мимо него строку,
    /// которой в реестре нет (например расширение уже занятой метки), и ни одна
    /// проба этого не увидела бы. Теперь это не компилируется.
    #[must_use]
    pub fn new(label: Label) -> Self {
        let bytes = label.as_bytes();
        let mut buf = Vec::with_capacity(bytes.len().saturating_add(64));
        buf.extend_from_slice(bytes);
        buf.push(0x00);
        Self { buf }
    }

    /// Добавить один байт: идентификатор алгоритма, версию, тег.
    pub fn u8(&mut self, value: u8) -> &mut Self {
        self.buf.push(value);
        self
    }

    /// Добавить `u32` в little-endian. Порядок задан спецификацией.
    pub fn u32le(&mut self, value: u32) -> &mut Self {
        self.buf.extend_from_slice(&value.to_le_bytes());
        self
    }

    /// Добавить `u32` в big-endian: так кодируются номера чанков.
    pub fn u32be(&mut self, value: u32) -> &mut Self {
        self.buf.extend_from_slice(&value.to_be_bytes());
        self
    }

    /// Добавить `u64` в big-endian: так кодируются последовательности лизингов.
    pub fn u64be(&mut self, value: u64) -> &mut Self {
        self.buf.extend_from_slice(&value.to_be_bytes());
        self
    }

    /// Добавить данные фиксированной длины: ключ, отпечаток, идентификатор.
    ///
    /// Для полей **переменной** длины используется [`Transcript::field`], иначе
    /// две разные последовательности полей дают одни и те же байты и подпись
    /// перестаёт однозначно определять содержание.
    pub fn fixed(&mut self, value: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(value);
        self
    }

    /// Добавить поле переменной длины с префиксом длины.
    pub fn field(&mut self, value: &[u8]) -> &mut Self {
        let len = u32::try_from(value.len()).unwrap_or(u32::MAX);
        self.buf.extend_from_slice(&len.to_le_bytes());
        self.buf.extend_from_slice(value);
        self
    }

    /// Добавить завершающий блок без префикса длины.
    ///
    /// Допустимо **только** когда длина уже была записана в транскрипт раньше —
    /// как в подписи заголовка, где `u32le(HeaderLen)` предшествует самому
    /// заголовку.
    pub fn tail_after_declared_length(&mut self, value: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(value);
        self
    }

    /// Готовые байты.
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Длина в байтах.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Пуст ли транскрипт. Метка всегда присутствует, поэтому всегда `false`.
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::label;

    #[test]
    fn every_transcript_starts_with_its_label() {
        let t = Transcript::new(label::LEASE);
        assert!(t.as_bytes().starts_with(label::LEASE.as_bytes()));
        assert_eq!(t.as_bytes().get(label::LEASE.len()), Some(&0x00));
    }

    #[test]
    fn prefix_labels_do_not_collide_even_though_the_set_is_prefix_free() {
        // Двойная страховка: набор меток беспрефиксный, и сверх того транскрипт
        // ставит нулевой байт после метки. Тест фиксирует вторую защиту, чтобы
        // её не убрали как «избыточную».
        let mut a = Transcript::new(label::LEASE);
        a.fixed(b"-cache-and-more");
        let mut b = Transcript::new(label::CACHED_LEASE);
        b.fixed(b"-and-more");
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn different_labels_never_collide() {
        // Смысл всего типа: одни и те же данные под разными метками дают разные
        // байты, поэтому подпись из одного контекста не проходит в другом.
        let mut a = Transcript::new(label::LEASE);
        a.fixed(&[1, 2, 3]);
        let mut b = Transcript::new(label::REVOCATION);
        b.fixed(&[1, 2, 3]);
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn variable_length_fields_are_unambiguous() {
        // Без префикса длины ("ab","c") и ("a","bc") дали бы одни байты.
        let mut a = Transcript::new(label::GRANT);
        a.field(b"ab").field(b"c");
        let mut b = Transcript::new(label::GRANT);
        b.field(b"a").field(b"bc");
        assert_ne!(a.as_bytes(), b.as_bytes());
    }

    #[test]
    fn fixed_length_fields_are_concatenated_verbatim() {
        let mut t = Transcript::new(label::CHUNK);
        t.fixed(&[0xaa; 16]).u32be(7).u8(1);
        let expected_len = label::CHUNK.len() + 1 + 16 + 4 + 1;
        assert_eq!(t.len(), expected_len);
        assert_eq!(t.as_bytes().get(t.len() - 5..t.len()), Some(&[0, 0, 0, 7, 1][..]));
    }

    #[test]
    fn endianness_is_explicit_and_distinct() {
        let mut le = Transcript::new(label::CHUNK);
        le.u32le(1);
        let mut be = Transcript::new(label::CHUNK);
        be.u32be(1);
        assert_ne!(le.as_bytes(), be.as_bytes(), "порядок байтов обязан быть явным");
    }
}
