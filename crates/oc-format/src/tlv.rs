//! Кодирование заголовка: поля с числовыми тегами, длиной и значением.
//!
//! Формат закрытый, читать его сторонним разработчикам не нужно, поэтому CBOR
//! здесь не даёт ничего, кроме вопроса о канонизации и большого парсера. Вместо
//! него — простейший TLV с одним жёстким правилом: **теги идут строго по
//! возрастанию**. Из этого правила бесплатно следует всё, ради чего в других
//! форматах вводят «каноническую кодировку»: дубликаты тегов невозможны,
//! перестановка полей невозможна, две разные последовательности байтов не могут
//! означать одно и то же. Проверка занимает одно сравнение на поле.
//!
//! Разделение критичных и необязательных полей — по диапазону тега. Неизвестный
//! критичный тег означает, что файл использует семантику, которой этот клиент не
//! знает, и открывать его нельзя. Неизвестный необязательный тег игнорируется.
//! Без этого разделения каждое новое значимое поле следующей версии формата
//! стало бы днём отказа для всех старых клиентов.

use crate::FormatError;
use core::ops::Range;
use zeroize::Zeroizing;

/// Теги не выше этого значения критичны: неизвестный такой тег — отказ.
pub const CRIT_TAG_MAX: u16 = 0x7FFF;

/// Заголовок поля: тег (u16) и длина (u32).
///
/// Публичная потому, что от неё зависит вырез записей из `core_hash`: там нужна
/// граница ЗАПИСИ, а не значения, и вычисляется она вычитанием этой длины из
/// начала значения. Второй источник истины об этом числе означал бы, что при
/// смене ширины тега или длины разъедется хеш ядра — молча и только у части
/// файлов.
pub const FIELD_PREFIX_LEN: usize = 6;

/// Разобранное поле с точным диапазоном его значения в исходном буфере.
///
/// Диапазон нужен не для удобства: хеши политики и ядра заголовка считаются по
/// исходным байтам, а не по повторной кодировке разобранной структуры — иначе
/// воспроизводится всё семейство ошибок канонизации, известное по JWS и XML-DSig.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field<'a> {
    pub tag: u16,
    pub value: &'a [u8],
    /// Диапазон значения в буфере, переданном в [`TlvReader::new`].
    pub span: Range<usize>,
}

impl<'a> Field<'a> {
    /// Значение как ровно один байт.
    pub fn u8(&self) -> Result<u8, FormatError> {
        match self.value {
            [b] => Ok(*b),
            _ => Err(FormatError::BadFieldLength { tag: self.tag, len: self.value.len() }),
        }
    }

    /// Значение как `u16` little-endian.
    pub fn u16(&self) -> Result<u16, FormatError> {
        self.array::<2>().map(u16::from_le_bytes)
    }

    /// Значение как `u32` little-endian.
    pub fn u32(&self) -> Result<u32, FormatError> {
        self.array::<4>().map(u32::from_le_bytes)
    }

    /// Значение как `u64` little-endian.
    pub fn u64(&self) -> Result<u64, FormatError> {
        self.array::<8>().map(u64::from_le_bytes)
    }

    /// Значение как массив точно заданной длины.
    ///
    /// Длина проверяется, а не подгоняется: короткое значение не дополняется
    /// нулями, длинное не обрезается. Иначе противник управляет тем, какие байты
    /// попадут в ключ или в отпечаток.
    pub fn array<const N: usize>(&self) -> Result<[u8; N], FormatError> {
        <[u8; N]>::try_from(self.value)
            .map_err(|_| FormatError::BadFieldLength { tag: self.tag, len: self.value.len() })
    }
}

/// Последовательное чтение полей с проверкой возрастания тегов.
#[derive(Debug)]
pub struct TlvReader<'a> {
    buf: &'a [u8],
    pos: usize,
    last_tag: Option<u16>,
}

impl<'a> TlvReader<'a> {
    /// Начать чтение. Ничего не разбирает: разбор происходит в [`TlvReader::next_field`].
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0, last_tag: None }
    }

    /// Прочитан ли буфер целиком.
    pub fn is_exhausted(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// Следующее поле, либо `None` в конце буфера.
    ///
    /// Тотальна: любой буфер либо разбирается, либо даёт ошибку, но никогда не
    /// паникует и никогда не зацикливается — позиция строго растёт на каждом шаге.
    pub fn next_field(&mut self) -> Result<Option<Field<'a>>, FormatError> {
        if self.pos >= self.buf.len() {
            return Ok(None);
        }

        let header_end = self
            .pos
            .checked_add(FIELD_PREFIX_LEN)
            .ok_or(FormatError::OffsetOverflow)?;
        let prefix = self.buf.get(self.pos..header_end).ok_or(FormatError::Truncated {
            need: header_end as u64,
            have: self.buf.len() as u64,
        })?;

        let tag = prefix
            .get(0..2)
            .and_then(|s| <[u8; 2]>::try_from(s).ok())
            .map(u16::from_le_bytes)
            .ok_or(FormatError::OffsetOverflow)?;
        let len = prefix
            .get(2..6)
            .and_then(|s| <[u8; 4]>::try_from(s).ok())
            .map(u32::from_le_bytes)
            .ok_or(FormatError::OffsetOverflow)? as usize;

        // Возрастание тегов — единственное правило канонизации в этом формате.
        // Равенство запрещено тоже: два поля с одним тегом означали бы, что
        // читатель волен выбрать любое из них, а разные читатели выбрали бы разные.
        match self.last_tag {
            Some(prev) if tag <= prev => {
                return Err(FormatError::FieldsOutOfOrder { previous: prev, found: tag });
            }
            _ => {}
        }

        let value_end = header_end.checked_add(len).ok_or(FormatError::OffsetOverflow)?;
        let value = self.buf.get(header_end..value_end).ok_or(FormatError::Truncated {
            need: value_end as u64,
            have: self.buf.len() as u64,
        })?;

        self.last_tag = Some(tag);
        self.pos = value_end;
        Ok(Some(Field { tag, value, span: header_end..value_end }))
    }
}

/// Запись полей с той же проверкой возрастания тегов.
///
/// Проверка на стороне записи не дублирует проверку чтения: она не даёт
/// сгенерировать заголовок, который наш же читатель отвергнет.
///
/// Буфер здесь **затирающий**, и это не запас прочности «на всякий случай».
/// Этим же писателем собираются приватные метаданные — настоящее имя файла,
/// ради сокрытия которого поле `private_meta` вообще существует и шифруется
/// отдельным ключом K5. Обычный `Vec` отдал бы это имя аллокатору как есть, и
/// оно осталось бы читаемым в освобождённой куче — то есть шифрование в
/// заголовке защищало бы файл на диске, но не процесс, который его собрал.
/// Публичные поля заголовка от затирания не страдают: цена — один memset на
/// уничтожение писателя.
#[derive(Debug, Default)]
pub struct TlvWriter {
    buf: Zeroizing<Vec<u8>>,
    last_tag: Option<u16>,
}

impl TlvWriter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Писатель с заранее известной ёмкостью.
    ///
    /// Рост буфера безопасен (см. `TlvWriter::reserve`), но не бесплатен:
    /// каждое перевыделение — копирование и затирание всего накопленного. Там,
    /// где итоговый размер известен заранее, роста лучше не допускать вовсе.
    pub fn with_capacity(capacity: usize) -> Self {
        Self { buf: Zeroizing::new(Vec::with_capacity(capacity)), last_tag: None }
    }

    /// Освободить место под `extra` байт, не рассыпая уже записанное по куче.
    ///
    /// Обычный рост `Vec` отдаёт старый блок аллокатору нетронутым, поэтому имя
    /// файла оказалось бы в освобождённой куче столько раз, сколько случилось
    /// перевыделений: растущий буфер здесь хуже просто незатёртого. Новый буфер
    /// выделяется явно, старый уезжает в локальную переменную и затирается её
    /// `Drop` **до** возврата памяти аллокатору.
    fn reserve(&mut self, extra: usize) -> Result<(), FormatError> {
        let needed = self.buf.len().checked_add(extra).ok_or(FormatError::OffsetOverflow)?;
        if needed <= self.buf.capacity() {
            return Ok(());
        }
        // Удвоение, а не рост впритык: иначе каждое поле стоило бы копирования и
        // затирания всего буфера, и запись заголовка стала бы квадратичной.
        let target = needed.max(self.buf.capacity().saturating_mul(2));
        let mut previous = Zeroizing::new(Vec::with_capacity(target));
        previous.extend_from_slice(&self.buf);
        core::mem::swap(&mut self.buf, &mut previous);
        Ok(())
    }

    /// Записать поле. Теги обязаны идти по возрастанию.
    pub fn put(&mut self, tag: u16, value: &[u8]) -> Result<(), FormatError> {
        match self.last_tag {
            Some(prev) if tag <= prev => {
                return Err(FormatError::FieldsOutOfOrder { previous: prev, found: tag });
            }
            _ => {}
        }
        let len = u32::try_from(value.len())
            .map_err(|_| FormatError::BadFieldLength { tag, len: value.len() })?;
        // Место под заголовок поля и значение берётся одним куском заранее:
        // три `extend_from_slice` подряд по растущему буферу дали бы до трёх
        // перевыделений на поле, а значит и до трёх копий значения в куче.
        self.reserve(FIELD_PREFIX_LEN.saturating_add(value.len()))?;
        self.buf.extend_from_slice(&tag.to_le_bytes());
        self.buf.extend_from_slice(&len.to_le_bytes());
        self.buf.extend_from_slice(value);
        self.last_tag = Some(tag);
        Ok(())
    }

    /// Записать необязательное поле: `None` не занимает места.
    pub fn put_opt(&mut self, tag: u16, value: Option<&[u8]>) -> Result<(), FormatError> {
        match value {
            Some(v) => self.put(tag, v),
            None => Ok(()),
        }
    }

    /// Готовые байты — в затирающей обёртке.
    ///
    /// Тип возврата — часть гарантии, а не украшение: отдай эта функция обычный
    /// `Vec`, и всё, что писатель бережно не рассыпал по куче, вызывающий отдал
    /// бы аллокатору целиком при первом же `drop`. Кому нужны именно публичные
    /// байты (заголовок, политика, описание содержимого), тот копирует их явно
    /// через `to_vec` — и это видно в коде.
    pub fn finish(self) -> Zeroizing<Vec<u8>> {
        self.buf
    }

    /// Текущая длина.
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

/// Как поступить с полем, тег которого читателю неизвестен.
///
/// Разделение по диапазону тега — самая ценная точка расширения формата. Без неё
/// каждое значимое поле следующей версии становится днём отказа.
pub fn unknown_tag_action(tag: u16) -> UnknownTag {
    if tag <= CRIT_TAG_MAX { UnknownTag::Refuse } else { UnknownTag::Ignore }
}

/// Решение по неизвестному тегу.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnknownTag {
    /// Критичный диапазон: файл использует семантику, которой мы не знаем.
    Refuse,
    /// Необязательный диапазон: пропустить.
    Ignore,
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn encoded(fields: &[(u16, &[u8])]) -> Vec<u8> {
        let mut w = TlvWriter::new();
        for (tag, value) in fields {
            w.put(*tag, value).unwrap();
        }
        w.finish().to_vec()
    }

    fn read_all(buf: &[u8]) -> Result<Vec<(u16, Vec<u8>)>, FormatError> {
        let mut r = TlvReader::new(buf);
        let mut out = Vec::new();
        while let Some(f) = r.next_field()? {
            out.push((f.tag, f.value.to_vec()));
        }
        Ok(out)
    }

    #[test]
    fn round_trips_fields_in_order() {
        let buf = encoded(&[(1, b"a"), (5, b""), (9, b"hello")]);
        let got = read_all(&buf).unwrap();
        assert_eq!(got, vec![(1, b"a".to_vec()), (5, vec![]), (9, b"hello".to_vec())]);
    }

    #[test]
    fn duplicate_tags_are_impossible_to_write_and_to_read() {
        // Дубликат означал бы, что читатель волен выбрать любое из двух значений,
        // а разные читатели выбрали бы разные. Это классический источник
        // расхождения между тем, что проверила подпись, и тем, что применил код.
        let mut w = TlvWriter::new();
        w.put(3, b"first").unwrap();
        assert!(matches!(w.put(3, b"second"), Err(FormatError::FieldsOutOfOrder { .. })));

        // И на чтении тоже — на случай, если заголовок собран не нашим кодом.
        let mut hand_made = Vec::new();
        for value in [b"first".as_ref(), b"second".as_ref()] {
            hand_made.extend_from_slice(&3u16.to_le_bytes());
            hand_made.extend_from_slice(&(value.len() as u32).to_le_bytes());
            hand_made.extend_from_slice(value);
        }
        assert!(matches!(
            read_all(&hand_made),
            Err(FormatError::FieldsOutOfOrder { previous: 3, found: 3 })
        ));
    }

    #[test]
    fn reordered_fields_are_refused() {
        let mut hand_made = Vec::new();
        for tag in [9u16, 1u16] {
            hand_made.extend_from_slice(&tag.to_le_bytes());
            hand_made.extend_from_slice(&0u32.to_le_bytes());
        }
        assert!(matches!(
            read_all(&hand_made),
            Err(FormatError::FieldsOutOfOrder { previous: 9, found: 1 })
        ));
    }

    #[test]
    fn spans_point_at_the_original_bytes() {
        // Хеши считаются по диапазону исходных байтов, а не по повторной
        // кодировке: именно это закрывает семейство ошибок канонизации.
        let buf = encoded(&[(1, b"abc"), (2, b"defg")]);
        let mut r = TlvReader::new(&buf);
        let f1 = r.next_field().unwrap().unwrap();
        let f2 = r.next_field().unwrap().unwrap();
        assert_eq!(&buf[f1.span.clone()], b"abc");
        assert_eq!(&buf[f2.span.clone()], b"defg");
    }

    #[test]
    fn truncation_at_every_boundary_is_an_error_not_a_panic() {
        let buf = encoded(&[(1, b"abc"), (7, b"defgh")]);
        for cut in 0..buf.len() {
            match read_all(&buf[..cut]) {
                Ok(fields) => {
                    // Обрыв ровно на границе поля — допустимое короткое чтение.
                    assert!(fields.len() < 2, "обрезание на {cut} байтах прошло целиком");
                }
                Err(FormatError::Truncated { .. }) => {}
                Err(other) => panic!("обрезание на {cut} байтах дало {other:?}"),
            }
        }
    }

    #[test]
    fn a_declared_length_larger_than_the_buffer_is_refused() {
        // Классический вектор: объявить гигантскую длину и заставить читателя
        // выделить память или прочитать чужие байты.
        let mut hand_made = Vec::new();
        hand_made.extend_from_slice(&1u16.to_le_bytes());
        hand_made.extend_from_slice(&u32::MAX.to_le_bytes());
        hand_made.extend_from_slice(b"short");
        assert!(matches!(read_all(&hand_made), Err(FormatError::Truncated { .. })));
    }

    #[test]
    fn never_panics_on_arbitrary_bytes() {
        let mut soup: Vec<u8> = Vec::new();
        for i in 0..512u16 {
            soup.push((i % 256) as u8);
        }
        for cut in 0..soup.len() {
            let _ = read_all(&soup[..cut]);
        }
    }

    #[test]
    fn typed_accessors_check_length_exactly() {
        let buf = encoded(&[(1, &[7]), (2, &2000u16.to_le_bytes()), (3, b"xxx")]);
        let mut r = TlvReader::new(&buf);
        assert_eq!(r.next_field().unwrap().unwrap().u8().unwrap(), 7);
        assert_eq!(r.next_field().unwrap().unwrap().u16().unwrap(), 2000);
        // Три байта — это не u32 и не u16: длина проверяется, а не подгоняется.
        let f = r.next_field().unwrap().unwrap();
        assert!(matches!(f.u32(), Err(FormatError::BadFieldLength { tag: 3, len: 3 })));
        assert!(matches!(f.u16(), Err(FormatError::BadFieldLength { tag: 3, len: 3 })));
    }

    #[test]
    fn unknown_critical_tags_are_refused_and_optional_ones_ignored() {
        assert_eq!(unknown_tag_action(0), UnknownTag::Refuse);
        assert_eq!(unknown_tag_action(CRIT_TAG_MAX), UnknownTag::Refuse);
        assert_eq!(unknown_tag_action(CRIT_TAG_MAX + 1), UnknownTag::Ignore);
        assert_eq!(unknown_tag_action(u16::MAX), UnknownTag::Ignore);
    }

    #[test]
    fn empty_buffer_yields_no_fields() {
        assert_eq!(read_all(&[]).unwrap(), vec![]);
    }
}
