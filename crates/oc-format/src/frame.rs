//! Кадрирование сообщений: четыре байта длины, младшим байтом вперёд.
//!
//! # Почему это лежит здесь, а не у первого потребителя
//!
//! Потому что потребителей уже три: движок за трубой, его клиент и сервер за
//! сокетом. Правило у всех одно — **потолок проверяется ДО выделения**, — и
//! копий этого правила успело побывать две, обе словами.
//!
//! Расхождение копий здесь означает не стилистику, а разночтение длины между
//! процессами: одна сторона считает сообщение допустимым, другая обрывает
//! разговор. Поэтому реализация одна, и лежит она в крейте, который видят все.
//!
//! Сюда же переехало то, что вчера появилось в `oc-engine`: с третьим
//! потребителем прежнее место перестало быть общим.
//!
//! # Чего здесь НЕТ
//!
//! Ввода-вывода. У движка это труба, у клиента дочерний процесс, у сервера
//! сокет; сводить три разных ввода-вывода в один тип значило бы прятать
//! различия, которые надо видеть — у каждого свои ошибки и свой конец разговора.

use crate::FormatError;

/// Длина заголовка кадра.
pub const HEADER_LEN: usize = 4;

/// Заголовок кадра для тела длиной `len`.
///
/// # Errors
/// Отдаёт [`FormatError::OffsetOverflow`], если тело длиннее `max`.
pub fn header(len: usize, max: usize) -> Result<[u8; HEADER_LEN], FormatError> {
    if len > max {
        return Err(FormatError::OffsetOverflow);
    }
    let value = u32::try_from(len).map_err(|_| FormatError::OffsetOverflow)?;
    Ok(value.to_le_bytes())
}

/// Длина тела из заголовка кадра, с потолком.
///
/// Потолок здесь не украшение: четыре байта, пришедшие от чужой стороны, — это
/// указание, сколько памяти выделить. Без проверки они означают «выдели четыре
/// гигабайта», и отказ в обслуживании стоит противнику одного пакета.
///
/// # Errors
/// Отдаёт [`FormatError::OffsetOverflow`], если объявленная длина больше `max`.
pub fn body_len(head: [u8; HEADER_LEN], max: usize) -> Result<usize, FormatError> {
    let len = u32::from_le_bytes(head) as usize;
    if len > max {
        return Err(FormatError::OffsetOverflow);
    }
    Ok(len)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    /// ПОТОЛОК ДЕРЖИТСЯ В ОБЕ СТОРОНЫ И РОВНО НА ГРАНИЦЕ.
    #[test]
    fn the_ceiling_holds_in_both_directions() {
        assert_eq!(header(3, 10).unwrap(), 3u32.to_le_bytes());
        assert_eq!(header(10, 10).unwrap(), 10u32.to_le_bytes(), "ровно потолок законен");
        assert!(header(11, 10).is_err());

        assert_eq!(body_len(3u32.to_le_bytes(), 10).unwrap(), 3);
        assert_eq!(body_len(10u32.to_le_bytes(), 10).unwrap(), 10);
        assert!(body_len(11u32.to_le_bytes(), 10).is_err());

        // Четыре байта, обещающие четыре гигабайта, — тот самый случай, ради
        // которого потолок и стоит.
        assert!(body_len(u32::MAX.to_le_bytes(), 1 << 20).is_err());
    }
}
