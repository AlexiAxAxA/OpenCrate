//! Единое правило крейта для незнакомого тега (И-7, решение 2026-09-21).
//!
//! Решение о теге принимает `oc_format::tlv::unknown_tag_action` — та же
//! функция, что у контейнера, и второй её здесь нет намеренно: два места,
//! считающие границу критичного диапазона, разошлись бы молча, и разошлись бы
//! ровно в сторону «пропустили то, что обязаны были отвергнуть».
//!
//! # Почему помощник, а не строка в каждом разборщике
//!
//! Разборщиков документов в крейте четырнадцать, и три строки `match`, дословно
//! повторённые четырнадцать раз, — это известная болезнь репозитория: один путь
//! чинят, соседний забывают. Здесь забыть нечего: правило одно и лежит в одном
//! месте.
//!
//! # Почему у второго помощника есть ПАМЯТЬ о пропущенном
//!
//! Часть документов крейта сверяется сама с собой: разобранная структура
//! кодируется заново и обязана дать ИСХОДНЫЕ байты (`control::Binding`,
//! `ControlRequest`, `Receipt`, `Transfer`, `directory::Record`). Проверка эта
//! стоит не зря — она и есть каноничность: тело, которое наш кодировщик не
//! воспроизводит, не имеет единственного представления, а именно по его байтам
//! считается подпись, соподпись и лист журнала каталога.
//!
//! Пропущенный необязательный тег ломает сверку: перекодирование его теряет.
//! Поэтому сверяется не всё тело, а тело БЕЗ пропущенных записей — каноничность
//! ЗНАКОМЫХ полей остаётся под сторожем, а незнакомое необязательное поле
//! проезжает мимо неё. Вырезаются записи целиком (тег, длина, значение) — тем же
//! приёмом, что у И-3.

use core::ops::Range;
use oc_format::FormatError;
use oc_format::tlv::{FIELD_PREFIX_LEN, Field, UnknownTag, unknown_tag_action};

/// Решение по незнакомому тегу: критичный — отказ, необязательный — пропуск.
///
/// Вариант ошибки тот же, каким крейт отвечал на ЛЮБОЙ незнакомый тег до
/// решения 2026-09-21: для критичного диапазона поведение не изменилось ничем,
/// включая текст отказа.
///
/// # Errors
/// [`FormatError::UnknownCriticalField`] — тег из критичного диапазона.
pub(crate) fn refuse_if_critical(tag: u16) -> Result<(), FormatError> {
    match unknown_tag_action(tag) {
        UnknownTag::Refuse => Err(FormatError::UnknownCriticalField { tag }),
        UnknownTag::Ignore => Ok(()),
    }
}

/// То же решение, но с памятью о том, какие записи пропущены.
#[derive(Debug, Default)]
pub(crate) struct Skipped {
    /// Диапазоны ЗАПИСЕЙ (тег, длина, значение) в теле, переданном разборщику.
    spans: Vec<Range<usize>>,
}

impl Skipped {
    /// Увидеть незнакомое поле: критичное — отказ, необязательное — запомнить.
    ///
    /// # Errors
    /// [`FormatError::UnknownCriticalField`] — тег из критичного диапазона.
    pub(crate) fn see(&mut self, field: &Field<'_>) -> Result<(), FormatError> {
        refuse_if_critical(field.tag)?;
        // Граница ЗАПИСИ, а не значения: длина префикса берётся у формата, а не
        // повторяется здесь числом — иначе смена ширины тега разъехалась бы с
        // вырезом молча (тот же довод, что у `FIELD_PREFIX_LEN`).
        let start = field.span.start.checked_sub(FIELD_PREFIX_LEN).ok_or(FormatError::OffsetOverflow)?;
        self.spans.push(start..field.span.end);
        Ok(())
    }

    /// Тело без пропущенных записей — то, с чем сверяется перекодирование.
    ///
    /// Диапазоны идут по возрастанию по построению: теги строго растут (И-7), а
    /// значит растут и смещения. Порядок здесь не восстанавливается и не
    /// проверяется — он свойство обхода, а не этих данных.
    pub(crate) fn strip(&self, body: &[u8]) -> Vec<u8> {
        if self.spans.is_empty() {
            return body.to_vec();
        }
        let mut out = Vec::with_capacity(body.len());
        let mut cut = 0usize;
        for span in &self.spans {
            if let Some(keep) = body.get(cut..span.start) {
                out.extend_from_slice(keep);
            }
            cut = span.end;
        }
        if let Some(tail) = body.get(cut..) {
            out.extend_from_slice(tail);
        }
        out
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use oc_format::tlv::{CRIT_TAG_MAX, TlvReader, TlvWriter};

    #[test]
    fn the_critical_range_is_refused_and_the_optional_one_is_not() {
        assert!(refuse_if_critical(1).is_err());
        assert!(refuse_if_critical(CRIT_TAG_MAX).is_err());
        assert!(refuse_if_critical(CRIT_TAG_MAX + 1).is_ok());
        assert!(refuse_if_critical(u16::MAX).is_ok());
    }

    /// Вырезанное тело — ровно то, что написал бы кодировщик без лишних полей.
    #[test]
    fn stripping_gives_back_the_body_the_writer_would_have_written() {
        let mut w = TlvWriter::new();
        w.put(1, b"one").unwrap();
        w.put(0x8ABC, b"unknown").unwrap();
        w.put(0x8ABD, b"").unwrap();
        let with_extra = w.finish().to_vec();

        let mut w = TlvWriter::new();
        w.put(1, b"one").unwrap();
        let without = w.finish().to_vec();

        let mut skipped = Skipped::default();
        let mut reader = TlvReader::new(&with_extra);
        while let Some(field) = reader.next_field().unwrap() {
            if field.tag != 1 {
                skipped.see(&field).unwrap();
            }
        }
        assert_eq!(skipped.strip(&with_extra), without);
        // Ничего не пропущено — тело отдаётся как есть.
        assert_eq!(Skipped::default().strip(&without), without);
    }
}
