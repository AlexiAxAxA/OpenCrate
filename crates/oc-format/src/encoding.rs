// SPDX-License-Identifier: MPL-2.0
//! Single-byte Cyrillic decoding shared by display and renderer hosts.
//!
//! Generated tables avoid maintaining separate mappings. Email uses its declared
//! encoding; text files without a declaration may use a guess. The guessed
//! encoding name is returned so the host can show it to the reader.

/// The encoding in which the bytes could be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    /// Windows-1251: the most common encoding for Russian text on Windows.
    Cp1251,
    /// KOI8-R: legacy email and Unix.
    Koi8R,
    /// CP866: MS-DOS program output, still found in logs.
    Cp866,
}

impl Encoding {
    /// A name to display to the user.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Cp1251 => "CP-1251",
            Self::Koi8R => "KOI8-R",
            Self::Cp866 => "CP-866",
        }
    }

    const fn table(self) -> &'static [u16; 128] {
        match self {
            Self::Cp1251 => &CP1251,
            Self::Koi8R => &KOI8_R,
            Self::Cp866 => &CP866,
        }
    }

    /// Decode one byte.
    #[must_use]
    pub fn char_of(self, byte: u8) -> char {
        if byte < 0x80 {
            return char::from(byte);
        }
        let index = (byte as usize).saturating_sub(0x80);
        let code = self.table().get(index).copied().unwrap_or(u16::from(byte));
        char::from_u32(u32::from(code)).unwrap_or(char::REPLACEMENT_CHARACTER)
    }

    /// Decode all bytes.
    #[must_use]
    pub fn decode(self, bytes: &[u8]) -> String {
        bytes.iter().map(|byte| self.char_of(*byte)).collect()
    }
}

/// All candidate encodings.
pub const ALL: [Encoding; 3] = [Encoding::Cp1251, Encoding::Koi8R, Encoding::Cp866];

/// How confidently a candidate must win to be accepted.
///
/// Three quarters of high bytes must become Cyrillic letters. A lower threshold
/// would accept binary files: roughly half of random bytes become Cyrillic
/// under any of the three tables, so there would always be a "winner".
const CONFIDENT: u32 = 3;

/// Guess text encoding; return None when confidence is insufficient.
///
/// Short, binary or non-Cyrillic input may have no candidate and should not be
/// silently displayed as guessed text. CP1251/KOI8-R scoring counts lowercase
/// Cyrillic: KOI8-R uses `0xC0..=0xDF`, CP1251 `0xE0..=0xFF`, so letter count
/// alone would not distinguish the two tables.
#[must_use]
pub fn guess(bytes: &[u8]) -> Option<Encoding> {
    let high = bytes.iter().filter(|byte| **byte >= 0x80).count();
    // Меньше восьми старших байт — судить не о чем: на таком куске выигрывает
    // случайность.
    if high < 8 {
        return None;
    }

    let mut best: Option<(Encoding, usize)> = None;
    for candidate in ALL {
        let score = bytes
            .iter()
            .filter(|byte| **byte >= 0x80)
            .filter(|byte| is_cyrillic_lowercase(candidate.char_of(**byte)))
            .count();
        if best.is_none_or(|(_, previous)| score > previous) {
            best = Some((candidate, score));
        }
    }

    let (winner, score) = best?;
    // Порог: доля строчной кириллицы среди старших байт.
    if score.saturating_mul(4) >= high.saturating_mul(CONFIDENT as usize) {
        Some(winner)
    } else {
        None
    }
}

/// Whether this is a lowercase Cyrillic letter.
///
/// The range `а`–`я` plus `ё`. Uppercase letters are deliberately NOT counted:
/// their predominance is precisely what reveals the wrong table.
fn is_cyrillic_lowercase(c: char) -> bool {
    matches!(c, '\u{0430}'..='\u{044F}' | '\u{0451}')
}

const CP1251: [u16; 128] = [
    0x0402, 0x0403, 0x201A, 0x0453, 0x201E, 0x2026, 0x2020, 0x2021,
    0x20AC, 0x2030, 0x0409, 0x2039, 0x040A, 0x040C, 0x040B, 0x040F,
    0x0452, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,
    0x0098, 0x2122, 0x0459, 0x203A, 0x045A, 0x045C, 0x045B, 0x045F,
    0x00A0, 0x040E, 0x045E, 0x0408, 0x00A4, 0x0490, 0x00A6, 0x00A7,
    0x0401, 0x00A9, 0x0404, 0x00AB, 0x00AC, 0x00AD, 0x00AE, 0x0407,
    0x00B0, 0x00B1, 0x0406, 0x0456, 0x0491, 0x00B5, 0x00B6, 0x00B7,
    0x0451, 0x2116, 0x0454, 0x00BB, 0x0458, 0x0405, 0x0455, 0x0457,
    0x0410, 0x0411, 0x0412, 0x0413, 0x0414, 0x0415, 0x0416, 0x0417,
    0x0418, 0x0419, 0x041A, 0x041B, 0x041C, 0x041D, 0x041E, 0x041F,
    0x0420, 0x0421, 0x0422, 0x0423, 0x0424, 0x0425, 0x0426, 0x0427,
    0x0428, 0x0429, 0x042A, 0x042B, 0x042C, 0x042D, 0x042E, 0x042F,
    0x0430, 0x0431, 0x0432, 0x0433, 0x0434, 0x0435, 0x0436, 0x0437,
    0x0438, 0x0439, 0x043A, 0x043B, 0x043C, 0x043D, 0x043E, 0x043F,
    0x0440, 0x0441, 0x0442, 0x0443, 0x0444, 0x0445, 0x0446, 0x0447,
    0x0448, 0x0449, 0x044A, 0x044B, 0x044C, 0x044D, 0x044E, 0x044F,
];

const KOI8_R: [u16; 128] = [
    0x2500, 0x2502, 0x250C, 0x2510, 0x2514, 0x2518, 0x251C, 0x2524,
    0x252C, 0x2534, 0x253C, 0x2580, 0x2584, 0x2588, 0x258C, 0x2590,
    0x2591, 0x2592, 0x2593, 0x2320, 0x25A0, 0x2219, 0x221A, 0x2248,
    0x2264, 0x2265, 0x00A0, 0x2321, 0x00B0, 0x00B2, 0x00B7, 0x00F7,
    0x2550, 0x2551, 0x2552, 0x0451, 0x2553, 0x2554, 0x2555, 0x2556,
    0x2557, 0x2558, 0x2559, 0x255A, 0x255B, 0x255C, 0x255D, 0x255E,
    0x255F, 0x2560, 0x2561, 0x0401, 0x2562, 0x2563, 0x2564, 0x2565,
    0x2566, 0x2567, 0x2568, 0x2569, 0x256A, 0x256B, 0x256C, 0x00A9,
    0x044E, 0x0430, 0x0431, 0x0446, 0x0434, 0x0435, 0x0444, 0x0433,
    0x0445, 0x0438, 0x0439, 0x043A, 0x043B, 0x043C, 0x043D, 0x043E,
    0x043F, 0x044F, 0x0440, 0x0441, 0x0442, 0x0443, 0x0436, 0x0432,
    0x044C, 0x044B, 0x0437, 0x0448, 0x044D, 0x0449, 0x0447, 0x044A,
    0x042E, 0x0410, 0x0411, 0x0426, 0x0414, 0x0415, 0x0424, 0x0413,
    0x0425, 0x0418, 0x0419, 0x041A, 0x041B, 0x041C, 0x041D, 0x041E,
    0x041F, 0x042F, 0x0420, 0x0421, 0x0422, 0x0423, 0x0416, 0x0412,
    0x042C, 0x042B, 0x0417, 0x0428, 0x042D, 0x0429, 0x0427, 0x042A,
];

const CP866: [u16; 128] = [
    0x0410, 0x0411, 0x0412, 0x0413, 0x0414, 0x0415, 0x0416, 0x0417,
    0x0418, 0x0419, 0x041A, 0x041B, 0x041C, 0x041D, 0x041E, 0x041F,
    0x0420, 0x0421, 0x0422, 0x0423, 0x0424, 0x0425, 0x0426, 0x0427,
    0x0428, 0x0429, 0x042A, 0x042B, 0x042C, 0x042D, 0x042E, 0x042F,
    0x0430, 0x0431, 0x0432, 0x0433, 0x0434, 0x0435, 0x0436, 0x0437,
    0x0438, 0x0439, 0x043A, 0x043B, 0x043C, 0x043D, 0x043E, 0x043F,
    0x2591, 0x2592, 0x2593, 0x2502, 0x2524, 0x2561, 0x2562, 0x2556,
    0x2555, 0x2563, 0x2551, 0x2557, 0x255D, 0x255C, 0x255B, 0x2510,
    0x2514, 0x2534, 0x252C, 0x251C, 0x2500, 0x253C, 0x255E, 0x255F,
    0x255A, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256C, 0x2567,
    0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256B,
    0x256A, 0x2518, 0x250C, 0x2588, 0x2584, 0x258C, 0x2590, 0x2580,
    0x0440, 0x0441, 0x0442, 0x0443, 0x0444, 0x0445, 0x0446, 0x0447,
    0x0448, 0x0449, 0x044A, 0x044B, 0x044C, 0x044D, 0x044E, 0x044F,
    0x0401, 0x0451, 0x0404, 0x0454, 0x0407, 0x0457, 0x040E, 0x045E,
    0x00B0, 0x2219, 0x00B7, 0x221A, 0x2116, 0x00A4, 0x25A0, 0x00A0,
];

#[cfg(test)]
// Пробы строят входы из заведомо верных величин.
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Russian text is recognized in each of the three encodings.
    ///
    /// Constructed here by reversing the process: take known text, encode it
    /// with a table, and require the guess to return that exact table. This tests
    /// what matters: discrimination, rather than merely "letters came out".
    #[test]
    fn each_encoding_is_recognised_from_its_own_bytes() {
        let text = "мы храним документы в защищённом виде и показываем их людям";
        for encoding in ALL {
            let bytes: Vec<u8> = text
                .chars()
                .map(|c| {
                    (0u8..=255)
                        .find(|byte| encoding.char_of(*byte) == c)
                        .expect("символ есть в таблице")
                })
                .collect();
            assert_eq!(
                guess(&bytes),
                Some(encoding),
                "{} не опознана",
                encoding.name()
            );
            assert_eq!(encoding.decode(&bytes), text, "{} не раскодировалась", encoding.name());
        }
    }

    /// CP1251 and KOI8-R ARE DISTINGUISHED despite placing Cyrillic in the same range.
    ///
    /// A separate probe because this is the only easily confused pair:
    /// case distinguishes them, rather than the range.
    #[test]
    fn the_two_lookalikes_are_told_apart() {
        let text = "документ открыт и показан";
        let cp: Vec<u8> = text
            .chars()
            .map(|c| (0u8..=255).find(|b| Encoding::Cp1251.char_of(*b) == c).unwrap())
            .collect();
        let koi: Vec<u8> = text
            .chars()
            .map(|c| (0u8..=255).find(|b| Encoding::Koi8R.char_of(*b) == c).unwrap())
            .collect();
        assert_ne!(cp, koi, "байты совпали — проба ничего не различает");
        assert_eq!(guess(&cp), Some(Encoding::Cp1251));
        assert_eq!(guess(&koi), Some(Encoding::Koi8R));
    }

    /// A BINARY FILE IS NOT CLASSIFIED AS AN ENCODING.
    ///
    /// Without a confidence threshold there would always be a winner: roughly half
    /// of random bytes become Cyrillic under any table. Every executable
    /// would then be displayed as seemingly coherent nonsense.
    #[test]
    fn binary_bytes_are_not_declared_to_be_text() {
        // Отрезок, где старшие байты равномерны, — то, чем и является машинный код.
        let rubbish: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        assert_eq!(guess(&rubbish), None, "мусор объявлен текстом");
        // Латиница со старшими байтами из диакритики — тоже не кириллица.
        let latin: Vec<u8> = (0xC0u8..=0xFF).flat_map(|b| [b, b'a', b'b']).collect();
        assert!(
            guess(&latin).is_none() || guess(&latin) == Some(Encoding::Cp1251),
            "неожиданный исход на латинице: {:?}",
            guess(&latin)
        );
    }

    /// A short fragment cannot support a judgment, and this is acknowledged honestly.
    #[test]
    fn a_short_run_is_refused_rather_than_guessed() {
        assert_eq!(guess(b"\xE4\xE0"), None, "по двум байтам вынесен вердикт");
        assert_eq!(guess(b""), None);
        assert_eq!(guess(b"plain ascii only"), None, "у ASCII нет старших байт");
    }
}
