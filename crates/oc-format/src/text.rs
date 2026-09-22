//! Rules for displaying text chosen by AN OUTSIDER.
//!
//! # Why a separate module
//!
//! The same rule existed in FOUR copies in the repository: filenames
//! (`cc-cli`, finding V-8), server denial text (`activate.rs`), the request queue
//! (`decide.rs`), and the note (`access.rs`); a fifth function of the same kind,
//! `printable`, had no list at all. The copies diverged just as copies always
//! do: nobody updated any of the nine-code-point lists,
//! and nobody updated `printable` because a nearby comment promised
//! that its input was already constrained.
//!
//! The rule lives here in the pure crate for two reasons: parsing must
//! REJECT such text, while display must REPLACE it with a dot, and both must
//! use the same list. The responses differ; the set is shared.
//!
//! # What is absent and why
//!
//! * **Restriction to printable ASCII.** Correct for server addresses, which
//!   have a wire representation (non-Latin names use punycode), but incorrect for
//!   anything a person writes: a document name may legitimately be Russian,
//!   as may a note. CATEGORIES are excluded, not alphabets.
//! * **A ban on U+200C and U+200D** (ZWNJ and ZWJ). Invisible but orthographically
//!   REQUIRED in Persian, Arabic, and Devanagari, they also join composite
//!   emoji. Banning them would repeat the mistake of restricting to
//!   ASCII, one level deeper.
//! * **A ban on combining marks.** "Zalgo" with a hundred diacritics breaks layout,
//!   but combining marks belong to the writing systems of half the world. A
//!   LENGTH limit applies here, rather than a ban on the category.
//! * **A ban on variation selectors** (U+FE00..U+FE0F): these change the appearance
//!   of the preceding character, rather than the order or visibility of the line.

/// Code points that reorder displayed text.
///
/// **Twelve, not nine.** The previous copies listed only the Trojan
/// Source set: embeddings (LRE, RLE), PDF, overrides (LRO, RLO), and isolates
/// (LRI, RLI, FSI, PDI). The direction MARKS themselves, ALM, LRM, and RLM, were
/// absent from all four copies, although they do the same thing:
/// set the direction of adjacent text and change display order.
///
/// They are NOT control characters: `char::is_control` covers category
/// `Cc` only, while all three belong to `Cf`. The second condition therefore
/// missed them, and after the note's character set was expanded they passed
/// straight through to the author's terminal.
pub const BIDI: [char; 12] = [
    '\u{061c}', // ALM  ARABIC LETTER MARK
    '\u{200e}', // LRM  LEFT-TO-RIGHT MARK
    '\u{200f}', // RLM  RIGHT-TO-LEFT MARK
    '\u{202a}', // LRE  LEFT-TO-RIGHT EMBEDDING
    '\u{202b}', // RLE  RIGHT-TO-LEFT EMBEDDING
    '\u{202c}', // PDF  POP DIRECTIONAL FORMATTING
    '\u{202d}', // LRO  LEFT-TO-RIGHT OVERRIDE
    '\u{202e}', // RLO  RIGHT-TO-LEFT OVERRIDE
    '\u{2066}', // LRI  LEFT-TO-RIGHT ISOLATE
    '\u{2067}', // RLI  RIGHT-TO-LEFT ISOLATE
    '\u{2068}', // FSI  FIRST STRONG ISOLATE
    '\u{2069}', // PDI  POP DIRECTIONAL ISOLATE
];

/// Invisible formatting characters with no orthographic role.
///
/// They do not change order: they are not displayed at all, which is the danger:
/// two different strings are displayed INDISTINGUISHABLY.
///
/// The example below uses VISIBLE notation: `(U+2060)` instead of the character itself.
/// Previously it contained the actual invisible character, causing the very problem
/// it describes: invisible when reading the file, it survives copying
/// into someone else's code with the example. The hygiene guard found it, not an eye. Where a person decides based on
/// displayed text, this is forgery, however quiet: "Peter from acc(U+2060)ounting" with
/// an invisible character looks like the real Peter in the same queue.
pub const INVISIBLE: [char; 5] = [
    '\u{00ad}', // SOFT HYPHEN
    '\u{180e}', // MONGOLIAN VOWEL SEPARATOR
    '\u{200b}', // ZERO WIDTH SPACE
    '\u{2060}', // WORD JOINER
    '\u{feff}', // ZERO WIDTH NO-BREAK SPACE (BOM в середине строки)
];

/// Line and paragraph separators.
///
/// Deliberately separate from controls: their categories are `Zl` and `Zp`, not `Cc`,
/// so `char::is_control` misses them. Yet they insert a line break,
/// doing exactly what `\n` is forbidden for: shifting output and forging
/// a list.
pub const SEPARATORS: [char; 2] = [
    '\u{2028}', // LINE SEPARATOR
    '\u{2029}', // PARAGRAPH SEPARATOR
];

/// Tag characters: an invisible copy of ASCII.
///
/// U+E0020..U+E007F repeat printable ASCII with invisible characters, allowing
/// text to be hidden inside text. Rejected along with U+E0001. The cost is
/// explicit: subdivision flag sequences (England's flag and similar)
/// use precisely these tag characters and will not pass this check. For a
/// field on which a human bases a decision, invisible smuggling is more dangerous
/// than losing a flag.
const TAG_FIRST: char = '\u{e0000}';
const TAG_LAST: char = '\u{e007f}';

/// Whether this character is dangerous to display to a person.
///
/// One set for the entire repository. Parsing REJECTS using it; display
/// REPLACES with a dot. The caller chooses the response; the contents of
/// the set are decided here.
#[must_use]
pub fn is_display_unsafe(c: char) -> bool {
    c.is_control()
        || BIDI.contains(&c)
        || INVISIBLE.contains(&c)
        || SEPARATORS.contains(&c)
        || (TAG_FIRST..=TAG_LAST).contains(&c)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every code point in the lists must be dangerous, with none
    /// accidentally accepted. This probe prevents divergence between the list and predicate.
    #[test]
    fn every_listed_point_is_unsafe() {
        for c in BIDI.into_iter().chain(INVISIBLE).chain(SEPARATORS) {
            assert!(is_display_unsafe(c), "пропущен U+{:04X}", u32::from(c));
        }
        for c in [TAG_FIRST, '\u{e0041}', TAG_LAST] {
            assert!(is_display_unsafe(c), "пропущен теговый U+{:04X}", u32::from(c));
        }
    }

    /// Control: letters of living writing systems are not considered dangerous.
    ///
    /// This probe is not here for completeness. The bug that prompted the rule
    /// was precisely the opposite: restriction to printable ASCII rejected
    /// legitimate text, and no test noticed because all tests were
    /// written in Latin characters.
    #[test]
    fn letters_of_living_scripts_are_safe() {
        for c in "Пётр из бухгалтерии 会计部的彼得 פטר حساب Ελλάδα ñ é ß 123 .,!-".chars() {
            assert!(!is_display_unsafe(c), "отвергнута буква U+{:04X}", u32::from(c));
        }
        // ZWNJ и ZWJ обязаны проходить: без них ломается персидский, деванагари
        // и составные эмодзи.
        for c in ['\u{200c}', '\u{200d}'] {
            assert!(!is_display_unsafe(c), "отвергнут U+{:04X}", u32::from(c));
        }
    }

    /// Control characters are caught, and these are the only characters `is_control`
    /// caught on its own.
    #[test]
    fn control_characters_are_unsafe() {
        for c in ['\u{0}', '\r', '\n', '\u{1b}', '\u{7f}', '\u{9b}'] {
            assert!(is_display_unsafe(c), "пропущен U+{:04X}", u32::from(c));
        }
    }
}
