# Documentation language and literal examples

[Documentation](index.md) · [Format](format.md) · [Protocol](protocol.md)

Public guides, specification prose and Rust API documentation are in English.
Algorithm names, byte literals, field identifiers and frozen fixture bytes retain
their original representation. Descriptive pseudocode annotations are localized;
they do not change the encoded format or the cryptographic transcripts.

Some examples intentionally show the Russian product CLI's actual diagnostic
strings. They are literal outputs, not untranslated English instructions:

| Literal output | Meaning |
| --- | --- |
| `МОЖНО РАЗДАВАТЬ` | Ready to distribute |
| `РАЗДАВАТЬ НЕЛЬЗЯ` | Must not distribute |
| `НЕ ЗНАЮ` | Unknown; the required evidence could not be obtained |

The Unicode characters `а` (U+0430), `я` (U+044F) and `ё` (U+0451) also remain
literal where a test or security explanation needs that exact character. Turning
them into Latin letters would change the example being explained.

Historical internal decision identifiers are transliterated (for example,
the invariant prefix becomes `I-`). They are references to design history,
rather than wire fields. The specifications retain dated decisions and the
historical baseline; later explicit amendments supersede earlier statements.
For the current supported container version, start with
[format compatibility](architecture.md#format-compatibility).

Rust implementation comments and existing runtime diagnostic strings retain
their source language. Changing public documentation does not change program
behavior or the bytes authenticated by the format.
