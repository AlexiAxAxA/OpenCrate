// SPDX-License-Identifier: MPL-2.0
#![allow(clippy::unwrap_used)]

use oc_format::tlv::{Field, TlvReader, TlvWriter};

#[test]
fn writer_debug_omits_field_contents() {
    let mut first = TlvWriter::new();
    first.put(1, &[0x51; 32]).unwrap();
    let mut second = TlvWriter::new();
    second.put(1, &[0xa7; 32]).unwrap();
    assert!(format!("{first:?}") == format!("{second:?}"), "value affects Debug");
    assert!(format!("{first:#?}") == format!("{second:#?}"), "value affects pretty Debug");
}

#[test]
fn reader_debug_omits_input_contents() {
    let first = TlvReader::new(&[0x51; 32]);
    let second = TlvReader::new(&[0xa7; 32]);
    assert!(format!("{first:?}") == format!("{second:?}"), "input affects Debug");
    assert!(format!("{first:#?}") == format!("{second:#?}"), "input affects pretty Debug");
}

#[test]
fn field_debug_omits_value_contents() {
    let first = Field { tag: 1, value: &[0x51; 32], span: 6..38 };
    let second = Field { tag: 1, value: &[0xa7; 32], span: 6..38 };
    assert!(format!("{first:?}") == format!("{second:?}"), "value affects Debug");
    assert!(format!("{first:#?}") == format!("{second:#?}"), "value affects pretty Debug");
}
