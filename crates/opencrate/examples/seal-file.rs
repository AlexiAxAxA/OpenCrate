//! Read any small file as bytes and round-trip it through the optional SDK.
//! This demonstration keeps a temporary key in memory and writes no envelope.
// The example is the host boundary: unlike the core libraries it accepts a path
// and reads the selected file.
#![allow(clippy::disallowed_methods)]

use opencrate::app_data::{generate_recipient, open_bytes, recipient_public, seal_bytes};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args_os().nth(1).ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "usage: seal-file <input-path>")
    })?;
    let input = std::fs::read(path)?;
    let recipient = generate_recipient()?;
    let purpose = "org.opencrate.example.file.v1";
    let context = b"example-file";
    let envelope = seal_bytes(&recipient_public(&recipient), purpose, context, &input)?;
    let opened = open_bytes(&recipient, purpose, context, &envelope)?;
    if opened.as_slice() != input {
        return Err("file round trip failed".into());
    }
    println!("Sealed and opened {} input bytes", input.len());
    Ok(())
}
