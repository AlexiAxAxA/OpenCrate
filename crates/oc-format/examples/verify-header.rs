//! Authenticate a local header without treating an unknown author as trusted.
// The example is the I/O host, not part of the pure library.
#![allow(clippy::disallowed_methods)]

use oc_format::verify::{EmptyTrustStore, SignerTrust, verify_and_parse};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).ok_or("usage: verify-header FILE.cc")?;
    let bytes = std::fs::read(path)?;
    let header = verify_and_parse(&bytes, &EmptyTrustStore)
        .map_err(|_| "header authentication failed")?;
    if !matches!(header.trust, SignerTrust::Unknown) {
        return Err("unexpected trust result".into());
    }
    println!("Header signature verified. Author is UNKNOWN: pin a verified identity before granting access.");
    Ok(())
}
