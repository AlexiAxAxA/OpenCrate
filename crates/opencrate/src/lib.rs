//! One-dependency entry point for the five Open Crate core libraries.
//! The modules re-export the same APIs as the individual `oc-*` crates.
#![forbid(unsafe_code)]

pub use oc_crypto as crypto;
pub use oc_engine as engine;
pub use oc_format as format;
pub use oc_policy as policy;
pub use oc_protocol as protocol;
