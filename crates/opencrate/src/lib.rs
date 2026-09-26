// SPDX-License-Identifier: MPL-2.0
//! One-dependency entry point for the five Open Crate core libraries.
//! The modules re-export the same APIs as the individual `oc-*` crates.
//! Enable `app-data` to access the separate, host-side SDK for small arbitrary
//! byte values. Its `OCSB1` envelope is not a `.cc` document.
#![forbid(unsafe_code)]

pub use oc_crypto as crypto;
pub use oc_engine as engine;
pub use oc_format as format;
pub use oc_policy as policy;
pub use oc_protocol as protocol;

/// Host-side sealed-data SDK. Available only with the `app-data` feature.
/// It uses OS randomness, supports one recipient and limits values to 16 MiB.
#[cfg(feature = "app-data")]
pub use opencrate_sdk as app_data;
