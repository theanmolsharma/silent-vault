//! Receive-side BIP352 Silent Payments logic for SP Receive Card.
//!
//! This crate has no KeyOS dependencies so it can be unit-tested on the host and compiled for
//! Passport Prime (`armv7a-unknown-xous-elf`) unchanged. It covers:
//!
//! - the KeyOS app seed -> BIP39 -> BIP32 chain ([`seed`]),
//! - BIP32 derivation of the BIP352 scan and spend keys (`m/352'/coin'/account'/{1',0'}/0`),
//! - BIP352 labels and silent payment address encoding/decoding (bech32m, version 0),
//! - the BIP392 `sp(spscan…)` watch-only descriptor with its BIP380 checksum,
//! - the persisted, non-secret application state (label names and indices),
//! - QR matrices for on-screen codes ([`qr`]).
//!
//! It deliberately has no sending, scanning, or spending code: the app only receives.
//!
//! Secret handling: the spend private key is dropped as soon as the spend public key has been
//! computed, and the scan private key lives inside [`keys::ReceiverKeys`], whose secret is
//! zeroized on drop. Nothing here logs.

#![forbid(unsafe_code)]

pub mod address;
pub mod descriptor;
pub mod export;
pub mod hash;
pub mod keys;
pub mod network;
pub mod qr;
pub mod seed;
pub mod store;

pub use address::{AddressError, SilentPaymentAddress};
pub use descriptor::DescriptorError;
pub use export::WatchOnlyExport;
pub use keys::{KeyError, KeyOrigin, ReceiverKeys};
pub use network::Network;
pub use store::{AppState, LabelNameError, LabelRecord, StoreError};
