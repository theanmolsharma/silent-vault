#![allow(dead_code)]

use sha2::{Digest, Sha256};
use sp_core::keys::KeyOrigin;
use sp_core::Network;

pub fn hex_array<const N: usize>(s: &str) -> [u8; N] {
    hex::decode(s).expect("hex").try_into().expect("length")
}

/// Deterministic, test-only "app seeds" so failures are reproducible.
pub fn test_app_seed(i: u32) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"sp-receive-card test app seed");
    h.update(i.to_be_bytes());
    h.finalize().into()
}

/// Origin for raw key material that did not come from BIP32 (e.g. BIP352 vectors).
pub fn raw_origin(network: Network) -> KeyOrigin { KeyOrigin { master_fingerprint: [0; 4], network, account: 0 } }

pub fn compressed_pubkey(secret: &[u8; 32]) -> [u8; 33] {
    let sk = k256::SecretKey::from_slice(secret).expect("valid secret");
    sp_core::keys::compressed(&sk.public_key())
}
