//! From the KeyOS per-app seed to BIP32 seed material.
//!
//! KeyOS gives a third-party app 32 bytes of app-scoped seed material (`GetAppSeed`). Following
//! the SDK's guidance for apps that need a wallet identity, those bytes are used as BIP39 entropy:
//!
//! ```text
//! app_seed (32 bytes) -> 24-word BIP39 mnemonic -> BIP39 seed (PBKDF2, empty passphrase) -> BIP32 master
//! ```
//!
//! The result is an ordinary BIP39 wallet, so the BIP352 keys derived from it are exactly what any
//! BIP352 wallet would derive from the same 24 words.

use core::fmt;

use bip39::{Language, Mnemonic};
use zeroize::Zeroizing;

/// Length of the KeyOS app seed.
pub const APP_SEED_LEN: usize = 32;

/// Length of a BIP39 seed.
pub const BIP39_SEED_LEN: usize = 64;

/// The entropy is not a valid BIP39 length (16, 20, 24, 28 or 32 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidEntropy;

impl fmt::Display for InvalidEntropy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str("invalid BIP39 entropy length") }
}

impl std::error::Error for InvalidEntropy {}

/// BIP39 seed for the English mnemonic encoding `entropy`, with `passphrase`.
pub fn bip39_seed(entropy: &[u8], passphrase: &str) -> Result<Zeroizing<[u8; BIP39_SEED_LEN]>, InvalidEntropy> {
    let mnemonic = Mnemonic::from_entropy_in(Language::English, entropy).map_err(|_| InvalidEntropy)?;
    Ok(Zeroizing::new(mnemonic.to_seed(passphrase)))
}

/// BIP32 seed material for the app seed: the BIP39 seed of its 24-word mnemonic, no passphrase.
pub fn bip32_seed_from_app_seed(app_seed: &[u8; APP_SEED_LEN]) -> Zeroizing<[u8; BIP39_SEED_LEN]> {
    bip39_seed(app_seed, "").expect("32 bytes is valid BIP39 entropy")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_invalid_entropy_lengths() {
        for len in [0, 8, 15, 17, 33, 64] {
            assert_eq!(bip39_seed(&vec![0u8; len], "").unwrap_err(), InvalidEntropy);
        }
    }

    #[test]
    fn app_seed_uses_empty_passphrase() {
        let app_seed = [0x11u8; 32];
        assert_eq!(*bip32_seed_from_app_seed(&app_seed), *bip39_seed(&app_seed, "").unwrap());
        assert_ne!(*bip32_seed_from_app_seed(&app_seed), *bip39_seed(&app_seed, "x").unwrap());
    }
}
