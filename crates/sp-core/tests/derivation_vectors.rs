//! BIP39 and BIP32 reference vectors for the derivation chain
//! `app seed -> BIP39 seed -> BIP32 master -> m/352'/...`.

mod common;

use bip32::{DerivationPath, Prefix, XPrv};
use serde_json::Value;
use sp_core::seed::bip39_seed;

/// Trezor's reference vectors (passphrase "TREZOR"): entropy -> mnemonic -> seed -> master xprv.
#[test]
fn bip39_trezor_vectors() {
    let data: Value = serde_json::from_str(include_str!("data/bip39_trezor_vectors.json")).unwrap();
    let passphrase = data["passphrase"].as_str().unwrap();
    let vectors = data["english"].as_array().unwrap();
    assert_eq!(vectors.len(), 24);
    for v in vectors {
        let entropy = hex::decode(v[0].as_str().unwrap()).unwrap();
        let mnemonic = bip39::Mnemonic::from_entropy(&entropy).unwrap();
        assert_eq!(mnemonic.to_string(), v[1].as_str().unwrap());

        let seed = bip39_seed(&entropy, passphrase).unwrap();
        assert_eq!(hex::encode(*seed), v[2].as_str().unwrap());

        let master = XPrv::new(*seed).unwrap();
        assert_eq!(master.to_string(Prefix::XPRV).as_str(), v[3].as_str().unwrap());
    }
}

/// The official BIP32 test vectors 1-4, checked with the BIP32 implementation the app uses.
#[test]
fn bip32_official_vectors() {
    let data: Value = serde_json::from_str(include_str!("data/bip32_vectors.json")).unwrap();
    let mut chains = 0;
    for vector in data["vectors"].as_array().unwrap() {
        let seed = hex::decode(vector["seed"].as_str().unwrap()).unwrap();
        for chain in vector["chains"].as_array().unwrap() {
            let path: DerivationPath = chain["path"].as_str().unwrap().replace('h', "'").parse().unwrap();
            let xprv = XPrv::derive_from_path(&seed, &path).unwrap();
            assert_eq!(xprv.to_string(Prefix::XPRV).as_str(), chain["xprv"].as_str().unwrap(), "{path}");
            assert_eq!(xprv.public_key().to_string(Prefix::XPUB), chain["xpub"].as_str().unwrap(), "{path}");
            chains += 1;
        }
    }
    assert_eq!(chains, 17);
}
