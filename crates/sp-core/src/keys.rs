//! BIP352 receiver keys: BIP32 derivation of the scan and spend keys, and labels.
//!
//! Derivation follows BIP352 "Key Derivation" exactly, with hardened steps as required:
//!
//! ```text
//!  scan_private_key: m / 352' / coin_type' / account' / 1' / 0
//! spend_private_key: m / 352' / coin_type' / account' / 0' / 0
//! ```
//!
//! `m` is the BIP32 master key of the seed material passed to [`ReceiverKeys::derive`].

use core::fmt;

use bip32::{ChildNumber, XPrv};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{FieldBytes, ProjectivePoint, PublicKey, Scalar, SecretKey};
use zeroize::Zeroizing;

use crate::address::SilentPaymentAddress;
use crate::hash::{tagged_hash, LABEL_TAG};
use crate::network::Network;
use crate::seed::{bip32_seed_from_app_seed, APP_SEED_LEN};

/// BIP43 purpose for silent payments.
pub const PURPOSE: u32 = 352;

/// Largest account index that can be used as a hardened BIP32 child.
pub const MAX_ACCOUNT: u32 = (1 << 31) - 1;

/// Errors from key derivation and label tweaking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyError {
    /// BIP32 seeds must be 16, 32 or 64 bytes long.
    SeedLength(usize),
    /// The account index does not fit in a hardened child number.
    InvalidAccount(u32),
    /// BIP32 produced an invalid child key (probability below 2^-127).
    Derivation,
    /// Bytes are not a valid secp256k1 secret key.
    InvalidSecretKey,
    /// Bytes are not a valid compressed secp256k1 public key.
    InvalidPublicKey,
    /// The label tweak is not a valid scalar, or the labelled spend key is the point at infinity.
    /// Both have negligible probability; BIP352 treats them as failures.
    InvalidLabel,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KeyError::SeedLength(len) => write!(f, "seed must be 16, 32 or 64 bytes, got {len}"),
            KeyError::InvalidAccount(account) => write!(f, "account {account} is out of range"),
            KeyError::Derivation => f.write_str("BIP32 derivation produced an invalid key"),
            KeyError::InvalidSecretKey => f.write_str("invalid secret key"),
            KeyError::InvalidPublicKey => f.write_str("invalid compressed public key"),
            KeyError::InvalidLabel => f.write_str("label tweak is invalid"),
        }
    }
}

impl std::error::Error for KeyError {}

/// Where the receiver keys come from: the master key fingerprint and the BIP352 account node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyOrigin {
    /// First four bytes of HASH160 of the BIP32 master public key.
    pub master_fingerprint: [u8; 4],
    /// Network, which selects the coin type.
    pub network: Network,
    /// BIP44-style account index (unhardened value; always derived hardened).
    pub account: u32,
}

impl KeyOrigin {
    /// Path from the master key to the account node, in BIP380 notation: `352h/0h/0h`.
    pub fn account_path(&self) -> String {
        format!("{PURPOSE}h/{}h/{}h", self.network.coin_type(), self.account)
    }

    /// Lowercase hex master fingerprint, as used in descriptor key origins.
    pub fn fingerprint_hex(&self) -> String { hex_lower(&self.master_fingerprint) }
}

/// The receiver's scan key pair and spend public key.
///
/// This is everything needed to produce addresses and labels. The spend private key is never
/// stored here: [`ReceiverKeys::derive`] computes the spend public key and drops the private key.
/// The scan private key is zeroized when this value is dropped.
pub struct ReceiverKeys {
    origin: KeyOrigin,
    scan_secret: SecretKey,
    scan_public: PublicKey,
    spend_public: PublicKey,
}

impl ReceiverKeys {
    /// Derives the BIP352 keys from the KeyOS app seed (see [`crate::seed`]).
    pub fn derive_from_app_seed(
        app_seed: &[u8; APP_SEED_LEN],
        network: Network,
        account: u32,
    ) -> Result<Self, KeyError> {
        Self::derive(&*bip32_seed_from_app_seed(app_seed), network, account)
    }

    /// Derives the BIP352 keys for `network` and `account` from BIP32 seed material.
    pub fn derive(seed: &[u8], network: Network, account: u32) -> Result<Self, KeyError> {
        if !matches!(seed.len(), 16 | 32 | 64) {
            return Err(KeyError::SeedLength(seed.len()));
        }
        if account > MAX_ACCOUNT {
            return Err(KeyError::InvalidAccount(account));
        }

        let master = XPrv::new(seed).map_err(|_| KeyError::Derivation)?;
        let master_fingerprint = master.public_key().fingerprint();

        let account_node = derive(&master, &[
            hardened(PURPOSE)?,
            hardened(network.coin_type())?,
            hardened(account)?,
        ])?;
        drop(master);

        let scan_node = derive(&account_node, &[hardened(1)?, normal(0)?])?;
        let spend_node = derive(&account_node, &[hardened(0)?, normal(0)?])?;
        drop(account_node);

        let scan_secret = SecretKey::from(scan_node.private_key().as_nonzero_scalar());
        drop(scan_node);
        let spend_public = PublicKey::from(spend_node.private_key().verifying_key());
        drop(spend_node);

        Ok(Self::assemble(KeyOrigin { master_fingerprint, network, account }, scan_secret, spend_public))
    }

    /// Builds receiver keys from raw key material (used for test vectors and imports).
    pub fn from_raw(
        origin: KeyOrigin,
        scan_secret: &[u8; 32],
        spend_public: &[u8; 33],
    ) -> Result<Self, KeyError> {
        let scan_secret = SecretKey::from_bytes(&FieldBytes::from(*scan_secret))
            .map_err(|_| KeyError::InvalidSecretKey)?;
        let spend_public = parse_compressed_point(spend_public)?;
        Ok(Self::assemble(origin, scan_secret, spend_public))
    }

    fn assemble(origin: KeyOrigin, scan_secret: SecretKey, spend_public: PublicKey) -> Self {
        let scan_public = scan_secret.public_key();
        Self { origin, scan_secret, scan_public, spend_public }
    }

    /// Fingerprint, network and account of these keys.
    pub fn origin(&self) -> &KeyOrigin { &self.origin }

    /// Network these keys were derived for.
    pub fn network(&self) -> Network { self.origin.network }

    /// `ser_P(B_scan)`.
    pub fn scan_public_bytes(&self) -> [u8; 33] { compressed(&self.scan_public) }

    /// `ser_P(B_spend)`.
    pub fn spend_public_bytes(&self) -> [u8; 33] { compressed(&self.spend_public) }

    /// `ser_256(b_scan)`. Only needed for the watch-only export; the caller owns the copy.
    pub fn scan_secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.scan_secret.to_bytes().into())
    }

    /// The unlabelled silent payment address `(B_scan, B_spend)`.
    pub fn address(&self) -> SilentPaymentAddress {
        SilentPaymentAddress::new(self.origin.network, &self.scan_public, &self.spend_public)
    }

    /// `B_m = B_spend + hash_BIP0352/Label(ser_256(b_scan) || ser_32(m))·G`.
    ///
    /// `m = 0` is the change label. It is accepted here so the BIP352 test vectors can be checked,
    /// but the app never hands it out (see [`crate::store`]).
    pub fn labeled_spend_public(&self, m: u32) -> Result<PublicKey, KeyError> {
        let tweak = label_tweak(&self.scan_secret, m)?;
        let point = self.spend_public.to_projective() + ProjectivePoint::GENERATOR * tweak;
        PublicKey::from_affine(point.to_affine()).map_err(|_| KeyError::InvalidLabel)
    }

    /// The address `(B_scan, B_m)` for label `m`.
    pub fn labeled_address(&self, m: u32) -> Result<SilentPaymentAddress, KeyError> {
        let spend = self.labeled_spend_public(m)?;
        Ok(SilentPaymentAddress::new(self.origin.network, &self.scan_public, &spend))
    }
}

impl fmt::Debug for ReceiverKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReceiverKeys")
            .field("origin", &self.origin)
            .field("scan_secret", &"<redacted>")
            .field("scan_public", &hex_lower(&self.scan_public_bytes()))
            .field("spend_public", &hex_lower(&self.spend_public_bytes()))
            .finish()
    }
}

/// `hash_BIP0352/Label(ser_256(b_scan) || ser_32(m))` as a scalar.
///
/// Like the BIP352 reference implementation (`Scalar.from_bytes_checked`), a hash that is not
/// below the group order is an error rather than being reduced.
pub fn label_tweak(scan_secret: &SecretKey, m: u32) -> Result<Scalar, KeyError> {
    let b_scan: Zeroizing<[u8; 32]> = Zeroizing::new(scan_secret.to_bytes().into());
    let hash = tagged_hash(LABEL_TAG, &[b_scan.as_slice(), &m.to_be_bytes()]);
    Option::<Scalar>::from(Scalar::from_repr(FieldBytes::from(hash))).ok_or(KeyError::InvalidLabel)
}

/// Parses `ser_P(P)`; uncompressed and invalid encodings are rejected.
pub fn parse_compressed_point(bytes: &[u8; 33]) -> Result<PublicKey, KeyError> {
    if !matches!(bytes[0], 0x02 | 0x03) {
        return Err(KeyError::InvalidPublicKey);
    }
    PublicKey::from_sec1_bytes(bytes).map_err(|_| KeyError::InvalidPublicKey)
}

/// `ser_P(P)`.
pub fn compressed(point: &PublicKey) -> [u8; 33] {
    point
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .expect("compressed secp256k1 points are 33 bytes")
}

fn derive(parent: &XPrv, path: &[ChildNumber]) -> Result<XPrv, KeyError> {
    let mut node = parent.derive_child(path[0]).map_err(|_| KeyError::Derivation)?;
    for &child in &path[1..] {
        node = node.derive_child(child).map_err(|_| KeyError::Derivation)?;
    }
    Ok(node)
}

fn hardened(index: u32) -> Result<ChildNumber, KeyError> {
    ChildNumber::new(index, true).map_err(|_| KeyError::InvalidAccount(index))
}

fn normal(index: u32) -> Result<ChildNumber, KeyError> {
    ChildNumber::new(index, false).map_err(|_| KeyError::InvalidAccount(index))
}

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS[usize::from(b >> 4)] as char);
        out.push(DIGITS[usize::from(b & 0x0f)] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [0x42; 32];

    #[test]
    fn rejects_bad_seed_lengths() {
        for len in [0, 15, 17, 31, 33, 63, 65] {
            let seed = vec![1u8; len];
            assert_eq!(
                ReceiverKeys::derive(&seed, Network::Mainnet, 0).unwrap_err(),
                KeyError::SeedLength(len)
            );
        }
    }

    #[test]
    fn rejects_out_of_range_account() {
        assert_eq!(
            ReceiverKeys::derive(&SEED, Network::Mainnet, 1 << 31).unwrap_err(),
            KeyError::InvalidAccount(1 << 31)
        );
        assert!(ReceiverKeys::derive(&SEED, Network::Mainnet, MAX_ACCOUNT).is_ok());
    }

    #[test]
    fn derivation_is_deterministic_and_network_separated() {
        let a = ReceiverKeys::derive(&SEED, Network::Mainnet, 0).unwrap();
        let b = ReceiverKeys::derive(&SEED, Network::Mainnet, 0).unwrap();
        let t = ReceiverKeys::derive(&SEED, Network::Testnet, 0).unwrap();
        let acct1 = ReceiverKeys::derive(&SEED, Network::Mainnet, 1).unwrap();
        assert_eq!(a.address(), b.address());
        assert_ne!(a.spend_public_bytes(), t.spend_public_bytes());
        assert_ne!(a.scan_public_bytes(), t.scan_public_bytes());
        assert_ne!(a.spend_public_bytes(), acct1.spend_public_bytes());
        assert_eq!(a.origin().master_fingerprint, t.origin().master_fingerprint);
        assert_ne!(a.scan_public_bytes(), a.spend_public_bytes());
    }

    #[test]
    fn debug_output_redacts_scan_secret() {
        let keys = ReceiverKeys::derive(&SEED, Network::Mainnet, 0).unwrap();
        let secret_hex = hex_lower(&*keys.scan_secret_bytes());
        let debug = format!("{keys:?}");
        assert!(!debug.contains(&secret_hex));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn account_path_uses_hardened_notation() {
        let origin = KeyOrigin { master_fingerprint: [0xde, 0xad, 0xbe, 0xef], network: Network::Testnet, account: 7 };
        assert_eq!(origin.account_path(), "352h/1h/7h");
        assert_eq!(origin.fingerprint_hex(), "deadbeef");
    }

    #[test]
    fn rejects_uncompressed_or_invalid_points() {
        let keys = ReceiverKeys::derive(&SEED, Network::Mainnet, 0).unwrap();
        let mut point = keys.spend_public_bytes();
        point[0] = 0x04;
        assert_eq!(parse_compressed_point(&point).unwrap_err(), KeyError::InvalidPublicKey);
        // secp256k1 has no point with x = 0 (7 is not a square mod p).
        let zero_x = {
            let mut p = [0u8; 33];
            p[0] = 0x02;
            p
        };
        assert_eq!(parse_compressed_point(&zero_x).unwrap_err(), KeyError::InvalidPublicKey);
    }
}
