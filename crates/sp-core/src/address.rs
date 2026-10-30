//! BIP352 silent payment address encoding (bech32m, version 0).
//!
//! An address is the bech32m encoding of the HRP (`sp` / `tsp`), a version character (`q` for
//! version 0) and the 66-byte payload `ser_P(B_scan) || ser_P(B_m)`. BIP352 recommends a
//! 1023-character limit instead of BIP173's 90.

use core::fmt;
use core::str::FromStr;

use bech32::primitives::decode::{CheckedHrpstring, CheckedHrpstringError};
use bech32::{Bech32m, ByteIterExt, Fe32, Fe32IterExt, Hrp};
use k256::PublicKey;

use crate::keys::{compressed, parse_compressed_point};
use crate::network::Network;

/// Payload size of a version 0 address: two compressed public keys.
pub const V0_PAYLOAD_LEN: usize = 66;

/// Maximum address length recommended by BIP352.
pub const MAX_ADDRESS_LEN: usize = 1023;

/// The only address version this app produces.
pub const VERSION_0: u8 = 0;

/// Version 31 is reserved by BIP352 for a backwards-incompatible change.
pub const RESERVED_VERSION: u8 = 31;

/// Why a string is not a silent payment address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressError {
    /// Not valid bech32m (bad characters, mixed case, wrong checksum, too long, ...).
    Bech32(String),
    /// The HRP is not `sp` or `tsp`.
    UnknownHrp(String),
    /// The data part is empty.
    MissingVersion,
    /// Version 31 is reserved and must be rejected.
    ReservedVersion,
    /// The 5-bit to 8-bit conversion left non-zero or more than four padding bits.
    InvalidPadding,
    /// Version 0 payloads must be exactly 66 bytes; later versions at least 66.
    InvalidPayloadLength(usize),
    /// One of the two keys is not a valid compressed secp256k1 point.
    InvalidKey,
}

impl fmt::Display for AddressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddressError::Bech32(e) => write!(f, "invalid bech32m: {e}"),
            AddressError::UnknownHrp(hrp) => write!(f, "unknown silent payment prefix \"{hrp}\""),
            AddressError::MissingVersion => f.write_str("missing version"),
            AddressError::ReservedVersion => f.write_str("version 31 is reserved"),
            AddressError::InvalidPadding => f.write_str("invalid padding"),
            AddressError::InvalidPayloadLength(len) => write!(f, "invalid payload length {len}"),
            AddressError::InvalidKey => f.write_str("invalid public key"),
        }
    }
}

impl std::error::Error for AddressError {}

impl From<CheckedHrpstringError> for AddressError {
    fn from(e: CheckedHrpstringError) -> Self { AddressError::Bech32(e.to_string()) }
}

/// A parsed silent payment address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SilentPaymentAddress {
    network: Network,
    version: u8,
    scan_key: [u8; 33],
    spend_key: [u8; 33],
}

impl SilentPaymentAddress {
    /// Version 0 address for `(B_scan, B_m)`.
    pub fn new(network: Network, scan_key: &PublicKey, spend_key: &PublicKey) -> Self {
        Self { network, version: VERSION_0, scan_key: compressed(scan_key), spend_key: compressed(spend_key) }
    }

    /// Network implied by the HRP.
    pub fn network(&self) -> Network { self.network }

    /// Address version (0 for every address this app creates).
    pub fn version(&self) -> u8 { self.version }

    /// `ser_P(B_scan)`.
    pub fn scan_key(&self) -> &[u8; 33] { &self.scan_key }

    /// `ser_P(B_m)`: the spend key, possibly labelled.
    pub fn spend_key(&self) -> &[u8; 33] { &self.spend_key }

    /// The lowercase bech32m string. This exact string is also the QR payload.
    pub fn encode(&self) -> String {
        let hrp = Hrp::parse(self.network.sp_hrp()).expect("static HRPs are valid");
        let version = Fe32::try_from(self.version).expect("versions are below 32");
        let mut payload = [0u8; V0_PAYLOAD_LEN];
        payload[..33].copy_from_slice(&self.scan_key);
        payload[33..].copy_from_slice(&self.spend_key);
        payload
            .iter()
            .copied()
            .bytes_to_fes()
            .with_checksum::<Bech32m>(&hrp)
            .with_witness_version(version)
            .chars()
            .collect()
    }

    /// The QR code payload: exactly the address string, with no URI scheme or other text.
    pub fn qr_payload(&self) -> String { self.encode() }

    /// Parses an address following BIP352: version 0 must carry exactly 66 bytes, versions 1-30
    /// are read forward-compatibly (first 66 bytes), version 31 fails.
    pub fn decode(s: &str) -> Result<Self, AddressError> {
        let checked = CheckedHrpstring::new::<Bech32m>(s)?;
        let hrp = checked.hrp().to_lowercase();
        let network = Network::from_sp_hrp(&hrp).ok_or_else(|| AddressError::UnknownHrp(hrp.clone()))?;

        let (version, payload) = split_version_and_payload(checked.data_part_ascii_no_checksum())?;
        if version == RESERVED_VERSION {
            return Err(AddressError::ReservedVersion);
        }
        if (version == VERSION_0 && payload.len() != V0_PAYLOAD_LEN) || payload.len() < V0_PAYLOAD_LEN {
            return Err(AddressError::InvalidPayloadLength(payload.len()));
        }

        let scan_key: [u8; 33] = payload[..33].try_into().expect("length checked");
        let spend_key: [u8; 33] = payload[33..66].try_into().expect("length checked");
        parse_compressed_point(&scan_key).map_err(|_| AddressError::InvalidKey)?;
        parse_compressed_point(&spend_key).map_err(|_| AddressError::InvalidKey)?;

        Ok(Self { network, version, scan_key, spend_key })
    }
}

impl fmt::Display for SilentPaymentAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&self.encode()) }
}

impl FromStr for SilentPaymentAddress {
    type Err = AddressError;

    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::decode(s) }
}

/// Splits a bech32 data part (ASCII, checksum removed) into its leading 5-bit version and the
/// 8-bit payload, enforcing BIP173 padding rules (at most 4 padding bits, all zero).
pub(crate) fn split_version_and_payload(data: &[u8]) -> Result<(u8, Vec<u8>), AddressError> {
    let (&version, rest) = data.split_first().ok_or(AddressError::MissingVersion)?;
    let version = to_fe(version)?.to_u8();
    let fes = rest.iter().map(|&c| to_fe(c)).collect::<Result<Vec<_>, _>>()?;

    let padding_bits = (fes.len() * 5) % 8;
    if padding_bits > 4 {
        return Err(AddressError::InvalidPadding);
    }
    if let Some(last) = fes.last() {
        if last.to_u8() & ((1u8 << padding_bits) - 1) != 0 {
            return Err(AddressError::InvalidPadding);
        }
    }

    Ok((version, fes.into_iter().fes_to_bytes().collect()))
}

fn to_fe(c: u8) -> Result<Fe32, AddressError> {
    Fe32::from_char(char::from(c)).map_err(|e| AddressError::Bech32(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::ReceiverKeys;

    fn keys(network: Network) -> ReceiverKeys { ReceiverKeys::derive(&[9u8; 32], network, 0).unwrap() }

    /// Encodes arbitrary version/payload pairs to build malformed addresses for tests.
    fn raw_encode(hrp: &str, version: u8, payload: &[u8]) -> String {
        let hrp = Hrp::parse(hrp).unwrap();
        payload
            .iter()
            .copied()
            .bytes_to_fes()
            .with_checksum::<Bech32m>(&hrp)
            .with_witness_version(Fe32::try_from(version).unwrap())
            .chars()
            .collect()
    }

    fn payload(k: &ReceiverKeys) -> Vec<u8> {
        [k.scan_public_bytes().as_slice(), k.spend_public_bytes().as_slice()].concat()
    }

    #[test]
    fn mainnet_and_testnet_lengths_and_prefixes() {
        let main = keys(Network::Mainnet).address().encode();
        let test = keys(Network::Testnet).address().encode();
        assert!(main.starts_with("sp1q"));
        assert!(test.starts_with("tsp1q"));
        // 116 characters for "sp", 117 for "tsp" (BIP352 footnote).
        assert_eq!(main.len(), 116);
        assert_eq!(test.len(), 117);
        assert_eq!(main, main.to_lowercase());
    }

    #[test]
    fn round_trip() {
        for network in Network::ALL {
            let addr = keys(network).address();
            let decoded = SilentPaymentAddress::decode(&addr.encode()).unwrap();
            assert_eq!(decoded, addr);
            assert_eq!(decoded.network(), network);
            assert_eq!(decoded.version(), 0);
        }
    }

    #[test]
    fn accepts_uppercase_rejects_mixed_case() {
        let addr = keys(Network::Mainnet).address().encode();
        assert!(SilentPaymentAddress::decode(&addr.to_uppercase()).is_ok());
        let mut mixed = addr.clone();
        mixed.replace_range(5..6, &addr[5..6].to_uppercase());
        if mixed != addr {
            assert!(matches!(SilentPaymentAddress::decode(&mixed), Err(AddressError::Bech32(_))));
        }
    }

    #[test]
    fn rejects_corrupted_checksum() {
        let addr = keys(Network::Mainnet).address().encode();
        let mut chars: Vec<char> = addr.chars().collect();
        let i = 20;
        chars[i] = if chars[i] == 'q' { 'p' } else { 'q' };
        let corrupted: String = chars.into_iter().collect();
        assert!(matches!(SilentPaymentAddress::decode(&corrupted), Err(AddressError::Bech32(_))));
    }

    #[test]
    fn rejects_bech32_non_m_checksum() {
        let k = keys(Network::Mainnet);
        let hrp = Hrp::parse("sp").unwrap();
        let bech32_plain: String = payload(&k)
            .iter()
            .copied()
            .bytes_to_fes()
            .with_checksum::<bech32::Bech32>(&hrp)
            .with_witness_version(Fe32::Q)
            .chars()
            .collect();
        assert!(matches!(SilentPaymentAddress::decode(&bech32_plain), Err(AddressError::Bech32(_))));
    }

    #[test]
    fn rejects_wrong_hrp() {
        let k = keys(Network::Mainnet);
        for hrp in ["bc", "sprt", "spscan", "xsp"] {
            let s = raw_encode(hrp, 0, &payload(&k));
            assert_eq!(SilentPaymentAddress::decode(&s), Err(AddressError::UnknownHrp(hrp.into())));
        }
    }

    #[test]
    fn version_rules() {
        let k = keys(Network::Mainnet);
        let mut long = payload(&k);
        long.extend_from_slice(&[0xab; 10]);

        // v0 must be exactly 66 bytes.
        assert_eq!(
            SilentPaymentAddress::decode(&raw_encode("sp", 0, &long)),
            Err(AddressError::InvalidPayloadLength(76))
        );
        assert_eq!(
            SilentPaymentAddress::decode(&raw_encode("sp", 0, &payload(&k)[..65])),
            Err(AddressError::InvalidPayloadLength(65))
        );
        // v1..=30 read the first 66 bytes and ignore the rest.
        let v1 = SilentPaymentAddress::decode(&raw_encode("sp", 1, &long)).unwrap();
        assert_eq!(v1.version(), 1);
        assert_eq!(v1.spend_key(), &k.spend_public_bytes());
        assert_eq!(
            SilentPaymentAddress::decode(&raw_encode("sp", 30, &payload(&k)[..60])),
            Err(AddressError::InvalidPayloadLength(60))
        );
        // v31 is reserved.
        assert_eq!(
            SilentPaymentAddress::decode(&raw_encode("sp", 31, &payload(&k))),
            Err(AddressError::ReservedVersion)
        );
    }

    #[test]
    fn rejects_invalid_points() {
        let k = keys(Network::Mainnet);
        let mut p = payload(&k);
        p[33] = 0x04;
        assert_eq!(SilentPaymentAddress::decode(&raw_encode("sp", 0, &p)), Err(AddressError::InvalidKey));
        let mut p = payload(&k);
        p[0] = 0x05;
        assert_eq!(SilentPaymentAddress::decode(&raw_encode("sp", 0, &p)), Err(AddressError::InvalidKey));
    }

    #[test]
    fn rejects_non_zero_padding() {
        // 66 bytes = 528 bits -> 106 groups of 5 bits with 2 padding bits. Flip a padding bit.
        let addr = keys(Network::Mainnet).address().encode();
        let checked = CheckedHrpstring::new::<Bech32m>(&addr).unwrap();
        let data = checked.data_part_ascii_no_checksum().to_vec();
        let mut fes: Vec<Fe32> = data.iter().map(|&c| Fe32::from_char(c as char).unwrap()).collect();
        let last = fes.len() - 1;
        fes[last] = Fe32::try_from(fes[last].to_u8() | 1).unwrap();
        let hrp = Hrp::parse("sp").unwrap();
        let tampered: String = fes.into_iter().with_checksum::<Bech32m>(&hrp).chars().collect();
        assert_eq!(SilentPaymentAddress::decode(&tampered), Err(AddressError::InvalidPadding));
    }

    #[test]
    fn rejects_overlong_strings() {
        let k = keys(Network::Mainnet);
        let mut huge = payload(&k);
        huge.resize(700, 0);
        let s = raw_encode("sp", 1, &huge);
        assert!(s.len() > MAX_ADDRESS_LEN);
        assert!(matches!(SilentPaymentAddress::decode(&s), Err(AddressError::Bech32(_))));
    }

    #[test]
    fn rejects_garbage() {
        for s in ["", "sp1", "sp1q", "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "hello world"] {
            assert!(SilentPaymentAddress::decode(s).is_err(), "{s}");
        }
    }
}
