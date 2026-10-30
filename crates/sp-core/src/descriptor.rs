//! Watch-only export format: BIP392 `sp()` descriptors with BIP380 checksums.
//!
//! The export is `sp([fingerprint/352h/coin'h/account'h]spscan1q...)#checksum`, where the
//! `spscan` key expression (BIP392) is the bech32m encoding of HRP `spscan`/`tspscan`, version
//! `q`, and `ser_256(b_scan) || ser_P(B_spend)`. It lets a scanning wallet detect payments but
//! not spend them.

use core::fmt;

use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32m, ByteIterExt, Fe32, Fe32IterExt, Hrp};
use k256::{PublicKey, SecretKey};
use zeroize::{Zeroize, Zeroizing};

use crate::address::split_version_and_payload;
use crate::keys::{compressed, parse_compressed_point, ReceiverKeys, PURPOSE};
use crate::network::Network;

/// `ser_256(b_scan) || ser_P(B_spend)`.
pub const SPSCAN_PAYLOAD_LEN: usize = 65;

/// Errors from parsing descriptors and `spscan` keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DescriptorError {
    /// A character outside the BIP380 descriptor character set.
    InvalidCharacter,
    /// Missing, malformed or wrong checksum.
    Checksum,
    /// Not of the form `sp(KEY)`.
    Syntax,
    /// Malformed `[fingerprint/path]` key origin.
    KeyOrigin,
    /// Not a valid `spscan` key expression.
    InvalidSpscan(String),
}

impl fmt::Display for DescriptorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DescriptorError::InvalidCharacter => f.write_str("invalid descriptor character"),
            DescriptorError::Checksum => f.write_str("invalid descriptor checksum"),
            DescriptorError::Syntax => f.write_str("expected sp(KEY)"),
            DescriptorError::KeyOrigin => f.write_str("invalid key origin"),
            DescriptorError::InvalidSpscan(e) => write!(f, "invalid spscan key: {e}"),
        }
    }
}

impl std::error::Error for DescriptorError {}

// ---------------------------------------------------------------------------------------------
// BIP380 checksum

const INPUT_CHARSET: &str =
    "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
const CHECKSUM_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GENERATOR: [u64; 5] = [0xf5dee51989, 0xa9fdca3312, 0x1bab10e32d, 0x3706b1677a, 0x644d626ffd];

fn polymod(symbols: impl IntoIterator<Item = u64>) -> u64 {
    let mut chk = 1u64;
    for value in symbols {
        let top = chk >> 35;
        chk = ((chk & 0x7_ffff_ffff) << 5) ^ value;
        for (i, generator) in GENERATOR.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= generator;
            }
        }
    }
    chk
}

fn expand(s: &str) -> Result<Vec<u64>, DescriptorError> {
    let mut symbols = Vec::with_capacity(s.len() + s.len() / 3 + 1);
    let mut groups = Vec::with_capacity(3);
    for c in s.chars() {
        let v = INPUT_CHARSET.find(c).ok_or(DescriptorError::InvalidCharacter)? as u64;
        symbols.push(v & 31);
        groups.push(v >> 5);
        if groups.len() == 3 {
            symbols.push(groups[0] * 9 + groups[1] * 3 + groups[2]);
            groups.clear();
        }
    }
    match groups.as_slice() {
        [g] => symbols.push(*g),
        [g0, g1] => symbols.push(g0 * 3 + g1),
        _ => {}
    }
    Ok(symbols)
}

/// The 8-character BIP380 checksum of a descriptor without `#checksum`.
pub fn checksum(descriptor: &str) -> Result<String, DescriptorError> {
    let mut symbols = expand(descriptor)?;
    symbols.extend([0; 8]);
    let c = polymod(symbols) ^ 1;
    Ok((0..8).map(|i| CHECKSUM_CHARSET[((c >> (5 * (7 - i))) & 31) as usize] as char).collect())
}

/// `descriptor#checksum`.
pub fn with_checksum(descriptor: &str) -> Result<String, DescriptorError> {
    Ok(format!("{descriptor}#{}", checksum(descriptor)?))
}

/// Verifies `descriptor#checksum` and returns the descriptor part.
pub fn verify_checksum(s: &str) -> Result<&str, DescriptorError> {
    let (body, sum) = s.rsplit_once('#').ok_or(DescriptorError::Checksum)?;
    if sum.len() != 8 || !sum.bytes().all(|b| CHECKSUM_CHARSET.contains(&b)) {
        return Err(DescriptorError::Checksum);
    }
    let mut symbols = expand(body)?;
    symbols.extend(sum.bytes().map(|b| CHECKSUM_CHARSET.iter().position(|&c| c == b).unwrap() as u64));
    if polymod(symbols) == 1 {
        Ok(body)
    } else {
        Err(DescriptorError::Checksum)
    }
}

// ---------------------------------------------------------------------------------------------
// BIP392 spscan key expression

/// Bech32m `spscan` encoding of `ser_256(b_scan) || ser_P(B_spend)`.
pub fn encode_spscan(network: Network, scan_secret: &[u8; 32], spend_public: &[u8; 33]) -> Zeroizing<String> {
    let mut payload = Zeroizing::new([0u8; SPSCAN_PAYLOAD_LEN]);
    payload[..32].copy_from_slice(scan_secret);
    payload[32..].copy_from_slice(spend_public);
    let hrp = Hrp::parse(network.spscan_hrp()).expect("static HRPs are valid");
    Zeroizing::new(
        payload
            .iter()
            .copied()
            .bytes_to_fes()
            .with_checksum::<Bech32m>(&hrp)
            .with_witness_version(Fe32::Q)
            .chars()
            .collect(),
    )
}

/// A decoded `spscan` key: everything a scanning wallet needs.
pub struct SpscanKey {
    /// Network from the HRP.
    pub network: Network,
    /// `b_scan`, zeroized on drop.
    pub scan_secret: SecretKey,
    /// `B_spend`.
    pub spend_public: PublicKey,
}

impl fmt::Debug for SpscanKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpscanKey")
            .field("network", &self.network)
            .field("scan_secret", &"<redacted>")
            .field("spend_public", &crate::keys::hex_lower(&compressed(&self.spend_public)))
            .finish()
    }
}

/// Parses a BIP392 `spscan` key expression (version 0 only).
pub fn decode_spscan(s: &str) -> Result<SpscanKey, DescriptorError> {
    let invalid = |e: &dyn fmt::Display| DescriptorError::InvalidSpscan(e.to_string());
    let checked = CheckedHrpstring::new::<Bech32m>(s).map_err(|e| invalid(&e))?;
    let hrp = checked.hrp().to_lowercase();
    let network = Network::from_spscan_hrp(&hrp).ok_or_else(|| invalid(&format_args!("unknown prefix {hrp}")))?;
    let (version, mut payload) =
        split_version_and_payload(checked.data_part_ascii_no_checksum()).map_err(|e| invalid(&e))?;
    let result = (|| {
        if version != 0 {
            return Err(invalid(&format_args!("unsupported version {version}")));
        }
        if payload.len() != SPSCAN_PAYLOAD_LEN {
            return Err(invalid(&format_args!("payload is {} bytes", payload.len())));
        }
        let scan_secret = SecretKey::from_slice(&payload[..32])
            .map_err(|_| invalid(&"scan key is not a valid secret key"))?;
        let spend: [u8; 33] = payload[32..].try_into().expect("length checked");
        let spend_public = parse_compressed_point(&spend).map_err(|e| invalid(&e))?;
        Ok(SpscanKey { network, scan_secret, spend_public })
    })();
    payload.zeroize();
    result
}

// ---------------------------------------------------------------------------------------------
// sp() descriptors

/// The watch-only BIP392 descriptor for `keys`, with key origin and checksum.
///
/// This string contains the scan private key. Show it only after the user has authenticated and
/// never persist it.
pub fn watch_only_descriptor(keys: &ReceiverKeys) -> Zeroizing<String> {
    let origin = keys.origin();
    let spscan = encode_spscan(keys.network(), &keys.scan_secret_bytes(), &keys.spend_public_bytes());
    let body = Zeroizing::new(format!(
        "sp([{}/{}]{})",
        origin.fingerprint_hex(),
        origin.account_path(),
        spscan.as_str()
    ));
    Zeroizing::new(with_checksum(&body).expect("descriptor only uses checksum-safe characters"))
}

/// Key origin as written in a descriptor: master fingerprint plus derivation steps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescriptorOrigin {
    /// Master key fingerprint.
    pub fingerprint: [u8; 4],
    /// Child numbers as `(index, hardened)`.
    pub path: Vec<(u32, bool)>,
}

impl DescriptorOrigin {
    /// Whether the path is exactly `352h/coin'h/account'h` for `network`.
    pub fn is_bip352_account(&self, network: Network) -> bool {
        matches!(self.path.as_slice(),
            [(PURPOSE, true), (coin, true), (_, true)] if *coin == network.coin_type())
    }
}

/// A parsed watch-only `sp(spscan…)` descriptor.
#[derive(Debug)]
pub struct WatchOnlyDescriptor {
    /// Optional key origin.
    pub origin: Option<DescriptorOrigin>,
    /// The decoded `spscan` key.
    pub key: SpscanKey,
}

/// Parses `sp([origin]spscan1…)#checksum`. A checksum is required.
pub fn parse_watch_only_descriptor(s: &str) -> Result<WatchOnlyDescriptor, DescriptorError> {
    let body = verify_checksum(s)?;
    let inner = body.strip_prefix("sp(").and_then(|r| r.strip_suffix(')')).ok_or(DescriptorError::Syntax)?;
    if inner.contains(',') || inner.contains('(') {
        return Err(DescriptorError::Syntax);
    }
    let (origin, key) = match inner.strip_prefix('[') {
        Some(rest) => {
            let (origin, key) = rest.split_once(']').ok_or(DescriptorError::KeyOrigin)?;
            (Some(parse_origin(origin)?), key)
        }
        None => (None, inner),
    };
    let key = decode_spscan(key)?;
    if let Some(origin) = &origin {
        if !origin.is_bip352_account(key.network) {
            return Err(DescriptorError::KeyOrigin);
        }
    }
    Ok(WatchOnlyDescriptor { origin, key })
}

fn parse_origin(s: &str) -> Result<DescriptorOrigin, DescriptorError> {
    let mut parts = s.split('/');
    let fp = parts.next().ok_or(DescriptorError::KeyOrigin)?;
    if fp.len() != 8 || !fp.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(DescriptorError::KeyOrigin);
    }
    let mut fingerprint = [0u8; 4];
    for (i, byte) in fingerprint.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&fp[2 * i..2 * i + 2], 16).map_err(|_| DescriptorError::KeyOrigin)?;
    }
    let path = parts
        .map(|step| {
            let (num, hardened) = match step.strip_suffix(['h', '\'']) {
                Some(num) => (num, true),
                None => (step, false),
            };
            if num.is_empty() || !num.bytes().all(|b| b.is_ascii_digit()) {
                return Err(DescriptorError::KeyOrigin);
            }
            let index: u32 = num.parse().map_err(|_| DescriptorError::KeyOrigin)?;
            if index >= 1 << 31 {
                return Err(DescriptorError::KeyOrigin);
            }
            Ok((index, hardened))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(DescriptorOrigin { fingerprint, path })
}

#[cfg(test)]
mod tests {
    use super::*;

    // BIP380 "Test Vectors" for the checksum.
    #[test]
    fn bip380_checksum_vectors() {
        assert_eq!(checksum("raw(deadbeef)").unwrap(), "89f8spxm");
        assert_eq!(verify_checksum("raw(deadbeef)#89f8spxm").unwrap(), "raw(deadbeef)");
        assert!(verify_checksum("raw(deadbeef)").is_err());
        assert!(verify_checksum("raw(deadbeef)#").is_err());
        assert!(verify_checksum("raw(deadbeef)#89f8spxmx").is_err());
        assert!(verify_checksum("raw(deadbeef)#89f8spx").is_err());
        assert!(verify_checksum("raw(deedbeef)#89f8spxm").is_err());
        assert!(verify_checksum("raw(deedbeef)##9f8spxm").is_err());
        assert_eq!(verify_checksum("raw(Ü)#00000000"), Err(DescriptorError::InvalidCharacter));
    }

    #[test]
    fn spscan_round_trip_and_prefixes() {
        for network in Network::ALL {
            let keys = ReceiverKeys::derive(&[3u8; 32], network, 0).unwrap();
            let s = encode_spscan(network, &keys.scan_secret_bytes(), &keys.spend_public_bytes());
            assert!(s.starts_with(&format!("{}1q", network.spscan_hrp())));
            let decoded = decode_spscan(&s).unwrap();
            assert_eq!(decoded.network, network);
            assert_eq!(*keys.scan_secret_bytes(), <[u8; 32]>::from(decoded.scan_secret.to_bytes()));
            assert_eq!(compressed(&decoded.spend_public), keys.spend_public_bytes());
        }
    }

    #[test]
    fn spscan_rejects_address_and_bad_payloads() {
        let keys = ReceiverKeys::derive(&[3u8; 32], Network::Mainnet, 0).unwrap();
        assert!(decode_spscan(&keys.address().encode()).is_err());
        let zero_scan = encode_spscan(Network::Mainnet, &[0u8; 32], &keys.spend_public_bytes());
        assert!(decode_spscan(&zero_scan).is_err());
        let mut bad_point = keys.spend_public_bytes();
        bad_point[0] = 0x04;
        assert!(decode_spscan(&encode_spscan(Network::Mainnet, &[1u8; 32], &bad_point)).is_err());
    }

    #[test]
    fn descriptor_shape() {
        let keys = ReceiverKeys::derive(&[5u8; 32], Network::Mainnet, 0).unwrap();
        let d = watch_only_descriptor(&keys);
        let fp = keys.origin().fingerprint_hex();
        assert!(d.starts_with(&format!("sp([{fp}/352h/0h/0h]spscan1q")), "{}", d.as_str());
        let body = verify_checksum(&d).unwrap();
        assert!(body.ends_with(')'));
        let parsed = parse_watch_only_descriptor(&d).unwrap();
        assert_eq!(parsed.origin.as_ref().unwrap().fingerprint, keys.origin().master_fingerprint);
        assert_eq!(parsed.key.network, Network::Mainnet);

        let t = ReceiverKeys::derive(&[5u8; 32], Network::Testnet, 0).unwrap();
        assert!(watch_only_descriptor(&t).starts_with(&format!("sp([{fp}/352h/1h/0h]tspscan1q")));
    }

    #[test]
    fn descriptor_parser_rejects_malformed_input() {
        let keys = ReceiverKeys::derive(&[5u8; 32], Network::Mainnet, 0).unwrap();
        let spscan = encode_spscan(Network::Mainnet, &keys.scan_secret_bytes(), &keys.spend_public_bytes());
        let fp = keys.origin().fingerprint_hex();
        let cases = [
            format!("sp({})", spscan.as_str()),                                // no checksum
            with_checksum(&format!("sh(sp({}))", spscan.as_str())).unwrap(),   // not top level
            with_checksum(&format!("sp({0},{0})", spscan.as_str())).unwrap(),  // two spscan keys
            with_checksum(&format!("sp([{fp}/352h/1h/0h]{})", spscan.as_str())).unwrap(), // coin mismatch
            with_checksum(&format!("sp([{fp}/352h/0h]{})", spscan.as_str())).unwrap(),    // short path
            with_checksum(&format!("sp([zzzzzzzz/352h/0h/0h]{})", spscan.as_str())).unwrap(),
            with_checksum(&format!("sp([{fp}/352H/0h/0h]{})", spscan.as_str())).unwrap(),
            with_checksum("sp()").unwrap(),
        ];
        for case in &cases {
            assert!(parse_watch_only_descriptor(case).is_err(), "{case}");
        }
        // Apostrophe hardened markers and no origin are both fine.
        assert!(parse_watch_only_descriptor(&with_checksum(&format!("sp([{fp}/352'/0'/0']{})", spscan.as_str())).unwrap()).is_ok());
        assert!(parse_watch_only_descriptor(&with_checksum(&format!("sp({})", spscan.as_str())).unwrap()).is_ok());
    }
}
