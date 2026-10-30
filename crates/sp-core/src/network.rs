//! Network parameters for silent payment addresses and key derivation.

use core::fmt;

use serde::{Deserialize, Serialize};

/// The Bitcoin network a receiving identity is used on.
///
/// BIP352 defines two address prefixes: `sp` for mainnet and `tsp` for test networks
/// ("e.g. signet, testnet"), so testnet3, testnet4 and signet all share [`Network::Testnet`].
/// The BIP44 coin type used in the BIP352 derivation path follows the same split.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    /// Bitcoin mainnet: `sp` addresses, coin type `0'`.
    Mainnet,
    /// Bitcoin test networks (testnet, signet): `tsp` addresses, coin type `1'`.
    Testnet,
}

impl Network {
    /// Every supported network, mainnet first.
    pub const ALL: [Network; 2] = [Network::Mainnet, Network::Testnet];

    /// BIP352 address human-readable part.
    pub const fn sp_hrp(self) -> &'static str {
        match self {
            Network::Mainnet => "sp",
            Network::Testnet => "tsp",
        }
    }

    /// BIP392 `spscan` key-expression human-readable part.
    pub const fn spscan_hrp(self) -> &'static str {
        match self {
            Network::Mainnet => "spscan",
            Network::Testnet => "tspscan",
        }
    }

    /// BIP44 coin type used at the second level of the BIP352 derivation path.
    pub const fn coin_type(self) -> u32 {
        match self {
            Network::Mainnet => 0,
            Network::Testnet => 1,
        }
    }

    /// Network for a BIP352 address HRP. The HRP must already be lowercase.
    pub fn from_sp_hrp(hrp: &str) -> Option<Network> {
        Network::ALL.into_iter().find(|n| n.sp_hrp() == hrp)
    }

    /// Network for a BIP392 `spscan` HRP. The HRP must already be lowercase.
    pub fn from_spscan_hrp(hrp: &str) -> Option<Network> {
        Network::ALL.into_iter().find(|n| n.spscan_hrp() == hrp)
    }

    /// Short user-facing name.
    pub const fn display_name(self) -> &'static str {
        match self {
            Network::Mainnet => "Mainnet",
            Network::Testnet => "Testnet / Signet",
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(self.display_name()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parameters_match_bip352() {
        assert_eq!(Network::Mainnet.sp_hrp(), "sp");
        assert_eq!(Network::Testnet.sp_hrp(), "tsp");
        assert_eq!(Network::Mainnet.coin_type(), 0);
        assert_eq!(Network::Testnet.coin_type(), 1);
        assert_eq!(Network::Mainnet.spscan_hrp(), "spscan");
        assert_eq!(Network::Testnet.spscan_hrp(), "tspscan");
    }

    #[test]
    fn hrp_round_trip() {
        for n in Network::ALL {
            assert_eq!(Network::from_sp_hrp(n.sp_hrp()), Some(n));
            assert_eq!(Network::from_spscan_hrp(n.spscan_hrp()), Some(n));
        }
        assert_eq!(Network::from_sp_hrp("bc"), None);
        assert_eq!(Network::from_sp_hrp("sprt"), None);
        assert_eq!(Network::from_sp_hrp("spscan"), None);
    }

    #[test]
    fn serde_names_are_stable() {
        assert_eq!(serde_json::to_string(&Network::Mainnet).unwrap(), "\"mainnet\"");
        assert_eq!(serde_json::to_string(&Network::Testnet).unwrap(), "\"testnet\"");
        assert!(serde_json::from_str::<Network>("\"regtest\"").is_err());
    }
}
