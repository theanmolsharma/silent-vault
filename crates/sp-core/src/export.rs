//! Watch-only export bundle shown on the export screen.

use core::fmt;

use zeroize::Zeroizing;

use crate::descriptor::watch_only_descriptor;
use crate::keys::ReceiverKeys;
use crate::network::Network;
use crate::store::{AppState, LabelRecord};

/// What the export screen shows after PIN and slide-to-confirm.
///
/// Only `descriptor` goes into the QR code: it is the standard BIP392 format. The label list is
/// shown as text because no standard carries label names; BIP352 asks that label usage be part
/// of a backup, so the screen states which label integers a scanner must check.
pub struct WatchOnlyExport {
    /// `sp([fp/352h/coin'h/0h]spscan1q…)#checksum`. Contains the scan private key.
    pub descriptor: Zeroizing<String>,
    /// Network of the keys.
    pub network: Network,
    /// Master key fingerprint, lowercase hex.
    pub fingerprint: String,
    /// Account path in BIP380 notation, e.g. `m/352h/0h/0h`.
    pub account_path: String,
    /// Highest label integer ever issued; a scanner should check labels `1..=max_label`.
    pub max_label: Option<u32>,
    /// Current labels and their names.
    pub labels: Vec<LabelRecord>,
}

impl WatchOnlyExport {
    /// Builds the export for the current keys and labels.
    pub fn new(keys: &ReceiverKeys, state: &AppState) -> Self {
        let origin = keys.origin();
        Self {
            descriptor: watch_only_descriptor(keys),
            network: keys.network(),
            fingerprint: origin.fingerprint_hex(),
            account_path: format!("m/{}", origin.account_path()),
            max_label: state.max_issued_label(),
            labels: state.labels().to_vec(),
        }
    }

    /// One-line instruction about which labels a scanning wallet must check.
    pub fn label_scan_hint(&self) -> String {
        match self.max_label {
            None => "No labels issued. Scanners only need the change label (0).".into(),
            Some(1) => "Scan for label 1 and the change label (0).".into(),
            Some(m) => format!("Scan for labels 1 to {m} and the change label (0)."),
        }
    }

    /// Label list as `m: name` lines.
    pub fn label_lines(&self) -> Vec<String> { self.labels.iter().map(|l| format!("{}: {}", l.m, l.name)).collect() }
}

impl fmt::Debug for WatchOnlyExport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WatchOnlyExport")
            .field("descriptor", &"<redacted>")
            .field("network", &self.network)
            .field("fingerprint", &self.fingerprint)
            .field("account_path", &self.account_path)
            .field("max_label", &self.max_label)
            .field("labels", &self.labels.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::descriptor::parse_watch_only_descriptor;

    #[test]
    fn export_contents() {
        let keys = ReceiverKeys::derive(&[7u8; 32], Network::Mainnet, 0).unwrap();
        let mut state = AppState::new();
        let export = WatchOnlyExport::new(&keys, &state);
        assert_eq!(export.max_label, None);
        assert_eq!(export.account_path, "m/352h/0h/0h");
        assert!(export.label_scan_hint().contains("change label (0)"));

        state.create_label("Personal").unwrap();
        state.create_label("Donations").unwrap();
        state.delete_label(1).unwrap();
        let export = WatchOnlyExport::new(&keys, &state);
        assert_eq!(export.max_label, Some(2));
        assert_eq!(export.label_lines(), vec!["2: Donations".to_string()]);
        assert_eq!(export.label_scan_hint(), "Scan for labels 1 to 2 and the change label (0).");

        let parsed = parse_watch_only_descriptor(&export.descriptor).unwrap();
        assert_eq!(parsed.key.network, Network::Mainnet);
        assert!(!format!("{export:?}").contains("spscan"));
    }
}
