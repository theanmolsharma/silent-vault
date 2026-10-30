//! Prints key material and the addresses/descriptors `sp-core` derives for a set of test-only
//! seeds, as JSON for `tools/bip352_reference_crosscheck.py`. Never run this with a real seed.

use sha2::{Digest, Sha256};
use sp_core::{AppState, Network, ReceiverKeys, WatchOnlyExport};

const LABELS: [u32; 6] = [1, 2, 3, 50, 1337, 4_294_967_295];

fn test_app_seed(i: u32) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"sp-receive-card crosscheck seed");
    h.update(i.to_be_bytes());
    h.finalize().into()
}

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

fn main() {
    let mut cases = Vec::new();
    for i in 0..16 {
        for network in Network::ALL {
            let keys = ReceiverKeys::derive_from_app_seed(&test_app_seed(i), network, 0).unwrap();
            let mut state = AppState::new();
            state.set_network(network);
            let export = WatchOnlyExport::new(&keys, &state);
            let labeled: Vec<_> = LABELS
                .iter()
                .map(|&m| serde_json::json!({ "m": m, "address": keys.labeled_address(m).unwrap().encode() }))
                .collect();
            cases.push(serde_json::json!({
                "app_seed": hex(&test_app_seed(i)),
                "hrp": network.sp_hrp(),
                "coin_type": network.coin_type(),
                "scan_priv_key": hex(&*keys.scan_secret_bytes()),
                "spend_pub_key": hex(&keys.spend_public_bytes()),
                "master_fingerprint": keys.origin().fingerprint_hex(),
                "address": keys.address().encode(),
                "change_address": keys.labeled_address(0).unwrap().encode(),
                "labeled": labeled,
                "descriptor": export.descriptor.as_str(),
            }));
        }
    }
    println!("{}", serde_json::to_string_pretty(&cases).unwrap());
}
