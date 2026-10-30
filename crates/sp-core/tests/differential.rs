//! Cross-checks against independent implementations:
//!
//! - `bitcoin` (rust-bitcoin, libsecp256k1) for BIP32 derivation of the BIP352 paths,
//! - `silentpayments` (rust-silentpayments, libsecp256k1) for addresses, labels, the change label,
//!   and end-to-end scanning with the exported watch-only key.

mod common;

use std::str::FromStr;

use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::secp256k1::Secp256k1;
use common::test_app_seed;
use silentpayments::receiving::{Label, Receiver};
use silentpayments::secp256k1 as sp_secp;
use silentpayments::{Network as SpNetwork, SilentPaymentCode, SpVersion};
use sp_core::descriptor::parse_watch_only_descriptor;
use sp_core::export::WatchOnlyExport;
use sp_core::seed::bip32_seed_from_app_seed;
use sp_core::{AppState, Network, ReceiverKeys};

const SEEDS: u32 = 48;
const LABELS: [u32; 8] = [1, 2, 3, 7, 42, 1000, 1_001_337, u32::MAX];

fn sp_network(n: Network) -> SpNetwork {
    match n {
        Network::Mainnet => SpNetwork::Mainnet,
        Network::Testnet => SpNetwork::Testnet,
    }
}

/// Builds a rust-silentpayments receiver from raw scan secret and spend public key bytes.
fn reference_receiver(scan_secret: &[u8; 32], spend_public: &[u8; 33], network: Network) -> (Receiver, sp_secp::SecretKey) {
    let secp = sp_secp::Secp256k1::new();
    let b_scan = sp_secp::SecretKey::from_slice(scan_secret).unwrap();
    let scan_pub = sp_secp::PublicKey::from_secret_key(&secp, &b_scan);
    let spend_pub = sp_secp::PublicKey::from_slice(spend_public).unwrap();
    let receiver = Receiver::new(SpVersion::ZERO, scan_pub, spend_pub, Label::new(b_scan, 0), sp_network(network)).unwrap();
    (receiver, b_scan)
}

#[test]
fn bip352_paths_match_rust_bitcoin() {
    let secp = Secp256k1::new();
    for network in Network::ALL {
        let coin = network.coin_type();
        for i in 0..SEEDS {
            let app_seed = test_app_seed(i);
            let ours = ReceiverKeys::derive_from_app_seed(&app_seed, network, 0).unwrap();

            let seed = bip32_seed_from_app_seed(&app_seed);
            let master = Xpriv::new_master(bitcoin::NetworkKind::Main, &*seed).unwrap();
            let scan_path = DerivationPath::from_str(&format!("m/352'/{coin}'/0'/1'/0")).unwrap();
            let spend_path = DerivationPath::from_str(&format!("m/352'/{coin}'/0'/0'/0")).unwrap();
            let scan = master.derive_priv(&secp, &scan_path).unwrap();
            let spend = master.derive_priv(&secp, &spend_path).unwrap();

            assert_eq!(*ours.scan_secret_bytes(), scan.private_key.secret_bytes(), "seed {i} {network:?}");
            assert_eq!(ours.scan_public_bytes(), scan.private_key.public_key(&secp).serialize());
            assert_eq!(ours.spend_public_bytes(), spend.private_key.public_key(&secp).serialize());
            assert_eq!(ours.origin().master_fingerprint, master.fingerprint(&secp).to_bytes());
        }
    }
}

#[test]
fn addresses_and_labels_match_rust_silentpayments() {
    for network in Network::ALL {
        for i in 0..SEEDS {
            let ours = ReceiverKeys::derive_from_app_seed(&test_app_seed(i), network, 0).unwrap();
            let (mut reference, b_scan) =
                reference_receiver(&ours.scan_secret_bytes(), &ours.spend_public_bytes(), network);

            assert_eq!(ours.address().encode(), reference.receiving_code().to_string());
            assert_eq!(ours.labeled_address(0).unwrap().encode(), reference.change_code().to_string());

            for m in LABELS {
                let label = Label::new(b_scan, m);
                reference.add_label(label.clone()).unwrap();
                let expected = reference.receiving_code_for_label(&label).unwrap().to_string();
                assert_eq!(ours.labeled_address(m).unwrap().encode(), expected, "seed {i} m {m}");
            }
        }
    }
}

#[test]
fn reference_decoder_accepts_our_addresses() {
    for network in Network::ALL {
        let ours = ReceiverKeys::derive_from_app_seed(&test_app_seed(1), network, 0).unwrap();
        for address in [ours.address(), ours.labeled_address(5).unwrap()] {
            let decoded = SilentPaymentCode::from_str(&address.encode()).unwrap();
            assert_eq!(decoded.network(), sp_network(network));
            assert_eq!(decoded.scan_key().serialize(), *address.scan_key());
            assert_eq!(decoded.m_pubkey().serialize(), *address.spend_key());
        }
    }
}

/// The exported descriptor, parsed back and handed to an independent scanner, detects payments
/// made to the unlabelled address and to labelled addresses, and nothing else.
#[test]
fn watch_only_export_detects_payments_in_reference_scanner() {
    let secp = sp_secp::Secp256k1::new();
    for network in Network::ALL {
        let keys = ReceiverKeys::derive_from_app_seed(&test_app_seed(7), network, 0).unwrap();
        let mut state = AppState::new();
        state.set_network(network);
        for name in ["Personal", "Donations", "Business"] {
            state.create_label(name).unwrap();
        }
        let export = WatchOnlyExport::new(&keys, &state);

        // A wallet importing the export only gets the descriptor text plus the label range.
        let parsed = parse_watch_only_descriptor(&export.descriptor).unwrap();
        assert_eq!(parsed.key.network, network);
        let scan_secret: [u8; 32] = parsed.key.scan_secret.to_bytes().into();
        let spend_public = sp_core::keys::compressed(&parsed.key.spend_public);
        let (mut watcher, b_scan) = reference_receiver(&scan_secret, &spend_public, network);
        for m in 1..=export.max_label.unwrap() {
            watcher.add_label(Label::new(b_scan, m)).unwrap();
        }

        // Senders pay to what the device displays.
        let targets = [
            (None, keys.address()),
            (Some(1u32), keys.labeled_address(1).unwrap()),
            (Some(3u32), keys.labeled_address(3).unwrap()),
        ];
        for (n, (label, address)) in targets.iter().enumerate() {
            let sender_key = sp_secp::SecretKey::from_slice(&test_app_seed(1000 + n as u32)).unwrap();
            let outpoint = silentpayments::utils::OutPoint::from_txid_bytes_and_vout(test_app_seed(2000 + n as u32), 0);
            let partial = silentpayments::utils::sending::calculate_partial_secret(&[(sender_key, false)], &[outpoint]).unwrap();
            let recipient = SilentPaymentCode::from_str(&address.encode()).unwrap();
            let outputs = silentpayments::sending::generate_recipient_pubkeys([recipient], partial).unwrap();
            let output = outputs[&recipient][0];

            // An unrelated taproot output in the same transaction must not match.
            let unrelated = sp_secp::SecretKey::from_slice(&test_app_seed(3000 + n as u32))
                .unwrap()
                .x_only_public_key(&secp)
                .0;

            let sender_pub = sp_secp::PublicKey::from_secret_key(&secp, &sender_key);
            let tweak = silentpayments::utils::receiving::calculate_tweak_data(&[&sender_pub], &[outpoint]).unwrap();
            let shared = silentpayments::utils::receiving::calculate_ecdh_shared_secret(&tweak, &b_scan);
            let found = watcher.scan_transaction(&shared, &[unrelated, output]).unwrap();

            let expected_label = label.map(|m| Label::new(b_scan, m));
            assert_eq!(found.len(), 1, "{network:?} target {n}");
            let outputs_for_label = &found[&expected_label];
            assert_eq!(outputs_for_label.len(), 1);
            assert!(outputs_for_label.contains_key(&output));
        }
    }
}
