//! Persistence and recovery: labels survive restarts, addresses are reproducible from the app
//! seed plus the saved label integers, and unreadable data is never silently overwritten.

mod common;

use std::collections::HashMap;

use common::test_app_seed;
use sp_core::store::{load_state, IdentityCheck, LoadOutcome};
use sp_core::{AppState, Network, ReceiverKeys};

/// Stand-in for the app's private storage: a file name to bytes map that only changes on save.
#[derive(Default, Clone)]
struct Disk(HashMap<&'static str, Vec<u8>>);

const STATE_FILE: &str = "state.json";

impl Disk {
    fn save(&mut self, state: &AppState) { self.0.insert(STATE_FILE, state.to_json()); }
    fn load(&self) -> LoadOutcome { load_state(self.0.get(STATE_FILE).map(Vec::as_slice)) }
}

/// What the home screen would show: (label, address) pairs, primary first.
fn screen(app_seed: &[u8; 32], state: &AppState) -> Vec<(String, String)> {
    let keys = ReceiverKeys::derive_from_app_seed(app_seed, state.network(), 0).unwrap();
    let mut rows = vec![("Primary".to_owned(), keys.address().encode())];
    for label in state.labels() {
        rows.push((label.name.clone(), keys.labeled_address(label.m).unwrap().encode()));
    }
    rows
}

#[test]
fn labels_survive_restart() {
    let seed = test_app_seed(21);
    let mut disk = Disk::default();

    // First launch.
    let mut state = disk.load().into_state();
    let keys = ReceiverKeys::derive_from_app_seed(&seed, state.network(), 0).unwrap();
    assert_eq!(state.check_identity(keys.origin().master_fingerprint), IdentityCheck::New);
    for name in ["Personal", "Donations", "Business", "Conference", "Open-source contributions"] {
        state.create_label(name).unwrap();
        disk.save(&state);
    }
    state.rename_label(2, "Tips").unwrap();
    state.delete_label(4).unwrap();
    disk.save(&state);
    let before = screen(&seed, &state);
    drop(state);

    // Restart: only the disk and the (re-fetched) app seed remain.
    let LoadOutcome::Loaded(mut state) = disk.load() else { panic!("expected saved state") };
    let keys = ReceiverKeys::derive_from_app_seed(&seed, state.network(), 0).unwrap();
    assert_eq!(state.check_identity(keys.origin().master_fingerprint), IdentityCheck::Match);
    assert_eq!(screen(&seed, &state), before);
    assert_eq!(state.labels().iter().map(|l| l.m).collect::<Vec<_>>(), vec![1, 2, 3, 5]);
    assert_eq!(state.label(2).unwrap().name, "Tips");

    // New labels after restart continue the sequence; deleted integers are not reused.
    assert_eq!(state.create_label("Family").unwrap().m, 6);
}

#[test]
fn network_preference_survives_restart() {
    let seed = test_app_seed(22);
    let mut disk = Disk::default();
    let mut state = AppState::new();
    state.set_network(Network::Testnet);
    state.create_label("Faucet").unwrap();
    disk.save(&state);
    let state = disk.load().into_state();
    assert_eq!(state.network(), Network::Testnet);
    assert!(screen(&seed, &state).iter().all(|(_, a)| a.starts_with("tsp1q")));
}

/// Restoring the same master seed on another Passport gives the same app seed (current KeyOS
/// behaviour), and Magic Backup restores the app's private storage: everything matches.
#[test]
fn device_recovery_with_restored_storage_reproduces_everything() {
    let seed = test_app_seed(23);
    let mut disk = Disk::default();
    let mut state = AppState::new();
    let keys = ReceiverKeys::derive_from_app_seed(&seed, state.network(), 0).unwrap();
    state.check_identity(keys.origin().master_fingerprint);
    state.create_label("Donations").unwrap();
    disk.save(&state);
    let original = screen(&seed, &state);

    let restored_disk = disk.clone();
    let restored = restored_disk.load().into_state();
    assert_eq!(screen(&seed, &restored), original);
}

/// Without restored storage the identity (primary address) still comes back from the seed; the
/// label names are lost, but label integers re-created in order give the same addresses.
#[test]
fn device_recovery_without_storage_keeps_identity() {
    let seed = test_app_seed(24);
    let mut state = AppState::new();
    state.create_label("Personal").unwrap();
    state.create_label("Business").unwrap();
    let original = screen(&seed, &state);

    let mut fresh = Disk::default().load().into_state();
    assert!(fresh.labels().is_empty());
    assert_eq!(screen(&seed, &fresh)[0], original[0]);
    fresh.create_label("Personal").unwrap();
    fresh.create_label("Business").unwrap();
    assert_eq!(screen(&seed, &fresh), original);
}

#[test]
fn different_seed_is_detected() {
    let mut state = AppState::new();
    let a = ReceiverKeys::derive_from_app_seed(&test_app_seed(25), Network::Mainnet, 0).unwrap();
    let b = ReceiverKeys::derive_from_app_seed(&test_app_seed(26), Network::Mainnet, 0).unwrap();
    state.check_identity(a.origin().master_fingerprint);
    assert_eq!(
        state.check_identity(b.origin().master_fingerprint),
        IdentityCheck::Mismatch { stored: a.origin().master_fingerprint }
    );
}

#[test]
fn unreadable_data_is_reported_not_overwritten() {
    let mut disk = Disk::default();
    disk.0.insert(STATE_FILE, b"{\"version\":1,\"labels\":[".to_vec());
    let outcome = disk.load();
    assert!(matches!(outcome, LoadOutcome::Corrupt { .. }));
    // Loading never writes; the app decides to keep a copy before saving anything new.
    assert_eq!(disk.0[STATE_FILE], b"{\"version\":1,\"labels\":[".to_vec());
    assert_eq!(outcome.into_state(), AppState::new());

    assert!(matches!(load_state(Some(b"")), LoadOutcome::Fresh(_)));
    assert!(matches!(load_state(None), LoadOutcome::Fresh(_)));
}

#[test]
fn saved_file_contains_no_key_material() {
    let seed = test_app_seed(27);
    let keys = ReceiverKeys::derive_from_app_seed(&seed, Network::Mainnet, 0).unwrap();
    let mut state = AppState::new();
    state.check_identity(keys.origin().master_fingerprint);
    state.create_label("Personal").unwrap();
    let saved = String::from_utf8(state.to_json()).unwrap();
    let scan_hex = hex::encode(*keys.scan_secret_bytes());
    let spend_pub_hex = hex::encode(keys.spend_public_bytes());
    for secret_ish in [scan_hex.as_str(), spend_pub_hex.as_str(), &keys.address().encode(), "spscan", "sp1q"] {
        assert!(!saved.contains(secret_ish), "saved state contains {secret_ish}");
    }
    assert!(!saved.contains(&hex::encode(seed)));
}
