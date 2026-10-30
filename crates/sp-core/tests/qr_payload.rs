//! QR payload validation: the pixels the app puts on screen decode, with an independent decoder
//! (`rqrr`), to exactly the address or descriptor string, which in turn decodes to the right keys.

mod common;

use common::test_app_seed;
use sp_core::descriptor::parse_watch_only_descriptor;
use sp_core::qr::QrMatrix;
use sp_core::{AppState, Network, ReceiverKeys, SilentPaymentAddress, WatchOnlyExport};

/// Same path as the app: payload -> QrMatrix -> RGBA at an integer scale -> decoder.
fn render_and_scan(payload: &str, max_px: usize) -> String {
    let matrix = QrMatrix::encode(payload).unwrap();
    let scale = matrix.scale_for(max_px);
    let (side, rgba) = matrix.to_rgba(scale);
    let mut image = rqrr::PreparedImage::prepare_from_bitmap(side, side, |x, y| rgba[(y * side + x) * 4] < 0x80);
    let grids = image.detect_grids();
    assert_eq!(grids.len(), 1, "expected exactly one QR code");
    grids[0].decode().unwrap().1
}

#[test]
fn address_qr_contains_exactly_the_address() {
    for network in Network::ALL {
        let keys = ReceiverKeys::derive_from_app_seed(&test_app_seed(11), network, 0).unwrap();
        let addresses = [keys.address(), keys.labeled_address(1).unwrap(), keys.labeled_address(49).unwrap()];
        for address in addresses {
            let payload = address.qr_payload();
            assert_eq!(payload, address.encode());
            assert!(payload.starts_with(&format!("{}1q", network.sp_hrp())));
            assert!(payload.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
            assert!(!payload.contains(':'), "no URI scheme");

            for max_px in [120, 360, 560] {
                let scanned = render_and_scan(&payload, max_px);
                assert_eq!(scanned, payload);
                assert_eq!(SilentPaymentAddress::decode(&scanned).unwrap(), address);
            }
        }
    }
}

#[test]
fn export_qr_contains_exactly_the_descriptor() {
    let keys = ReceiverKeys::derive_from_app_seed(&test_app_seed(12), Network::Mainnet, 0).unwrap();
    let mut state = AppState::new();
    state.create_label("Conference").unwrap();
    let export = WatchOnlyExport::new(&keys, &state);
    let scanned = render_and_scan(&export.descriptor, 480);
    assert_eq!(scanned, export.descriptor.as_str());
    let parsed = parse_watch_only_descriptor(&scanned).unwrap();
    assert_eq!(sp_core::keys::compressed(&parsed.key.spend_public), keys.spend_public_bytes());
}

#[test]
fn qr_sizes_stay_scannable_on_device() {
    for network in Network::ALL {
        let keys = ReceiverKeys::derive_from_app_seed(&test_app_seed(13), network, 0).unwrap();
        let address = QrMatrix::encode(&keys.address().qr_payload()).unwrap();
        let export = WatchOnlyExport::new(&keys, &AppState::new());
        let export = QrMatrix::encode(&export.descriptor).unwrap();
        // Single static codes: version 7 (45 modules) for addresses, at most version 11 for the export.
        assert!(address.width() <= 45, "address QR is {} modules", address.width());
        assert!(export.width() <= 61, "export QR is {} modules", export.width());
        // At least 4 px per module on a 400 px area.
        assert!(address.scale_for(400) >= 4 && export.scale_for(400) >= 4);
    }
}
