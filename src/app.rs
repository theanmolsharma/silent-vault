// SPDX-License-Identifier: MIT

//! Connects the `Sp` UI global to `sp_core`, KeyOS storage and KeyOS security services.
//!
//! Key material: the app seed is fetched, used to derive the receiver keys, and dropped (zeroized)
//! immediately. Only the scan private key and spend public key stay in memory, inside
//! `ReceiverKeys`, for as long as the app runs. The watch-only descriptor exists only while the
//! export screen shows it.

use std::cell::RefCell;
use std::rc::Rc;
use std::time::Duration;

use slint_keyos_platform::slint::{
    self, ComponentHandle, Image, ModelRc, Rgba8Pixel, SharedPixelBuffer, SharedString, Timer, VecModel,
};
use sp_core::qr::QrMatrix;
use sp_core::store::{IdentityCheck, LoadOutcome, MAX_LABELS};
use sp_core::{AppState, Network, ReceiverKeys, SilentPaymentAddress, WatchOnlyExport};
use zeroize::Zeroize;

use crate::device::{self, PinCheck, SeedError};
use crate::storage::Storage;
use crate::{AppWindow, ExportStage, LabelRow, Phase, Sp};

/// v1 uses one BIP352 account.
const ACCOUNT: u32 = 0;
/// The export screen hides the descriptor on its own after this long.
const EXPORT_TIMEOUT: Duration = Duration::from_secs(120);
const NOTICE_TIMEOUT: Duration = Duration::from_secs(3);
/// Largest QR sizes in pixels (the screen is 480 px wide). Codes are rendered at an integer
/// number of pixels per module up to these sizes and shown unscaled.
const QR_HOME_PX: usize = 300;
const QR_DETAIL_PX: usize = 380;
const QR_FULLSCREEN_PX: usize = 456;
const QR_EXPORT_PX: usize = 410;

pub struct App {
    ui: slint::Weak<AppWindow>,
    storage: Storage,
    state: RefCell<AppState>,
    keys: RefCell<Option<ReceiverKeys>>,
    export_timer: Timer,
    notice_timer: Timer,
}

impl App {
    pub fn new(ui: &AppWindow, storage: Storage) -> Rc<Self> {
        Rc::new(Self {
            ui: ui.as_weak(),
            storage,
            state: RefCell::new(AppState::new()),
            keys: RefCell::new(None),
            export_timer: Timer::default(),
            notice_timer: Timer::default(),
        })
    }

    /// Registers every `Sp` callback. Callbacks hold a weak reference to the app.
    pub fn wire(self: &Rc<Self>, ui: &AppWindow) {
        let sp = ui.global::<Sp>();
        let weak = || Rc::downgrade(self);

        let app = weak();
        sp.on_begin_setup(move || app.upgrade().into_iter().for_each(|app| app.begin_setup()));
        let app = weak();
        sp.on_finish_setup(move || app.upgrade().into_iter().for_each(|app| app.set_phase(Phase::Ready)));
        let app = weak();
        sp.on_retry(move || app.upgrade().into_iter().for_each(|app| app.boot()));
        let app = weak();
        sp.on_acknowledge_identity_change(move || {
            app.upgrade().into_iter().for_each(|app| app.acknowledge_identity_change())
        });
        let app = weak();
        sp.on_select_address(move |id| app.upgrade().into_iter().for_each(|app| app.select_address(id)));
        let app = weak();
        sp.on_start_create_label(move || app.upgrade().into_iter().for_each(|app| app.start_create_label()));
        let app = weak();
        sp.on_start_rename_label(move |m| app.upgrade().into_iter().for_each(|app| app.start_rename_label(m)));
        let app = weak();
        sp.on_save_label(move |name| app.upgrade().is_some_and(|app| app.save_label(&name)));
        let app = weak();
        sp.on_delete_label(move |m| app.upgrade().into_iter().for_each(|app| app.delete_label(m)));
        let app = weak();
        sp.on_request_export(move || app.upgrade().into_iter().for_each(|app| app.request_export()));
        let app = weak();
        sp.on_clear_export(move || app.upgrade().into_iter().for_each(|app| app.clear_export()));
        let app = weak();
        sp.on_set_network(move |testnet| app.upgrade().into_iter().for_each(|app| app.set_network(testnet)));
    }

    fn with_sp(&self, f: impl FnOnce(Sp<'_>)) {
        if let Some(ui) = self.ui.upgrade() {
            f(ui.global::<Sp>());
        }
    }

    fn set_phase(&self, phase: Phase) { self.with_sp(|sp| sp.set_phase(phase)); }

    // ------------------------------------------------------------------------------------------
    // Launch and setup

    /// Loads saved state and, if setup is complete, re-derives the keys.
    ///
    /// Runs from a timer after the event loop has started, because deriving the keys may show
    /// the app-seed permission prompt (SDK MIGRATIONS gotcha 24).
    pub fn boot(&self) {
        self.set_phase(Phase::Loading);
        match self.storage.load() {
            Err(e) => {
                log::error!("loading saved state failed: {e:?}");
                self.fail("Storage unavailable", "SP Receive Card could not read its saved data. Try again; if this keeps happening, restart Passport.");
            }
            Ok(outcome) => {
                let corrupt = matches!(outcome, LoadOutcome::Corrupt { .. });
                if let LoadOutcome::Corrupt { error, .. } = &outcome {
                    log::warn!("saved state rejected: {error}");
                }
                *self.state.borrow_mut() = outcome.into_state();
                if corrupt {
                    self.notify("Saved labels could not be read. A copy was kept.", true);
                }
                if self.state.borrow().is_set_up() {
                    self.unlock(false);
                } else {
                    self.set_phase(Phase::Welcome);
                }
            }
        }
    }

    fn begin_setup(self: &Rc<Self>) {
        self.set_phase(Phase::Deriving);
        // Let the spinner paint before the (blocking) permission prompt and key derivation.
        let app = Rc::downgrade(self);
        Timer::single_shot(Duration::from_millis(50), move || {
            if let Some(app) = app.upgrade() {
                app.unlock(true);
            }
        });
    }

    /// Derives the keys for the saved network and shows the home screen.
    fn unlock(&self, first_time: bool) {
        let network = self.state.borrow().network();
        let keys = match derive_keys(network) {
            Ok(keys) => keys,
            Err(SeedError::Denied) => {
                return self.fail(
                    "Seed access needed",
                    "SP Receive Card derives your receiving keys from its app seed. If you chose Not Now, close and reopen the app to be asked again.",
                );
            }
            Err(SeedError::Unavailable) => {
                return self.fail("Passport security unavailable", "The app seed could not be read. Try again.");
            }
        };

        let check = self.state.borrow_mut().check_identity(keys.origin().master_fingerprint);
        match check {
            IdentityCheck::New => {
                if let Err(e) = self.storage.save(&self.state.borrow()) {
                    log::error!("saving new identity failed: {e:?}");
                    self.notify("Could not save. Labels will not be kept.", true);
                }
            }
            IdentityCheck::Match => {}
            IdentityCheck::Mismatch { .. } => {
                log::warn!("derived identity differs from the saved one");
                self.with_sp(|sp| sp.set_identity_changed(true));
            }
        }

        *self.keys.borrow_mut() = Some(keys);
        self.refresh();
        self.set_phase(if first_time { Phase::Created } else { Phase::Ready });
    }

    fn fail(&self, title: &str, message: &str) {
        self.with_sp(|sp| {
            sp.set_failure_title(title.into());
            sp.set_failure_message(message.into());
            sp.set_phase(Phase::Failed);
        });
    }

    fn acknowledge_identity_change(&self) {
        let Some(fingerprint) = self.keys.borrow().as_ref().map(|k| k.origin().master_fingerprint) else { return };
        let mut next = self.state.borrow().clone();
        next.replace_identity(fingerprint);
        if self.commit(next) {
            self.with_sp(|sp| sp.set_identity_changed(false));
        }
    }

    // ------------------------------------------------------------------------------------------
    // Home screen data

    /// Pushes addresses, labels and identity details to the UI.
    fn refresh(&self) {
        let keys = self.keys.borrow();
        let Some(keys) = keys.as_ref() else { return };
        let state = self.state.borrow();
        let primary = keys.address().encode();

        let rows: Vec<LabelRow> = state
            .labels()
            .iter()
            .filter_map(|label| {
                let address = keys.labeled_address(label.m).ok()?.encode();
                Some(LabelRow {
                    m: label.m as i32,
                    name: label.name.as_str().into(),
                    short_address: shorten(&address).into(),
                })
            })
            .collect();

        self.with_sp(|sp| {
            let network = keys.network();
            sp.set_network_name(network.display_name().into());
            sp.set_testnet(network == Network::Testnet);
            sp.set_fingerprint(keys.origin().fingerprint_hex().into());
            sp.set_account_path(format!("m/{}", keys.origin().account_path().replace('h', "'")).into());
            sp.set_primary_qr(qr_image(&keys.address().qr_payload(), QR_HOME_PX));
            sp.set_primary_address(primary.into());
            sp.set_labels(ModelRc::new(VecModel::from(rows)));
            sp.set_can_add_label(state.labels().len() < MAX_LABELS);
            sp.set_max_labels(MAX_LABELS as i32);
        });
    }

    /// Fills the address page. `id` 0 is the unlabelled address; otherwise it is a label `m`.
    fn select_address(&self, id: i32) {
        let keys = self.keys.borrow();
        let Some(keys) = keys.as_ref() else { return };
        let state = self.state.borrow();

        let (title, subtitle, address): (String, String, SilentPaymentAddress) = if id == 0 {
            ("Primary address".into(), "No label. Share this one anywhere.".into(), keys.address())
        } else {
            let Some(label) = u32::try_from(id).ok().and_then(|m| state.label(m)) else { return };
            let Ok(address) = keys.labeled_address(label.m) else { return };
            (label.name.clone(), format!("Label {} · same identity as your primary address", label.m), address)
        };
        let encoded = address.encode();
        let groups: Vec<SharedString> = encoded
            .as_bytes()
            .chunks(4)
            .map(|c| SharedString::from(std::str::from_utf8(c).expect("bech32 is ASCII")))
            .collect();

        self.with_sp(|sp| {
            sp.set_detail_id(id);
            sp.set_detail_title(title.into());
            sp.set_detail_subtitle(subtitle.into());
            sp.set_detail_qr(qr_image(&address.qr_payload(), QR_DETAIL_PX));
            sp.set_detail_qr_large(qr_image(&address.qr_payload(), QR_FULLSCREEN_PX));
            sp.set_detail_address(encoded.as_str().into());
            sp.set_detail_groups(ModelRc::new(VecModel::from(groups)));
        });
    }

    // ------------------------------------------------------------------------------------------
    // Labels

    fn start_create_label(&self) {
        self.with_sp(|sp| {
            sp.set_editor_renaming(false);
            sp.set_editor_m(0);
            sp.set_editor_initial("".into());
            sp.set_editor_error("".into());
        });
    }

    fn start_rename_label(&self, m: i32) {
        let name = u32::try_from(m).ok().and_then(|m| self.state.borrow().label(m).map(|l| l.name.clone()));
        let Some(name) = name else { return };
        self.with_sp(|sp| {
            sp.set_editor_renaming(true);
            sp.set_editor_m(m);
            sp.set_editor_initial(name.into());
            sp.set_editor_error("".into());
        });
    }

    fn save_label(&self, name: &str) -> bool {
        let Some(ui) = self.ui.upgrade() else { return false };
        let sp = ui.global::<Sp>();
        let mut next = self.state.borrow().clone();
        let result = if sp.get_editor_renaming() {
            let m = u32::try_from(sp.get_editor_m()).unwrap_or(0);
            next.rename_label(m, name).map(|()| ("Label renamed", m))
        } else {
            next.create_label(name).map(|l| ("Label created", l.m))
        };
        match result {
            Err(e) => {
                sp.set_editor_error(e.to_string().into());
                false
            }
            Ok((message, m)) => {
                if !self.commit(next) {
                    sp.set_editor_error("Could not save. Try again.".into());
                    return false;
                }
                sp.set_editor_error("".into());
                self.refresh();
                // Keep the address page in sync after a rename.
                if sp.get_detail_id() == m as i32 {
                    self.select_address(m as i32);
                }
                self.notify(message, false);
                true
            }
        }
    }

    fn delete_label(&self, m: i32) {
        let Ok(m) = u32::try_from(m) else { return };
        let mut next = self.state.borrow().clone();
        if next.delete_label(m).is_err() {
            return;
        }
        if self.commit(next) {
            self.refresh();
            self.notify("Label deleted", false);
        }
    }

    /// Saves `next` and makes it current. On failure nothing changes and the user is told.
    fn commit(&self, next: AppState) -> bool {
        match self.storage.save(&next) {
            Ok(()) => {
                *self.state.borrow_mut() = next;
                true
            }
            Err(e) => {
                log::error!("saving state failed: {e:?}");
                self.notify("Could not save the change.", true);
                false
            }
        }
    }

    // ------------------------------------------------------------------------------------------
    // Network

    fn set_network(&self, testnet: bool) {
        let network = if testnet { Network::Testnet } else { Network::Mainnet };
        if self.state.borrow().network() == network {
            return;
        }
        let keys = match derive_keys(network) {
            Ok(keys) => keys,
            Err(_) => return self.notify("Could not read the app seed.", true),
        };
        let mut next = self.state.borrow().clone();
        next.set_network(network);
        if self.commit(next) {
            *self.keys.borrow_mut() = Some(keys);
            self.refresh();
            self.notify(&format!("Using {}", network.display_name()), false);
        }
    }

    // ------------------------------------------------------------------------------------------
    // Watch-only export

    /// Called after the slide-to-confirm. Shows the system PIN prompt, then the export.
    fn request_export(self: &Rc<Self>) {
        self.with_sp(|sp| sp.set_export_stage(ExportStage::Verifying));
        let app = Rc::downgrade(self);
        slint_keyos_platform::spawn_local(async move {
            let result = device::verify_pin("Watch-only export").await;
            if let Some(app) = app.upgrade() {
                app.finish_export(result);
            }
        })
        .detach();
    }

    fn finish_export(self: &Rc<Self>, result: PinCheck) {
        match result {
            PinCheck::Verified => {}
            PinCheck::NotVerified => {
                self.with_sp(|sp| sp.set_export_stage(ExportStage::Intro));
                return self.notify("PIN not confirmed. Nothing was revealed.", true);
            }
            PinCheck::Unavailable(reason) => {
                log::warn!("PIN prompt unavailable: {reason}");
                return self.with_sp(|sp| {
                    sp.set_export_error(
                        "Passport could not show its PIN prompt, so the scan key stays hidden. Restart the app and try again."
                            .into(),
                    );
                    sp.set_export_stage(ExportStage::Failed);
                });
            }
        }

        let keys = self.keys.borrow();
        let Some(keys) = keys.as_ref() else { return };
        let export = WatchOnlyExport::new(keys, &self.state.borrow());
        let qr = qr_image(&export.descriptor, QR_EXPORT_PX);
        self.with_sp(|sp| {
            sp.set_export_qr(qr);
            sp.set_export_descriptor(export.descriptor.as_str().into());
            sp.set_export_network(export.network.display_name().into());
            sp.set_export_fingerprint(export.fingerprint.as_str().into());
            sp.set_export_path(export.account_path.as_str().into());
            sp.set_export_label_hint(export.label_scan_hint().into());
            let lines: Vec<SharedString> = export.label_lines().into_iter().map(Into::into).collect();
            sp.set_export_label_lines(ModelRc::new(VecModel::from(lines)));
            sp.set_export_stage(ExportStage::Shown);
        });
        drop(export);

        let app = Rc::downgrade(self);
        self.export_timer.start(slint::TimerMode::SingleShot, EXPORT_TIMEOUT, move || {
            if let Some(app) = app.upgrade() {
                app.clear_export();
                app.notify("Export hidden after 2 minutes.", false);
            }
        });
    }

    /// Removes the descriptor from the UI. Slint keeps its own string and image copies until
    /// they are replaced, so this replaces them right away.
    fn clear_export(&self) {
        self.export_timer.stop();
        self.with_sp(|sp| {
            sp.set_export_descriptor("".into());
            sp.set_export_qr(Image::default());
            sp.set_export_label_lines(ModelRc::default());
            sp.set_export_error("".into());
            sp.set_export_stage(ExportStage::Intro);
        });
    }

    // ------------------------------------------------------------------------------------------
    // Notices

    fn notify(&self, message: &str, is_error: bool) {
        self.with_sp(|sp| {
            sp.set_notice(message.into());
            sp.set_notice_is_error(is_error);
            sp.set_notice_open(true);
        });
        let ui = self.ui.clone();
        self.notice_timer.start(slint::TimerMode::SingleShot, NOTICE_TIMEOUT, move || {
            if let Some(ui) = ui.upgrade() {
                ui.global::<Sp>().set_notice_open(false);
            }
        });
    }
}

/// Fetches the app seed, derives the receiver keys, and lets the seed drop (it is zeroized).
fn derive_keys(network: Network) -> Result<ReceiverKeys, SeedError> {
    let app_seed = device::fetch_app_seed()?;
    ReceiverKeys::derive_from_app_seed(&app_seed, network, ACCOUNT).map_err(|e| {
        log::error!("key derivation failed: {e}");
        SeedError::Unavailable
    })
}

/// `sp1qqgst…k4xyz8hjk9w`: the prefix plus the tail, where labelled addresses differ.
fn shorten(address: &str) -> String {
    let tail = address.len().saturating_sub(12);
    format!("{}…{}", &address[..8.min(address.len())], &address[tail..])
}

/// Renders a QR code as an image: black on white, 4-module quiet zone, integer scale.
fn qr_image(payload: &str, max_px: usize) -> Image {
    let Ok(matrix) = QrMatrix::encode(payload) else {
        log::error!("QR payload too long");
        return Image::default();
    };
    let (side, mut rgba) = matrix.to_rgba(matrix.scale_for(max_px));
    let buffer = SharedPixelBuffer::<Rgba8Pixel>::clone_from_slice(&rgba, side as u32, side as u32);
    rgba.zeroize();
    Image::from_rgba8(buffer)
}

#[cfg(test)]
mod tests {
    use super::shorten;

    #[test]
    fn shorten_keeps_prefix_and_tail() {
        let a = "sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv";
        assert_eq!(shorten(a), "sp1qqgst…mr70xc9pkqwv");
    }
}
