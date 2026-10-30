// SPDX-License-Identifier: MIT

//! KeyOS services: the per-app seed and the system PIN prompt.

use slint_keyos_platform::gui_server_api::error::NavigationError;
use slint_keyos_platform::gui_server_api::msg::ShowModal;
use slint_keyos_platform::gui_server_api::navigation::lockscreen::{VerifyPinOptions, VerifyPinResult};
use slint_keyos_platform::gui_server_api::navigation::LOCK_SCREEN_APP_ID;
use slint_keyos_platform::gui_server_api::ModalStyle;
use sp_core::seed::APP_SEED_LEN;
use zeroize::Zeroizing;

security::use_api!();

/// The app seed could not be obtained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeedError {
    /// The user declined the permission, or the security server refused.
    Denied,
    /// The security server could not be reached.
    Unavailable,
}

/// Fetches the app-scoped seed, prompting for permission on first use.
///
/// Must run on the UI thread after the event loop has started (from a timer or a UI callback):
/// the permission prompt is drawn through this app's GUI connection (SDK MIGRATIONS gotcha 24).
/// Uses the non-panicking `try_send_blocking_archive` so that a denial is reported, not a crash.
pub fn fetch_app_seed() -> Result<Zeroizing<[u8; APP_SEED_LEN]>, SeedError> {
    let conn = server::CheckedConn::<security_permissions::SecurityPermissions>::try_connect()
        .ok_or(SeedError::Unavailable)?;
    match conn.try_send_blocking_archive(security::messages::GetAppSeed) {
        Ok(Ok(seed)) => Ok(Zeroizing::new(*seed.as_bytes())),
        Ok(Err(_)) => Err(SeedError::Denied),
        Err(e) => {
            log::warn!("app seed request failed: {e:?}");
            Err(SeedError::Denied)
        }
    }
}

/// Result of asking the system for the user's PIN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinCheck {
    Verified,
    /// Wrong PIN, cancelled, or dismissed.
    NotVerified,
    /// The PIN prompt could not be shown.
    Unavailable(String),
}

/// Shows the KeyOS lock-screen PIN prompt (a system-drawn modal the app cannot spoof).
///
/// This is `slint_keyos_platform::navigation::verify_pin` without the panic on transport errors
/// and without blocking the UI thread.
pub async fn verify_pin(title: &str) -> PinCheck {
    let options = VerifyPinOptions { title: Some(title.to_owned()), want_security_words: false };
    let request = ShowModal {
        app_id: LOCK_SCREEN_APP_ID,
        modal_style: ModalStyle::SlideUpFullscreen,
        args: options.serialize(),
    };
    match slint_keyos_platform::try_async_archive::<crate::gui_permissions::GuiPermissions, _>(request).await {
        Ok(Ok(response)) => match VerifyPinResult::from_slice(response.as_slice()) {
            Some(VerifyPinResult { success: true, .. }) => PinCheck::Verified,
            Some(_) => PinCheck::NotVerified,
            None => PinCheck::Unavailable("unexpected response from the PIN prompt".into()),
        },
        Ok(Err(NavigationError::CanceledByUser | NavigationError::CanceledBySystem)) => PinCheck::NotVerified,
        Ok(Err(e)) => PinCheck::Unavailable(e.to_string()),
        Err(e) => PinCheck::Unavailable(format!("{e:?}")),
    }
}
