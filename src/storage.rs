// SPDX-License-Identifier: MIT

//! App-private persistence.
//!
//! One JSON file in `fs::Location::AppData` (`<encrypted>/appdata/<app-id>/`), written with the
//! SDK's crash-safe `durable_file_write`. KeyOS includes this directory in Magic Backup and wipes
//! it when the app is removed. Only non-secret data is ever written here (see `sp_core::store`).

use std::sync::Arc;

use slint_keyos_platform::fs::{Error as FsError, Location};
use sp_core::store::{load_state, LoadOutcome};
use sp_core::AppState;

const STATE_FILE: &str = "state.json";
/// Unreadable state is copied here before anything new is saved, so it is never lost silently.
const UNREADABLE_COPY: &str = "state.unreadable.json";

pub struct Storage {
    fs: Arc<crate::FileSystem>,
}

impl Storage {
    pub fn new(fs: Arc<crate::FileSystem>) -> Self { Self { fs } }

    /// Reads and validates the saved state. Unreadable bytes are preserved in a side file.
    pub fn load(&self) -> Result<LoadOutcome, FsError> {
        let saved = match self.fs.durable_file_read(STATE_FILE, Location::AppData) {
            Ok(bytes) => Some(bytes),
            Err(FsError::FileNotFound) => None,
            Err(e) => return Err(e),
        };
        let outcome = load_state(saved.as_deref());
        if let (LoadOutcome::Corrupt { .. }, Some(bytes)) = (&outcome, &saved) {
            self.fs.durable_file_write(UNREADABLE_COPY, Location::AppData, bytes)?;
        }
        Ok(outcome)
    }

    pub fn save(&self, state: &AppState) -> Result<(), FsError> {
        self.fs.durable_file_write(STATE_FILE, Location::AppData, &state.to_json())
    }
}
