// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: MIT

//! SP Receive Card: a BIP352 Silent Payments receive card for Passport Prime.
//!
//! The BIP352 logic lives in `crates/sp-core`; this crate is the KeyOS app around it.

mod app;
mod device;
mod storage;
mod theme;

use std::time::Duration;

use slint_keyos_platform::app_ui2;

app_ui2!("SP Receive Card");

fn app_main(cx: AppContext, ui: AppWindow) {
    log_server::init_wait(env!("CARGO_CRATE_NAME")).unwrap();
    log::set_max_level(log::LevelFilter::Info);

    theme::init(&ui);

    let app = app::App::new(&ui, storage::Storage::new(cx.fs.clone()));
    app.wire(&ui);

    // Loading may fetch the app seed, which can show a permission prompt. That must happen on
    // the UI thread once the event loop is running, so start it from a timer.
    let boot = app.clone();
    slint::Timer::single_shot(Duration::from_millis(100), move || boot.boot());

    ui.run().expect("UI running");
}
