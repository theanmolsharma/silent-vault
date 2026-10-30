# Stage 1: SDK inspection and implementation plan

Inspected: Foundation SDK 1.1.0 (KeyOS API 1.4.0) at `~/.foundation/sdk/current`, its
`docs/guide/src/{foundation-cli,MIGRATIONS}.md`, the API rustdoc bundle (`docs/api/v1.4.0`),
the `lib/keyos` sources and templates, the developer docs at docs.foundation.xyz/developers, and
the hackathon setup gist. Nothing below is invented; each API is cited by source path
(relative to `lib/keyos/` unless stated).

## SDK APIs used

| Need | API | Where | Permission |
| --- | --- | --- | --- |
| App seed | `Security::app_seed()` / message `GetAppSeed` → `AppSeed([u8; 32])` | `api/security/src/lib.rs` | `"os/security" = ["GetAppSeed"]`, group `device-secrets.app-scoped-seed`, `grantOnFirstUse` |
| PIN check | `navigation::verify_pin` = `ShowModal` to the lock screen (`LOCK_SCREEN_APP_ID`) with `VerifyPinOptions` → `VerifyPinResult { success }` | `slint-keyos-platform/runtime/src/navigation.rs`, `api/gui-server/src/navigation/lockscreen.rs` | `ShowModal` (in `gui-app` template), group `ui-and-input.brokered-modal`, `grantOnFirstUse` |
| Private storage | `FileSystem::durable_file_write/read` at `fs::Location::AppData` (`<encrypted>/appdata/<app-id>/`) | `api/fs/src/lib.rs` | `fs-generic` template |
| QR display | `qrcode` 0.12 (the crate the platform uses); see "QR rendering" below | `slint-keyos-platform/runtime/src/qrcode.rs` | none |
| QR scanning | `navigation::open_qr_scanner` (QR scanner modal) | same file | `ShowModal` — **not needed in v1** (the app never reads QR codes) |
| SlideToConfirm | `SlideToConfirm` component | `ui2/components/ui/slide_to_confirm.slint` | none |
| Clipboard | **does not exist** in KeyOS | — | — |
| UI / navigation | ui2 Slint kit (`@ui/*.slint`), generated router (`include_router: true`, `ui/pages/**/props.slint` with `@rust-attr(route(...))`, `Navigate.*`) | `ui2/components/ui`, multi-page-app template | `gui-app` template |
| Randomness | not needed (all keys are deterministic from the app seed) | — | — |

## Crates on KeyOS (`armv7a-unknown-xous-elf`)

Verified by cross-compiling with the SDK's toolchain and the flags `foundation build` uses
(`--cfg keyos -C relocation-model=pic -C link-arg=-pie -Zunstable-options`):

- **Builds, used:** `k256` 0.13 (secp256k1 arithmetic, pure Rust), `bip32` 0.5, `bip39` 2.x
  (same as the KeyOS security API), `bech32` 0.11, `sha2` 0.10, `qrcode` 0.12, `zeroize`,
  `serde`/`serde_json`. No C code and no `getrandom` in the dependency tree.
- **Builds, not used on device:** `secp256k1` 0.29 (C `libsecp256k1`). On macOS it happened to
  cross-compile with Apple clang; on Linux `cc` picks the host gcc and fails (MIGRATIONS gotcha 15).
  It is used only as a host-side test oracle (via `silentpayments` and `bitcoin`).
- `getrandom` must stay at the SDK's patched 0.2.10 (template `[patch.crates-io]`).

## Seed source and its stability

- Third-party apps cannot read the master seed (`GetSeed` is Foundation-only; the CLI rejects it).
  `GetAppSeed` is the only seed source, and MIGRATIONS gotcha 21 says to use it as BIP39 entropy:
  `Mnemonic::from_entropy(app_seed)` → standard derivation. The app does exactly that:
  `app seed → 24-word mnemonic → BIP39 seed (empty passphrase) → BIP32 → m/352'/coin'/0'/{1',0'}/0`.
- **Reinstall:** stable for the same app ID (developer docs, "Capabilities").
- **Device recovery:** MIGRATIONS gotcha 21: KeyOS 1.x derives it as `hmac256(app_id, master_seed)`
  with no device-unique input, so restoring the same BIP39 seed on another Passport reproduces it.
  The same note warns this is *current behaviour, not a committed API*. **Before holding real funds,
  get a written stability guarantee from the KeyOS team** (see Limitations).
- **App ID is key material.** `app-id` in `app-config.toml` must never change; changing it changes
  every key and address.
- Consequence: the keys are **not** the BIP352 keys of the Passport's main seed words. Another
  wallet restoring the main 24 words at `m/352'/…` gets a different identity. The identity is
  equivalent to a separate 24-word wallet (the app-seed mnemonic), which v1 never displays.

## Implementation plan (stages from plan.md)

1. SDK assessment (this document).
2. `crates/sp-core`: BIP352 keys, labels, bech32m addresses, BIP392 descriptor + BIP380 checksum,
   persisted state, QR matrices. Pure Rust, host-tested against official vectors and independent
   implementations.
3. Seed integration: fetch the app seed on the UI thread after the event loop starts (MIGRATIONS
   gotcha 24), via `CheckedConn::try_send_blocking_archive` so a denial is an error, not a panic.
   Keys are derived in memory at each launch; nothing secret is stored.
4. Addresses and labels: label integers from 1, never reused; `m = 0` (change) never shown.
5. UI + storage: router pages (Welcome, Home, Address, Label editor, Export, Settings),
   `durable_file_write` of `state.json` in AppData (included in Magic Backup).
6. Watch-only export: warning → SlideToConfirm → PIN (lock-screen modal) → BIP392 descriptor QR.
   Generated on demand, never stored, cleared when leaving the screen.
7. Testing: official vectors, differential tests, Python reference cross-check, simulator runs.

## Limitations found (and what the app does instead)

| Requirement | Limitation | Safest supported alternative |
| --- | --- | --- |
| Copy address | No clipboard API in KeyOS | "Show full address" view with the address split into 4-character groups for manual comparison; QR is the transfer mechanism |
| Share QR | No share sheet; Passport is offline | Full-screen QR view for scanning by another device |
| PIN authentication | PIN/login messages are Foundation-only; apps can only open the lock-screen PIN modal via `ShowModal` (`grantOnFirstUse`). Developer docs don't describe this flow | Use it; if the modal is unavailable or denied, the export stays locked (no fallback that skips the PIN) |
| Seed stability across recovery | Documented as current behaviour, not a committed API | Documented; identity fingerprint stored so the app warns if the derived identity ever changes |
| Interoperable export | BIP392 (`sp()` descriptors) is a Draft BIP; there is no standard for label names | Export is the BIP392 descriptor only; label integers/names are shown as text, not put in the QR |
| Spending | Spend key can only be used on this Passport, and v1 has no signing | Documented: funds are spendable only by a future version of this app (same app ID) or by recovering the app-seed mnemonic, which v1 never reveals |
| Regtest | BIP352 defines only `sp` and `tsp` | Mainnet and Testnet/Signet only |
| QR rendering | Platform `qrcode::render` masks image corners with a fixed 24 px radius at 1 px/module, cutting into finder patterns | App renders codes itself with the same `qrcode` crate: black on white, 4-module quiet zone, integer scaling |

## Findings from building and running it (simulator)

- **App seed formula confirmed in the simulator.** `HMAC-SHA256(key = app_id, msg = master_seed)`
  from the simulator's test seed, fed through an independent Python BIP39/BIP32/BIP352 chain,
  reproduces exactly the fingerprint and addresses the app shows (`tools/sim_identity_check.py`).
  Hardware behaviour still needs the written guarantee noted above.
- **Seed permission.** "Not Now" denies `GetAppSeed` for the rest of the app session (no new
  prompt until relaunch); the app reports it instead of crashing because it uses
  `CheckedConn::try_send_blocking_archive` (the SDK's `Security::app_seed` would panic).
- **PIN prompt.** The first `ShowModal` asks for a "System dialogs" permission
  (`ui-and-input.brokered-modal`), then the system lock screen takes the PIN with the app's title.
  Wrong PINs are handled (and counted) by the system; the app only learns success or failure.
- **Simulator kernel panic after the PIN modal** (`process.rs:285`, len 32): reproduces with the
  SDK's own `verify_pin`; see `docs/TESTING.md`. Needs reporting and a hardware check.
- **UI kit quirks worked around:** `IconButton` centres its icon but anchors its touch area at the
  left, so a stretched IconButton is untappable (pinned to its control size); a `SlideToConfirm`
  inside a `Flickable` never completes because the Flickable takes the drag (moved outside);
  the platform QR renderer's corner mask (replaced, see Limitations).
- **Direct `cargo build` outside the CLI** needs the env the CLI sets:
  `FOUNDATION_UI_LIBRARY_PATH`, `FOUNDATION_THEMES_SLINT_DIR`, `FOUNDATION_THEMES_RUST_DIR`
  (see `tools/host-build.sh`). Without them the `@ui` icons' relative `@image-url`s don't resolve.
