# Testing

Run everything host-side with `cargo test -p sp-core` (inside `foundation develop`, or any Rust
toolchain). Test data is vendored under `crates/sp-core/tests/data/` with its source commit.

## What is covered

| Plan requirement | Test | Oracle |
| --- | --- | --- |
| Official BIP352 vectors | `tests/bip352_vectors.rs`: every receiving case's expected addresses (incl. labels 0, 1, 2, 3, 1337, 1001337) from the given keys; every sending recipient address decodes to its listed keys | `bitcoin/bips` `bip-0352/send_and_receive_test_vectors.json` @ `3c68d3f3` |
| Key derivation | `tests/derivation_vectors.rs`: 24 Trezor BIP39 vectors (entropy → mnemonic → seed → master xprv); BIP32 test vectors 1–4 (17 chains) | `trezor/python-mnemonic` vectors @ `b57a5ad7`; `bip-0032.mediawiki` |
| Key derivation (independent) | `tests/differential.rs::bip352_paths_match_rust_bitcoin`: 48 seeds × 2 networks, scan key, spend key, fingerprint | `bitcoin` 0.32 (libsecp256k1) |
| Address encoding/decoding | `src/address.rs` unit tests: lengths (116/117), round trip, uppercase, mixed case, checksum corruption, bech32 vs bech32m, wrong HRP, versions 0/1–30/31, invalid points, padding, >1023 chars, garbage | spec rules |
| Labels | official vectors above; `differential.rs::addresses_and_labels_match_rust_silentpayments` (labels 1…u32::MAX and change label) | `silentpayments` 0.8 (rust-silentpayments) |
| Mainnet and test networks | all differential, QR and descriptor tests run for `sp`/`tsp` and coin types 0'/1' | `silentpayments`, `bitcoin` |
| QR payload | `tests/qr_payload.rs`: the app's actual render path (`QrMatrix` → RGBA at 3 scales) decoded by `rqrr` equals the exact address/descriptor string; no URI or extra text | `rqrr` decoder |
| Persistence and recovery | `tests/persistence.rs` and `src/store.rs`: restart round trip, rename/delete, label integers never reused, network preference, restore with/without app data, identity mismatch, corrupt/foreign/newer files rejected and never overwritten, no key material in the saved file | — |
| Watch-only export | `src/descriptor.rs`: BIP380 checksum vectors, spscan round trip, malformed descriptors; `differential.rs::watch_only_export_detects_payments_in_reference_scanner`: the exported descriptor, parsed back and given to an independent scanner, finds payments to the primary and labelled addresses and ignores unrelated outputs | `silentpayments` scanner; BIP380 vectors |
| Independent implementation | `tools/bip352_reference_crosscheck.py`: 32 identities, 192 labelled addresses, 32 descriptors re-derived in pure Python (hashlib PBKDF2/HMAC, secp256k1lab, BIP352 `reference.py`, BIP380 code) | BIP352 reference implementation |

The Python cross-check was also run against deliberately corrupted dumps to confirm it fails.

## Simulator end-to-end (`foundation sim`, KeyOS SDK 1.1.0)

Driven with `foundation-passport-drive --sim` (screenshots, taps, swipes, text input). QR codes on
screen were decoded from the screenshots with an independent decoder (`rqrr`). The expected values
come from `tools/sim_identity_check.py`, which recomputes the identity from the simulator's *test*
master seed with the KeyOS app-seed formula and the pure-Python reference chain.

| Check | Result |
| --- | --- |
| First launch: explanation, "Create receiving identity", system app-seed permission prompt | Pass |
| Permission "Not Now": app shows "Seed access needed", no crash (`AccessDenied` logged); KeyOS keeps the denial for the session, relaunch prompts again | Pass |
| Permission "Always Allow": success screen, fingerprint `f1f95a21` | Pass, equals reference |
| Home QR decodes to the displayed address; address equals the reference derivation (`HMAC-SHA256(app_id, master_seed)` → BIP39 → BIP32 → BIP352) | Pass |
| Address page: 4-character groups, full-screen QR (decodes correctly) | Pass |
| Create label (suggestion chip), empty name rejected, duplicate (case-insensitive) rejected | Pass |
| Labels 1, 2, 3 on screen equal reference labels 1, 2, 3; QR of label 1 decodes to reference | Pass |
| Rename keeps the address; delete removes the row; next label gets m = 3 (no reuse) | Pass |
| Labels, names, network and permission grant survive app and simulator restarts (incl. hard kill) | Pass |
| Testnet/Signet switch: `tsp1q…` equals reference (coin type 1'); switching back restores `sp1q…` | Pass |
| Export: warning, slide-to-confirm, "System dialogs" permission prompt, system PIN screen with our title | Pass |
| Wrong PIN: system shows "1 failed attempt", nothing revealed | Pass |
| Correct PIN: descriptor QR decodes to `sp([f1f95a21/352h/0h/0h]spscan1q…)#…`; checksum valid; scan key and spend key equal the reference; reproduces primary and label addresses | Pass |
| Export hides itself after 2 minutes; "Done"/back clear it | Pass |
| Full app cross-compiles for `armv7a-unknown-xous-elf` with `foundation build`'s flags; largest stack frame in app code ≈10.7 KiB | Pass (unsigned; no signing identity on this machine) |

### Known simulator issue

After an app uses the lock-screen PIN modal, the hosted simulator kernel panics a few navigations
later: `xous/kernel/src/process.rs:285: index out of bounds: the len is 32 but the index is 32`.
It reproduces with the SDK's own `slint_keyos_platform::navigation::verify_pin`, and does not occur
in 12+ navigation cycles without the PIN modal, so it is not specific to this app's code. It should
be reported to Foundation and checked on hardware.

## Not run

- Signed build, sideload and tests on a Passport Prime (needs a signing identity and hardware).
- Magic Backup restore and tamper/restore on hardware.
- Importing the descriptor into a third-party wallet app. Interoperability was verified against
  independent implementations (rust-silentpayments scanner, BIP352 reference code) instead.
