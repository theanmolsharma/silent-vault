# SP Receive Card

A BIP352 Silent Payments receive card for Foundation Passport Prime (KeyOS), built with the
Foundation SDK 1.1.0.

- Derives a Silent Payments identity from Passport's app-scoped seed.
- Shows the address as text and as a QR code; creates labelled addresses (BIP352 labels).
- Saves label names in the app's private, encrypted storage (included in Magic Backup).
- Exports a watch-only BIP392 descriptor (`sp(spscan…)`) behind slide-to-confirm and the system
  PIN prompt.

It does **not** send, sign, scan the chain, or construct transactions.

See [`docs/SDK_ASSESSMENT.md`](docs/SDK_ASSESSMENT.md) for the SDK inspection, design decisions and
limitations, and [`docs/TESTING.md`](docs/TESTING.md) for the test plan and results.

## Layout

```
crates/sp-core/   BIP352 logic, no KeyOS dependencies (host-testable, builds for the device)
  src/seed.rs       app seed -> BIP39 mnemonic -> BIP39 seed
  src/keys.rs       BIP32 m/352'/coin'/0'/{1',0'}/0, labels
  src/address.rs    bech32m sp1q/tsp1q encoding and decoding
  src/descriptor.rs BIP392 spscan key, sp() descriptor, BIP380 checksum
  src/store.rs      persisted state: network, label names and integers, identity fingerprint
  src/qr.rs         QR matrices for on-screen codes
  tests/            official BIP352/BIP39/BIP32 vectors, differential tests, QR, persistence
src/              KeyOS app: seed and PIN services, storage, UI controller
ui/               Slint pages (router) and shared components
tools/            pure-Python cross-check against the BIP352 reference implementation
```

## Key derivation

```
GetAppSeed (32 bytes, KeyOS: hmac256(app_id, master_seed))
  -> 24-word BIP39 mnemonic (app seed as entropy) -> BIP39 seed, empty passphrase
  -> BIP32 master
  -> scan:  m/352'/coin'/0'/1'/0      coin = 0' mainnet, 1' testnet/signet
  -> spend: m/352'/coin'/0'/0'/0
```

The spend private key is computed only to get its public key and is then dropped. Nothing secret
is written to storage. **`app-id` in `app-config.toml` is key material: changing it changes every
address.**

## Build and run

```sh
foundation develop                 # enter the SDK shell
foundation sim                     # build and run in the simulator
cargo test -p sp-core              # host tests; any stable Rust (needs the .foundation-sdk link `foundation` creates)
tools/host-build.sh test --workspace   # all tests, after one `foundation sim`
foundation build                   # signed device build (needs a signing identity)
```

The simulator's PIN is `raw_pin` in the SDK's `lib/keyos/simulator/xous/kernel/hosted_security_data.json`.
`tools/sim_identity_check.py` recomputes the simulator identity independently so you can compare
it with the screen.

Independent cross-check against the BIP352 reference implementation:

```sh
tools/fetch_bip_references.sh /tmp/bipref
cargo run -q -p sp-core --example crosscheck_dump > /tmp/dump.json
python3 -I tools/bip352_reference_crosscheck.py /tmp/bipref /tmp/dump.json
```
