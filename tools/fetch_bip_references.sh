#!/usr/bin/env sh
# Downloads the pinned BIP352 reference implementation and BIP39 English word list into DIR,
# for tools/bip352_reference_crosscheck.py. Files are fetched by commit, so they cannot change
# under us.
set -eu

DIR=${1:?usage: fetch_bip_references.sh DIR}
BIPS=https://raw.githubusercontent.com/bitcoin/bips
COMMIT=3c68d3f3a19b9ed3ee1e9129147541a15f1603cb

mkdir -p "$DIR/secp256k1lab/src/secp256k1lab"
for f in reference.py bech32m.py bitcoin_utils.py ripemd160.py; do
  curl -sSfL -o "$DIR/$f" "$BIPS/$COMMIT/bip-0352/$f"
done
for f in __init__.py bip340.py ecdh.py keys.py secp256k1.py util.py; do
  curl -sSfL -o "$DIR/secp256k1lab/src/secp256k1lab/$f" "$BIPS/$COMMIT/bip-0352/secp256k1lab/src/secp256k1lab/$f"
done
curl -sSfL -o "$DIR/english.txt" "$BIPS/$COMMIT/bip-0039/english.txt"
echo "Fetched BIP352 reference ($COMMIT) into $DIR"
