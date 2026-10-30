#!/usr/bin/env python3
"""Cross-check sp-core against an independent, pure-Python derivation chain.

Everything here is computed without any of the Rust crates the app uses:

  app seed -> BIP39 mnemonic (word list) -> BIP39 seed (hashlib PBKDF2)
           -> BIP32 master and m/352'/coin'/0'/{1',0'}/0 (hmac + secp256k1lab)
           -> addresses and labels (BIP352 reference.py)
           -> BIP392 spscan key (reference bech32m.py) and BIP380 checksum (code from BIP380)

Usage:
  tools/fetch_bip_references.sh REF_DIR
  cargo run -q -p sp-core --example crosscheck_dump > dump.json
  python3 -I tools/bip352_reference_crosscheck.py REF_DIR dump.json
"""

import hashlib
import hmac
import json
import sys
from pathlib import Path

ref_dir = Path(sys.argv[1]).resolve()
dump_path = Path(sys.argv[2]).resolve()
sys.path.insert(0, str(ref_dir))
sys.path.insert(0, str(ref_dir / "secp256k1lab" / "src"))

import reference  # noqa: E402  (BIP352 reference implementation)
from bech32m import Encoding, bech32_encode, convertbits  # noqa: E402
from ripemd160 import ripemd160  # noqa: E402
from secp256k1lab.secp256k1 import G, GE, Scalar  # noqa: E402

WORDS = (ref_dir / "english.txt").read_text().split()
assert len(WORDS) == 2048
N = GE.ORDER
HARDENED = 0x80000000


def mnemonic_from_entropy(entropy: bytes) -> str:
    bits = "".join(f"{b:08b}" for b in entropy)
    checksum_bits = len(entropy) * 8 // 32
    bits += "".join(f"{b:08b}" for b in hashlib.sha256(entropy).digest())[:checksum_bits]
    return " ".join(WORDS[int(bits[i:i + 11], 2)] for i in range(0, len(bits), 11))


def bip39_seed(mnemonic: str, passphrase: str = "") -> bytes:
    return hashlib.pbkdf2_hmac("sha512", mnemonic.encode(), ("mnemonic" + passphrase).encode(), 2048)


def ser_p(k: int) -> bytes:
    return (Scalar(k) * G).to_bytes_compressed()


def bip32_master(seed: bytes):
    i = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    k = int.from_bytes(i[:32], "big")
    assert 0 < k < N
    return k, i[32:]


def ckd_priv(k: int, c: bytes, index: int):
    if index >= HARDENED:
        data = b"\x00" + k.to_bytes(32, "big") + index.to_bytes(4, "big")
    else:
        data = ser_p(k) + index.to_bytes(4, "big")
    i = hmac.new(c, data, hashlib.sha512).digest()
    il = int.from_bytes(i[:32], "big")
    assert il < N
    child = (il + k) % N
    assert child != 0
    return child, i[32:]


def derive(seed: bytes, path):
    k, c = bip32_master(seed)
    for index in path:
        k, c = ckd_priv(k, c, index)
    return k


# BIP380 checksum, as given in the BIP.
INPUT_CHARSET = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
GENERATOR = [0xF5DEE51989, 0xA9FDCA3312, 0x1BAB10E32D, 0x3706B1677A, 0x644D626FFD]


def descsum_polymod(symbols):
    chk = 1
    for value in symbols:
        top = chk >> 35
        chk = (chk & 0x7FFFFFFFF) << 5 ^ value
        for i in range(5):
            chk ^= GENERATOR[i] if ((top >> i) & 1) else 0
    return chk


def descsum_expand(s):
    groups, symbols = [], []
    for c in s:
        v = INPUT_CHARSET.find(c)
        assert v >= 0
        symbols.append(v & 31)
        groups.append(v >> 5)
        if len(groups) == 3:
            symbols.append(groups[0] * 9 + groups[1] * 3 + groups[2])
            groups = []
    if len(groups) == 1:
        symbols.append(groups[0])
    elif len(groups) == 2:
        symbols.append(groups[0] * 3 + groups[1])
    return symbols


def descsum_create(s):
    symbols = descsum_expand(s) + [0] * 8
    checksum = descsum_polymod(symbols) ^ 1
    return s + "#" + "".join(CHECKSUM_CHARSET[(checksum >> (5 * (7 - i))) & 31] for i in range(8))


def main():
    cases = json.loads(dump_path.read_text())
    labels_checked = 0
    for case in cases:
        hrp, coin = case["hrp"], case["coin_type"]
        seed = bip39_seed(mnemonic_from_entropy(bytes.fromhex(case["app_seed"])))

        master_k, _ = bip32_master(seed)
        fingerprint = ripemd160(hashlib.sha256(ser_p(master_k)).digest())[:4].hex()
        account = [352 + HARDENED, coin + HARDENED, 0 + HARDENED]
        b_scan = derive(seed, account + [1 + HARDENED, 0])
        b_spend = derive(seed, account + [0 + HARDENED, 0])

        assert fingerprint == case["master_fingerprint"], "fingerprint"
        assert b_scan.to_bytes(32, "big").hex() == case["scan_priv_key"], "scan key"
        assert ser_p(b_spend).hex() == case["spend_pub_key"], "spend key"

        B_scan = Scalar(b_scan) * G
        B_spend = Scalar(b_spend) * G
        assert reference.encode_silent_payment_address(B_scan, B_spend, hrp=hrp) == case["address"], "address"
        assert reference.create_labeled_silent_payment_address(
            Scalar(b_scan), B_spend, m=0, hrp=hrp) == case["change_address"], "change"
        for labeled in case["labeled"]:
            expected = reference.create_labeled_silent_payment_address(
                Scalar(b_scan), B_spend, m=labeled["m"], hrp=hrp)
            assert expected == labeled["address"], f"label {labeled['m']}"
            labels_checked += 1

        payload = b_scan.to_bytes(32, "big") + ser_p(b_spend)
        spscan = bech32_encode(hrp + "scan", [0] + convertbits(payload, 8, 5), Encoding.BECH32M)
        descriptor = descsum_create(f"sp([{fingerprint}/352h/{coin}h/0h]{spscan})")
        assert descriptor == case["descriptor"], "descriptor"

    print(f"OK: {len(cases)} identities, {labels_checked} labelled addresses, "
          f"{len(cases)} descriptors match the independent Python chain")


if __name__ == "__main__":
    main()
