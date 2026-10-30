#!/usr/bin/env python3
"""Simulator only: recompute SP Receive Card's primary address from the KeyOS simulator's *test*
master seed, using the app-seed formula KeyOS 1.x documents (MIGRATIONS gotcha 21):

    app_seed = HMAC-SHA256(key=app_id, msg=master_seed)

then the independent Python chain in bip352_reference_crosscheck.py. If the printed address
matches the app's screen, the device integration (seed access -> sp-core -> QR) is correct.
Prints only public values. Never point this at real seed material.

Usage:
  python3 -I tools/sim_identity_check.py \
      ~/.foundation/sdk/current/lib/keyos/simulator/xous/kernel/hosted_security_data.json \
      REF_DIR tools/bip352_reference_crosscheck.py APP_ID [mainnet|testnet]
"""
import hashlib
import hmac
import json
import sys
from pathlib import Path

sec_path, ref_dir, crosscheck, app_id_hex = sys.argv[1], Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4]
testnet = len(sys.argv) > 5 and sys.argv[5] == "testnet"
sys.argv = [str(crosscheck), str(ref_dir), "/dev/null"]
ns = {"__name__": "crosscheck_lib"}
exec(compile(crosscheck.read_text(), str(crosscheck), "exec"), ns)

master_seed = bytes(json.load(open(sec_path))["seed"])
app_id = bytes.fromhex(app_id_hex.removeprefix("0x"))
app_seed = hmac.new(app_id, master_seed, hashlib.sha256).digest()

seed = ns["bip39_seed"](ns["mnemonic_from_entropy"](app_seed))
k, _ = ns["bip32_master"](seed)
fingerprint = ns["ripemd160"](hashlib.sha256(ns["ser_p"](k)).digest())[:4].hex()
H = 0x80000000
coin = 1 if testnet else 0
b_scan = ns["derive"](seed, [352 + H, coin + H, 0 + H, 1 + H, 0])
b_spend = ns["derive"](seed, [352 + H, coin + H, 0 + H, 0 + H, 0])
G, Scalar = ns["G"], ns["Scalar"]
hrp = "tsp" if testnet else "sp"
print("fingerprint", fingerprint)
print("address    ", ns["reference"].encode_silent_payment_address(Scalar(b_scan) * G, Scalar(b_spend) * G, hrp=hrp))
for m in (1, 2, 3):
    print(f"label {m}    ", ns["reference"].create_labeled_silent_payment_address(Scalar(b_scan), Scalar(b_spend) * G, m=m, hrp=hrp))
