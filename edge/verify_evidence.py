"""
verify_evidence.py - check that an evidence file has not been altered.

  python verify_evidence.py evidence/alert_file.jpg            # local check
  python verify_evidence.py evidence/alert_file.jpg --chain    # also compare with the blockchain
  python verify_evidence.py --audit evidence/                  # check the whole log for edits/deletions

Local check: recompute the hash from the file + metadata, compare with the sealed
hash, and verify the device signature. --chain also looks the hash up in the
smart contract (needs CHAIN_RPC_URL and CHAIN_CONTRACT environment variables).
Exit code 0 = intact, 1 = problem found.
"""
import glob
import json
import os
import sys

from evidence import CONTRACT_ABI, compute_event_hash, verify_signature

GREEN, RED, END = "\033[92m", "\033[91m", "\033[0m"


def ok(msg):   print(f"{GREEN}[ OK ]{END} {msg}")
def bad(msg):  print(f"{RED}[FAIL]{END} {msg}")


def load_record(path):
    sidecar = path if path.endswith(".json") else path + ".json"
    with open(sidecar) as f:
        return json.load(f), sidecar


def check_one(path, use_chain=False):
    rec, sidecar = load_record(path)
    meta = rec["meta"]
    good = True

    image_bytes = b""
    if rec.get("image_file"):
        image_path = path if not path.endswith(".json") else \
            os.path.join(os.path.dirname(path), rec["image_file"])
        if not os.path.exists(image_path):
            bad(f"image file missing: {image_path}")
            return False
        with open(image_path, "rb") as f:
            image_bytes = f.read()

    event_hash, _ = compute_event_hash(image_bytes, meta)
    if event_hash == rec["event_hash"]:
        ok(f"hash matches sealed record ({event_hash[:16]}...)")
    else:
        bad("HASH MISMATCH - the image or its metadata has been ALTERED since it was sealed")
        good = False

    if verify_signature(rec["public_key"], rec["event_hash"], rec["signature"]):
        ok(f"device signature valid (device {meta['device_id']}, key {rec['public_key'][:12]}...)")
    else:
        bad("SIGNATURE INVALID - record was not signed by this device key")
        good = False

    if use_chain:
        good = check_chain(rec) and good

    print(f"\n{meta.get('kind')} at {meta.get('camera')} - {meta.get('device_time_utc')}")
    print((GREEN + "RESULT: UNTOUCHED" if good else RED + "RESULT: ALTERED OR UNVERIFIED") + END)
    return good


def check_chain(rec):
    from web3 import Web3
    url, addr = os.environ.get("CHAIN_RPC_URL"), os.environ.get("CHAIN_CONTRACT")
    if not url or not addr:
        bad("set CHAIN_RPC_URL and CHAIN_CONTRACT to check the blockchain")
        return False
    try:
        w3 = Web3(Web3.HTTPProvider(url, request_kwargs={"timeout": 20}))
        contract = w3.eth.contract(address=Web3.to_checksum_address(addr), abi=CONTRACT_ABI)
        device_id, device_time, block_time, reporter, sig = \
            contract.functions.records(bytes.fromhex(rec["event_hash"])).call()
    except Exception as e:
        bad(f"could not read the chain: {e}")
        return False
    if block_time == 0:
        bad("this hash is NOT on the blockchain (not anchored yet, or the record is fake)")
        return False
    good = True
    if device_id != rec["meta"]["device_id"] or device_time != rec["meta"]["device_time_unix"]:
        bad("on-chain device/time do not match the record")
        good = False
    if sig.hex() != rec["signature"]:
        bad("on-chain signature does not match the record")
        good = False
    if good:
        ok(f"found on-chain, recorded at block time {block_time} (device time {device_time})")
    return good


def audit(folder):
    """Every event stores the previous event's hash; a gap or edit breaks the chain."""
    records = []
    for p in glob.glob(os.path.join(folder, "*.json")):
        try:
            with open(p) as f:
                r = json.load(f)
            if "meta" in r and "event_hash" in r:
                records.append((r["meta"]["seq"], p, r))
        except (ValueError, KeyError):
            pass
    records.sort(key=lambda t: t[0])
    if not records:
        bad("no sealed events found")
        return False
    good, prev_hash, prev_seq = True, "0" * 64, 0
    for seq, p, r in records:
        if seq != prev_seq + 1:
            bad(f"GAP: event(s) {prev_seq + 1}..{seq - 1} missing before #{seq}")
            good = False
        if r["meta"]["prev_event_hash"] != prev_hash:
            bad(f"#{seq}: previous-hash link broken (an earlier event was removed or changed)")
            good = False
        image_bytes = b""
        if r.get("image_file"):
            ip = os.path.join(os.path.dirname(p), r["image_file"])
            if os.path.exists(ip):
                image_bytes = open(ip, "rb").read()
            else:
                bad(f"#{seq}: image missing ({r['image_file']})")
                good = False
        if compute_event_hash(image_bytes, r["meta"])[0] != r["event_hash"] or \
           not verify_signature(r["public_key"], r["event_hash"], r["signature"]):
            bad(f"#{seq}: content or signature check failed")
            good = False
        prev_hash, prev_seq = r["event_hash"], seq
    if good:
        ok(f"{len(records)} events, unbroken chain, all hashes and signatures valid")
    return good


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    if "--audit" in sys.argv:
        sys.exit(0 if audit(args[0] if args else "evidence") else 1)
    if not args:
        print(__doc__)
        sys.exit(2)
    sys.exit(0 if check_one(args[0], "--chain" in sys.argv) else 1)
