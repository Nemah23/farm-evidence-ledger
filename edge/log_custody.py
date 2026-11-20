"""
log_custody.py - add a chain-of-custody entry for a sealed event (2nd kind of on-chain transaction).

  python log_custody.py evidence/<file>_raw_<time>.jpg "reviewed by ranger"
  python log_custody.py <64-hex event hash> "exported for case"
  python log_custody.py --show evidence/<file>_raw_<time>.jpg

The wallet in CHAIN_PRIVATE_KEY must be an authorised handler (the contract owner is one
by default; the owner can add more with setHandler).
Needs CHAIN_RPC_URL, CHAIN_CONTRACT, CHAIN_PRIVATE_KEY (and CHAIN_ID if you want to fix it).
"""
import json
import os
import sys
from datetime import datetime, timezone

from web3 import Web3

ABI = [
    {"type": "function", "name": "logCustody", "stateMutability": "nonpayable",
     "inputs": [{"name": "eventHash", "type": "bytes32"}, {"name": "action", "type": "string"}],
     "outputs": []},
    {"type": "function", "name": "custodyCount", "stateMutability": "view",
     "inputs": [{"name": "eventHash", "type": "bytes32"}],
     "outputs": [{"name": "", "type": "uint256"}]},
    {"type": "function", "name": "getCustody", "stateMutability": "view",
     "inputs": [{"name": "eventHash", "type": "bytes32"}, {"name": "index", "type": "uint256"}],
     "outputs": [{"name": "handler", "type": "address"}, {"name": "action", "type": "string"},
                 {"name": "time", "type": "uint64"}]},
]


def event_hash_from(arg):
    if len(arg) == 64 and all(c in "0123456789abcdefABCDEF" for c in arg):
        return arg.lower()
    sidecar = arg if arg.endswith(".json") else arg + ".json"
    with open(sidecar) as f:
        return json.load(f)["event_hash"]


def connect():
    for k in ("CHAIN_RPC_URL", "CHAIN_CONTRACT"):
        if not os.environ.get(k):
            sys.exit(f"set {k} first")
    w3 = Web3(Web3.HTTPProvider(os.environ["CHAIN_RPC_URL"], request_kwargs={"timeout": 30}))
    contract = w3.eth.contract(address=Web3.to_checksum_address(os.environ["CHAIN_CONTRACT"]), abi=ABI)
    return w3, contract


def show(h):
    w3, contract = connect()
    n = contract.functions.custodyCount(bytes.fromhex(h)).call()
    print(f"event {h[:16]}... has {n} custody entr{'y' if n == 1 else 'ies'}")
    for i in range(n):
        handler, action, ts = contract.functions.getCustody(bytes.fromhex(h), i).call()
        when = datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds")
        print(f"  {i + 1}. {when}  {handler}  {action}")


def log(h, action):
    if not os.environ.get("CHAIN_PRIVATE_KEY"):
        sys.exit("set CHAIN_PRIVATE_KEY first")
    w3, contract = connect()
    acct = w3.eth.account.from_key(os.environ["CHAIN_PRIVATE_KEY"])
    chain_id = int(os.environ.get("CHAIN_ID") or w3.eth.chain_id)
    tx = contract.functions.logCustody(bytes.fromhex(h), action).build_transaction({
        "from": acct.address,
        "nonce": w3.eth.get_transaction_count(acct.address, "pending"),
        "chainId": chain_id})
    signed = acct.sign_transaction(tx)
    raw = getattr(signed, "raw_transaction", None) or signed.rawTransaction
    tx_hash = w3.eth.send_raw_transaction(raw)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=90)
    h_txt = tx_hash.hex()
    h_txt = h_txt if h_txt.startswith("0x") else "0x" + h_txt
    if receipt.status != 1:
        sys.exit("transaction reverted (is this wallet an authorised handler, and is the event anchored?)")
    print(f"custody entry logged: '{action}'\ntx {h_txt}")


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if a != "--show"]
    if "--show" in sys.argv and len(args) == 1:
        show(event_hash_from(args[0]))
    elif len(args) == 2:
        log(event_hash_from(args[0]), args[1])
    else:
        print(__doc__)
        sys.exit(2)
