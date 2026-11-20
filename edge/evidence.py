"""
evidence.py - seals detection events as tamper-evident evidence.

For every event:
  1. event_hash = SHA-256( SHA-256(image bytes) | canonical JSON of metadata )
  2. the hash is signed with this device's Ed25519 key
  3. image + a JSON "sidecar" (metadata, hashes, signature, public key) go to disk
  4. the event is queued in a local SQLite database
  5. a background thread sends the Telegram alert and anchors the hash on-chain,
     retrying until it succeeds (store-and-forward, so it works through
     load shedding and patchy signal)

Each event also carries the hash of the previous event (prev_event_hash), so
deleting an event from the middle of the log is detectable (see verify_evidence.py --audit).

Settings come from environment variables (nothing secret is stored in code):
  TELEGRAM_BOT_TOKEN, TELEGRAM_CHAT_ID           -> alerts (optional)
  CHAIN_RPC_URL, CHAIN_CONTRACT, CHAIN_PRIVATE_KEY, [CHAIN_ID]  -> anchoring (optional)
  HEARTBEAT_URL                                  -> POST heartbeats to a server (optional)
"""
import hashlib
import json
import os
import sqlite3
import threading
import time
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)

CONTRACT_ABI = [
    {"type": "function", "name": "recordEvent", "stateMutability": "nonpayable",
     "inputs": [{"name": "eventHash", "type": "bytes32"},
                {"name": "deviceId", "type": "string"},
                {"name": "deviceTime", "type": "uint64"},
                {"name": "signature", "type": "bytes"}],
     "outputs": []},
    {"type": "function", "name": "records", "stateMutability": "view",
     "inputs": [{"name": "", "type": "bytes32"}],
     "outputs": [{"name": "deviceId", "type": "string"},
                 {"name": "deviceTime", "type": "uint64"},
                 {"name": "blockTime", "type": "uint64"},
                 {"name": "reporter", "type": "address"},
                 {"name": "signature", "type": "bytes"}]},
]


# ── Shared helpers (also used by verify_evidence.py) ─────────────────────────
def canonical(meta):
    return json.dumps(meta, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode("ascii")


def compute_event_hash(image_bytes, meta):
    image_digest = hashlib.sha256(image_bytes or b"").hexdigest()
    payload = image_digest.encode("ascii") + b"|" + canonical(meta)
    return hashlib.sha256(payload).hexdigest(), image_digest


def verify_signature(public_key_hex, event_hash_hex, signature_hex):
    try:
        pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        pub.verify(bytes.fromhex(signature_hex), bytes.fromhex(event_hash_hex))
        return True
    except (InvalidSignature, ValueError):
        return False


def _log(msg):
    print(f"[EVIDENCE] {msg}", flush=True)


class EvidenceSealer:
    def __init__(self, folder, device_id, heartbeat_seconds=60):
        self.folder     = folder
        self.device_id  = device_id
        self.db_path    = os.path.join(folder, "events.db")
        self.heartbeat_seconds = heartbeat_seconds
        os.makedirs(folder, exist_ok=True)

        self._lock    = threading.Lock()
        self._wake    = threading.Event()
        self._running = True
        self._chain   = None            # (w3, account, contract, chain_id) once connected

        self.tg_token = os.environ.get("TELEGRAM_BOT_TOKEN")
        self.tg_chat  = os.environ.get("TELEGRAM_CHAT_ID")
        self.chain_on = all(os.environ.get(k) for k in
                            ("CHAIN_RPC_URL", "CHAIN_CONTRACT", "CHAIN_PRIVATE_KEY"))
        self.hb_url   = os.environ.get("HEARTBEAT_URL")

        self._load_or_create_key()
        self._init_db()

        _log(f"device {device_id}, public key {self.public_key_hex[:16]}...")
        _log("Telegram alerts: " + ("on" if self.tg_token and self.tg_chat else "OFF (not configured)"))
        _log("On-chain anchoring: " + ("on" if self.chain_on else "OFF (not configured) - events are queued"))

        threading.Thread(target=self._worker, daemon=True).start()
        threading.Thread(target=self._heartbeat_loop, daemon=True).start()

    # ── key + database ───────────────────────────────────────────────────────
    def _load_or_create_key(self):
        key_path = os.path.join(self.folder, "device_key.pem")
        if os.path.exists(key_path):
            with open(key_path, "rb") as f:
                self._key = serialization.load_pem_private_key(f.read(), password=None)
        else:
            self._key = Ed25519PrivateKey.generate()
            pem = self._key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption())
            with open(key_path, "wb") as f:
                f.write(pem)
            try:
                os.chmod(key_path, 0o600)
            except OSError:
                pass
            _log("new device key created (keep device_key.pem private)")
        self.public_key_hex = self._key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()

    def _db(self):
        return sqlite3.connect(self.db_path, timeout=10)

    def _init_db(self):
        with self._lock:
            con = self._db()
            try:
                con.executescript("""
                CREATE TABLE IF NOT EXISTS events(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event_hash TEXT UNIQUE, meta_path TEXT, image_path TEXT,
                    display_path TEXT, summary TEXT, created REAL,
                    telegram_done INTEGER DEFAULT 0,
                    chain_done INTEGER DEFAULT 0, tx_hash TEXT);
                CREATE TABLE IF NOT EXISTS heartbeats(
                    id INTEGER PRIMARY KEY AUTOINCREMENT, ts INTEGER, signature TEXT);
                CREATE TABLE IF NOT EXISTS state(key TEXT PRIMARY KEY, value TEXT);
                """)
                con.commit()
            finally:
                con.close()

    # ── sealing ──────────────────────────────────────────────────────────────
    def seal(self, meta, image_path=None, display_path=None, summary=""):
        """Seal one event. Returns the event hash (hex).
        image_path   : the file to hash (use the untouched frame)
        display_path : optional nicer picture (e.g. with boxes) sent to Telegram only"""
        now = time.time()
        with self._lock:
            con = self._db()
            try:
                row = con.execute("SELECT value FROM state WHERE key='last_hash'").fetchone()
                prev_hash = row[0] if row else "0" * 64
                row = con.execute("SELECT value FROM state WHERE key='seq'").fetchone()
                seq = (int(row[0]) if row else 0) + 1

                meta = dict(meta)
                meta.update({
                    "device_id": self.device_id,
                    "device_time_unix": int(now),
                    "device_time_utc": datetime.fromtimestamp(now, timezone.utc)
                                       .isoformat(timespec="seconds"),
                    "seq": seq,
                    "prev_event_hash": prev_hash,
                })

                image_bytes = b""
                if image_path:
                    with open(image_path, "rb") as f:
                        image_bytes = f.read()
                event_hash, image_digest = compute_event_hash(image_bytes, meta)
                signature = self._key.sign(bytes.fromhex(event_hash)).hex()

                record = {
                    "meta": meta,
                    "image_file": os.path.basename(image_path) if image_path else None,
                    "image_sha256": image_digest,
                    "event_hash": event_hash,
                    "signature": signature,
                    "public_key": self.public_key_hex,
                    "scheme": "event_hash=SHA256(SHA256(image)|canonical_json(meta)); Ed25519 over event_hash",
                }
                if image_path:
                    meta_path = image_path + ".json"
                else:
                    meta_path = os.path.join(
                        self.folder, f"event_{seq:05d}_{meta.get('kind', 'event')}.json")
                tmp = meta_path + ".tmp"
                with open(tmp, "w") as f:
                    json.dump(record, f, indent=2)
                os.replace(tmp, meta_path)

                tg_done = 0 if (self.tg_token and self.tg_chat) else 1
                con.execute(
                    "INSERT INTO events(event_hash, meta_path, image_path, display_path,"
                    " summary, created, telegram_done) VALUES(?,?,?,?,?,?,?)",
                    (event_hash, meta_path, image_path, display_path or image_path,
                     summary, now, tg_done))
                con.execute("INSERT OR REPLACE INTO state VALUES('last_hash', ?)", (event_hash,))
                con.execute("INSERT OR REPLACE INTO state VALUES('seq', ?)", (str(seq),))
                con.commit()
            finally:
                con.close()
        _log(f"sealed #{seq}: {event_hash[:16]}... ({meta.get('kind')})")
        self._wake.set()
        return event_hash

    def seal_event(self, meta, summary=""):
        return self.seal(meta, image_path=None, summary=summary)

    # ── background worker: Telegram + chain, with retry ──────────────────────
    def _worker(self):
        while self._running:
            self._wake.wait(timeout=5)
            self._wake.clear()
            if not self._running:
                break
            try:
                self._flush()
            except Exception as e:
                _log(f"worker error: {e}")

    def _pending(self):
        q = ("SELECT id, event_hash, meta_path, display_path, summary, created,"
             " telegram_done, chain_done FROM events WHERE telegram_done=0")
        if self.chain_on:
            q += " OR chain_done=0"
        q += " ORDER BY id LIMIT 20"
        with self._lock:
            con = self._db()
            try:
                return con.execute(q).fetchall()
            finally:
                con.close()

    def _mark(self, row_id, **fields):
        sets = ", ".join(f"{k}=?" for k in fields)
        with self._lock:
            con = self._db()
            try:
                con.execute(f"UPDATE events SET {sets} WHERE id=?",
                            (*fields.values(), row_id))
                con.commit()
            finally:
                con.close()

    def _flush(self):
        for (row_id, event_hash, meta_path, display_path, summary,
             created, tg_done, chain_done) in self._pending():
            if not tg_done and self._send_telegram(event_hash, display_path, summary, created):
                self._mark(row_id, telegram_done=1)
            if self.chain_on and not chain_done:
                tx = self._anchor(event_hash, meta_path)
                if tx:
                    self._mark(row_id, chain_done=1, tx_hash=tx)
                    _log(f"anchored {event_hash[:16]}... tx {tx}")

    def _send_telegram(self, event_hash, photo_path, summary, created):
        try:
            import requests
            text = f"{summary}\nEvidence hash: {event_hash[:16]}..."
            if time.time() - created > 120:
                text += "\n(delayed - device was offline)"
            base = f"https://api.telegram.org/bot{self.tg_token}"
            if photo_path and os.path.exists(photo_path):
                with open(photo_path, "rb") as f:
                    r = requests.post(base + "/sendPhoto",
                                      data={"chat_id": self.tg_chat, "caption": text},
                                      files={"photo": f}, timeout=20)
            else:
                r = requests.post(base + "/sendMessage",
                                  data={"chat_id": self.tg_chat, "text": text}, timeout=20)
            if r.ok:
                return True
            _log(f"Telegram refused: {r.status_code} {r.text[:120]}")
        except Exception as e:
            _log(f"Telegram not sent yet (will retry): {type(e).__name__}")
        return False

    def _connect_chain(self):
        if self._chain:
            return self._chain
        from web3 import Web3
        w3 = Web3(Web3.HTTPProvider(os.environ["CHAIN_RPC_URL"],
                                    request_kwargs={"timeout": 20}))
        account  = w3.eth.account.from_key(os.environ["CHAIN_PRIVATE_KEY"])
        contract = w3.eth.contract(
            address=Web3.to_checksum_address(os.environ["CHAIN_CONTRACT"]),
            abi=CONTRACT_ABI)
        chain_id = int(os.environ.get("CHAIN_ID") or w3.eth.chain_id)
        self._chain = (w3, account, contract, chain_id)
        _log(f"connected to chain {chain_id}, reporter {account.address}")
        return self._chain

    def _anchor(self, event_hash, meta_path):
        try:
            w3, account, contract, chain_id = self._connect_chain()
            with open(meta_path) as f:
                rec = json.load(f)
            fn = contract.functions.recordEvent(
                bytes.fromhex(event_hash),
                rec["meta"]["device_id"],
                int(rec["meta"]["device_time_unix"]),
                bytes.fromhex(rec["signature"]))
            tx = fn.build_transaction({
                "from": account.address,
                "nonce": w3.eth.get_transaction_count(account.address, "pending"),
                "chainId": chain_id,
            })
            signed = account.sign_transaction(tx)
            raw = getattr(signed, "raw_transaction", None) or signed.rawTransaction
            tx_hash = w3.eth.send_raw_transaction(raw)
            receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=90)
            if receipt.status != 1:
                _log("transaction reverted (already recorded, or reporter not authorised?)")
                return None
            h = tx_hash.hex()
            return h if h.startswith("0x") else "0x" + h
        except Exception as e:
            self._chain = None   # reconnect next time
            _log(f"chain write not done yet (will retry): {type(e).__name__}: {str(e)[:100]}")
            return None

    # ── heartbeat ────────────────────────────────────────────────────────────
    def _heartbeat_loop(self):
        while self._running:
            ts  = int(time.time())
            sig = self._key.sign(f"heartbeat|{self.device_id}|{ts}".encode()).hex()
            with self._lock:
                con = self._db()
                try:
                    con.execute("INSERT INTO heartbeats(ts, signature) VALUES(?,?)", (ts, sig))
                    con.execute("DELETE FROM heartbeats WHERE id < "
                                "(SELECT MAX(id) - 2000 FROM heartbeats)")
                    con.commit()
                finally:
                    con.close()
            if self.hb_url:
                try:
                    import requests
                    requests.post(self.hb_url, timeout=10, json={
                        "device_id": self.device_id, "ts": ts, "signature": sig,
                        "public_key": self.public_key_hex})
                except Exception:
                    pass
            for _ in range(int(self.heartbeat_seconds * 10)):
                if not self._running:
                    return
                time.sleep(0.1)

    def stop(self):
        self._running = False
        self._wake.set()
