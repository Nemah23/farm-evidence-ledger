"""
preflight.py - run this first on the Pi (or laptop) to see what still needs fixing.
  python3 preflight.py
Checks packages, models, cameras, GPIO, Telegram, blockchain and evidence sealing,
and prints a PASS / FAIL / SKIP line for each.
"""
import importlib, os, sys, tempfile, time

results = []
def report(name, status, detail=""):
    results.append(status)
    colour = {"PASS": "\033[92m", "FAIL": "\033[91m", "SKIP": "\033[93m"}[status]
    print(f"{colour}[{status}]\033[0m {name}" + (f" - {detail}" if detail else ""), flush=True)

# 1. packages
for mod, hint in [("cv2", "opencv-python"), ("numpy", "numpy"), ("ultralytics", "ultralytics"),
                  ("cryptography", "cryptography"), ("requests", "requests"),
                  ("web3", "web3"), ("serial", "pyserial")]:
    try:
        importlib.import_module(mod); report(f"package {mod}", "PASS")
    except Exception as e:
        report(f"package {mod}", "FAIL", f"pip install {hint}  ({type(e).__name__})")
try:
    import RPi.GPIO  # noqa
    report("package RPi.GPIO", "PASS")
except Exception as e:
    report("package RPi.GPIO", "SKIP", f"not available ({type(e).__name__}); fine on a laptop. "
           "On a Pi 5 install rpi-lgpio - otherwise the monitor silently runs with SIMULATED sensors")

# 2. models + speed
model_path = os.environ.get("FARM_MODEL_PATH", "/home/pi/Final_Year_Project/yolov8n.onnx")
yunet_path = os.environ.get("FARM_YUNET_PATH", "/home/pi/Final_Year_Project/face_detection_yunet_2023mar.onnx")
report("YOLO model file", "PASS" if os.path.exists(model_path) or not model_path.startswith("/") else "FAIL", model_path)
report("YuNet model file", "PASS" if os.path.exists(yunet_path) else "FAIL", yunet_path)
try:
    import numpy as np
    from ultralytics import YOLO
    m = YOLO(model_path)
    img = np.zeros((480, 640, 3), np.uint8)
    m(img, imgsz=320, verbose=False)            # warm-up
    t0 = time.time()
    for _ in range(10):
        m(img, imgsz=320, verbose=False)
    ms = (time.time() - t0) / 10 * 1000
    report("YOLO inference", "PASS", f"{ms:.0f} ms per frame at 320px (~{1000/ms:.1f} runs/s)")
except Exception as e:
    report("YOLO inference", "FAIL", f"{type(e).__name__}: {str(e)[:120]}")

# 3. cameras
try:
    import cv2
    for idx in (int(os.environ.get("FARM_GATE_CAM", 0)), int(os.environ.get("FARM_KRAAL_CAM", 2))):
        cap = cv2.VideoCapture(idx); ok, _ = cap.read(); cap.release()
        report(f"camera index {idx}", "PASS" if ok else "FAIL", "" if ok else "no frame (check index with: ls /dev/video*)")
except Exception as e:
    report("cameras", "FAIL", str(e)[:100])

# 4. Telegram
tok, chat = os.environ.get("TELEGRAM_BOT_TOKEN"), os.environ.get("TELEGRAM_CHAT_ID")
if tok and chat:
    try:
        import requests
        r = requests.get(f"https://api.telegram.org/bot{tok}/getMe", timeout=10)
        ok = r.ok
        if ok:
            r = requests.post(f"https://api.telegram.org/bot{tok}/sendMessage",
                              data={"chat_id": chat, "text": "preflight test message"}, timeout=10)
            ok = r.ok
        report("Telegram", "PASS" if ok else "FAIL", "test message sent" if ok else r.text[:100])
    except Exception as e:
        report("Telegram", "FAIL", f"{type(e).__name__} (internet?)")
else:
    report("Telegram", "SKIP", "TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID not set")

# 5. blockchain
need = ("CHAIN_RPC_URL", "CHAIN_CONTRACT", "CHAIN_PRIVATE_KEY")
if all(os.environ.get(k) for k in need):
    try:
        from web3 import Web3
        w3 = Web3(Web3.HTTPProvider(os.environ["CHAIN_RPC_URL"], request_kwargs={"timeout": 15}))
        acct = w3.eth.account.from_key(os.environ["CHAIN_PRIVATE_KEY"])
        bal = w3.from_wei(w3.eth.get_balance(acct.address), "ether")
        code = w3.eth.get_code(Web3.to_checksum_address(os.environ["CHAIN_CONTRACT"]))
        report("chain connection", "PASS", f"chain id {w3.eth.chain_id}, wallet balance {bal}")
        report("contract deployed", "PASS" if len(code) > 2 else "FAIL",
               "" if len(code) > 2 else "no contract code at CHAIN_CONTRACT on this network")
        if bal == 0:
            report("wallet funded", "FAIL", "balance is 0 - get test tokens from the faucet")
    except Exception as e:
        report("chain connection", "FAIL", f"{type(e).__name__}: {str(e)[:100]}")
else:
    report("blockchain", "SKIP", "CHAIN_* variables not set")

# 6. evidence sealing
try:
    from evidence import EvidenceSealer
    from verify_evidence import check_one
    import cv2, numpy as np
    d = tempfile.mkdtemp()
    s = EvidenceSealer(d, "preflight", heartbeat_seconds=3600)
    p = os.path.join(d, "t.jpg"); cv2.imwrite(p, np.random.randint(0, 255, (120, 160, 3), np.uint8))
    s.seal({"camera": "TEST", "kind": "PERSON", "alert_no": 0}, image_path=p, summary="preflight"); s.stop()
    import io, contextlib
    with contextlib.redirect_stdout(io.StringIO()):
        good = check_one(p)
    report("evidence seal + verify", "PASS" if good else "FAIL")
except Exception as e:
    report("evidence seal + verify", "FAIL", f"{type(e).__name__}: {str(e)[:100]}")

print(f"\n{results.count('PASS')} passed, {results.count('FAIL')} failed, {results.count('SKIP')} skipped")
sys.exit(1 if "FAIL" in results else 0)
