import cv2
import numpy as np
import time
import csv
import os
import sys
import serial
import threading
import queue
try:
    import RPi.GPIO as GPIO
except (ImportError, RuntimeError):
    # Laptop fallback so the same code runs without a Raspberry Pi
    class _FakeGPIO:
        BCM = IN = PUD_UP = PUD_DOWN = 0
        def setmode(self, *a, **k): pass
        def setup(self, *a, **k): pass
        def input(self, pin): return 1     # PIR always "on"; tamper inputs idle
        def cleanup(self): pass
    GPIO = _FakeGPIO()
    print("RPi.GPIO not found - running with simulated GPIO (laptop mode)")
from collections import deque
from datetime import datetime
from ultralytics import YOLO
from evidence import EvidenceSealer

# ─────────────────────────────────────────────────────────────────
# FARM EVIDENCE MONITOR - Livestock Theft Detection + Sealed Evidence
# Dual-Camera (Gate + Kraal) | adapted from the Boundary Monitoring System
#
# DETECTION STRATEGY:
#   One YOLO model (COCO yolov8n) on both cameras:
#     person / vehicle       -> threat at any time
#     cattle / sheep / horse -> threat only at night, otherwise normal
#   The gate camera also runs YuNet every frame to catch faces up close.
#
# PERSISTENCE:
#   Gate : 3 threat detections in last 8 frames = ALERT
#   Kraal: same persistence counter as the original system
#
# EVIDENCE (evidence.py):
#   Every alert and tamper event is hashed (SHA-256), signed with the device
#   key, queued locally, then anchored on-chain and sent to Telegram whenever
#   a connection is available (store-and-forward).
# ─────────────────────────────────────────────────────────────────

# ── Camera Settings ──────────────────────────────────────────────
GATE_CAMERA_INDEX      = int(os.environ.get("FARM_GATE_CAM", 0))
KRAAL_CAMERA_INDEX     = int(os.environ.get("FARM_KRAAL_CAM", 2))
FRAME_WIDTH            = 640
FRAME_HEIGHT           = 480

# ── Model Paths ───────────────────────────────────────────────────
# One general model for the farm. COCO yolov8n detects person, vehicles, horse,
# sheep and cow (no goat). To use a fine-tuned livestock model later, change the
# path and the class maps further down.
FARM_MODEL_PATH  = os.environ.get("FARM_MODEL_PATH", "/home/pi/Final_Year_Project/yolov8n.onnx")
YUNET_MODEL_PATH = os.environ.get("FARM_YUNET_PATH", "/home/pi/Final_Year_Project/face_detection_yunet_2023mar.onnx")

# ── Detection Thresholds ─────────────────────────────────────────
YOLO_CONFIDENCE        = 0.3
YUNET_CONFIDENCE       = 0.6
LIVESTOCK_CONFIDENCE   = 0.4   # livestock must be at least this confident
NIGHT_START_HOUR       = 18    # livestock movement is a threat from 18:00 ...
NIGHT_END_HOUR         = 5     # ... until 05:00
FORCE_NIGHT            = os.environ.get("FARM_FORCE_NIGHT") == "1"   # demo/testing switch

# ── Processing Frequency ─────────────────────────────────────────
YUNET_EVERY_N_FRAMES   = 1    # YuNet runs every frame — very fast
YOLO_EVERY_N_FRAMES    = 5    # YOLOv8n runs every 5th frame

# ── Sliding Window Persistence ───────────────────────────────────
WINDOW_SIZE            = 8    # look at last 8 frames
WINDOW_MIN_DETECTIONS  = 3    # need 3 human detections in window
GATE_YOLO_RUNS_NEEDED  = 2    # OR: threat seen in 2 of the last 3 YOLO runs. YOLO only runs every 5th
                              # frame, so on its own it can never fill the 3-of-8 frame window (vehicles never trigger YuNet)

# ── Alert Cooldown ───────────────────────────────────────────────
ALERT_COOLDOWN_SECONDS = 60

# ── PIR Settings ─────────────────────────────────────────────────
PIR_PINS     = [4, 22]     # one GPIO per PIR (edit if the 2nd PIR is on another pin)
IDLE_TIMEOUT = 30          # seconds with no PIR trigger AND no detection before standby
ANIMAL_HOLD_SECONDS = 1.0  # how long a green animal box stays on screen
WINDOW_TITLE = "Farm Evidence Monitor | YuNet+YOLO | Q to quit"
# Headless only on Linux with no display (the Pi). Windows/Mac laptops always have a window.
HEADLESS = (os.environ.get("DCBMS_HEADLESS") == "1" or
            (sys.platform.startswith("linux") and not os.environ.get("DISPLAY")))
WARMUP_SECONDS = 5
BREACH_HOLD_SECONDS = 60   # stay awake this long after a confirmed breach

# ── YOLO (COCO) Classes ──────────────────────────────────────────
PERSON_CLASS_ID   = 0
VEHICLE_CLASSES   = {2: "Car", 3: "Motorcycle", 5: "Bus", 7: "Truck"}
LIVESTOCK_CLASSES = {17: "Horse", 18: "Sheep", 19: "Cattle"}   # COCO has no goat class
KIND_PRIORITY     = {"PERSON": 3, "VEHICLE": 2, "LIVESTOCK_NIGHT": 1}
KIND_TEXT         = {"PERSON": "PERSON", "VEHICLE": "VEHICLE",
                     "LIVESTOCK_NIGHT": "LIVESTOCK MOVING AT NIGHT"}

# ── Sigfox Settings ──────────────────────────────────────────────
SIGFOX_ENABLED = False     # Sigfox module unresolved - alerts go via Telegram + blockchain instead
SIGFOX_PORT    = "/dev/serial0"
SIGFOX_BAUD    = 9600
SIGFOX_TIMEOUT = 15
SIGFOX_TX_TIMEOUT = 30     # max seconds to wait for the module to finish sending
SIGFOX_MIN_HOLD   = 12     # always keep the module busy at least this long per message

# ── Tamper Detection ─────────────────────────────────────────────
VIBRATION_PIN            = 27
REED_PIN                 = 17
VIBRATION_PULL           = GPIO.PUD_DOWN  # module drives its own output (idles LOW)
REED_PULL                = GPIO.PUD_UP    # lid closed = HIGH, lid open = LOW
VIBRATION_MIN_EVENTS     = 3      # pulses needed ...
VIBRATION_WINDOW_SECONDS = 3.0    # ... inside this many seconds
REED_DEBOUNCE_SECONDS    = 0.5    # reed must stay changed this long
TAMPER_ARM_DELAY         = 5      # ignore tamper inputs this long after start
TAMPER_COOLDOWN_SECONDS  = 60     # min gap between vibration alerts
SIGFOX_TYPES = {"INTRUDER": 1, "ESCAPED": 2, "VIBRATION": 3, "LID": 4}

# ── Screenshot Settings ──────────────────────────────────────────
EVIDENCE_FOLDER   = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evidence")
SCREENSHOT_FOLDER = EVIDENCE_FOLDER
DEVICE_ID         = os.environ.get("FARM_DEVICE_ID", "farm-cam-01")

# ── CSV Logging ──────────────────────────────────────────────────
LOG_FOLDER   = os.path.dirname(os.path.abspath(__file__))
LOG_FILENAME = os.path.join(LOG_FOLDER,
    f"boundary_log_{datetime.now().strftime('%Y-%m-%d')}.csv")
CSV_HEADERS  = [
    "timestamp", "camera_zone", "classification",
    "label", "confidence", "breach_detected",
    "alert_sent", "window_count"
]

# ── Colours (BGR) ────────────────────────────────────────────────
COLOUR_BREACH_HUMAN  = (0,   0,   255)
COLOUR_BREACH_ANIMAL = (0,   165, 255)
COLOUR_IGNORED       = (128, 128, 128)
COLOUR_NORMAL        = (0,   255, 0  )
COLOUR_WHITE         = (255, 255, 255)


def setup_pir():
    GPIO.setmode(GPIO.BCM)
    for pin in PIR_PINS:
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_DOWN)
    print("PIR sensors ready on GPIO " + ", ".join(str(p) for p in PIR_PINS))


_pir_prev = {}


def pir_triggered():
    """True if ANY PIR is high. Prints which PIR fired on each rising edge."""
    active = False
    for pin in PIR_PINS:
        v = GPIO.input(pin)
        if v and not _pir_prev.get(pin, 0):
            print(f"PIR on GPIO{pin} triggered")
        _pir_prev[pin] = v
        active = active or bool(v)
    return active


def show(img):
    if not HEADLESS:
        cv2.imshow(WINDOW_TITLE, img)


def poll_key(delay_ms=1):
    if HEADLESS:
        time.sleep(delay_ms / 1000.0)
        return -1
    return cv2.waitKey(delay_ms) & 0xFF


class TamperMonitor:
    """Watches the vibration sensor and reed switch in a background thread
    (works in standby too). Events are queued for the main loop."""

    def __init__(self):
        self.events  = queue.Queue()
        self.running = True
        GPIO.setup(VIBRATION_PIN, GPIO.IN, pull_up_down=VIBRATION_PULL)
        GPIO.setup(REED_PIN,      GPIO.IN, pull_up_down=REED_PULL)
        self.vib_idle    = self._baseline(VIBRATION_PIN)
        self.reed_closed = self._baseline(REED_PIN)
        print(f"Tamper: vibration GPIO{VIBRATION_PIN} idle={self.vib_idle}, "
              f"reed GPIO{REED_PIN} closed={self.reed_closed} (assumes lid closed now)")
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    @staticmethod
    def _baseline(pin):
        highs = 0
        for _ in range(21):
            highs += GPIO.input(pin)
            time.sleep(0.02)
        return 1 if highs > 10 else 0

    def _run(self):
        t0             = time.time()
        vib_prev       = False
        vib_times      = deque()
        last_vib_alert = 0
        reed_since     = None
        reed_alerted   = False
        while self.running:
            now   = time.time()
            armed = (now - t0) >= TAMPER_ARM_DELAY

            vib_active = (GPIO.input(VIBRATION_PIN) != self.vib_idle)
            if vib_active and not vib_prev:
                vib_times.append(now)
            vib_prev = vib_active
            while vib_times and now - vib_times[0] > VIBRATION_WINDOW_SECONDS:
                vib_times.popleft()
            if (armed and len(vib_times) >= VIBRATION_MIN_EVENTS and
                    now - last_vib_alert > TAMPER_COOLDOWN_SECONDS):
                last_vib_alert = now
                vib_times.clear()
                self.events.put(("VIBRATION", "Vibration / impact on enclosure"))

            reed_open = (GPIO.input(REED_PIN) != self.reed_closed)
            if reed_open:
                if reed_since is None:
                    reed_since = now
                elif (armed and not reed_alerted and
                        now - reed_since >= REED_DEBOUNCE_SECONDS):
                    reed_alerted = True
                    self.events.put(("LID", "Enclosure lid opened"))
            else:
                if reed_alerted:
                    print("Tamper: lid closed again — re-armed")
                reed_since   = None
                reed_alerted = False

            time.sleep(0.005)

    def stop(self):
        self.running = False


TAMPER_STATE = {"count": 0, "text": "", "until": 0.0}
SEALER = None   # EvidenceSealer, created in main()


def handle_tamper_events(tamper, csv_file, csv_writer, sigfox_ser):
    """Drain queued tamper events: print, log, send Sigfox. True if any."""
    if tamper is None:
        return False
    handled = False
    while True:
        try:
            kind, text = tamper.events.get_nowait()
        except queue.Empty:
            break
        handled = True
        TAMPER_STATE["count"] += 1
        n = TAMPER_STATE["count"]
        print(f"\n*** TAMPER — {text} (tamper alert #{n}) ***")
        csv_writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            "ENCLOSURE", "TAMPER", text, "", "YES", "YES", ""
        ])
        csv_file.flush()
        TAMPER_STATE["text"]  = text
        TAMPER_STATE["until"] = time.time() + 10
        if SEALER:
            SEALER.seal({"camera": "ENCLOSURE", "kind": kind,
                         "alert_no": n, "detail": text},
                        summary=f"TAMPER #{n}: {text}")
        threading.Thread(target=send_sigfox_alert,
                         args=(kind, n, sigfox_ser), daemon=True).start()
    return handled


def wait_for_motion(tamper=None, csv_file=None, csv_writer=None, sigfox_ser=None):
    print("Waiting for motion...")
    standby = np.zeros((240, 640, 3), dtype=np.uint8)
    cv2.putText(standby, "STANDBY - waiting for PIR motion", (30, 120),
                cv2.FONT_HERSHEY_SIMPLEX, 0.8, (255, 255, 255), 2)
    cv2.putText(standby, "Press Q to quit", (30, 160),
                cv2.FONT_HERSHEY_SIMPLEX, 0.6, (180, 180, 180), 1)
    while True:
        if handle_tamper_events(tamper, csv_file, csv_writer, sigfox_ser):
            print("Tamper — waking system")
            return True
        if pir_triggered():
            print("Motion detected — starting detection")
            return True
        if HEADLESS:
            time.sleep(0.1)
        else:
            show(standby)
            if (cv2.waitKey(100) & 0xFF) == ord('q'):
                return False


class LatestFrameCamera:
    """Reads a camera in a background thread and keeps only the newest
    frame, so a slow detection loop never falls behind (no lag)."""

    def __init__(self, cap):
        self.cap     = cap
        self.lock    = threading.Lock()
        self.frame   = None
        self.running = True
        self.thread  = threading.Thread(target=self._reader, daemon=True)
        self.thread.start()
        t0 = time.time()
        while self.frame is None and time.time() - t0 < 5:
            time.sleep(0.01)

    def _reader(self):
        while self.running:
            ok, f = self.cap.read()
            if ok:
                with self.lock:
                    self.frame = f
            else:
                time.sleep(0.01)

    def read(self):
        with self.lock:
            if self.frame is None:
                return False, None
            f = self.frame.copy()
        return True, f

    def release(self):
        self.running = False
        self.thread.join(timeout=2)
        self.cap.release()


def open_camera(index):
    cap = cv2.VideoCapture(index)
    cap.set(cv2.CAP_PROP_FRAME_WIDTH,  FRAME_WIDTH)
    cap.set(cv2.CAP_PROP_FRAME_HEIGHT, FRAME_HEIGHT)
    cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)
    if not cap.isOpened():
        print(f"ERROR: Cannot open camera {index}")
        return None
    print(f"Camera {index} ready.")
    for _ in range(3):
        cap.read()
    return LatestFrameCamera(cap)


def setup_csv():
    exists = os.path.isfile(LOG_FILENAME)
    f      = open(LOG_FILENAME, 'a', newline='')
    w      = csv.writer(f)
    if not exists:
        w.writerow(CSV_HEADERS)
    print(f"Logging to: {LOG_FILENAME}")
    return f, w


def save_screenshot(frame_park, frame_community, alert_count, breach_type):
    os.makedirs(SCREENSHOT_FOLDER, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename  = f"breach_{alert_count}_{breach_type}_{timestamp}.jpg"
    filepath  = os.path.join(SCREENSHOT_FOLDER, filename)
    combined  = cv2.hconcat([frame_park, frame_community])
    cv2.imwrite(filepath, combined)
    print(f"    Screenshot saved: {filename}")
    return filename


sigfox_lock = threading.Lock()


def _sigfox_cmd(ser, cmd, wait_for=(b"OK", b"ERROR"), timeout=5.0):
    """Send one AT command and wait until a marker appears or timeout."""
    ser.reset_input_buffer()
    ser.write(cmd)
    buf = b""
    t0  = time.time()
    while time.time() - t0 < timeout:
        n = ser.in_waiting
        if n:
            buf += ser.read(n)
        if any(w in buf for w in wait_for):
            break
        time.sleep(0.05)
    return buf


def send_sigfox_alert(breach_type, alert_count, sigfox_ser=None):
    """Payload: [type][counter][01][00]. Type 01 intruder, 02 escaped,
    03 vibration, 04 lid. Counter lets you tell messages apart on the backend.
    One message at a time (lock) so alerts never overlap on the serial port."""
    if not SIGFOX_ENABLED:
        return False
    with sigfox_lock:
        close_after = False
        try:
            if sigfox_ser is None or not sigfox_ser.is_open:
                sigfox_ser  = serial.Serial(SIGFOX_PORT, SIGFOX_BAUD, timeout=0.2)
                close_after = True

            code    = SIGFOX_TYPES.get(breach_type, 1)
            payload = f"{code:02X}{alert_count & 0xFF:02X}0100"

            # Wake the module first (it sometimes ignores the first command)
            awake = False
            for _ in range(3):
                if b"OK" in _sigfox_cmd(sigfox_ser, b"AT\r\n", timeout=1.5):
                    awake = True
                    break
            if not awake:
                print("    Sigfox: module did not answer AT — check wiring/power")
                return False

            print(f"    Sending Sigfox alert: AT$SF={payload}")
            t0   = time.time()
            resp = _sigfox_cmd(sigfox_ser, b"AT$SF=" + payload.encode("ascii") + b"\r\n",
                               wait_for=(b"OK", b"ERR"), timeout=SIGFOX_TX_TIMEOUT)
            took = time.time() - t0

            # Keep the module undisturbed while it finishes transmitting
            time.sleep(max(0.0, SIGFOX_MIN_HOLD - took))
            n = sigfox_ser.in_waiting
            if n:
                resp += sigfox_ser.read(n)

            if close_after:
                sigfox_ser.close()

            if (b"OK" in resp or b"TX END" in resp) and b"ERR" not in resp:
                print(f"    Sigfox alert sent (took {took:.1f}s, payload {payload})")
                return True
            print(f"    Sigfox FAILED after {took:.1f}s, response: {resp}")
            return False

        except Exception as e:
            print(f"    Sigfox error: {e}")
            return False


def process_park_yunet(frame, yunet):
    """
    Run YuNet face detector on park frame.
    Fast — runs every frame.
    Returns: frame with annotations, human_detected (bool)
    """
    h, w = frame.shape[:2]
    yunet.setInputSize((w, h))
    _, faces = yunet.detect(frame)

    if faces is None or len(faces) == 0:
        return frame, False

    for face in faces:
        fx, fy, fw, fh = face[0:4].astype(int)
        conf = float(face[14])
        cv2.rectangle(frame, (fx, fy), (fx+fw, fy+fh),
                      COLOUR_BREACH_HUMAN, 3)
        cv2.putText(frame, f"Face {conf:.0%}",
                    (fx, fy - 22),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.65, COLOUR_BREACH_HUMAN, 2)
        cv2.putText(frame, "PERSON DETECTED",
                    (fx, fy - 5),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.55, COLOUR_BREACH_HUMAN, 2)
        print(f"[GATE] Face       {conf:.0%} | THREAT - person (YuNet)")

    return frame, True


_animal_cache = {"boxes": [], "t": 0.0}


def draw_animal_cache(frame):
    """Redraw last-seen park animals every frame so the box does not flash."""
    if time.time() - _animal_cache["t"] > ANIMAL_HOLD_SECONDS:
        return
    for (x1, y1, x2, y2) in _animal_cache["boxes"]:
        cv2.rectangle(frame, (x1, y1), (x2, y2), COLOUR_NORMAL, 2)
        cv2.putText(frame, "Livestock (normal)", (x1, max(y1 - 8, 15)),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.6, COLOUR_NORMAL, 2)


def is_night():
    if FORCE_NIGHT:
        return True
    h = datetime.now().hour
    return h >= NIGHT_START_HOUR or h < NIGHT_END_HOUR


def process_farm_frame(frame, model, zone):
    """
    Run the farm YOLO model on one frame (used for both cameras).
      person / vehicle -> threat at any time
      livestock        -> threat only at night, otherwise normal
    Returns: frame, threat (bool), detections (list), kind (str or None)
    """
    detections   = []
    normal_boxes = []
    kind         = None
    night        = is_night()
    results      = model(frame, conf=YOLO_CONFIDENCE, verbose=False, imgsz=320)

    for r in results:
        if r.boxes is None:
            continue
        for box in r.boxes:
            cid        = int(box.cls[0])
            confidence = float(box.conf[0])
            x1, y1, x2, y2 = map(int, box.xyxy[0])

            if cid == PERSON_CLASS_ID:
                cls, label, threat_kind = "PERSON", "Person", "PERSON"
            elif cid in VEHICLE_CLASSES:
                cls, label, threat_kind = "VEHICLE", VEHICLE_CLASSES[cid], "VEHICLE"
            elif cid in LIVESTOCK_CLASSES and confidence >= LIVESTOCK_CONFIDENCE:
                cls, label = "LIVESTOCK", LIVESTOCK_CLASSES[cid]
                threat_kind = "LIVESTOCK_NIGHT" if night else None
            else:
                continue

            if threat_kind:
                colour = COLOUR_BREACH_ANIMAL if cls == "LIVESTOCK" else COLOUR_BREACH_HUMAN
                cv2.rectangle(frame, (x1, y1), (x2, y2), colour, 3)
                cv2.putText(frame, f"{label} {confidence:.0%}",
                            (x1, max(y1 - 22, 15)),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.65, colour, 2)
                cv2.putText(frame, "ALERT - " + KIND_TEXT[threat_kind],
                            (x1, max(y1 - 5, 15)),
                            cv2.FONT_HERSHEY_SIMPLEX, 0.55, colour, 2)
                if kind is None or KIND_PRIORITY[threat_kind] > KIND_PRIORITY[kind]:
                    kind = threat_kind
                print(f"[{zone}] {label:10s} {confidence:.0%} | THREAT - {KIND_TEXT[threat_kind].lower()}")
            else:
                normal_boxes.append((x1, y1, x2, y2))
                if zone != "GATE":   # gate boxes are redrawn from the cache every frame
                    cv2.rectangle(frame, (x1, y1), (x2, y2), COLOUR_NORMAL, 2)
                    cv2.putText(frame, "Livestock (normal)", (x1, max(y1 - 8, 15)),
                                cv2.FONT_HERSHEY_SIMPLEX, 0.6, COLOUR_NORMAL, 2)
                print(f"[{zone}] {label:10s} {confidence:.0%} | normal (daytime livestock)")

            detections.append({
                "cls": cls, "label": label,
                "conf": confidence, "breach": threat_kind is not None
            })

    if normal_boxes and zone == "GATE":
        _animal_cache["boxes"] = normal_boxes
        _animal_cache["t"] = time.time()
    return frame, kind is not None, detections, kind


def draw_header(frame, zone_label, window_count, alerts,
                last_breach_type, last_alert_time, warmup_done, pir_active):
    col = (0, 0, 130) if "GATE" in zone_label else (0, 100, 130)
    cv2.rectangle(frame, (0, 0), (FRAME_WIDTH, 30), col, -1)
    cv2.putText(frame, zone_label, (8, 22),
                cv2.FONT_HERSHEY_SIMPLEX, 0.7, COLOUR_WHITE, 2)

    if not warmup_done:
        cv2.putText(frame, "Warming up...",
                    (FRAME_WIDTH - 160, 22),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 255, 255), 1)

    pir_colour = (0, 255, 0) if pir_active else (128, 128, 128)
    cv2.putText(frame, "PIR:ON" if pir_active else "PIR:--",
                (FRAME_WIDTH - 80, 22),
                cv2.FONT_HERSHEY_SIMPLEX, 0.4, pir_colour, 1)

    if window_count > 0 and warmup_done and "GATE" in zone_label:
        bw = int((FRAME_WIDTH - 16) * (window_count / WINDOW_MIN_DETECTIONS))
        bw = min(bw, FRAME_WIDTH - 16)
        cv2.rectangle(frame, (8, 34), (FRAME_WIDTH - 8, 48),
                      (50, 50, 50), -1)
        cv2.rectangle(frame, (8, 34), (8 + bw, 48), (0, 0, 255), -1)
        cv2.putText(frame,
                    f"Threat evidence: {window_count}/{WINDOW_MIN_DETECTIONS}",
                    (8, 65),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.42, (0, 0, 255), 1)

    if last_breach_type and (time.time() - last_alert_time) < 30:
        cv2.putText(frame, f"Last: {last_breach_type}",
                    (8, FRAME_HEIGHT - 28),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.42, (0, 165, 255), 1)

    cv2.putText(frame, f"Alerts: {alerts}",
                (8, FRAME_HEIGHT - 8),
                cv2.FONT_HERSHEY_SIMPLEX, 0.5, COLOUR_WHITE, 1)
    return frame


def run_detection(farm_model, yunet,
                  csv_file, csv_writer, sigfox_ser=None,
                  cam_park=None, cam_community=None, tamper=None):

    print("Detection active.")

    alert_count      = 0
    last_alert_time  = 0
    total_logged     = 0
    session_start    = time.time()
    frame_count      = 0
    last_breach_type = ""
    warmup_done      = False
    last_motion_time = time.time()
    sigfox_thread    = None

    fps_times             = deque(maxlen=20)
    fp_last               = None
    fc_last               = None
    bp                    = False
    bc                    = False
    dc                    = []
    community_persistence = 0
    human_window          = deque(maxlen=WINDOW_SIZE)  # stores 1 (human) or 0 per frame
    yolo_runs             = deque(maxlen=3)   # 1/0 per YOLO run on the gate camera
    gate_kind             = None   # strongest threat kind seen at the gate
    kraal_kind            = None   # same, for the kraal camera (bc = kraal threat)

    while True:
        ok_p, fp = cam_park.read()
        ok_c, fc = cam_community.read()
        if not ok_p or not ok_c:
            time.sleep(0.005)
            continue
        raw_p, raw_c = fp.copy(), fc.copy()   # untouched frames, kept for sealing as evidence

        frame_count    += 1
        current_time    = time.time()
        fps_times.append(current_time)
        cooldown_active = (current_time - last_alert_time) < ALERT_COOLDOWN_SECONDS
        pir_active      = pir_triggered()

        if pir_active:
            last_motion_time = current_time

        if handle_tamper_events(tamper, csv_file, csv_writer, sigfox_ser):
            last_motion_time = current_time

        if (current_time - last_motion_time > IDLE_TIMEOUT and
                current_time - last_alert_time > BREACH_HOLD_SECONDS):
            if sigfox_thread and sigfox_thread.is_alive():
                print("Waiting for Sigfox...")
                sigfox_thread.join(timeout=15)
            print(f"No motion for {IDLE_TIMEOUT}s — returning to standby")
            break

        if not warmup_done and (current_time - session_start) >= WARMUP_SECONDS:
            warmup_done = True
            print("Warmup complete — alerts now active.")

        # ── GATE CAMERA ──────────────────────────────────────────
        # YuNet runs every frame - fast
        fp, yunet_human = process_park_yunet(fp, yunet)

        # YOLO runs every 5th frame - slower but thorough
        yolo_threat = False
        if frame_count % YOLO_EVERY_N_FRAMES == 0:
            fp, yolo_threat, dp, gate_yolo_kind = process_farm_frame(fp, farm_model, "GATE")
            yolo_runs.append(1 if yolo_threat else 0)
            if gate_yolo_kind:
                gate_kind = gate_yolo_kind
            for det in dp:
                csv_writer.writerow([
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "GATE", det["cls"], det["label"],
                    f"{det['conf']:.2f}",
                    "YES" if det["breach"] else "NO", "NO",
                    sum(human_window)
                ])
                total_logged += 1

        draw_animal_cache(fp)

        # Sliding window - 1 if a threat was seen by either detector
        if yunet_human:
            gate_kind = "PERSON"
        human_this_frame = 1 if (yunet_human or yolo_threat) else 0
        human_window.append(human_this_frame)
        window_count = sum(human_window)
        if window_count == 0 and not any(yolo_runs):
            gate_kind = None
        bp = (window_count >= WINDOW_MIN_DETECTIONS or
              sum(yolo_runs) >= GATE_YOLO_RUNS_NEEDED)

        # ── KRAAL CAMERA ─────────────────────────────────────────
        if frame_count % YOLO_EVERY_N_FRAMES == 0:
            fc, bc, dc, kraal_kind = process_farm_frame(fc, farm_model, "KRAAL")
            fc_last = fc.copy()
            for det in dc:
                csv_writer.writerow([
                    datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    "KRAAL", det["cls"], det["label"],
                    f"{det['conf']:.2f}",
                    "YES" if det["breach"] else "NO",
                    "NO", community_persistence
                ])
                total_logged += 1
        else:
            if fc_last is not None:
                fc = fc_last.copy()

        # Kraal persistence (same logic as the original community side)
        if bc:
            community_persistence += 1
        else:
            community_persistence = 0

        bc_confirmed = community_persistence >= 3

        # Any detection in view keeps the system awake even if the
        # PIR has gone quiet (PIR only senses movement).
        if human_this_frame or bc or dc:
            last_motion_time = current_time


        # ── ALERT LOGIC ──────────────────────────────────────────
        breach_confirmed = (bp or bc_confirmed) and warmup_done

        if breach_confirmed and not cooldown_active:
            alert_count    += 1
            last_alert_time = current_time
            human_window.clear()
            yolo_runs.clear()
            community_persistence = 0

            if bp:
                zone, kind = "GATE", (gate_kind or "PERSON")
            else:
                zone, kind = "KRAAL", (kraal_kind or "LIVESTOCK_NIGHT")
            last_breach_type = f"{KIND_TEXT[kind]} ({zone})"
            gate_kind = None

            print(f"\n*** ALERT #{alert_count} - {last_breach_type} ***")
            # annotated picture (for the screen / Telegram) ...
            shot_name = save_screenshot(fp, fc, alert_count, kind.lower())
            # ... and the untouched frames, which are what gets hashed and sealed
            raw_name = save_screenshot(raw_p, raw_c, alert_count, kind.lower() + "_raw")
            if SEALER:
                SEALER.seal({"camera": zone, "kind": kind, "alert_no": alert_count},
                            image_path=os.path.join(SCREENSHOT_FOLDER, raw_name),
                            display_path=os.path.join(SCREENSHOT_FOLDER, shot_name),
                            summary=f"ALERT #{alert_count}: {last_breach_type}")
            print(f"    Cooldown: {ALERT_COOLDOWN_SECONDS}s\n")

        elif breach_confirmed and cooldown_active:
            remaining = ALERT_COOLDOWN_SECONDS - (current_time - last_alert_time)
            print(f"    [Cooldown: {remaining:.0f}s]")
            human_window.clear()
            yolo_runs.clear()
            community_persistence = 0

        # ── DRAW HEADERS ─────────────────────────────────────────
        fp = draw_header(fp, "GATE", window_count, alert_count,
                         last_breach_type, last_alert_time,
                         warmup_done, pir_active)
        if len(fps_times) > 1:
            fps = (len(fps_times) - 1) / max(fps_times[-1] - fps_times[0], 1e-6)
            cv2.putText(fp, f"FPS: {fps:.1f}", (FRAME_WIDTH - 90, 44),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.45, (0, 255, 255), 1)
        fc = draw_header(fc, "KRAAL", community_persistence,
                         alert_count, last_breach_type, last_alert_time,
                         warmup_done, pir_active)

        # ── ALERT BANNER ─────────────────────────────────────────
        elapsed = current_time - last_alert_time
        if elapsed < 5 and alert_count > 0:
            cv2.rectangle(fp, (0, FRAME_HEIGHT - 40),
                          (FRAME_WIDTH, FRAME_HEIGHT), (0, 0, 180), -1)
            cv2.putText(fp, f"ALERT #{alert_count} — {last_breach_type}",
                        (8, FRAME_HEIGHT - 12),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.6, COLOUR_WHITE, 2)
            cv2.rectangle(fc, (0, FRAME_HEIGHT - 40),
                          (FRAME_WIDTH, FRAME_HEIGHT), (0, 0, 180), -1)
            cv2.putText(fc, "Evidence sealed",
                        (8, FRAME_HEIGHT - 12),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.55, COLOUR_WHITE, 1)

        if current_time < TAMPER_STATE["until"]:
            cv2.rectangle(fp, (0, 70), (FRAME_WIDTH, 100), (0, 0, 200), -1)
            cv2.putText(fp, f"TAMPER: {TAMPER_STATE['text']}", (8, 92),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.55, COLOUR_WHITE, 2)

        combined = cv2.hconcat([fp, fc])
        show(combined)
        csv_file.flush()

        key = poll_key(1)
        if key == ord('q'):
            return True

    print(f"Detection session complete. Logged: {total_logged}")
    return False


def main():
    global SEALER
    print("=" * 60)
    print("FARM EVIDENCE MONITOR - YuNet + YOLO + sealed evidence")
    print("Dual-Camera | Gate + Kraal")
    print("=" * 60)
    print()
    print("Loading models...")
    farm_model = YOLO(FARM_MODEL_PATH)
    yunet = cv2.FaceDetectorYN.create(
        YUNET_MODEL_PATH, "",
        (FRAME_WIDTH, FRAME_HEIGHT),
        score_threshold=YUNET_CONFIDENCE,
        nms_threshold=0.3,
        top_k=5000
    )
    print("All models loaded.")
    print()
    print("ZONE CONFIGURATION:")
    print(f"  Camera {GATE_CAMERA_INDEX} = GATE")
    print(f"    YuNet face detection - every frame")
    print(f"    YOLO person/vehicle/livestock - every {YOLO_EVERY_N_FRAMES}th frame")
    print(f"    ALERT: {WINDOW_MIN_DETECTIONS} threat detections in last {WINDOW_SIZE} frames")
    print(f"  Camera {KRAAL_CAMERA_INDEX} = KRAAL")
    print(f"    ALERT: person/vehicle, or livestock at night ({NIGHT_START_HOUR}:00-{NIGHT_END_HOUR}:00)")
    print(f"  PIR sensors   : GPIO {PIR_PINS}")
    print(f"  Tamper        : vibration GPIO{VIBRATION_PIN}, reed GPIO{REED_PIN}")
    print(f"  Idle timeout  : {IDLE_TIMEOUT}s (breach hold {BREACH_HOLD_SECONDS}s)")
    print(f"  Warmup        : {WARMUP_SECONDS}s")
    print(f"  Cooldown      : {ALERT_COOLDOWN_SECONDS}s")
    print(f"  Evidence      : {EVIDENCE_FOLDER} (device {DEVICE_ID})")
    print()

    if HEADLESS:
        print("HEADLESS mode: no display. Press Ctrl+C to stop.")

    setup_pir()

    tamper = None
    try:
        tamper = TamperMonitor()
    except Exception as e:
        print(f"Tamper monitor error: {e}")

    sigfox_ser = None
    if SIGFOX_ENABLED:
        try:
            sigfox_ser = serial.Serial(SIGFOX_PORT, SIGFOX_BAUD, timeout=0.2)
            sigfox_ser.reset_input_buffer()
            print("Sigfox port opened successfully")
        except Exception as e:
            print(f"Sigfox port error: {e}")

    os.makedirs(SCREENSHOT_FOLDER, exist_ok=True)
    csv_file, csv_writer = setup_csv()
    SEALER = EvidenceSealer(EVIDENCE_FOLDER, DEVICE_ID)

    print()
    print("System ready. Wave hand past a PIR to start. Press Q to quit.")
    print()

    # Open cameras once at startup — stay open permanently
    cam_park      = open_camera(GATE_CAMERA_INDEX)
    cam_community = open_camera(KRAAL_CAMERA_INDEX)

    if cam_park and not cam_community:
        print("Kraal camera not found - reusing the gate camera for both views.")
        cam_community = cam_park

    if not cam_park:
        print("ERROR: Cannot open cameras.")
        return

    print("Both cameras ready. Wave hand past PIR to start. Press Q to quit.")

    try:
        while True:
            if not wait_for_motion(tamper, csv_file, csv_writer, sigfox_ser):
                break
            quit_requested = run_detection(
                farm_model, yunet,
                csv_file, csv_writer, sigfox_ser,
                cam_park, cam_community, tamper)
            if quit_requested:
                break

    except KeyboardInterrupt:
        print("\nStopped by user.")
    finally:
        if tamper:
            tamper.stop()
        if SEALER:
            SEALER.stop()
        GPIO.cleanup()
        if sigfox_ser and sigfox_ser.is_open:
            sigfox_ser.close()
        if cam_park:
            cam_park.release()
        if cam_community and cam_community is not cam_park:
            cam_community.release()
        if not HEADLESS:
            cv2.destroyAllWindows()
        csv_file.close()
        print("System shutdown complete.")


if __name__ == "__main__":
    main()
