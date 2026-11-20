# Farm Evidence Ledger

**Tamper-evident evidence for livestock theft, anchored on Avalanche.**
A camera at the farm gate or kraal detects people, vehicles and livestock with AI, seals every
event (SHA-256 hash + device signature) and anchors the hash on the Avalanche Fuji testnet.
Police, insurers and buyers can later check that a photo is untouched without having to trust the farmer.

BACISS 2026 Project Build submission.

## Submission checklist
| Requirement | Where |
|---|---|
| Deployed contract on Fuji + explorer link | **Contract:** `0x777398f6c4b3ac46b85d8e60ef0b39d8032c4e26`  **Explorer:** `https://testnet.snowscan.xyz/address/0x777398f6c4b3ac46b85d8e60ef0b39d8032c4e26` |
| Source code, README, basic tests | this repo (`contracts/`, `test/`, `edge/`) |
| Live demo, at least two state-changing transactions | see [Demo script](#demo-script) |
| Problem, why Avalanche, next milestone | see below |
| No real funds / personal data | mock identities and test tokens only (see [Data and safety](#data-and-safety)) |

## The problem
Stock theft is hard to prove. Farm cameras record footage, but footage can be edited, deleted or
challenged, and thieves often work at night in places the farmer cannot watch. When evidence is
disputed, cases and insurance claims stall. Farmers, police and insurers need a record that none
of them can quietly rewrite.

*(Add your survey and interview findings here: number of responses, key quotes, sourced statistics.)*

## Why Avalanche
- **Low-cost, fast transactions:** every detection is a transaction, so cost and speed per event matter.
- **EVM compatible:** standard Solidity and tooling; the same contract runs on any EVM chain.
- **Path to privacy:** farm evidence should not be public. Production can move to a permissioned
  Avalanche L1 where only registered cameras, farmers, police and insurers can write or read.
- **Only hashes go on-chain**, never images or locations, so the public testnet leaks nothing sensitive.

## How it works
```
camera -> AI detection (YOLO) -> seal: SHA-256(image + metadata), signed with device key
       -> local queue (works offline / during load shedding)
       -> Telegram alert to the farmer
       -> EvidenceLedger.recordEvent(...) on Avalanche Fuji
later:  rangers / police / insurers -> logCustody(...)   (who handled the evidence, and when)
        anyone -> verify_evidence.py  (recompute hash, check signature, compare with the chain)
```
Each sealed event also carries the hash of the previous one, so deleting an event from the log is detectable (`--audit`).

## Smart contract: `contracts/EvidenceLedger.sol`
| Function | Who | What it does |
|---|---|---|
| `recordEvent(hash, deviceId, deviceTime, signature)` | authorised reporter | anchors a sealed event (rejects duplicates, empty device id, bad signature length) |
| `logCustody(hash, action)` | authorised handler | appends a chain-of-custody entry to an anchored event |
| `setReporter(addr, allowed)` | owner | authorise or revoke a camera/gateway wallet (e.g. stolen device) |
| `setHandler(addr, allowed)` | owner | authorise or revoke someone who can log custody |
| `transferOwnership(addr)` | owner | hand over control |
| `records`, `isRecorded`, `custodyCount`, `getCustody` | anyone | read-only verification |

Access control: owner, reporters and handlers are separate roles. A revoked reporter cannot write,
but evidence it recorded earlier stays intact.

## Run the tests
```
npm install
npm test
```
14 tests cover recording, duplicate and invalid-input rejection, access control, revocation,
ownership transfer and the custody trail.

## Deploy to Avalanche Fuji
Use a **throwaway test wallet** with test AVAX from the Avalanche faucet.
```
# 1. copy .env.example to .env and put your test wallet key in it (with or without 0x)
# 2. deploy:
npm run deploy:fuji
```
(An environment variable named `PRIVATE_KEY` works too.)
The script prints the contract address and explorer link. (Or paste `contracts/EvidenceLedger.sol`
into Remix, compile with EVM version `paris`, and deploy with MetaMask on Fuji.)

### Verify the contract on the explorer
Open `https://testnet.snowscan.xyz/address/<ADDRESS>`, choose Contract, then Verify and Publish. Use "Solidity (Single file)",
compiler 0.8.26, MIT license, optimizer enabled with 200 runs, EVM version `paris`, and paste `contracts/EvidenceLedger.sol`.
The settings must match the deployed build exactly (if you deployed from Remix, use the compiler and optimizer settings Remix shows).
Verified source lets judges read the code and use the explorer's Write Contract tab.

## Run the edge monitor
Python 3.10 to 3.14.
```
pip install ultralytics opencv-python numpy cryptography requests web3 pyserial
cd edge
python preflight.py        # checks packages, models, cameras, Telegram, chain, sealing
python farm_monitor.py
```
Settings are environment variables: `FARM_MODEL_PATH`, `FARM_YUNET_PATH`, `FARM_GATE_CAM`,
`FARM_KRAAL_CAM`, `FARM_FORCE_NIGHT=1` (demo: livestock alerts in daytime),
`TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, `CHAIN_RPC_URL`, `CHAIN_CONTRACT`, `CHAIN_PRIVATE_KEY`, `CHAIN_ID=43113`.
The YuNet model `face_detection_yunet_2023mar.onnx` comes from the OpenCV Zoo.
Without a Raspberry Pi the monitor runs with simulated GPIO (laptop mode).

## Demo script
1. **Detection -> state-changing transaction #1:** a person appears at the gate; the event is sealed,
   a Telegram alert arrives, and `recordEvent` is anchored on Fuji (open the transaction on the explorer).
2. **Custody -> transaction #2:** `python log_custody.py evidence/<file>_raw_<time>.jpg "reviewed by ranger"`,
   then `python log_custody.py --show <same file>` to read the trail.
3. **Verify:** `python verify_evidence.py <file> --chain` shows UNTOUCHED. Edit the image and run it again:
   ALTERED. `python verify_evidence.py --audit evidence` shows the log is unbroken.
4. **Access control -> transaction #3 (optional):** the owner calls `setReporter(<camera wallet>, false)`
   (Remix or the explorer's Write Contract tab); a further `recordEvent` from that wallet now reverts.

## Design notes (following the Avalanche beginner guide)
- **C-Chain first.** The contract is deployed on the Fuji C-Chain. Our own Avalanche L1 is a later step, only if restricted access
  (approved cameras, farmers, police and insurers only) becomes necessary.
- **Only what must be trustless goes on-chain:** hashes, device id, timestamps and signatures. Detection, images and alerts stay off-chain.
- **Tested failure cases:** duplicate events, invalid input, unauthorised wallets, revoked wallets and unknown events are covered by tests.
- **Access control** is a small role model (owner, reporters, handlers) covered by tests. Before any mainnet use we would use
  OpenZeppelin AccessControl and get an independent security review.

## Data and safety
- Demo uses mock identities, mock device ids and Fuji test tokens only; no real funds or customer data.
- Images, locations and personal data stay off-chain. Only hashes, device id, timestamps and signatures go on-chain.
- Never commit keys. `.gitignore` excludes `.env`, `*.pem` and the `evidence/` folder.

## Limitations (honest)
- The hash proves a file is unchanged since sealing, not that the camera input was genuine.
  Mitigations: device signing keys, tamper and heartbeat monitoring, revocation of stolen devices.
- The general COCO model detects cattle, sheep and horses but has no goat class; night performance
  with a basic webcam is limited. Accuracy results: *(add your test numbers)*.
- Edge code and contract are tested in simulation and on a local chain; field testing is the next step.

## Next milestone
Pilot with a farmers' association: field-test cameras with battery backup, add an animal-ownership
registry and a buyer-side "reported stolen" check, move to a permissioned Avalanche L1, and add a
dashboard and heartbeat watcher that alerts when a camera goes offline.

## Repository layout
```
contracts/EvidenceLedger.sol    smart contract
test/EvidenceLedger.test.js     Hardhat tests (14)
scripts/deploy.js               deploy to Fuji
edge/farm_monitor.py            camera detection loop (adapted from our boundary monitoring system)
edge/evidence.py                hash, sign, offline queue, Telegram, on-chain anchoring, heartbeat
edge/verify_evidence.py         verify a file / audit the log
edge/log_custody.py             add or read chain-of-custody entries
edge/preflight.py               setup checker
```
