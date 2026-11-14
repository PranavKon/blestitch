# blestitch

Passive BLE **address-rotation stitcher**. BLE devices rotate their advertising
address (~every 15 min) to resist tracking; blestitch links those temporary
addresses back into continuous per-device timelines from a passive radio
capture, and shows the result in a web GUI.

> **Scope:** built for a **controlled environment with consenting
> participants/devices**. Accuracy grading and a calibrated confidence meter
> (which require the devices' IRKs) are **v2**; see `PLAN.md`.

## v1

A **rule-based** stitcher — no training data, no answer keys. The pipeline:

```
capture → dissect → address epochs → (M3: stitch into device trails) → GUI
```

Today (M2) the pipeline stops at profiled address epochs: load a capture and
explore every temporary address on a zoomable timeline, with its advertising
cadence, vendor/protocol identity and decoded payloads.

## What it reads

- **Containers:** `.pcap` and `.pcapng`, optionally gzip-compressed.
- **Link types:** Nordic nRF Sniffer (DLT 272, protocol versions 1–3) and
  `BLUETOOTH_LE_LL_WITH_PHDR` (DLT 256).
- **Timing:** nRF Sniffer packets are timed by the sniffer's hardware clock
  (unwrapped and anchored to capture time), not by the jittery host timestamps.
- **Filtering:** packets that failed the sniffer's CRC check and connection
  (data-channel) traffic are dropped and counted; the GUI shows the counts.
- **PDUs:** all legacy advertising PDUs. SCAN_REQ / CONNECT_IND are attached to
  the epoch they target. Extended advertising is attributed when the PDU itself
  carries the advertiser address; following AUX chains is not done yet.
- **Payloads:** generic AD fields, Bluetooth SIG company and service names,
  Apple Continuity (Nearby Info, Handoff, Proximity Pairing, Find My, iBeacon,
  …), Eddystone, Exposure Notification, Fast Pair, Tile, MiBeacon. Apple's
  formats are undocumented; decoding follows public reverse engineering and the
  raw bytes are always shown.

## Layout

```
blestitch/      pure-Python engine (no UI deps)
  io/           capture reader (pcap/pcapng; DLT 256 / Nordic 272), LabeledTrace seam
  dissect/      PDU + AD parsing, vendor decoders, epoch segmentation, epoch profiles
  results/      structured JSON artifact (engine ↔ GUI seam)
  data/         vendored Bluetooth company / service identifiers (see NOTICE)
  link/ features/ eval/ vault/   (filled in later milestones)
backend/        FastAPI (serves the engine to the GUI)
frontend/       React + Vite GUI (canvas timeline on D3 scales/zoom)
scripts/        fetch_samples.py — public sample captures for development
tests/          pytest suite
```

## Run it

Backend (Python 3.11+):

```bash
pip install -e ".[backend,dev]"
uvicorn backend.app:app --reload        # http://localhost:8000
```

Frontend (Node 18+):

```bash
cd frontend
npm install
npm run dev                             # http://localhost:5173
```

Open the frontend and choose (or drop) a BLE capture. The dev server proxies
`/api/*` to the backend automatically.

- **Timeline:** one bar per address epoch, coloured by address type. Drag to
  pan, Ctrl/⌘ + scroll (or pinch) to zoom, click a bar to select it.
- **Epoch table:** the same epochs, sortable; rows are keyboard-selectable.
- **Epoch detail:** cadence, RSSI, channels, PDU mix, then every distinct
  payload in order of first appearance — decoded, with the bytes that changed
  since the previous payload highlighted — and the packet list.

## Sample captures

```bash
python scripts/fetch_samples.py         # downloads into data/ (git-ignored)
```

Fetches a real nRF Sniffer capture and two Wireshark coverage captures. Put
your own captures in `data/` too; nothing in that directory is committed.

## Test

```bash
pytest -q
```

Tests that need the sample captures skip when they have not been fetched.

## Status

v1 milestones: **M1 done** (vertical slice), **M2 done** (dissection, epoch
profiles, timeline + drilldown GUI). Next: M3 clue features + rule-based
stitcher + global solver. See `PLAN.md`.
