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
capture → dissect → address epochs → clue features → matcher → solver → device trails → GUI
```

Load a capture and every temporary address appears on a zoomable timeline,
grouped into device trails, with the evidence behind each link one click away.

## How it stitches

An *epoch* is one address's stretch of packets. For every pair "address A went
quiet, address B appeared shortly after" the matcher weighs six clues:

| Clue | What it checks |
|---|---|
| timing | B was first heard soon after A's last packet, judged against how often the device was being heard at all |
| structure | the advertisement is laid out the same way |
| cadence | the advertising interval is the same |
| signal | signal strength just before and just after matches |
| carryover | payload content survived the change (a name, an AirPlay address, a service-data blob), discounted by how many other devices send the same thing |
| counter | a rolling counter (Apple Handoff, Eddystone-TLM, MiBeacon) continues |

Each clue gives evidence from −1 to +1, multiplied by a fixed weight. A solver
then picks links **jointly** — one successor and one predecessor per address —
so that several devices rotating at the same instant are resolved together
rather than greedily. Links with a close rival are flagged *ambiguous*.

Two refinements came out of real captures:

- **Re-identification.** A device that goes quiet (asleep, out of range) and
  returns later under a new address is still linked if both addresses carry
  the same identifier-grade content that no other address was sending.
- **Sibling trails.** Some devices use two addresses *at once* with identical
  content. Trails on air together, at the same signal strength, sending the
  same such content are grouped into one device (`D3a`, `D3b`).

The score is a ranking aid from fixed rules, **not a calibrated probability**.
Measuring accuracy needs ground truth (the devices' IRKs) and is v2.

## What it reads

- **Containers:** `.pcap` and `.pcapng`, optionally gzip-compressed.
- **Link types:** Nordic nRF Sniffer (DLT 272, protocol versions 1–3),
  `BLUETOOTH_LE_LL_WITH_PHDR` (DLT 256) and bare `BLUETOOTH_LE_LL` (DLT 251,
  which records no channel or signal strength).
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
  features/     per-epoch features, tokens, counters, the pairwise clues
  link/         rule-based matcher (heuristic.py), global solver (solver.py),
                concurrent-address grouping (siblings.py)
  results/      structured JSON artifact (engine ↔ GUI seam)
  data/         vendored Bluetooth company / service identifiers (see NOTICE)
  eval/ vault/  (filled in later milestones)
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

- **Timeline:** one row per device trail, one bar per address, coloured by
  address type. A diamond marks each rotation link (hollow when ambiguous).
  Drag to pan, Ctrl/⌘ + scroll (or pinch) to zoom. "Packed rows" and "One row
  per epoch" show the raw epochs instead.
- **Tables:** device trails and address epochs, sortable; rows are
  keyboard-selectable.
- **Detail:** click a *link* for the clues that fired and how much each added;
  a *trail* for its chain of addresses; an *address* for its cadence, RSSI,
  PDU mix, every distinct payload (decoded, with changed bytes highlighted)
  and its packets.

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
profiles, timeline + drilldown GUI), **M3 done** (clue features, rule-based
matcher, global solver, trails + link drilldown). Next: M4 scale and run
controls. See `PLAN.md`.
