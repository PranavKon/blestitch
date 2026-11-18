# blestitch

Passive BLE **address-rotation stitcher**. BLE devices rotate their advertising
address (~every 15 min) to resist tracking; blestitch links those temporary
addresses back into continuous per-device timelines from a passive radio
capture, and shows the result in a web GUI.

> **Scope:** built for a **controlled environment with consenting
> participants/devices**. Accuracy grading and a calibrated confidence meter
> (which require the devices' IRKs) are **v2**; see `PLAN.md`.

## v1 (this milestone)

A **rule-based** stitcher — no training data, no answer keys. The pipeline:

```
PCAP → dissect → address epochs → (M3: stitch into device trails) → GUI
```

M1 proves the engine → results → GUI seam end to end: load a capture, parse it,
group packets into address epochs, and view them in the browser.

## Layout

```
blestitch/      pure-Python engine (no UI deps)
  io/           PCAP reader (DLT 256 / Nordic 272), LabeledTrace data seam
  dissect/      PDU + AD parsing, epoch segmentation
  results/      structured JSON artifact (engine ↔ GUI seam)
  link/ features/ eval/ vault/   (filled in later milestones)
backend/        FastAPI (serves the engine to the GUI)
frontend/       React + Vite GUI
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

Open the frontend, choose a BLE `.pcap`, and you'll see the address epochs. The
dev server proxies `/api/*` to the backend automatically.

## Test

```bash
pytest -q
```

## Status

v1 milestones: **M1 done** (vertical slice). Next: M2 richer dissection/timeline,
M3 clue features + rule-based stitcher + global solver. See `PLAN.md`.
