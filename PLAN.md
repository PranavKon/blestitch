# BLE Address-Rotation Linking Engine — Build Plan (v1.3)

> Status: **M1–M3 done (first working stitch); M4 (scale + run controls) is next.**
> Repo and package: `blestitch/`. Scope split in §0.5.

---

## 0. Mission & scope

**Mission:** an operational tool that stitches randomized BLE identities back into continuous
per-device timelines across address rotations, with a **GUI** to run captures and inspect the
stitched results.

**Scope:** a **controlled environment with consenting participants/devices** (confirmed). Measuring
*how well* it links — accuracy + a trustworthy confidence meter — is **v2**, and needs the IRK
answer key (§0.5).

**Non-goals:** no fake-data generator; no use outside the controlled, consented set.

---

## 0.5 Scope: v1 (stitcher) vs v2 (confidence meter + measurement)

**v1 — rule-based stitcher. No training data, no SimBle, no Docker, no IRKs.**
- Ingest nRF Sniffer PCAP (+ public sample PCAPs for dev).
- Dissect packets → group into address epochs.
- Extract the clue features: rolling-counter continuity, payload-token carryover, structural/cadence
  match. (Clock-skew clue joins when the hardware arrives.)
- **Rule-based matcher** scores candidate handoffs from the clues directly — no model to train.
- Global **time-windowed solver** → stitched device trails, incl. crowded "elevator" moments.
- GUI: load a capture, run the stitcher, explore trails, click a link to see which clues fired.

**v2 — confidence meter + measurement (needs IRKs + real labeled data).**
- IRK labeling protocol + `ah()` ground-truth resolver.
- Grade the stitcher (precision/recall/F1, full-track continuity, false-merge rate).
- **ML matcher trained on real IRK-labeled captures** (learns counter/carryover/skew from reality —
  which is why it belongs here, not v1); calibrated into an honest confidence meter.
- Performance envelope (accuracy vs. density, rotation interval, loss, length) + signal ablation.
- GUI: ground-truth overlay, confidence coloring, metrics dashboard.

**Dropped / optional:** SimBle + NS-3 + Docker are no longer on the path. The ML's weights are
learned from real data in v2 and shipped as a model file; SimBle would only ever be an optional
side experiment, never a runtime dependency.

**Hardware-gated (slots in when the nRF52840 arrives):** clock-skew clue; real IRK self-captures;
cross-session re-ID (vault).

---

## 1. Deliverable & stack

**Deliverable:** a **local web app** — a pure-Python engine (importable library) with a React
browser GUI on top, built **alongside** the engine. Cross-platform; runs on macOS/Windows/Linux.

| Layer | Choice | Why |
|---|---|---|
| Language | **Python 3.11+** | Reference literature + libs. |
| Engine | pure library (no UI deps) | Testable core; GUI is a consumer. |
| Packet parsing | `scapy` BLE + custom nRF dissector | nRF Sniffer PCAP (DLT 256) carries RSSI/channel/hw-timestamp. |
| Numerics | `numpy`, `scipy` (`linear_sum_assignment`) | Solver + (later) clock-skew regression. |
| ML (v2) | `scikit-learn`, model shipped as a file | Trained on real labeled data; no training deps at runtime. |
| Vault (later) | **SQLite** | Cross-session device profiles. |
| Results artifact | **JSON + Parquet** | Seam between engine and GUI. |
| Backend | **FastAPI** + `uvicorn`, WebSocket progress | Serves engine + results to the GUI. |
| Frontend | **React + Vite + canvas/D3** | Timeline/Gantt on a virtualized canvas with D3 scales/zoom (chosen over Plotly at M2: no Gantt/WebGL bar trace, large bundle), packet view. Two-language monorepo. |
| Packaging | `pyproject.toml`, `ruff`, `pytest` | Clean, testable. |

**Pattern:** `engine (pure) → results artifact → FastAPI → React GUI`. Engine runs/tests headless.

---

## 1.5 Data strategy

| Source | Role |
|---|---|
| **nRF Sniffer PCAP** (your hardware) | Real captures to stitch (v1) and, with IRKs, to train/grade (v2). |
| **Nordic/Sniffle/CRAWDAD/Mendeley sample PCAPs** | Validate reader/dissector + realistic background now. |
| **Self-capture, IRK-known** (post-hardware) | v2 real labeled training + grading data. |
| **"Learning to Link"** (arXiv 2609.26079) | Optional v2 real-data upgrade — request from authors. |

v1 needs no labeled data (rule-based). v2's ML learns from real IRK-labeled captures. A
`LabeledTrace` interface keeps data sources interchangeable.

---

## 2. Module layout

```
blestitch/
  io/            pcap_reader.py, labeled_trace.py
  dissect/       pdu.py, ad.py, continuity.py, vendors.py, epoch.py, profile.py
  features/      summary.py, tokens.py, counters.py, pairwise.py (the clues), clock_skew.py (hw, later)
  link/          heuristic.py (v1 matcher), solver.py (joint assignment), model.py (v2 ML)
  eval/          irk_resolve.py, metrics.py            # v2
  vault/         store.py                              # later
  results/       artifact.py (JSON/Parquet — GUI seam)
backend/         app.py (FastAPI), routes, ws progress
frontend/        React+Vite GUI
```

Records: `Packet`, `AddressEpoch`, `CandidatePair`, `FeatureVector`, `DeviceTrack`, `AnalysisResult`.

---

## 3. Build order

**v1 — stitcher**
1. **M1 — vertical slice.** Records + `Packet`/`LabeledTrace` + nRF PCAP reader + minimal FastAPI +
   React shell that loads a PCAP and shows packets/epochs. Proves engine→artifact→GUI end to end.
2. **M2 — dissection + epoch segmentation + GUI epoch/timeline panel.**
3. **M3 — clue features (counter, carryover, structural) + rule-based matcher + global solver;
   GUI shows stitched trails + link drilldown.** First working stitch.
4. **M4 — scale + polish:** time-windowed solver for 100+ devices, WebGL timeline, run controls
   (load, re-run, adjust rotation window/thresholds).

**v2 — confidence meter + measurement**
5. **M5 — IRK labeling protocol + `ah()` resolver + grading harness.**
6. **M6 — ML matcher trained on real labeled captures; calibrate → confidence meter; GUI overlay +
   confidence coloring + metrics dashboard.**
7. **M7 — performance-envelope sweeps + signal ablation.**

**Hardware-gated:** clock-skew clue; real self-captures; cross-session re-ID (vault).

Every milestone: tests green + a working GUI state.

**M2 as built.** Reader: pcapng + gzip, Nordic DLT 272 layout validated against a real nRF Sniffer
capture, hardware-clock timing, CRC filtering. Dissection: all legacy PDUs, SCAN_REQ/CONNECT_IND
attached to their target epoch, generic AD decode, Apple Continuity and tracker/beacon decoders.
Epoch profile (the M3 clue inputs): advertising interval + jitter, PDU/channel mix, payload shape,
ordered payload variants, vendor/name/services. GUI: canvas timeline, epoch table, epoch detail.
**Deferred from M2:** following extended-advertising AUX chains (only PDUs that carry the
advertiser address are attributed); a GUI control for the epoch-split gap (API parameter only).

**M3 as built.** Six clues (timing, structure, cadence, signal, carryover, counter) each give
evidence in −1…+1; `link/heuristic.py` weighs and sums them with a fixed accept line.
`link/solver.py` merges epochs that share an address, scores every allowed handoff, splits the
candidates into independent groups and solves each exactly (Hungarian), one successor and one
predecessor per address. Links with a close rival are flagged ambiguous. GUI: trail rows with link
markers, trail table, link drilldown showing each clue's contribution.

**Learned from the first real household capture (nRF Sniffer, protocol v3):**
- Trackers near their owner rotated **all at the same instant**, so the joint solver is needed in
  ordinary homes, not only in crowds. Signal strength and payload layout separated them.
- Devices **restart their advertising train at rotation**: the new address does not continue the old
  timing grid, so "phase continuity" is not a usable clue. The interval itself is stable.
- **One device can advertise under several addresses at once** (seen: two addresses with identical
  payloads changing at identical moments, rotating together). Trails are per *address chain*.
- Weak devices are heard on one channel and rarely; the interval estimator had to find the
  fundamental period under heavy loss, and the timing clue is judged against how often a device is
  actually heard.
- A second, 27-minute household capture (191 epochs) added: a **sleeping device that wakes for about
  five seconds at a time, under fresh addresses each time**; tracker rotations landing exactly on
  quarter-hour wall-clock marks; and concurrent twins on most Apple computers/TVs. In response:
  re-identification across long silences by identifier-grade content, and sibling grouping of
  trails that send the same such content at once (`link/siblings.py`). Ambiguous links fell from
  77 to 16 of ~100; 191 epochs became 50 trails in 38 estimated devices.
  **Still open:** addresses of one device that share *no* content (e.g. its AirPlay address and its
  Nearby Info addresses) are only related by being born and dying together. That is not used,
  because devices that all rotate on the same wall-clock mark look the same; so the device count is
  still an overestimate.
- The weights and thresholds are judgement calls checked against two captures and the fixtures. They
  are not validated; that is what v2's ground truth is for.

---

## 4. GUI panels

**v1:** timeline/Gantt of stitched trails (WebGL, zoom/pan, 100+ tracks); link drilldown (which
clues fired); packet dissector; run controls.
**v2:** ground-truth overlay; confidence coloring; metrics dashboard; sweep/ablation views.

---

## 5. Status

Resolved: Python engine + React/Vite web GUI (canvas + D3 timeline), built alongside · offline v1 · nRF Sniffer
PCAP/pcapng only · **v1 = rule-based stitcher (no SimBle/Docker/ML/IRKs)** · **v2 = IRKs + ML on real data
+ confidence meter + accuracy** · large scale (100+, windowed solver, WebGL timeline) · clock-skew,
self-capture & vault gated on hardware · host macOS/Windows/Pi, dev in this cloud session, delivered
via GitHub.

Minor open assumption (non-blocking): v2 participant set is fixed & known (all IRKs held).
```
