"""FastAPI backend for the blestitch GUI.

Thin layer over the engine: it accepts a BLE capture upload, runs the v1
pipeline, and returns the results artifact as JSON. All analysis lives in
`blestitch`; this module only moves bytes and shapes HTTP responses.

A finished analysis is kept in memory under an id so the GUI can ask for one
epoch's packets when the user clicks it, instead of receiving every packet up
front. Only the few most recent analyses are kept.

If the GUI has been built (``frontend/dist``), it is served from ``/`` too, so
one process is the whole app: ``scripts/run.sh``. For work on the code, run
the backend and the Vite dev server side by side: ``scripts/dev.sh``.
"""

from __future__ import annotations

import threading
import uuid
from collections import OrderedDict
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from blestitch.dissect.epoch import DEFAULT_MAX_GAP_US
from blestitch.io.pcap_reader import PcapFormatError
from blestitch.pipeline import Analysis, analyze_bytes
from blestitch.results.artifact import epoch_detail, packet_rows

app = FastAPI(title="blestitch", version="0.3.0")

# The React dev server (Vite) runs on a different port; allow it in dev.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)

MAX_STORED_ANALYSES = 4

_store: OrderedDict[str, Analysis] = OrderedDict()
_store_lock = threading.Lock()


def _remember(analysis: Analysis) -> str:
    analysis_id = uuid.uuid4().hex
    with _store_lock:
        _store[analysis_id] = analysis
        while len(_store) > MAX_STORED_ANALYSES:
            _store.popitem(last=False)
    return analysis_id


def _epoch(analysis_id: str, epoch_id: int):
    with _store_lock:
        analysis = _store.get(analysis_id)
        if analysis is not None:
            _store.move_to_end(analysis_id)
    if analysis is None:
        raise HTTPException(
            status_code=404,
            detail="analysis not found (it may have expired); load the capture again",
        )
    if not 0 <= epoch_id < len(analysis.epochs):
        raise HTTPException(status_code=404, detail="no such epoch")
    return analysis.epochs[epoch_id], analysis.profiles[epoch_id]


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "version": app.version}


@app.post("/api/analyze")
async def analyze(
    file: Annotated[UploadFile, File()],
    max_gap_s: Annotated[
        float,
        Query(gt=0, description="Silence (seconds) that splits one address into two epochs."),
    ] = DEFAULT_MAX_GAP_US / 1e6,
) -> dict:
    """Analyze an uploaded BLE capture and return the results artifact."""
    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail="empty file")
    try:
        analysis = analyze_bytes(
            data,
            source=f"pcap:{file.filename}",
            max_gap_us=int(max_gap_s * 1e6),
        )
    except PcapFormatError as exc:
        raise HTTPException(status_code=400, detail=f"unreadable capture: {exc}")

    return {
        "analysis_id": _remember(analysis),
        "filename": file.filename,
        **analysis.result.to_dict(),
    }


@app.get("/api/analyses/{analysis_id}/epochs/{epoch_id}")
def get_epoch(analysis_id: str, epoch_id: int) -> dict:
    """Decoded payload variants for one epoch."""
    epoch, profile = _epoch(analysis_id, epoch_id)
    return epoch_detail(epoch, profile)


@app.get("/api/analyses/{analysis_id}/epochs/{epoch_id}/packets")
def get_epoch_packets(
    analysis_id: str,
    epoch_id: int,
    offset: int = Query(0, ge=0),
    limit: int = Query(500, ge=1, le=5000),
) -> dict:
    """A page of one epoch's packets, in time order."""
    epoch, profile = _epoch(analysis_id, epoch_id)
    return packet_rows(epoch, profile, offset=offset, limit=limit)


GUI_DIR = Path(__file__).resolve().parent.parent / "frontend" / "dist"


def mount_gui(target: FastAPI, directory: Path = GUI_DIR) -> bool:
    """Serve the built GUI from ``/`` if it has been built. Mounted last, so
    the ``/api`` routes above always win."""
    if not (directory / "index.html").is_file():
        return False
    target.mount("/", StaticFiles(directory=directory, html=True), name="gui")
    return True


mount_gui(app)
