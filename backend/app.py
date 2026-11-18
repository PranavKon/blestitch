"""FastAPI backend for the blestitch GUI.

Thin layer over the engine: it accepts a BLE PCAP upload, runs the v1 pipeline,
and returns the results artifact as JSON. All analysis lives in `blestitch`;
this module only moves bytes and shapes HTTP responses.

Run locally:  uvicorn backend.app:app --reload
"""

from __future__ import annotations

import os
import tempfile

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from blestitch.io.pcap_reader import PcapFormatError
from blestitch.pipeline import analyze_pcap

app = FastAPI(title="blestitch", version="0.1.0")

# The React dev server (Vite) runs on a different port; allow it in dev.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health() -> dict:
    return {"status": "ok", "version": app.version}


@app.post("/api/analyze")
async def analyze(file: UploadFile = File(...)) -> dict:
    """Analyze an uploaded BLE PCAP and return the results artifact."""
    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail="empty file")

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            tmp.write(data)
            tmp_path = tmp.name
        result = analyze_pcap(tmp_path)
    except PcapFormatError as exc:
        raise HTTPException(status_code=400, detail=f"unreadable capture: {exc}")
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)

    return {"filename": file.filename, **result.to_dict()}
