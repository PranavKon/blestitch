import React, { useMemo, useState } from "react";

import { analyzeFile } from "./api.js";
import EpochDetail from "./EpochDetail.jsx";
import EpochTable from "./EpochTable.jsx";
import { fmtClock, fmtDuration, fmtInt } from "./format.js";
import Timeline from "./Timeline.jsx";
import { ADDR_TYPES } from "./types.js";

export default function App() {
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);
  const [fileName, setFileName] = useState(null);
  const [selectedId, setSelectedId] = useState(null);
  const [query, setQuery] = useState("");
  const [hiddenTypes, setHiddenTypes] = useState(() => new Set());
  const [minPackets, setMinPackets] = useState(1);
  const [dragging, setDragging] = useState(false);

  async function load(file) {
    if (!file) return;
    setFileName(file.name);
    setLoading(true);
    setError(null);
    try {
      const next = await analyzeFile(file);
      setResult(next);
      setSelectedId(null);
      setQuery("");
      setHiddenTypes(new Set());
      setMinPackets(1);
    } catch (err) {
      setError(err.message);
      setResult(null);
    } finally {
      setLoading(false);
    }
  }

  const epochs = useMemo(() => {
    if (!result) return [];
    const q = query.trim().toLowerCase();
    return result.epochs.filter(
      (e) =>
        !hiddenTypes.has(e.addr_type) &&
        e.n_packets >= minPackets &&
        (!q || e.address.includes(q) || e.label.toLowerCase().includes(q)),
    );
  }, [result, query, hiddenTypes, minPackets]);

  const selected = result?.epochs.find((e) => e.id === selectedId) ?? null;

  function toggleType(key) {
    setHiddenTypes((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }

  return (
    <div className="app">
      <header className="top">
        <div>
          <h1>blestitch</h1>
          <p className="sub">BLE address-rotation stitcher — address epochs</p>
        </div>
        <label
          className={`upload${dragging ? " dragging" : ""}`}
          onDragOver={(ev) => {
            ev.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={(ev) => {
            ev.preventDefault();
            setDragging(false);
            load(ev.dataTransfer.files?.[0]);
          }}
        >
          <input
            type="file"
            accept=".pcap,.pcapng,.gz"
            onChange={(ev) => {
              load(ev.target.files?.[0]);
              ev.target.value = "";
            }}
          />
          <span>
            {loading
              ? `Analyzing ${fileName}…`
              : fileName && result
                ? `${fileName} — choose or drop another capture`
                : "Choose or drop a BLE capture (.pcap, .pcapng)"}
          </span>
        </label>
      </header>

      {error && <p className="error" role="alert">Could not analyze {fileName}: {error}</p>}

      {result && (
        <div className={loading ? "stale" : ""}>
          <Summary result={result} />

          <div className="filters">
            <input
              type="search"
              placeholder="Filter by address, vendor or name"
              value={query}
              onChange={(ev) => setQuery(ev.target.value)}
              aria-label="Filter epochs"
            />
            <div className="legend" role="group" aria-label="Address types">
              {ADDR_TYPES.filter((t) => result.addr_type_counts[t.key]).map((t) => (
                <button
                  key={t.key}
                  className={hiddenTypes.has(t.key) ? "off" : ""}
                  aria-pressed={!hiddenTypes.has(t.key)}
                  title={`${t.hint} — click to ${hiddenTypes.has(t.key) ? "show" : "hide"}`}
                  onClick={() => toggleType(t.key)}
                >
                  <span className="swatch" style={{ background: t.color }} />
                  {t.label}
                  <span className="muted">{result.addr_type_counts[t.key]}</span>
                </button>
              ))}
            </div>
            <label className="min-packets">
              Min packets
              <input
                type="number"
                min="1"
                value={minPackets}
                onChange={(ev) => setMinPackets(Math.max(1, Number(ev.target.value) || 1))}
              />
            </label>
          </div>

          <Timeline
            epochs={epochs}
            tMin={result.t_min_us}
            tMax={result.t_max_us}
            selectedId={selectedId}
            onSelect={setSelectedId}
          />

          <div className="split">
            <EpochTable
              epochs={epochs}
              tMin={result.t_min_us}
              selectedId={selectedId}
              onSelect={setSelectedId}
            />
            {selected ? (
              <EpochDetail
                key={`${result.analysis_id}:${selected.id}`}
                analysisId={result.analysis_id}
                epoch={selected}
                tMin={result.t_min_us}
              />
            ) : (
              <section className="panel detail empty">
                <p className="muted">
                  Select an epoch on the timeline or in the table to see its profile, payloads and
                  packets.
                </p>
              </section>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function Summary({ result }) {
  const c = result.capture;
  const started = fmtClock(result.t_min_us);
  const dropped = [
    c.n_bad_crc && `${fmtInt(c.n_bad_crc)} failed CRC`,
    c.n_data_channel && `${fmtInt(c.n_data_channel)} connection-data packets`,
    c.n_unattributed && `${fmtInt(c.n_unattributed)} extended adverts without an address`,
    c.n_malformed && `${fmtInt(c.n_malformed)} malformed`,
    c.n_unsupported_link && `${fmtInt(c.n_unsupported_link)} on other link types`,
  ].filter(Boolean);
  return (
    <>
      <section className="summary">
        <Stat label="Address epochs" value={fmtInt(result.n_epochs)} />
        <Stat label="Advertising packets" value={fmtInt(result.n_packets)} />
        <Stat label="Capture length" value={fmtDuration(result.t_max_us - result.t_min_us)} />
        <Stat label="Records in file" value={fmtInt(c.n_records)} />
      </section>
      <p className="capture-note muted small">
        {c.link_types.join(", ")} ·{" "}
        {c.time_source === "firmware"
          ? "timed by the sniffer's hardware clock"
          : "timed by capture-file timestamps"}
        {started && ` · started ${started}`}
        {dropped.length > 0 && ` · not used: ${dropped.join(", ")}`}
      </p>
    </>
  );
}

function Stat({ label, value }) {
  return (
    <div className="stat">
      <div className="stat-value">{value}</div>
      <div className="stat-label">{label}</div>
    </div>
  );
}
