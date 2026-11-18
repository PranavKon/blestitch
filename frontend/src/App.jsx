import React, { useState } from "react";

const US_PER_S = 1_000_000;

function fmtDuration(us) {
  const s = us / US_PER_S;
  if (s < 1) return `${us} µs`;
  if (s < 60) return `${s.toFixed(1)} s`;
  return `${(s / 60).toFixed(1)} min`;
}

export default function App() {
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);
  const [fileName, setFileName] = useState(null);

  async function onFile(e) {
    const file = e.target.files?.[0];
    if (!file) return;
    setFileName(file.name);
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const body = new FormData();
      body.append("file", file);
      const resp = await fetch("/api/analyze", { method: "POST", body });
      if (!resp.ok) {
        const detail = await resp.json().catch(() => ({}));
        throw new Error(detail.detail || `HTTP ${resp.status}`);
      }
      setResult(await resp.json());
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="app">
      <header>
        <h1>blestitch</h1>
        <p className="sub">BLE address-rotation stitcher — v1 (epochs)</p>
      </header>

      <label className="upload">
        <input type="file" accept=".pcap,.pcapng" onChange={onFile} />
        <span>{fileName ? `Loaded: ${fileName}` : "Choose a BLE PCAP capture…"}</span>
      </label>

      {loading && <p className="muted">Analyzing…</p>}
      {error && <p className="error">Error: {error}</p>}

      {result && (
        <>
          <section className="summary">
            <Stat label="Packets" value={result.n_packets} />
            <Stat label="Address epochs" value={result.n_epochs} />
            {Object.entries(result.addr_type_counts).map(([k, v]) => (
              <Stat key={k} label={k} value={v} />
            ))}
          </section>

          <table className="epochs">
            <thead>
              <tr>
                <th>Address</th>
                <th>Type</th>
                <th>Start (µs)</th>
                <th>Duration</th>
                <th>Packets</th>
                <th>Channels</th>
                <th>RSSI (mean)</th>
              </tr>
            </thead>
            <tbody>
              {result.epochs.map((e, i) => (
                <tr key={i}>
                  <td className="mono">{e.address}</td>
                  <td>
                    <span className={`tag tag-${e.addr_type}`}>{e.addr_type}</span>
                  </td>
                  <td className="mono">{e.t_start_us.toLocaleString()}</td>
                  <td>{fmtDuration(e.duration_us)}</td>
                  <td>{e.n_packets}</td>
                  <td className="mono">{e.channels.join(", ")}</td>
                  <td>{e.rssi_mean} dBm</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </div>
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
