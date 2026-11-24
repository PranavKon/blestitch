import React, { useEffect, useState } from "react";

import { fetchEpochDetail, fetchEpochPackets } from "./api.js";
import { fmtClock, fmtDuration, fmtMs, fmtOffset, hexBytes, trailName } from "./format.js";
import { TYPE_BY_KEY } from "./types.js";

const PACKET_PAGE = 200;

// Everything known about one epoch: its profile, each distinct payload it
// sent (decoded, with the bytes that changed since the previous payload
// marked), and its packets.
export default function EpochDetail({ analysisId, epoch, track, tMin, onSelect }) {
  const [detail, setDetail] = useState(null);
  const [packets, setPackets] = useState(null);
  const [error, setError] = useState(null);
  const [loadingMore, setLoadingMore] = useState(false);

  useEffect(() => {
    const ctl = new AbortController();
    setDetail(null);
    setPackets(null);
    setError(null);
    Promise.all([
      fetchEpochDetail(analysisId, epoch.id, ctl.signal),
      fetchEpochPackets(analysisId, epoch.id, 0, PACKET_PAGE, ctl.signal),
    ])
      .then(([d, p]) => {
        setDetail(d);
        setPackets(p);
      })
      .catch((err) => {
        if (err.name !== "AbortError") setError(err.message);
      });
    return () => ctl.abort();
  }, [analysisId, epoch.id]);

  async function loadMore() {
    setLoadingMore(true);
    try {
      const next = await fetchEpochPackets(analysisId, epoch.id, packets.rows.length, PACKET_PAGE);
      setPackets((p) => ({ ...p, rows: [...p.rows, ...next.rows] }));
    } catch (err) {
      setError(err.message);
    } finally {
      setLoadingMore(false);
    }
  }

  const type = TYPE_BY_KEY[epoch.addr_type];
  const clock = fmtClock(epoch.t_start_us);

  return (
    <section className="panel detail">
      <div className="panel-head">
        <h2 className="mono">{epoch.address}</h2>
        <span className={`tag tag-${epoch.addr_type}`}>{type?.label ?? epoch.addr_type}</span>
        {track && (
          <button className="chip" onClick={() => onSelect({ kind: "track", id: track.id })}>
            Trail {trailName(track.id)}
            {track.n_addresses > 1 && ` · ${track.n_addresses} addresses`}
          </button>
        )}
      </div>
      {epoch.label && <p className="detail-label">{epoch.label}</p>}

      <dl className="facts">
        <Fact label="First seen">
          {fmtOffset(epoch.t_start_us - tMin)}
          {clock && <span className="muted"> · {clock}</span>}
        </Fact>
        <Fact label="Duration">{fmtDuration(epoch.duration_us)}</Fact>
        <Fact label="Packets">
          {epoch.n_packets.toLocaleString()}
          <span className="muted"> in {epoch.n_events.toLocaleString()} advertising events</span>
        </Fact>
        <Fact label="Adv. interval">
          {fmtMs(epoch.adv_interval_ms)}
          {epoch.adv_interval_jitter_ms != null && (
            <span className="muted"> ± {fmtMs(epoch.adv_interval_jitter_ms)} jitter</span>
          )}
        </Fact>
        <Fact label="RSSI">
          {epoch.rssi_mean == null ? (
            "—"
          ) : (
            <>
              {epoch.rssi_mean} dBm
              <span className="muted"> ({epoch.rssi_min} to {epoch.rssi_max})</span>
            </>
          )}
        </Fact>
        <Fact label="Channels">{counts(epoch.channel_counts)}</Fact>
        <Fact label="PDU types">{counts(epoch.pdu_counts)}</Fact>
        <Fact label="Behaviour">
          {[
            epoch.connectable ? "connectable" : "not connectable",
            epoch.scannable ? "scannable" : "not scannable",
          ].join(", ")}
          {(epoch.n_scan_req > 0 || epoch.n_connect_ind > 0) && (
            <span className="muted">
              {" "}· {epoch.n_scan_req} scan requests, {epoch.n_connect_ind} connection requests
            </span>
          )}
        </Fact>
        {epoch.tx_power != null && <Fact label="TX power">{epoch.tx_power} dBm</Fact>}
        {epoch.service_uuids.length > 0 && (
          <Fact label="Services">
            <span className="mono">{epoch.service_uuids.join(", ")}</span>
          </Fact>
        )}
        <Fact label="Payload shape">
          <span className="mono">{epoch.ad_signature || "(empty)"}</span>
          {epoch.n_signatures > 1 && (
            <span className="muted"> · {epoch.n_signatures} shapes seen</span>
          )}
        </Fact>
      </dl>

      {error && <p className="error">Could not load packets: {error}</p>}
      {!detail && !error && <p className="muted">Loading packets…</p>}

      {detail && (
        <>
          <h3>
            Payloads{" "}
            <span className="muted small">
              {detail.n_variants} distinct, in order of first appearance
              {detail.n_variants > detail.variants.length &&
                ` (first ${detail.variants.length} shown)`}
            </span>
          </h3>
          <ol className="variants">
            {detail.variants.map((v, i) => (
              <Variant key={v.index} v={v} prev={detail.variants[i - 1]} tMin={tMin} />
            ))}
          </ol>
        </>
      )}

      {packets && (
        <>
          <h3>
            Packets{" "}
            <span className="muted small">
              {packets.rows.length.toLocaleString()} of {packets.total.toLocaleString()}
            </span>
          </h3>
          <div className="table-scroll short">
            <table className="packets">
              <thead>
                <tr>
                  <th className="num">Time</th>
                  <th className="num">Δ prev</th>
                  <th className="num">Ch</th>
                  <th className="num">RSSI</th>
                  <th>PDU</th>
                  <th>Payload / peer</th>
                </tr>
              </thead>
              <tbody>
                {packets.rows.map((r, i) => (
                  <tr key={i} className={r.from_advertiser ? "" : "interaction"}>
                    <td className="num mono">{fmtOffset(r.t_us - tMin, 4)}</td>
                    <td className="num mono">
                      {i === 0 ? "" : fmtDelta(r.t_us - packets.rows[i - 1].t_us)}
                    </td>
                    <td className="num">{r.channel}</td>
                    <td className="num">{r.rssi ?? "—"}</td>
                    <td>{r.pdu}</td>
                    <td className="mono">
                      {r.from_advertiser ? `#${r.variant + 1}` : `from ${r.peer}`}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {packets.rows.length < packets.total && (
              <button className="more" onClick={loadMore} disabled={loadingMore}>
                {loadingMore ? "Loading…" : `Load ${PACKET_PAGE} more`}
              </button>
            )}
          </div>
        </>
      )}
    </section>
  );
}

function Fact({ label, children }) {
  return (
    <>
      <dt>{label}</dt>
      <dd>{children}</dd>
    </>
  );
}

function counts(obj) {
  return Object.entries(obj)
    .map(([k, n]) => `${k} × ${n.toLocaleString()}`)
    .join(" · ");
}

function fmtDelta(us) {
  if (us < 1000) return `${us} µs`;
  if (us < 1_000_000) return `${(us / 1000).toFixed(2)} ms`;
  return `${(us / 1_000_000).toFixed(3)} s`;
}

function Variant({ v, prev, tMin }) {
  const bytes = hexBytes(v.hex);
  // Mark bytes that differ from the previous payload of the same PDU type and
  // length — that is where rolling counters and rotating tokens show up.
  const prevBytes =
    prev && prev.pdu === v.pdu && prev.hex.length === v.hex.length ? hexBytes(prev.hex) : null;
  return (
    <li>
      <div className="variant-head">
        <span className="variant-n">#{v.index + 1}</span>
        <span>{v.pdu}</span>
        <span className="muted">
          × {v.count.toLocaleString()} · {fmtOffset(v.t_first_us - tMin)}
          {v.t_last_us !== v.t_first_us && ` to ${fmtOffset(v.t_last_us - tMin)}`}
        </span>
      </div>
      {v.fields.length > 0 && (
        <ul className="fields">
          {v.fields.map((f, i) => (
            <li key={i}>
              <span className="field-name">{f.name}</span>
              <span className="field-summary">{f.summary}</span>
              {f.fields.length > 0 && (
                <dl className="subfields">
                  {f.fields.map(([k, val], j) => (
                    <React.Fragment key={j}>
                      <dt>{k}</dt>
                      <dd className="mono">{val}</dd>
                    </React.Fragment>
                  ))}
                </dl>
              )}
            </li>
          ))}
        </ul>
      )}
      <div className="hex mono" aria-label="Raw payload bytes">
        {bytes.length === 0 && <span className="muted">(no advertising data)</span>}
        {bytes.map((b, i) => (
          <span key={i} className={prevBytes && prevBytes[i] !== b ? "changed" : ""}>
            {b}
          </span>
        ))}
      </div>
      {prevBytes && <p className="muted small">Highlighted bytes changed since #{v.index}.</p>}
    </li>
  );
}
