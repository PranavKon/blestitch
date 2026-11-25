import React from "react";

import { fmtDuration, fmtOffset, fmtScore } from "./format.js";
import { TYPE_BY_KEY } from "./types.js";

// One device trail as a chain: each address it used, and the link that joins
// each one to the next.
export default function TrackDetail({ track, tracks, siblings, epochs, links, tMin, onSelect }) {
  const linkInto = new Map(links.filter((l) => l.track_id === track.id).map((l) => [l.b, l]));
  const type = TYPE_BY_KEY[track.addr_type];
  // Other trails of the same device, with the direct evidence where there is any.
  const direct = new Map();
  for (const s of siblings) {
    if (s.track_a === track.id) direct.set(s.track_b, s.detail);
    if (s.track_b === track.id) direct.set(s.track_a, s.detail);
  }
  const related = tracks
    .filter((t) => t.device_id === track.device_id && t.id !== track.id)
    .map((other) => ({
      other,
      detail: direct.get(other.id) ?? "linked through another trail of this device",
    }));
  return (
    <section className="panel detail">
      <div className="panel-head">
        <h2>Trail {track.name}</h2>
        <span className={`tag tag-${track.addr_type}`}>{type?.label ?? track.addr_type}</span>
      </div>
      {track.label && <p className="detail-label">{track.label}</p>}

      <dl className="facts">
        <dt>Seen</dt>
        <dd>
          {fmtOffset(track.t_start_us - tMin)} to {fmtOffset(track.t_end_us - tMin)}
          <span className="muted"> · {fmtDuration(track.t_end_us - track.t_start_us)}</span>
        </dd>
        <dt>Addresses</dt>
        <dd>
          {track.n_addresses}
          <span className="muted">
            {" "}· {track.n_rotations} {track.n_rotations === 1 ? "rotation" : "rotations"} linked
          </span>
        </dd>
        <dt>Packets</dt>
        <dd>{track.n_packets.toLocaleString()}</dd>
        <dt>Weakest link</dt>
        <dd>
          {track.min_score == null ? "no rotation in this trail" : fmtScore(track.min_score)}
          {track.ambiguous && <span className="flag">ambiguous</span>}
        </dd>
      </dl>

      {related.length > 0 && (
        <>
          <h3>Same device</h3>
          <ul className="siblings">
            {related.map(({ other, detail }) => (
              <li key={other.id}>
                <button className="chip" onClick={() => onSelect({ kind: "track", id: other.id })}>
                  Trail {other.name}
                </button>
                <span className="muted small">{detail}</span>
              </li>
            ))}
          </ul>
          <p className="muted small">
            Two addresses on air together, at the same signal strength, sending identical content
            that nothing else sends: one device using several addresses at once.
          </p>
        </>
      )}

      <h3>Chain</h3>
      <ol className="chain">
        {track.epoch_ids.map((id) => {
          const e = epochs[id];
          const link = linkInto.get(id);
          return (
            <React.Fragment key={id}>
              {link && (
                <li className="chain-link">
                  <button onClick={() => onSelect({ kind: "link", id: link.id })}>
                    {link.kind === "rotation" ? (
                      <>
                        <span className={`chain-mark${link.ambiguous ? " hollow" : ""}`} />
                        rotation after {fmtDuration(Math.max(0, link.gap_us))} · score{" "}
                        {fmtScore(link.score)}
                        {link.ambiguous && <span className="flag">ambiguous</span>}
                      </>
                    ) : (
                      <>same address again after {fmtDuration(link.gap_us)}</>
                    )}
                  </button>
                </li>
              )}
              <li className="chain-epoch">
                <button onClick={() => onSelect({ kind: "epoch", id })}>
                  <span className="mono">{e.address}</span>
                  <span className="muted small">
                    {fmtOffset(e.t_start_us - tMin)} for {fmtDuration(e.duration_us)} ·{" "}
                    {e.n_packets.toLocaleString()} packets
                  </span>
                </button>
              </li>
            </React.Fragment>
          );
        })}
      </ol>
      <p className="muted small">Click an address for its packets, or a link for its evidence.</p>
    </section>
  );
}
