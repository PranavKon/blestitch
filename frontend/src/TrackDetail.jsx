import React from "react";

import { fmtDuration, fmtOffset, fmtScore, trailName } from "./format.js";
import { TYPE_BY_KEY } from "./types.js";

// One device trail as a chain: each address it used, and the link that joins
// each one to the next.
export default function TrackDetail({ track, epochs, links, tMin, onSelect }) {
  const linkInto = new Map(links.filter((l) => l.track_id === track.id).map((l) => [l.b, l]));
  const type = TYPE_BY_KEY[track.addr_type];
  return (
    <section className="panel detail">
      <div className="panel-head">
        <h2>Trail {trailName(track.id)}</h2>
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
