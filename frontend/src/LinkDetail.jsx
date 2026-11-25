import React from "react";

import { fmtDuration, fmtOffset, fmtScore } from "./format.js";

// A gap this long is a device returning, not an address simply rotating.
const LONG_GAP_US = 30_000_000;

// Why two addresses were joined: every clue the matcher weighed, how hard it
// pushed and in which direction.
export default function LinkDetail({ link, track, epochs, tMin, acceptTotal, onSelect }) {
  const [a, b] = [epochs[link.a], epochs[link.b]];
  const clues = [...link.clues].sort((x, y) => Math.abs(y.contribution) - Math.abs(x.contribution));
  return (
    <section className="panel detail">
      <div className="panel-head">
        <h2>{link.kind === "rotation" ? "Rotation link" : "Same address seen again"}</h2>
        <button className="chip" onClick={() => onSelect({ kind: "track", id: link.track_id })}>
          Trail {track.name}
        </button>
      </div>

      <div className="seam">
        <EpochButton epoch={a} onSelect={onSelect} note={`last heard ${fmtOffset(a.t_end_us - tMin)}`} />
        <span className="seam-arrow" aria-hidden="true">→</span>
        <EpochButton epoch={b} onSelect={onSelect} note={`first heard ${fmtOffset(b.t_start_us - tMin)}`} />
      </div>

      {link.kind === "same_address" ? (
        <p>
          The same address was heard again after {fmtDuration(link.gap_us)} of silence, so this is
          the same device by definition. No clues are needed.
        </p>
      ) : (
        <>
          <dl className="facts">
            <dt>Score</dt>
            <dd>
              {fmtScore(link.score)}
              <span className="muted"> · accepted above 0.50</span>
            </dd>
            <dt>Gap</dt>
            <dd>
              {fmtDuration(Math.max(0, link.gap_us))}
              {link.gap_us > LONG_GAP_US && (
                <span className="muted">
                  {" "}· the device went quiet and came back; linked by what it kept sending
                </span>
              )}
            </dd>
            <dt>Rivals</dt>
            <dd>
              {link.margin == null
                ? "none: no other address could have been the successor or predecessor"
                : link.ambiguous
                  ? `ambiguous: the best rival pairing scored ${rival(link.margin)}`
                  : `clear: the best rival pairing scored ${rival(link.margin)}`}
            </dd>
          </dl>
          {link.ambiguous && (
            <p className="warn-note">
              <strong>Ambiguous.</strong> Another address fits about as well. The solver picked the
              combination that scores best overall, but treat this link as a guess.
            </p>
          )}

          <h3>Clues <span className="muted small">strongest first</span></h3>
          <table className="clues">
            <thead>
              <tr>
                <th>Clue</th>
                <th>Evidence</th>
                <th className="num">Weight</th>
                <th className="num">Adds</th>
              </tr>
            </thead>
            <tbody>
              {clues.map((c) => (
                <React.Fragment key={c.name}>
                  <tr>
                    <td className="clue-name">{c.name}</td>
                    <td>
                      <EvidenceBar value={c.evidence} />
                    </td>
                    <td className="num">× {c.weight}</td>
                    <td className="num">{signed(c.contribution)}</td>
                  </tr>
                  <tr className="clue-detail">
                    <td colSpan={4}>{c.detail}</td>
                  </tr>
                </React.Fragment>
              ))}
              <tr className="clue-total">
                <td colSpan={3}>Total (accepted at {acceptTotal.toFixed(2)} or more)</td>
                <td className="num">{link.total.toFixed(2)}</td>
              </tr>
            </tbody>
          </table>
          <p className="muted small">
            Evidence runs from −1 (contradicts “same device”) to +1 (supports it). The score is a
            ranking aid from fixed rules, not a measured probability.
          </p>
        </>
      )}
    </section>
  );
}

function rival(margin) {
  const by = Math.abs(margin).toFixed(2);
  return margin >= 0 ? `${by} lower` : `${by} higher on its own`;
}

function signed(x) {
  return `${x >= 0 ? "+" : "−"}${Math.abs(x).toFixed(2)}`;
}

function EpochButton({ epoch, note, onSelect }) {
  return (
    <button className="seam-epoch" onClick={() => onSelect({ kind: "epoch", id: epoch.id })}>
      <span className="mono">{epoch.address}</span>
      <span className="muted small">{note}</span>
    </button>
  );
}

// A bar growing right of centre for support, left for contradiction; the
// number beside it carries the same information as text.
function EvidenceBar({ value }) {
  const pct = Math.min(1, Math.abs(value)) * 50;
  return (
    <span className="evidence">
      <span className="evidence-track" aria-hidden="true">
        <span
          className={`evidence-fill ${value >= 0 ? "pos" : "neg"}`}
          style={value >= 0 ? { left: "50%", width: `${pct}%` } : { right: "50%", width: `${pct}%` }}
        />
      </span>
      <span className="evidence-num">{signed(value)}</span>
    </span>
  );
}
