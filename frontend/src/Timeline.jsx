import React, { useEffect, useMemo, useRef, useState } from "react";
import { scaleLinear } from "d3-scale";
import { select } from "d3-selection";
import { zoom, zoomIdentity } from "d3-zoom";

import {
  US_PER_S,
  fmtDuration,
  fmtMs,
  fmtOffset,
  fmtScore,
  fmtTick,
  timeTicks,
} from "./format.js";
import { oneLaneEach, packLanes, trailLanes } from "./lanes.js";
import { TYPE_BY_KEY, typeColor } from "./types.js";

const ROW_H = 22;
const BAR_H = 14;
const AXIS_H = 28;
const PAD_X = 14;
const GUTTER_W = 46; // trail names, in trail mode only
const MIN_BAR_W = 3;
const MAX_VIEW_H = 460;
const LABEL_MIN_W = 64;
const MARKER_R = 5;
const MARKER_HIT = 9;

const INK = "#e6edf3";
const MUTED = "#8b98a5";
const GRID = "#222c38";
const SURFACE = "#141b23";
const BAR_TEXT = "#0b0f14";
const WARNING = "#fab219";
const ACCENT = "#4aa8ff";

const MODES = [
  { key: "trails", label: "Device trails" },
  { key: "packed", label: "Packed rows" },
  { key: "each", label: "One row per epoch" },
];

// Epochs as bars on a shared time axis. In trail mode each row is one
// stitched device and the links between its addresses are marked on the row.
// The canvas only draws what is in view, so the row count is not limited by
// canvas size.
export default function Timeline({ epochs, tracks, links, tMin, tMax, selection, onSelect }) {
  const wrapRef = useRef(null);
  const scrollRef = useRef(null);
  const canvasRef = useRef(null);
  const zoomRef = useRef(null);
  const [mode, setMode] = useState("trails");
  const [width, setWidth] = useState(900);
  const [scrollTop, setScrollTop] = useState(0);
  const [transform, setTransform] = useState(zoomIdentity);
  const [hover, setHover] = useState(null); // { kind, item, x, y }

  const spanUs = Math.max(1, tMax - tMin);
  const spanS = spanUs / US_PER_S;
  const trailMode = mode === "trails";
  const left = PAD_X + (trailMode ? GUTTER_W : 0);

  // Each lane: { trackId (trail mode only), epochs: [...] }.
  const lanes = useMemo(() => {
    if (mode === "trails") return trailLanes(epochs, tracks);
    const rows = mode === "packed" ? packLanes(epochs, spanUs * 0.004) : oneLaneEach(epochs);
    return rows.map((row) => ({ trackId: null, epochs: row }));
  }, [epochs, tracks, mode, spanUs]);

  // Links drawn on each lane: those whose two epochs are both visible.
  const laneLinks = useMemo(() => {
    if (!trailMode) return [];
    const visible = new Map(epochs.map((e) => [e.id, e]));
    const laneOfTrack = new Map(lanes.map((lane, i) => [lane.trackId, i]));
    const out = lanes.map(() => []);
    for (const link of links) {
      const [a, b] = [visible.get(link.a), visible.get(link.b)];
      const lane = laneOfTrack.get(link.track_id);
      if (a && b && lane != null) out[lane].push({ link, a, b });
    }
    return out;
  }, [trailMode, epochs, lanes, links]);

  const contentH = AXIS_H + lanes.length * ROW_H + 10;
  const viewH = Math.max(AXIS_H + ROW_H * 3, Math.min(contentH, MAX_VIEW_H));

  const baseScale = useMemo(
    () => scaleLinear().domain([0, spanS]).range([left, Math.max(left + 1, width - PAD_X)]),
    [spanS, width, left],
  );
  const xScale = useMemo(() => transform.rescaleX(baseScale), [transform, baseScale]);

  // Track the container width.
  useEffect(() => {
    const el = scrollRef.current;
    const ro = new ResizeObserver(() => setWidth(el.clientWidth));
    ro.observe(el);
    setWidth(el.clientWidth);
    return () => ro.disconnect();
  }, []);

  // Zoom and pan along time. Plain wheel is left alone so it scrolls the rows
  // (and the page); Ctrl/⌘ + wheel, or a trackpad pinch, zooms.
  useEffect(() => {
    const canvas = select(canvasRef.current);
    const behavior = zoom()
      .scaleExtent([1, Math.max(1, spanS / 0.002)])
      .translateExtent([[left, 0], [width - PAD_X, 0]])
      .extent([[left, 0], [width - PAD_X, viewH]])
      .filter((ev) => (ev.type === "wheel" ? ev.ctrlKey || ev.metaKey : !ev.button))
      // At most ~1.4x per wheel notch; trackpad pinches send many small steps.
      .wheelDelta((ev) => Math.max(-0.5, Math.min(0.5, -ev.deltaY * 0.01)))
      .on("zoom", (ev) => setTransform(ev.transform));
    canvas.call(behavior);
    zoomRef.current = behavior;
    return () => canvas.on(".zoom", null);
  }, [width, viewH, spanS, left]);

  // A new capture, or a different row layout, starts fully zoomed out.
  useEffect(() => {
    if (zoomRef.current) select(canvasRef.current).call(zoomRef.current.transform, zoomIdentity);
    scrollRef.current.scrollTop = 0;
  }, [tMin, tMax, trailMode]);

  function zoomBy(factor) {
    select(canvasRef.current).call(zoomRef.current.scaleBy, factor);
  }
  function zoomFit() {
    select(canvasRef.current).call(zoomRef.current.transform, zoomIdentity);
  }

  // The time range and row of whatever is selected, for "Zoom to selected".
  function selectedExtent() {
    if (!selection) return null;
    const { kind, id } = selection;
    for (let i = 0; i < lanes.length; i++) {
      if (kind === "epoch") {
        const e = lanes[i].epochs.find((x) => x.id === id);
        if (e) return { lane: i, t0: e.t_start_us, t1: e.t_end_us };
      } else if (kind === "track" && lanes[i].trackId === id) {
        const es = lanes[i].epochs;
        return { lane: i, t0: es[0].t_start_us, t1: Math.max(...es.map((e) => e.t_end_us)) };
      } else if (kind === "link") {
        const hit = (laneLinks[i] ?? []).find((x) => x.link.id === id);
        // Show the seam with a little of each side.
        if (hit) {
          const pad = Math.max(hit.link.gap_us * 2, spanUs * 0.01);
          return { lane: i, t0: hit.a.t_end_us - pad, t1: hit.b.t_start_us + pad };
        }
      }
    }
    return null;
  }
  const canZoomToSelected = selectedExtent() != null;

  function zoomToSelected() {
    const ext = selectedExtent();
    if (!ext) return;
    const s0 = (ext.t0 - tMin) / US_PER_S;
    const s1 = Math.max((ext.t1 - tMin) / US_PER_S, s0 + spanS * 1e-4);
    const margin = (s1 - s0) * 0.15;
    // Programmatic transforms are not clamped by d3-zoom, so stay in range here.
    const x0 = baseScale(Math.max(0, s0 - margin));
    const x1 = baseScale(Math.min(spanS, s1 + margin));
    const k = Math.min(zoomRef.current.scaleExtent()[1], (width - PAD_X - left) / (x1 - x0));
    const t = zoomIdentity.translate(left - x0 * k, 0).scale(k);
    select(canvasRef.current).call(zoomRef.current.transform, t);
    const top = ext.lane * ROW_H;
    const el = scrollRef.current;
    if (top < el.scrollTop || top + ROW_H > el.scrollTop + viewH - AXIS_H) {
      el.scrollTop = Math.max(0, top - (viewH - AXIS_H) / 2);
    }
  }

  const tx = (us) => xScale((us - tMin) / US_PER_S);

  // Bar geometry for one epoch at the current zoom.
  function barX(e) {
    const x0 = tx(e.t_start_us);
    return [x0, Math.max(MIN_BAR_W, tx(e.t_end_us) - x0)];
  }
  // Where a link's marker sits: the middle of the seam between its epochs.
  function markerX({ a, b }) {
    const [ax, aw] = barX(a);
    return (ax + aw + Math.max(ax + aw, tx(b.t_start_us))) / 2;
  }

  function hitTest(px, py) {
    if (py < AXIS_H) return null;
    const i = Math.floor((py - AXIS_H + scrollTop) / ROW_H);
    const lane = lanes[i];
    if (!lane) return null;
    if (px < left - MARKER_HIT) {
      // The gutter: a trail's name stands for the whole trail.
      return trailMode ? { kind: "track", item: tracks[lane.trackId] } : null;
    }
    // Link markers sit on top of the bars, so they win.
    let best = null;
    let bestDist = MARKER_HIT;
    for (const entry of laneLinks[i] ?? []) {
      if (entry.link.kind !== "rotation") continue;
      const dist = Math.abs(px - markerX(entry));
      if (dist < bestDist) {
        best = { kind: "link", item: entry.link };
        bestDist = dist;
      }
    }
    if (best) return best;
    bestDist = 4; // forgiving hit area around thin bars
    for (const e of lane.epochs) {
      const [x, w] = barX(e);
      const dist = px < x ? x - px : px > x + w ? px - x - w : 0;
      if (dist < bestDist) {
        best = { kind: "epoch", item: e };
        bestDist = dist;
      }
    }
    return best;
  }

  function pointerPos(ev) {
    const rect = canvasRef.current.getBoundingClientRect();
    return [ev.clientX - rect.left, ev.clientY - rect.top];
  }

  function onPointerMove(ev) {
    const hit = hitTest(...pointerPos(ev));
    const wrap = wrapRef.current.getBoundingClientRect();
    setHover(hit ? { ...hit, x: ev.clientX - wrap.left, y: ev.clientY - wrap.top } : null);
  }

  function onClick(ev) {
    const hit = hitTest(...pointerPos(ev));
    if (hit) onSelect({ kind: hit.kind, id: hit.item.id });
  }

  const hoverKey = hover ? `${hover.kind}:${hover.item.id}` : null;
  const selKey = selection ? `${selection.kind}:${selection.id}` : null;

  // Paint.
  useEffect(() => {
    const canvas = canvasRef.current;
    const dpr = window.devicePixelRatio || 1;
    canvas.width = Math.round(width * dpr);
    canvas.height = Math.round(viewH * dpr);
    const ctx = canvas.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, width, viewH);
    const is = (kind, id) => selKey === `${kind}:${id}`;
    const hovered = (kind, id) => hoverKey === `${kind}:${id}`;

    // Time axis and recessive grid.
    const [lo, hi] = xScale.domain();
    const { step, ticks } = timeTicks(Math.max(0, lo), hi, Math.max(2, Math.floor(width / 110)));
    ctx.font = "11px -apple-system, 'Segoe UI', Roboto, sans-serif";
    ctx.textBaseline = "middle";
    ctx.strokeStyle = GRID;
    ctx.lineWidth = 1;
    ctx.fillStyle = MUTED;
    for (const t of ticks) {
      const x = Math.round(xScale(t)) + 0.5;
      if (x < left - 1) continue;
      ctx.beginPath();
      ctx.moveTo(x, AXIS_H - 6);
      ctx.lineTo(x, viewH);
      ctx.stroke();
      const text = fmtTick(t, step);
      if (x + 4 + ctx.measureText(text).width <= width) ctx.fillText(text, x + 4, AXIS_H / 2 - 2);
    }
    ctx.beginPath();
    ctx.moveTo(0, AXIS_H - 0.5);
    ctx.lineTo(width, AXIS_H - 0.5);
    ctx.stroke();

    const first = Math.max(0, Math.floor(scrollTop / ROW_H));
    const last = Math.min(lanes.length - 1, Math.ceil((scrollTop + viewH - AXIS_H) / ROW_H));
    const rowY = (i) => AXIS_H + i * ROW_H - scrollTop + (ROW_H - BAR_H) / 2;

    // Bars and links: only rows and epochs that are in view, clipped to the plot.
    ctx.save();
    ctx.beginPath();
    ctx.rect(left - MARKER_R - 2, AXIS_H, width - left + MARKER_R + 2, viewH - AXIS_H);
    ctx.clip();
    for (let i = first; i <= last; i++) {
      const lane = lanes[i];
      const y = rowY(i);
      const mid = y + BAR_H / 2;
      const trackSelected = lane.trackId != null && is("track", lane.trackId);

      // Connectors under the bars: solid across a rotation, dashed where the
      // same address was simply seen again.
      for (const entry of laneLinks[i] ?? []) {
        const [ax, aw] = barX(entry.a);
        const bx = tx(entry.b.t_start_us);
        if (bx - (ax + aw) < 1) continue;
        ctx.strokeStyle = MUTED;
        ctx.lineWidth = 1.5;
        ctx.setLineDash(entry.link.kind === "rotation" ? [] : [3, 3]);
        ctx.beginPath();
        ctx.moveTo(ax + aw, mid);
        ctx.lineTo(bx, mid);
        ctx.stroke();
        ctx.setLineDash([]);
      }

      for (const e of lane.epochs) {
        const [x, w] = barX(e);
        if (x + w < left || x > width) continue;
        ctx.fillStyle = typeColor(e.addr_type);
        ctx.beginPath();
        ctx.roundRect(x, y, w, BAR_H, Math.min(3, w / 2));
        ctx.fill();
        if (hovered("epoch", e.id)) {
          ctx.fillStyle = "rgba(255,255,255,0.22)";
          ctx.fill();
        }
        if (is("epoch", e.id) || trackSelected) {
          ctx.strokeStyle = INK;
          ctx.lineWidth = is("epoch", e.id) ? 2 : 1;
          ctx.beginPath();
          ctx.roundRect(x - 2, y - 2, w + 4, BAR_H + 4, 4);
          ctx.stroke();
        }
        if (w >= LABEL_MIN_W) {
          const visibleX = Math.max(x, left);
          const room = Math.min(x + w, width) - visibleX - 10;
          const text = fitText(ctx, e.label || e.address, room);
          if (text) {
            ctx.fillStyle = BAR_TEXT;
            ctx.fillText(text, visibleX + 5, y + BAR_H / 2 + 0.5);
          }
        }
      }

      // Rotation markers on top: a filled diamond, hollow and amber when the
      // link has a close rival. Shape carries the difference, not colour alone.
      for (const entry of laneLinks[i] ?? []) {
        const { link } = entry;
        if (link.kind !== "rotation") continue;
        const x = markerX(entry);
        if (x < left - MARKER_R || x > width + MARKER_R) continue;
        const r = MARKER_R + (is("link", link.id) || hovered("link", link.id) ? 1.5 : 0);
        diamond(ctx, x, mid, r + 2);
        ctx.fillStyle = SURFACE; // ring separating the marker from the bars
        ctx.fill();
        diamond(ctx, x, mid, r);
        if (link.ambiguous) {
          ctx.strokeStyle = WARNING;
          ctx.lineWidth = 2;
          ctx.stroke();
        } else {
          ctx.fillStyle = INK;
          ctx.fill();
        }
        if (is("link", link.id)) {
          diamond(ctx, x, mid, r + 4);
          ctx.strokeStyle = ACCENT;
          ctx.lineWidth = 2;
          ctx.stroke();
        }
      }
    }
    ctx.restore();

    // Trail names in the gutter.
    if (trailMode) {
      ctx.save();
      ctx.beginPath();
      ctx.rect(0, AXIS_H, left - MARKER_R - 2, viewH - AXIS_H);
      ctx.clip();
      for (let i = first; i <= last; i++) {
        const id = lanes[i].trackId;
        const active = is("track", id) || hovered("track", id);
        ctx.fillStyle = active ? INK : MUTED;
        ctx.fillText(tracks[id].name, PAD_X - 6, rowY(i) + BAR_H / 2 + 0.5);
      }
      ctx.restore();
    }
  }, [lanes, laneLinks, tracks, xScale, width, viewH, scrollTop, selKey, hoverKey, tMin, left, trailMode]);

  const zoomed = transform.k > 1.0001;
  const nRotations = links.filter((l) => l.kind === "rotation").length;

  return (
    <section className="panel timeline">
      <div className="panel-head">
        <h2>Timeline</h2>
        <span className="muted small">
          {lanes.length} {trailMode ? "device trails" : lanes.length === 1 ? "row" : "rows"} · time
          since capture start
        </span>
        <div className="spacer" />
        <div className="seg" role="group" aria-label="Row layout">
          {MODES.map((m) => (
            <button key={m.key} className={mode === m.key ? "on" : ""} onClick={() => setMode(m.key)}>
              {m.label}
            </button>
          ))}
        </div>
        <div className="seg" role="group" aria-label="Zoom">
          <button onClick={() => zoomBy(1 / 2)} disabled={!zoomed} aria-label="Zoom out">−</button>
          <button onClick={() => zoomBy(2)} aria-label="Zoom in">+</button>
          <button onClick={zoomFit} disabled={!zoomed}>Fit</button>
          <button onClick={zoomToSelected} disabled={!canZoomToSelected}>Zoom to selected</button>
        </div>
      </div>

      <div className="tl-wrap" ref={wrapRef}>
        <div
          className="tl-scroll"
          ref={scrollRef}
          style={{ height: viewH }}
          onScroll={(ev) => setScrollTop(ev.currentTarget.scrollTop)}
        >
          <div style={{ height: contentH }}>
            <canvas
              ref={canvasRef}
              className={`tl-canvas${hover ? " over-bar" : zoomed ? " pannable" : ""}`}
              style={{ height: viewH }}
              role="img"
              aria-label={`Timeline of ${epochs.length} address epochs in ${tracks.length} device trails. The tables below list the same data.`}
              onPointerMove={onPointerMove}
              onPointerLeave={() => setHover(null)}
              onClick={onClick}
            />
          </div>
        </div>
        {epochs.length === 0 && <p className="tl-empty muted">No epochs match the filters.</p>}
        {hover && <Tooltip hover={hover} tMin={tMin} maxX={width} />}
      </div>
      {trailMode && nRotations > 0 && (
        <p className="link-key muted small">
          <span className="key-item"><i className="key-diamond" /> rotation link</span>
          <span className="key-item"><i className="key-diamond hollow" /> ambiguous link (a rival scored nearly as well)</span>
          <span className="key-item"><i className="key-dash" /> same address seen again</span>
        </p>
      )}
      <p className="hint muted small">
        Drag to pan · Ctrl/⌘ + scroll or pinch to zoom · double-click to zoom in · click a bar for
        its packets{trailMode ? ", a diamond for the evidence behind a link" : ""}
      </p>
    </section>
  );
}

function Tooltip({ hover, tMin, maxX }) {
  const left = Math.min(hover.x + 14, Math.max(0, maxX - 290));
  const style = { left, top: hover.y + 18 };
  const item = hover.item;
  if (hover.kind === "link") {
    const best = [...item.clues].sort((a, b) => b.contribution - a.contribution)[0];
    return (
      <div className="tooltip" style={style}>
        <div className="tt-title">Rotation link{item.ambiguous ? " · ambiguous" : ""}</div>
        <dl>
          <dt>Score</dt>
          <dd>{fmtScore(item.score)}</dd>
          <dt>Gap</dt>
          <dd>{fmtDuration(Math.max(0, item.gap_us))}</dd>
          {best && (
            <>
              <dt>Top clue</dt>
              <dd>{best.name}</dd>
            </>
          )}
        </dl>
      </div>
    );
  }
  if (hover.kind === "track") {
    return (
      <div className="tooltip" style={style}>
        <div className="tt-title">Trail {item.name}</div>
        {item.label && <div className="tt-label">{item.label}</div>}
        <dl>
          <dt>Addresses</dt>
          <dd>{item.n_addresses}</dd>
          <dt>Packets</dt>
          <dd>{item.n_packets.toLocaleString()}</dd>
        </dl>
      </div>
    );
  }
  return (
    <div className="tooltip" style={style}>
      <div className="tt-title mono">{item.address}</div>
      {item.label && <div className="tt-label">{item.label}</div>}
      <dl>
        <dt>Type</dt>
        <dd>{TYPE_BY_KEY[item.addr_type]?.label ?? item.addr_type}</dd>
        <dt>Seen</dt>
        <dd>
          {fmtOffset(item.t_start_us - tMin)} for {fmtDuration(item.duration_us)}
        </dd>
        <dt>Packets</dt>
        <dd>{item.n_packets.toLocaleString()}</dd>
        <dt>Interval</dt>
        <dd>{fmtMs(item.adv_interval_ms)}</dd>
      </dl>
    </div>
  );
}

function diamond(ctx, x, y, r) {
  ctx.beginPath();
  ctx.moveTo(x, y - r);
  ctx.lineTo(x + r, y);
  ctx.lineTo(x, y + r);
  ctx.lineTo(x - r, y);
  ctx.closePath();
}

// Truncate `text` with an ellipsis so it fits in `room` pixels.
function fitText(ctx, text, room) {
  if (room < 24) return "";
  if (ctx.measureText(text).width <= room) return text;
  let lo = 0;
  let hi = text.length;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (ctx.measureText(text.slice(0, mid) + "…").width <= room) lo = mid;
    else hi = mid - 1;
  }
  return lo > 0 ? text.slice(0, lo) + "…" : "";
}
