import React, { useEffect, useMemo, useRef, useState } from "react";
import { scaleLinear } from "d3-scale";
import { select } from "d3-selection";
import { zoom, zoomIdentity } from "d3-zoom";

import { US_PER_S, fmtDuration, fmtMs, fmtOffset, fmtTick, timeTicks } from "./format.js";
import { oneLaneEach, packLanes } from "./lanes.js";
import { TYPE_BY_KEY, typeColor } from "./types.js";

const ROW_H = 22;
const BAR_H = 14;
const AXIS_H = 28;
const PAD_X = 14;
const MIN_BAR_W = 3;
const MAX_VIEW_H = 460;
const LABEL_MIN_W = 64;

const INK = "#e6edf3";
const MUTED = "#8b98a5";
const GRID = "#222c38";
const BAR_TEXT = "#0b0f14";

// Epochs as bars on a shared time axis. Rows are packed so that addresses
// which never overlap share a row; the canvas only draws what is in view, so
// the row count is not limited by canvas size.
export default function Timeline({ epochs, tMin, tMax, selectedId, onSelect }) {
  const wrapRef = useRef(null);
  const scrollRef = useRef(null);
  const canvasRef = useRef(null);
  const zoomRef = useRef(null);
  const [mode, setMode] = useState("packed");
  const [width, setWidth] = useState(900);
  const [scrollTop, setScrollTop] = useState(0);
  const [transform, setTransform] = useState(zoomIdentity);
  const [hover, setHover] = useState(null); // { epoch, x, y }

  const spanUs = Math.max(1, tMax - tMin);
  const spanS = spanUs / US_PER_S;

  const lanes = useMemo(
    () => (mode === "packed" ? packLanes(epochs, spanUs * 0.004) : oneLaneEach(epochs)),
    [epochs, mode, spanUs],
  );

  const contentH = AXIS_H + lanes.length * ROW_H + 10;
  const viewH = Math.max(AXIS_H + ROW_H * 3, Math.min(contentH, MAX_VIEW_H));

  const baseScale = useMemo(
    () => scaleLinear().domain([0, spanS]).range([PAD_X, Math.max(PAD_X + 1, width - PAD_X)]),
    [spanS, width],
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
      .translateExtent([[0, 0], [width, 0]])
      .extent([[0, 0], [width, viewH]])
      .filter((ev) => (ev.type === "wheel" ? ev.ctrlKey || ev.metaKey : !ev.button))
      // At most ~1.4x per wheel notch; trackpad pinches send many small steps.
      .wheelDelta((ev) => Math.max(-0.5, Math.min(0.5, -ev.deltaY * 0.01)))
      .on("zoom", (ev) => setTransform(ev.transform));
    canvas.call(behavior);
    zoomRef.current = behavior;
    return () => canvas.on(".zoom", null);
  }, [width, viewH, spanS]);

  // A new capture starts fully zoomed out.
  useEffect(() => {
    if (zoomRef.current) select(canvasRef.current).call(zoomRef.current.transform, zoomIdentity);
    scrollRef.current.scrollTop = 0;
  }, [tMin, tMax]);

  function zoomBy(factor) {
    select(canvasRef.current).call(zoomRef.current.scaleBy, factor);
  }
  function zoomFit() {
    select(canvasRef.current).call(zoomRef.current.transform, zoomIdentity);
  }
  function zoomToSelected() {
    const lane = lanes.findIndex((l) => l.some((e) => e.id === selectedId));
    if (lane === -1) return;
    const e = lanes[lane].find((x) => x.id === selectedId);
    const s0 = (e.t_start_us - tMin) / US_PER_S;
    const s1 = Math.max((e.t_end_us - tMin) / US_PER_S, s0 + spanS * 1e-4);
    const margin = (s1 - s0) * 0.15;
    // Programmatic transforms are not clamped by d3-zoom, so stay in range here.
    const x0 = baseScale(Math.max(0, s0 - margin));
    const x1 = baseScale(Math.min(spanS, s1 + margin));
    const k = Math.min(zoomRef.current.scaleExtent()[1], (width - 2 * PAD_X) / (x1 - x0));
    const t = zoomIdentity.translate(PAD_X - x0 * k, 0).scale(k);
    select(canvasRef.current).call(zoomRef.current.transform, t);
    const top = lane * ROW_H;
    const el = scrollRef.current;
    if (top < el.scrollTop || top + ROW_H > el.scrollTop + viewH - AXIS_H) {
      el.scrollTop = Math.max(0, top - (viewH - AXIS_H) / 2);
    }
  }

  // Bar geometry for one epoch at the current zoom.
  function barX(e) {
    const x0 = xScale((e.t_start_us - tMin) / US_PER_S);
    const x1 = xScale((e.t_end_us - tMin) / US_PER_S);
    return [x0, Math.max(MIN_BAR_W, x1 - x0)];
  }

  function hitTest(px, py) {
    if (py < AXIS_H) return null;
    const lane = lanes[Math.floor((py - AXIS_H + scrollTop) / ROW_H)];
    if (!lane) return null;
    let best = null;
    let bestDist = 4; // forgiving hit area around thin bars
    for (const e of lane) {
      const [x, w] = barX(e);
      const dist = px < x ? x - px : px > x + w ? px - x - w : 0;
      if (dist < bestDist) {
        best = e;
        bestDist = dist;
      }
    }
    return best;
  }

  function onPointerMove(ev) {
    const rect = canvasRef.current.getBoundingClientRect();
    const [px, py] = [ev.clientX - rect.left, ev.clientY - rect.top];
    const epoch = hitTest(px, py);
    const wrap = wrapRef.current.getBoundingClientRect();
    setHover(epoch ? { epoch, x: ev.clientX - wrap.left, y: ev.clientY - wrap.top } : null);
  }

  function onClick(ev) {
    const rect = canvasRef.current.getBoundingClientRect();
    const epoch = hitTest(ev.clientX - rect.left, ev.clientY - rect.top);
    if (epoch) onSelect(epoch.id);
  }

  const hoverId = hover?.epoch.id ?? null;

  // Paint.
  useEffect(() => {
    const canvas = canvasRef.current;
    const dpr = window.devicePixelRatio || 1;
    canvas.width = Math.round(width * dpr);
    canvas.height = Math.round(viewH * dpr);
    const ctx = canvas.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, width, viewH);

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

    // Bars: only rows and epochs that are in view.
    ctx.save();
    ctx.beginPath();
    ctx.rect(0, AXIS_H, width, viewH - AXIS_H);
    ctx.clip();
    const first = Math.max(0, Math.floor(scrollTop / ROW_H));
    const last = Math.min(lanes.length - 1, Math.ceil((scrollTop + viewH - AXIS_H) / ROW_H));
    for (let i = first; i <= last; i++) {
      const y = AXIS_H + i * ROW_H - scrollTop + (ROW_H - BAR_H) / 2;
      for (const e of lanes[i]) {
        const [x, w] = barX(e);
        if (x + w < 0 || x > width) continue;
        ctx.fillStyle = typeColor(e.addr_type);
        ctx.beginPath();
        ctx.roundRect(x, y, w, BAR_H, Math.min(3, w / 2));
        ctx.fill();
        if (e.id === hoverId) {
          ctx.fillStyle = "rgba(255,255,255,0.22)";
          ctx.fill();
        }
        if (e.id === selectedId) {
          ctx.strokeStyle = INK;
          ctx.lineWidth = 2;
          ctx.beginPath();
          ctx.roundRect(x - 2, y - 2, w + 4, BAR_H + 4, 4);
          ctx.stroke();
        }
        if (w >= LABEL_MIN_W) {
          const visibleX = Math.max(x, 0);
          const room = Math.min(x + w, width) - visibleX - 10;
          const text = fitText(ctx, e.label || e.address, room);
          if (text) {
            ctx.fillStyle = BAR_TEXT;
            ctx.fillText(text, visibleX + 5, y + BAR_H / 2 + 0.5);
          }
        }
      }
    }
    ctx.restore();
  }, [lanes, xScale, width, viewH, scrollTop, selectedId, hoverId, tMin]);

  const zoomed = transform.k > 1.0001;

  return (
    <section className="panel timeline">
      <div className="panel-head">
        <h2>Timeline</h2>
        <span className="muted small">
          {lanes.length} {lanes.length === 1 ? "row" : "rows"} · time since capture start
        </span>
        <div className="spacer" />
        <div className="seg" role="group" aria-label="Row layout">
          <button className={mode === "packed" ? "on" : ""} onClick={() => setMode("packed")}>
            Packed rows
          </button>
          <button className={mode === "each" ? "on" : ""} onClick={() => setMode("each")}>
            One row per epoch
          </button>
        </div>
        <div className="seg" role="group" aria-label="Zoom">
          <button onClick={() => zoomBy(1 / 2)} disabled={!zoomed} aria-label="Zoom out">−</button>
          <button onClick={() => zoomBy(2)} aria-label="Zoom in">+</button>
          <button onClick={zoomFit} disabled={!zoomed}>Fit</button>
          <button onClick={zoomToSelected} disabled={selectedId == null}>Zoom to selected</button>
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
              aria-label={`Timeline of ${epochs.length} address epochs. The epoch table below lists the same data.`}
              onPointerMove={onPointerMove}
              onPointerLeave={() => setHover(null)}
              onClick={onClick}
            />
          </div>
        </div>
        {epochs.length === 0 && <p className="tl-empty muted">No epochs match the filters.</p>}
        {hover && <Tooltip hover={hover} tMin={tMin} maxX={width} />}
      </div>
      <p className="hint muted small">
        Drag to pan · Ctrl/⌘ + scroll or pinch to zoom · double-click to zoom in · click a bar for
        its packets
      </p>
    </section>
  );
}

function Tooltip({ hover, tMin, maxX }) {
  const e = hover.epoch;
  const left = Math.min(hover.x + 14, Math.max(0, maxX - 290));
  return (
    <div className="tooltip" style={{ left, top: hover.y + 18 }}>
      <div className="tt-title mono">{e.address}</div>
      {e.label && <div className="tt-label">{e.label}</div>}
      <dl>
        <dt>Type</dt>
        <dd>{TYPE_BY_KEY[e.addr_type]?.label ?? e.addr_type}</dd>
        <dt>Seen</dt>
        <dd>
          {fmtOffset(e.t_start_us - tMin)} for {fmtDuration(e.duration_us)}
        </dd>
        <dt>Packets</dt>
        <dd>{e.n_packets.toLocaleString()}</dd>
        <dt>Interval</dt>
        <dd>{fmtMs(e.adv_interval_ms)}</dd>
      </dl>
    </div>
  );
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
