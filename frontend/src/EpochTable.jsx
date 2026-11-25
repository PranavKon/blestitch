import React, { useEffect, useMemo, useRef, useState } from "react";

import { fmtDuration, fmtMs, fmtOffset } from "./format.js";
import { TYPE_BY_KEY } from "./types.js";

const PAGE = 300;

const COLUMNS = [
  { key: "address", label: "Address", sort: (e) => e.address },
  { key: "addr_type", label: "Type", sort: (e) => e.addr_type },
  { key: "label", label: "Identity", sort: (e) => e.label.toLowerCase() },
  { key: "t_start_us", label: "First seen", sort: (e) => e.t_start_us, num: true },
  { key: "duration_us", label: "Duration", sort: (e) => e.duration_us, num: true },
  { key: "n_packets", label: "Packets", sort: (e) => e.n_packets, num: true },
  { key: "adv_interval_ms", label: "Interval", sort: (e) => e.adv_interval_ms ?? Infinity, num: true },
  { key: "n_payload_variants", label: "Payloads", sort: (e) => e.n_payload_variants, num: true },
];

// The same epochs as the timeline, as a sortable table. This is also the
// keyboard path: every row is focusable and Enter selects it.
export default function EpochTable({ epochs, tMin, selectedId, onSelect }) {
  const [sort, setSort] = useState({ key: "t_start_us", dir: 1 });
  const [limit, setLimit] = useState(PAGE);
  const selectedRow = useRef(null);
  const scroller = useRef(null);

  const sorted = useMemo(() => {
    const col = COLUMNS.find((c) => c.key === sort.key);
    return [...epochs].sort((a, b) => {
      const [x, y] = [col.sort(a), col.sort(b)];
      return (x < y ? -1 : x > y ? 1 : a.id - b.id) * sort.dir;
    });
  }, [epochs, sort]);

  // Keep the selected row rendered and in view when it is picked on the timeline.
  const selectedIndex = sorted.findIndex((e) => e.id === selectedId);
  useEffect(() => {
    if (selectedIndex >= limit) setLimit(Math.ceil((selectedIndex + 1) / PAGE) * PAGE);
  }, [selectedIndex, limit]);
  useEffect(() => {
    // Scroll only the table's own box, and only vertically.
    const [row, box] = [selectedRow.current, scroller.current];
    if (!row || !box) return;
    const head = box.querySelector("thead").offsetHeight;
    if (row.offsetTop < box.scrollTop + head) box.scrollTop = row.offsetTop - head;
    else if (row.offsetTop + row.offsetHeight > box.scrollTop + box.clientHeight) {
      box.scrollTop = row.offsetTop + row.offsetHeight - box.clientHeight;
    }
  }, [selectedId, limit]);

  function toggleSort(key) {
    setSort((s) => (s.key === key ? { key, dir: -s.dir } : { key, dir: 1 }));
  }

  return (
      <div className="table-scroll" ref={scroller}>
        <table className="epochs">
          <thead>
            <tr>
              {COLUMNS.map((c) => (
                <th
                  key={c.key}
                  className={c.num ? "num" : ""}
                  aria-sort={sort.key === c.key ? (sort.dir === 1 ? "ascending" : "descending") : "none"}
                >
                  <button onClick={() => toggleSort(c.key)}>
                    {c.label}
                    <span className="sort-mark">
                      {sort.key === c.key ? (sort.dir === 1 ? "▲" : "▼") : ""}
                    </span>
                  </button>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sorted.slice(0, limit).map((e) => {
              const selected = e.id === selectedId;
              return (
                <tr
                  key={e.id}
                  ref={selected ? selectedRow : null}
                  className={selected ? "selected" : ""}
                  tabIndex={0}
                  aria-selected={selected}
                  onClick={() => onSelect(e.id)}
                  onKeyDown={(ev) => {
                    if (ev.key === "Enter" || ev.key === " ") {
                      ev.preventDefault();
                      onSelect(e.id);
                    }
                  }}
                >
                  <td className="mono">{e.address}</td>
                  <td>
                    <span
                      className={`tag tag-${e.addr_type}`}
                      title={TYPE_BY_KEY[e.addr_type]?.label}
                    >
                      {TYPE_BY_KEY[e.addr_type]?.short ?? e.addr_type}
                    </span>
                  </td>
                  <td className="identity" title={e.label}>
                    {e.label || <span className="muted">—</span>}
                  </td>
                  <td className="num mono">{fmtOffset(e.t_start_us - tMin)}</td>
                  <td className="num">{fmtDuration(e.duration_us)}</td>
                  <td className="num">{e.n_packets.toLocaleString()}</td>
                  <td className="num">{fmtMs(e.adv_interval_ms)}</td>
                  <td className="num">{e.n_payload_variants}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {sorted.length > limit && (
          <button className="more" onClick={() => setLimit((n) => n + PAGE)}>
            Show {Math.min(PAGE, sorted.length - limit)} more of {sorted.length - limit} remaining
          </button>
        )}
      </div>
  );
}
