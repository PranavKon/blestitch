import React, { useEffect, useMemo, useRef, useState } from "react";

import { fmtDuration, fmtOffset, fmtScore, trailName } from "./format.js";
import { TYPE_BY_KEY } from "./types.js";

const COLUMNS = [
  { key: "id", label: "Trail", sort: (t) => t.id },
  { key: "label", label: "Identity", sort: (t) => t.label.toLowerCase() },
  { key: "addr_type", label: "Type", sort: (t) => t.addr_type },
  { key: "n_addresses", label: "Addrs", sort: (t) => t.n_addresses, num: true },
  { key: "t_start_us", label: "First seen", sort: (t) => t.t_start_us, num: true },
  { key: "span", label: "Span", sort: (t) => t.t_end_us - t.t_start_us, num: true },
  { key: "n_packets", label: "Packets", sort: (t) => t.n_packets, num: true },
  { key: "min_score", label: "Weakest link", sort: (t) => t.min_score ?? 2 },
];

// One row per stitched device trail. Like the epoch table, every row is
// focusable and Enter selects it.
export default function TrackTable({ tracks, tMin, selectedId, onSelect }) {
  const [sort, setSort] = useState({ key: "id", dir: 1 });
  const scroller = useRef(null);
  const selectedRow = useRef(null);

  const sorted = useMemo(() => {
    const col = COLUMNS.find((c) => c.key === sort.key);
    return [...tracks].sort((a, b) => {
      const [x, y] = [col.sort(a), col.sort(b)];
      return (x < y ? -1 : x > y ? 1 : a.id - b.id) * sort.dir;
    });
  }, [tracks, sort]);

  useEffect(() => {
    const [row, box] = [selectedRow.current, scroller.current];
    if (!row || !box) return;
    const head = box.querySelector("thead").offsetHeight;
    if (row.offsetTop < box.scrollTop + head) box.scrollTop = row.offsetTop - head;
    else if (row.offsetTop + row.offsetHeight > box.scrollTop + box.clientHeight) {
      box.scrollTop = row.offsetTop + row.offsetHeight - box.clientHeight;
    }
  }, [selectedId]);

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
                <button
                  onClick={() =>
                    setSort((s) => (s.key === c.key ? { key: c.key, dir: -s.dir } : { key: c.key, dir: 1 }))
                  }
                >
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
          {sorted.map((t) => {
            const selected = t.id === selectedId;
            return (
              <tr
                key={t.id}
                ref={selected ? selectedRow : null}
                className={selected ? "selected" : ""}
                tabIndex={0}
                aria-selected={selected}
                onClick={() => onSelect(t.id)}
                onKeyDown={(ev) => {
                  if (ev.key === "Enter" || ev.key === " ") {
                    ev.preventDefault();
                    onSelect(t.id);
                  }
                }}
              >
                <td>{trailName(t.id)}</td>
                <td className="identity wide" title={t.label}>
                  {t.label || <span className="muted">—</span>}
                </td>
                <td>
                  <span className={`tag tag-${t.addr_type}`} title={TYPE_BY_KEY[t.addr_type]?.label}>
                    {TYPE_BY_KEY[t.addr_type]?.short ?? t.addr_type}
                  </span>
                </td>
                <td className="num">{t.n_addresses}</td>
                <td className="num mono">{fmtOffset(t.t_start_us - tMin)}</td>
                <td className="num">{fmtDuration(t.t_end_us - t.t_start_us)}</td>
                <td className="num">{t.n_packets.toLocaleString()}</td>
                <td>
                  {t.min_score == null ? (
                    <span className="muted">no rotation</span>
                  ) : (
                    <>
                      {fmtScore(t.min_score)}
                      {t.ambiguous && <span className="flag">ambiguous</span>}
                    </>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
