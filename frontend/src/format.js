// Formatting helpers shared by every panel. All times arrive in microseconds.

export const US_PER_S = 1_000_000;

export function fmtDuration(us) {
  if (us == null) return "—";
  if (us === 0) return "single packet";
  const s = us / US_PER_S;
  if (s < 0.001) return `${us} µs`;
  if (s < 1) return `${(s * 1000).toFixed(1)} ms`;
  if (s < 59.95) return `${s.toFixed(1)} s`;
  const whole = Math.round(s);
  if (whole < 3600) return `${Math.floor(whole / 60)} min ${whole % 60} s`;
  const minutes = Math.round(s / 60);
  return `${Math.floor(minutes / 60)} h ${minutes % 60} min`;
}

// Offset from the start of the capture, e.g. "+3:07.25" or "+1:02:03".
export function fmtOffset(us, decimals = 2) {
  const s = us / US_PER_S;
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  const secText = sec.toFixed(decimals).padStart(decimals ? decimals + 3 : 2, "0");
  return h > 0
    ? `+${h}:${String(m).padStart(2, "0")}:${secText}`
    : `+${m}:${secText}`;
}

// Sniffer timestamps anchored to host time are Unix-epoch microseconds; a
// capture with no wall clock starts near zero.
export function isWallClock(us) {
  return us > 978_307_200 * US_PER_S; // after 2001-01-01
}

export function fmtClock(us) {
  if (!isWallClock(us)) return null;
  return new Date(us / 1000).toLocaleString(undefined, {
    year: "numeric", month: "short", day: "numeric",
    hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

export function fmtMs(ms) {
  if (ms == null) return "—";
  return ms >= 1000 ? `${(ms / 1000).toFixed(2)} s` : `${ms.toFixed(ms < 100 ? 1 : 0)} ms`;
}

export function fmtInt(n) {
  return n == null ? "—" : n.toLocaleString();
}

// Group a hex string into space-separated bytes.
export function hexBytes(hex) {
  return hex.match(/../g) ?? [];
}

// ---- time axis ---------------------------------------------------------

const TICK_STEPS_S = [
  0.0001, 0.0002, 0.0005, 0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5,
  1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 14400, 43200, 86400,
];

// Tick positions (seconds) for a visible [lo, hi] range, on clock-friendly steps.
export function timeTicks(lo, hi, target) {
  const span = hi - lo;
  if (!(span > 0)) return { step: 1, ticks: [lo] };
  const step = TICK_STEPS_S.find((s) => span / s <= target) ?? 86400;
  const ticks = [];
  for (let t = Math.ceil(lo / step) * step; t <= hi + step * 1e-9; t += step) ticks.push(t);
  return { step, ticks };
}

export function fmtTick(seconds, step) {
  const decimals = step >= 1 ? 0 : Math.min(4, Math.ceil(-Math.log10(step)));
  return fmtOffset(Math.round(seconds * US_PER_S), decimals).slice(1);
}
