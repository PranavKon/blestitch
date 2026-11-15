// Address types and the colour each one wears on the timeline.
//
// Colour answers one question — does this address rotate? — so it uses three
// hues that stay distinguishable in any pairing (validated all-pairs for
// colour-vision deficiency on the panel surface) plus a neutral for addresses
// that are not random at all. The type is always also written out in the
// legend, the tooltip and the table, so colour never carries it alone.

export const ADDR_TYPES = [
  { key: "resolvable", label: "Resolvable (RPA)", short: "RPA", hint: "rotates; resolvable with the device's IRK", color: "#3987e5" },
  { key: "nrpa", label: "Non-resolvable", short: "NRPA", hint: "rotates; not resolvable", color: "#199e70" },
  { key: "static", label: "Static random", short: "Static", hint: "fixed until power cycle", color: "#d95926" },
  { key: "public", label: "Public", short: "Public", hint: "manufacturer-assigned, never rotates", color: "#8b98a5" },
  { key: "unknown", label: "Reserved", short: "Reserved", hint: "reserved address bits", color: "#5d6873" },
];

export const TYPE_BY_KEY = Object.fromEntries(ADDR_TYPES.map((t) => [t.key, t]));

export function typeColor(key) {
  return (TYPE_BY_KEY[key] ?? TYPE_BY_KEY.unknown).color;
}
