// Lay epochs out in rows ("lanes") for the timeline.

// Greedy interval packing: each epoch goes in the first lane that is free
// when it starts, so lanes ≈ devices on air at once. `gapUs` keeps a little
// air between neighbours so bars drawn at a minimum width do not collide.
export function packLanes(epochs, gapUs = 0) {
  const lanes = [];
  const laneEnd = [];
  for (const e of [...epochs].sort((a, b) => a.t_start_us - b.t_start_us)) {
    let i = laneEnd.findIndex((end) => end + gapUs < e.t_start_us);
    if (i === -1) {
      i = lanes.length;
      lanes.push([]);
      laneEnd.push(0);
    }
    lanes[i].push(e);
    laneEnd[i] = e.t_end_us;
  }
  return lanes;
}

// One epoch per lane, in order of first appearance.
export function oneLaneEach(epochs) {
  return [...epochs].sort((a, b) => a.t_start_us - b.t_start_us).map((e) => [e]);
}
