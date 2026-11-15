// Thin client for the FastAPI backend (proxied at /api by the Vite dev server).

async function parse(resp) {
  if (!resp.ok) {
    const body = await resp.json().catch(() => ({}));
    const detail = typeof body.detail === "string" ? body.detail : null;
    throw new Error(detail || `HTTP ${resp.status}`);
  }
  return resp.json();
}

export async function analyzeFile(file) {
  const body = new FormData();
  body.append("file", file);
  return parse(await fetch("/api/analyze", { method: "POST", body }));
}

export async function fetchEpochDetail(analysisId, epochId, signal) {
  return parse(await fetch(`/api/analyses/${analysisId}/epochs/${epochId}`, { signal }));
}

export async function fetchEpochPackets(analysisId, epochId, offset, limit, signal) {
  const q = new URLSearchParams({ offset, limit });
  return parse(
    await fetch(`/api/analyses/${analysisId}/epochs/${epochId}/packets?${q}`, { signal }),
  );
}
