const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || "").replace(/\/$/, "");

export function apiUrl(path) {
  return `${API_BASE_URL}${path}`;
}

export async function createScan(payload) {
  const response = await fetch(apiUrl("/scans"), {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(payload)
  });

  return readJsonResponse(response);
}

export async function getScan(scanId) {
  const response = await fetch(apiUrl(`/scans/${encodeURIComponent(scanId)}`));
  return readJsonResponse(response);
}

export function scanStreamUrl(scanId) {
  return apiUrl(`/scans/${encodeURIComponent(scanId)}/stream`);
}

async function readJsonResponse(response) {
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = body.detail || "Request failed.";
    throw new Error(detail);
  }
  return body;
}
