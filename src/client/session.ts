export function generateSessionId(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  // Pre-randomUUID fallback (legacy browsers): RFC 4122 v4 from getRandomValues.
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  bytes[6] = (bytes[6]! & 0x0f) | 0x40;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, '0'));
  return `${hex.slice(0, 4).join('')}-${hex.slice(4, 6).join('')}-${hex.slice(6, 8).join('')}-${hex.slice(8, 10).join('')}-${hex.slice(10, 16).join('')}`;
}

export async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest('SHA-256', data);
  const arr = new Uint8Array(digest);
  let out = '';
  for (let i = 0; i < arr.length; i++) {
    out += arr[i]!.toString(16).padStart(2, '0');
  }
  return out;
}

export interface CollectResponse {
  ok: boolean;
  sessionId: string;
  recapUrl: string;
}

export interface CollectResult {
  ok: boolean;
  reason: string;
  data: CollectResponse | null;
}

export async function postCollect(payload: unknown): Promise<CollectResult> {
  try {
    const res = await fetch('/collect', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
      keepalive: true,
    });
    if (!res.ok) {
      return { ok: false, reason: `HTTP ${res.status}`, data: null };
    }
    const data = (await res.json()) as CollectResponse;
    return { ok: true, reason: 'ok', data };
  } catch (err) {
    const reason = err instanceof Error ? `réseau : ${err.message}` : 'réseau';
    return { ok: false, reason, data: null };
  }
}
