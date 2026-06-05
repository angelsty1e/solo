import type { TlsFingerprint } from '../types.js';

// ─── TLS profiling — does the TLS stack match a real browser? ────────────────
// Captured server-side from the ClientHello (before TLS terminates), so it can't
// be forged in JS. The headline level-2 lie is "browser User-Agent + curl/python
// TLS stack". Two complementary mechanisms (per design decision "both"):
//   1. Structural heuristic  — robust, self-contained, no external data.
//   2. KNOWN_TOOL_SIGNATURES — exact/structural patterns that *name* the tool;
//      operator-extensible with observed JA3/JA4 values.

interface ParsedTls {
  hasH2: boolean; // ALPN advertises HTTP/2 — every HTTPS browser offers it
  cipherCount: number; // GREASE already filtered upstream
  ja3Hash: string;
  ja4: string;
}

function parse(tls: TlsFingerprint): ParsedTls {
  return {
    hasH2: tls.alpn.includes('h2'),
    cipherCount: tls.ciphers.length,
    ja3Hash: tls.ja3Hash,
    ja4: tls.ja4,
  };
}

export interface ToolSignature {
  tool: string;
  ja3Hash?: string; // exact JA3 md5 (operator-supplied, most precise)
  ja4Prefix?: string; // match on the readable JA4 prefix (e.g. 't12d')
  match?: (p: ParsedTls) => boolean; // structural fallback
}

// Seeded with structural matchers (always usable). The exact-hash slots are for
// operators who have observed specific tool fingerprints in their own traffic —
// add them to name the tool precisely without changing detection logic.
export const KNOWN_TOOL_SIGNATURES: ToolSignature[] = [
  { tool: 'client HTTP sans HTTP/2 (curl / requests / Go par défaut)', match: (p) => !p.hasH2 },
  { tool: 'client TLS minimaliste (très peu de cipher suites)', match: (p) => p.cipherCount > 0 && p.cipherCount < 5 },
  // Opérateur : ajoutez des signatures exactes observées, ex.
  // { tool: 'curl 8.x', ja3Hash: '<md5 observé>' },
  // { tool: 'python-requests', ja4Prefix: 't12d' },
];

export function matchToolSignature(tls: TlsFingerprint): string | null {
  const p = parse(tls);
  for (const sig of KNOWN_TOOL_SIGNATURES) {
    if (sig.ja3Hash && sig.ja3Hash === p.ja3Hash) return sig.tool;
    if (sig.ja4Prefix && p.ja4.startsWith(sig.ja4Prefix)) return sig.tool;
    if (sig.match && sig.match(p)) return sig.tool;
  }
  return null;
}

// A genuine browser doing HTTPS always advertises h2 in ALPN and offers a
// healthy cipher list. The absence of either is the structural tell.
export function classifyTls(tls: TlsFingerprint): { browserLike: boolean; reasons: string[] } {
  const p = parse(tls);
  const reasons: string[] = [];
  if (!p.hasH2) reasons.push("ALPN n'annonce pas h2 (un navigateur HTTPS l'offre toujours)");
  if (p.cipherCount > 0 && p.cipherCount < 5) reasons.push(`seulement ${p.cipherCount} cipher suites proposées`);
  return { browserLike: p.hasH2 && p.cipherCount >= 5, reasons };
}
