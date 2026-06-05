import type { TlsFingerprint } from '../types.js';

// ─── TLS profiling — does the TLS stack match a real browser? ────────────────
// Captured server-side from the ClientHello (before TLS terminates), so it can't
// be forged in JS. The headline level-2 lie is "browser User-Agent + curl/python
// TLS stack". Two complementary mechanisms (per design decision "both"):
//   1. Structural heuristic  — robust, self-contained, no external data. Now
//      reads the *rich* ClientHello features (TLS-1.3 advertisement, the modern
//      handshake extensions, the offered curves, GREASE), not just "h2 + 5
//      ciphers" — those two alone are trivially satisfied by curl/Go/uTLS.
//   2. KNOWN_TOOL_SIGNATURES — exact/structural patterns that *name* the tool;
//      operator-extensible with observed JA3/JA4 values.

// TLS extension numbers we key on (RFC 8446 / IANA).
const EXT_SUPPORTED_GROUPS = 0x000a; // 10
const EXT_SIG_ALGS = 0x000d; // 13
const EXT_SUPPORTED_VERSIONS = 0x002b; // 43
const EXT_KEY_SHARE = 0x0033; // 51
const CURVE_X25519 = 0x001d; // 29 — every modern browser offers it first
const TLS13 = 0x0304;

// GREASE (RFC 8701) — Chrome/Edge inject these reserved values into ciphers,
// extensions, curves and versions; almost no TLS library does. Local copy so
// this stays self-contained (no shared→server import that the client would pull).
function isGrease(value: number): boolean {
  if ((value & 0x0f0f) !== 0x0a0a) return false;
  return ((value >> 8) & 0xff) === (value & 0xff);
}

interface ParsedTls {
  hasH2: boolean; // ALPN advertises HTTP/2 — every HTTPS browser offers it
  cipherCount: number; // GREASE-inclusive count from the ClientHello
  hasTls13: boolean; // supported_versions advertises TLS 1.3
  hasKeyShare: boolean; // key_share present → a real TLS 1.3 handshake
  hasSupportedVersionsExt: boolean;
  hasSigAlgs: boolean; // signature_algorithms present
  hasSupportedGroups: boolean;
  offersX25519: boolean; // X25519 among the supported groups
  hasGrease: boolean; // any GREASE value anywhere → browser-like
  extCount: number;
  ja3Hash: string;
  ja4: string;
}

function parse(tls: TlsFingerprint): ParsedTls {
  const exts = tls.extensions;
  const hasExt = (n: number): boolean => exts.includes(n);
  const grease =
    tls.ciphers.some(isGrease) ||
    exts.some(isGrease) ||
    tls.ellipticCurves.some(isGrease) ||
    tls.supportedVersions.some(isGrease);
  return {
    hasH2: tls.alpn.includes('h2'),
    cipherCount: tls.ciphers.length,
    hasTls13: tls.supportedVersions.includes(TLS13),
    hasKeyShare: hasExt(EXT_KEY_SHARE),
    hasSupportedVersionsExt: hasExt(EXT_SUPPORTED_VERSIONS),
    hasSigAlgs: hasExt(EXT_SIG_ALGS),
    hasSupportedGroups: hasExt(EXT_SUPPORTED_GROUPS),
    offersX25519: tls.ellipticCurves.includes(CURVE_X25519),
    hasGrease: grease,
    extCount: exts.length,
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

// Ordered specific → generic. The exact-hash slots are for operators who have
// observed specific tool fingerprints in their own traffic — add them to name
// the tool precisely without changing detection logic. The structural matchers
// below are always usable and now lean on the rich ClientHello features.
export const KNOWN_TOOL_SIGNATURES: ToolSignature[] = [
  // ── Operator-supplied exact fingerprints (examples — fill from your traffic):
  // { tool: 'curl 8.x (OpenSSL)', ja3Hash: '<md5 observé>' },
  // { tool: 'python-requests / urllib3', ja4Prefix: 't13d' },
  // { tool: 'Go net/http', ja3Hash: '<md5 observé>' },

  // ── Structural signatures (rich-field based, no external data) ──────────────
  {
    tool: 'client HTTP sans TLS 1.3 ni HTTP/2 (curl / requests / Go par défaut)',
    match: (p) => !p.hasTls13 && !p.hasH2,
  },
  {
    tool: 'pile TLS sans key_share (pas de vrai handshake TLS 1.3 — lib basique)',
    match: (p) => p.hasTls13 && !p.hasKeyShare,
  },
  {
    tool: 'pile TLS sans signature_algorithms / supported_groups (client minimal)',
    match: (p) => !p.hasSigAlgs || !p.hasSupportedGroups,
  },
  {
    tool: 'pile TLS 1.2 uniquement (pas de TLS 1.3 — navigateur ancien ou outil)',
    match: (p) => !p.hasTls13,
  },
  {
    tool: 'courbes sans X25519 (un navigateur moderne le propose en premier)',
    match: (p) => p.hasSupportedGroups && !p.offersX25519,
  },
  {
    tool: 'client HTTP sans HTTP/2 (curl / requests / Go par défaut)',
    match: (p) => !p.hasH2,
  },
  {
    tool: 'client TLS minimaliste (très peu de cipher suites)',
    match: (p) => p.cipherCount > 0 && p.cipherCount < 5,
  },
  {
    tool: 'absence de GREASE (Chrome/Edge en injectent partout)',
    // Last, most generic catch: an otherwise rich hello that copied a cipher
    // list but not the GREASE padding a real Chrome/Edge sprinkles everywhere.
    match: (p) => !p.hasGrease && p.cipherCount >= 5 && p.hasH2,
  },
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

// A genuine browser doing HTTPS advertises h2 in ALPN, offers a healthy cipher
// list, AND negotiates TLS 1.3 the modern way: supported_versions + key_share +
// signature_algorithms extensions, with X25519 among its groups. Requiring the
// rich shape (not just "h2 + 5 ciphers") is what catches a curl/Go/python client
// — or a careless impersonator — that wears a browser User-Agent. A perfect uTLS
// clone still passes structurally; that's what the operator exact-hash slots and
// the GREASE/curve tells above are for.
export function classifyTls(tls: TlsFingerprint): { browserLike: boolean; reasons: string[] } {
  const p = parse(tls);
  const reasons: string[] = [];
  if (!p.hasH2) reasons.push("ALPN n'annonce pas h2 (un navigateur HTTPS l'offre toujours)");
  if (p.cipherCount > 0 && p.cipherCount < 5) reasons.push(`seulement ${p.cipherCount} cipher suites proposées`);
  if (!p.hasTls13) reasons.push("supported_versions n'annonce pas TLS 1.3");
  if (p.hasTls13 && !p.hasKeyShare) reasons.push('TLS 1.3 annoncé sans extension key_share (handshake incomplet)');
  if (!p.hasSigAlgs) reasons.push('pas de signature_algorithms (extension standard des navigateurs)');
  if (p.hasSupportedGroups && !p.offersX25519) reasons.push('X25519 absent des courbes proposées');

  const browserLike =
    p.hasH2 &&
    p.cipherCount >= 5 &&
    p.hasTls13 &&
    p.hasKeyShare &&
    p.hasSupportedVersionsExt &&
    p.hasSigAlgs &&
    p.offersX25519;

  return { browserLike, reasons };
}
