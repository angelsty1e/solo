import type { IncomingMessage } from 'node:http';
import type { HttpFingerprint, SecFetchHeaders } from '../../shared/types.js';

const CLIENT_HINT_PREFIX = 'sec-ch-';

function pickHeader(req: IncomingMessage, name: string): string | null {
  const v = req.headers[name];
  if (Array.isArray(v)) return v[0] ?? null;
  return (v as string | undefined) ?? null;
}

function captureSecFetch(req: IncomingMessage): SecFetchHeaders {
  return {
    site: pickHeader(req, 'sec-fetch-site'),
    mode: pickHeader(req, 'sec-fetch-mode'),
    dest: pickHeader(req, 'sec-fetch-dest'),
    user: pickHeader(req, 'sec-fetch-user'),
  };
}

export function captureHttpFingerprint(req: IncomingMessage): HttpFingerprint {
  // rawHeaders is an interleaved array [name, value, name, value, ...]
  // preserving the on-the-wire order. This is the data anti-bot vendors hash.
  const rawHeaders = req.rawHeaders.slice();
  const headerOrder: string[] = [];
  const lowerSeen = new Set<string>();
  for (let i = 0; i < rawHeaders.length; i += 2) {
    const name = rawHeaders[i]!.toLowerCase();
    if (!lowerSeen.has(name)) {
      lowerSeen.add(name);
      headerOrder.push(name);
    }
  }

  const clientHints: Record<string, string> = {};
  for (const name of Object.keys(req.headers)) {
    if (name.startsWith(CLIENT_HINT_PREFIX)) {
      const value = req.headers[name];
      clientHints[name] = Array.isArray(value) ? value.join(', ') : value ?? '';
    }
  }

  const secFetch = captureSecFetch(req);
  const inconsistencies = detectInconsistencies(req, headerOrder, secFetch);

  return {
    method: req.method ?? '',
    path: req.url ?? '',
    httpVersion: req.httpVersion,
    rawHeaders,
    headerOrder,
    userAgent: (req.headers['user-agent'] as string | undefined) ?? null,
    clientHints,
    accept: (req.headers['accept'] as string | undefined) ?? null,
    acceptLanguage: (req.headers['accept-language'] as string | undefined) ?? null,
    acceptEncoding: (req.headers['accept-encoding'] as string | undefined) ?? null,
    secFetch,
    inconsistencies,
  };
}

function detectInconsistencies(
  req: IncomingMessage,
  order: string[],
  secFetch: SecFetchHeaders,
): string[] {
  const out: string[] = [];
  const ua = (req.headers['user-agent'] as string | undefined) ?? '';
  const secChUa = (req.headers['sec-ch-ua'] as string | undefined) ?? '';
  const secChMobile = (req.headers['sec-ch-ua-mobile'] as string | undefined) ?? '';
  const acceptLang = (req.headers['accept-language'] as string | undefined) ?? '';

  if (ua.includes('Chrome/') && !secChUa) {
    out.push('chrome-ua-without-sec-ch-ua');
  }
  if (secChMobile === '?1' && !/Mobile|Android|iPhone/i.test(ua)) {
    out.push('sec-ch-mobile-mismatch');
  }
  if (ua && !acceptLang) {
    out.push('missing-accept-language');
  }
  // Order anomaly: typical browsers send Host first, then User-Agent or Sec-* before Accept.
  const hostIdx = order.indexOf('host');
  const uaIdx = order.indexOf('user-agent');
  if (hostIdx > -1 && uaIdx > -1 && hostIdx > uaIdx) {
    out.push('host-after-user-agent');
  }
  // Modern Chromium/WebKit/Firefox always send Sec-Fetch-* for navigations.
  // Missing on a Chrome UA strongly suggests a stripped-header bot.
  if (ua.includes('Chrome/') && !secFetch.site) {
    out.push('chrome-without-sec-fetch');
  }
  if (secFetch.mode === 'navigate' && secFetch.dest && secFetch.dest !== 'document' && secFetch.dest !== 'iframe') {
    out.push('sec-fetch-navigate-non-document');
  }
  return out;
}
