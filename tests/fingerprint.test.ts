import { createHash } from 'node:crypto';
import { describe, it, expect } from 'vitest';
import {
  isGrease,
  parseClientHello,
  negotiatedVersion,
} from '../src/server/tls/clienthello.js';
import { computeJa3 } from '../src/server/tls/ja3.js';
import { computeJa4 } from '../src/server/tls/ja4.js';
import { captureHttpFingerprint } from '../src/server/http/headers.js';

// ─── ClientHello builder (just enough to exercise the parser deterministically) ─
function u8(n: number): Buffer {
  return Buffer.from([n & 0xff]);
}
function u16(n: number): Buffer {
  const b = Buffer.alloc(2);
  b.writeUInt16BE(n & 0xffff);
  return b;
}
function u24(n: number): Buffer {
  return Buffer.from([(n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff]);
}
function u16list(values: number[]): Buffer {
  return Buffer.concat(values.map(u16));
}
function ext(type: number, data: Buffer): Buffer {
  return Buffer.concat([u16(type), u16(data.length), data]);
}

function buildClientHello(): Buffer {
  // GREASE values are deliberately mixed in to verify they are filtered.
  const ciphers = u16list([0x0a0a, 0x1301, 0x1302, 0xc02b]);

  const host = Buffer.from('example.com', 'utf8');
  const sniEntry = Buffer.concat([u8(0), u16(host.length), host]);
  const sni = ext(0x0000, Buffer.concat([u16(sniEntry.length), sniEntry]));

  const protos = Buffer.concat([
    Buffer.concat([u8(2), Buffer.from('h2')]),
    Buffer.concat([u8(8), Buffer.from('http/1.1')]),
  ]);
  const alpn = ext(0x0010, Buffer.concat([u16(protos.length), protos]));

  const versions = u16list([0x0a0a, 0x0304, 0x0303]);
  const supportedVersions = ext(0x002b, Buffer.concat([u8(versions.length), versions]));

  const groups = u16list([0x0a0a, 0x001d, 0x0017]);
  const supportedGroups = ext(0x000a, Buffer.concat([u16(groups.length), groups]));

  const formats = Buffer.from([0x00]);
  const ecPointFormats = ext(0x000b, Buffer.concat([u8(formats.length), formats]));

  const sigs = u16list([0x0403, 0x0804]);
  const sigAlgs = ext(0x000d, Buffer.concat([u16(sigs.length), sigs]));

  const greaseExt = ext(0x1a1a, Buffer.alloc(0));

  const extensions = Buffer.concat([sni, alpn, supportedVersions, supportedGroups, ecPointFormats, sigAlgs, greaseExt]);

  const body = Buffer.concat([
    u16(0x0303), // legacy_version
    Buffer.alloc(32), // random
    u8(0), // session_id length
    u16(ciphers.length),
    ciphers,
    u8(1), // compression methods length
    u8(0), // null compression
    u16(extensions.length),
    extensions,
  ]);

  const handshake = Buffer.concat([u8(0x01), u24(body.length), body]);
  return Buffer.concat([u8(0x16), u16(0x0301), u16(handshake.length), handshake]);
}

describe('isGrease', () => {
  it('recognises GREASE values (RFC 8701)', () => {
    expect(isGrease(0x0a0a)).toBe(true);
    expect(isGrease(0x1a1a)).toBe(true);
    expect(isGrease(0xfafa)).toBe(true);
  });
  it('rejects real values', () => {
    expect(isGrease(0x1301)).toBe(false);
    expect(isGrease(0x0a0b)).toBe(false);
    expect(isGrease(0x0303)).toBe(false);
  });
});

describe('parseClientHello', () => {
  const parsed = parseClientHello(buildClientHello());

  it('extracts SNI and ALPN', () => {
    expect(parsed.sni).toBe('example.com');
    expect(parsed.alpn).toEqual(['h2', 'http/1.1']);
  });

  it('keeps raw ciphers/curves/extensions in wire order (GREASE retained at parse time)', () => {
    expect(parsed.cipherSuites).toEqual([0x0a0a, 0x1301, 0x1302, 0xc02b]);
    expect(parsed.ellipticCurves).toEqual([0x0a0a, 0x001d, 0x0017]);
    expect(parsed.signatureAlgorithms).toEqual([0x0403, 0x0804]);
    expect(parsed.supportedVersions).toEqual([0x0a0a, 0x0304, 0x0303]);
    expect(parsed.extensionTypes).toEqual([0x0000, 0x0010, 0x002b, 0x000a, 0x000b, 0x000d, 0x1a1a]);
  });

  it('negotiates TLS 1.3 when advertised in supported_versions', () => {
    expect(negotiatedVersion(parsed)).toBe(0x0304);
  });

  it('throws on a non-handshake record instead of reading out of bounds', () => {
    expect(() => parseClientHello(Buffer.from([0x17, 0x03, 0x03, 0x00, 0x01, 0x00]))).toThrow();
  });

  it('throws on a truncated buffer (DoS safety)', () => {
    const full = buildClientHello();
    expect(() => parseClientHello(full.subarray(0, 10))).toThrow();
  });
});

describe('computeJa3', () => {
  const parsed = parseClientHello(buildClientHello());
  const { ja3, ja3Hash } = computeJa3(parsed);

  it('builds the canonical JA3 string with GREASE stripped', () => {
    expect(ja3).toBe('771,4865-4866-49195,0-16-43-10-11-13,29-23,0');
  });

  it('hashes it with MD5', () => {
    expect(ja3Hash).toBe(createHash('md5').update(ja3).digest('hex'));
    expect(ja3Hash).toMatch(/^[0-9a-f]{32}$/);
  });

  it('is deterministic', () => {
    expect(computeJa3(parsed).ja3Hash).toBe(ja3Hash);
  });
});

describe('computeJa4', () => {
  const parsed = parseClientHello(buildClientHello());
  const { ja4 } = computeJa4(parsed);

  it('encodes the human-readable prefix (t, TLS1.3, SNI, 3 ciphers, 6 exts, h2)', () => {
    expect(ja4.startsWith('t13d0306h2_')).toBe(true);
  });

  it('matches the full JA4 shape', () => {
    expect(ja4).toMatch(/^t13d0306h2_[0-9a-f]{12}_[0-9a-f]{12}$/);
  });

  it('is deterministic', () => {
    expect(computeJa4(parsed).ja4).toBe(ja4);
  });
});

describe('captureHttpFingerprint inconsistency detection', () => {
  const req = {
    method: 'GET',
    url: '/',
    httpVersion: '1.1',
    rawHeaders: ['User-Agent', 'Mozilla/5.0 Chrome/120.0', 'Host', 'lab.local', 'Accept', '*/*'],
    headers: {
      'user-agent': 'Mozilla/5.0 Chrome/120.0',
      host: 'lab.local',
      accept: '*/*',
    },
  } as unknown as import('node:http').IncomingMessage;

  const fp = captureHttpFingerprint(req);

  it('flags a Chrome UA without sec-ch-ua / sec-fetch', () => {
    expect(fp.inconsistencies).toContain('chrome-ua-without-sec-ch-ua');
    expect(fp.inconsistencies).toContain('chrome-without-sec-fetch');
  });

  it('flags Host appearing after User-Agent', () => {
    expect(fp.inconsistencies).toContain('host-after-user-agent');
  });

  it('flags a missing Accept-Language', () => {
    expect(fp.inconsistencies).toContain('missing-accept-language');
  });

  it('preserves on-the-wire header order', () => {
    expect(fp.headerOrder).toEqual(['user-agent', 'host', 'accept']);
  });

  // Previously-untested branches (headers.ts: sec-ch-mobile-mismatch and
  // sec-fetch-navigate-non-document).
  const req2 = {
    method: 'GET',
    url: '/',
    httpVersion: '1.1',
    rawHeaders: [
      'Host', 'lab.local',
      'User-Agent', 'Mozilla/5.0 Chrome/120.0',
      'Accept-Language', 'fr',
      'Sec-CH-UA', '"Chromium";v="120"',
      'Sec-CH-UA-Mobile', '?1',
      'Sec-Fetch-Mode', 'navigate',
      'Sec-Fetch-Dest', 'empty',
      'Sec-Fetch-Site', 'none',
    ],
    headers: {
      host: 'lab.local',
      'user-agent': 'Mozilla/5.0 Chrome/120.0',
      'accept-language': 'fr',
      'sec-ch-ua': '"Chromium";v="120"',
      'sec-ch-ua-mobile': '?1',
      'sec-fetch-mode': 'navigate',
      'sec-fetch-dest': 'empty',
      'sec-fetch-site': 'none',
    },
  } as unknown as import('node:http').IncomingMessage;

  const fp2 = captureHttpFingerprint(req2);

  it('flags Sec-CH-UA-Mobile=?1 on a non-mobile UA', () => {
    expect(fp2.inconsistencies).toContain('sec-ch-mobile-mismatch');
  });

  it('flags a navigate request whose Sec-Fetch-Dest is not a document', () => {
    expect(fp2.inconsistencies).toContain('sec-fetch-navigate-non-document');
  });
});
