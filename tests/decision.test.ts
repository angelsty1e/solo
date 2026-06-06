import { describe, it, expect } from 'vitest';
import type { AutomationSnapshot, HttpFingerprint, IpFingerprint, TlsFingerprint } from '../src/shared/types.js';
import type { DecisionInput } from '../src/shared/decision/types.js';
import { runDecision } from '../src/shared/decision/engine.js';
import { evaluateLevel } from '../src/shared/decision/level.js';
import { defaultConfig, resolveConfig } from '../src/shared/decision/config.js';

const CHROME_UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';

// A "clean" automation snapshot: a plausible real Chrome with plugins and
// chrome.runtime present, no automation tells.
function cleanAutomation(over: Partial<AutomationSnapshot> = {}): AutomationSnapshot {
  return {
    webdriver: false,
    pluginsLength: 3,
    mimeTypesLength: 2,
    pluginNames: ['PDF Viewer'],
    mimeTypeNames: ['application/pdf'],
    chromeRuntime: true,
    hasNotificationPermission: false,
    inconsistencies: [],
    callPhantom: false,
    nightmare: false,
    selenium: false,
    playwrightHints: [],
    cdpHints: [],
    ...over,
  };
}

function input(over: Partial<AutomationSnapshot> = {}, userAgent: string | null = CHROME_UA): DecisionInput {
  return { automation: cleanAutomation(over), userAgent };
}

const L1 = defaultConfig.levels[0]!;

describe('level 1 — hard confessions force bot', () => {
  const cases: Array<[string, Partial<AutomationSnapshot>]> = [
    ['webdriver', { webdriver: true }],
    ['pw_globals', { playwrightHints: ['__playwright'] }],
    ['cdp_traces', { cdpHints: ['cdc_adoQpoasnfa76pfcZLmcfl_Array'] }],
    ['selenium', { selenium: true }],
    ['phantom', { callPhantom: true }],
    ['nightmare', { nightmare: true }],
    ['headless_ua', { inconsistencies: ['headless-chrome-ua'] }],
  ];

  for (const [id, over] of cases) {
    it(`${id} alone → bot, forced, score 1`, () => {
      const r = evaluateLevel(1,input(over), L1);
      expect(r.verdict).toBe('bot');
      expect(r.forced).toBe(true);
      expect(r.score).toBe(1);
      expect(r.hits.find((h) => h.id === id)?.severity).toBe('hard');
    });
  }

  it('carries the concrete evidence', () => {
    const r = evaluateLevel(1,input({ playwrightHints: ['__playwright', '__pw_foo'] }), L1);
    expect(r.hits.find((h) => h.id === 'pw_globals')?.evidence).toEqual(['__playwright', '__pw_foo']);
  });
});

describe('level 1 — soft signals accumulate to thresholds', () => {
  it('single soft signal below review stays clean', () => {
    // notif_no_focus = 0.15 < review (0.4)
    const r = evaluateLevel(1,input({ inconsistencies: ['notif-denied-no-focus'] }), L1);
    expect(r.verdict).toBe('clean');
    expect(r.forced).toBe(false);
    expect(r.score).toBeCloseTo(0.15);
  });

  it('forged_chrome alone is now a near-zero signal (0.15) → clean', () => {
    // chrome.runtime is often absent on a legit Chrome → deliberately tiny weight
    // so it never triggers 'suspect' on its own (was a false-positive source).
    const r = evaluateLevel(1,input({ chromeRuntime: false }), L1);
    expect(r.verdict).toBe('clean');
    expect(r.score).toBeCloseTo(0.15);
  });

  it('all three soft signals stack to the block threshold → bot, not forced', () => {
    // zero_plugins 0.5 + forged_chrome 0.15 + notif_no_focus 0.15 = 0.8
    const r = evaluateLevel(1,
      input({ chromeRuntime: false, inconsistencies: ['chrome-ua-zero-plugins', 'notif-denied-no-focus'] }),
      L1,
    );
    expect(r.verdict).toBe('bot');
    expect(r.forced).toBe(false);
    expect(r.score).toBeCloseTo(0.8);
  });

  it('zero_plugins (0.5) alone → suspect', () => {
    const r = evaluateLevel(1,input({ inconsistencies: ['chrome-ua-zero-plugins'] }), L1);
    expect(r.verdict).toBe('suspect');
    expect(r.score).toBeCloseTo(0.5);
  });
});

describe('level 1 — neutral / no false positives', () => {
  it('webdriver null is neutral (unknown ≠ bot)', () => {
    const r = evaluateLevel(1,input({ webdriver: null }), L1);
    expect(r.verdict).toBe('clean');
    expect(r.hits.find((h) => h.id === 'webdriver')).toBeUndefined();
  });

  it('clean Chrome → clean with low confidence (L1 cannot vouch for humanity)', () => {
    const r = evaluateLevel(1,input(), L1);
    expect(r.verdict).toBe('clean');
    expect(r.hits).toHaveLength(0);
    expect(r.confidence).toBe(0); // score 0 → confidence 0
  });

  it('forged_chrome does NOT fire on a non-Chrome UA', () => {
    const firefoxUa = 'Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0';
    const r = evaluateLevel(1,input({ chromeRuntime: false }, firefoxUa), L1);
    expect(r.hits.find((h) => h.id === 'forged_chrome')).toBeUndefined();
    expect(r.verdict).toBe('clean');
  });

  it('forged_chrome does NOT fire on an Edge UA (legit fork without chrome.runtime)', () => {
    const edgeUa = CHROME_UA + ' Edg/124.0.0.0';
    const r = evaluateLevel(1,input({ chromeRuntime: false }, edgeUa), L1);
    expect(r.hits.find((h) => h.id === 'forged_chrome')).toBeUndefined();
  });
});

describe('config is tunable', () => {
  it('lowering the review threshold turns a single soft signal into suspect', () => {
    const cfg = resolveConfig({ levels: [{ ...L1, thresholds: { block: 0.8, review: 0.1 } }] });
    const r = evaluateLevel(1,input({ inconsistencies: ['notif-denied-no-focus'] }), cfg.levels[0]!);
    expect(r.verdict).toBe('suspect'); // 0.15 >= 0.1
  });

  it('removing a signal from hardSignals downgrades it to a weighted soft signal', () => {
    const cfg = resolveConfig({
      levels: [
        {
          ...L1,
          hardSignals: L1.hardSignals.filter((s) => s !== 'webdriver'),
          weights: { ...L1.weights, webdriver: 0.3 },
        },
      ],
    });
    const r = evaluateLevel(1,input({ webdriver: true }), cfg.levels[0]!);
    expect(r.forced).toBe(false);
    expect(r.verdict).toBe('clean'); // 0.3 < review (0.4)
    expect(r.hits.find((h) => h.id === 'webdriver')?.severity).toBe('soft');
  });
});

describe('engine aggregation', () => {
  it('produces a stable DecisionResult with version and injected timestamp', () => {
    const r = runDecision(input({ webdriver: true }), defaultConfig, '2026-06-01T00:00:00.000Z');
    expect(r.verdict).toBe('bot');
    expect(r.forced).toBe(true);
    expect(r.configVersion.startsWith(defaultConfig.version)).toBe(true);
    expect(r.configVersion).toMatch(/\+[0-9a-f]{8}$/); // human label + rule-content hash
    expect(r.computedAt).toBe('2026-06-01T00:00:00.000Z');
    expect(r.byLevel.length).toBeGreaterThanOrEqual(1);
  });

  it('skips disabled levels', () => {
    // Hand-built single-level config (not merged with the default) so the
    // result is deterministic regardless of how many levels exist by default.
    const cfg = {
      version: 'test',
      levels: [{ ...L1, enabled: false }],
      aggregate: defaultConfig.aggregate,
      trust: defaultConfig.trust,
    };
    const r = runDecision(input({ webdriver: true }), cfg, '2026-06-01T00:00:00.000Z');
    expect(r.byLevel).toHaveLength(0);
    expect(r.verdict).toBe('unknown');
  });
});

// ─── Level 2 — réseau / contexte (côté serveur) ─────────────────────────────
const L2 = defaultConfig.levels.find((l) => l.level === 2)!;

function browserTls(over: Partial<TlsFingerprint> = {}): TlsFingerprint {
  return {
    version: 0x0303,
    versionName: 'TLS 1.2',
    ciphers: [
      0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f,
      0x0035,
    ],
    extensions: [0, 23, 65281, 10, 11, 35, 16, 5, 13, 18, 51, 45, 43, 27, 17513],
    ellipticCurves: [29, 23, 24],
    ecPointFormats: [0],
    signatureAlgorithms: [0x0403, 0x0804],
    alpn: ['h2', 'http/1.1'],
    sni: 'example.com',
    supportedVersions: [0x0304, 0x0303],
    ja3: 'x',
    ja3Hash: 'browserhash',
    ja4: 't13d1516h2_aaaa_bbbb',
    ...over,
  };
}

function ipFp(over: Partial<IpFingerprint> = {}): IpFingerprint {
  return {
    ip: '203.0.113.7',
    asn: 12345,
    asnOrganization: 'Orange SA',
    country: 'FR',
    isDatacenter: false,
    isProxyHint: false,
    reverseDns: null,
    isTorExit: false,
    tcpRttMs: 42,
    ...over,
  };
}

function httpFp(over: Partial<HttpFingerprint> = {}): HttpFingerprint {
  return {
    method: 'POST',
    path: '/collect',
    httpVersion: '1.1',
    rawHeaders: [],
    headerOrder: ['host', 'user-agent', 'accept'],
    userAgent: CHROME_UA,
    clientHints: {},
    accept: '*/*',
    acceptLanguage: 'fr-FR',
    acceptEncoding: 'gzip',
    secFetch: { site: 'same-origin', mode: 'cors', dest: 'empty', user: null },
    inconsistencies: [],
    ...over,
  };
}

function l2Input(parts: {
  ua?: string;
  tls?: TlsFingerprint | null;
  http?: HttpFingerprint | null;
  ip?: IpFingerprint | null;
}): DecisionInput {
  return {
    automation: cleanAutomation(),
    userAgent: parts.ua ?? CHROME_UA,
    tls: parts.tls ?? null,
    http: parts.http ?? null,
    ip: parts.ip ?? null,
  };
}

describe('level 2 — TLS ↔ UA mismatch', () => {
  it('browser UA + tool-like TLS (no h2) → suspect (0.7)', () => {
    const r = evaluateLevel(2, l2Input({ tls: browserTls({ alpn: [] }) }), L2);
    expect(r.verdict).toBe('suspect');
    expect(r.score).toBeCloseTo(0.7);
    const hit = r.hits.find((h) => h.id === 'tls_ua_mismatch');
    expect(hit).toBeDefined();
    expect(hit?.evidence.join(' ')).toMatch(/h2/);
  });

  it('browser UA + genuine browser TLS → clean', () => {
    const r = evaluateLevel(2, l2Input({ tls: browserTls() }), L2);
    expect(r.hits.find((h) => h.id === 'tls_ua_mismatch')).toBeUndefined();
    expect(r.verdict).toBe('clean');
  });

  it('honest tool UA (curl) is NOT flagged as a lie even with tool TLS', () => {
    const r = evaluateLevel(2, l2Input({ ua: 'curl/8.4.0', tls: browserTls({ alpn: [] }) }), L2);
    expect(r.hits.find((h) => h.id === 'tls_ua_mismatch')).toBeUndefined();
  });

  it('too few cipher suites on a browser UA → mismatch', () => {
    const r = evaluateLevel(2, l2Input({ tls: browserTls({ ciphers: [0x1301, 0x1302] }) }), L2);
    expect(r.hits.find((h) => h.id === 'tls_ua_mismatch')).toBeDefined();
  });
});

describe('level 2 — IP provenance & stacking', () => {
  it('datacenter alone → suspect (0.4)', () => {
    const r = evaluateLevel(2, l2Input({ ip: ipFp({ isDatacenter: true, asnOrganization: 'Amazon' }) }), L2);
    expect(r.verdict).toBe('suspect');
    expect(r.score).toBeCloseTo(0.4);
  });

  it('Tor exit alone → suspect (0.6)', () => {
    const r = evaluateLevel(2, l2Input({ ip: ipFp({ isTorExit: true }) }), L2);
    expect(r.verdict).toBe('suspect');
    expect(r.score).toBeCloseTo(0.6);
  });

  it('TLS lie (0.7) + datacenter (0.4) stack → bot, no hard override', () => {
    const r = evaluateLevel(2, l2Input({ tls: browserTls({ alpn: [] }), ip: ipFp({ isDatacenter: true }) }), L2);
    expect(r.verdict).toBe('bot');
    expect(r.forced).toBe(false);
    expect(r.score).toBe(1); // 1.1 capped
  });

  it('http inconsistencies contribute (0.5)', () => {
    const r = evaluateLevel(2, l2Input({ http: httpFp({ inconsistencies: ['chrome-ua-without-sec-ch-ua'] }) }), L2);
    expect(r.hits.find((h) => h.id === 'http_inconsistencies')).toBeDefined();
    expect(r.score).toBeCloseTo(0.5);
  });

  it('residential IP → clean', () => {
    const r = evaluateLevel(2, l2Input({ ip: ipFp() }), L2);
    expect(r.verdict).toBe('clean');
  });

  it('rtt incoherence fires on a mobile UA with near-zero RTT', () => {
    const mobileUa = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Safari/604.1';
    const r = evaluateLevel(2, l2Input({ ua: mobileUa, ip: ipFp({ tcpRttMs: 0.4 }) }), L2);
    expect(r.hits.find((h) => h.id === 'rtt_incoherence')).toBeDefined();
  });
});

describe('level 2 — server ↔ client coherence', () => {
  function chInput(parts: {
    ua?: string;
    acceptLanguage?: string | null;
    jsLangs?: string[];
    secChUa?: string;
    jsBrands?: Array<{ brand: string; version: string }>;
  }): DecisionInput {
    const http = httpFp({
      acceptLanguage: parts.acceptLanguage ?? null,
      clientHints: parts.secChUa ? { 'sec-ch-ua': parts.secChUa } : {},
    });
    const navigator = { languages: parts.jsLangs ?? [], uaData: parts.jsBrands ? { brands: parts.jsBrands } : null };
    return {
      automation: cleanAutomation(),
      userAgent: parts.ua ?? CHROME_UA,
      http,
      client: { navigator } as unknown as DecisionInput['client'],
    };
  }

  it('Accept-Language ≠ navigator.languages → mismatch, suspect (0.5)', () => {
    const r = evaluateLevel(2, chInput({ acceptLanguage: 'en-US,en;q=0.9', jsLangs: ['fr-FR', 'fr'] }), L2);
    expect(r.hits.find((h) => h.id === 'lang_header_js_mismatch')).toBeDefined();
    expect(r.score).toBeCloseTo(0.5);
  });

  it('matching primary language (region differs) does NOT fire', () => {
    const r = evaluateLevel(2, chInput({ acceptLanguage: 'fr-FR,fr;q=0.9', jsLangs: ['fr-CA', 'fr'] }), L2);
    expect(r.hits.find((h) => h.id === 'lang_header_js_mismatch')).toBeUndefined();
  });

  it('Sec-CH-UA brands ≠ userAgentData brands → mismatch', () => {
    const r = evaluateLevel(
      2,
      chInput({
        secChUa: '"Chromium";v="124", "Google Chrome";v="124", "Not.A/Brand";v="99"',
        jsBrands: [
          { brand: 'Chromium', version: '124' },
          { brand: 'Microsoft Edge', version: '124' },
          { brand: 'Not.A/Brand', version: '99' },
        ],
      }),
      L2,
    );
    expect(r.hits.find((h) => h.id === 'client_hints_ua_mismatch')).toBeDefined();
  });

  it('identical brands (GREASE ignored) do NOT fire', () => {
    const r = evaluateLevel(
      2,
      chInput({
        secChUa: '"Chromium";v="124", "Google Chrome";v="124", "Not.A/Brand";v="99"',
        jsBrands: [
          { brand: 'Chromium', version: '124' },
          { brand: 'Google Chrome', version: '124' },
          { brand: 'Not-A.Brand', version: '8' }, // different GREASE form, still ignored
        ],
      }),
      L2,
    );
    expect(r.hits.find((h) => h.id === 'client_hints_ua_mismatch')).toBeUndefined();
    expect(r.verdict).toBe('clean');
  });

  it('client hints absent on one side does NOT fire (covered by N3)', () => {
    const r = evaluateLevel(2, chInput({ secChUa: '"Chromium";v="124"', jsBrands: undefined }), L2);
    expect(r.hits.find((h) => h.id === 'client_hints_ua_mismatch')).toBeUndefined();
  });
});

describe('engine aggregation across N1/N2', () => {
  it('L1 clean + L2 presumption → overall suspect', () => {
    const r = runDecision(l2Input({ ip: ipFp({ isDatacenter: true }) }), defaultConfig, '2026-06-01T00:00:00.000Z');
    expect(r.verdict).toBe('suspect');
    expect(r.byLevel.find((l) => l.level === 2)?.verdict).toBe('suspect');
  });

  it('an L1 confession dominates the aggregate even on a clean network', () => {
    const r = runDecision(
      { ...l2Input({ tls: browserTls() }), automation: cleanAutomation({ webdriver: true }) },
      defaultConfig,
      '2026-06-01T00:00:00.000Z',
    );
    expect(r.verdict).toBe('bot');
    expect(r.forced).toBe(true);
  });
});

// ─── Level 3 — cohérence d'environnement ─────────────────────────────────────
// Coherence signals are all soft (a contradiction is a presumption, never an
// avowal). We craft minimal client snapshots — only the fields a signal reads —
// and cast, since detect() guards every access with optional chaining.
const L3 = defaultConfig.levels.find((l) => l.level === 3)!;

// A coherent Windows/Chrome navigator: matching platform, non-empty languages,
// userAgentData with brands. On its own it fires nothing.
function coherentClient(over: Record<string, unknown> = {}): DecisionInput['client'] {
  return {
    navigator: {
      platform: 'Win32',
      languages: ['fr-FR', 'fr'],
      uaData: { brands: [{ brand: 'Chromium', version: '124' }] },
    },
    ...over,
  } as unknown as DecisionInput['client'];
}

function l3Input(
  client: DecisionInput['client'],
  userAgent: string | null = CHROME_UA,
  ip: IpFingerprint | null = null,
): DecisionInput {
  return { automation: cleanAutomation(), userAgent, ip, client };
}

describe('level 3 — coherence: a single contradiction → suspect', () => {
  const cases: Array<[string, DecisionInput['client'], number]> = [
    [
      'env_platform_os_mismatch',
      coherentClient({ navigator: { platform: 'Linux x86_64', languages: ['fr'], uaData: { brands: [{}] } } }),
      0.6,
    ],
    [
      'env_languages_empty',
      coherentClient({ navigator: { platform: 'Win32', languages: [], uaData: { brands: [{}] } } }),
      0.5,
    ],
    ['env_software_gpu', coherentClient({ webgl: { unmaskedRenderer: 'Google SwiftShader', renderer: null } }), 0.65],
    ['env_engine_ua_mismatch', coherentClient({ engine: { detectedEngine: 'spidermonkey' } }), 0.65],
  ];

  for (const [id, client, weight] of cases) {
    it(`${id} (${weight}) alone → suspect, soft`, () => {
      const r = evaluateLevel(3, l3Input(client), L3);
      expect(r.verdict).toBe('suspect');
      expect(r.forced).toBe(false);
      expect(r.score).toBeCloseTo(weight);
      expect(r.hits.find((h) => h.id === id)?.severity).toBe('soft');
    });
  }
});

describe('level 3 — coherence: stacking & no false positives', () => {
  it('two strong contradictions accumulate to bot (never forced)', () => {
    const client = coherentClient({
      navigator: { platform: 'Linux x86_64', languages: ['fr'], uaData: { brands: [{}] } }, // mismatch 0.6
      engine: { detectedEngine: 'javascriptcore' }, // mismatch 0.65
    });
    const r = evaluateLevel(3, l3Input(client), L3);
    expect(r.verdict).toBe('bot');
    expect(r.forced).toBe(false);
    expect(r.score).toBe(1); // 1.25 capped
  });

  it('a fully coherent Windows/Chrome environment fires nothing', () => {
    const r = evaluateLevel(3, l3Input(coherentClient()), L3);
    expect(r.verdict).toBe('clean');
    expect(r.hits).toHaveLength(0);
  });

  it('engine mismatch does NOT fire when the engine is unknown', () => {
    const r = evaluateLevel(3, l3Input(coherentClient({ engine: { detectedEngine: 'unknown' } })), L3);
    expect(r.hits.find((h) => h.id === 'env_engine_ua_mismatch')).toBeUndefined();
  });

  it('locale ↔ IP mismatch fires only when the IP country differs', () => {
    const client = coherentClient({ locale: { resolvedOptionsLocale: 'fr-FR' } });
    const match = evaluateLevel(3, l3Input(client, CHROME_UA, { country: 'FR' } as IpFingerprint), L3);
    expect(match.hits.find((h) => h.id === 'env_locale_ip_mismatch')).toBeUndefined();
    const mismatch = evaluateLevel(3, l3Input(client, CHROME_UA, { country: 'US' } as IpFingerprint), L3);
    expect(mismatch.hits.find((h) => h.id === 'env_locale_ip_mismatch')?.severity).toBe('soft');
  });
});

describe('level 3 — Mac/Safari false-positive regressions', () => {
  const SAFARI_UA =
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15';
  const macNav = { platform: 'MacIntel', languages: ['fr-FR'], uaData: null };

  it('Safari (JSC seen as spidermonkey) does NOT fire engine mismatch — both non-V8', () => {
    const client = coherentClient({ navigator: macNav, engine: { detectedEngine: 'spidermonkey' } });
    const r = evaluateLevel(3, l3Input(client, SAFARI_UA), L3);
    expect(r.hits.find((h) => h.id === 'env_engine_ua_mismatch')).toBeUndefined();
    expect(r.verdict).toBe('clean');
  });

  it('a Safari UA actually running V8 (headless Chrome lying) DOES fire', () => {
    const client = coherentClient({ navigator: macNav, engine: { detectedEngine: 'v8' } });
    const r = evaluateLevel(3, l3Input(client, SAFARI_UA), L3);
    expect(r.hits.find((h) => h.id === 'env_engine_ua_mismatch')).toBeDefined();
  });

  it('mDNS .local host candidate counts as local IP → no WebRTC false positive', () => {
    const client = coherentClient({
      navigator: macNav,
      webrtc: {
        localIps: [],
        publicIp: null,
        error: null,
        candidates: ['candidate:1 1 UDP 2122260223 9b36eef0-abcd.local 53421 typ host'],
      },
    });
    const r = evaluateLevel(3, l3Input(client, SAFARI_UA), L3);
    expect(r.hits.find((h) => h.id === 'env_webrtc_no_local_ip')).toBeUndefined();
  });

  it('no host candidate at all → WebRTC signal still fires (bare environment)', () => {
    const client = coherentClient({
      navigator: macNav,
      webrtc: { localIps: [], publicIp: null, error: null, candidates: [] },
    });
    const r = evaluateLevel(3, l3Input(client, SAFARI_UA), L3);
    expect(r.hits.find((h) => h.id === 'env_webrtc_no_local_ip')).toBeDefined();
  });
});

// ─── Level 4 — comportement ──────────────────────────────────────────────────
const L4 = defaultConfig.levels.find((l) => l.level === 4)!;

// A human-like behavioral snapshot: enough samples, with natural variance and
// curvature. On its own it fires nothing.
function behavioral(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    totalEvents: 200,
    durationMs: 8000,
    mouse: { moves: 120, clicks: 3, meanSpeed: 1.2, stdSpeed: 0.6, meanCurvature: 0.4, stillRatio: 0.3, jitterRatio: 0.2 },
    keyboard: { keydowns: 20, keyups: 20, meanDwellMs: 90, stdDwellMs: 25, meanFlightMs: 140, stdFlightMs: 40, backspaceRatio: 0.05 },
    scroll: { events: 30, totalDeltaPx: 4000, meanDeltaPx: 130, linearRatio: 0.6 },
    touch: { starts: 0, moves: 0, ends: 0, meanPressure: 0, multiTouchMax: 0 },
    ...over,
  };
}

function behInput(b: Record<string, unknown>): DecisionInput {
  return { automation: cleanAutomation(), userAgent: CHROME_UA, client: { behavioral: b } as unknown as DecisionInput['client'] };
}

describe('level 4 — behaviour: synthetic patterns', () => {
  it('a human-like snapshot fires nothing → clean', () => {
    const r = evaluateLevel(4, behInput(behavioral()), L4);
    expect(r.verdict).toBe('clean');
    expect(r.hits).toHaveLength(0);
  });

  it('straight-line mouse (curvature 0) on 120 moves → mouse_synthetic, suspect', () => {
    const b = behavioral({ mouse: { moves: 120, meanSpeed: 1.2, stdSpeed: 0.6, meanCurvature: 0, jitterRatio: 0.2 } });
    const r = evaluateLevel(4, behInput(b), L4);
    expect(r.hits.find((h) => h.id === 'beh_mouse_synthetic')).toBeDefined();
    expect(r.verdict).toBe('suspect');
    expect(r.score).toBeCloseTo(0.45);
  });

  it('perfectly linear scroll → scroll_linear', () => {
    const b = behavioral({ scroll: { events: 30, linearRatio: 1 } });
    const r = evaluateLevel(4, behInput(b), L4);
    expect(r.hits.find((h) => h.id === 'beh_scroll_linear')).toBeDefined();
  });

  it('zero keystroke timing variance → keystroke_robotic', () => {
    const b = behavioral({ keyboard: { keydowns: 20, stdDwellMs: 0, stdFlightMs: 0 } });
    const r = evaluateLevel(4, behInput(b), L4);
    expect(r.hits.find((h) => h.id === 'beh_keystroke_robotic')).toBeDefined();
  });

  it('two synthetic tells stack → bot (never forced)', () => {
    const b = behavioral({
      mouse: { moves: 120, meanSpeed: 1.2, stdSpeed: 0.6, meanCurvature: 0, jitterRatio: 0.2 }, // 0.45
      scroll: { events: 30, linearRatio: 1 }, // 0.4
    });
    const r = evaluateLevel(4, behInput(b), L4);
    expect(r.verdict).toBe('bot');
    expect(r.forced).toBe(false);
    expect(r.score).toBeCloseTo(0.85);
  });

  it('low sample size does NOT trip the mouse heuristic (conservative)', () => {
    const b = behavioral({ mouse: { moves: 10, meanSpeed: 1, stdSpeed: 0, meanCurvature: 0, jitterRatio: 0 } });
    const r = evaluateLevel(4, behInput(b), L4);
    expect(r.hits.find((h) => h.id === 'beh_mouse_synthetic')).toBeUndefined();
    expect(r.hits.find((h) => h.id === 'beh_mouse_constant_speed')).toBeUndefined();
  });

  it('no interaction at all is a weak signal (0.2) → stays clean alone', () => {
    const b = behavioral({ totalEvents: 0, durationMs: 8000, mouse: { moves: 0 }, scroll: { events: 0 }, keyboard: { keydowns: 0 } });
    const r = evaluateLevel(4, behInput(b), L4);
    expect(r.hits.find((h) => h.id === 'beh_no_interaction')).toBeDefined();
    expect(r.verdict).toBe('clean');
    expect(r.score).toBeCloseTo(0.2);
  });
});

// ─── Trust credit & the positive 'human' verdict ─────────────────────────────
function humanClient(over: Record<string, unknown> = {}): DecisionInput['client'] {
  return {
    navigator: {
      platform: 'Win32',
      languages: ['fr-FR', 'fr'],
      userAgent: CHROME_UA,
      uaData: { brands: [{ brand: 'Chromium', version: '124' }] },
    },
    behavioral: behavioral(), // organic → liveness
    webgl: { unmaskedRenderer: 'NVIDIA GeForce RTX 3060', renderer: 'ANGLE' },
    ...over,
  } as unknown as DecisionInput['client'];
}

function fullInput(over: Partial<DecisionInput> = {}): DecisionInput {
  return {
    automation: cleanAutomation(),
    userAgent: CHROME_UA,
    tls: browserTls(),
    http: httpFp({ acceptLanguage: 'fr-FR,fr;q=0.9' }),
    ip: ipFp(), // residential
    client: humanClient(),
    ...over,
  };
}

describe('trust credit & human verdict', () => {
  it('a coherent human with organic behaviour → verdict human, high trust', () => {
    const r = runDecision(fullInput(), defaultConfig, '2026-06-01T00:00:00.000Z');
    expect(r.verdict).toBe('human');
    expect(r.trustScore).toBeGreaterThanOrEqual(0.5);
    expect(r.trustSignals.find((t) => t.id === 'trust_behavior_human')).toBeDefined();
  });

  it('passive-only trust (no behaviour) cannot reach human → clean', () => {
    // Strip behavioural liveness; keep passive credits ≥ humanThreshold.
    const client = humanClient({ behavioral: { totalEvents: 0, durationMs: 8000, mouse: { moves: 0 }, scroll: { events: 0 }, keyboard: { keydowns: 0 } } });
    const r = runDecision(fullInput({ client }), defaultConfig, '2026-06-01T00:00:00.000Z');
    expect(r.trustSignals.find((t) => t.id === 'trust_behavior_human')).toBeUndefined();
    expect(r.verdict).toBe('clean');
  });

  it('trust offsets a network presumption (VPN human) → clean, never bot', () => {
    // Proxy IP alone = 0.4 (suspect); organic behaviour + coherence offsets it
    // below review (0.25). But a proxy IP yields NO residential corroboration, so
    // the positive 'human' label is gated off (trust.serverCorroborated false) —
    // a VPN is not proof of humanity. Result: 'clean' (cleared, not vouched), and
    // crucially never 'bot'. The residential case below keeps 'human'.
    const r = runDecision(fullInput({ ip: ipFp({ isProxyHint: true }) }), defaultConfig, '2026-06-01T00:00:00.000Z');
    expect(r.verdict).toBe('clean');
  });

  it('a hard confession is immune to trust (stays bot despite organic behaviour)', () => {
    const r = runDecision(
      { ...fullInput(), automation: cleanAutomation({ webdriver: true }) },
      defaultConfig,
      '2026-06-01T00:00:00.000Z',
    );
    expect(r.verdict).toBe('bot');
    expect(r.forced).toBe(true);
  });
});

// ─── Trust forgery resistance — a forged client payload can't mint 'human' ────
// Every trust signal except residential-IP is client-forgeable: a bot can post
// organic-looking behaviour, a real-GPU string and a coherent navigator. The
// forgeable-offset cap (config.trust.maxForgeableOffset) lets that credit shed a
// moderate presumption but never whitewash a strong/stacked SERVER signal.
describe('trust credit — forgery resistance', () => {
  it('forged client trust + TLS↔UA lie + datacenter IP → bot (not human)', () => {
    const r = runDecision(
      fullInput({ tls: browserTls({ alpn: [] }), ip: ipFp({ isDatacenter: true }) }),
      defaultConfig,
      '2026-06-01T00:00:00.000Z',
    );
    // N2 = tls_ua_mismatch 0.7 + ip_datacenter 0.4 = 1.0 (capped). Forgeable
    // credit offsets at most 0.15 → net 0.85 → stays bot, despite full trust.
    expect(r.verdict).toBe('bot');
    expect(r.trustScore).toBeGreaterThanOrEqual(0.5); // full credit is still high…
  });

  it('forged client trust + TLS↔UA lie alone → suspect (not human)', () => {
    // No IP signals (ip: null) so only the 0.7 TLS lie remains; capped offset
    // 0.15 → net 0.55 → suspect. Pre-fix (offset = full ~0.85) this was 'human'.
    const r = runDecision(
      fullInput({ tls: browserTls({ alpn: [] }), ip: null }),
      defaultConfig,
      '2026-06-01T00:00:00.000Z',
    );
    expect(r.verdict).toBe('suspect');
  });

  it('forged client trust on a Tor exit → suspect (not human)', () => {
    // ip_tor 0.6 − capped offset 0.15 = 0.45 ≥ review → suspect.
    const r = runDecision(fullInput({ ip: ipFp({ isTorExit: true }) }), defaultConfig, '2026-06-01T00:00:00.000Z');
    expect(r.verdict).toBe('suspect');
  });

  it('a lone forged behavioural blob (no other tell) cannot reach human → clean', () => {
    // Only the liveness anchor fires (forgeable + uncorroborated) → the
    // corroboration gate denies the positive label.
    const client = { behavioral: behavioral() } as unknown as DecisionInput['client'];
    const r = runDecision(
      { automation: cleanAutomation(), userAgent: CHROME_UA, client },
      defaultConfig,
      '2026-06-01T00:00:00.000Z',
    );
    expect(r.trustSignals.find((t) => t.id === 'trust_behavior_human')).toBeDefined();
    expect(r.verdict).toBe('clean');
  });

  it('the cap does NOT push a real human escaping one VPN presumption to bot/suspect', () => {
    // Regression guard for the legitimate case: proxy 0.4 − 0.15 = 0.25 < review,
    // so the VPN human is NOT inculpated (never bot, never suspect). The positive
    // 'human' label is reserved for a residential anchor (serverCorroborated), so
    // on a proxy IP the right landing is 'clean' — see the trust-credit suite.
    const r = runDecision(fullInput({ ip: ipFp({ isProxyHint: true }) }), defaultConfig, '2026-06-01T00:00:00.000Z');
    expect(r.verdict).toBe('clean');
    expect(r.verdict).not.toBe('bot');
  });

  it('a residential human with full forgeable credit still earns the positive human label', () => {
    // The fix gates 'human' on a SERVER-corroborated credit; this is that anchor.
    // A real residential IP (ipFp default: not datacenter/proxy/Tor) fires
    // trust_residential_ip → serverCorroborated → the positive label is allowed.
    const r = runDecision(fullInput(), defaultConfig, '2026-06-01T00:00:00.000Z');
    expect(r.trustSignals.find((t) => t.id === 'trust_residential_ip')).toBeDefined();
    expect(r.verdict).toBe('human');
  });
});

// ─── TLS profiling — rich-field structural detection (beyond h2 + 5 ciphers) ──
describe('level 2 — TLS rich-field profiling', () => {
  it('h2 + full cipher list but no TLS 1.3 advertised → mismatch', () => {
    const r = evaluateLevel(2, l2Input({ tls: browserTls({ supportedVersions: [0x0303], version: 0x0303 }) }), L2);
    const hit = r.hits.find((h) => h.id === 'tls_ua_mismatch');
    expect(hit).toBeDefined();
    expect(hit?.evidence.join(' ')).toMatch(/TLS 1\.3/);
  });

  it('TLS 1.3 advertised but no key_share extension → mismatch (incomplete handshake)', () => {
    // Drop key_share (51) from the extension list.
    const r = evaluateLevel(2, l2Input({ tls: browserTls({ extensions: [0, 23, 65281, 10, 11, 13, 43] }) }), L2);
    expect(r.hits.find((h) => h.id === 'tls_ua_mismatch')).toBeDefined();
  });

  it('no X25519 among the offered curves → mismatch', () => {
    const r = evaluateLevel(2, l2Input({ tls: browserTls({ ellipticCurves: [23, 24] }) }), L2);
    expect(r.hits.find((h) => h.id === 'tls_ua_mismatch')).toBeDefined();
  });

  it('a genuine modern-browser hello (h2, TLS1.3, key_share, X25519) → no mismatch', () => {
    const r = evaluateLevel(2, l2Input({ tls: browserTls() }), L2);
    expect(r.hits.find((h) => h.id === 'tls_ua_mismatch')).toBeUndefined();
  });

  it('matchToolSignature names a TLS-1.2-only tool wearing a browser UA', () => {
    const r = evaluateLevel(2, l2Input({ tls: browserTls({ supportedVersions: [0x0303], version: 0x0303 }) }), L2);
    const hit = r.hits.find((h) => h.id === 'tls_ua_mismatch');
    expect(hit?.evidence.join(' ')).toMatch(/profil reconnu/);
  });
});

// ─── Level 5 — réputation (agrégat cross-session) ────────────────────────────
const L5 = defaultConfig.levels.find((l) => l.level === 5)!;

function repInput(fpDistinctIps: number): DecisionInput {
  return {
    automation: cleanAutomation(),
    userAgent: CHROME_UA,
    reputation: { fpDistinctIps, fpTotalSessions: fpDistinctIps + 2 },
  };
}

describe('level 5 — fingerprint reputation', () => {
  it('same fingerprint on ≥4 distinct IPs → suspect (0.6)', () => {
    const r = evaluateLevel(5, repInput(4), L5);
    expect(r.hits.find((h) => h.id === 'rep_fp_many_ips')).toBeDefined();
    expect(r.verdict).toBe('suspect');
    expect(r.score).toBeCloseTo(0.6);
  });

  it('3 distinct IPs is below the threshold → no fire (mobile/VPN tolerance)', () => {
    const r = evaluateLevel(5, repInput(3), L5);
    expect(r.hits.find((h) => h.id === 'rep_fp_many_ips')).toBeUndefined();
    expect(r.verdict).toBe('clean');
  });

  it('no reputation data → no fire', () => {
    const r = evaluateLevel(5, { automation: cleanAutomation(), userAgent: CHROME_UA }, L5);
    expect(r.hits).toHaveLength(0);
  });

  it('a swarm (≥10 IPs) escalates within level 5 → bot', () => {
    // many_ips 0.6 + swarm 0.4 = 1.0 (same level sums) → bot, on its own.
    const r = evaluateLevel(5, repInput(12), L5);
    expect(r.hits.find((h) => h.id === 'rep_fp_swarm')).toBeDefined();
    expect(r.verdict).toBe('bot');
    expect(r.forced).toBe(false);
    expect(r.score).toBeCloseTo(1);
  });

  it('cross-level aggregation takes the MAX, not the sum (conservative)', () => {
    // Reuse (L5 0.6) + datacenter (L2 0.4): max = 0.6 → suspect, not bot. A
    // single dimension presumption never escalates another's; avoids piling up
    // weak independent signals into false positives.
    const r = runDecision(
      {
        automation: cleanAutomation(),
        userAgent: CHROME_UA,
        ip: ipFp({ isDatacenter: true }),
        reputation: { fpDistinctIps: 5, fpTotalSessions: 9 },
      },
      defaultConfig,
      '2026-06-01T00:00:00.000Z',
    );
    expect(r.verdict).toBe('suspect');
  });
});
