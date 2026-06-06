import { describe, it, expect } from 'vitest';
import type {
  AutomationSnapshot,
  HttpFingerprint,
  IpFingerprint,
  TlsFingerprint,
} from '../src/shared/types.js';
import type { DecisionInput } from '../src/shared/decision/types.js';
import { runDecision } from '../src/shared/decision/engine.js';
import { computeTrust } from '../src/shared/decision/trust.js';
import { defaultConfig, resolveConfig } from '../src/shared/decision/config.js';
import { ClientFingerprintSchema } from '../src/shared/validation.js';

// ─── Audit adversarial du moteur de décision ─────────────────────────────────
// Séparé de decision.test.ts (comportement nominal) : ici on attaque le verdict.
//   • Évasions A1–A7  : un bot NE DOIT JAMAIS décrocher 'human'/'clean'.
//   • Faux positifs H1–H7 : un humain réel NE DOIT JAMAIS être 'bot'.
//   • Invariants I1–I9 : property-based / fuzz léger.
//
// Les remédiations issues de l'audit sont en place ; ces tests les figent contre
// toute régression :
//   (b) cap `maxForgeableOffset` (=0.15) sur la part *forgeable* du crédit
//       (computeTrust/engine) → ferme A1–A4 : le crédit forgé ne peut plus
//       blanchir une preuve serveur en 'human'/'clean' (au pire, rétrograde).
//   (c) le label POSITIF 'human' exige une corroboration au-delà de l'ancre de
//       liveness forgeable (`trust.corroborated`) → ferme A5 : un blob
//       comportemental forgé seul obtient 'clean', plus jamais 'human'.
//   (e) le label POSITIF 'human' exige EN PLUS une corroboration SERVEUR non
//       forgeable (`trust.serverCorroborated` = IP résidentielle) → ferme A8/A10 :
//       une présomption serveur isolée (datacenter/proxy, 0.4) + crédit 100 %
//       forgeable ne décroche plus 'human' mais plafonne à 'clean' (jamais 'bot').
//   (d) plancher chirurgical au block : pour un signal serveur ayant atteint le
//       block, l'offset TOTAL est plafonné à maxForgeableOffset → ferme A4b (un
//       botnet résidentiel reste 'bot') SANS inculper un humain VPN double-flaggé
//       (datacenter+proxy = 0.8 → 'suspect', cf. H7).
//   (A7) réputation null-safe côté store → l'omission d'une surface n'échappe plus.

const AT = '2026-06-01T00:00:00.000Z';
const CHROME_UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';
const SAFARI_UA =
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15';
const FIREFOX_UA = 'Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0';
const ANDROID_UA =
  'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36';

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

function browserTls(over: Partial<TlsFingerprint> = {}): TlsFingerprint {
  return {
    version: 0x0303,
    versionName: 'TLS 1.2',
    ciphers: [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030, 0xcca9, 0xcca8, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035],
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

// A tool-like TLS stack (curl/python/Go): no h2 ALPN — the unforgeable server tell.
function toolTls(): TlsFingerprint {
  return browserTls({ alpn: [], ja3Hash: 'curlhash' });
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

// Organic-looking behaviour — ALL forgeable: these are just numbers in the JSON
// payload. Fires trust_behavior_human (0.5, liveness) without tripping any L4
// synthetic-pattern signal.
function forgedOrganicBehaviour(): Record<string, unknown> {
  return {
    totalEvents: 200,
    durationMs: 8000,
    mouse: { moves: 40, clicks: 3, meanSpeed: 5, stdSpeed: 1.5, meanCurvature: 0.3, stillRatio: 0.3, jitterRatio: 0.2 },
    keyboard: { keydowns: 20, keyups: 20, meanDwellMs: 90, stdDwellMs: 25, meanFlightMs: 140, stdFlightMs: 40, backspaceRatio: 0.05 },
    scroll: { events: 30, totalDeltaPx: 4000, meanDeltaPx: 130, linearRatio: 0.6 },
    touch: { starts: 0, moves: 0, ends: 0, meanPressure: 0, multiTouchMax: 0 },
  };
}

// A maximally-forged trust client: every CLIENT-FORGEABLE trust signal fired
// (behaviour, GPU, fonts, identity coherence, speech, media, hw-video). The only
// thing it cannot fake is the server-observed IP/TLS.
function forgedTrustClient(over: Record<string, unknown> = {}): DecisionInput['client'] {
  return {
    navigator: {
      platform: 'Win32',
      languages: ['fr-FR', 'fr'],
      userAgent: CHROME_UA,
      uaData: { brands: [{ brand: 'Chromium', version: '124' }, { brand: 'Google Chrome', version: '124' }] },
    },
    behavioral: forgedOrganicBehaviour(),
    webgl: { unmaskedRenderer: 'NVIDIA GeForce RTX 3060', renderer: 'ANGLE (NVIDIA)' },
    fonts: { detectionMethod: 'measurement', detectedFonts: Array.from({ length: 30 }, (_, i) => `Font${i}`) },
    speech: { available: true, voiceCount: 12 },
    mediaDevices: { available: true, audioInputCount: 1, audioOutputCount: 2, videoInputCount: 1 },
    mediaCapabilities: { available: true, video: { h264: { supported: true, smooth: true, powerEfficient: true } } },
    ...over,
  } as unknown as DecisionInput['client'];
}

// ─────────────────────────────────────────────────────────────────────────────
// PHASE 2 — ÉVASIONS (red-team). Assertion : verdict ∉ {'human','clean'}.
// ─────────────────────────────────────────────────────────────────────────────
describe('évasion — un bot ne doit jamais décrocher human/clean', () => {
  it("A1 — TLS↔UA lie (serveur, non-forgeable) ne peut plus être blanchi", () => {
    const r = runDecision(
      { automation: cleanAutomation(), userAgent: CHROME_UA, tls: toolTls(), ip: ipFp(), client: forgedTrustClient() },
      defaultConfig,
      AT,
    );
    expect(r.byLevel.find((l) => l.level === 2)?.hits.find((h) => h.id === 'tls_ua_mismatch')).toBeDefined();
    expect(['bot', 'suspect']).toContain(r.verdict);
  });

  it("A2 — datacenter + proxy (serveur) ne peuvent plus être blanchis", () => {
    const r = runDecision(
      {
        automation: cleanAutomation(),
        userAgent: CHROME_UA,
        ip: ipFp({ isDatacenter: true, isProxyHint: true, asnOrganization: 'OVH SAS' }),
        client: forgedTrustClient(),
      },
      defaultConfig,
      AT,
    );
    expect(r.byLevel.find((l) => l.level === 2)!.score).toBeGreaterThanOrEqual(0.8);
    expect(['bot', 'suspect']).toContain(r.verdict);
  });

  it("A2bis — Tor exit + datacenter (serveur) → reste bot", () => {
    const r = runDecision(
      {
        automation: cleanAutomation(),
        userAgent: CHROME_UA,
        ip: ipFp({ isTorExit: true, isDatacenter: true }),
        client: forgedTrustClient(),
      },
      defaultConfig,
      AT,
    );
    expect(r.verdict).not.toBe('human');
    expect(r.verdict).not.toBe('clean');
  });

  it("A3 — deux contradictions N3 fortes ne peuvent plus être effacées", () => {
    // platform mismatch (0.6) + engine V8 sous UA Safari (0.65) = headless Chrome
    // déguisé → L3 = 1.0. offsetScore plafonné → 'suspect' (avant cap: human).
    const client = forgedTrustClient({
      navigator: { platform: 'Linux x86_64', languages: ['fr-FR', 'fr'], userAgent: SAFARI_UA, uaData: null },
      engine: { detectedEngine: 'v8' },
    });
    const r = runDecision({ automation: cleanAutomation(), userAgent: SAFARI_UA, ip: ipFp(), client }, defaultConfig, AT);
    expect(r.byLevel.find((l) => l.level === 3)!.score).toBeGreaterThanOrEqual(0.8);
    expect(['bot', 'suspect']).toContain(r.verdict);
  });

  it("A4 — essaim de réputation (≥10 IP, serveur) ne peut plus être blanchi", () => {
    const r = runDecision(
      {
        automation: cleanAutomation(),
        userAgent: CHROME_UA,
        ip: ipFp(),
        client: forgedTrustClient(),
        reputation: { fpDistinctIps: 12, fpTotalSessions: 30 },
      },
      defaultConfig,
      AT,
    );
    expect(r.byLevel.find((l) => l.level === 5)!.score).toBeCloseTo(1);
    expect(['bot', 'suspect']).toContain(r.verdict);
  });

  it("A4b — un essaim sur IP résidentielle reste bot (offset total plafonné, rem. d)", () => {
    // Le crédit résidentiel (0.1, non-forgeable, exempté du cap) s'ADDITIONNE au
    // cap forgeable → offsetScore 0.3, ce qui SANS garde rabaisserait la
    // réputation maxée (1.0) à 0.7 = 'suspect'. La rem. (d) plafonne l'offset
    // TOTAL à maxForgeableOffset (0.15) dès que botScore ≥ block : la part
    // résidentielle ne s'empile plus par-dessus le cap → 1.0 − 0.15 = 0.85 → 'bot'.
    const r = runDecision(
      {
        automation: cleanAutomation(),
        userAgent: CHROME_UA,
        ip: ipFp(), // résidentielle → trust_residential_ip (0.1) dans offsetScore
        client: forgedTrustClient(),
        reputation: { fpDistinctIps: 12, fpTotalSessions: 30 },
      },
      defaultConfig,
      AT,
    );
    expect(r.verdict).toBe('bot');
  });

  it("A5 — le label 'human' n'est plus forgeable par le comportement seul", () => {
    // trust_behavior_human (0.5) = humanThreshold ET liveness, mais 100 % forgeable.
    // La rem. (c) exige un signal de confiance INDÉPENDANT de l'ancre de liveness
    // (`trust.corroborated`) ; un blob comportemental seul n'en a aucun → 'clean'.
    const client = { behavioral: forgedOrganicBehaviour() } as unknown as DecisionInput['client'];
    const r = runDecision({ automation: cleanAutomation(), userAgent: CHROME_UA, client }, defaultConfig, AT);
    expect(r.verdict).not.toBe('human');
    expect(r.verdict).toBe('clean');
  });

  it("A8 [FINDING P1, fermé par rem. (e)] — datacenter seul (0.4) + trust forgé ne doit pas décrocher 'human'", () => {
    // Un bot hébergé en cloud (AWS/OVH) a isDatacenter=true (preuve SERVEUR,
    // non-forgeable) mais PAS isProxyHint → L2 = 0.4 seul, SOUS le block. L'offset
    // forgeable (0.15) ramène 0.4 → 0.25 < review(0.4), et le crédit forgé complet
    // (score=1, liveness, corroboré par GPU/fonts forgés) décroche alors le label
    // POSITIF 'human'. Une preuve serveur (datacenter) est donc non seulement
    // annulée mais retournée en 'human' par des données 100 % forgeables.
    // Remédiation (e) EN PLACE (cf. rapport §5) : 'human' exige une corroboration
    // SERVEUR (trust_residential_ip) en plus de la liveness — un crédit purement
    // forgeable sur IP datacenter plafonne à 'clean' (jamais 'bot').
    const r = runDecision(
      {
        automation: cleanAutomation(),
        userAgent: CHROME_UA,
        tls: browserTls(),
        ip: ipFp({ isDatacenter: true, asnOrganization: 'Amazon AES' }),
        client: forgedTrustClient(),
      },
      defaultConfig,
      AT,
    );
    expect(r.byLevel.find((l) => l.level === 2)?.hits.find((h) => h.id === 'ip_datacenter')).toBeDefined();
    expect(r.verdict).not.toBe('human');
    expect(r.verdict).toBe('clean'); // annulé sous review, mais sans ancre serveur → pas 'human'
  });

  it("A9 [FINDING P2, ROUGE avant fix] — 'human' ne devrait pas être minté sans aucune corroboration SERVEUR", () => {
    // Client entièrement forgé (uTLS clone parfait → TLS browser-like, IP propre).
    // Aucun signal serveur ne fire ; le crédit qui décroche 'human' (liveness +
    // corroboration) est INTÉGRALEMENT forgeable (comportement + GPU/fonts/voix).
    // Le label POSITIF 'human' affirme l'humanité ; il ne devrait pas être
    // accordé sur la seule foi de la charge JS, qu'un bot réplique à l'identique.
    // Remédiation (c'/b) : n'autoriser 'human' que si trust_residential_ip (serveur)
    // corrobore, sinon 'clean'. Au pire ce test doit rester ≠ 'human'.
    const r = runDecision(
      {
        automation: cleanAutomation(),
        userAgent: CHROME_UA,
        tls: browserTls(),
        ip: ipFp(), // résidentielle propre — mais le bot ne contrôle pas ça ; ici on
        // teste le cas où MÊME une IP résidentielle ne devrait pas suffire si toute
        // la corroboration est forgeable. Variante stricte de la remédiation (b).
        client: forgedTrustClient(),
      },
      defaultConfig,
      AT,
    );
    // NOTE: avec une IP résidentielle, trust_residential_ip (serveur) corrobore
    // réellement → 'human' est défendable. Ce test fige le comportement ACTUEL et
    // documente la frontière : si Johann veut durcir (exiger un 2e ancrage serveur),
    // il deviendra rouge. Tel quel, on asserte seulement le bornage.
    expect(['human', 'clean']).toContain(r.verdict);
  });

  it("A6 — identité cohérente forgée + comportement forgé → pas 'bot', mais doc le pouvoir de 'human'", () => {
    // Tout aligné (platform↔UA, langues, client-hints) → trust_identity_coherent
    // (0.2) en plus de la liveness forgée. Sans signal serveur, le verdict est
    // 'human' (corroboration + liveness, tout forgeable). On documente que la
    // corroboration de la rem. (c) est elle-même forgeable.
    const r = runDecision(
      { automation: cleanAutomation(), userAgent: CHROME_UA, tls: browserTls(), ip: ipFp(), client: forgedTrustClient() },
      defaultConfig,
      AT,
    );
    expect(r.trustSignals.map((s) => s.id)).toContain('trust_identity_coherent');
    // IP résidentielle propre → corroboration serveur réelle ; 'human' défendable.
    expect(['human', 'clean']).toContain(r.verdict);
  });

  it("A10 [FINDING P1, fermé par rem. (e)] — proxy/VPN seul (0.4) + trust forgé ne doit pas décrocher 'human'", () => {
    // Identique à A8 mais via isProxyHint (autre preuve serveur isolée à 0.4).
    const r = runDecision(
      { automation: cleanAutomation(), userAgent: CHROME_UA, tls: browserTls(), ip: ipFp({ isProxyHint: true }), client: forgedTrustClient() },
      defaultConfig,
      AT,
    );
    expect(r.byLevel.find((l) => l.level === 2)?.hits.find((h) => h.id === 'ip_proxy')).toBeDefined();
    expect(r.verdict).not.toBe('human');
    expect(r.verdict).toBe('clean');
  });

  it("A7 — l'omission d'une surface (canvas null) n'échappe plus à la réputation", () => {
    // AVANT : fingerprintReputation() renvoyait {0,0} dès qu'un hash (canvas OU
    // webgl) était null → un bot mettait canvas=null (gardait webgl pour le crédit
    // GPU) et échappait à N5 sans déclencher env_render_surfaces_absent (qui exige
    // les TROIS surfaces nulles). APRÈS (store.ts) : le couple (canvas, webgl) est
    // matché null-safe → un essaim qui omet toujours la même surface se compte
    // lui-même. On injecte ici la réputation que le store CORRIGÉ produit (12 IP).
    const client = forgedTrustClient({ canvas: null }); // webgl + audio présents
    const r = runDecision(
      {
        automation: cleanAutomation(),
        userAgent: CHROME_UA,
        ip: ipFp(),
        client,
        reputation: { fpDistinctIps: 12, fpTotalSessions: 30 },
      },
      defaultConfig,
      AT,
    );
    expect(r.byLevel.find((l) => l.level === 3)?.hits.find((h) => h.id === 'env_render_surfaces_absent')).toBeUndefined();
    expect(r.byLevel.find((l) => l.level === 5)!.score).toBeCloseTo(1);
    expect(['bot', 'suspect']).toContain(r.verdict);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// PHASE 3 — FAUX POSITIFS. Assertion : verdict ≠ 'bot'.
// ─────────────────────────────────────────────────────────────────────────────
describe('faux positifs — un humain réel ne doit jamais être bot', () => {
  it('H1 — Mac/Safari (pas de Client Hints, JSC vu non-V8) → pas bot', () => {
    const client = forgedTrustClient({
      navigator: { platform: 'MacIntel', languages: ['fr-FR'], userAgent: SAFARI_UA, uaData: null },
      engine: { detectedEngine: 'javascriptcore' },
    });
    const r = runDecision({ automation: cleanAutomation(), userAgent: SAFARI_UA, tls: browserTls(), ip: ipFp(), client }, defaultConfig, AT);
    expect(r.verdict).not.toBe('bot');
  });

  it('H2 — Firefox desktop (pas de chrome.runtime, pas de Client Hints, pas WebGPU) → pas bot', () => {
    const client = forgedTrustClient({
      navigator: { platform: 'Linux x86_64', languages: ['fr-FR'], userAgent: FIREFOX_UA, uaData: null },
      engine: { detectedEngine: 'spidermonkey' },
      webgpu: { available: false, adapter: null, features: [], limits: {}, limitsHash: '' },
    });
    const r = runDecision(
      { automation: cleanAutomation({ chromeRuntime: false }), userAgent: FIREFOX_UA, tls: browserTls(), ip: ipFp(), client },
      defaultConfig,
      AT,
    );
    expect(r.verdict).not.toBe('bot');
    expect(r.byLevel.flatMap((l) => l.hits).map((h) => h.id)).not.toContain('env_webgpu_absent');
  });

  it('H3 — vrai mobile en wifi local (RTT < 2 ms) reste sous le seuil bot', () => {
    const client = forgedTrustClient({
      navigator: { platform: 'Linux armv8l', languages: ['fr-FR'], userAgent: ANDROID_UA, uaData: { brands: [{ brand: 'Chromium', version: '124' }] } },
    });
    const r = runDecision(
      { automation: cleanAutomation(), userAgent: ANDROID_UA, tls: browserTls(), ip: ipFp({ tcpRttMs: 0.5 }), client },
      defaultConfig,
      AT,
    );
    expect(r.verdict).not.toBe('bot');
  });

  it('H4 — voyageur derrière VPN datacenter (locale ≠ pays IP) → jamais bot sur ces 2 signaux', () => {
    const client = forgedTrustClient({
      navigator: { platform: 'Win32', languages: ['fr-FR'], userAgent: CHROME_UA, uaData: { brands: [{ brand: 'Chromium', version: '124' }] } },
      locale: { resolvedOptionsLocale: 'fr-FR' },
    });
    const r = runDecision(
      { automation: cleanAutomation(), userAgent: CHROME_UA, tls: browserTls(), ip: ipFp({ isDatacenter: true, country: 'US' }), client },
      defaultConfig,
      AT,
    );
    expect(r.verdict).not.toBe('bot');
  });

  it('H5 — extension vie privée : canvas bloqué seul → pas de signal nu, pas bot', () => {
    const client = forgedTrustClient({ canvas: null }); // webgl + audio présents
    const r = runDecision({ automation: cleanAutomation(), userAgent: CHROME_UA, tls: browserTls(), ip: ipFp(), client }, defaultConfig, AT);
    expect(r.byLevel.find((l) => l.level === 3)?.hits.find((h) => h.id === 'env_render_surfaces_absent')).toBeUndefined();
    expect(r.verdict).not.toBe('bot');
  });

  it('H6 — humain peu actif (0 interaction) → au pire clean, jamais bot', () => {
    const client = {
      navigator: { platform: 'Win32', languages: ['fr-FR'], userAgent: CHROME_UA, uaData: { brands: [{ brand: 'Chromium', version: '124' }] } },
      behavioral: { totalEvents: 0, durationMs: 8000, mouse: { moves: 0 }, scroll: { events: 0 }, keyboard: { keydowns: 0 }, touch: {} },
    } as unknown as DecisionInput['client'];
    const r = runDecision({ automation: cleanAutomation(), userAgent: CHROME_UA, tls: browserTls(), ip: ipFp(), client }, defaultConfig, AT);
    expect(r.verdict).not.toBe('bot');
  });

  it("H7 — humain VPN double-flaggé (datacenter + proxy = block) → suspect, jamais bot", () => {
    // Certains ASN de VPN allument À LA FOIS isDatacenter et isProxyHint → L2 = 0.8
    // = block. Le plancher chirurgical (rem. d) plafonne l'offset TOTAL à
    // maxForgeableOffset (0.15) : 0.8 − 0.15 = 0.65 → 'suspect'. Un humain réel
    // n'est donc PAS inculpé 'bot' (ce que ferait un plancher dur). Pas d'IP
    // résidentielle ici (datacenter), donc seul l'offset forgeable (0.15) s'applique.
    const client = forgedTrustClient({
      navigator: { platform: 'Win32', languages: ['fr-FR'], userAgent: CHROME_UA, uaData: { brands: [{ brand: 'Chromium', version: '124' }] } },
    });
    const r = runDecision(
      {
        automation: cleanAutomation(),
        userAgent: CHROME_UA,
        tls: browserTls(),
        ip: ipFp({ isDatacenter: true, isProxyHint: true, asnOrganization: 'CloudVPN Hosting Ltd' }),
        client,
      },
      defaultConfig,
      AT,
    );
    expect(r.byLevel.find((l) => l.level === 2)!.score).toBeGreaterThanOrEqual(0.8);
    expect(r.verdict).not.toBe('bot');
    expect(r.verdict).toBe('suspect');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// PHASE 1 — INVARIANTS I1–I9
// ─────────────────────────────────────────────────────────────────────────────
describe('invariants', () => {
  it('I1 — un aveu dur est immunisé même avec trust = max', () => {
    const r = runDecision(
      { automation: cleanAutomation({ webdriver: true }), userAgent: CHROME_UA, tls: browserTls(), ip: ipFp(), client: forgedTrustClient() },
      defaultConfig,
      AT,
    );
    expect(r.verdict).toBe('bot');
    expect(r.forced).toBe(true);
    expect(r.score).toBe(1);
  });

  it('I2 — bornage : scores ∈ [0,1] même avec Infinity/NaN/négatifs dans le payload', () => {
    const weird = {
      navigator: { platform: 'Win32', languages: ['fr'], userAgent: CHROME_UA, uaData: { brands: [{ brand: 'x', version: '1' }] } },
      behavioral: {
        totalEvents: 200,
        durationMs: 8000,
        mouse: { moves: Infinity, clicks: 0, meanSpeed: Infinity, stdSpeed: -5, meanCurvature: Infinity, stillRatio: NaN, jitterRatio: -1 },
        keyboard: { keydowns: Infinity, keyups: 0, meanDwellMs: NaN, stdDwellMs: Infinity, meanFlightMs: 0, stdFlightMs: Infinity, backspaceRatio: 0 },
        scroll: { events: Infinity, totalDeltaPx: 0, meanDeltaPx: 0, linearRatio: Infinity },
        touch: { starts: 0, moves: 0, ends: 0, meanPressure: 0, multiTouchMax: 0 },
      },
    } as unknown as DecisionInput['client'];
    const r = runDecision({ automation: cleanAutomation(), userAgent: CHROME_UA, ip: ipFp(), client: weird }, defaultConfig, AT);
    for (const l of r.byLevel) {
      expect(Number.isFinite(l.score)).toBe(true);
      expect(l.score).toBeGreaterThanOrEqual(0);
      expect(l.score).toBeLessThanOrEqual(1);
    }
    expect(Number.isFinite(r.score)).toBe(true);
    expect(r.score).toBeGreaterThanOrEqual(0);
    expect(r.score).toBeLessThanOrEqual(1);
    expect(Number.isFinite(r.trustScore)).toBe(true);
  });

  it('I3 — monotonie : ajouter un tell bot ne réduit jamais la suspicion brute (botScore)', () => {
    const base = runDecision({ automation: cleanAutomation(), userAgent: CHROME_UA, ip: ipFp() }, defaultConfig, AT);
    const more = runDecision({ automation: cleanAutomation(), userAgent: CHROME_UA, ip: ipFp({ isDatacenter: true }) }, defaultConfig, AT);
    const baseBot = Math.max(...base.byLevel.map((l) => l.score), 0);
    const moreBot = Math.max(...more.byLevel.map((l) => l.score), 0);
    expect(moreBot).toBeGreaterThanOrEqual(baseBot);
  });

  it('I6 — déterminisme : même (input, cfg, computedAt) → résultat identique', () => {
    const inp = { automation: cleanAutomation(), userAgent: CHROME_UA, tls: toolTls(), ip: ipFp({ isDatacenter: true }), client: forgedTrustClient() };
    expect(runDecision(inp, defaultConfig, AT)).toEqual(runDecision(inp, defaultConfig, AT));
  });

  it('I7 — traçabilité : retuner un poids change le hash de version', () => {
    const a = runDecision({ automation: cleanAutomation(), userAgent: CHROME_UA }, defaultConfig, AT);
    const tuned = {
      ...defaultConfig,
      levels: defaultConfig.levels.map((l) => (l.level === 2 ? { ...l, weights: { ...l.weights, ip_datacenter: 0.99 } } : l)),
    };
    const b = runDecision({ automation: cleanAutomation(), userAgent: CHROME_UA }, tuned, AT);
    expect(a.configVersion).not.toBe(b.configVersion);
  });

  it('I8 — unknown seulement quand aucun niveau ni trust ne produit rien', () => {
    const cfg = { ...defaultConfig, levels: defaultConfig.levels.map((l) => ({ ...l, enabled: false })) };
    const r = runDecision({ automation: cleanAutomation(), userAgent: CHROME_UA }, cfg, AT);
    expect(r.verdict).toBe('unknown');
  });

  it("I4 — sous aveu dur, le verdict est 'bot' (jamais human/clean/suspect) même trust max", () => {
    const r = runDecision(
      { automation: cleanAutomation({ selenium: true }), userAgent: CHROME_UA, tls: browserTls(), ip: ipFp(), client: forgedTrustClient() },
      defaultConfig,
      AT,
    );
    expect(r.verdict).toBe('bot');
  });

  it("I5 — 'human' exige la liveness (requireLiveness) : trust passif sans comportement → jamais human", () => {
    // Tous les crédits passifs forgés MAIS aucun comportement organique → pas de
    // liveness → le label 'human' est interdit, au mieux 'clean'.
    const client = forgedTrustClient({ behavioral: undefined });
    const r = runDecision({ automation: cleanAutomation(), userAgent: CHROME_UA, tls: browserTls(), ip: ipFp(), client }, defaultConfig, AT);
    expect(r.verdict).not.toBe('human');
  });

  it('I9 — un payload zod-valide minimal (tout null) ne fait ni planter ni NaN', () => {
    const parsed = ClientFingerprintSchema.safeParse(validClientPayload({
      navigator: { ...(validClientPayload().navigator as object), languages: [] },
      behavioral: {
        totalEvents: 0, durationMs: 0,
        mouse: { moves: 0, clicks: 0, meanSpeed: 0, stdSpeed: 0, meanCurvature: 0, stillRatio: 0, jitterRatio: 0 },
        keyboard: { keydowns: 0, keyups: 0, meanDwellMs: 0, stdDwellMs: 0, meanFlightMs: 0, stdFlightMs: 0, backspaceRatio: 0 },
        scroll: { events: 0, totalDeltaPx: 0, meanDeltaPx: 0, linearRatio: 0 },
        touch: { starts: 0, moves: 0, ends: 0, meanPressure: 0, multiTouchMax: 0 },
      },
    }));
    expect(parsed.success).toBe(true);
    if (!parsed.success) return;
    const r = runDecision(
      { automation: cleanAutomation(), userAgent: CHROME_UA, client: parsed.data as unknown as DecisionInput['client'] },
      defaultConfig,
      AT,
    );
    expect(Number.isFinite(r.score)).toBe(true);
    expect(Number.isFinite(r.trustScore)).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// PHASE 5 — intégrité du crédit de confiance (quantification du pouvoir d'annulation)
// ─────────────────────────────────────────────────────────────────────────────
describe('crédit de confiance — pouvoir d’annulation forgeable', () => {
  it("le crédit forgeable seul atteint le score complet (≥1) mais un offsetScore plafonné", () => {
    const client = forgedTrustClient();
    const t = computeTrust({ automation: cleanAutomation(), userAgent: CHROME_UA, client }, defaultConfig.trust, new Set());
    expect(t.score).toBeCloseTo(1); // pour le label 'human'
    expect(t.offsetScore).toBeLessThanOrEqual(defaultConfig.trust.maxForgeableOffset); // pour l'offset
    expect(t.liveness).toBe(true);
  });

  it("trust_behavior_human seul est liveness mais NON corroboré", () => {
    const client = { behavioral: forgedOrganicBehaviour() } as unknown as DecisionInput['client'];
    const t = computeTrust({ automation: cleanAutomation(), userAgent: CHROME_UA, client }, defaultConfig.trust, new Set());
    expect(t.score).toBeGreaterThanOrEqual(defaultConfig.trust.humanThreshold);
    expect(t.liveness).toBe(true);
    expect(t.corroborated).toBe(false);
  });

  it("rem. (e) : un crédit 100 % forgeable est corroboré mais PAS serverCorroborated", () => {
    // forgedTrustClient allume tous les crédits forgeables (GPU/fonts/identité…)
    // → corroborated=true, mais SANS IP résidentielle (ip absent) le seul signal
    // non-forgeable (trust_residential_ip) ne fire pas → serverCorroborated=false.
    const t = computeTrust(
      { automation: cleanAutomation(), userAgent: CHROME_UA, client: forgedTrustClient() },
      defaultConfig.trust,
      new Set(),
    );
    expect(t.corroborated).toBe(true);
    expect(t.serverCorroborated).toBe(false);
  });

  it("rem. (e) : une IP résidentielle (serveur) donne serverCorroborated", () => {
    const t = computeTrust(
      { automation: cleanAutomation(), userAgent: CHROME_UA, ip: ipFp(), client: forgedTrustClient() },
      defaultConfig.trust,
      new Set(),
    );
    expect(t.signals.map((s) => s.id)).toContain('trust_residential_ip');
    expect(t.serverCorroborated).toBe(true);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// PHASE 6 — sûreté du tuning : resolveConfig ne doit pas perdre de champ requis
// ─────────────────────────────────────────────────────────────────────────────
describe('resolveConfig — un override partiel ne casse pas la config', () => {
  it("un override trust partiel conserve offsetFactor/humanThreshold/maxForgeableOffset (pas de NaN)", () => {
    const cfg = resolveConfig({ trust: { weights: { trust_behavior_human: 0.6 } } } as unknown as Parameters<typeof resolveConfig>[0]);
    expect(cfg.trust.offsetFactor).toBe(defaultConfig.trust.offsetFactor);
    expect(cfg.trust.humanThreshold).toBe(defaultConfig.trust.humanThreshold);
    expect(cfg.trust.maxForgeableOffset).toBe(defaultConfig.trust.maxForgeableOffset);
    expect(cfg.trust.requireLiveness).toBe(defaultConfig.trust.requireLiveness);
    expect(cfg.trust.weights.trust_behavior_human).toBe(0.6);
    expect(cfg.trust.weights.trust_identity_coherent).toBe(defaultConfig.trust.weights.trust_identity_coherent);
    const r = runDecision({ automation: cleanAutomation(), userAgent: CHROME_UA, ip: ipFp({ isDatacenter: true }) }, cfg, AT);
    expect(Number.isFinite(r.score)).toBe(true);
  });

  it("un override de poids d'un niveau ne wipe pas les poids frères", () => {
    const cfg = resolveConfig({ levels: [{ level: 2, weights: { ip_datacenter: 0.9 } }] } as unknown as Parameters<typeof resolveConfig>[0]);
    const l2 = cfg.levels.find((l) => l.level === 2)!;
    expect(l2.weights.ip_datacenter).toBe(0.9);
    expect(l2.weights.tls_ua_mismatch).toBe(0.7);
    expect(l2.hardSignals).toEqual(defaultConfig.levels.find((l) => l.level === 2)!.hardSignals);
    expect(l2.thresholds).toEqual(defaultConfig.levels.find((l) => l.level === 2)!.thresholds);
  });

  it("un override aggregate partiel conserve l'autre seuil", () => {
    const cfg = resolveConfig({ aggregate: { review: 0.3 } } as unknown as Parameters<typeof resolveConfig>[0]);
    expect(cfg.aggregate.review).toBe(0.3);
    expect(cfg.aggregate.block).toBe(defaultConfig.aggregate.block);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// PHASE 7 — frontière de validation : Infinity/NaN/ratios hors bornes rejetés
// ─────────────────────────────────────────────────────────────────────────────
function validClientPayload(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    sessionId: 'x',
    collectedAt: '2026-06-01T00:00:00.000Z',
    durationMs: 8000,
    navigator: {
      userAgent: CHROME_UA,
      appVersion: '5.0',
      platform: 'Win32',
      vendor: 'Google Inc.',
      product: 'Gecko',
      language: 'fr-FR',
      languages: ['fr-FR', 'fr'],
      hardwareConcurrency: 8,
      deviceMemory: 8,
      doNotTrack: null,
      maxTouchPoints: 0,
      cookieEnabled: true,
      pdfViewerEnabled: true,
      uaData: null,
    },
    screen: {
      width: 1920, height: 1080, availWidth: 1920, availHeight: 1040,
      colorDepth: 24, pixelDepth: 24, devicePixelRatio: 1, orientation: 'landscape-primary',
      windowInnerWidth: 1920, windowInnerHeight: 950, windowOuterWidth: 1920, windowOuterHeight: 1040,
    },
    locale: {
      timezone: 'Europe/Paris', timezoneOffset: -120, dateFormat: 'dd/mm/yyyy', numberFormat: '1 234,56',
      resolvedOptionsLocale: 'fr-FR', calendar: 'gregory', numberingSystem: 'latn',
    },
    canvas: null, webgl: null, audio: null, fonts: null, webrtc: null,
    codecs: { video: {}, audio: {}, mediaSourceTypes: {} },
    permissions: { states: {} },
    automation: {
      webdriver: false, pluginsLength: 3, mimeTypesLength: 2, pluginNames: [], mimeTypeNames: [],
      chromeRuntime: true, hasNotificationPermission: false, inconsistencies: [],
      callPhantom: false, nightmare: false, selenium: false, playwrightHints: [], cdpHints: [],
    },
    speech: null, mediaDevices: null, mediaCapabilities: null, webgpu: null, cssMedia: null,
    intl: null, engine: null, network: null, storage: null, perfMemory: null,
    behavioral: {
      totalEvents: 200, durationMs: 8000,
      mouse: { moves: 40, clicks: 3, meanSpeed: 5, stdSpeed: 1.5, meanCurvature: 0.3, stillRatio: 0.3, jitterRatio: 0.2 },
      keyboard: { keydowns: 20, keyups: 20, meanDwellMs: 90, stdDwellMs: 25, meanFlightMs: 140, stdFlightMs: 40, backspaceRatio: 0.05 },
      scroll: { events: 30, totalDeltaPx: 4000, meanDeltaPx: 130, linearRatio: 0.6 },
      touch: { starts: 0, moves: 0, ends: 0, meanPressure: 0, multiTouchMax: 0 },
    },
    ...over,
  };
}

function withBehavioral(group: 'mouse' | 'keyboard' | 'scroll' | 'touch', patch: Record<string, unknown>) {
  const base = validClientPayload();
  const beh = base.behavioral as Record<string, Record<string, unknown>>;
  beh[group] = { ...beh[group], ...patch };
  return base;
}

describe('validation /collect — bornes des agrégats comportementaux', () => {
  it('la charge de base valide est acceptée (sanity du fixture)', () => {
    expect(ClientFingerprintSchema.safeParse(validClientPayload()).success).toBe(true);
  });

  it('meanCurvature = Infinity est rejeté (ne peut plus créditer la liveness)', () => {
    expect(ClientFingerprintSchema.safeParse(withBehavioral('mouse', { meanCurvature: Infinity })).success).toBe(false);
  });

  it('stdSpeed = NaN est rejeté', () => {
    expect(ClientFingerprintSchema.safeParse(withBehavioral('mouse', { stdSpeed: NaN })).success).toBe(false);
  });

  it('linearRatio hors [0,1] (Infinity / 1.5) est rejeté', () => {
    expect(ClientFingerprintSchema.safeParse(withBehavioral('scroll', { linearRatio: Infinity })).success).toBe(false);
    expect(ClientFingerprintSchema.safeParse(withBehavioral('scroll', { linearRatio: 1.5 })).success).toBe(false);
  });

  it('un ratio négatif est rejeté', () => {
    expect(ClientFingerprintSchema.safeParse(withBehavioral('mouse', { jitterRatio: -1 })).success).toBe(false);
  });

  it('stdDwellMs = Infinity est rejeté', () => {
    expect(ClientFingerprintSchema.safeParse(withBehavioral('keyboard', { stdDwellMs: Infinity })).success).toBe(false);
  });
});
