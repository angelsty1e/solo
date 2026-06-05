import { describe, it, expect } from 'vitest';
import type { AutomationSnapshot, IpFingerprint } from '../src/shared/types.js';
import type { DecisionInput } from '../src/shared/decision/types.js';
import { runDecision } from '../src/shared/decision/engine.js';
import { computeTrust } from '../src/shared/decision/trust.js';
import { defaultConfig } from '../src/shared/decision/config.js';

// ─── Contrat de frontière : crédit résidentiel — null (GeoIP down) ≠ false ───────
// Le commentaire le plus important du moteur (trust.ts:119-122 / engine.ts) :
// renvoyer `false` au lieu de `null` quand GeoIP est down « handerait à un bot
// le crédit de confiance NON-FORGEABLE qu'il ne peut sinon pas falsifier ».
//
// La suite adversariale teste déjà l'effet du crédit (A4b : empilement plafonné ;
// A5 : blob comportemental seul → clean). Ce qu'elle ne teste PAS — et ce que ce
// fichier verrouille — c'est l'invariant à la SOURCE : la triple égalité stricte
// de trust.ts:120
//
//     ip.isDatacenter === false && ip.isProxyHint === false && ip.isTorExit !== true
//
// Tester que `classifyAsn` renvoie `null` (cf. tests enrich) est nécessaire mais
// PAS suffisant : l'invariant ne protège rien tant qu'on n'a pas prouvé que le
// CONSOMMATEUR (computeTrust) traite `null` différemment de `false`. Si quelqu'un
// « simplifie » un jour `null → false` côté enrich OU côté trust, ces tests
// doivent rougir — pas seulement les tests unitaires de la feuille.
//
// Deux couches :
//   • Couche 1 (computeTrust) — table de vérité du signal trust_residential_ip,
//     + preuve que ce crédit est routé en NON-forgeable (s'empile par-dessus le
//     cap maxForgeableOffset).
//   • Couche 2 (runDecision) — la conséquence end-to-end : une IP résidentielle
//     CONFIRMÉE corrobore un humain organique → 'human' ; une IP où GeoIP est
//     DOWN (null) ne corrobore pas → 'clean'. Un bot au comportement forgé sur
//     une IP non résolue ne décroche donc pas l'humanité par ce biais.

const AT = '2026-06-01T00:00:00.000Z';
const CHROME_UA =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';

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

// IpFingerprint avec les trois drapeaux d'enrichissement surchargeables. Les
// défauts décrivent une résidentielle CONFIRMÉE (lookup réussi : false, pas null).
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

// Comportement organique (forgeable — ce ne sont que des nombres). Fait firer
// trust_behavior_human (0.5, liveness) sans déclencher de motif synthétique N4.
// IDENTIQUE au fixture A5 : un blob seul = liveness mais NON corroboré → 'clean'.
// Ici on ajoute la SEULE corroboration non-forgeable possible (l'IP résidentielle)
// et on observe le basculement.
function organicBehaviour(): Record<string, unknown> {
  return {
    totalEvents: 200,
    durationMs: 8000,
    mouse: { moves: 40, clicks: 3, meanSpeed: 5, stdSpeed: 1.5, meanCurvature: 0.3, stillRatio: 0.3, jitterRatio: 0.2 },
    keyboard: { keydowns: 20, keyups: 20, meanDwellMs: 90, stdDwellMs: 25, meanFlightMs: 140, stdFlightMs: 40, backspaceRatio: 0.05 },
    scroll: { events: 30, totalDeltaPx: 4000, meanDeltaPx: 130, linearRatio: 0.6 },
    touch: { starts: 0, moves: 0, ends: 0, meanPressure: 0, multiTouchMax: 0 },
  };
}

const RESIDENTIAL = 'trust_residential_ip';
const fired = (i: DecisionInput) =>
  computeTrust(i, defaultConfig.trust, new Set()).signals.some((s) => s.id === RESIDENTIAL);

// ─────────────────────────────────────────────────────────────────────────────
// COUCHE 1 — computeTrust : table de vérité de trust_residential_ip
// On isole le signal en ne fournissant AUCUN autre crédit : `client: undefined`
// neutralise tous les signaux client (ils lisent i.client?.x) ; seul i.ip compte.
// ─────────────────────────────────────────────────────────────────────────────
describe('contrat — trust_residential_ip : table de vérité (dc, proxy, tor)', () => {
  const base = (ip: IpFingerprint | null): DecisionInput => ({
    automation: cleanAutomation(),
    userAgent: CHROME_UA,
    ip,
    client: undefined,
  });

  // [isDatacenter, isProxyHint, isTorExit, doitFirer, intitulé]
  const cases: Array<[IpFingerprint['isDatacenter'], IpFingerprint['isProxyHint'], IpFingerprint['isTorExit'], boolean, string]> = [
    [false, false, false, true, 'résidentielle confirmée (false/false/false)'],
    [false, false, null, true, 'liste Tor absente (tor=null) ne voide pas le crédit'],
    [false, false, true, false, 'nœud Tor confirmé (tor=true) disqualifie'],
    [null, false, false, false, 'GeoIP down sur datacenter (dc=null) → PAS de crédit'],
    [false, null, false, false, 'GeoIP down sur proxy (proxy=null) → PAS de crédit'],
    [null, null, null, false, 'GeoIP totalement down (null/null/null) → PAS de crédit'],
    [true, false, false, false, 'datacenter confirmé (dc=true) disqualifie'],
    [false, true, false, false, 'proxy/VPN confirmé (proxy=true) disqualifie'],
  ];

  for (const [dc, proxy, tor, expected, label] of cases) {
    it(`${expected ? 'fire' : 'ne fire pas'} — ${label}`, () => {
      expect(fired(base(ipFp({ isDatacenter: dc, isProxyHint: proxy, isTorExit: tor })))).toBe(expected);
    });
  }

  it('ne fire pas — aucune IP observée (ip=null)', () => {
    expect(fired(base(null))).toBe(false);
  });

  it("le crédit n'est accordé QUE sur false strict, jamais sur une absence (null)", () => {
    // Cœur de l'invariant : false (lookup réussi → résidentiel) ≠ null (lookup
    // raté → inconnu). Une régression null→false rendrait ces deux lignes égales.
    const confirmedResidential = fired(base(ipFp({ isDatacenter: false, isProxyHint: false })));
    const geoipDown = fired(base(ipFp({ isDatacenter: null, isProxyHint: null })));
    expect(confirmedResidential).toBe(true);
    expect(geoipDown).toBe(false);
    expect(confirmedResidential).not.toBe(geoipDown);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// COUCHE 1bis — le crédit résidentiel est NON-FORGEABLE (exempté du cap)
// Preuve unitaire de l'arithmétique testée end-to-end par A4b : la part
// résidentielle (trustedSum) s'AJOUTE par-dessus le plafond forgeable (0.15),
// au lieu d'y être absorbée.
// ─────────────────────────────────────────────────────────────────────────────
describe('contrat — le crédit résidentiel échappe au plafond forgeable', () => {
  // Client maximalement forgé : tous les crédits client-forgeables firent →
  // forgeableSum élevé, donc plafonné à maxForgeableOffset (0.15) dans l'offset.
  function forgedTrustClient(): DecisionInput['client'] {
    return {
      navigator: {
        platform: 'Win32',
        languages: ['fr-FR', 'fr'],
        userAgent: CHROME_UA,
        uaData: { brands: [{ brand: 'Chromium', version: '124' }, { brand: 'Google Chrome', version: '124' }] },
      },
      behavioral: organicBehaviour(),
      webgl: { unmaskedRenderer: 'NVIDIA GeForce RTX 3060', renderer: 'ANGLE (NVIDIA)' },
      fonts: { detectionMethod: 'measurement', detectedFonts: Array.from({ length: 30 }, (_, i) => `Font${i}`) },
      speech: { available: true, voiceCount: 12 },
      mediaDevices: { available: true, audioInputCount: 1, audioOutputCount: 2, videoInputCount: 1 },
      mediaCapabilities: { available: true, video: { h264: { supported: true, smooth: true, powerEfficient: true } } },
    } as unknown as DecisionInput['client'];
  }

  it("residential (0.1, non-forgeable) s'empile PAR-DESSUS le cap forgeable (0.15) → offset 0.25", () => {
    const cfg = defaultConfig.trust;
    const withResidential = computeTrust(
      { automation: cleanAutomation(), userAgent: CHROME_UA, ip: ipFp(), client: forgedTrustClient() },
      cfg,
      new Set(),
    );
    const geoipDown = computeTrust(
      { automation: cleanAutomation(), userAgent: CHROME_UA, ip: ipFp({ isDatacenter: null, isProxyHint: null, isTorExit: null }), client: forgedTrustClient() },
      cfg,
      new Set(),
    );
    // Sans la part serveur : offset = cap forgeable seul.
    expect(geoipDown.offsetScore).toBeCloseTo(cfg.maxForgeableOffset); // 0.15
    // Avec la part serveur : le 0.1 non-forgeable s'ajoute au cap (≠ absorbé).
    expect(withResidential.offsetScore).toBeCloseTo(cfg.maxForgeableOffset + cfg.weights[RESIDENTIAL]!); // 0.25
    expect(withResidential.offsetScore).toBeGreaterThan(geoipDown.offsetScore);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// COUCHE 2 — conséquence end-to-end (runDecision)
// Complément exact de A5 : un humain organique seul = liveness mais NON corroboré
// → 'clean'. La SEULE corroboration non-forgeable qu'un bot ne peut pas fabriquer
// est l'IP résidentielle observée serveur. On prouve qu'elle :
//   • fait basculer un humain organique vers le label POSITIF 'human' (résidentiel
//     confirmé) ;
//   • ne le fait PAS quand GeoIP est down (null) — sinon un bot au comportement
//     forgé sur une IP non résolue décrocherait 'human'.
// ─────────────────────────────────────────────────────────────────────────────
describe('contrat — corroboration résidentielle : confirmé → human, GeoIP down → clean', () => {
  // Client minimal : comportement organique UNIQUEMENT (comme A5). Aucun crédit
  // client non-liveness ne fire → la corroboration ne peut venir QUE du serveur.
  const organicOnlyClient = { behavioral: organicBehaviour() } as unknown as DecisionInput['client'];

  function run(ip: IpFingerprint) {
    return runDecision(
      { automation: cleanAutomation(), userAgent: CHROME_UA, ip, client: organicOnlyClient },
      defaultConfig,
      AT,
    );
  }

  it("IP résidentielle CONFIRMÉE corrobore la liveness → 'human'", () => {
    const r = run(ipFp({ isDatacenter: false, isProxyHint: false, isTorExit: false }));
    expect(r.trustSignals.map((s) => s.id)).toContain(RESIDENTIAL);
    expect(r.verdict).toBe('human');
  });

  it("GeoIP down (null/null/null) ne corrobore pas → 'clean', jamais 'human'", () => {
    // L'invariant de sécurité : une IP non résolue n'accorde pas le crédit
    // serveur. Sans corroboration non-liveness, le label POSITIF est interdit
    // (trust.corroborated=false), exactement comme A5.
    const r = run(ipFp({ isDatacenter: null, isProxyHint: null, isTorExit: null }));
    expect(r.trustSignals.map((s) => s.id)).not.toContain(RESIDENTIAL);
    expect(r.verdict).not.toBe('human');
    expect(r.verdict).toBe('clean');
  });

  it("proxy=null seul (dc=false) suffit à retirer la corroboration → pas 'human'", () => {
    // Strictness par-champ : il ne suffit pas que dc soit false ; CHAQUE champ
    // doit être strictement false (tor !== true). Un seul null casse le crédit.
    const r = run(ipFp({ isDatacenter: false, isProxyHint: null, isTorExit: false }));
    expect(r.trustSignals.map((s) => s.id)).not.toContain(RESIDENTIAL);
    expect(r.verdict).not.toBe('human');
  });

  it("Tor confirmé (tor=true) retire la corroboration même si dc/proxy=false → pas 'human'", () => {
    const r = run(ipFp({ isDatacenter: false, isProxyHint: false, isTorExit: true }));
    expect(r.trustSignals.map((s) => s.id)).not.toContain(RESIDENTIAL);
    expect(r.verdict).not.toBe('human');
  });
});
