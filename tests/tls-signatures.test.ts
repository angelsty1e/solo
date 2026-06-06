import { describe, it, expect } from 'vitest';
import type { TlsFingerprint } from '../src/shared/types.js';
import { classifyTls, matchToolSignature } from '../src/shared/decision/tls-signatures.js';

// ─── Profilage TLS — le stack ressemble-t-il à un vrai navigateur ? ───────────
// Capté serveur-side depuis le ClientHello (non-forgeable en JS). Le moteur teste
// le VERDICT ; ici on verrouille les reasons[] et l'ORDRE des signatures outil.
//
// Piège vérifié : un TLS « browser-like » SANS GREASE matche quand même la
// dernière signature `absence de GREASE`. Pour qu'un hello soit matchToolSignature
// → null, il faut du GREASE injecté (ce que Chrome/Edge font partout).

const EXT = { GROUPS: 10, SIG_ALGS: 13, SUPPORTED_VERSIONS: 43, KEY_SHARE: 51 };
const TLS13 = 0x0304;
const TLS12 = 0x0303;
const X25519 = 29;
const GREASE = 0x0a0a; // (v & 0x0f0f)===0x0a0a et octet haut==bas → GREASE

// ClientHello d'un vrai navigateur moderne : h2, ≥5 ciphers, TLS 1.3 « riche »
// (key_share + supported_versions + sig_algs + supported_groups), X25519, GREASE.
function browserTls(over: Partial<TlsFingerprint> = {}): TlsFingerprint {
  return {
    version: TLS12,
    versionName: 'TLS 1.2',
    ciphers: [GREASE, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c, 0xc030],
    extensions: [GREASE, EXT.GROUPS, EXT.SIG_ALGS, EXT.SUPPORTED_VERSIONS, EXT.KEY_SHARE, 0, 23, 65281],
    ellipticCurves: [GREASE, X25519, 23, 24],
    ecPointFormats: [0],
    signatureAlgorithms: [0x0403, 0x0804],
    alpn: ['h2', 'http/1.1'],
    sni: 'example.com',
    supportedVersions: [GREASE, TLS13, TLS12],
    ja3: 'x',
    ja3Hash: 'browserhash',
    ja4: 't13d1516h2_aaaa_bbbb',
    ...over,
  };
}

describe('classifyTls — browserLike & reasons', () => {
  it('un vrai navigateur (riche + GREASE) → browserLike, aucune reason', () => {
    const r = classifyTls(browserTls());
    expect(r.browserLike).toBe(true);
    expect(r.reasons).toEqual([]);
  });

  it("absence de h2 → reason ALPN + non browserLike", () => {
    const r = classifyTls(browserTls({ alpn: ['http/1.1'] }));
    expect(r.browserLike).toBe(false);
    expect(r.reasons).toContain("ALPN n'annonce pas h2 (un navigateur HTTPS l'offre toujours)");
  });

  it('moins de 5 ciphers → reason cipher count', () => {
    const r = classifyTls(browserTls({ ciphers: [0x1301, 0x1302] }));
    expect(r.reasons).toContain('seulement 2 cipher suites proposées');
    expect(r.browserLike).toBe(false);
  });

  it("pas de TLS 1.3 (TLS 1.2 only) → reason supported_versions", () => {
    const r = classifyTls(browserTls({ supportedVersions: [TLS12] }));
    expect(r.reasons).toContain("supported_versions n'annonce pas TLS 1.3");
    expect(r.browserLike).toBe(false);
  });

  it('TLS 1.3 annoncé mais key_share absent → reason handshake incomplet', () => {
    const r = classifyTls(browserTls({ extensions: [GREASE, EXT.GROUPS, EXT.SIG_ALGS, EXT.SUPPORTED_VERSIONS, 0, 23] }));
    expect(r.reasons).toContain('TLS 1.3 annoncé sans extension key_share (handshake incomplet)');
    expect(r.browserLike).toBe(false);
  });

  it('signature_algorithms absent → reason', () => {
    const r = classifyTls(browserTls({ extensions: [GREASE, EXT.GROUPS, EXT.SUPPORTED_VERSIONS, EXT.KEY_SHARE, 0, 23] }));
    expect(r.reasons).toContain('pas de signature_algorithms (extension standard des navigateurs)');
  });

  it('groupes présents mais X25519 absent → reason courbe', () => {
    const r = classifyTls(browserTls({ ellipticCurves: [23, 24] }));
    expect(r.reasons).toContain('X25519 absent des courbes proposées');
    expect(r.browserLike).toBe(false);
  });
});

describe('matchToolSignature — ordre spécifique → générique', () => {
  it('un vrai navigateur (avec GREASE) → null (uTLS-clone parfait passe structurellement)', () => {
    expect(matchToolSignature(browserTls())).toBeNull();
  });

  it('ni TLS 1.3 ni h2 → première signature (la plus spécifique l’emporte)', () => {
    const sig = matchToolSignature(browserTls({ supportedVersions: [TLS12], alpn: [] }));
    expect(sig).toBe('client HTTP sans TLS 1.3 ni HTTP/2 (curl / requests / Go par défaut)');
  });

  it('TLS 1.3 sans key_share → signature « pile sans key_share »', () => {
    const sig = matchToolSignature(browserTls({ extensions: [GREASE, EXT.GROUPS, EXT.SIG_ALGS, EXT.SUPPORTED_VERSIONS, 0, 23] }));
    expect(sig).toBe('pile TLS sans key_share (pas de vrai handshake TLS 1.3 — lib basique)');
  });

  it('hello riche mais SANS GREASE → dernière signature « absence de GREASE »', () => {
    // Démontre le piège : tout est browser-like sauf le padding GREASE → c'est le
    // dernier filet qui attrape l’imitateur ayant copié les ciphers mais pas GREASE.
    const sig = matchToolSignature(
      browserTls({
        ciphers: [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc02c],
        extensions: [EXT.GROUPS, EXT.SIG_ALGS, EXT.SUPPORTED_VERSIONS, EXT.KEY_SHARE, 0, 23],
        ellipticCurves: [X25519, 23, 24],
        supportedVersions: [TLS13, TLS12],
      }),
    );
    expect(sig).toBe('absence de GREASE (Chrome/Edge en injectent partout)');
  });

  it('très peu de ciphers (mais sinon riche+GREASE) → signature « minimaliste »', () => {
    // 4 ciphers dont GREASE → cipherCount 4 (<5). hasGrease true, donc on ne tombe
    // pas dans « absence de GREASE » ; c’est la signature cipherCount qui matche.
    const sig = matchToolSignature(browserTls({ ciphers: [GREASE, 0x1301, 0x1302, 0x1303] }));
    expect(sig).toBe('client TLS minimaliste (très peu de cipher suites)');
  });
});
