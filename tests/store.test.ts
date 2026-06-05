import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import type { ClientFingerprint, IpFingerprint, ServerFingerprint } from '../src/shared/types.js';
import type { DecisionResult } from '../src/shared/decision/types.js';
import { initDb, getDb, closeDb } from '../src/server/db.js';
import { upsertServer, upsertClient, upsertDecision, fingerprintReputation, get, list, startSweeper } from '../src/server/store.js';

// ─── Store SQLite — intégration en base :memory: ─────────────────────────────
// Tests d'intégration sur une base éphémère (foreign_keys ON → CASCADE réel).
// Couvre les invariants à VRAI risque que les fonctions pures ne touchent pas :
//   • startSweeper : expiration RÉELLE des sessions + purge des tables enfant
//     (invariant RGPD — pas d'orphelins après le TTL ; cf. audit-privacy).
//   • fingerprintReputation : compte d'IP DISTINCTES (alimente N5 swarm), null-safe
//     sur le couple (canvas, webgl) (anti-évasion A7), fenêtre de rétention.
//   • upsertServer : ⚠️ incohérence trouvée — is_proxy_hint écrase null en 0,
//     alors que is_datacenter / is_tor_exit préservent null (épinglé ci-dessous).

const T0 = new Date('2026-06-01T00:00:00.000Z').getTime();
const HOUR = 60 * 60 * 1000;

beforeEach(() => {
  // Horloge figée + déterministe : nowMs()=Date.now() est faké, donc created_at /
  // expires_at / le sweeper sont tous pilotables.
  vi.useFakeTimers();
  vi.setSystemTime(T0);
  initDb(':memory:');
});

afterEach(() => {
  closeDb();
  vi.useRealTimers();
});

// ─── Fixtures minimales ──────────────────────────────────────────────────────
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

function serverFp(over: Partial<IpFingerprint> = {}): ServerFingerprint {
  return { capturedAt: '2026-06-01T00:00:00.000Z', tls: null, http: null, ip: ipFp(over) };
}

function clientFp(sessionId: string, canvas: string | null, webgl: string | null): ClientFingerprint {
  return {
    sessionId,
    collectedAt: '2026-06-01T00:00:00.000Z',
    durationMs: 8000,
    canvas: canvas ? { dataUrlHash: canvas } : null,
    webgl: webgl ? { parametersHash: webgl } : null,
  } as unknown as ClientFingerprint;
}

function decisionFp(): DecisionResult {
  return {
    verdict: 'clean',
    score: 0,
    forced: false,
    byLevel: [],
    trustScore: 0,
    trustSignals: [],
    cards: [],
    configVersion: 'test',
    computedAt: '2026-06-01T00:00:00.000Z',
  };
}

// Crée une session complète (sessions + server_ip + client_full + decisions) →
// 4 lignes, dont 3 enfants pour vérifier le CASCADE.
function makeSession(
  id: string,
  opts: { ip?: string; canvas?: string | null; webgl?: string | null } & Partial<IpFingerprint> = {},
): void {
  const { ip = '203.0.113.7', canvas = null, webgl = null, ...ipOver } = opts;
  upsertServer(id, serverFp({ ip, ...ipOver }));
  upsertClient(id, clientFp(id, canvas, webgl));
  upsertDecision(id, decisionFp());
}

const rawCount = (table: string, id: string): number =>
  (getDb().prepare(`SELECT COUNT(*) AS n FROM ${table} WHERE session_id = ?`).get(id) as { n: number }).n;

// ─────────────────────────────────────────────────────────────────────────────
// Round-trip + filtre d'expiration
// ─────────────────────────────────────────────────────────────────────────────
describe('upsert / get — round-trip et filtre d’expiration', () => {
  it('une session fraîchement écrite est relisible', () => {
    makeSession('s1', { ip: '198.51.100.1', canvas: 'C1', webgl: 'W1' });
    const full = get('s1');
    expect(full).not.toBeNull();
    expect(full!.sessionId).toBe('s1');
    expect(full!.server.ip?.ip).toBe('198.51.100.1');
  });

  it('upsert idempotent : réécrire le même id ne crée pas de doublon', () => {
    makeSession('s1', { ip: '198.51.100.1' });
    upsertServer('s1', serverFp({ ip: '198.51.100.2' })); // ON CONFLICT → update
    const rows = (getDb().prepare(`SELECT COUNT(*) AS n FROM sessions WHERE id = 's1'`).get() as { n: number }).n;
    expect(rows).toBe(1);
    expect(get('s1')!.server.ip?.ip).toBe('198.51.100.2');
  });

  it('au-delà du TTL, get() ne retourne plus la session (filtre expires_at)', () => {
    makeSession('s1');
    vi.setSystemTime(T0 + 2 * HOUR); // expires_at = T0+1h < now
    expect(get('s1')).toBeNull();
  });

  it('list() n’expose que les sessions non expirées', () => {
    makeSession('alive');
    vi.setSystemTime(T0 + 30 * 60 * 1000);
    makeSession('also-alive');
    vi.setSystemTime(T0 + 90 * 60 * 1000); // 'alive' (exp T0+60m) expirée, l'autre non
    const ids = list().map((r) => r.sessionId);
    expect(ids).toContain('also-alive');
    expect(ids).not.toContain('alive');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// fingerprintReputation — compte d'IP distinctes (alimente N5)
// ─────────────────────────────────────────────────────────────────────────────
describe('fingerprintReputation', () => {
  it('compte les IP DISTINCTES partageant la même empreinte (canvas+webgl)', () => {
    for (let i = 1; i <= 4; i++) makeSession(`s${i}`, { ip: `1.0.0.${i}`, canvas: 'C', webgl: 'W' });
    const rep = fingerprintReputation('C', 'W');
    expect(rep.fpDistinctIps).toBe(4);
    expect(rep.fpTotalSessions).toBe(4);
  });

  it('même IP rescannée plusieurs fois → 1 seule IP distincte (robuste au re-scan)', () => {
    makeSession('a', { ip: '1.0.0.9', canvas: 'C', webgl: 'W' });
    makeSession('b', { ip: '1.0.0.9', canvas: 'C', webgl: 'W' });
    const rep = fingerprintReputation('C', 'W');
    expect(rep.fpDistinctIps).toBe(1);
    expect(rep.fpTotalSessions).toBe(2);
  });

  it('null-safe (A7) : un essaim qui omet TOUJOURS le canvas se compte lui-même', () => {
    // L'identité est le COUPLE exact (canvas, webgl), matché null-safe (IS ?). Un
    // bot qui met canvas=null (en gardant webgl pour son crédit GPU) ne s'évade
    // plus : ses sessions collisionnent entre elles sur (null, 'W').
    makeSession('x', { ip: '2.0.0.1', canvas: null, webgl: 'W' });
    makeSession('y', { ip: '2.0.0.2', canvas: null, webgl: 'W' });
    const rep = fingerprintReputation(null, 'W');
    expect(rep.fpDistinctIps).toBe(2);
  });

  it('les deux surfaces nulles → aucun jugement (humain durci ≠ un seul bucket)', () => {
    makeSession('z', { ip: '2.0.0.3', canvas: null, webgl: null });
    expect(fingerprintReputation(null, null)).toEqual({ fpDistinctIps: 0, fpTotalSessions: 0 });
  });

  it('fenêtre de rétention : une session plus vieille que le TTL est exclue du compte', () => {
    makeSession('old', { ip: '3.0.0.1', canvas: 'C', webgl: 'W' }); // created_at = T0
    vi.setSystemTime(T0 + 2 * HOUR); // since = now-1h = T0+1h ; 'old' (T0) est hors fenêtre
    makeSession('new', { ip: '3.0.0.2', canvas: 'C', webgl: 'W' }); // created_at = T0+2h
    const rep = fingerprintReputation('C', 'W');
    expect(rep.fpDistinctIps).toBe(1); // seule 'new' compte
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Préservation de null sur les drapeaux d'enrichissement (store.ts:118-121)
// Les TROIS drapeaux (is_datacenter, is_proxy_hint, is_tor_exit) doivent préserver
// null (GeoIP down / ASN non résolu) plutôt que l'écraser en 0. null = "inconnu",
// 0 = "confirmé absent" : les confondre fait compter du GeoIP-down comme
// résidentiel confirmé dans toute requête analytique `WHERE is_proxy_hint = 0`.
// is_proxy_hint a été aligné sur ses deux frères (`== null ? null : … ? 1 : 0`) ;
// ce test verrouille les trois contre une régression.
// ─────────────────────────────────────────────────────────────────────────────
describe('upsertServer — préservation de null sur les drapeaux d’enrichissement', () => {
  function readFlags(id: string) {
    return getDb()
      .prepare(`SELECT is_datacenter, is_proxy_hint, is_tor_exit FROM sessions WHERE id = ?`)
      .get(id) as { is_datacenter: number | null; is_proxy_hint: number | null; is_tor_exit: number | null };
  }

  it('GeoIP down (null) est préservé sur les trois drapeaux (jamais écrasé en 0)', () => {
    upsertServer('g', serverFp({ isDatacenter: null, isProxyHint: null, isTorExit: null }));
    const f = readFlags('g');
    expect(f.is_datacenter).toBeNull();
    expect(f.is_proxy_hint).toBeNull(); // ← aligné : null préservé, plus écrasé en 0
    expect(f.is_tor_exit).toBeNull();
  });

  it('true/false sont stockés fidèlement (1/0) sur les trois drapeaux', () => {
    upsertServer('t', serverFp({ isDatacenter: true, isProxyHint: true, isTorExit: false }));
    const f = readFlags('t');
    expect(f.is_datacenter).toBe(1);
    expect(f.is_proxy_hint).toBe(1);
    expect(f.is_tor_exit).toBe(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// startSweeper — expiration réelle + purge en cascade des tables enfant
// ─────────────────────────────────────────────────────────────────────────────
describe('startSweeper — purge des sessions expirées et de leurs enfants', () => {
  it('supprime physiquement la session expirée ET ses lignes enfant (CASCADE), garde la fraîche', () => {
    makeSession('expired', { ip: '4.0.0.1' }); // created_at T0, expires_at T0+1h
    const timer = startSweeper(); // setInterval toutes les 5 min

    // Avance à T0+30min : 6 balayages, rien d'expiré encore.
    vi.advanceTimersByTime(30 * 60 * 1000);
    makeSession('fresh', { ip: '4.0.0.2' }); // expires_at = T0+30m+1h = T0+90m

    // Avance jusqu'à T0+70min : un balayage avec now ≥ T0+65min purge 'expired'.
    vi.advanceTimersByTime(40 * 60 * 1000);
    clearInterval(timer);

    // 'expired' physiquement supprimée de sessions ET des tables enfant (CASCADE).
    expect((getDb().prepare(`SELECT COUNT(*) AS n FROM sessions WHERE id = 'expired'`).get() as { n: number }).n).toBe(0);
    expect(rawCount('server_ip', 'expired')).toBe(0);
    expect(rawCount('client_full', 'expired')).toBe(0);
    expect(rawCount('decisions', 'expired')).toBe(0);

    // 'fresh' intacte (pas encore expirée) — preuve que le sweep est sélectif.
    expect((getDb().prepare(`SELECT COUNT(*) AS n FROM sessions WHERE id = 'fresh'`).get() as { n: number }).n).toBe(1);
    expect(rawCount('server_ip', 'fresh')).toBe(1);
    expect(rawCount('client_full', 'fresh')).toBe(1);
    expect(rawCount('decisions', 'fresh')).toBe(1);
  });
});
