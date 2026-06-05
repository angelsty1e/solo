import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';

// ─── reverseDns / reverseDnsCached — PTR best-effort, cache TTL ──────────────
// On mocke node:dns/promises pour ne JAMAIS faire de vrai DNS en test (flaky/lent)
// et pour observer si un lookup a été tenté. Le module porte un cache singleton :
// chaque test utilise une IP DISTINCTE pour éviter les collisions de cache.
const { reverseMock } = vi.hoisted(() => ({ reverseMock: vi.fn() }));
vi.mock('node:dns/promises', () => ({ default: { reverse: reverseMock } }));

import { reverseDns, reverseDnsCached } from '../src/server/enrich/rdns.js';

beforeEach(() => {
  reverseMock.mockReset();
});
afterEach(() => {
  vi.useRealTimers();
});

// ─────────────────────────────────────────────────────────────────────────────
// IP privées : court-circuitées AVANT tout lookup (pas d'abus du résolveur)
// ─────────────────────────────────────────────────────────────────────────────
describe('reverseDns — IP privées → null sans lookup', () => {
  const privates = [
    '10.0.0.1',
    '192.168.1.1',
    '172.16.0.1',
    '172.31.255.1',
    '127.0.0.1',
    '::1',
    '169.254.1.1',
    'fc00::1',
    'fd12::1',
    'fe80::abcd',
    '',
  ];
  for (const ip of privates) {
    it(`${ip || '(vide)'} → null, aucun appel DNS`, async () => {
      expect(await reverseDns(ip)).toBeNull();
      expect(reverseMock).not.toHaveBeenCalled();
    });
  }

  it('172.15.x est HORS plage privée (172.16–31 seulement) → lookup tenté', async () => {
    reverseMock.mockResolvedValue(['x.example.com']);
    await reverseDns('172.15.0.1');
    expect(reverseMock).toHaveBeenCalledWith('172.15.0.1');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// IP publique : résolution, cache, lecture synchrone
// ─────────────────────────────────────────────────────────────────────────────
describe('reverseDns — résolution et cache', () => {
  it('PTR résolu, mis en cache, relu sans 2e lookup ; reverseDnsCached concorde', async () => {
    reverseMock.mockResolvedValue(['host.example.com']);
    expect(await reverseDns('8.8.8.8')).toBe('host.example.com');
    expect(reverseMock).toHaveBeenCalledTimes(1);
    // 2e appel servi par le cache → toujours 1 seul lookup.
    expect(await reverseDns('8.8.8.8')).toBe('host.example.com');
    expect(reverseMock).toHaveBeenCalledTimes(1);
    // Le wrapper synchrone lit la même valeur cachée.
    expect(reverseDnsCached('8.8.8.8')).toBe('host.example.com');
  });

  it('aucun PTR (tableau vide) → null', async () => {
    reverseMock.mockResolvedValue([]);
    expect(await reverseDns('8.8.4.4')).toBeNull();
  });

  it('reverseDnsCached sur une IP jamais résolue → null (pas de blocage)', () => {
    expect(reverseDnsCached('203.0.113.200')).toBeNull();
  });

  it('TTL : reverseDnsCached renvoie null après expiration (1h)', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(0);
    reverseMock.mockResolvedValue(['ttl.example.com']);
    expect(await reverseDns('9.9.9.9')).toBe('ttl.example.com');
    expect(reverseDnsCached('9.9.9.9')).toBe('ttl.example.com');
    vi.setSystemTime(60 * 60 * 1000 + 1); // > CACHE_TTL_MS
    expect(reverseDnsCached('9.9.9.9')).toBeNull();
  });

  it('lookup qui traîne au-delà du timeout → null (le résolveur lent ne bloque pas /collect)', async () => {
    vi.useFakeTimers();
    reverseMock.mockReturnValue(new Promise(() => {})); // ne se résout jamais
    const p = reverseDns('7.7.7.7', 250);
    await vi.advanceTimersByTimeAsync(250);
    expect(await p).toBeNull();
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// ⚠️ BUGS isPrivate (asn.ts non concerné) — détection par préfixe string
// isPrivate fait des startsWith SENSIBLES À LA CASSE et incomplets. Comme cette
// fonction garde l'accès au résolveur et reçoit des IP issues du XFF (contrôlé
// client, cf. audit-endpoints), ces cas méritent d'être épinglés.
// ─────────────────────────────────────────────────────────────────────────────
describe('⚠️ reverseDns — détection isPrivate sensible à la casse / incomplète', () => {
  it('casse : FC00::1 (MAJUSCULES) n’est PAS reconnu privé → lookup tenté', async () => {
    reverseMock.mockResolvedValue([]);
    await reverseDns('FC00::1');
    // Bug : startsWith('fc') est sensible à la casse. Une ULA en majuscules échappe
    // au court-circuit et déclenche un reverse DNS. Devrait court-circuiter.
    expect(reverseMock).toHaveBeenCalledWith('FC00::1');
  });

  it('contre-épreuve : fc00::1 (minuscules) court-circuite bien (aucun lookup)', async () => {
    await reverseDns('fc00::1');
    expect(reverseMock).not.toHaveBeenCalled();
  });

  it('couverture fe80::/10 incomplète : fe90:: n’est PAS reconnu privé → lookup tenté', async () => {
    reverseMock.mockResolvedValue([]);
    await reverseDns('fe90::1');
    // startsWith('fe80') ne couvre que fe80, pas tout le bloc link-local fe80::/10
    // (fe80–febf). fe90:: est link-local mais traité comme public.
    expect(reverseMock).toHaveBeenCalledWith('fe90::1');
  });
});
