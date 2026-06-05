import { describe, it, expect, beforeAll, afterAll, beforeEach, vi } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// ─── isTorExit / initTorList — liste d'exit Tor (état module-level) ──────────
// Le module porte un singleton (`exits`, `loadAttempted`). Conséquence pour les
// tests : une fois initTorList appelé, loadAttempted reste true À VIE pour cette
// instance de module. Le cas « avant tout init → null » est donc impossible sans
// repartir d'un module VIERGE → vi.resetModules() + import() dynamique par test.
//
// Invariant clé : isTorExit ne renvoie JAMAIS false tant qu'aucune liste utile
// n'est chargée — c'est null (inconnu). Une liste optionnelle absente ne doit pas
// silencieusement disqualifier le crédit résidentiel (cf. trust.ts:118-120).

let dir: string;
let validList: string;
let emptyList: string;
const MISSING = '/nonexistent/path/torbulkexitlist.txt';

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'solo-tor-'));
  validList = join(dir, 'exits.txt');
  emptyList = join(dir, 'empty.txt');
  // Mélange volontaire : commentaires, lignes vides, junk non-IP, IPv4 + IPv6.
  writeFileSync(
    validList,
    [
      '# Tor bulk exit list',
      '',
      '198.51.100.1',
      '198.51.100.2',
      'not-an-ip-at-all',
      '2001:db8::1',
      'garbage 12345 junk',
      '# trailing comment',
    ].join('\n'),
  );
  writeFileSync(emptyList, '# header only\n\n');
});

afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

// Chaque test repart d'un module vierge.
beforeEach(() => {
  vi.resetModules();
});
async function load() {
  return import('../src/server/enrich/tor.js');
}

describe('isTorExit — états sans liste utile → null (jamais false)', () => {
  it('avant tout initTorList → null', async () => {
    const tor = await load();
    expect(tor.isTorExit('198.51.100.1')).toBeNull();
  });

  it('fichier manquant → init renvoie false, isTorExit reste null', async () => {
    const tor = await load();
    expect(await tor.initTorList(MISSING)).toBe(false);
    expect(tor.isTorExit('198.51.100.1')).toBeNull();
    expect(tor.torListStatus()).toMatchObject({ loaded: false, attempted: true, count: 0, mtime: null });
  });

  it('liste vide (que des commentaires) → isTorExit reste null (pas false)', async () => {
    const tor = await load();
    expect(await tor.initTorList(emptyList)).toBe(true); // fichier lu, mais 0 IP utile
    expect(tor.isTorExit('198.51.100.1')).toBeNull();
    expect(tor.torListStatus().count).toBe(0);
  });

  it('IP vide → null même liste chargée', async () => {
    const tor = await load();
    await tor.initTorList(validList);
    expect(tor.isTorExit('')).toBeNull();
  });
});

describe('isTorExit — liste valide chargée', () => {
  it('IP dans la liste → true, hors liste → false', async () => {
    const tor = await load();
    expect(await tor.initTorList(validList)).toBe(true);
    expect(tor.isTorExit('198.51.100.1')).toBe(true);
    expect(tor.isTorExit('2001:db8::1')).toBe(true); // IPv6 conservée
    expect(tor.isTorExit('203.0.113.99')).toBe(false); // hors liste, MAIS liste utile → false légitime
  });

  it('initTorList filtre les lignes non-IP (commentaires, junk) via net.isIP', async () => {
    const tor = await load();
    await tor.initTorList(validList);
    // 8 lignes en entrée, seules 3 sont des IP valides (2× IPv4 + 1× IPv6).
    expect(tor.torListStatus().count).toBe(3);
    expect(tor.isTorExit('not-an-ip-at-all')).toBe(false);
  });

  it('torListStatus expose loaded/attempted/count/path', async () => {
    const tor = await load();
    await tor.initTorList(validList);
    expect(tor.torListStatus()).toMatchObject({ loaded: true, attempted: true, count: 3, path: validList });
  });
});
