import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { sha256File, verifyFileSha256 } from '../src/server/enrich/integrity.js';

// ─── Intégrité des bases MaxMind (.mmdb) — fail-closed opt-in ─────────────────
// verifyFileSha256 garde la chaîne d'approvisionnement de la GeoIP : une base
// altérée/corrompue ne doit jamais être chargée. Le contrat (integrity.ts) :
//   • pas de hash attendu (undefined / vide / espaces) → true (skip opt-in)
//   • hash attendu présent ET concordant → true
//   • hash attendu présent ET divergent → false (fail-closed)
// Comparaison insensible à la casse et aux espaces (`.trim().toLowerCase()`).

let dir: string;
const CONTENT = 'fake mmdb payload\n';
let filePath: string;
let realHash: string;

beforeAll(() => {
  dir = mkdtempSync(join(tmpdir(), 'solo-integrity-'));
  filePath = join(dir, 'GeoLite2-ASN.mmdb');
  writeFileSync(filePath, CONTENT);
  realHash = createHash('sha256').update(CONTENT).digest('hex');
});

afterAll(() => {
  rmSync(dir, { recursive: true, force: true });
});

describe('sha256File', () => {
  it('hash en streaming = hash de référence node:crypto', async () => {
    expect(await sha256File(filePath)).toBe(realHash);
  });
});

describe('verifyFileSha256 — opt-in (pas de hash → skip)', () => {
  it('expected=undefined → true (vérification désactivée)', async () => {
    expect(await verifyFileSha256(filePath, undefined)).toBe(true);
  });

  it('expected="" → true (chaîne vide = pas de hash)', async () => {
    expect(await verifyFileSha256(filePath, '')).toBe(true);
  });

  it('expected="   " (espaces) → true (trim → vide)', async () => {
    expect(await verifyFileSha256(filePath, '   ')).toBe(true);
  });
});

describe('verifyFileSha256 — fail-closed (hash présent)', () => {
  it('hash correct → true', async () => {
    expect(await verifyFileSha256(filePath, realHash)).toBe(true);
  });

  it('hash correct en MAJUSCULES → true (insensible à la casse)', async () => {
    expect(await verifyFileSha256(filePath, realHash.toUpperCase())).toBe(true);
  });

  it('hash correct entouré d’espaces → true (trim)', async () => {
    expect(await verifyFileSha256(filePath, `  ${realHash}  `)).toBe(true);
  });

  it('hash faux → false (fail-closed : la base altérée n’est pas chargée)', async () => {
    const wrong = 'deadbeef'.repeat(8); // 64 hex, ≠ realHash
    expect(await verifyFileSha256(filePath, wrong)).toBe(false);
  });
});
