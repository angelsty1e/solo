import { existsSync } from 'node:fs';
import { open, type CountryResponse, type Reader } from 'maxmind';
import { verifyFileSha256 } from './integrity.js';

let reader: Reader<CountryResponse> | null = null;
let loadAttempted = false;
let dbPath = '';

// `expectedSha256` is optional: when provided the DB is verified before use and
// loading fails closed on mismatch; when absent the check is skipped.
export async function initCountryDb(path: string, expectedSha256?: string): Promise<boolean> {
  dbPath = path;
  loadAttempted = true;
  if (!existsSync(path)) {
    reader = null;
    return false;
  }
  if (!(await verifyFileSha256(path, expectedSha256))) {
    reader = null;
    throw new Error(`GeoIP Country DB integrity check failed (SHA-256 mismatch) for ${path}`);
  }
  reader = await open<CountryResponse>(path);
  return true;
}

export function lookupCountry(ip: string): string | null {
  if (!reader) return null;
  if (!ip || ip === '127.0.0.1' || ip === '::1') return null;
  try {
    const r = reader.get(ip);
    return r?.country?.iso_code ?? null;
  } catch {
    return null;
  }
}

export function countryDbStatus(): { loaded: boolean; attempted: boolean; path: string } {
  return { loaded: reader !== null, attempted: loadAttempted, path: dbPath };
}
