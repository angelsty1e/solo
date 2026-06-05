import { existsSync } from 'node:fs';
import { open, type AsnResponse, type Reader } from 'maxmind';
import { verifyFileSha256 } from './integrity.js';

let reader: Reader<AsnResponse> | null = null;
let loadAttempted = false;
let dbPath = '';

// `expectedSha256` is optional: when provided (e.g. from env) the DB is verified
// before use and loading fails closed on mismatch; when absent the check is
// skipped for backward compatibility.
export async function initGeoIp(path: string, expectedSha256?: string): Promise<boolean> {
  dbPath = path;
  loadAttempted = true;
  if (!existsSync(path)) {
    reader = null;
    return false;
  }
  if (!(await verifyFileSha256(path, expectedSha256))) {
    reader = null;
    throw new Error(`GeoIP ASN DB integrity check failed (SHA-256 mismatch) for ${path}`);
  }
  reader = await open<AsnResponse>(path);
  return true;
}

export interface GeoLookup {
  asn: number | null;
  asnOrganization: string | null;
}

export function lookupAsn(ip: string): GeoLookup {
  if (!reader) return { asn: null, asnOrganization: null };
  if (!ip || ip === '127.0.0.1' || ip === '::1' || ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.')) {
    return { asn: null, asnOrganization: null };
  }
  try {
    const r = reader.get(ip);
    if (!r) return { asn: null, asnOrganization: null };
    return {
      asn: typeof r.autonomous_system_number === 'number' ? r.autonomous_system_number : null,
      asnOrganization: r.autonomous_system_organization ?? null,
    };
  } catch {
    return { asn: null, asnOrganization: null };
  }
}

export function geoIpStatus(): { loaded: boolean; attempted: boolean; path: string } {
  return { loaded: reader !== null, attempted: loadAttempted, path: dbPath };
}
