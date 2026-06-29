/*
 * Copyright 2026 angelsty1e
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { existsSync } from 'node:fs';
import { open, type AsnResponse, type Reader } from 'maxmind';
import { verifyFileSha256 } from './integrity.js';
import { isPrivateOrReservedIp } from './ip.js';

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
  // Only genuinely private/reserved space is skipped. The previous inline check
  // used `ip.startsWith('172.')`, which swallowed the public 172/8 datacenter
  // ranges (Cloudflare/Google) and let bots there dodge ip_datacenter/ip_proxy
  // (audit E1). isPrivateOrReservedIp scopes 172 correctly to 172.16.0.0/12.
  if (isPrivateOrReservedIp(ip)) {
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