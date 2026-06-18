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