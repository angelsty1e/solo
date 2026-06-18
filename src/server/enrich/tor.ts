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

import fs from 'node:fs';
import net from 'node:net';
import readline from 'node:readline';

// Tor exit list: one IPv4/IPv6 per line. The user is expected to refresh
// this from https://check.torproject.org/torbulkexitlist on a schedule
// (cron / systemd timer). We stream it line-by-line at startup so a huge (or
// malicious) file never has to be loaded into memory all at once, and only
// well-formed IP literals are kept.
const exits = new Set<string>();
let loadAttempted = false;
let listPath = '';
let count = 0;
let mtime: string | null = null;

export async function initTorList(path: string): Promise<boolean> {
  listPath = path;
  loadAttempted = true;
  exits.clear();
  if (!fs.existsSync(path)) {
    count = 0;
    mtime = null;
    return false;
  }
  const rl = readline.createInterface({
    input: fs.createReadStream(path, { encoding: 'utf8' }),
    crlfDelay: Infinity,
  });
  for await (const line of rl) {
    const ip = line.trim();
    if (!ip || ip.startsWith('#')) continue;
    // Reject anything that isn't a valid IPv4/IPv6 literal — keeps junk /
    // hostile lines out of the lookup set.
    if (net.isIP(ip) !== 0) exits.add(ip);
  }
  count = exits.size;
  mtime = fs.statSync(path).mtime.toISOString();
  return true;
}

export function isTorExit(ip: string): boolean | null {
  if (!loadAttempted) return null;
  if (exits.size === 0) return null;
  if (!ip) return null;
  return exits.has(ip);
}

export function torListStatus(): { loaded: boolean; attempted: boolean; path: string; count: number; mtime: string | null } {
  return { loaded: exits.size > 0, attempted: loadAttempted, path: listPath, count, mtime };
}