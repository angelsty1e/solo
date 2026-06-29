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

import dns from 'node:dns/promises';
import { isPrivateOrReservedIp } from './ip.js';

// Best-effort PTR lookup. Capped at ~250ms so a slow resolver can't stall
// `/collect`. Result cached for an hour — same IP hits us repeatedly during
// a behavioral session and we don't want N×lookups.
//
// NOT forward-confirmed (CWE-350): the PTR record is set by the IP's owner, and
// we take names[0] without resolving it back to the IP. This is deliberate and
// safe HERE because the derived `rdns_hosting` signal is ADVISORY and strictly
// ONE-DIRECTIONAL — it only ADDS bot suspicion, never grants trust. A forged PTR
// can therefore at most suppress suspicion on the attacker's OWN IP (something a
// hosting customer can already do, and which ASN-number classification still
// catches); it can never mint a positive verdict or poison a victim. The day
// rDNS feeds a trust/positive decision, switch to forward-confirmed rDNS (FCrDNS:
// resolve the PTR name's A/AAAA and require it to map back to `ip`).

const CACHE_TTL_MS = 60 * 60 * 1000;
// Bound the cache so a flood of distinct source IPs can't grow it without
// limit. Map preserves insertion order, so the first key is the oldest — we
// evict it (LRU) once we exceed the cap. Each entry also carries a TTL.
const CACHE_MAX = 100_000;
const cache = new Map<string, { value: string | null; expiresAt: number }>();

function cacheStore(ip: string, value: string | null, now: number): void {
  // Re-insert at the end so recently-used keys are the last to be evicted.
  cache.delete(ip);
  cache.set(ip, { value, expiresAt: now + CACHE_TTL_MS });
  while (cache.size > CACHE_MAX) {
    const oldest = cache.keys().next().value;
    if (oldest === undefined) break;
    cache.delete(oldest);
  }
}

export async function reverseDns(ip: string, timeoutMs = 250): Promise<string | null> {
  if (isPrivateOrReservedIp(ip)) return null;
  const now = Date.now();
  const cached = cache.get(ip);
  if (cached && cached.expiresAt > now) return cached.value;

  // Cap the lookup so a slow/hostile resolver can't stall /collect. Capture the
  // timer to clear it on the fast-success path (otherwise it holds an event-loop
  // ref for up to timeoutMs) and unref it so it can never keep the process alive.
  // (The underlying c-ares query isn't cancellable and may finish in the
  // background — harmless given the cache + the global rate limits.)
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<null>((resolve) => {
    timer = setTimeout(() => resolve(null), timeoutMs);
    timer.unref?.();
  });
  const result = await Promise.race<string | null>([
    dns.reverse(ip).then((names) => names[0] ?? null).catch(() => null),
    timeout,
  ]).finally(() => {
    if (timer) clearTimeout(timer);
  });
  cacheStore(ip, result, now);
  return result;
}

// Synchronous wrapper that returns the cached value (or null) without
// blocking. Used when we need a server fingerprint immediately and don't
// want to await — the lookup populates the cache for the next request.
export function reverseDnsCached(ip: string): string | null {
  const c = cache.get(ip);
  if (c && c.expiresAt > Date.now()) return c.value;
  return null;
}