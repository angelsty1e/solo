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

  const result = await Promise.race<string | null>([
    dns.reverse(ip).then((names) => names[0] ?? null).catch(() => null),
    new Promise<null>((resolve) => setTimeout(() => resolve(null), timeoutMs)),
  ]);
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