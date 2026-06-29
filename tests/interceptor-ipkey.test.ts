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

import { describe, it, expect } from 'vitest';
import { connCapKey } from '../src/server/tls/interceptor.js';

// [N1] connCapKey is the per-source bucket for BOTH the concurrency cap and the
// rate-limit. The /64 grouping must survive IPv6 host-bit rotation in EVERY
// textual form Node may emit (it returns the canonical compressed form). The old
// `split(':').slice(0,4)` leaked host bits when `::` started at/before hextet 4,
// re-opening the rotation bypass for the common `a:b::/64` allocation shape.
describe('connCapKey — /64 grouping resists IPv6 rotation (audit N1)', () => {
  it('groups a compressible-prefix /64 (2001:db8::/64) into ONE key', () => {
    const k = connCapKey('2001:db8::1');
    expect(connCapKey('2001:db8::2')).toBe(k);
    expect(connCapKey('2001:db8::cafe')).toBe(k);
    // Same /64 written fully-expanded must collapse to the same key.
    expect(connCapKey('2001:0db8:0:0:0:0:0:9')).toBe(k);
  });

  it('groups a full-prefix /64 into ONE key', () => {
    const k = connCapKey('2401:4900:1a8f:bc2e::1');
    expect(connCapKey('2401:4900:1a8f:bc2e::2')).toBe(k);
    expect(connCapKey('2401:4900:1a8f:bc2e::dead:beef')).toBe(k);
  });

  it('keeps DISTINCT /64s in distinct keys', () => {
    expect(connCapKey('2001:db8::1')).not.toBe(connCapKey('2001:db9::1'));
    expect(connCapKey('2401:4900:1a8f:bc2e::1')).not.toBe(connCapKey('2401:4900:1a8f:bc2f::1'));
  });

  it('keys IPv4 on the full host address', () => {
    expect(connCapKey('203.0.113.4')).toBe('203.0.113.4');
    expect(connCapKey('203.0.113.4')).not.toBe(connCapKey('203.0.113.5'));
  });

  it('keys IPv4-mapped IPv6 per-host (not one shared /64 bucket)', () => {
    expect(connCapKey('::ffff:1.2.3.4')).not.toBe(connCapKey('::ffff:1.2.3.5'));
  });

  it('strips an IPv6 zone id before grouping', () => {
    expect(connCapKey('fe80::1%eth0')).toBe(connCapKey('fe80::2%eth1'));
  });

  it('empty address yields an empty key (unkeyable → caller falls back)', () => {
    expect(connCapKey('')).toBe('');
  });
});
