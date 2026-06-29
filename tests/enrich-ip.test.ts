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
import { isPrivateOrReservedIp, canonicalizeIp } from '../src/server/enrich/ip.js';

// [E1] isPrivateOrReservedIp must scope 172 to 172.16.0.0/12 — NOT the whole
// 172.0.0.0/8 (the old `startsWith('172.')` bug that swallowed public datacenter
// ranges and let bots there dodge ip_datacenter/ip_proxy).
describe('isPrivateOrReservedIp — 172 scoping (audit E1)', () => {
  it('treats 172.16.0.0/12 as private', () => {
    for (const ip of ['172.16.0.1', '172.31.255.254', '172.20.1.1']) {
      expect(isPrivateOrReservedIp(ip)).toBe(true);
    }
  });

  it('treats public 172/8 outside /12 as PUBLIC (so ASN lookup runs)', () => {
    // Cloudflare 172.64/13, Google 172.217/16, and 172.15 / 172.32 boundaries.
    for (const ip of ['172.64.0.1', '172.217.0.1', '172.15.0.1', '172.32.0.1']) {
      expect(isPrivateOrReservedIp(ip)).toBe(false);
    }
  });

  it('still catches loopback / RFC1918 / link-local / ULA', () => {
    for (const ip of ['127.0.0.1', '::1', '10.0.0.1', '192.168.1.1', '169.254.1.1', 'fc00::1', 'fe80::1']) {
      expect(isPrivateOrReservedIp(ip)).toBe(true);
    }
    expect(isPrivateOrReservedIp('8.8.8.8')).toBe(false);
    expect(isPrivateOrReservedIp('2606:4700::1')).toBe(false);
  });
});

// [F4] A Tor exit listed in one textual form must match the socket-reported form,
// or the ip_tor signal is silently voided. canonicalizeIp collapses every spelling
// of one address to a single string.
describe('canonicalizeIp — exact-match normalisation (audit F4)', () => {
  it('matches expanded list entry against compressed socket form', () => {
    expect(canonicalizeIp('2001:0db8:0000:0000:0000:0000:0000:0001')).toBe(canonicalizeIp('2001:db8::1'));
  });

  it('is case-insensitive', () => {
    expect(canonicalizeIp('2A02:1234::ABCD')).toBe(canonicalizeIp('2a02:1234::abcd'));
  });

  it('maps IPv4-mapped IPv6 to the dotted IPv4 (matches an IPv4 list entry)', () => {
    expect(canonicalizeIp('::ffff:185.220.101.5')).toBe('185.220.101.5');
    expect(canonicalizeIp('185.220.101.5')).toBe('185.220.101.5');
  });

  it('strips an IPv6 zone id', () => {
    expect(canonicalizeIp('fe80::1%eth0')).toBe(canonicalizeIp('fe80::1'));
  });

  it('keeps distinct addresses distinct', () => {
    expect(canonicalizeIp('2001:db8::1')).not.toBe(canonicalizeIp('2001:db8::2'));
  });
});
