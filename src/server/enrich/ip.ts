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

// Single source of truth for "skip IP-intelligence lookups for this address?" —
// loopback, RFC1918 private, link-local and ULA ranges a GeoIP/ASN/rDNS lookup
// can never meaningfully resolve.
//
// Centralised on purpose: the checks had diverged. `geoip.lookupAsn` skipped the
// ENTIRE 172.0.0.0/8 via `ip.startsWith('172.')`, but only 172.16.0.0/12 is
// private — so public datacenter ranges that live in 172/8 (Cloudflare
// 172.64.0.0/13, Google 172.217.0.0/16, others) were silently treated as private
// and returned no ASN. With no ASN, `classifyAsn` yields {isDatacenter:null,
// isProxyHint:null}, so the `ip_datacenter` / `ip_proxy` bot signals never fired:
// a bot egressing from such a 172.x public host evaded the whole network-origin
// classification (audit finding E1). `rdns.ts` already used the correct /12 test;
// this helper makes geoip and rdns share it so they can't drift again.
export function isPrivateOrReservedIp(ip: string): boolean {
  return (
    !ip ||
    ip === '127.0.0.1' ||
    ip === '::1' ||
    ip.startsWith('10.') ||
    ip.startsWith('192.168.') ||
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./.test(ip) || // 172.16.0.0/12 only
    ip.startsWith('169.254.') ||
    ip.startsWith('fc') ||
    ip.startsWith('fd') ||
    ip.startsWith('fe80')
  );
}
