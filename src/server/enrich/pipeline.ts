import type { IpFingerprint } from '../../shared/types.js';
import { lookupAsn } from './geoip.js';
import { lookupCountry } from './country.js';
import { classifyAsn } from './asn.js';
import { isTorExit } from './tor.js';
import { reverseDns, reverseDnsCached } from './rdns.js';

// ─── IP enrichment pipeline ──────────────────────────────────────────────────
// Each enricher contributes a subset of IpFingerprint fields from the IP. They
// mutate a shared accumulator and run in array order, so a dependent enricher
// (e.g. `classify`, which reads the ASN) just lists after its provider. Adding a
// new intelligence source (threat feed, ASN reputation, …) = push one entry to
// IP_ENRICHERS — no change to the route.
//
//   apply()   — synchronous, from in-memory caches / local DBs (GeoLite, lists).
//   resolve() — optional async step (network lookup), run only by the awaited path.
export interface IpEnricher {
  readonly name: string;
  apply(ip: string, acc: IpFingerprint): void;
  resolve?(ip: string, acc: IpFingerprint): Promise<void>;
}

const asnEnricher: IpEnricher = {
  name: 'asn',
  apply(ip, acc) {
    const a = lookupAsn(ip);
    acc.asn = a.asn;
    acc.asnOrganization = a.asnOrganization;
  },
};

// Must run AFTER `asn` — it reads acc.asn / acc.asnOrganization.
const classifyEnricher: IpEnricher = {
  name: 'classify',
  apply(_ip, acc) {
    const k = classifyAsn(acc.asnOrganization, acc.asn);
    acc.isDatacenter = k.isDatacenter;
    acc.isProxyHint = k.isProxyHint;
  },
};

const countryEnricher: IpEnricher = {
  name: 'country',
  apply(ip, acc) {
    acc.country = lookupCountry(ip);
  },
};

const torEnricher: IpEnricher = {
  name: 'tor',
  apply(ip, acc) {
    acc.isTorExit = isTorExit(ip);
  },
};

const rdnsEnricher: IpEnricher = {
  name: 'rdns',
  // Use the cached PTR synchronously; if absent, fire an async lookup so the
  // cache is warm for the next snapshot of this IP.
  apply(ip, acc) {
    acc.reverseDns = reverseDnsCached(ip);
    if (acc.reverseDns === null && ip) void reverseDns(ip);
  },
  // The awaited path (e.g. /collect) blocks once to fill the PTR first time.
  async resolve(ip, acc) {
    if (acc.reverseDns === null && ip) acc.reverseDns = await reverseDns(ip);
  },
};

// Order matters: `asn` before `classify`. Everything else is independent.
export const IP_ENRICHERS: IpEnricher[] = [
  asnEnricher,
  classifyEnricher,
  countryEnricher,
  torEnricher,
  rdnsEnricher,
];

// Connection-measured inputs the pipeline doesn't look up (IP is extracted from
// the socket, RTT is measured at the TCP layer) — seeded into the accumulator.
export interface IpEnrichSeed {
  ip: string;
  tcpRttMs: number | null;
}

function seed(s: IpEnrichSeed): IpFingerprint {
  return {
    ip: s.ip,
    asn: null,
    asnOrganization: null,
    country: null,
    isDatacenter: null,
    isProxyHint: false,
    reverseDns: null,
    isTorExit: null,
    tcpRttMs: s.tcpRttMs,
  };
}

// Synchronous enrichment: caches / local DBs only (used by the live /api/fp/me).
export function enrichIpSync(s: IpEnrichSeed): IpFingerprint {
  const acc = seed(s);
  for (const e of IP_ENRICHERS) e.apply(s.ip, acc);
  return acc;
}

// Awaited enrichment: runs the sync pass, then any async resolve() steps (used by
// /collect, which can afford to wait once for the rDNS PTR).
export async function enrichIpAwaited(s: IpEnrichSeed): Promise<IpFingerprint> {
  const acc = enrichIpSync(s);
  for (const e of IP_ENRICHERS) {
    if (e.resolve) await e.resolve(s.ip, acc);
  }
  return acc;
}
