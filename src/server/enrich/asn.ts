// Heuristic classification: is an IP's network typical of a datacenter / hosting
// provider (or a VPN) rather than a residential ISP. Not authoritative, but a
// useful Level-2 (network) signal.
//
// Two layers, checked in order:
//   1. ASN *number* against a curated set — authoritative and stable (an AS
//      number doesn't drift the way the free-text org name does). This is the
//      reliable path and should be preferred.
//   2. ASN *org name* keyword match — fallback for providers not in the set,
//      and for IPs where GeoLite returns a name but a number we don't track.

// Curated hosting / cloud ASNs (extensible — add numbers as you meet them).
// Sources: providers' public AS numbers. Illustrative, not exhaustive.
const DATACENTER_ASNS = new Set<number>([
  16509, 14618, // Amazon AWS
  15169, 396982, // Google / Google Cloud
  8075, 8068, 8069, // Microsoft / Azure
  13335, // Cloudflare
  16276, // OVH
  24940, // Hetzner
  47583, 207079, // Hostinger
  14061, // DigitalOcean
  20473, // The Constant Company / Vultr (Choopa)
  63949, // Akamai / Linode
  16625, 20940, // Akamai
  9009, // M247
  51167, // Contabo
  45102, 37963, // Alibaba Cloud (intl / cn)
  132203, // Tencent
  8560, // IONOS / 1&1
  197540, // netcup
  16265, 30633, 60781, // LeaseWeb
  19994, 12200, // Rackspace
  36351, // SoftLayer / IBM
  26496, // GoDaddy
  53667, // FranTech / BuyVM
]);

// Curated VPN ASNs. Note: most consumer VPNs ride on hosting ASNs, so this set
// overlaps with datacenters and the keyword fallback below catches the rest.
const VPN_ASNS = new Set<number>([
  9009, // M247 (carries many VPN exit nodes)
  60068, 212238, // Datacamp / CDN77 (NordVPN infra)
  39351, // 31173 Services (Mullvad)
  51852, // Private Layer
  198605, // AVAST / HMA
]);

const DATACENTER_KEYWORDS = [
  'amazon',
  'aws',
  'microsoft',
  'azure',
  'google',
  'gcp',
  'cloudflare',
  'digitalocean',
  'linode',
  'akamai',
  'fastly',
  'ovh',
  'hetzner',
  'hostinger',
  'scaleway',
  'leaseweb',
  'vultr',
  'oracle',
  'alibaba',
  'tencent',
  'rackspace',
  'datacamp',
  'm247',
  'choopa',
  'contabo',
  'as-colocrossing',
  'host',
  'hosting',
  'cdn',
  'cloud',
  'colocation',
  'datacenter',
  'data center',
];

// VPN + scraping / residential-proxy provider names. Caveat: residential-proxy
// services (Bright Data, Oxylabs…) route through real peer devices on ordinary
// ISP ASNs, so their *exit* IPs evade this layer entirely — we only catch their
// gateways / datacenter tiers when GeoLite returns the provider's own org name.
const PROXY_KEYWORDS = [
  'vpn',
  'proxy',
  'tor exit',
  'tor-exit',
  'mullvad',
  'privateinternetaccess',
  'nordvpn',
  'expressvpn',
  'brightdata',
  'bright data',
  'luminati',
  'oxylabs',
  'smartproxy',
  'packetstream',
  'iproyal',
  'netnut',
  'soax',
  'webshare',
  'zyte',
  'crawlera',
];

export function classifyAsn(
  orgName: string | null,
  asn?: number | null,
): { isDatacenter: boolean | null; isProxyHint: boolean | null } {
  const dcByNumber = asn != null && DATACENTER_ASNS.has(asn);
  const vpnByNumber = asn != null && VPN_ASNS.has(asn);

  // Without an org name we can only POSITIVELY assert via the ASN number; the
  // absence of a match is "unknown" (null), not "definitely not". Symmetric for
  // both flags — otherwise a GeoIP-down lookup would masquerade as a confirmed
  // residential IP and hand a bot the non-forgeable trust credit (see trust.ts).
  if (!orgName) {
    return { isDatacenter: dcByNumber ? true : null, isProxyHint: vpnByNumber ? true : null };
  }

  const lower = orgName.toLowerCase();
  const isDatacenter = dcByNumber || DATACENTER_KEYWORDS.some((k) => lower.includes(k));
  const isProxyHint = vpnByNumber || PROXY_KEYWORDS.some((k) => lower.includes(k));
  return { isDatacenter, isProxyHint };
}
