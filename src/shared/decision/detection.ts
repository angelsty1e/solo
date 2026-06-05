// ─── Detection utilities — single source of truth ───────────────────────────
// UA / platform / engine / brand parsing and the software-GPU pattern, shared
// by registry.ts, environment.ts, cards.ts and trust.ts. Previously duplicated
// (and drifting — e.g. the SOFTWARE_GPU regex diverged between files). Keep all
// such heuristics HERE so a fix lands in one place.

export type DetectedEngine = 'v8' | 'spidermonkey' | 'javascriptcore' | 'unknown';
export type Os = 'windows' | 'mac' | 'linux' | 'android' | 'ios';
export type Browser = 'chrome' | 'edge' | 'opera' | 'firefox' | 'safari';

// Software / virtual renderers: betray an emulated GPU (headless or VM).
// Canonical superset — includes the hypervisor renderers some copies missed.
export const SOFTWARE_GPU =
  /swiftshader|llvmpipe|software|mesa offscreen|microsoft basic render|virtualbox|vmware|parallels|qemu/i;

// OS announced by the UA. Android before Linux (its UA contains "Linux"); iOS
// before Mac for the same reason.
export function uaOs(ua: string): Os | null {
  if (/Windows NT/i.test(ua)) return 'windows';
  if (/Android/i.test(ua)) return 'android';
  if (/(iPhone|iPad|iPod)/i.test(ua)) return 'ios';
  if (/Mac OS X|Macintosh/i.test(ua)) return 'mac';
  if (/Linux|X11|CrOS/i.test(ua)) return 'linux';
  return null;
}

// Browser family. Edge/Opera before Chrome (their UA carries the "Chrome"
// token); Safari last (no "Chrome" token, requires "Version/").
export function uaBrowser(ua: string): Browser | null {
  if (/Edg\//i.test(ua)) return 'edge';
  if (/OPR\/|Opera/i.test(ua)) return 'opera';
  if (/Firefox\//i.test(ua)) return 'firefox';
  if (/Chrome\/|Chromium\//i.test(ua)) return 'chrome';
  if (/Safari\//i.test(ua) && /Version\//i.test(ua)) return 'safari';
  return null;
}

export function isMobileUa(ua: string): boolean {
  return /Mobi|Android|iPhone|iPad|iPod/i.test(ua);
}

export function isChromium(b: Browser | null): boolean {
  return b === 'chrome' || b === 'edge' || b === 'opera';
}

export function isChromiumUa(ua: string): boolean {
  return isChromium(uaBrowser(ua));
}

// The JS engine expected for a browser family.
export function expectedEngine(b: Browser | null): DetectedEngine | null {
  switch (b) {
    case 'chrome':
    case 'edge':
    case 'opera':
      return 'v8';
    case 'firefox':
      return 'spidermonkey';
    case 'safari':
      return 'javascriptcore';
    default:
      return null;
  }
}

// navigator.platform expected for an OS. Tolerant (substring) since values vary
// ("Win32", "MacIntel", "Linux x86_64", "iPhone"…).
export function platformMatchesOs(platform: string, os: Os): boolean {
  const p = platform.toLowerCase();
  switch (os) {
    case 'windows':
      return p.includes('win');
    case 'mac':
      return p.includes('mac');
    case 'linux':
      return p.includes('linux') || p.includes('x11');
    case 'android':
      return p.includes('linux') || p.includes('android') || p.includes('arm') || p.includes('aarch');
    case 'ios':
      return p.includes('iphone') || p.includes('ipad') || p.includes('ipod') || p.includes('mac');
  }
}

// Does navigator.platform agree with the OS in the UA? Browser-agnostic.
export function platformMatchesUa(platform: string, ua: string): boolean {
  const os = uaOs(ua);
  return os ? platformMatchesOs(platform, os) : false;
}

// A UA that *claims* to be a real interactive browser (not a self-declared
// tool/headless) — used to decide when a TLS↔UA mismatch is actually a lie.
export function isRealBrowserUa(ua: string): boolean {
  if (!ua) return false;
  const browser = /(Chrome|Firefox|Safari|Edg|OPR)\//i.test(ua);
  const tool = /(curl|wget|python|go-http|java\/|okhttp|HeadlessChrome|Headless|bot|spider|crawler|PhantomJS)/i.test(ua);
  return browser && !tool;
}

// A genuine Chrome UA, excluding forks that legitimately differ (Edge/Opera)
// and HeadlessChrome (caught by its own hard signal).
export function isGenuineChromeUa(ua: string): boolean {
  return /Chrome\//i.test(ua) && !/Edg\/|OPR\/|HeadlessChrome/i.test(ua);
}

// Base language subtag, lowercased: "fr-FR" → "fr".
export function baseLang(tag: string): string {
  return tag.toLowerCase().trim().split('-')[0] ?? '';
}

// Brand names from a Sec-CH-UA header: `"Chromium";v="124", "Google Chrome";v="124"`.
export function parseSecChUaBrands(header: string): string[] {
  const out: string[] = [];
  const re = /"([^"]+)"\s*;\s*v=/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(header)) !== null) out.push(m[1]!);
  return out;
}

// GREASE / anti-fingerprinting placeholder brands ("Not A;Brand", "Not.A/Brand"…)
// vary by design and must be excluded before comparing brand sets.
export function isGreaseBrand(brand: string): boolean {
  const b = brand.toLowerCase();
  return b.includes('not') && b.includes('brand');
}

export function normalizedBrandSet(brands: string[]): string[] {
  return brands
    .map((b) => b.toLowerCase().trim())
    .filter((b) => b && !isGreaseBrand(b))
    .sort();
}
