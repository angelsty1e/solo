import type { NavigatorSnapshot, WebglSnapshot, WebgpuSnapshot } from '../shared/types.js';

// Reference dictionaries — render-time only.
//
// The fingerprint DB stores the *raw* numeric IDs (cipher 0x1301, extension 43,
// storage in bytes…) because those are what JA3/JA4 hash and what makes the
// fingerprint canonical. This module maps those numbers to the human-readable
// names from the public IANA registries, purely for display in the recap.
// Nothing here is persisted; changing a label never affects an empreinte.
//
// Sources: IANA "TLS Cipher Suites", "TLS ExtensionType Values",
// "TLS Supported Groups", "TLS SignatureScheme" registries.

// GREASE (RFC 8701): reserved values browsers inject to keep the ecosystem
// tolerant of unknown codes. They are not real ciphers/extensions/groups, so
// we label them as such instead of "inconnu".
export function isGrease(v: number): boolean {
  return (v >> 8) === (v & 0xff) && (v & 0x0f) === 0x0a;
}

function hex(v: number): string {
  return '0x' + v.toString(16).padStart(4, '0');
}

export const CIPHER_SUITES: Record<number, string> = {
  // TLS 1.3
  0x1301: 'TLS_AES_128_GCM_SHA256',
  0x1302: 'TLS_AES_256_GCM_SHA384',
  0x1303: 'TLS_CHACHA20_POLY1305_SHA256',
  0x1304: 'TLS_AES_128_CCM_SHA256',
  0x1305: 'TLS_AES_128_CCM_8_SHA256',
  // ECDHE (TLS 1.2)
  0xc02b: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
  0xc02c: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
  0xc02f: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
  0xc030: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
  0xcca8: 'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
  0xcca9: 'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
  0xc013: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
  0xc014: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
  0xc009: 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
  0xc00a: 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
  0xc027: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
  0xc028: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
  0xc023: 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
  0xc024: 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
  // RSA static (legacy)
  0x009c: 'TLS_RSA_WITH_AES_128_GCM_SHA256',
  0x009d: 'TLS_RSA_WITH_AES_256_GCM_SHA384',
  0x003c: 'TLS_RSA_WITH_AES_128_CBC_SHA256',
  0x003d: 'TLS_RSA_WITH_AES_256_CBC_SHA256',
  0x002f: 'TLS_RSA_WITH_AES_128_CBC_SHA',
  0x0035: 'TLS_RSA_WITH_AES_256_CBC_SHA',
  0x000a: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
  // Signalling
  0x00ff: 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV',
};

export const TLS_EXTENSIONS: Record<number, string> = {
  0: 'server_name (SNI)',
  1: 'max_fragment_length',
  5: 'status_request (OCSP)',
  10: 'supported_groups',
  11: 'ec_point_formats',
  13: 'signature_algorithms',
  14: 'use_srtp',
  15: 'heartbeat',
  16: 'application_layer_protocol_negotiation (ALPN)',
  17: 'status_request_v2',
  18: 'signed_certificate_timestamp (SCT)',
  19: 'client_certificate_type',
  20: 'server_certificate_type',
  21: 'padding',
  22: 'encrypt_then_mac',
  23: 'extended_master_secret',
  27: 'compress_certificate',
  28: 'record_size_limit',
  35: 'session_ticket',
  41: 'pre_shared_key',
  42: 'early_data',
  43: 'supported_versions',
  44: 'cookie',
  45: 'psk_key_exchange_modes',
  47: 'certificate_authorities',
  48: 'oid_filters',
  49: 'post_handshake_auth',
  50: 'signature_algorithms_cert',
  51: 'key_share',
  17513: 'application_settings (ALPS)',
  65037: 'encrypted_client_hello (ECH)',
  65281: 'renegotiation_info',
};

export const SUPPORTED_GROUPS: Record<number, string> = {
  23: 'secp256r1 (P-256)',
  24: 'secp384r1 (P-384)',
  25: 'secp521r1 (P-521)',
  29: 'x25519',
  30: 'x448',
  256: 'ffdhe2048',
  257: 'ffdhe3072',
  258: 'ffdhe4096',
  4587: 'X25519MLKEM768',
  25497: 'X25519Kyber768Draft00',
};

export const SIGNATURE_SCHEMES: Record<number, string> = {
  0x0201: 'rsa_pkcs1_sha1',
  0x0203: 'ecdsa_sha1',
  0x0401: 'rsa_pkcs1_sha256',
  0x0403: 'ecdsa_secp256r1_sha256',
  0x0501: 'rsa_pkcs1_sha384',
  0x0503: 'ecdsa_secp384r1_sha384',
  0x0601: 'rsa_pkcs1_sha512',
  0x0603: 'ecdsa_secp521r1_sha512',
  0x0804: 'rsa_pss_rsae_sha256',
  0x0805: 'rsa_pss_rsae_sha384',
  0x0806: 'rsa_pss_rsae_sha512',
  0x0807: 'ed25519',
  0x0808: 'ed448',
  0x0809: 'rsa_pss_pss_sha256',
  0x080a: 'rsa_pss_pss_sha384',
  0x080b: 'rsa_pss_pss_sha512',
};

export const EC_POINT_FORMATS: Record<number, string> = {
  0: 'uncompressed',
  1: 'ansiX962_compressed_prime',
  2: 'ansiX962_compressed_char2',
};

// "name (0xXXXX)" — falls back to "inconnu" / "GREASE" so the hex is never lost.
export function labelId(id: number, map: Record<number, string>): string {
  if (isGrease(id)) return `GREASE (${hex(id)})`;
  const name = map[id];
  return name ? `${name} (${hex(id)})` : `inconnu (${hex(id)})`;
}

export function labelList(ids: number[], map: Record<number, string>): string {
  if (!ids || ids.length === 0) return '';
  return ids.map((id) => labelId(id, map)).join(', ');
}

// Bytes → "1,95 Go (2 097 152 000 o)". Keeps the exact byte count alongside the
// human unit so the value stays usable as a fingerprint signal. Base 1024.
export function formatBytes(n: number | null | undefined): string | null {
  if (n === null || n === undefined || Number.isNaN(n)) return null;
  if (n === 0) return '0 o';
  const units = ['o', 'Ko', 'Mo', 'Go', 'To'];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  const human = i === 0 ? `${v} o` : `${v.toFixed(v < 10 ? 2 : 1)} ${units[i]}`;
  return `${human} (${n.toLocaleString('fr-FR')} o)`;
}

// ─── Géo : pays ISO → drapeau + nom, langue, cohérence ───────────────────────

// Lazy singletons: Intl.DisplayNames is cheap to reuse, and we tolerate older
// engines (or restricted locales) by falling back to the raw code.
let regionDN: Intl.DisplayNames | null | undefined;
let langDN: Intl.DisplayNames | null | undefined;
function displayNames(type: 'region' | 'language'): Intl.DisplayNames | null {
  if (type === 'region') {
    if (regionDN === undefined) {
      try {
        regionDN = new Intl.DisplayNames(undefined, { type: 'region' });
      } catch {
        regionDN = null;
      }
    }
    return regionDN;
  }
  if (langDN === undefined) {
    try {
      langDN = new Intl.DisplayNames(undefined, { type: 'language' });
    } catch {
      langDN = null;
    }
  }
  return langDN;
}

// "FR" → "🇫🇷". Maps the two ASCII letters to their regional-indicator symbols.
function flagEmoji(iso: string): string {
  if (!/^[A-Za-z]{2}$/.test(iso)) return '';
  const cc = iso.toUpperCase();
  return String.fromCodePoint(...[...cc].map((c) => 127397 + c.charCodeAt(0)));
}

// "FR" → "🇫🇷 France (FR)". Name is rendered in the *viewer's* locale.
export function formatCountry(iso: string | null | undefined): string | null {
  if (!iso) return null;
  const code = iso.toUpperCase();
  let name = code;
  try {
    name = displayNames('region')?.of(code) ?? code;
  } catch {
    name = code;
  }
  const flag = flagEmoji(code);
  return `${flag ? flag + ' ' : ''}${name} (${code})`;
}

// "fr-FR" → "Français (France)". Falls back to the raw BCP-47 tag.
export function languageName(tag: string | null | undefined): string | null {
  if (!tag) return null;
  try {
    return displayNames('language')?.of(tag) ?? tag;
  } catch {
    return tag;
  }
}

// Explicit region subtag of a BCP-47 locale: "fr-FR" → "FR", "en" → null.
// We deliberately do NOT maximize(): inferring a region from a region-less tag
// ("en" → US) would fabricate divergences against the IP country.
function localeRegion(locale: string | null | undefined): string | null {
  if (!locale) return null;
  try {
    const r = new Intl.Locale(locale).region;
    if (r) return r.toUpperCase();
  } catch {
    /* fall through to regex */
  }
  const m = locale.match(/[-_]([A-Za-z]{2})\b/);
  return m && m[1] ? m[1].toUpperCase() : null;
}

// Display-only coherence hint: does the browser locale's country match the IP
// country? A mismatch is typical of a VPN/proxy. NOT a verdict — just a flag.
export function geoCoherence(locale: string | null | undefined, ipCountry: string | null | undefined): string | null {
  const region = localeRegion(locale);
  const ip = ipCountry ? ipCountry.toUpperCase() : null;
  if (!region || !ip) return null;
  return region === ip
    ? `✓ cohérent (locale ${region} = IP ${ip})`
    : `⚠ divergence (locale ${region} ≠ IP ${ip}) — typique d'un VPN/proxy`;
}

// getTimezoneOffset() is minutes to ADD to local time to reach UTC, so its sign
// is the opposite of the conventional UTC offset. -120 → "UTC+02:00".
export function formatTzOffset(minutes: number | null | undefined): string | null {
  if (minutes === null || minutes === undefined || Number.isNaN(minutes)) return null;
  const utc = -minutes;
  const sign = utc >= 0 ? '+' : '-';
  const abs = Math.abs(utc);
  const hh = Math.floor(abs / 60);
  const mm = abs % 60;
  const pad = (x: number): string => String(x).padStart(2, '0');
  return `UTC${sign}${pad(hh)}:${pad(mm)}`;
}

// ─── JS engine → browser family ──────────────────────────────────────────────

export const ENGINE_FAMILY: Record<string, string> = {
  v8: 'Chrome / Edge / Chromium (V8)',
  spidermonkey: 'Firefox (SpiderMonkey)',
  javascriptcore: 'Safari / WebKit (JavaScriptCore)',
  unknown: 'inconnu',
};

export function engineFamily(detected: string | null | undefined): string | null {
  if (!detected) return null;
  return ENGINE_FAMILY[detected] ?? detected;
}

// ─── Locale: calendar / numbering system → readable ──────────────────────────

export const CALENDARS: Record<string, string> = {
  gregory: 'Grégorien',
  iso8601: 'ISO 8601',
  buddhist: 'Bouddhiste',
  japanese: 'Japonais',
  islamic: 'Islamique',
  'islamic-civil': 'Islamique (civil)',
  hebrew: 'Hébraïque',
  chinese: 'Chinois',
  persian: 'Persan',
  indian: 'Indien',
  coptic: 'Copte',
  ethiopic: 'Éthiopien',
};

export const NUMBERING_SYSTEMS: Record<string, string> = {
  latn: 'Latins (0-9)',
  arab: 'Arabo-indiens',
  arabext: 'Arabo-indiens étendus',
  deva: 'Devanagari',
  beng: 'Bengali',
  hanidec: 'Chinois décimal',
  fullwide: 'Pleine largeur',
  thai: 'Thaï',
  tamldec: 'Tamoul',
};

export function calendarName(id: string | null | undefined): string | null {
  if (!id) return null;
  return CALENDARS[id] ? `${CALENDARS[id]} (${id})` : id;
}

export function numberingSystemName(id: string | null | undefined): string | null {
  if (!id) return null;
  return NUMBERING_SYSTEMS[id] ? `${NUMBERING_SYSTEMS[id]} (${id})` : id;
}

// ─── Codecs: full MIME string → friendly name ────────────────────────────────

export const CODEC_NAMES: Record<string, string> = {
  'video/mp4; codecs="avc1.42E01E"': 'H.264 Baseline',
  'video/mp4; codecs="avc1.640028"': 'H.264 High',
  'video/mp4; codecs="hev1.1.6.L93.B0"': 'H.265 / HEVC',
  'video/webm; codecs="vp8"': 'VP8',
  'video/webm; codecs="vp9"': 'VP9',
  'video/webm; codecs="vp09.00.10.08"': 'VP9 (profil 0)',
  'video/mp4; codecs="av01.0.05M.08"': 'AV1',
  'video/ogg; codecs="theora"': 'Theora',
  'audio/mp4; codecs="mp4a.40.2"': 'AAC-LC',
  'audio/mp4; codecs="mp4a.40.5"': 'HE-AAC',
  'audio/ogg; codecs="vorbis"': 'Vorbis',
  'audio/ogg; codecs="opus"': 'Opus (Ogg)',
  'audio/webm; codecs="opus"': 'Opus (WebM)',
  'audio/flac': 'FLAC',
  'audio/wav; codecs="1"': 'WAV (PCM)',
  'audio/aac': 'AAC (ADTS)',
};

// Rewrites a {mimeString: result} map to {friendlyName: result}, keeping the raw
// key as a fallback so an unknown probe is never silently dropped.
export function humanizeCodecMap<T>(rec: Record<string, T>): Record<string, T> {
  const out: Record<string, T> = {};
  for (const [k, v] of Object.entries(rec)) {
    out[CODEC_NAMES[k] ?? k] = v;
  }
  return out;
}

// devicePixelRatio → "2 (HiDPI / Retina)".
export function dprLabel(dpr: number | null | undefined): string | null {
  if (dpr === null || dpr === undefined || Number.isNaN(dpr)) return null;
  if (dpr >= 2) return `${dpr} (HiDPI / Retina)`;
  if (dpr > 1) return `${dpr} (HiDPI)`;
  return `${dpr} (standard)`;
}

// ─── Inférence du processeur ────────────────────────────────────────────────
// Piège classique : navigator.platform vaut "MacIntel" même sur les Mac Apple
// Silicon (Apple le fige pour la rétro-compat). S'y fier seul classe à tort un
// M1/M2/M3 comme Intel. On croise donc plusieurs signaux, du plus fiable au
// plus faible, et on ne conclut "Intel" que sur preuve positive :
//   1. WebGL unmasked renderer  → expose souvent la puce exacte ("Apple M1",
//      "Apple GPU", "Intel Iris", "AMD Radeon").
//   2. Client Hints architecture → "arm" / "x86" (Chromium uniquement).
//   3. WebGPU adapter vendor     → "apple".
//   4. navigator.platform        → seulement en dernier recours.
export function inferCpu(
  nav: NavigatorSnapshot,
  webgl: WebglSnapshot | null,
  webgpu: WebgpuSnapshot | null,
): string | null {
  const renderer = (webgl?.unmaskedRenderer ?? webgl?.renderer ?? '').trim();
  const arch = (nav.uaData?.architecture ?? '').toLowerCase();
  const bitness = nav.uaData?.bitness ?? '';
  const uaPlatform = (nav.uaData?.platform ?? '').toLowerCase();
  const platform = nav.platform ?? '';
  const gpuVendor = (webgpu?.adapter?.vendor ?? '').toLowerCase();
  const ua = nav.userAgent ?? '';

  const isMac = /mac/i.test(platform) || uaPlatform === 'macos';
  // iPadOS se déguise en Mac (platform "MacIntel" + écran tactile, sans uaData).
  const isIos =
    /iphone|ipad|ipod/i.test(platform) ||
    /iphone|ipad/i.test(ua) ||
    (isMac && nav.maxTouchPoints > 1 && !nav.uaData);

  // Puce Apple exacte exposée par WebGL : "Apple M1", "Apple M2 Pro", …
  const chip = renderer.match(/Apple\s+(M\d+(?:\s?(?:Pro|Max|Ultra))?)/i);
  if (chip) return `Apple Silicon — ${chip[0].replace(/\s+/g, ' ')} (ARM64)`;

  const looksApple =
    (arch === 'arm' && isMac) ||
    /apple gpu/i.test(renderer) ||
    gpuVendor === 'apple' ||
    isIos;
  if (looksApple) return isIos ? 'Apple Silicon (ARM, iOS/iPadOS)' : 'Apple Silicon (ARM64)';

  // Mac sans signe d'Apple Silicon → Intel, mais uniquement sur preuve positive
  // (archi x86 ou GPU Intel/AMD/NVIDIA), jamais sur le seul "MacIntel".
  if (isMac) {
    if (arch === 'x86' || /intel|amd|radeon|nvidia|geforce/i.test(renderer)) {
      return 'Intel (x86-64) — Mac Intel';
    }
    return 'Mac — architecture indéterminée (Client Hints absents)';
  }

  // Hors Mac : Client Hints d'architecture en priorité.
  if (arch === 'arm') return bitness === '64' ? 'ARM64' : 'ARM';
  if (arch === 'x86') return bitness === '32' ? 'x86 (32 bits)' : 'x86-64 (Intel/AMD)';

  // Derniers indices : platform brut.
  if (/arm|aarch64/i.test(platform)) return 'ARM';
  if (/x86_64|win64|wow64|x64|win32/i.test(platform)) return 'x86-64 (Intel/AMD)';
  return null;
}
