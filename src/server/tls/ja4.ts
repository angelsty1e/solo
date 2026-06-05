import { createHash } from 'node:crypto';
import { isGrease, type ParsedClientHello } from './clienthello.js';

// JA4 fingerprint (FoxIO spec, simplified TCP/TLS variant).
// Format: <a>_<b>_<c>
//   a = (t|q)(tlsVer 2 chars)(d|i)(nCiphers 2 chars)(nExts 2 chars)(alpn 2 chars)
//   b = first 12 hex chars of sha256(sorted ciphers hex, comma-joined)
//   c = first 12 hex chars of sha256(sorted exts hex (excl 0x0000, 0x0010), comma-joined
//        + "_" + signature_algorithms in original order, comma-joined hex)
// GREASE values are excluded from all counts and lists.

function hex4(n: number): string {
  return n.toString(16).padStart(4, '0');
}

function pad2Dec(n: number): string {
  if (n > 99) return '99';
  return n.toString().padStart(2, '0');
}

function mapTlsVersion(parsed: ParsedClientHello): string {
  const nonGrease = parsed.supportedVersions.filter((v) => !isGrease(v));
  let v = parsed.legacyVersion;
  if (nonGrease.includes(0x0304)) v = 0x0304;
  else if (nonGrease.includes(0x0303)) v = 0x0303;
  switch (v) {
    case 0x0304:
      return '13';
    case 0x0303:
      return '12';
    case 0x0302:
      return '11';
    case 0x0301:
      return '10';
    case 0x0300:
      return 's3';
    default:
      return '00';
  }
}

function alpnCode(alpn: string[]): string {
  if (alpn.length === 0) return '00';
  const first = alpn[0]!;
  if (first.length === 0) return '00';
  if (first.length === 1) return first + first;
  return first.charAt(0) + first.charAt(first.length - 1);
}

export interface Ja4Result {
  ja4: string;
}

export function computeJa4(parsed: ParsedClientHello, transport: 't' | 'q' = 't'): Ja4Result {
  const tlsVer = mapTlsVersion(parsed);
  const sniFlag = parsed.sni ? 'd' : 'i';

  const ciphersClean = parsed.cipherSuites.filter((c) => !isGrease(c));
  const extsClean = parsed.extensionTypes.filter((e) => !isGrease(e));

  const nCiphers = pad2Dec(ciphersClean.length);
  const nExts = pad2Dec(extsClean.length);
  const alpn = alpnCode(parsed.alpn);

  const a = `${transport}${tlsVer}${sniFlag}${nCiphers}${nExts}${alpn}`;

  const sortedCiphers = [...ciphersClean].sort((x, y) => x - y).map(hex4);
  const cipherStr = sortedCiphers.join(',');
  const b = createHash('sha256').update(cipherStr).digest('hex').slice(0, 12);

  const extsForHash = extsClean.filter((e) => e !== 0x0000 && e !== 0x0010);
  const sortedExts = [...extsForHash].sort((x, y) => x - y).map(hex4);
  const sigAlgs = parsed.signatureAlgorithms.map(hex4);
  const extStr = `${sortedExts.join(',')}_${sigAlgs.join(',')}`;
  const c = createHash('sha256').update(extStr).digest('hex').slice(0, 12);

  return { ja4: `${a}_${b}_${c}` };
}
