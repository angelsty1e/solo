// ClientHello parser — pure byte reading, no third-party lib.
// Reads a TLS record (handshake type=0x16) and extracts ClientHello fields.

export interface ParsedClientHello {
  legacyVersion: number;
  random: Buffer;
  sessionId: Buffer;
  cipherSuites: number[];
  compressionMethods: number[];
  extensions: ParsedExtension[];
  extensionTypes: number[];
  sni: string | null;
  alpn: string[];
  supportedVersions: number[];
  ellipticCurves: number[];
  ecPointFormats: number[];
  signatureAlgorithms: number[];
}

export interface ParsedExtension {
  type: number;
  data: Buffer;
}

// GREASE values RFC 8701 — 0x0A0A, 0x1A1A, ... 0xFAFA.
export function isGrease(value: number): boolean {
  if ((value & 0x0f0f) !== 0x0a0a) return false;
  const high = (value >> 8) & 0xff;
  const low = value & 0xff;
  return high === low;
}

class Reader {
  buf: Buffer;
  pos: number;
  constructor(buf: Buffer, pos = 0) {
    this.buf = buf;
    this.pos = pos;
  }
  u8(): number {
    if (this.pos + 1 > this.buf.length) throw new Error('eof u8');
    const v = this.buf.readUInt8(this.pos);
    this.pos += 1;
    return v;
  }
  u16(): number {
    if (this.pos + 2 > this.buf.length) throw new Error('eof u16');
    const v = this.buf.readUInt16BE(this.pos);
    this.pos += 2;
    return v;
  }
  u24(): number {
    if (this.pos + 3 > this.buf.length) throw new Error('eof u24');
    const v =
      (this.buf.readUInt8(this.pos) << 16) |
      (this.buf.readUInt8(this.pos + 1) << 8) |
      this.buf.readUInt8(this.pos + 2);
    this.pos += 3;
    return v;
  }
  slice(n: number): Buffer {
    if (this.pos + n > this.buf.length) throw new Error('eof slice');
    const v = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return v;
  }
  remaining(): number {
    return this.buf.length - this.pos;
  }
}

export function parseClientHello(raw: Buffer): ParsedClientHello {
  const r = new Reader(raw);

  // TLS record header
  const recordType = r.u8();
  if (recordType !== 0x16) {
    throw new Error(`not a handshake record (type=0x${recordType.toString(16)})`);
  }
  r.u16(); // record version
  const recordLength = r.u16();
  if (recordLength < 4) throw new Error('truncated record');

  // Handshake header
  const hsType = r.u8();
  if (hsType !== 0x01) {
    throw new Error(`not a ClientHello handshake (type=0x${hsType.toString(16)})`);
  }
  r.u24(); // handshake body length

  // ClientHello body
  const legacyVersion = r.u16();
  const random = r.slice(32);

  const sessionIdLen = r.u8();
  const sessionId = r.slice(sessionIdLen);

  const cipherLen = r.u16();
  if (cipherLen % 2 !== 0) throw new Error('odd cipher length');
  const ciphersBuf = r.slice(cipherLen);
  const cipherSuites: number[] = [];
  for (let i = 0; i < cipherLen; i += 2) {
    cipherSuites.push(ciphersBuf.readUInt16BE(i));
  }

  const compLen = r.u8();
  const compBuf = r.slice(compLen);
  const compressionMethods: number[] = [];
  for (let i = 0; i < compLen; i++) compressionMethods.push(compBuf.readUInt8(i));

  const extensions: ParsedExtension[] = [];
  const extensionTypes: number[] = [];
  let sni: string | null = null;
  const alpn: string[] = [];
  const supportedVersions: number[] = [];
  const ellipticCurves: number[] = [];
  const ecPointFormats: number[] = [];
  const signatureAlgorithms: number[] = [];

  if (r.remaining() >= 2) {
    const extTotalLen = r.u16();
    const extReader = new Reader(r.slice(extTotalLen));
    while (extReader.remaining() >= 4) {
      const type = extReader.u16();
      const len = extReader.u16();
      const data = extReader.slice(len);
      extensions.push({ type, data });
      extensionTypes.push(type);

      switch (type) {
        case 0x0000: {
          // server_name (SNI)
          if (data.length >= 5) {
            const listLen = data.readUInt16BE(0);
            if (listLen + 2 <= data.length) {
              let off = 2;
              while (off + 3 <= 2 + listLen) {
                const nameType = data.readUInt8(off);
                const nameLen = data.readUInt16BE(off + 1);
                off += 3;
                if (off + nameLen > data.length) break;
                if (nameType === 0) {
                  // A DNS hostname is at most 253 chars; cap at 256 so a
                  // crafted ClientHello can't make us decode/keep a giant blob,
                  // and only accept a valid hostname charset (defends the
                  // downstream consumers that log / store / render this).
                  if (nameLen <= 256) {
                    const candidate = data.subarray(off, off + nameLen).toString('utf8');
                    if (/^[A-Za-z0-9._-]+$/.test(candidate)) sni = candidate;
                  }
                  break;
                }
                off += nameLen;
              }
            }
          }
          break;
        }
        case 0x0010: {
          // ALPN
          if (data.length >= 2) {
            const listLen = data.readUInt16BE(0);
            let off = 2;
            const end = Math.min(2 + listLen, data.length);
            while (off < end) {
              const protoLen = data.readUInt8(off);
              off += 1;
              if (off + protoLen > end) break;
              alpn.push(data.subarray(off, off + protoLen).toString('utf8'));
              off += protoLen;
            }
          }
          break;
        }
        case 0x002b: {
          // supported_versions (in ClientHello: length prefix u8)
          if (data.length >= 1) {
            const listLen = data.readUInt8(0);
            for (let off = 1; off + 2 <= 1 + listLen && off + 2 <= data.length; off += 2) {
              supportedVersions.push(data.readUInt16BE(off));
            }
          }
          break;
        }
        case 0x000a: {
          // supported_groups (elliptic curves)
          if (data.length >= 2) {
            const listLen = data.readUInt16BE(0);
            for (let off = 2; off + 2 <= 2 + listLen && off + 2 <= data.length; off += 2) {
              ellipticCurves.push(data.readUInt16BE(off));
            }
          }
          break;
        }
        case 0x000b: {
          // ec_point_formats
          if (data.length >= 1) {
            const listLen = data.readUInt8(0);
            for (let off = 1; off < 1 + listLen && off < data.length; off++) {
              ecPointFormats.push(data.readUInt8(off));
            }
          }
          break;
        }
        case 0x000d: {
          // signature_algorithms
          if (data.length >= 2) {
            const listLen = data.readUInt16BE(0);
            for (let off = 2; off + 2 <= 2 + listLen && off + 2 <= data.length; off += 2) {
              signatureAlgorithms.push(data.readUInt16BE(off));
            }
          }
          break;
        }
        default:
          break;
      }
    }
  }

  return {
    legacyVersion,
    random,
    sessionId,
    cipherSuites,
    compressionMethods,
    extensions,
    extensionTypes,
    sni,
    alpn,
    supportedVersions,
    ellipticCurves,
    ecPointFormats,
    signatureAlgorithms,
  };
}

export function tlsVersionName(version: number): string {
  switch (version) {
    case 0x0301:
      return 'TLS 1.0';
    case 0x0302:
      return 'TLS 1.1';
    case 0x0303:
      return 'TLS 1.2';
    case 0x0304:
      return 'TLS 1.3';
    default:
      return `0x${version.toString(16).padStart(4, '0')}`;
  }
}

export function negotiatedVersion(parsed: ParsedClientHello): number {
  // If supported_versions advertises 1.3, that's effectively the version offered.
  const nonGrease = parsed.supportedVersions.filter((v) => !isGrease(v));
  if (nonGrease.includes(0x0304)) return 0x0304;
  if (nonGrease.length > 0) return nonGrease[0]!;
  return parsed.legacyVersion;
}
