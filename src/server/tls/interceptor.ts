import http from 'node:http';
import net from 'node:net';
import tls from 'node:tls';
import type { TlsFingerprint } from '../../shared/types.js';
import { negotiatedVersion, parseClientHello, tlsVersionName } from './clienthello.js';
import { computeJa3 } from './ja3.js';
import { computeJa4 } from './ja4.js';

// ─── Why a TCP proxy instead of unshift ──────────────────────────────────────
// The "naive" pattern (read 1st chunk on net.Socket → unshift → emit 'connection'
// on tls.Server) is broken in modern Node: when tls.Server takes over the socket,
// it grabs the underlying libuv `_handle` and sets `socket._handle = null`. The
// JS-level readableState buffer (where unshift puts the chunk) is then orphaned —
// TLSWrap reads new bytes from libuv but never sees the buffered chunk, so the
// handshake hangs (TLS handshake timeout).
//
// Instead we run a transparent TCP proxy: the public listener captures the first
// chunk for fingerprinting, then forwards every byte verbatim to an internal TLS
// server on 127.0.0.1:<ephemeral>. The fingerprint is keyed by the upstream
// socket's *localPort*, which is exactly what tls.Server sees as `remotePort` on
// the incoming connection. The real client IP/port is kept in a side map so the
// HTTP layer can recover it (since `req.ip` would otherwise show 127.0.0.1).

export interface RealRemote {
  addr: string;
  port: number;
}

const fpByUpPort = new Map<number, TlsFingerprint>();
const rttByUpPort = new Map<number, number>();
const remoteByUpPort = new Map<number, RealRemote>();

// ─── Slowloris / buffer-exhaustion guards ────────────────────────────────────
// Each in-flight connection buffers its (possibly fragmented) ClientHello —
// up to ~16 KB — before handing off to the TLS server. Without a ceiling,
// thousands of slow connections could collectively pin the heap, and a single
// source could open unbounded sockets. We cap both: concurrent connections per
// source IP, and total bytes buffered across all in-flight captures.
const MAX_CONN_PER_IP = 64;
const MAX_TOTAL_CAPTURE_BYTES = 32 * 1024 * 1024; // hard ceiling on in-flight ClientHello buffers
const connCountByIp = new Map<string, number>();
let totalCaptureBytes = 0;

function buildFingerprint(chunk: Buffer): TlsFingerprint | null {
  try {
    const parsed = parseClientHello(chunk);
    const { ja3, ja3Hash } = computeJa3(parsed);
    const { ja4 } = computeJa4(parsed);
    const version = negotiatedVersion(parsed);
    return {
      version,
      versionName: tlsVersionName(version),
      ciphers: parsed.cipherSuites,
      extensions: parsed.extensionTypes,
      ellipticCurves: parsed.ellipticCurves,
      ecPointFormats: parsed.ecPointFormats,
      signatureAlgorithms: parsed.signatureAlgorithms,
      alpn: parsed.alpn,
      sni: parsed.sni,
      supportedVersions: parsed.supportedVersions,
      ja3,
      ja3Hash,
      ja4,
    };
  } catch {
    return null;
  }
}

export interface InterceptedServerOptions {
  tls: tls.SecureContextOptions;
  alpnProtocols?: string[];
  logger?: { info: (...a: unknown[]) => void; warn: (...a: unknown[]) => void };
}

export function createInterceptedServerFactory(opts: InterceptedServerOptions) {
  const { tls: tlsOptions, alpnProtocols = ['http/1.1'], logger } = opts;

  return (handler: http.RequestListener, _serverOpts: unknown): http.Server => {
    const httpServer = http.createServer({}, handler);

    const tlsServer = tls.createServer({
      ...tlsOptions,
      ALPNProtocols: alpnProtocols,
    });

    tlsServer.on('secureConnection', (tlsSocket) => {
      httpServer.emit('connection', tlsSocket);
    });

    tlsServer.on('tlsClientError', (err) => {
      logger?.warn?.('tlsClientError', err.message);
    });

    // Internal TLS listener on a loopback ephemeral port.
    let tlsAddr: net.AddressInfo | null = null;
    const tlsReady = new Promise<void>((resolve, reject) => {
      tlsServer.once('error', reject);
      tlsServer.listen(0, '127.0.0.1', () => {
        const addr = tlsServer.address();
        if (addr && typeof addr === 'object') {
          tlsAddr = addr;
          resolve();
        } else {
          reject(new Error('internal TLS server got no address'));
        }
      });
    });

    // Public TCP proxy — what Fastify actually listens on.
    const tcpProxy = net.createServer({ allowHalfOpen: false }, (clientSocket: net.Socket) => {
      const realAddr = clientSocket.remoteAddress ?? '';
      const realPort = clientSocket.remotePort ?? 0;

      // Per-IP concurrency cap: one source can't open thousands of slow
      // connections to exhaust sockets / capture-buffer memory (slowloris).
      const ipCount = realAddr ? (connCountByIp.get(realAddr) ?? 0) : 0;
      if (realAddr && ipCount >= MAX_CONN_PER_IP) {
        logger?.warn?.('per-ip connection cap reached, dropping', realAddr);
        clientSocket.destroy();
        return;
      }
      if (realAddr) connCountByIp.set(realAddr, ipCount + 1);

      clientSocket.setKeepAlive(true, 30_000);
      // Drop connections that never send a ClientHello (port scans, slowloris):
      // without this the loopback upstream socket would leak (→ EMFILE).
      clientSocket.setTimeout(15_000);
      clientSocket.pause();
      const connectedAt = process.hrtime.bigint();

      let upstream: net.Socket | null = null;
      let upPort = 0;
      let cleaned = false;
      // Bytes this connection currently contributes to `totalCaptureBytes`.
      // Released (subtracted) once on finalize() or cleanup(), whichever first.
      let bufferedHere = 0;

      // Single cleanup path, attached to error/close/timeout of BOTH sockets, so
      // a connection that dies at any stage frees its Map entries and tears down
      // its peer socket (no half-open leak, no stale fingerprint kept around).
      const cleanup = () => {
        if (cleaned) return;
        cleaned = true;
        // Release this connection's still-buffered bytes and per-IP slot.
        if (bufferedHere) {
          totalCaptureBytes -= bufferedHere;
          bufferedHere = 0;
        }
        if (realAddr) {
          const n = (connCountByIp.get(realAddr) ?? 1) - 1;
          if (n <= 0) connCountByIp.delete(realAddr);
          else connCountByIp.set(realAddr, n);
        }
        if (upPort) {
          fpByUpPort.delete(upPort);
          rttByUpPort.delete(upPort);
          remoteByUpPort.delete(upPort);
        }
        try {
          clientSocket.destroy();
        } catch {
          /* ignore */
        }
        try {
          upstream?.destroy();
        } catch {
          /* ignore */
        }
      };

      clientSocket.on('error', cleanup);
      clientSocket.on('close', cleanup);
      clientSocket.on('timeout', cleanup);

      const handoff = () => {
        if (!tlsAddr) {
          cleanup();
          return;
        }
        upstream = net.createConnection({ host: '127.0.0.1', port: tlsAddr.port });
        upstream.on('error', cleanup);
        upstream.on('close', cleanup);

        upstream.once('connect', () => {
          const p = upstream!.localPort;
          if (!p) {
            cleanup();
            return;
          }
          upPort = p;

          // Reassemble the ClientHello: it can span several TCP segments
          // (modern Chrome post-quantum hellos exceed one MSS), in which case a
          // single-chunk read would parse a truncated record → JA3/JA4 null for
          // a legitimate client. We buffer until the TLS record is complete.
          const FIRST_RECORD_CAP = 16384 + 5; // max TLS record + 5-byte header
          const chunks: Buffer[] = [];
          let total = 0;
          let captured = false;
          let captureTimer: NodeJS.Timeout | null = null;

          const hasFullRecord = (buf: Buffer): boolean => {
            if (buf.length < 5) return false;
            if (buf[0] !== 0x16) return true; // not a handshake record → don't wait
            return buf.length >= 5 + buf.readUInt16BE(3);
          };

          const finalize = () => {
            if (captured) return;
            captured = true;
            if (captureTimer) clearTimeout(captureTimer);
            clientSocket.off('data', onData);
            clientSocket.setTimeout(0); // connection is now established

            // Buffer is about to be consumed and released — drop our share of
            // the global accounting so cleanup() doesn't double-subtract.
            totalCaptureBytes -= bufferedHere;
            bufferedHere = 0;

            const hello = Buffer.concat(chunks, total);
            const rttMs = Number(process.hrtime.bigint() - connectedAt) / 1_000_000;
            rttByUpPort.set(upPort, rttMs);
            remoteByUpPort.set(upPort, { addr: realAddr, port: realPort });

            const fp = buildFingerprint(hello);
            if (fp) {
              fpByUpPort.set(upPort, fp);
            } else {
              logger?.warn?.('clientHello parse failed', hello.subarray(0, 16).toString('hex'));
            }

            // Forward the captured bytes, then pipe both directions transparently.
            upstream!.write(hello);
            clientSocket.pipe(upstream!);
            upstream!.pipe(clientSocket);
          };

          const onData = (chunk: Buffer) => {
            // Global capture-buffer ceiling: under a flood of slow connections
            // this sheds load by dropping the connection that would tip us over
            // rather than letting the heap grow unbounded. The cap is far above
            // any single legitimate ClientHello (~16 KB), so only an aggregate
            // attack reaches it.
            if (totalCaptureBytes + chunk.length > MAX_TOTAL_CAPTURE_BYTES) {
              logger?.warn?.('global capture buffer cap reached, dropping connection');
              cleanup();
              return;
            }
            chunks.push(chunk);
            total += chunk.length;
            bufferedHere += chunk.length;
            totalCaptureBytes += chunk.length;
            // Bound the wait for a fragmented hello; forward what we have at 1.5s.
            if (!captureTimer) captureTimer = setTimeout(finalize, 1500);
            if (hasFullRecord(Buffer.concat(chunks, total)) || total >= FIRST_RECORD_CAP) {
              finalize();
            }
          };

          clientSocket.on('data', onData);
          clientSocket.resume();
        });
      };

      if (tlsAddr) {
        handoff();
      } else {
        tlsReady.then(handoff).catch(cleanup);
      }
    });

    return tcpProxy as unknown as http.Server;
  };
}

// ─── Lookups used by routes ──────────────────────────────────────────────────

export function getFingerprintForSocket(
  socket: net.Socket | tls.TLSSocket | null | undefined,
): TlsFingerprint | null {
  if (!socket) return null;
  if (socket instanceof tls.TLSSocket) {
    const port = socket.remotePort;
    if (typeof port === 'number') return fpByUpPort.get(port) ?? null;
  }
  return null;
}

export function getRttForSocket(
  socket: net.Socket | tls.TLSSocket | null | undefined,
): number | null {
  if (!socket) return null;
  if (socket instanceof tls.TLSSocket) {
    const port = socket.remotePort;
    if (typeof port === 'number') {
      const v = rttByUpPort.get(port);
      return typeof v === 'number' ? v : null;
    }
  }
  return null;
}

export function getRealRemoteForSocket(
  socket: net.Socket | tls.TLSSocket | null | undefined,
): RealRemote | null {
  if (!socket) return null;
  if (socket instanceof tls.TLSSocket) {
    const port = socket.remotePort;
    if (typeof port === 'number') return remoteByUpPort.get(port) ?? null;
  }
  return null;
}
