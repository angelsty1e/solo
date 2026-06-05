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
// server on 127.0.0.1:<ephemeral>. The upstream socket's *localPort* is what
// tls.Server sees as `remotePort`, so it's used only as a one-shot handoff key:
// at 'secureConnection' the captured context (fingerprint, RTT, real client
// IP/port) is moved onto the TLS socket object and the port entry is dropped.
// Every later lookup is by socket identity, so a recycled ephemeral port can
// never cross-attribute one connection's data to another.

export interface RealRemote {
  addr: string;
  port: number;
}

// Per-connection context captured server-side from the ClientHello, plus the
// real client IP/port and the measured TCP RTT.
interface ConnContext {
  fp: TlsFingerprint | null;
  rttMs: number;
  remote: RealRemote;
}

// Transient handoff map: populated at finalize() under the upstream loopback
// localPort, consumed exactly once at 'secureConnection' and deleted there. The
// upstream socket is still open at both moments, so the port is provably unique
// for that window — no other connection can hold the same number between the set
// and the consume.
const pendingByUpPort = new Map<number, ConnContext>();
// Authoritative store, keyed by the live TLS socket *object*. Object identity is
// stable for the whole request and never recycled, unlike the ephemeral port —
// this is what closes the cross-attribution race (the IP here feeds rate-limit
// and reputation, so a stale mapping is a spoofing vector, not just a glitch).
// WeakMap so a closed socket's entry is reclaimed by GC with no manual teardown.
const ctxBySocket = new WeakMap<net.Socket, ConnContext>();

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
      // Move the captured context from the transient port map onto the socket
      // object itself, then drop the port entry. From here on every lookup is by
      // object identity, immune to ephemeral-port reuse.
      const port = tlsSocket.remotePort;
      if (typeof port === 'number') {
        const ctx = pendingByUpPort.get(port);
        if (ctx) {
          pendingByUpPort.delete(port);
          ctxBySocket.set(tlsSocket, ctx);
        }
      }
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
        // Only the transient handoff entry can be orphaned here (if the socket
        // dies before 'secureConnection' consumed it). The WeakMap entry, if
        // already set, belongs to a live request and GC reclaims it on its own.
        if (upPort) pendingByUpPort.delete(upPort);
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

          // Incremental completeness: the old code ran `Buffer.concat(chunks)` on
          // EVERY data event, so a hello fragmented into N 1-byte segments cost
          // O(N²) CPU + allocations (a cheap pre-auth DoS, one per connection up to
          // the per-IP cap). Instead, parse the 5-byte record header ONCE — the
          // moment we have ≥5 bytes — to learn the total length, then compare the
          // running byte count. O(1) per chunk; the lone concat in the rare
          // header-split case runs at most once.
          let needTotal = -1; // bytes required for a full first record; -1 until header seen
          const updateNeed = () => {
            if (needTotal >= 0 || total < 5) return;
            const first = chunks[0]!;
            const head = first.length >= 5 ? first : Buffer.concat(chunks).subarray(0, 5);
            // Not a handshake record (port scan / garbage): forward as-is, don't wait.
            needTotal = head[0] !== 0x16 ? 5 : 5 + head.readUInt16BE(3);
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
            const fp = buildFingerprint(hello);
            if (!fp) {
              logger?.warn?.('clientHello parse failed', hello.subarray(0, 16).toString('hex'));
            }
            // Stash under the upstream port; 'secureConnection' moves it onto the
            // TLS socket object and deletes this entry.
            pendingByUpPort.set(upPort, { fp, rttMs, remote: { addr: realAddr, port: realPort } });

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
            updateNeed();
            if ((needTotal >= 0 && total >= needTotal) || total >= FIRST_RECORD_CAP) {
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
  return ctxBySocket.get(socket)?.fp ?? null;
}

export function getRttForSocket(
  socket: net.Socket | tls.TLSSocket | null | undefined,
): number | null {
  if (!socket) return null;
  const v = ctxBySocket.get(socket)?.rttMs;
  return typeof v === 'number' ? v : null;
}

export function getRealRemoteForSocket(
  socket: net.Socket | tls.TLSSocket | null | undefined,
): RealRemote | null {
  if (!socket) return null;
  return ctxBySocket.get(socket)?.remote ?? null;
}

// Rate-limit key: the real client IP when known, else a per-connection-unique
// token (the loopback ephemeral port). NEVER a shared constant like `req.ip`
// (always 127.0.0.1 behind the internal proxy) — pooling every unkeyable request
// into one bucket lets a single client drain the budget for everyone (DoS) or
// slip its count by flip-flopping in and out of the shared bucket. Every real
// request rides a TLS socket whose remote is resolved at 'secureConnection', so
// a missing IP is anomalous; isolating it per connection fails safe.
export function rateLimitKeyForSocket(socket: net.Socket | tls.TLSSocket | null | undefined): string {
  const real = getRealRemoteForSocket(socket);
  if (real?.addr) return real.addr;
  return `noip:${socket?.remotePort ?? 'unknown'}`;
}
