import path from 'node:path';
import fs from 'node:fs';
import { randomUUID } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import type { FastifyInstance, FastifyRequest } from 'fastify';
import fastifyStatic from '@fastify/static';
import type { ServerFingerprint } from '../shared/types.js';
import { captureHttpFingerprint } from './http/headers.js';
import { geoIpStatus } from './enrich/geoip.js';
import { countryDbStatus } from './enrich/country.js';
import { torListStatus } from './enrich/tor.js';
import { enrichIpSync, enrichIpAwaited } from './enrich/pipeline.js';
import { getFingerprintForSocket, getRealRemoteForSocket, getRttForSocket, rateLimitKeyForSocket } from './tls/interceptor.js';
import { getDb } from './db.js';
import * as store from './store.js';
import { analyze } from '../shared/decision/engine.js';
import { ClientFingerprintSchema } from '../shared/validation.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export interface RouteOptions {
  version: string;
}

// Walk up from dist/server until we find the project root (the dir that holds dist/client).
function resolveClientDir(): string {
  let cur = __dirname;
  for (let i = 0; i < 6; i++) {
    const candidate = path.join(cur, 'dist', 'client');
    if (fs.existsSync(candidate)) return candidate;
    cur = path.dirname(cur);
  }
  // Fallback to the dev path; will 404 cleanly if missing.
  return path.resolve(__dirname, '../../dist/client');
}

// The TLS connection arrives through our internal TCP proxy, so `req.ip` is
// always 127.0.0.1. The real client IP is recovered from the interceptor's
// side map. We deliberately do NOT trust X-Forwarded-For: the server is
// exposed directly (no reverse proxy), so any XFF would be attacker-controlled
// and would let a client spoof the IP that gets stored, geolocated and logged.
function extractIp(req: FastifyRequest): string {
  const real = getRealRemoteForSocket(req.raw.socket as never);
  if (real && real.addr) return real.addr;
  return req.ip;
}

// Connection-level capture: the raw TLS/HTTP fingerprints plus the inputs the IP
// enrichment pipeline can't look up (the client IP, the measured TCP RTT). The
// IP *intelligence* (ASN, geo, datacenter/proxy/Tor, rDNS) lives in the
// extensible pipeline in enrich/pipeline.ts.
function captureConnection(req: FastifyRequest): {
  tls: ServerFingerprint['tls'];
  http: ServerFingerprint['http'];
  ip: string;
  tcpRttMs: number | null;
} {
  return {
    tls: getFingerprintForSocket(req.raw.socket as never),
    http: captureHttpFingerprint(req.raw),
    ip: extractIp(req),
    tcpRttMs: getRttForSocket(req.raw.socket as never),
  };
}

function buildServerFingerprintSync(req: FastifyRequest): ServerFingerprint {
  const c = captureConnection(req);
  return {
    capturedAt: new Date().toISOString(),
    tls: c.tls,
    http: c.http,
    ip: enrichIpSync({ ip: c.ip, tcpRttMs: c.tcpRttMs }),
  };
}

async function buildServerFingerprintAwaited(req: FastifyRequest): Promise<ServerFingerprint> {
  const c = captureConnection(req);
  return {
    capturedAt: new Date().toISOString(),
    tls: c.tls,
    http: c.http,
    ip: await enrichIpAwaited({ ip: c.ip, tcpRttMs: c.tcpRttMs }),
  };
}

// Session ids are server-generated UUIDv4 (122 bits of entropy). The recap URL
// is therefore an unguessable capability: knowing the id == being allowed to
// read it. We never accept a client-supplied id (which would be guessable and
// would let a client overwrite another session), and there is no endpoint that
// enumerates sessions.
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

export async function registerRoutes(app: FastifyInstance, opts: RouteOptions): Promise<void> {
  const clientDir = resolveClientDir();
  await app.register(fastifyStatic, {
    root: path.join(clientDir, 'assets'),
    prefix: '/assets/',
    decorateReply: false,
  });

  // Liveness/readiness — also drives the Docker healthcheck.
  app.get('/healthz', async (_req, reply) => {
    let dbOk = false;
    try {
      getDb().prepare('SELECT 1').get();
      dbOk = true;
    } catch {
      dbOk = false;
    }
    // Only expose load-state, never the on-disk paths: leaking
    // /data/GeoLite2-*.mmdb, the Tor list path, etc. hands an attacker free
    // reconnaissance on the container layout.
    const geo = geoIpStatus();
    const ctry = countryDbStatus();
    const tor = torListStatus();
    reply.code(dbOk ? 200 : 503).send({
      status: dbOk ? 'ok' : 'degraded',
      version: opts.version,
      db: dbOk,
      geoip: { loaded: geo.loaded },
      country: { loaded: ctry.loaded },
      tor: { loaded: tor.loaded, count: tor.count },
    });
  });

  app.get('/', async (_req, reply) => {
    const indexPath = path.join(clientDir, 'index.html');
    if (!fs.existsSync(indexPath)) {
      reply.code(503).type('text/plain').send('Client bundle missing. Run `npm run build`.');
      return;
    }
    reply.type('text/html').send(fs.readFileSync(indexPath, 'utf8'));
  });

  app.get<{ Params: { id: string } }>('/recap/:id', async (_req, reply) => {
    // The page is just the static shell; the data is fetched from the
    // capability-protected /api/fp/:id below.
    const recapPath = path.join(clientDir, 'recap.html');
    if (!fs.existsSync(recapPath)) {
      reply.code(503).type('text/plain').send('Client bundle missing. Run `npm run build`.');
      return;
    }
    reply.type('text/html').send(fs.readFileSync(recapPath, 'utf8'));
  });

  // Live view of what the server already knows about *this* connection.
  app.get('/api/fp/me', async (req) => {
    return buildServerFingerprintSync(req);
  });

  app.get<{ Params: { id: string } }>('/api/fp/:id', async (req, reply) => {
    if (!UUID_V4.test(req.params.id)) {
      reply.code(400).send({ error: 'invalid id' });
      return;
    }
    const full = store.get(req.params.id);
    if (!full) {
      reply.code(404).send({ error: 'not found' });
      return;
    }
    return full;
  });

  app.post(
    '/collect',
    {
      // /collect is the expensive path (full fingerprint parse + several DB
      // writes + decision engine). Give it its own tighter budget on top of the
      // global 120/min so it can't be hammered to exhaust CPU / bloat the DB.
      // Keyed by the real client IP, like the global limiter.
      config: {
        rateLimit: {
          max: 15,
          timeWindow: '1 minute',
          keyGenerator: (req) => rateLimitKeyForSocket(req.raw.socket as never),
        },
      },
    },
    async (req, reply) => {
      // The body is the only attacker-controlled input we persist and feed to the
      // decision engine. Validate it against the full schema (correct types,
      // required fields, bounded numbers) before trusting any of it; a malformed
      // payload is rejected with 400 instead of polluting the DB or skewing scores.
      const parsed = ClientFingerprintSchema.safeParse(req.body);
      if (!parsed.success) {
        req.log.warn({ issues: parsed.error.issues.length }, 'rejected invalid /collect body');
        reply.code(400).send({ error: 'invalid fingerprint payload' });
        return;
      }
      // Ignore any client-supplied id: assign an unguessable server-side one.
      // Spread into a fresh object rather than mutating the parsed input.
      const sessionId = randomUUID();
      const client = { ...parsed.data, sessionId };
      const server = await buildServerFingerprintAwaited(req);
      store.upsertServer(sessionId, server);
      const full = store.upsertClient(sessionId, client);

      // Cross-session reputation: how many distinct IPs share this exact
      // canvas+WebGL fingerprint in the retention window. Queried AFTER the
      // current session is stored, so it counts itself.
      const reputation = store.fingerprintReputation(
        full.client.canvas?.dataUrlHash ?? null,
        full.client.webgl?.parametersHash ?? null,
      );

      // Decision engine: verdict + per-card tri-state, computed from the full
      // fingerprint and persisted alongside the session.
      const decision = analyze(full, undefined, undefined, reputation);
      store.upsertDecision(sessionId, decision);

      return {
        ok: true,
        sessionId: full.sessionId,
        recapUrl: `/recap/${full.sessionId}`,
        verdict: decision.verdict,
        score: decision.score,
      };
    },
  );

  app.get<{ Params: { id: string } }>('/export/:id', async (req, reply) => {
    if (!UUID_V4.test(req.params.id)) {
      reply.code(400).send({ error: 'invalid id' });
      return;
    }
    const full = store.get(req.params.id);
    if (!full) {
      reply.code(404).send({ error: 'not found' });
      return;
    }
    reply
      .type('application/json')
      .header('content-disposition', `attachment; filename="fingerprint-${req.params.id}.json"`)
      .send(JSON.stringify(full, null, 2));
  });
}
