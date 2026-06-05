import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import Fastify from 'fastify';
import helmet from '@fastify/helmet';
import rateLimit from '@fastify/rate-limit';
import { createInterceptedServerFactory, rateLimitKeyForSocket } from './tls/interceptor.js';
import { registerRoutes } from './routes.js';
import { initGeoIp, geoIpStatus } from './enrich/geoip.js';
import { initCountryDb, countryDbStatus } from './enrich/country.js';
import { initTorList, torListStatus } from './enrich/tor.js';
import { startSweeper } from './store.js';
import { initDb, closeDb } from './db.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT ?? 8443);
const HOST = process.env.HOST ?? '0.0.0.0';

function resolveAbs(p: string): string {
  return path.isAbsolute(p) ? p : path.resolve(__dirname, '../..', p);
}

function readVersion(): string {
  try {
    const pkg = JSON.parse(fs.readFileSync(resolveAbs('package.json'), 'utf8')) as { version?: string };
    return pkg.version ?? '0.0.0';
  } catch {
    return '0.0.0';
  }
}

const CERT_PATH = resolveAbs(process.env.CERT_PATH ?? 'certs/cert.pem');
const KEY_PATH = resolveAbs(process.env.KEY_PATH ?? 'certs/key.pem');
const GEOIP_DB = resolveAbs(process.env.GEOIP_DB ?? 'data/GeoLite2-ASN.mmdb');
const GEOIP_COUNTRY_DB = resolveAbs(process.env.GEOIP_COUNTRY_DB ?? 'data/GeoLite2-Country.mmdb');
const TOR_EXIT_LIST = resolveAbs(process.env.TOR_EXIT_LIST ?? 'data/tor-exit-nodes.txt');
const DB_PATH = resolveAbs(process.env.DB_PATH ?? 'data/solo.db');

async function main() {
  if (!fs.existsSync(CERT_PATH) || !fs.existsSync(KEY_PATH)) {
    console.error(
      `Missing TLS material. Expected:\n  cert: ${CERT_PATH}\n  key:  ${KEY_PATH}\n` +
        'Under Docker the entrypoint generates a self-signed cert automatically. ' +
        'For a local run: `mkcert -install && mkcert -key-file certs/key.pem -cert-file certs/cert.pem localhost 127.0.0.1 ::1`.',
    );
    process.exit(1);
  }

  const version = readVersion();

  initDb(DB_PATH);
  // Optional integrity pinning: set GEOIP_DB_SHA256 / GEOIP_COUNTRY_DB_SHA256
  // to the expected hex digest to make startup fail closed on a tampered DB.
  await initGeoIp(GEOIP_DB, process.env.GEOIP_DB_SHA256);
  await initCountryDb(GEOIP_COUNTRY_DB, process.env.GEOIP_COUNTRY_DB_SHA256);
  await initTorList(TOR_EXIT_LIST);

  const cert = fs.readFileSync(CERT_PATH);
  const key = fs.readFileSync(KEY_PATH);

  const app = Fastify({
    // A full fingerprint is well under this; caps the /collect payload to
    // avoid memory pressure / DB bloat from oversized bodies.
    bodyLimit: 512 * 1024,
    logger: {
      level: process.env.LOG_LEVEL ?? 'info',
      // Avoid persisting client IPs in the request logs.
      redact: { paths: ['req.headers.cookie', 'req.headers.authorization'], remove: true },
      transport:
        process.env.NODE_ENV === 'production'
          ? undefined
          : { target: 'pino-pretty', options: { colorize: true, translateTime: 'HH:MM:ss' } },
    },
    serverFactory: createInterceptedServerFactory({
      tls: { cert, key },
      alpnProtocols: ['http/1.1'],
      logger: { info: console.log, warn: console.warn },
    }),
    trustProxy: false,
    disableRequestLogging: false,
  });

  // Security headers. CSP is strict: everything is self-hosted now (GSAP is
  // bundled by Vite), inline <style> blocks need 'unsafe-inline' for styles only.
  await app.register(helmet, {
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        frameAncestors: ["'none'"],
        formAction: ["'self'"],
      },
    },
    // Self-signed cert on a lab: don't force HSTS preload on the operator.
    hsts: false,
  });

  // Basic abuse protection. Keyed by the real client IP recovered from the proxy
  // side-map (req.ip is always 127.0.0.1 here); an unkeyable request falls back
  // to a per-connection token, never a shared bucket. /healthz is NOT exempted:
  // the Docker healthcheck polls it every 30s (~2/min), far under the 120/min
  // budget, so keeping it rate-limited closes a free unauthenticated recon /
  // amplification endpoint without affecting health polling.
  await app.register(rateLimit, {
    global: true,
    max: 120,
    timeWindow: '1 minute',
    keyGenerator: (req) => rateLimitKeyForSocket(req.raw.socket as never),
  });

  // Centralized error handler: log the full error server-side, but never leak
  // stack traces / internals to clients. Client errors (4xx, incl. rate-limit
  // 429 and schema 400s) keep their status + message; anything 5xx becomes a
  // generic 500.
  app.setErrorHandler((err, req, reply) => {
    const status = err.statusCode ?? 500;
    if (status >= 500) {
      req.log.error({ err }, 'unhandled request error');
      reply.code(500).send({ error: 'internal server error' });
    } else {
      reply.code(status).send({ error: err.message });
    }
  });

  await registerRoutes(app, { version });
  const sweeper = startSweeper();

  app.addHook('onClose', async () => {
    clearInterval(sweeper);
    closeDb();
  });

  // Graceful shutdown: without these handlers `docker compose stop` (SIGTERM)
  // kills Node before onClose runs, so the DB is never checkpointed/closed.
  let shuttingDown = false;
  for (const sig of ['SIGTERM', 'SIGINT'] as const) {
    process.once(sig, () => {
      if (shuttingDown) return;
      shuttingDown = true;
      app.log.info({ sig }, 'shutting down');
      app
        .close()
        .then(() => process.exit(0))
        .catch((err) => {
          console.error(err);
          process.exit(1);
        });
    });
  }

  await app.listen({ host: HOST, port: PORT });
  app.log.info(
    {
      version,
      port: PORT,
      host: HOST,
      geoip: geoIpStatus(),
      country: countryDbStatus(),
      tor: torListStatus(),
      db: DB_PATH,
      cert: CERT_PATH,
    },
    'solo fingerprint-lab listening',
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
