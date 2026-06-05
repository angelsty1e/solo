import type { ClientFingerprint, FullFingerprint, ServerFingerprint } from '../shared/types.js';
import type { DecisionResult, ReputationStats } from '../shared/decision/types.js';
import { getDb } from './db.js';

// Sessions expire after TTL_MS to avoid unbounded growth.
const TTL_MS = 1000 * 60 * 60; // 1h

function nowMs(): number {
  return Date.now();
}

function selectFull(sessionId: string): FullFingerprint | null {
  const db = getDb();
  const row = db
    .prepare(
      `SELECT s.id AS id,
              (SELECT data FROM server_tls  WHERE session_id = s.id) AS tls,
              (SELECT data FROM server_http WHERE session_id = s.id) AS http,
              (SELECT data FROM server_ip   WHERE session_id = s.id) AS ip,
              (SELECT data FROM client_full WHERE session_id = s.id) AS client,
              (SELECT data FROM decisions   WHERE session_id = s.id) AS decision,
              s.server_captured_at AS captured
       FROM sessions s
       WHERE s.id = ? AND s.expires_at > ?`,
    )
    .get(sessionId, nowMs()) as
    | {
        id: string;
        tls: string | null;
        http: string | null;
        ip: string | null;
        client: string | null;
        decision: string | null;
        captured: string | null;
      }
    | undefined;
  if (!row) return null;
  const server: ServerFingerprint = {
    capturedAt: row.captured ?? new Date().toISOString(),
    tls: row.tls ? JSON.parse(row.tls) : null,
    http: row.http ? JSON.parse(row.http) : null,
    ip: row.ip ? JSON.parse(row.ip) : null,
  };
  const client: ClientFingerprint = row.client ? JSON.parse(row.client) : emptyClient(sessionId);
  const decision: DecisionResult | null = row.decision ? JSON.parse(row.decision) : null;
  return { sessionId: row.id, server, client, decision };
}

const upsertSessionShellSQL = `
  INSERT INTO sessions (id, created_at, updated_at, expires_at)
  VALUES (@id, @now, @now, @exp)
  ON CONFLICT(id) DO UPDATE SET updated_at = @now, expires_at = @exp
`;

const upsertServerColsSQL = `
  UPDATE sessions SET
    server_captured_at = @capturedAt,
    ip = @ip,
    asn = @asn,
    asn_org = @asnOrg,
    country = @country,
    is_datacenter = @isDatacenter,
    is_proxy_hint = @isProxyHint,
    reverse_dns = @reverseDns,
    is_tor_exit = @isTorExit,
    tcp_rtt_ms = @tcpRttMs,
    ja3 = @ja3,
    ja3_hash = @ja3Hash,
    ja4 = @ja4,
    tls_version = @tlsVersion,
    sni = @sni,
    alpn = @alpn,
    user_agent = @userAgent,
    http_version = @httpVersion,
    accept_language = @acceptLanguage,
    sec_fetch_site = @secFetchSite,
    sec_fetch_mode = @secFetchMode,
    sec_fetch_dest = @secFetchDest,
    sec_fetch_user = @secFetchUser
  WHERE id = @id
`;

const upsertClientColsSQL = `
  UPDATE sessions SET
    client_collected_at = @collectedAt,
    duration_ms = @durationMs,
    platform = @platform,
    vendor = @vendor,
    language = @language,
    timezone = @timezone,
    screen_w = @screenW,
    screen_h = @screenH,
    dpr = @dpr,
    webdriver = @webdriver,
    canvas_hash = @canvasHash,
    webgl_hash = @webglHash,
    webgl_renderer = @webglRenderer,
    audio_hash = @audioHash,
    fonts_count = @fontsCount
  WHERE id = @id
`;

export function upsertServer(sessionId: string, server: ServerFingerprint): void {
  const db = getDb();
  const now = nowMs();
  const exp = now + TTL_MS;

  const tx = db.transaction(() => {
    db.prepare(upsertSessionShellSQL).run({ id: sessionId, now, exp });

    db.prepare(upsertServerColsSQL).run({
      id: sessionId,
      capturedAt: server.capturedAt,
      ip: server.ip?.ip ?? null,
      asn: server.ip?.asn ?? null,
      asnOrg: server.ip?.asnOrganization ?? null,
      country: server.ip?.country ?? null,
      isDatacenter: server.ip?.isDatacenter == null ? null : server.ip.isDatacenter ? 1 : 0,
      isProxyHint: server.ip?.isProxyHint ? 1 : 0,
      reverseDns: server.ip?.reverseDns ?? null,
      isTorExit: server.ip?.isTorExit == null ? null : server.ip.isTorExit ? 1 : 0,
      tcpRttMs: server.ip?.tcpRttMs ?? null,
      ja3: server.tls?.ja3 ?? null,
      ja3Hash: server.tls?.ja3Hash ?? null,
      ja4: server.tls?.ja4 ?? null,
      tlsVersion: server.tls?.version ?? null,
      sni: server.tls?.sni ?? null,
      alpn: server.tls?.alpn.join(',') ?? null,
      userAgent: server.http?.userAgent ?? null,
      httpVersion: server.http?.httpVersion ?? null,
      acceptLanguage: server.http?.acceptLanguage ?? null,
      secFetchSite: server.http?.secFetch?.site ?? null,
      secFetchMode: server.http?.secFetch?.mode ?? null,
      secFetchDest: server.http?.secFetch?.dest ?? null,
      secFetchUser: server.http?.secFetch?.user ?? null,
    });

    if (server.tls) {
      db.prepare(
        `INSERT INTO server_tls (session_id, data) VALUES (?, ?)
         ON CONFLICT(session_id) DO UPDATE SET data = excluded.data`,
      ).run(sessionId, JSON.stringify(server.tls));
    }
    if (server.http) {
      db.prepare(
        `INSERT INTO server_http (session_id, data) VALUES (?, ?)
         ON CONFLICT(session_id) DO UPDATE SET data = excluded.data`,
      ).run(sessionId, JSON.stringify(server.http));
    }
    if (server.ip) {
      db.prepare(
        `INSERT INTO server_ip (session_id, data) VALUES (?, ?)
         ON CONFLICT(session_id) DO UPDATE SET data = excluded.data`,
      ).run(sessionId, JSON.stringify(server.ip));
    }
  });
  tx();
}

export function upsertClient(sessionId: string, client: ClientFingerprint): FullFingerprint {
  const db = getDb();
  const now = nowMs();
  const exp = now + TTL_MS;

  const tx = db.transaction(() => {
    db.prepare(upsertSessionShellSQL).run({ id: sessionId, now, exp });

    db.prepare(upsertClientColsSQL).run({
      id: sessionId,
      collectedAt: client.collectedAt,
      durationMs: Math.round(client.durationMs),
      platform: client.navigator?.platform ?? null,
      vendor: client.navigator?.vendor ?? null,
      language: client.navigator?.language ?? null,
      timezone: client.locale?.timezone ?? null,
      screenW: client.screen?.width ?? null,
      screenH: client.screen?.height ?? null,
      dpr: client.screen?.devicePixelRatio ?? null,
      webdriver: client.automation?.webdriver == null ? null : client.automation.webdriver ? 1 : 0,
      canvasHash: client.canvas?.dataUrlHash ?? null,
      webglHash: client.webgl?.parametersHash ?? null,
      webglRenderer: client.webgl?.unmaskedRenderer ?? client.webgl?.renderer ?? null,
      audioHash: client.audio?.oscillatorHash ?? null,
      fontsCount: client.fonts?.detectedFonts.length ?? null,
    });

    db.prepare(
      `INSERT INTO client_full (session_id, data) VALUES (?, ?)
       ON CONFLICT(session_id) DO UPDATE SET data = excluded.data`,
    ).run(sessionId, JSON.stringify(client));
  });
  tx();

  return selectFull(sessionId) ?? {
    sessionId,
    server: emptyServer(),
    client,
  };
}

// Persist the decision-engine verdict: full JSON in `decisions`, plus the
// indexable synthesis (verdict, score, …) flattened onto `sessions`.
export function upsertDecision(sessionId: string, decision: DecisionResult): void {
  const db = getDb();
  const tx = db.transaction(() => {
    db.prepare(
      `INSERT INTO decisions (session_id, data, computed_at) VALUES (?, ?, ?)
       ON CONFLICT(session_id) DO UPDATE SET data = excluded.data, computed_at = excluded.computed_at`,
    ).run(sessionId, JSON.stringify(decision), decision.computedAt);

    db.prepare(
      `UPDATE sessions SET verdict = @verdict, bot_score = @score, trust_score = @trust,
         decision_forced = @forced, decision_version = @version
       WHERE id = @id`,
    ).run({
      id: sessionId,
      verdict: decision.verdict,
      score: decision.score,
      trust: decision.trustScore ?? 0,
      forced: decision.forced ? 1 : 0,
      version: decision.configVersion,
    });
  });
  tx();
}

// Cross-session reputation of a canvas+WebGL fingerprint within the retention
// window (~TTL). Counts DISTINCT IPs (robust to one user re-scanning).
//
// We judge as soon as AT LEAST ONE rendering surface is present. Requiring BOTH
// (the old behaviour) let a bot evade reputation entirely just by nulling a
// single surface — e.g. `canvas: null` while still sending `webgl` for its GPU
// trust credit — without tripping env_render_surfaces_absent (which needs all
// three surfaces null). The match is null-safe on BOTH columns (`IS ?`, a null
// is a value, not a wildcard), so the composite identity is the exact pair
// `(canvas, webgl)`: a swarm that consistently omits the same surface still
// collides with itself, while a session keeps its full precision when both are
// present. Both-null = every surface blocked/randomised → no judgement (we don't
// lump privacy-hardened humans into one bucket), as before.
export function fingerprintReputation(canvasHash: string | null, webglHash: string | null): ReputationStats {
  if (!canvasHash && !webglHash) return { fpDistinctIps: 0, fpTotalSessions: 0 };
  const db = getDb();
  const since = nowMs() - TTL_MS;
  const row = db
    .prepare(
      `SELECT COUNT(DISTINCT ip) AS d, COUNT(*) AS t
       FROM sessions
       WHERE canvas_hash IS ? AND webgl_hash IS ? AND ip IS NOT NULL AND created_at >= ?`,
    )
    .get(canvasHash, webglHash, since) as { d: number; t: number };
  return { fpDistinctIps: row.d, fpTotalSessions: row.t };
}

export function get(sessionId: string): FullFingerprint | null {
  return selectFull(sessionId);
}

export function list(): Array<{ sessionId: string; capturedAt: string }> {
  const db = getDb();
  const rows = db
    .prepare(
      `SELECT id, server_captured_at FROM sessions
       WHERE expires_at > ?
       ORDER BY updated_at DESC
       LIMIT 200`,
    )
    .all(nowMs()) as Array<{ id: string; server_captured_at: string | null }>;
  return rows.map((r) => ({ sessionId: r.id, capturedAt: r.server_captured_at ?? '' }));
}

export function startSweeper(): NodeJS.Timeout {
  return setInterval(() => {
    try {
      const db = getDb();
      db.prepare(`DELETE FROM sessions WHERE expires_at < ?`).run(nowMs());
    } catch {
      // DB may be closed already during shutdown.
    }
  }, 5 * 60 * 1000).unref();
}

function emptyClient(sessionId: string): ClientFingerprint {
  return {
    sessionId,
    collectedAt: '',
    durationMs: 0,
    navigator: {} as ClientFingerprint['navigator'],
    screen: {} as ClientFingerprint['screen'],
    locale: {} as ClientFingerprint['locale'],
    canvas: null,
    webgl: null,
    audio: null,
    fonts: null,
    webrtc: null,
    codecs: { video: {}, audio: {}, mediaSourceTypes: {} },
    permissions: { states: {} },
    automation: {
      webdriver: null,
      pluginsLength: 0,
      mimeTypesLength: 0,
      pluginNames: [],
      mimeTypeNames: [],
      chromeRuntime: false,
      hasNotificationPermission: false,
      inconsistencies: [],
      callPhantom: false,
      nightmare: false,
      selenium: false,
      playwrightHints: [],
      cdpHints: [],
    },
    speech: null,
    mediaDevices: null,
    mediaCapabilities: null,
    webgpu: null,
    cssMedia: null,
    intl: null,
    engine: null,
    network: null,
    storage: null,
    perfMemory: null,
    behavioral: {
      totalEvents: 0,
      durationMs: 0,
      mouse: { moves: 0, clicks: 0, meanSpeed: 0, stdSpeed: 0, meanCurvature: 0, stillRatio: 0, jitterRatio: 0 },
      keyboard: { keydowns: 0, keyups: 0, meanDwellMs: 0, stdDwellMs: 0, meanFlightMs: 0, stdFlightMs: 0, backspaceRatio: 0 },
      scroll: { events: 0, totalDeltaPx: 0, meanDeltaPx: 0, linearRatio: 0 },
      touch: { starts: 0, moves: 0, ends: 0, meanPressure: 0, multiTouchMax: 0 },
    },
  };
}

function emptyServer(): ServerFingerprint {
  return {
    capturedAt: new Date().toISOString(),
    tls: null,
    http: null,
    ip: null,
  };
}
