import type { FullFingerprint } from '../types.js';
import type {
  DecisionConfig,
  DecisionInput,
  DecisionResult,
  LevelResult,
  ReputationStats,
  Verdict,
} from './types.js';
import { defaultConfig, versionTag } from './config.js';
import { evaluateLevel } from './level.js';
import { evaluateCards } from './cards.js';
import { computeTrust } from './trust.js';

function clamp01(n: number): number {
  return Math.max(0, Math.min(1, n));
}

// Run every enabled level (suspicion side), compute the trust credit (human
// side), then combine. The trust credit subtracts from accumulated suspicion
// but NEVER clears a hard N1 confession (forced). When the net suspicion is low
// enough AND the credit is high (with liveness, if required), the verdict is the
// positive 'human' — distinct from 'clean' ("nothing against you").
// `computedAt` is injectable so a pure caller (or tests) stays deterministic.
export function runDecision(
  input: DecisionInput,
  config: DecisionConfig = defaultConfig,
  computedAt: string = new Date().toISOString(),
): DecisionResult {
  const byLevel: LevelResult[] = [];
  for (const lvl of config.levels) {
    if (!lvl.enabled) continue;
    // Fully generic: the evaluator looks up this level's signals from the
    // registry. A level with no registered signals simply yields 'clean'.
    byLevel.push(evaluateLevel(lvl.level, input, lvl));
  }

  const forced = byLevel.some((l) => l.forced);
  const botScore = byLevel.reduce((m, l) => Math.max(m, l.score), 0);

  // Trust credit. Identity-coherence rewards the ABSENCE of identity mismatches,
  // so it needs the set of bot signals that actually fired.
  const firedBotSignals = new Set(byLevel.flatMap((l) => l.hits).map((h) => h.id));
  const trust = computeTrust(input, config.trust, firedBotSignals);

  // A hard confession is immune: a bot doesn't get cleared by good behaviour.
  // The offset uses `offsetScore` (forgeable credit capped), NOT the full
  // `trust.score`: organic-looking but JS-supplied evidence can shed a moderate
  // presumption (VPN/datacenter) but can't whitewash a strong/stacked server
  // signal (TLS↔UA lie, Tor, accumulation) down to 'human'. The full score still
  // governs the positive 'human' label below.
  const rawNet = clamp01(botScore - config.trust.offsetFactor * trust.offsetScore);
  // Block-level cap: when a server-side signal on its own reached the block
  // threshold (a TLS↔UA lie stacked with a datacenter, a Tor exit, a reputation
  // swarm), the NON-forgeable residential slice must not stack ON TOP of the
  // forgeable cap to buy a bot→suspect downgrade — that would let a residential
  // botnet (reputation maxed) escape just by originating from a residential IP.
  // So we cap the TOTAL offset at `maxForgeableOffset` here, rather than flooring
  // the verdict outright: this neutralises the residential overreach while still
  // letting a genuine VPN human whose ASN trips two server signals (datacenter +
  // proxy = block) keep the moderate forgeable offset → 'suspect', not 'bot'.
  const cappedOffset = Math.min(trust.offsetScore, config.trust.maxForgeableOffset);
  const netSuspicion = forced
    ? 1
    : botScore >= config.aggregate.block
      ? clamp01(botScore - config.trust.offsetFactor * cappedOffset)
      : rawNet;

  let verdict: Verdict;
  if (byLevel.length === 0 && trust.signals.length === 0) {
    verdict = 'unknown';
  } else if (netSuspicion >= config.aggregate.block) {
    verdict = 'bot';
  } else if (netSuspicion >= config.aggregate.review) {
    verdict = 'suspect';
  } else if (
    trust.score >= config.trust.humanThreshold &&
    (!config.trust.requireLiveness || trust.liveness) &&
    // The liveness anchor (organic behaviour) is itself client-forgeable, so it
    // must not mint 'human' on its own: require at least one INDEPENDENT trust
    // signal (identity coherence, real GPU, residential IP…). A lone forged
    // behavioural blob earns 'clean', not 'human'.
    trust.corroborated
  ) {
    verdict = 'human';
  } else {
    verdict = 'clean';
  }

  return {
    verdict,
    score: netSuspicion,
    forced,
    byLevel,
    trustScore: trust.score,
    trustSignals: trust.signals,
    cards: [], // filled by analyze(), which has the full fingerprint
    configVersion: versionTag(config), // human label + content hash (traceability)
    computedAt,
  };
}

// High-level entry point used by the server: derives the level inputs from the
// full fingerprint, runs the verdict, then computes the per-card tri-state.
export function analyze(
  full: FullFingerprint,
  config: DecisionConfig = defaultConfig,
  computedAt: string = new Date().toISOString(),
  reputation: ReputationStats | null = null,
): DecisionResult {
  // Prefer the client-observed UA (what the automation collector reasoned
  // about); fall back to the server-observed UA.
  const userAgent = full.client.navigator?.userAgent ?? full.server.http?.userAgent ?? null;
  const decision = runDecision(
    {
      automation: full.client.automation,
      userAgent,
      tls: full.server.tls,
      http: full.server.http,
      ip: full.server.ip,
      client: full.client,
      reputation,
    },
    config,
    computedAt,
  );
  return { ...decision, cards: evaluateCards(full, decision) };
}
