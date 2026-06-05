import type { AutomationSnapshot, ClientFingerprint, HttpFingerprint, IpFingerprint, TlsFingerprint } from '../types.js';

// ─── Decision engine — shared, deterministic types ──────────────────────────
// The engine is a pure function of a snapshot + a config. It produces, per
// level, a verdict and the exact signals that fired (with their evidence).
// Level 1 = "aveux d'automatisation": a single hard signal is near-proof of a
// bot; soft signals only count when they accumulate past a threshold.

// 'human' is a *positive* verdict (earned by a trust credit), distinct from
// 'clean' which only means "nothing against you". Per-level results never emit
// 'human' (levels only push towards bot); it emerges only at the aggregate.
export type Verdict = 'bot' | 'suspect' | 'clean' | 'human' | 'unknown';

// 'hard'  → presence alone forces `bot` (override, short-circuits the score).
// 'soft'  → contributes its weight to a cumulative score compared to thresholds.
export type Severity = 'hard' | 'soft';

// What the engine needs across levels. Level 1 reads `automation` + `userAgent`
// (a missing chrome.runtime only matters on a real Chrome UA). Level 2 reads the
// server-side `tls`/`http`/`ip` (impossible to mask in JS) and cross-checks them
// against the claimed `userAgent`. Level 3 (cohérence d'environnement) reads the
// full client snapshot and cross-checks its collectors against each other and
// against `ip`/`userAgent`. Fields are optional so a level only needs what it
// consumes; analyze() in engine.ts fills them from the full fingerprint.
// Cross-session reputation, computed server-side by querying the store (the
// engine stays pure — it only consumes these counts). Bounded by the retention
// window (~1h TTL): we never keep fingerprint↔IP data longer than that.
export interface ReputationStats {
  fpDistinctIps: number; // distinct IPs sharing this canvas+WebGL fingerprint
  fpTotalSessions: number; // total sessions with that fingerprint in the window
}

export interface DecisionInput {
  automation: AutomationSnapshot;
  userAgent: string | null;
  tls?: TlsFingerprint | null;
  http?: HttpFingerprint | null;
  ip?: IpFingerprint | null;
  client?: ClientFingerprint | null;
  reputation?: ReputationStats | null;
}

export interface SignalHit {
  id: string;
  label: string;
  level: number;
  severity: Severity;
  weight: number; // 0 for hard signals (they override), > 0 for soft contributions
  evidence: string[]; // the concrete proof: injected globals, inconsistency keys, …
}

export interface LevelResult {
  level: number;
  verdict: Verdict;
  score: number; // 0..1 (capped); always 1 when a hard signal forced the verdict
  forced: boolean; // a hard signal short-circuited the score
  confidence: number; // 0..1 — confidence in *this* verdict (see note in level.ts)
  hits: SignalHit[];
}

// Per-card traffic light shown in the recap. Deliberately a tri-state:
//   'bot'     🔴 a bot signal is present on this dimension
//   'human'   🟢 the data positively corroborates a real human browser
//   'unknown' 🟠 inconclusive — no decisive signal, OR a pure-identifier card
//             that says nothing about bot vs human (canvas/audio/fonts…).
// Note: 'human' never means "human proven" — it means "nothing suspicious and
// at least one positive tell here". Absence of a confession is not proof.
export type CardTone = 'bot' | 'human' | 'unknown';

export interface CardVerdict {
  id: string; // stable card id (matches the recap section)
  tone: CardTone;
  reason: string; // short human-readable justification (tooltip)
}

// A positive human-trust contribution. Mirror of SignalHit but for evidence
// *for* humanity rather than against — accumulates into the trust credit.
export interface TrustHit {
  id: string;
  label: string;
  weight: number; // positive contribution to the trust credit
  evidence: string[];
}

export interface DecisionResult {
  verdict: Verdict; // final verdict after trust offset (see engine.ts)
  score: number; // effective net suspicion (botScore − trust offset), 0..1
  forced: boolean; // a hard N1 confession fired → immune to trust offset
  byLevel: LevelResult[];
  trustScore: number; // 0..1 — positive human-trust credit
  trustSignals: TrustHit[];
  cards: CardVerdict[]; // per-card tri-state for the recap UI
  configVersion: string;
  computedAt: string; // ISO8601
}

export interface LevelThresholds {
  block: number; // score >= block  → 'bot'
  review: number; // score >= review → 'suspect'
}

export interface LevelConfig {
  level: number;
  enabled: boolean;
  hardSignals: string[]; // signal ids treated as hard (override) at this level
  weights: Record<string, number>; // signal id → weight, for soft signals
  thresholds: LevelThresholds;
}

// Trust credit configuration. `weights` per trust signal; `offsetFactor` scales
// how much the credit subtracts from accumulated suspicion; `humanThreshold` is
// the minimum credit to earn the positive 'human' verdict; `requireLiveness`
// gates 'human' on behavioural evidence (passive-only credit caps at 'clean').
export interface TrustConfig {
  weights: Record<string, number>;
  offsetFactor: number;
  humanThreshold: number;
  requireLiveness: boolean;
}

export interface DecisionConfig {
  version: string;
  levels: LevelConfig[];
  // Aggregate thresholds applied to the net suspicion (after trust offset).
  aggregate: LevelThresholds;
  trust: TrustConfig;
}

// A signal definition lives in the registry. `detect` returns the evidence
// array when the signal fires, or null when it doesn't. Whether a fired signal
// is hard or soft is decided by the *config*, not the registry — so thresholds
// and severities can be retuned without touching detection logic.
export interface SignalDef {
  id: string;
  label: string;
  level: number;
  detect: (input: DecisionInput) => string[] | null;
}

// Trust signal: returns positive evidence when the pro-human condition holds.
// `liveness` flags the behavioural-vivacity anchor (gates the 'human' verdict).
export interface TrustSignalDef {
  id: string;
  label: string;
  liveness?: boolean;
  detect: (input: DecisionInput, firedBotSignals: ReadonlySet<string>) => string[] | null;
}
