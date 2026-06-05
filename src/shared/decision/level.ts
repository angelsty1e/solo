import type { DecisionInput, LevelConfig, LevelResult, SignalHit, Verdict } from './types.js';
import { signalsForLevel } from './registry.js';

// ─── Generic per-level evaluator ────────────────────────────────────────────
// Same two-layer model for every level:
//   1. Any *hard* signal (config.hardSignals) → verdict 'bot', forced, score 1.
//   2. Otherwise sum the *soft* weights and compare to the thresholds.
//
// Asymmetry note (applies to all levels): a level can only push *towards* 'bot'.
// A 'clean' result therefore carries LOW confidence (confidence == score): the
// absence of a tell is not proof of a human. The aggregate verdict (engine.ts)
// takes the worst across levels, so presumptions stack with confessions.
export function evaluateLevel(level: number, input: DecisionInput, cfg: LevelConfig): LevelResult {
  const hits: SignalHit[] = [];

  for (const def of signalsForLevel(level)) {
    const evidence = def.detect(input);
    if (!evidence) continue;
    const isHard = cfg.hardSignals.includes(def.id);
    hits.push({
      id: def.id,
      label: def.label,
      level,
      severity: isHard ? 'hard' : 'soft',
      weight: isHard ? 0 : cfg.weights[def.id] ?? 0,
      evidence,
    });
  }

  const forced = hits.some((h) => h.severity === 'hard');
  if (forced) {
    return { level, verdict: 'bot', score: 1, forced: true, confidence: 0.99, hits };
  }

  const score = Math.min(1, hits.reduce((sum, h) => sum + h.weight, 0));
  let verdict: Verdict;
  if (score >= cfg.thresholds.block) verdict = 'bot';
  else if (score >= cfg.thresholds.review) verdict = 'suspect';
  else verdict = 'clean';

  return { level, verdict, score, forced: false, confidence: score, hits };
}
