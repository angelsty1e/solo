import type { DecisionConfig } from './types.js';
import { signalsForLevel } from './registry.js';

// ─── Default decision config ────────────────────────────────────────────────
// Tunable without touching code: edit the weights/thresholds here, or supply an
// override at runtime (see resolveConfig). The `version` is persisted with each
// verdict so a decision can always be traced back to the rules that produced it.
export const defaultConfig: DecisionConfig = {
  version: 'n1n2n3n4n5-trust-2026.06.4',
  levels: [
    {
      level: 1,
      enabled: true,
      // Hard signals: presence alone forces 'bot'.
      hardSignals: ['webdriver', 'pw_globals', 'cdp_traces', 'selenium', 'phantom', 'nightmare', 'headless_ua'],
      // Soft signals: accumulate towards the thresholds below.
      weights: {
        // chrome.runtime est souvent absent sur un Chrome légitime (hors
        // contexte d'extension) → signal très bruité, poids quasi nul. Ne
        // déclenche plus 'suspect' seul ; ne compte que s'il s'empile.
        forged_chrome: 0.15,
        zero_plugins: 0.5,
        notif_no_focus: 0.15,
      },
      thresholds: { block: 0.8, review: 0.4 },
    },
    {
      level: 2,
      enabled: true,
      // Level 2 = présomption: no hard override. Even the TLS↔UA lie is a strong
      // weighted signal (alone → suspect; stacks to 'bot' with anything else).
      hardSignals: [],
      weights: {
        tls_ua_mismatch: 0.7,
        http_inconsistencies: 0.5,
        ip_tor: 0.6,
        ip_datacenter: 0.4,
        ip_proxy: 0.4,
        rdns_hosting: 0.25,
        rtt_incoherence: 0.3,
        lang_header_js_mismatch: 0.5,
        client_hints_ua_mismatch: 0.5,
      },
      thresholds: { block: 0.8, review: 0.4 },
    },
    {
      level: 3,
      enabled: true,
      // Cohérence d'environnement = présomption, jamais un aveu : aucune
      // contradiction isolée ne force 'bot' (VPN, voyageur, extension vie
      // privée, VM utilisée par un humain ont tous des contradictions légitimes).
      // La force vient du faisceau — deux contradictions fortes → 'bot'.
      hardSignals: [],
      weights: {
        env_platform_os_mismatch: 0.6,
        env_languages_empty: 0.5,
        env_uadata_incoherent: 0.3,
        env_software_gpu: 0.65,
        env_render_surfaces_absent: 0.5,
        env_fonts_minimal: 0.3,
        env_no_hw_video_decode: 0.15,
        env_speech_no_voices: 0.2,
        env_no_media_devices: 0.25,
        env_webgpu_absent: 0.1,
        env_screen_default_dims: 0.3,
        env_permissions_all_denied: 0.15,
        env_locale_ip_mismatch: 0.2,
        env_engine_ua_mismatch: 0.65,
        env_webrtc_no_local_ip: 0.15,
        env_vm_resource_profile: 0.25,
      },
      thresholds: { block: 0.8, review: 0.4 },
    },
    {
      level: 4,
      enabled: true,
      // Comportement = présomption : motifs synthétiques seulement, aucun aveu.
      // Seuils conservateurs (taille d'échantillon + régularité exacte) pour ne
      // pas pénaliser un humain peu actif. La lecture *positive* (humain) viendra
      // du score de confiance, pas de ce niveau.
      hardSignals: [],
      weights: {
        beh_no_interaction: 0.2,
        beh_mouse_synthetic: 0.45,
        beh_mouse_constant_speed: 0.3,
        beh_scroll_linear: 0.4,
        beh_keystroke_robotic: 0.45,
      },
      thresholds: { block: 0.8, review: 0.4 },
    },
    {
      level: 5,
      enabled: true,
      // Réputation = présomption (agrégat cross-session). Aucun aveu dur : une
      // empreinte partagée peut avoir une explication (parc de machines clonées
      // légitime). Seul → suspect ; empilé avec un autre niveau → bot.
      hardSignals: [],
      weights: {
        rep_fp_many_ips: 0.6,
        rep_fp_swarm: 0.4, // s'ajoute à many_ips → 1.0 → 'bot' pour un essaim ≥10 IP
      },
      thresholds: { block: 0.8, review: 0.4 },
    },
  ],
  // Aggregate thresholds applied to the net suspicion (botScore − trust offset).
  aggregate: { block: 0.8, review: 0.4 },
  // Trust credit: positive evidence FOR humanity. Behaviour dominates (the only
  // liveness proof); passive signals add small amounts. Capped at 1.
  trust: {
    weights: {
      trust_behavior_human: 0.5,
      trust_identity_coherent: 0.2,
      trust_hardware_gpu: 0.15,
      trust_hw_video_decode: 0.1,
      trust_fonts_rich: 0.1,
      trust_residential_ip: 0.1,
      trust_speech_voices: 0.05,
      trust_media_devices: 0.05,
    },
    offsetFactor: 1.0, // 1 unit of trust cancels 1 unit of suspicion
    humanThreshold: 0.5, // min credit for the positive 'human' verdict
    requireLiveness: true, // 'human' requires organic behaviour
  },
};

// Shallow-merge an override onto the default. Levels are matched by `level`
// number; only the provided fields are replaced. Unknown levels are appended.
// Kept intentionally simple — enough to override thresholds/weights from a JSON
// file without a schema validator.
export function resolveConfig(override?: Partial<DecisionConfig>): DecisionConfig {
  if (!override) return defaultConfig;
  const byLevel = new Map(defaultConfig.levels.map((l) => [l.level, { ...l }]));
  for (const lvl of override.levels ?? []) {
    const base = byLevel.get(lvl.level);
    byLevel.set(lvl.level, base ? { ...base, ...lvl } : lvl);
  }
  const resolved: DecisionConfig = {
    version: override.version ?? defaultConfig.version,
    levels: [...byLevel.values()].sort((a, b) => a.level - b.level),
    aggregate: override.aggregate ?? defaultConfig.aggregate,
    trust: override.trust ?? defaultConfig.trust,
  };
  warnConfig(resolved);
  return resolved;
}

// ─── Config validation ──────────────────────────────────────────────────────
// Static sanity checks that surface silent misconfigurations. We deliberately do
// NOT warn on "Σ weights > 1" per level: a level like N3 has 16 rare signals that
// never all co-fire, so its sum is legitimately ≫ 1. Instead we catch the cases
// that are unambiguously wrong: typo'd ids, registered-but-unconfigured (inert)
// signals, and a single weight above the cap.
export function validateConfig(config: DecisionConfig): string[] {
  const warnings: string[] = [];
  for (const lvl of config.levels) {
    const known = new Set(signalsForLevel(lvl.level).map((s) => s.id));
    const configured = new Set([...Object.keys(lvl.weights), ...lvl.hardSignals]);

    for (const id of configured) {
      if (!known.has(id)) warnings.push(`niveau ${lvl.level} : id de signal inconnu « ${id} » (faute de frappe ? absent du registry)`);
    }
    for (const id of known) {
      if (!configured.has(id)) warnings.push(`niveau ${lvl.level} : signal « ${id} » enregistré mais ni pondéré ni hard → inerte`);
    }
    for (const [id, w] of Object.entries(lvl.weights)) {
      if (w > 1) warnings.push(`niveau ${lvl.level} : poids de « ${id} » = ${w} > 1 (l'excédent est inerte, score plafonné à 1)`);
    }
  }
  return warnings;
}

function warnConfig(config: DecisionConfig): void {
  for (const w of validateConfig(config)) console.warn(`[decision-config] ${w}`);
}

// Validate the built-in config once at module load (fail loud, not silent).
warnConfig(defaultConfig);

// ─── Content fingerprint of the rules ───────────────────────────────────────
// The human `version` label is hand-maintained and drifts (we saw it). We append
// a deterministic 8-hex hash of the ACTUAL rules (levels + aggregate + trust,
// excluding the label itself) to the persisted version. If someone retunes a
// weight but forgets to bump the label, the hash changes → the desync is visible
// in every stored decision. FNV-1a: pure JS, no deps, isomorphic-safe.
export function configFingerprint(config: DecisionConfig): string {
  const payload = JSON.stringify({ levels: config.levels, aggregate: config.aggregate, trust: config.trust });
  let h = 0x811c9dc5;
  for (let i = 0; i < payload.length; i++) {
    h ^= payload.charCodeAt(i);
    h = Math.imul(h, 0x01000193);
  }
  return (h >>> 0).toString(16).padStart(8, '0');
}

// The version string persisted with every decision: human label + rule hash.
export function versionTag(config: DecisionConfig): string {
  return `${config.version}+${configFingerprint(config)}`;
}
