import type { DecisionInput, TrustConfig, TrustHit, TrustSignalDef } from './types.js';
import { SOFTWARE_GPU, platformMatchesUa } from './detection.js';

// ─── Trust credit — positive evidence FOR humanity ──────────────────────────
// The only signals that point the other way: instead of "this looks like a bot"
// they say "this corroborates a real human". Mostly hard-to-fake things, with
// organic behaviour as the anchor (the sole true liveness proof). The credit
// subtracts from accumulated suspicion (see engine.ts) but never clears a hard
// N1 confession.

// Bot signals whose ABSENCE (combined with positive coherence) earns the
// identity-coherence credit. If any of these fired, identity isn't coherent.
const IDENTITY_BOT_SIGNALS = [
  'env_platform_os_mismatch',
  'env_engine_ua_mismatch',
  'env_uadata_incoherent',
  'env_languages_empty',
  'lang_header_js_mismatch',
  'client_hints_ua_mismatch',
];

export const TRUST_SIGNALS: TrustSignalDef[] = [
  {
    id: 'trust_behavior_human',
    label: 'Comportement organique (souris / clavier)',
    liveness: true, // the vivacity anchor
    detect: (i) => {
      const b = i.client?.behavioral;
      if (!b) return null;
      const m = b.mouse;
      const k = b.keyboard;
      // Souris organique : assez de déplacements AVEC courbure, micro-jitter et
      // variance de vitesse — un script reproduit rarement les trois ensemble.
      if (m && m.moves >= 25 && m.meanCurvature > 0 && m.jitterRatio > 0 && m.stdSpeed > 0) {
        return [`souris organique : ${m.moves} déplacements avec courbure, jitter et variance de vitesse`];
      }
      // Frappe organique : variance de rythme (dwell + flight) sur assez de touches.
      if (k && k.keydowns >= 8 && k.stdDwellMs > 0 && k.stdFlightMs > 0) {
        return [`frappe organique : variance de rythme sur ${k.keydowns} touches`];
      }
      return null;
    },
  },
  {
    id: 'trust_identity_coherent',
    label: 'Identité cohérente sur toutes les sources',
    detect: (i, fired) => {
      const nav = i.client?.navigator;
      const ua = i.userAgent ?? '';
      if (!nav || !ua || !nav.platform || (nav.languages?.length ?? 0) === 0) return null;
      if (!platformMatchesUa(nav.platform, ua)) return null;
      if (IDENTITY_BOT_SIGNALS.some((id) => fired.has(id))) return null;
      return ['plateforme, moteur, langues et client-hints tous concordants'];
    },
  },
  {
    id: 'trust_hardware_gpu',
    label: 'GPU matériel réel',
    detect: (i) => {
      const g = i.client?.webgl;
      const r = g?.unmaskedRenderer ?? g?.renderer ?? '';
      return r && !SOFTWARE_GPU.test(r) ? [`GPU matériel : ${r}`] : null;
    },
  },
  {
    id: 'trust_hw_video_decode',
    label: 'Décodage vidéo accéléré',
    detect: (i) => {
      const m = i.client?.mediaCapabilities;
      if (!m || !m.available) return null;
      const anyHw = Object.values(m.video).some((v) => v.supported && v.powerEfficient);
      return anyHw ? ['au moins un profil vidéo en décodage matériel'] : null;
    },
  },
  {
    id: 'trust_fonts_rich',
    label: 'Bibliothèque de polices riche',
    detect: (i) => {
      const f = i.client?.fonts;
      if (!f) return null;
      if (f.detectionMethod === 'queryLocalFonts' && f.detectedFonts.length > 0) {
        return [`${f.detectedFonts.length} polices via queryLocalFonts`];
      }
      if (f.detectionMethod === 'measurement' && f.detectedFonts.length > 10) {
        return [`${f.detectedFonts.length} polices détectées`];
      }
      return null;
    },
  },
  {
    id: 'trust_speech_voices',
    label: 'Voix de synthèse présentes',
    detect: (i) => {
      const sp = i.client?.speech;
      return sp?.available && sp.voiceCount > 0 ? [`${sp.voiceCount} voix de synthèse`] : null;
    },
  },
  {
    id: 'trust_residential_ip',
    label: 'IP résidentielle',
    detect: (i) => {
      const ip = i.ip;
      if (!ip) return null;
      return !ip.isDatacenter && !ip.isProxyHint && !ip.isTorExit ? ['IP résidentielle (ni datacenter, ni VPN, ni Tor)'] : null;
    },
  },
  {
    id: 'trust_media_devices',
    label: 'Périphériques média présents',
    detect: (i) => {
      const md = i.client?.mediaDevices;
      if (!md || !md.available) return null;
      const total = md.audioInputCount + md.audioOutputCount + md.videoInputCount;
      return total > 0 ? [`${total} périphérique(s) média`] : null;
    },
  },
];

export interface TrustResult {
  score: number; // 0..1
  signals: TrustHit[];
  liveness: boolean; // a liveness (behavioural) signal fired
}

export function computeTrust(
  input: DecisionInput,
  cfg: TrustConfig,
  firedBotSignals: ReadonlySet<string>,
): TrustResult {
  const signals: TrustHit[] = [];
  let liveness = false;
  for (const def of TRUST_SIGNALS) {
    const evidence = def.detect(input, firedBotSignals);
    if (!evidence) continue;
    const weight = cfg.weights[def.id] ?? 0;
    signals.push({ id: def.id, label: def.label, weight, evidence });
    if (def.liveness) liveness = true;
  }
  const score = Math.min(1, signals.reduce((sum, s) => sum + s.weight, 0));
  return { score, signals, liveness };
}
