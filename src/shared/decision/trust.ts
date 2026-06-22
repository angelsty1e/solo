/*
 * Copyright 2026 angelsty1e
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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
    clientForgeable: true, // behavioural metrics come from the JS payload
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
    clientForgeable: true, // navigator/UA/client-hints are all JS-supplied
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
    clientForgeable: true, // WebGL renderer string is JS-readable/spoofable
    detect: (i) => {
      const g = i.client?.webgl;
      const r = g?.unmaskedRenderer ?? g?.renderer ?? '';
      return r && !SOFTWARE_GPU.test(r) ? [`GPU matériel : ${r}`] : null;
    },
  },
  {
    id: 'trust_hw_video_decode',
    label: 'Décodage vidéo accéléré',
    clientForgeable: true, // mediaCapabilities is reported by client JS
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
    clientForgeable: true, // font list is enumerated/reported by client JS
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
    clientForgeable: true, // speechSynthesis voices come from client JS
    detect: (i) => {
      const sp = i.client?.speech;
      return sp?.available && sp.voiceCount > 0 ? [`${sp.voiceCount} voix de synthèse`] : null;
    },
  },
  {
    id: 'trust_residential_ip',
    label: 'IP résidentielle',
    // NOT forgeable: derived server-side from the observed IP / GeoIP, never
    // from the JS payload. This is the one credit a bot can't fabricate, so it
    // is exempt from the forgeable-offset cap.
    detect: (i) => {
      const ip = i.ip;
      if (!ip) return null;
      // Require GeoIP to POSITIVELY say not-datacenter AND not-proxy (strict
      // === false): a null there means GeoIP is down / the ASN is unresolved, and
      // truthiness (`!ip.isProxyHint`) would then credit an unknown IP as
      // residential — handing a bot the one non-forgeable trust slice it can't
      // otherwise fake. The Tor list is OPTIONAL, so isTorExit===null just means
      // "no list loaded"; only a POSITIVE Tor exit (===true) disqualifies — a
      // missing list must not silently void every residential credit.
      return ip.isDatacenter === false && ip.isProxyHint === false && ip.isTorExit !== true
        ? ['IP résidentielle (ni datacenter, ni VPN, ni Tor)']
        : null;
    },
  },
  {
    id: 'trust_media_devices',
    label: 'Périphériques média présents',
    clientForgeable: true, // enumerateDevices counts come from client JS
    detect: (i) => {
      const md = i.client?.mediaDevices;
      if (!md || !md.available) return null;
      const total = md.audioInputCount + md.audioOutputCount + md.videoInputCount;
      return total > 0 ? [`${total} périphérique(s) média`] : null;
    },
  },
];

export interface TrustResult {
  score: number; // 0..1 — full credit, used for the positive 'human' label
  offsetScore: number; // 0..1 — credit allowed to cancel suspicion (forgeable-capped)
  signals: TrustHit[];
  liveness: boolean; // a liveness (behavioural) signal fired
  // At least one trust signal OTHER than the liveness anchor fired. The liveness
  // anchor (organic behaviour) is itself client-forgeable — a bot can put any
  // numbers in the JSON payload — so on its own it must NOT mint the positive
  // 'human' label. Requiring an independent corroborating signal is a first
  // floor, but every such signal except residential-IP is ALSO client-forgeable.
  // See `serverCorroborated`.
  corroborated: boolean;
  // At least one trust signal that the client CANNOT forge fired — concretely
  // `trust_residential_ip`, derived server-side from the observed IP/GeoIP. This
  // is the real anchor for the positive 'human' label: without it, every credit
  // that earned the label (organic behaviour, real GPU, coherent identity…) is
  // replicable byte-for-byte by a bot posting a scripted payload, so a lone
  // datacenter/proxy/Tor origin could otherwise mint 'human' off pure forgery.
  // 'human' requires this; an uncorroborated-by-the-server credit caps at 'clean'
  // (NOT 'bot' — a VPN is not proof of *non*-humanity either). See runDecision.
  serverCorroborated: boolean;
  // [F1] At least one CLIENT-FORGEABLE, non-liveness trust signal corroborated
  // (real-GPU string, rich fonts, coherent identity, voices, media devices, hw
  // video). The lone server anchor for 'human' today is `trust_residential_ip`,
  // but that fires for a BOT too: a commercial residential proxy (Bright Data /
  // Oxylabs…) or a compromised host egresses on an ordinary ISP ASN that GeoIP
  // reads as "not datacenter / not proxy". So a fully-forged client (organic-
  // looking behaviour + a forged GPU/fonts/identity stack) on such an IP would
  // otherwise mint the positive 'human' vouch off a residential IP that proves
  // nothing. When residential IP is the SOLE server corroboration AND the rest of
  // the non-liveness corroboration is this forgeable stack, the engine caps at
  // 'clean': "nothing against you", but no positive vouch of humanity. The genuine
  // minimal organic human (liveness + residential, no forged passive stack) keeps
  // 'human' — its corroboration rests on the server anchor itself, not on forgeable
  // padding. 'clean' (not 'suspect'/'bot'): a residential IP is no proof of
  // *non*-humanity either, so this must never penalise. See runDecision.
  forgeableCorroborated: boolean;
  // [F1] At least one NON-forgeable trust signal OTHER than `trust_residential_ip`
  // corroborated. Today no such signal exists — residential IP is the lone
  // server-derived credit — so this is currently ALWAYS false. It exists so the
  // engine expresses its intent self-documentingly: 'human' off a forgeable stack
  // is refused only WHILE residential IP is the SOLE server anchor. The day a
  // second, stronger server-side trust signal is added (e.g. an attested device),
  // this turns true and legitimately re-opens 'human' for a forgeable-corroborated
  // client — no engine change needed.
  serverCorroboratedBeyondResidentialIp: boolean;
}

export function computeTrust(
  input: DecisionInput,
  cfg: TrustConfig,
  firedBotSignals: ReadonlySet<string>,
): TrustResult {
  const signals: TrustHit[] = [];
  let liveness = false;
  let corroborated = false;
  let serverCorroborated = false;
  let forgeableCorroborated = false; // [F1] a forgeable, non-liveness signal fired
  let serverCorroboratedBeyondResidentialIp = false; // [F1] a server signal ≠ residential IP
  // Sum forgeable and non-forgeable credit separately: the full sum earns the
  // positive 'human' label, but only a capped slice of the *forgeable* part may
  // offset server-side suspicion (a bot can replicate the whole client payload).
  let forgeableSum = 0;
  let trustedSum = 0;
  for (const def of TRUST_SIGNALS) {
    const evidence = def.detect(input, firedBotSignals);
    if (!evidence) continue;
    const weight = cfg.weights[def.id] ?? 0;
    signals.push({ id: def.id, label: def.label, weight, evidence });
    if (def.liveness) liveness = true;
    else {
      corroborated = true; // an independent (non-liveness) signal fired
      // [F1] track whether that independent corroboration is itself forgeable: a
      // forged client can stack GPU/fonts/identity/voices around a residential IP.
      if (def.clientForgeable) forgeableCorroborated = true;
    }
    if (def.clientForgeable) forgeableSum += weight;
    else {
      trustedSum += weight;
      serverCorroborated = true; // a non-forgeable (server-derived) signal fired
      // [F1] residential IP is the lone server anchor today; any OTHER server
      // signal would be a stronger corroboration that re-opens 'human'.
      if (def.id !== 'trust_residential_ip') serverCorroboratedBeyondResidentialIp = true;
    }
  }
  const score = Math.min(1, forgeableSum + trustedSum);
  const offsetScore = Math.min(1, trustedSum + Math.min(forgeableSum, cfg.maxForgeableOffset));
  return {
    score,
    offsetScore,
    signals,
    liveness,
    corroborated,
    serverCorroborated,
    forgeableCorroborated,
    serverCorroboratedBeyondResidentialIp,
  };
}
