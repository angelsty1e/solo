import type { SignalDef } from './types.js';
import { SOFTWARE_GPU, uaOs, uaBrowser, isMobileUa, isChromium, expectedEngine, platformMatchesOs } from './detection.js';

// ─── Level 3 — cohérence d'environnement ─────────────────────────────────────
// Source : collecteurs navigateur. La logique de ce niveau n'est PAS « la valeur
// est mauvaise » mais « les valeurs se contredisent ». Un environnement réel est
// cohérent de bout en bout (OS ↔ platform ↔ moteur ↔ GPU ↔ périphériques ↔
// locale) ; un navigateur forgé ou headless laisse des contradictions.
//
// Conséquence sur la sévérité : aucune incohérence n'est un *aveu* (≠ niveau 1).
// Une contradiction isolée peut avoir une explication légitime (VPN, voyageur,
// extension de confidentialité, VM utilisée par un humain). Tous les signaux
// sont donc *soft* — ils s'accumulent vers les seuils (voir config.ts). La force
// vient du faisceau : deux contradictions fortes suffisent à basculer « bot ».

// Tailles de fenêtre par défaut des navigateurs pilotés (Puppeteer/Playwright).
// Volontairement restreint aux valeurs « headless » classiques pour éviter les
// faux positifs avec de vraies résolutions courantes (1024×768, 1280×1024…).
const HEADLESS_DIMS = new Set(['800x600', '1280x720']);

// UA / platform / engine / GPU helpers live in detection.ts (single source).

export const LEVEL3: SignalDef[] = [
  // ── navigator : identité déclarée cohérente ? ─────────────────────────────
  {
    id: 'env_platform_os_mismatch',
    label: 'OS du User-Agent ≠ navigator.platform',
    level: 3,
    detect: (i) => {
      const nav = i.client?.navigator;
      const ua = i.userAgent ?? '';
      if (!nav || !ua) return null;
      const os = uaOs(ua);
      const plat = nav.platform;
      if (!os || !plat) return null;
      return platformMatchesOs(plat, os) ? null : [`UA annonce ${os}, navigator.platform = "${plat}"`];
    },
  },
  {
    id: 'env_languages_empty',
    label: 'navigator.languages vide',
    level: 3,
    detect: (i) => {
      const nav = i.client?.navigator;
      if (!nav) return null;
      return (nav.languages?.length ?? 0) === 0 ? ['navigator.languages = [] (un vrai navigateur en a toujours ≥ 1)'] : null;
    },
  },
  {
    id: 'env_uadata_incoherent',
    label: 'userAgentData incohérent avec le User-Agent',
    level: 3,
    detect: (i) => {
      const nav = i.client?.navigator;
      const ua = i.userAgent ?? '';
      if (!nav || !ua) return null;
      // Client Hints n'existent que sur Chromium desktop ; ne juger que là.
      if (!isChromium(uaBrowser(ua)) || isMobileUa(ua)) return null;
      const uaData = nav.uaData;
      if (uaData === null) return ['UA Chromium desktop mais navigator.userAgentData absent'];
      if ((uaData.brands?.length ?? 0) === 0) return ['userAgentData.brands vide sur UA Chromium'];
      return null;
    },
  },

  // ── canvas / webgl / audio : surfaces de rendu ────────────────────────────
  {
    id: 'env_software_gpu',
    label: 'GPU logiciel (rendu headless / VM)',
    level: 3,
    detect: (i) => {
      const g = i.client?.webgl;
      if (!g) return null;
      const r = g.unmaskedRenderer ?? g.renderer ?? '';
      return r && SOFTWARE_GPU.test(r) ? [`webgl.unmaskedRenderer = "${r}"`] : null;
    },
  },
  {
    id: 'env_render_surfaces_absent',
    label: 'Canvas, WebGL et audio tous absents',
    level: 3,
    detect: (i) => {
      const c = i.client;
      if (!c) return null;
      // Chacun peut être bloqué isolément (extension vie privée) ; les trois
      // simultanément indisponibles est le profil d'un environnement nu.
      return c.canvas === null && c.webgl === null && c.audio === null
        ? ['canvas + webgl + audio simultanément indisponibles']
        : null;
    },
  },

  // ── fonts : environnement nu ──────────────────────────────────────────────
  {
    id: 'env_fonts_minimal',
    label: 'Très peu de polices détectées',
    level: 3,
    detect: (i) => {
      const f = i.client?.fonts;
      if (!f || f.detectionMethod !== 'measurement') return null;
      return f.detectedFonts.length <= 2 ? [`${f.detectedFonts.length} police(s) détectée(s) par mesure`] : null;
    },
  },

  // ── codecs / mediaCapabilities : accélération matérielle ──────────────────
  {
    id: 'env_no_hw_video_decode',
    label: 'Aucun décodage vidéo accéléré',
    level: 3,
    detect: (i) => {
      const m = i.client?.mediaCapabilities;
      if (!m || !m.available) return null;
      const entries = Object.values(m.video);
      if (entries.length === 0) return null;
      const anyHw = entries.some((v) => v.supported && v.powerEfficient);
      return anyHw ? null : ['aucun profil vidéo « powerEfficient » (pas d’accélération matérielle = VM probable)'];
    },
  },

  // ── speech : voix de synthèse ─────────────────────────────────────────────
  {
    id: 'env_speech_no_voices',
    label: 'Aucune voix de synthèse',
    level: 3,
    detect: (i) => {
      const sp = i.client?.speech;
      const ua = i.userAgent ?? '';
      if (!sp || !sp.available || isMobileUa(ua)) return null;
      return sp.voiceCount === 0 ? ['speechSynthesis sans voix sur un OS desktop'] : null;
    },
  },

  // ── mediaDevices : périphériques ──────────────────────────────────────────
  {
    id: 'env_no_media_devices',
    label: 'Aucun périphérique média',
    level: 3,
    detect: (i) => {
      const ua = i.userAgent ?? '';
      // Safari renvoie parfois 0 périphérique tant que getUserMedia n'a pas été
      // accordé (et n'énumère jamais audiooutput) → on ne juge que sur Chromium
      // desktop, où enumerateDevices liste les périphériques avant permission.
      if (!isChromium(uaBrowser(ua)) || isMobileUa(ua)) return null;
      const md = i.client?.mediaDevices;
      if (!md || !md.available) return null;
      const total = md.audioInputCount + md.audioOutputCount + md.videoInputCount;
      return total === 0 ? ['0 micro / caméra / sortie audio (serveur sans périphérique)'] : null;
    },
  },

  // ── webgpu : adaptateur moderne ───────────────────────────────────────────
  {
    id: 'env_webgpu_absent',
    label: 'WebGPU absent sur Chrome/Edge récent',
    level: 3,
    detect: (i) => {
      const ua = i.userAgent ?? '';
      const b = uaBrowser(ua);
      if ((b !== 'chrome' && b !== 'edge') || isMobileUa(ua)) return null;
      const gpu = i.client?.webgpu;
      // null = non collecté (on ne tranche pas) ; available === false = absent.
      return gpu && gpu.available === false ? ['navigator.gpu indisponible sur Chrome/Edge desktop'] : null;
    },
  },

  // ── screen / fenêtre : dimensions par défaut ──────────────────────────────
  {
    id: 'env_screen_default_dims',
    label: 'Résolution par défaut typique headless',
    level: 3,
    detect: (i) => {
      const s = i.client?.screen;
      if (!s) return null;
      const key = `${s.width}x${s.height}`;
      return HEADLESS_DIMS.has(key) && s.devicePixelRatio === 1 ? [`écran ${key} @ devicePixelRatio 1`] : null;
    },
  },

  // ── permissions : combinaisons improbables ────────────────────────────────
  {
    id: 'env_permissions_all_denied',
    label: 'Toutes les permissions refusées',
    level: 3,
    detect: (i) => {
      const p = i.client?.permissions;
      if (!p) return null;
      const vals = Object.values(p.states);
      return vals.length >= 3 && vals.every((v) => v === 'denied')
        ? [`${vals.length} permissions toutes « denied »`]
        : null;
    },
  },

  // ── locale / intl : cohérence géographique ────────────────────────────────
  {
    id: 'env_locale_ip_mismatch',
    label: 'Locale incohérente avec le pays IP',
    level: 3,
    detect: (i) => {
      const loc = i.client?.locale;
      const country = i.ip?.country;
      if (!loc || !country) return null;
      const region = loc.resolvedOptionsLocale.split('-')[1]?.toUpperCase();
      return region && region !== country.toUpperCase()
        ? [`locale ${loc.resolvedOptionsLocale} vs pays IP ${country} (VPN/voyageur possible)`]
        : null;
    },
  },

  // ── engine : moteur JS réel ↔ UA annoncé ──────────────────────────────────
  {
    id: 'env_engine_ua_mismatch',
    label: 'Moteur JS ≠ celui annoncé par le User-Agent',
    level: 3,
    detect: (i) => {
      const e = i.client?.engine;
      const ua = i.userAgent ?? '';
      if (!e || !ua || e.detectedEngine === 'unknown') return null;
      const exp = expectedEngine(uaBrowser(ua));
      if (!exp) return null;
      // SpiderMonkey (Firefox) et JavaScriptCore (Safari) produisent le MÊME
      // format de stack `fn@url:ligne:col` : on ne peut pas les distinguer de
      // façon fiable. On ne juge donc que la frontière nette V8 ↔ non-V8 — la
      // seule contradiction prouvable (ex. un UA Safari qui tourne sous V8 =
      // Chrome headless déguisé). Sinon on n'inculpe pas Safari à tort.
      const detIsV8 = e.detectedEngine === 'v8';
      const expIsV8 = exp === 'v8';
      return detIsV8 !== expIsV8
        ? [`moteur ${detIsV8 ? 'V8' : 'non-V8'} détecté, incompatible avec l'UA (${exp} attendu)`]
        : null;
    },
  },

  // ── webrtc : IP locales ───────────────────────────────────────────────────
  {
    id: 'env_webrtc_no_local_ip',
    label: 'WebRTC sans IP locale',
    level: 3,
    detect: (i) => {
      const w = i.client?.webrtc;
      if (!w || w.error) return null; // erreur = bloqué → inconcluant, pas suspect
      // Les navigateurs modernes (Chrome, Safari) masquent l'IP locale derrière
      // un hostname mDNS « <uuid>.local » : le candidat `typ host` existe mais
      // sans IP numérique, donc localIps est vide alors que WebRTC fonctionne.
      // On ne s'alarme que si AUCUN candidat host n'est émis (environnement nu).
      const hasHostCandidate = w.candidates.some((c) => /typ host/.test(c));
      return !hasHostCandidate && w.localIps.length === 0
        ? ['aucun candidat WebRTC host (ni IP ni hostname mDNS)']
        : null;
    },
  },

  // ── storage / perfMemory / network : profil ressources VM ─────────────────
  {
    id: 'env_vm_resource_profile',
    label: 'APIs ressources toutes indisponibles (profil VM)',
    level: 3,
    detect: (i) => {
      const c = i.client;
      const ua = i.userAgent ?? '';
      // Ces trois APIs sont propres à Chromium ; ailleurs leur absence est normale.
      if (!c || !isChromium(uaBrowser(ua)) || isMobileUa(ua)) return null;
      const storageOff = c.storage ? c.storage.available === false : false;
      const memOff = c.perfMemory ? c.perfMemory.available === false : false;
      const netOff = c.network ? c.network.available === false : false;
      return storageOff && memOff && netOff
        ? ['StorageManager + performance.memory + NetworkInformation tous absents sur Chromium']
        : null;
    },
  },
];

// Mappe chaque signal niveau 3 vers la carte du récap qu'il concerne, pour
// allumer la pastille de la bonne section (voir cards.ts).
export const LEVEL3_CARD: Record<string, string> = {
  env_platform_os_mismatch: 'navigator',
  env_languages_empty: 'navigator',
  env_uadata_incoherent: 'navigator',
  env_software_gpu: 'hardware',
  env_render_surfaces_absent: 'hardware',
  env_fonts_minimal: 'fonts',
  env_no_hw_video_decode: 'mediaCapabilities',
  env_speech_no_voices: 'speech',
  env_no_media_devices: 'mediaDevices',
  env_webgpu_absent: 'webgpu',
  env_screen_default_dims: 'screen',
  env_permissions_all_denied: 'permissions',
  env_locale_ip_mismatch: 'locale',
  env_engine_ua_mismatch: 'engine',
  env_webrtc_no_local_ip: 'webrtc',
  env_vm_resource_profile: 'storage',
};
