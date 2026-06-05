import type { SignalDef } from './types.js';
import { classifyTls, matchToolSignature } from './tls-signatures.js';
import { LEVEL3 } from './environment.js';
import { LEVEL4 } from './behavior.js';
import {
  isGenuineChromeUa,
  isRealBrowserUa,
  isChromiumUa,
  baseLang,
  parseSecChUaBrands,
  normalizedBrandSet,
} from './detection.js';

// ─── Signal catalogue ───────────────────────────────────────────────────────
// One entry per indicator. Each `detect` reads the snapshot and returns the
// concrete evidence (so the recap can show *why*), or null when absent.
// Severity (hard vs soft) is NOT decided here — see DecisionConfig.

// ─── Comment ajouter un signal (mode d'emploi) ──────────────────────────────
// 1. Écrire le détecteur : { id, label, level, detect(input) → string[]|null }.
//    Ici pour N1/N2/N5 ; dans environment.ts (N3) ou behavior.ts (N4).
// 2. Déclarer son poids dans config.ts (bloc du niveau) ; l'ajouter à hardSignals
//    seulement s'il doit FORCER 'bot'. validateConfig() avertit si l'id est
//    inconnu ou si la somme des poids d'un niveau dépasse 1 (signal inerte).
// 3. (option) Mapper l'id → carte du récap : LEVEL3_CARD/BEHAVIOR_CARD pour les
//    cartes client, ou la logique dédiée de cards.ts pour N1/N2.
// 4. Ajouter un test dans tests/decision.test.ts.
// Parsing UA/plateforme/marques/GPU : detection.ts (source unique, ne pas dupliquer).

// rDNS patterns of the big hosters — reinforces the datacenter presumption.
const HOSTING_RDNS =
  /amazonaws\.com|compute[.-]|googleusercontent|\.google\.com|azure|cloudapp|\bovh\b|hetzner|digitalocean|linode|vultr|scaleway|contabo|leaseweb|m247/i;

const LEVEL1: SignalDef[] = [
  // ── Aveux durs (preuve forte, un seul suffit) ─────────────────────────────
  {
    id: 'webdriver',
    label: 'navigator.webdriver = true',
    level: 1,
    detect: (i) => (i.automation.webdriver === true ? ['navigator.webdriver === true'] : null),
  },
  {
    id: 'pw_globals',
    label: 'Globales Playwright injectées',
    level: 1,
    detect: (i) => (i.automation.playwrightHints.length > 0 ? i.automation.playwrightHints.slice() : null),
  },
  {
    id: 'cdp_traces',
    label: 'Traces CDP / DevTools',
    level: 1,
    detect: (i) => (i.automation.cdpHints.length > 0 ? i.automation.cdpHints.slice() : null),
  },
  {
    id: 'selenium',
    label: 'Globales Selenium',
    level: 1,
    detect: (i) => (i.automation.selenium ? ['window._selenium / document.__selenium_unwrapped'] : null),
  },
  {
    id: 'phantom',
    label: 'PhantomJS (callPhantom)',
    level: 1,
    detect: (i) => (i.automation.callPhantom ? ['window.callPhantom'] : null),
  },
  {
    id: 'nightmare',
    label: 'NightmareJS',
    level: 1,
    detect: (i) => (i.automation.nightmare ? ['window.__nightmare'] : null),
  },
  {
    id: 'headless_ua',
    label: 'User-Agent HeadlessChrome',
    level: 1,
    detect: (i) =>
      i.automation.inconsistencies.includes('headless-chrome-ua') ? ['inconsistencies: headless-chrome-ua'] : null,
  },

  // ── Aveux contextuels / désactivables (pondérés, accumulés) ───────────────
  {
    id: 'forged_chrome',
    label: 'chrome.runtime absent sur UA Chrome',
    level: 1,
    detect: (i) => {
      const ua = i.userAgent ?? '';
      if (isGenuineChromeUa(ua) && i.automation.chromeRuntime === false) {
        return ['chrome.runtime indéfini alors que le User-Agent annonce Chrome'];
      }
      return null;
    },
  },
  {
    id: 'zero_plugins',
    label: '0 plugin / mimeType sur UA Chrome',
    level: 1,
    detect: (i) =>
      i.automation.inconsistencies.includes('chrome-ua-zero-plugins')
        ? ['inconsistencies: chrome-ua-zero-plugins']
        : null,
  },
  {
    id: 'notif_no_focus',
    label: 'Notifications refusées sans focus',
    level: 1,
    detect: (i) =>
      i.automation.inconsistencies.includes('notif-denied-no-focus') ? ['inconsistencies: notif-denied-no-focus'] : null,
  },
];

// ─── Niveau 2 — réseau / contexte (côté serveur, non masquable en JS) ─────────
const LEVEL2: SignalDef[] = [
  {
    id: 'tls_ua_mismatch',
    label: 'Pile TLS ≠ User-Agent',
    level: 2,
    detect: (i) => {
      const tls = i.tls;
      const ua = i.userAgent ?? '';
      if (!tls || !isRealBrowserUa(ua)) return null;
      const cls = classifyTls(tls);
      if (cls.browserLike) return null;
      const evidence = [...cls.reasons];
      const tool = matchToolSignature(tls);
      if (tool) evidence.push(`profil reconnu : ${tool}`);
      evidence.push('le User-Agent annonce pourtant un navigateur');
      return evidence;
    },
  },
  {
    id: 'http_inconsistencies',
    label: 'En-têtes HTTP incohérents',
    level: 2,
    detect: (i) => (i.http && i.http.inconsistencies.length > 0 ? i.http.inconsistencies.slice() : null),
  },
  {
    id: 'ip_tor',
    label: 'Sortie Tor',
    level: 2,
    detect: (i) => (i.ip?.isTorExit ? ['IP = nœud de sortie Tor'] : null),
  },
  {
    id: 'ip_datacenter',
    label: 'IP datacenter',
    level: 2,
    detect: (i) => {
      if (!i.ip?.isDatacenter) return null;
      const detail = [i.ip.asn != null ? `AS${i.ip.asn}` : null, i.ip.asnOrganization].filter(Boolean).join(' ');
      return [`ASN hébergeur${detail ? ` : ${detail}` : ''}`];
    },
  },
  {
    id: 'ip_proxy',
    label: 'Indice proxy / VPN',
    level: 2,
    detect: (i) => {
      if (!i.ip?.isProxyHint) return null;
      const detail = [i.ip.asn != null ? `AS${i.ip.asn}` : null, i.ip.asnOrganization].filter(Boolean).join(' ');
      return [`ASN type VPN/proxy${detail ? ` : ${detail}` : ''}`];
    },
  },
  {
    id: 'rdns_hosting',
    label: 'Reverse DNS hébergeur',
    level: 2,
    detect: (i) => {
      const r = i.ip?.reverseDns;
      return r && HOSTING_RDNS.test(r) ? [`rDNS : ${r}`] : null;
    },
  },
  {
    id: 'rtt_incoherence',
    label: 'RTT incompatible avec un mobile distant',
    level: 2,
    detect: (i) => {
      const rtt = i.ip?.tcpRttMs;
      const ua = i.userAgent ?? '';
      if (rtt != null && rtt < 2 && /Mobile|Android|iPhone|iPad/i.test(ua)) {
        return [`RTT ${rtt.toFixed(2)} ms < 2 ms alors que l'UA est mobile (datacenter-adjacent)`];
      }
      return null;
    },
  },

  // ── Cohérence serveur ↔ client : le serveur observe une chose, le JS en ────
  //    déclare une autre. Un vrai navigateur dérive l'en-tête et le JS de la
  //    même source interne → ils concordent ; un client forgé en oublie un.
  {
    id: 'lang_header_js_mismatch',
    label: 'Accept-Language (HTTP) ≠ navigator.languages (JS)',
    level: 2,
    detect: (i) => {
      const header = i.http?.acceptLanguage ?? '';
      const jsLangs = i.client?.navigator?.languages ?? [];
      if (!header || jsLangs.length === 0) return null;
      // Langue primaire de chaque côté (1er token, sans le poids « ;q= »).
      const headerPrimary = header.split(',')[0]?.split(';')[0]?.trim() ?? '';
      const jsPrimary = jsLangs[0] ?? '';
      if (!headerPrimary || !jsPrimary) return null;
      return baseLang(headerPrimary) !== baseLang(jsPrimary)
        ? [`Accept-Language « ${headerPrimary} » vs navigator.languages[0] « ${jsPrimary} »`]
        : null;
    },
  },
  {
    id: 'client_hints_ua_mismatch',
    label: 'Sec-CH-UA (HTTP) ≠ navigator.userAgentData (JS)',
    level: 2,
    detect: (i) => {
      const ua = i.userAgent ?? '';
      if (!isChromiumUa(ua)) return null; // Client Hints = Chromium uniquement
      const header = i.http?.clientHints?.['sec-ch-ua'] ?? '';
      const uaData = i.client?.navigator?.uaData;
      // Absence d'un côté = couvert par env_uadata_incoherent (N3) ; ici on ne
      // juge que la *divergence* entre deux listes toutes deux présentes.
      if (!header || !uaData || (uaData.brands?.length ?? 0) === 0) return null;
      const headerBrands = normalizedBrandSet(parseSecChUaBrands(header));
      const jsBrands = normalizedBrandSet(uaData.brands.map((b) => b.brand));
      if (headerBrands.length === 0 || jsBrands.length === 0) return null;
      return headerBrands.join('|') !== jsBrands.join('|')
        ? [`Sec-CH-UA [${headerBrands.join(', ')}] vs userAgentData [${jsBrands.join(', ')}]`]
        : null;
    },
  },
];

// Level 3 (cohérence d'environnement) lives in environment.ts — its detection is
// a self-contained block of client-side cross-checks, registered here like any
// other level.
// ─── Niveau 5 — réputation (agrégat cross-session, fourni par le serveur) ─────
// ≥ ce nombre d'IP distinctes partageant le MÊME composite canvas+WebGL dans la
// fenêtre de rétention = réutilisation distribuée (clonage de VM / ferme). On
// compte des IP *distinctes* (pas les sessions) → immunisé au re-scan d'un même
// utilisateur depuis une seule IP.
const REP_MANY_IPS_MIN = 4;
const REP_SWARM_MIN = 10;

const LEVEL5: SignalDef[] = [
  {
    id: 'rep_fp_many_ips',
    label: 'Empreinte réutilisée sur plusieurs IP',
    level: 5,
    detect: (i) => {
      const rep = i.reputation;
      if (!rep) return null;
      return rep.fpDistinctIps >= REP_MANY_IPS_MIN
        ? [`même empreinte canvas+WebGL vue depuis ${rep.fpDistinctIps} IP distinctes (fenêtre ~1 h)`]
        : null;
    },
  },
  {
    // Escalade INTRA-niveau (le niveau 5 somme ses signaux) : une réutilisation
    // massive ajoute son poids au précédent → bascule 'bot' à elle seule, sans
    // dépendre de l'agrégat inter-niveaux (qui, lui, prend le max).
    id: 'rep_fp_swarm',
    label: 'Empreinte en essaim (réutilisation massive)',
    level: 5,
    detect: (i) => {
      const rep = i.reputation;
      if (!rep) return null;
      return rep.fpDistinctIps >= REP_SWARM_MIN
        ? [`réutilisation massive : ${rep.fpDistinctIps} IP distinctes sur la même empreinte`]
        : null;
    },
  },
];

const BY_LEVEL = new Map<number, SignalDef[]>([
  [1, LEVEL1],
  [2, LEVEL2],
  [3, LEVEL3],
  [4, LEVEL4],
  [5, LEVEL5],
]);

export function signalsForLevel(level: number): SignalDef[] {
  return BY_LEVEL.get(level) ?? [];
}

// Convenience for tests / introspection.
export const ALL_SIGNALS: SignalDef[] = [...LEVEL1, ...LEVEL2, ...LEVEL3, ...LEVEL4, ...LEVEL5];
