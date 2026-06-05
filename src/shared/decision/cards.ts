import type { FullFingerprint } from '../types.js';
import type { CardTone, CardVerdict, DecisionResult } from './types.js';
import { LEVEL3_CARD } from './environment.js';
import { SOFTWARE_GPU, platformMatchesUa } from './detection.js';

// ─── Per-card tri-state ─────────────────────────────────────────────────────
// Each card the recap shows gets a 🔴 bot / 🟢 human / 🟠 unknown light.
// Rules only colour a card 'human' when the data positively corroborates a real
// browser; everything inconclusive (and every pure-identifier card) stays
// 'unknown'. Cards not listed here default to 'unknown' in the UI.

function card(id: string, tone: CardTone, reason: string): CardVerdict {
  return { id, tone, reason };
}

// SOFTWARE_GPU and platformMatchesUa now come from detection.ts (single source).

export function evaluateCards(full: FullFingerprint, decision: DecisionResult): CardVerdict[] {
  const out: CardVerdict[] = [];
  const au = full.client.automation;
  const ip = full.server.ip;
  const http = full.server.http;
  const webgl = full.client.webgl;
  const ua = full.client.navigator?.userAgent ?? http?.userAgent ?? '';

  // Single source of truth: server-side cards derive from the engine's hits.
  const allHits = decision.byLevel.flatMap((l) => l.hits);
  const hit = (id: string) => allHits.find((h) => h.id === id);

  // ── Automation — mirrors the level-1 verdict (browser-agnostic) ───────────
  // Driven by the L1 *verdict*, not the raw hit count: a tiny noisy soft signal
  // (e.g. chrome.runtime absent, weight 0.15) keeps L1 'clean', so a real user
  // on Safari/Firefox/Chrome still goes green. No chrome.runtime requirement.
  const l1 = decision.byLevel.find((l) => l.level === 1);
  if (l1?.forced) {
    const tells = l1.hits.filter((h) => h.severity === 'hard').map((h) => h.label);
    out.push(card('automation', 'bot', `Aveu direct : ${tells.join(', ')}`));
  } else if (l1?.verdict === 'bot') {
    // Soft signals can accumulate to the block threshold without a hard override
    // (forced=false). The card must follow the *verdict*, not just `forced`: a
    // level that scored 'bot' is red, never the orange 'unknown' below.
    const tells = l1.hits.map((h) => h.label);
    out.push(card('automation', 'bot', `Accumulation de signaux d'automatisation : ${tells.join(', ')}.`));
  } else if (l1 && l1.verdict !== 'clean') {
    const tells = l1.hits.map((h) => h.label);
    out.push(card('automation', 'unknown', `Signaux faibles : ${tells.join(', ')}.`));
  } else if (au.webdriver === false) {
    out.push(card('automation', 'human', "Aucun marqueur d'automatisation (navigator.webdriver = false)."));
  } else {
    out.push(card('automation', 'unknown', 'navigator.webdriver indéterminé.'));
  }

  // ── TLS — la pile TLS trahit-elle le User-Agent ? (niveau 2) ──────────────
  if (full.server.tls) {
    const mismatch = hit('tls_ua_mismatch');
    if (mismatch) out.push(card('tls', 'bot', `Pile TLS ≠ UA : ${mismatch.evidence.join(' ; ')}`));
    else out.push(card('tls', 'human', 'Pile TLS cohérente avec un vrai navigateur (ALPN h2, ciphers attendus).'));
  }

  // ── HTTP — en-têtes forgés (niveau 2) ─────────────────────────────────────
  if (http) {
    const incon = hit('http_inconsistencies');
    if (incon) out.push(card('http', 'bot', `En-têtes incohérents : ${incon.evidence.join(', ')}`));
    else if (http.userAgent) out.push(card('http', 'human', 'En-têtes cohérents, ordre et Sec-* attendus.'));
    else out.push(card('http', 'unknown', 'Pas assez de signal HTTP.'));
  }

  // ── IP — provenance réseau (niveau 2) ─────────────────────────────────────
  if (ip) {
    const tor = hit('ip_tor');
    const dc = hit('ip_datacenter') ?? hit('ip_proxy') ?? hit('rdns_hosting');
    // Positively residential = GeoIP confirms not-datacenter & not-proxy; a
    // missing Tor list (isTorExit===null) is fine, only a real Tor exit isn't.
    const positivelyResidential = ip.isDatacenter === false && ip.isProxyHint === false && ip.isTorExit !== true;
    if (tor) out.push(card('ip', 'bot', 'Nœud de sortie Tor.'));
    else if (dc) out.push(card('ip', 'unknown', dc.evidence.join(' ; ')));
    else if (positivelyResidential) out.push(card('ip', 'human', 'IP résidentielle probable.'));
    // Provenance unresolved (GeoIP down / ASN not found): no signal fired but we
    // can't positively call it residential either → stay 'unknown', don't fake green.
    else out.push(card('ip', 'unknown', 'Provenance réseau indéterminée (enrichissement IP indisponible).'));
  }

  // ── Matériel / WebGL — GPU logiciel = headless ────────────────────────────
  const renderer = webgl?.unmaskedRenderer ?? webgl?.renderer ?? '';
  if (renderer) {
    if (SOFTWARE_GPU.test(renderer)) {
      const hw = card('hardware', 'bot', `GPU logiciel (${renderer}) — typique d'un environnement headless.`);
      out.push(hw, { ...hw, id: 'webgl' });
    } else {
      const hw = card('hardware', 'human', `GPU matériel détecté (${renderer}).`);
      out.push(hw, { ...hw, id: 'webgl' });
    }
  }

  // ── Locale — cohérence locale ↔ IP ────────────────────────────────────────
  // Vert dès qu'il n'y a pas de contradiction (région absente ou pays IP non
  // résolu → pas de contradiction possible). Orange seulement sur un vrai écart
  // région ↔ pays (VPN/voyageur).
  const locale = full.client.locale?.resolvedOptionsLocale ?? '';
  if (locale) {
    const country = ip?.country ?? '';
    const localeRegion = locale.split('-')[1]?.toUpperCase();
    if (country && localeRegion && localeRegion !== country.toUpperCase()) {
      out.push(card('locale', 'unknown', `Locale (${locale}) ≠ pays IP (${country}) — VPN ou voyageur possible.`));
    } else {
      out.push(card('locale', 'human', `Locale ${locale} déclarée, sans contradiction avec l'IP.`));
    }
  }

  // ── Navigator — identité déclarée : forgerie (N2) puis cohérence plateforme ─
  const nav = full.client.navigator;
  const plat = nav?.platform ?? '';
  const langs = nav?.languages ?? [];
  // Mensonge serveur↔client sur l'identité (langue ou client hints) = forgerie.
  const idForgery = hit('client_hints_ua_mismatch') ?? hit('lang_header_js_mismatch');
  if (au.webdriver === true) {
    out.push(card('navigator', 'bot', 'navigator.webdriver = true.'));
  } else if (idForgery) {
    out.push(card('navigator', 'bot', `Identité forgée — ${idForgery.evidence.join(' ; ')}`));
  } else if (plat && ua && platformMatchesUa(plat, ua) && langs.length > 0) {
    out.push(card('navigator', 'human', `Plateforme (${plat}) cohérente avec l'UA, langues déclarées.`));
  } else if (plat && ua && !platformMatchesUa(plat, ua)) {
    out.push(card('navigator', 'unknown', `Plateforme (${plat}) incohérente avec l'UA.`));
  }

  // ── Niveau 3 — cohérence d'environnement ──────────────────────────────────
  // Allume la pastille « robot » de chaque dimension dont une contradiction a
  // été relevée. Appended last → écrase un éventuel verdict 'unknown'/'human'
  // antérieur sur la même carte (une contradiction l'emporte sur l'absence de
  // tell). On saute les signaux déjà couverts plus haut avec une nuance propre
  // (GPU logiciel → hardware/webgl ; locale ↔ IP → 'unknown' car VPN/voyageur).
  const SKIP_L3 = new Set(['env_software_gpu', 'env_locale_ip_mismatch']);
  const l3ByCard = new Map<string, string[]>();
  for (const h of decision.byLevel.find((l) => l.level === 3)?.hits ?? []) {
    const cardId = LEVEL3_CARD[h.id];
    if (!cardId || SKIP_L3.has(h.id)) continue;
    const labels = l3ByCard.get(cardId) ?? [];
    labels.push(h.label);
    l3ByCard.set(cardId, labels);
  }
  for (const [cardId, labels] of l3ByCard) {
    out.push(card(cardId, 'bot', `Incohérence d'environnement : ${labels.join(' ; ')}.`));
  }

  // ── Niveau 4 — comportement ───────────────────────────────────────────────
  // Tous les signaux comportementaux pointent vers la carte « behavioral ».
  const l4hits = decision.byLevel.find((l) => l.level === 4)?.hits ?? [];
  if (l4hits.length > 0) {
    out.push(card('behavioral', 'bot', `Comportement synthétique : ${l4hits.map((h) => h.label).join(' ; ')}.`));
  }

  return out;
}
