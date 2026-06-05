import type { FullFingerprint } from '../shared/types.js';
import type { CardTone, CardVerdict } from '../shared/decision/types.js';
import {
  CIPHER_SUITES,
  TLS_EXTENSIONS,
  SUPPORTED_GROUPS,
  SIGNATURE_SCHEMES,
  EC_POINT_FORMATS,
  labelId,
  formatBytes,
  formatCountry,
  formatTzOffset,
  geoCoherence,
  calendarName,
  numberingSystemName,
  engineFamily,
  languageName,
  humanizeCodecMap,
  dprLabel,
  inferCpu,
} from './registry.js';

function extractId(): string | null {
  const m = window.location.pathname.match(/^\/recap\/([^\/]+)\/?$/);
  return m ? m[1] ?? null : null;
}

function el(tag: string, props: Record<string, unknown> = {}, children: Array<Node | string> = []): HTMLElement {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') node.className = String(v);
    // No `innerHTML` branch: everything renders via children/textContent so a
    // fingerprint value (UA, JA4, renderer, evidence…) can never be parsed as
    // HTML. Removed the dead 'html' prop that was a latent injection foot-gun.
    else node.setAttribute(k, String(v));
  }
  for (const c of children) {
    node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
  }
  return node;
}

function humanBool(v: boolean | null | undefined, yes = 'Oui', no = 'Non', unknown = 'Inconnu'): string {
  if (v === null || v === undefined) return unknown;
  return v ? yes : no;
}

// Row header cell — always `scope="row"` so screen readers announce it as the
// label for the value cell.
function th(label: string): HTMLElement {
  return el('th', { scope: 'row' }, [label]);
}

// Long enumerations (ciphers, extensions, fonts…) rendered as wrapping pills so
// they reflow on narrow screens instead of forcing horizontal scroll.
function wrapList(items: Array<string | number>, empty = 'aucun'): HTMLElement {
  const wrap = el('div', { class: 'list-wrap' });
  if (!items || items.length === 0) {
    wrap.appendChild(el('span', { class: 'empty' }, [empty]));
    return wrap;
  }
  for (const it of items) wrap.appendChild(el('span', { class: 'pill' }, [String(it)]));
  return wrap;
}

// A flat object (all-primitive values) renders as a readable key/value list
// rather than raw JSON; arrays become wrapping pills; nested/complex objects
// fall back to pretty-printed JSON.
function renderValue(value: unknown): Node {
  if (value === null || value === undefined || value === '') {
    return el('span', { class: 'empty' }, ['—']);
  }
  if (Array.isArray(value)) {
    return wrapList(value.map((v) => String(v)));
  }
  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>);
    const allPrimitive = entries.every(([, v]) => v === null || typeof v !== 'object');
    if (entries.length > 0 && allPrimitive) {
      const dl = el('dl', { class: 'kv' });
      for (const [k, v] of entries) {
        dl.appendChild(el('dt', {}, [k]));
        const dd = el('dd');
        if (v === null || v === undefined || v === '') {
          dd.appendChild(el('span', { class: 'empty' }, ['—']));
        } else {
          const code = document.createElement('code');
          code.textContent = String(v);
          dd.appendChild(code);
        }
        dl.appendChild(dd);
      }
      return dl;
    }
    const pre = el('pre');
    pre.textContent = JSON.stringify(value, null, 2);
    return pre;
  }
  const code = document.createElement('code');
  code.textContent = String(value);
  return code;
}

function row(label: string, value: unknown): HTMLTableRowElement {
  const td = document.createElement('td');
  td.appendChild(renderValue(value));
  const tr = document.createElement('tr');
  tr.appendChild(th(label));
  tr.appendChild(td);
  return tr;
}

// Per-card tri-state lookup, populated from the persisted decision. Cards with
// no explicit verdict default to 'unknown' (🟠) — they don't tell bot/human.
let CARD_VERDICTS = new Map<string, CardVerdict>();

const TONE_LABEL: Record<CardTone, string> = {
  bot: 'Signal robot',
  human: 'Cohérent humain',
  unknown: 'Indéterminé',
};

// Shape/symbol carried by each dot so the verdict is distinguishable WITHOUT
// relying on colour alone (red/green are indistinguishable for ~8% of men).
const TONE_SYMBOL: Record<CardTone, string> = {
  bot: '✗',
  human: '✓',
  unknown: '?',
};

// Traffic light — ONLY for cards that participate in the bot/human decision
// (those passed a cardId). A card with no verdict yet is "surveillée, RAS",
// not "suspect": orange here means a rule watches it but found nothing.
function cardDot(id: string): HTMLElement {
  const v = CARD_VERDICTS.get(id);
  const tone: CardTone = v?.tone ?? 'unknown';
  const reason = v?.reason ?? 'Surveillée — aucune incohérence détectée à ce niveau.';
  const label = v ? TONE_LABEL[tone] : 'Rien à signaler';
  // role=img + aria-label gives the dot an accessible name (not just a title,
  // which is invisible to keyboard/touch and many screen readers).
  return el(
    'span',
    { class: `card-dot ${tone}`, role: 'img', 'aria-label': `${label} — ${reason}`, title: `${label} — ${reason}` },
    [TONE_SYMBOL[tone]],
  );
}

// Identification-only cards (Canvas, Audio, Codec…) carry NO traffic light:
// they fingerprint/track but say nothing about bot vs human. A discreet neutral
// marker makes that explicit instead of a misleading orange dot.
function fingerprintTag(): HTMLElement {
  const text = "Donnée d'identification (pistage) — ne participe pas au verdict bot/humain.";
  return el('span', { class: 'card-fp', 'aria-label': text, title: text }, ['empreinte']);
}

// Visible, colour-independent legend mapping each symbol to its meaning — so the
// dots dotted across the sections are interpretable at a glance without hover.
function legend(): HTMLElement {
  const wrap = el('section', { class: 'legend', 'aria-label': 'Légende des pastilles' });
  const item = (tone: CardTone, text: string): HTMLElement => {
    const i = el('span', { class: 'legend-item' });
    i.appendChild(el('span', { class: `card-dot ${tone}`, 'aria-hidden': 'true' }, [TONE_SYMBOL[tone]]));
    i.appendChild(document.createTextNode(text));
    return i;
  };
  wrap.appendChild(item('human', 'Cohérent humain'));
  wrap.appendChild(item('bot', 'Signal robot'));
  wrap.appendChild(item('unknown', 'Indéterminé'));
  const fp = el('span', { class: 'legend-item' });
  fp.appendChild(el('span', { class: 'card-fp', 'aria-hidden': 'true' }, ['empreinte']));
  fp.appendChild(document.createTextNode('Identification — ne tranche pas'));
  wrap.appendChild(fp);
  return wrap;
}

function toneOf(cardId?: string): CardTone | null {
  if (!cardId) return null;
  return CARD_VERDICTS.get(cardId)?.tone ?? 'unknown';
}

// A section is a collapsible <details>, closed by default to keep the page
// scannable. A section whose dimension carries a robot signal opens itself so
// problems stay visible without a click. Decision cards get a stable id
// (`sec-<cardId>`) so the dashboard chips can deep-link + expand them;
// identification cards are tagged `data-fp` for the « Empreinte » regroup.
function section(
  title: string,
  rows: Array<HTMLTableRowElement>,
  note?: string,
  cardId?: string,
): HTMLElement {
  const details = el('details', { class: 'card', role: 'group', 'aria-label': title }) as HTMLDetailsElement;
  if (cardId) details.id = `sec-${cardId}`;
  else details.dataset.fp = '1';
  if (toneOf(cardId) === 'bot') details.open = true;

  // Decision-relevant cards (cardId set) get the tri-state dot; identification
  // cards get the neutral "empreinte" marker.
  const summary = el('summary', { class: 'card-title' });
  summary.appendChild(cardId ? cardDot(cardId) : fingerprintTag());
  summary.appendChild(document.createTextNode(title));
  details.appendChild(summary);

  if (note) details.appendChild(el('p', { class: 'section-note' }, [note]));
  const table = el('table');
  // Screen-reader caption: gives the data table an accessible name without
  // visually duplicating the summary heading.
  table.appendChild(el('caption', { class: 'sr-only' }, [`Détails — ${title}`]));
  const tbody = document.createElement('tbody');
  for (const r of rows) tbody.appendChild(r);
  table.appendChild(tbody);
  details.appendChild(table);
  return details;
}

// ── Dashboard: one clickable chip per analysed dimension, worst-first ─────────
// Lists only dimensions that actually have a computed verdict (present in the
// persisted decision). Clicking a chip opens and scrolls to its section.
const DIMENSIONS: Array<[string, string]> = [
  ['automation', 'Automation'],
  ['tls', 'TLS'],
  ['http', 'HTTP'],
  ['ip', 'IP'],
  ['navigator', 'Navigator'],
  ['hardware', 'Matériel'],
  ['webgl', 'WebGL'],
  ['locale', 'Locale'],
  ['screen', 'Écran'],
  ['fonts', 'Polices'],
  ['engine', 'Moteur JS'],
  ['webrtc', 'WebRTC'],
  ['permissions', 'Permissions'],
  ['speech', 'Voix'],
  ['mediaDevices', 'Périphériques'],
  ['mediaCapabilities', 'Codecs HW'],
  ['webgpu', 'WebGPU'],
  ['storage', 'Ressources'],
  ['behavioral', 'Comportement'],
];
const TONE_RANK: Record<CardTone, number> = { bot: 0, unknown: 1, human: 2 };

function scoreboard(): HTMLElement {
  const wrap = el('section', { class: 'exposure' });
  wrap.appendChild(el('h2', {}, ['Dimensions']));
  wrap.appendChild(
    el('p', {}, [
      'Une pastille par dimension analysée — clique pour ouvrir le détail. 🔴 signal robot · 🟠 indéterminé · 🟢 cohérent humain.',
    ]),
  );
  const present = DIMENSIONS.map(([id, label]) => ({ id, label, v: CARD_VERDICTS.get(id) }))
    .filter((d): d is { id: string; label: string; v: CardVerdict } => Boolean(d.v))
    .sort((a, b) => TONE_RANK[a.v.tone] - TONE_RANK[b.v.tone]);

  const board = el('div', { class: 'scoreboard' });
  if (present.length === 0) {
    board.appendChild(el('span', { class: 'empty' }, ['Aucune dimension évaluée.']));
  }
  for (const d of present) {
    const chip = el('span', {
      class: 'chip',
      role: 'button',
      tabindex: '0',
      'aria-label': `${d.label} : ${TONE_LABEL[d.v.tone]} — ${d.v.reason}`,
      title: `${TONE_LABEL[d.v.tone]} — ${d.v.reason}`,
    });
    chip.appendChild(el('span', { class: `card-dot ${d.v.tone}`, 'aria-hidden': 'true' }, [TONE_SYMBOL[d.v.tone]]));
    chip.appendChild(document.createTextNode(d.label));
    const go = (): void => {
      const target = document.getElementById(`sec-${d.id}`) as HTMLDetailsElement | null;
      if (target) {
        target.open = true;
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    };
    chip.addEventListener('click', go);
    chip.addEventListener('keydown', (e) => {
      const k = (e as KeyboardEvent).key;
      if (k === 'Enter' || k === ' ') {
        e.preventDefault();
        go();
      }
    });
    board.appendChild(chip);
  }
  wrap.appendChild(board);
  return wrap;
}

function groupTitle(text: string): HTMLElement {
  return el('div', { class: 'group-title' }, [text]);
}

function tags(list: string[], kind: 'warn' | 'ok' = 'warn'): HTMLElement {
  const wrap = el('div');
  if (list.length === 0) {
    wrap.appendChild(el('span', { class: 'empty' }, ['aucun']));
    return wrap;
  }
  for (const t of list) {
    wrap.appendChild(el('span', { class: `tag ${kind}` }, [t]));
  }
  return wrap;
}

function badge(label: string, kind: 'ok' | 'warn' | 'danger' | 'neutral'): HTMLElement {
  return el('span', { class: `badge ${kind}` }, [label]);
}

// Decision-engine verdict, computed server-side. Headline of the recap.
function verdictCard(full: FullFingerprint): HTMLElement | null {
  const d = full.decision;
  if (!d) return null;

  const map: Record<string, { kind: 'ok' | 'warn' | 'danger' | 'neutral'; label: string }> = {
    bot: { kind: 'danger', label: 'Bot' },
    suspect: { kind: 'warn', label: 'Suspect' },
    human: { kind: 'ok', label: 'Humain' },
    clean: { kind: 'neutral', label: 'Rien contre toi (non confirmé)' },
    unknown: { kind: 'neutral', label: 'Indéterminé' },
  };
  const v = map[d.verdict] ?? map.unknown!;

  // A decision persisted by an older engine (or a partial blob) may be missing
  // fields the type says are required. Normalise to safe defaults up front so a
  // single absent field renders a degraded-but-complete card instead of throwing
  // and taking the WHOLE recap down via render()'s catch-all.
  const score = d.score ?? 0;
  const trustScore = d.trustScore ?? 0;
  const trustSignals = d.trustSignals ?? [];
  const byLevel = d.byLevel ?? [];

  const wrap = el('section', { class: 'exposure' });
  wrap.appendChild(el('h2', {}, ['Verdict']));

  const head = el('div', { class: 'badges' });
  head.appendChild(badge(v.label, v.kind));
  head.appendChild(badge(`suspicion ${Math.round(score * 100)} / 100`, 'neutral'));
  if (trustScore > 0) head.appendChild(badge(`confiance ${Math.round(trustScore * 100)} / 100`, 'ok'));
  if (d.forced) head.appendChild(badge('aveu direct (immunisé au crédit)', 'danger'));
  wrap.appendChild(head);

  // Positive human-trust credit: what corroborates a real person.
  if (trustSignals.length > 0) {
    const tg = el('div', { class: 'level-group' });
    tg.appendChild(el('div', { class: 'level-head' }, ['Crédit de confiance (pro-humain)', badge(`+${trustScore.toFixed(2)}`, 'ok')]));
    const ul = el('ul', { class: 'verdict-signals' });
    for (const t of trustSignals) {
      const li = el('li', {}, [badge(`+${t.weight ?? 0}`, 'ok'), ` ${t.label ?? ''}`]);
      if (t.evidence && t.evidence.length > 0) {
        const code = document.createElement('code');
        code.textContent = ' ' + t.evidence.join(', ');
        li.appendChild(code);
      }
      ul.appendChild(li);
    }
    tg.appendChild(ul);
    wrap.appendChild(tg);
  }

  const totalHits = byLevel.reduce((n, l) => n + (l.hits?.length ?? 0), 0);
  if (totalHits === 0) {
    wrap.appendChild(
      el('p', {}, [
        "Aucun signal déclenché sur les niveaux actifs. Attention : l'absence d'aveu ne prouve pas qu'il s'agit d'un humain — un bot peut masquer ces marqueurs.",
      ]),
    );
  } else {
    // Group the fired signals by level so the « why » reads N1 (aveux) → N2
    // (réseau) → N3 (cohérence), each with its own sub-verdict and score.
    wrap.appendChild(el('p', {}, [`${totalHits} signal(aux) déclenché(s) :`]));
    for (const l of [...byLevel].sort((a, b) => (a.level ?? 0) - (b.level ?? 0))) {
      const hits = l.hits ?? [];
      if (hits.length === 0) continue;
      const meta = LEVEL_META[l.level] ?? { label: `Niveau ${l.level}` };
      const lv = VERDICT_BADGE[l.verdict] ?? VERDICT_BADGE.unknown!;
      const group = el('div', { class: 'level-group' });
      const headRow = el('div', { class: 'level-head' });
      headRow.appendChild(document.createTextNode(meta.label));
      headRow.appendChild(badge(lv.label, lv.kind));
      if (!l.forced) headRow.appendChild(badge(`score ${Math.round((l.score ?? 0) * 100)} / 100`, 'neutral'));
      group.appendChild(headRow);

      const ul = el('ul', { class: 'verdict-signals' });
      for (const h of hits) {
        const li = el('li', {}, [
          badge(h.severity === 'hard' ? 'aveu' : `+${h.weight ?? 0}`, h.severity === 'hard' ? 'danger' : 'warn'),
          ` ${h.label ?? ''}`,
        ]);
        if (h.evidence && h.evidence.length > 0) {
          const code = document.createElement('code');
          code.textContent = ' ' + h.evidence.join(', ');
          li.appendChild(code);
        }
        ul.appendChild(li);
      }
      group.appendChild(ul);
      wrap.appendChild(group);
    }
  }

  wrap.appendChild(el('p', { class: 'section-note' }, [`Règles : ${d.configVersion ?? 'inconnu'}.`]));
  return wrap;
}

const LEVEL_META: Record<number, { label: string }> = {
  1: { label: "Niveau 1 — aveux d'automatisation" },
  2: { label: 'Niveau 2 — réseau / contexte' },
  3: { label: "Niveau 3 — cohérence d'environnement" },
  4: { label: 'Niveau 4 — comportement' },
  5: { label: 'Niveau 5 — réputation' },
};

const VERDICT_BADGE: Record<string, { kind: 'ok' | 'warn' | 'danger' | 'neutral'; label: string }> = {
  bot: { kind: 'danger', label: 'Bot' },
  suspect: { kind: 'warn', label: 'Suspect' },
  clean: { kind: 'ok', label: 'RAS' },
  unknown: { kind: 'neutral', label: 'Indéterminé' },
};

// Announced loading state: role=status + aria-live so screen readers hear the
// page is working, with a spinner for sighted users.
function loadingPanel(message: string): HTMLElement {
  const wrap = el('section', { class: 'status', role: 'status', 'aria-live': 'polite' });
  wrap.appendChild(el('span', { class: 'spinner', 'aria-hidden': 'true' }));
  wrap.appendChild(document.createTextNode(message));
  return wrap;
}

// Announced error state: role=alert so it's spoken immediately, and visually
// distinct (red panel) so a 404 / network failure doesn't blend into the page.
function errorPanel(message: string): HTMLElement {
  return el('section', { class: 'error-panel', role: 'alert' }, [message]);
}

async function render(): Promise<void> {
  const id = extractId();
  const content = document.getElementById('content')!;
  const sessionEl = document.getElementById('session-id')!;
  const exportLink = document.getElementById('export-link') as HTMLAnchorElement;

  if (!id) {
    content.replaceChildren(errorPanel('Session ID introuvable dans l’URL.'));
    return;
  }
  sessionEl.textContent = id;
  exportLink.href = `/export/${id}`;
  content.replaceChildren(loadingPanel('Chargement du fingerprint…'));

  let res: Response;
  try {
    res = await fetch(`/api/fp/${id}`);
  } catch {
    content.replaceChildren(
      errorPanel('Erreur réseau — impossible de joindre le serveur. Réessaie dans un instant.'),
    );
    return;
  }
  if (!res.ok) {
    content.replaceChildren(
      errorPanel(`Session « ${id} » introuvable côté serveur (peut-être expirée — les sessions durent 1 h).`),
    );
    return;
  }
  const full = (await res.json()) as FullFingerprint;
  CARD_VERDICTS = new Map((full.decision?.cards ?? []).map((c) => [c.id, c]));
  content.replaceChildren();

  // Colour-independent legend up top, then verdict, then the dimension
  // dashboard; the raw data follows, collapsed.
  content.appendChild(legend());
  const verdict = verdictCard(full);
  if (verdict) content.appendChild(verdict);
  content.appendChild(scoreboard());

  // ─── Côté serveur ──────────────────────────────────────────────────────────
  content.appendChild(groupTitle('Côté serveur — ce que le réseau révèle'));

  const tls = full.server.tls;
  if (tls) {
    content.appendChild(
      section(
        'TLS — ClientHello',
        [
          row('Version négociée', `${tls.versionName} (0x${tls.version.toString(16)})`),
          row('SNI', tls.sni),
          row('ALPN', tls.alpn),
          row('JA3', tls.ja3),
          row('JA3 hash', tls.ja3Hash),
          row('JA4', tls.ja4),
          row(`Ciphers (${tls.ciphers.length})`, tls.ciphers.map((c) => labelId(c, CIPHER_SUITES))),
          row(`Extensions (${tls.extensions.length})`, tls.extensions.map((c) => labelId(c, TLS_EXTENSIONS))),
          row('Supported versions', tls.supportedVersions.map((v) => '0x' + v.toString(16))),
          row(`Courbes / groupes (${tls.ellipticCurves.length})`, tls.ellipticCurves.map((c) => labelId(c, SUPPORTED_GROUPS))),
          row('Algos de signature', tls.signatureAlgorithms.map((c) => labelId(c, SIGNATURE_SCHEMES))),
          row('EC point formats', tls.ecPointFormats.map((c) => labelId(c, EC_POINT_FORMATS))),
        ],
        "JA3/JA4 sont des empreintes de ta pile TLS (ordre des ciphers et extensions du ClientHello). Elles identifient le client — navigateur, version, ou outil/bot — indépendamment du User-Agent, souvent réutilisé tel quel par les anti-bots.",
        'tls',
      ),
    );
  } else {
    content.appendChild(section('TLS', [row('Capture', 'parse failed or absent')], undefined, 'tls'));
  }

  const http = full.server.http;
  if (http) {
    const incon = document.createElement('td');
    incon.appendChild(tags(http.inconsistencies, 'warn'));
    const inconRow = document.createElement('tr');
    inconRow.appendChild(th('Inconsistencies'));
    inconRow.appendChild(incon);
    content.appendChild(
      section(
        'HTTP',
        [
          row('Méthode', http.method),
          row('Path', http.path),
          row('Version', http.httpVersion),
          row('User-Agent', http.userAgent),
          row('Accept-Language', http.acceptLanguage),
          row('Accept-Encoding', http.acceptEncoding),
          row('Header order', http.headerOrder.join(' → ')),
          row('Client hints', http.clientHints),
          row('Sec-Fetch', http.secFetch),
          inconRow,
        ],
        "L'ordre exact des en-têtes et leur cohérence (UA vs Sec-CH-UA, Sec-Fetch…) trahissent un client forgé : un vrai navigateur a un ordre stable, un bot qui ré-assemble les en-têtes laisse des incohérences listées ci-dessous.",
        'http',
      ),
    );
  }

  const ip = full.server.ip;
  if (ip) {
    content.appendChild(
      section(
        'IP',
        [
          row('IP', ip.ip),
          row('ASN', ip.asn),
          row('Organisation', ip.asnOrganization),
          row('Pays', formatCountry(ip.country) ?? ip.country),
          row('Reverse DNS', ip.reverseDns),
          row('Sortie Tor ?', humanBool(ip.isTorExit)),
          row('Datacenter ?', humanBool(ip.isDatacenter)),
          row('Indice proxy/VPN ?', humanBool(ip.isProxyHint)),
          row('TCP RTT (ms)', ip.tcpRttMs === null ? '—' : ip.tcpRttMs.toFixed(2)),
        ],
        "Ton IP est rattachée à un opérateur (ASN). Une IP datacenter, un nœud Tor ou un indice VPN te distinguent d'un visiteur résidentiel ; le RTT TCP estime la distance réseau.",
        'ip',
      ),
    );
  }

  // ─── Côté navigateur ───────────────────────────────────────────────────────
  content.appendChild(groupTitle('Côté navigateur — ce que la page mesure'));

  const n = full.client.navigator;
  content.appendChild(
    section(
      'Navigator',
      [
        row('User-Agent', n.userAgent),
        row('Platform', n.platform),
        row('Vendor', n.vendor),
        row('Language', `${n.language} (${n.languages.join(', ')})`),
        row('hardwareConcurrency', n.hardwareConcurrency),
        row('deviceMemory', n.deviceMemory),
        row('maxTouchPoints', n.maxTouchPoints),
        row('cookieEnabled', n.cookieEnabled),
        row('doNotTrack', n.doNotTrack),
        row('userAgentData', n.uaData),
      ],
      undefined,
      'navigator',
    ),
  );

  // Matériel : agrège les signaux dispersés (CPU navigator, RAM navigator, GPU
  // WebGL) en une vue lisible. Tout est déduit du navigateur, jamais exact.
  const gw = full.client.webgl;
  content.appendChild(
    section(
      'Matériel (déduit)',
      [
        row('Processeur (déduit)', inferCpu(n, full.client.webgl, full.client.webgpu)),
        row('CPU — cœurs logiques', n.hardwareConcurrency ? `${n.hardwareConcurrency} cœurs` : '—'),
        row('RAM (deviceMemory)', n.deviceMemory ? `${n.deviceMemory} Go (plafonné par le navigateur)` : '—'),
        row('GPU — fabricant', gw?.unmaskedVendor ?? gw?.vendor ?? null),
        row('GPU — modèle', gw?.unmaskedRenderer ?? gw?.renderer ?? null),
        row('GPU — taille texture max', gw?.maxTextureSize ?? null),
      ],
      "Le navigateur n'expose qu'une vue approximative du matériel : le nombre de cœurs et la RAM sont plafonnés (souvent ≤ 8 Go), le GPU vient du « unmasked renderer » WebGL. Le processeur est déduit en croisant le renderer WebGL, les Client Hints d'architecture et le vendor WebGPU — car navigator.platform vaut « MacIntel » même sur un Mac Apple Silicon. Un GPU logiciel (SwiftShader, llvmpipe) trahit souvent un environnement headless.",
      'hardware',
    ),
  );

  const s = full.client.screen;
  content.appendChild(
    section('Screen / Window', [
      row('Screen', `${s.width} × ${s.height} (avail ${s.availWidth} × ${s.availHeight})`),
      row('Color/Pixel depth', `${s.colorDepth} / ${s.pixelDepth}`),
      row('devicePixelRatio', dprLabel(s.devicePixelRatio) ?? s.devicePixelRatio),
      row('Orientation', s.orientation),
      row('Inner', `${s.windowInnerWidth} × ${s.windowInnerHeight}`),
      row('Outer', `${s.windowOuterWidth} × ${s.windowOuterHeight}`),
    ], undefined, 'screen'),
  );

  const l = full.client.locale;
  content.appendChild(
    section('Locale', [
      row('Timezone', `${l.timezone} (${formatTzOffset(l.timezoneOffset) ?? `offset ${l.timezoneOffset}`})`),
      row('Locale (Intl)', l.resolvedOptionsLocale),
      row('Cohérence locale ↔ IP', geoCoherence(l.resolvedOptionsLocale, full.server.ip?.country)),
      row('Calendar', calendarName(l.calendar)),
      row('Numbering system', numberingSystemName(l.numberingSystem)),
      row('Format date', l.dateFormat),
      row('Format nombre', l.numberFormat),
    ], undefined, 'locale'),
  );

  if (full.client.canvas) {
    const c = full.client.canvas;
    content.appendChild(
      section(
        'Canvas',
        [
          row('SHA-256(dataURL)', c.dataUrlHash),
          row('SHA-256(textMetrics)', c.textMetricsHash),
          row('Winding evenodd', humanBool(c.winding)),
          row('dataURL length', c.toDataURLLength),
        ],
        "Le rendu d'un même texte/forme varie subtilement selon GPU, pilotes et polices : ce hash est donc très distinctif et stable, l'un des signaux les plus utilisés pour pister sans cookie.",
      ),
    );
  }

  if (full.client.webgl) {
    const g = full.client.webgl;
    content.appendChild(
      section(
        'WebGL',
        [
          row('Vendor', g.vendor),
          row('Renderer', g.renderer),
          row('Unmasked vendor', g.unmaskedVendor),
          row('Unmasked renderer', g.unmaskedRenderer),
          row('Version', g.version),
          row('GLSL', g.shadingLanguageVersion),
          row('Max texture size', g.maxTextureSize),
          row('Extensions', g.extensions),
          row('SHA-256(params)', g.parametersHash),
        ],
        "Le « unmasked renderer » expose souvent ton modèle exact de GPU, et les paramètres WebGL forment une empreinte matérielle complémentaire du canvas.",
        'webgl',
      ),
    );
  }

  if (full.client.audio) {
    const a = full.client.audio;
    content.appendChild(
      section(
        'Audio',
        [
          row('Oscillator hash', a.oscillatorHash),
          row('sampleRate', a.sampleRate),
          row('baseLatency', a.baseLatency),
          row('outputLatency', a.outputLatency),
          row('state', a.state),
        ],
        "Le traitement d'un signal par l'AudioContext diffère légèrement selon le matériel/l'OS : ce hash audio est un identifiant supplémentaire, indépendant du canvas.",
      ),
    );
  }

  if (full.client.fonts) {
    const f = full.client.fonts;
    content.appendChild(
      section('Fonts', [
        row('Méthode', f.detectionMethod),
        row(`Détectées (${f.detectedFonts.length})`, f.detectedFonts),
      ], undefined, 'fonts'),
    );
  }

  if (full.client.webrtc) {
    const w = full.client.webrtc;
    content.appendChild(
      section(
        'WebRTC',
        [
          row('Local IPs', w.localIps),
          row('Public IP (STUN)', w.publicIp),
          row('Erreur', w.error),
          row('Candidates', w.candidates),
        ],
        'WebRTC peut révéler ton IP locale (réseau privé) voire ton IP publique réelle même derrière un VPN — une fuite classique de dé-anonymisation.',
        'webrtc',
      ),
    );
  }

  content.appendChild(
    section('Codecs', [
      row('Vidéo', humanizeCodecMap(full.client.codecs.video)),
      row('Audio', humanizeCodecMap(full.client.codecs.audio)),
      row('MediaSource', humanizeCodecMap(full.client.codecs.mediaSourceTypes)),
    ]),
  );

  content.appendChild(section('Permissions', [row('États', full.client.permissions.states)], undefined, 'permissions'));

  const au = full.client.automation;
  const playHints = document.createElement('td');
  playHints.appendChild(tags(au.playwrightHints, 'warn'));
  const playRow = document.createElement('tr');
  playRow.appendChild(th('Playwright/Selenium hints'));
  playRow.appendChild(playHints);
  const cdpHints = document.createElement('td');
  cdpHints.appendChild(tags(au.cdpHints, 'warn'));
  const cdpRow = document.createElement('tr');
  cdpRow.appendChild(th('CDP hints'));
  cdpRow.appendChild(cdpHints);
  const inconAuto = document.createElement('td');
  inconAuto.appendChild(tags(au.inconsistencies, 'warn'));
  const inconAutoRow = document.createElement('tr');
  inconAutoRow.appendChild(th('Inconsistencies'));
  inconAutoRow.appendChild(inconAuto);
  content.appendChild(
    section(
      'Automation hints',
      [
        row('navigator.webdriver', humanBool(au.webdriver, 'true (piloté)', 'false')),
        row('plugins / mimeTypes', `${au.pluginsLength} / ${au.mimeTypesLength}`),
        row('Plugins (noms)', (au.pluginNames ?? []).join(', ')),
        row('MIME types (noms)', (au.mimeTypeNames ?? []).join(', ')),
        row('chrome.runtime', humanBool(au.chromeRuntime)),
        row('callPhantom / nightmare / selenium', `${au.callPhantom} / ${au.nightmare} / ${au.selenium}`),
        playRow,
        cdpRow,
        inconAutoRow,
      ],
      "Ces marqueurs trahissent un navigateur piloté (Selenium, Playwright, CDP) : présents, ils font basculer la plupart des anti-bots du côté « robot ».",
      'automation',
    ),
  );

  if (full.client.speech) {
    const sv = full.client.speech;
    content.appendChild(
      section('Speech synthesis voices', [
        row('Disponible', humanBool(sv.available)),
        row('Nombre de voix', sv.voiceCount),
        row('Hash (canonique)', sv.voicesHash),
        row(
          'Voix',
          sv.voices
            .map((v) => `${v.name} — ${languageName(v.lang) ?? v.lang} [${v.lang}]${v.localService ? ' (local)' : ''}`)
            .join('\n'),
        ),
      ], undefined, 'speech'),
    );
  }

  if (full.client.mediaDevices) {
    const md = full.client.mediaDevices;
    content.appendChild(
      section('MediaDevices', [
        row('Disponible', humanBool(md.available)),
        row('Audio inputs', md.audioInputCount),
        row('Audio outputs', md.audioOutputCount),
        row('Video inputs', md.videoInputCount),
        row('Hash groupIds', md.groupIdsHash),
      ], undefined, 'mediaDevices'),
    );
  }

  if (full.client.mediaCapabilities) {
    const mcap = full.client.mediaCapabilities;
    content.appendChild(
      section('MediaCapabilities (HW decode)', [
        row('Disponible', humanBool(mcap.available)),
        row('Codecs', mcap.video),
      ], undefined, 'mediaCapabilities'),
    );
  }

  if (full.client.webgpu) {
    const gpu = full.client.webgpu;
    content.appendChild(
      section('WebGPU', [
        row('Disponible', humanBool(gpu.available)),
        row('Adapter', gpu.adapter),
        row(`Features (${gpu.features.length})`, gpu.features),
        row('Hash (limits+features)', gpu.limitsHash),
      ], undefined, 'webgpu'),
    );
  }

  if (full.client.cssMedia) {
    const cm = full.client.cssMedia;
    content.appendChild(
      section('CSS media features', [
        row('prefers-color-scheme', cm.prefersColorScheme),
        row('prefers-reduced-motion', cm.prefersReducedMotion),
        row('prefers-contrast', cm.prefersContrast),
        row('forced-colors', cm.forcedColors),
        row('pointer / hover', `${cm.pointer} / ${cm.hover}`),
        row('any-pointer / any-hover', `${cm.anyPointer} / ${cm.anyHover}`),
        row('color-gamut', cm.colorGamut),
        row('dynamic-range', cm.dynamicRange),
        row('@supports', cm.supports),
      ]),
    );
  }

  if (full.client.intl) {
    const i = full.client.intl;
    content.appendChild(
      section('Intl supported values', [
        row('timeZone (n)', i.timeZones),
        row('calendar (n)', i.calendars),
        row('currency (n)', i.currencies),
        row('numberingSystem (n)', i.numberingSystems),
        row('collation (n)', i.collations),
        row('Hash', i.supportedHash),
      ]),
    );
  }

  if (full.client.engine) {
    const e = full.client.engine;
    content.appendChild(
      section('JS engine quirks', [
        row('Detected', engineFamily(e.detectedEngine) ?? e.detectedEngine),
        row('Math fingerprint (hash)', e.mathFingerprint),
        row('Error stack (3 first lines)', e.errorStackFormat),
      ], undefined, 'engine'),
    );
  }

  if (full.client.network) {
    const n2 = full.client.network;
    content.appendChild(
      section('Network info', [
        row('Disponible', humanBool(n2.available)),
        row('effectiveType', n2.effectiveType),
        row('downlink (Mbps)', n2.downlink),
        row('rtt (ms)', n2.rtt),
        row('saveData', humanBool(n2.saveData)),
        row('type', n2.type),
      ]),
    );
  }

  if (full.client.storage) {
    const st = full.client.storage;
    content.appendChild(
      section(
        'Storage estimate',
        [
          row('Disponible', humanBool(st.available)),
          row('Quota (budget navigateur)', formatBytes(st.quota)),
          row('Usage', formatBytes(st.usage)),
          row('Persisted', humanBool(st.persisted)),
        ],
        "Le quota n'est pas ton disque dur : c'est l'espace que le navigateur accorde à ce site (souvent une fraction de l'espace libre, plafonnée). L'usage est ce que le site occupe déjà.",
        'storage',
      ),
    );
  }

  if (full.client.perfMemory) {
    const pm = full.client.perfMemory;
    content.appendChild(
      section('Performance.memory', [
        row('Disponible', humanBool(pm.available)),
        row('jsHeapSizeLimit', formatBytes(pm.jsHeapSizeLimit)),
        row('totalJSHeapSize', formatBytes(pm.totalJSHeapSize)),
        row('usedJSHeapSize', formatBytes(pm.usedJSHeapSize)),
      ]),
    );
  }

  // ─── Empreinte (identification) ─────────────────────────────────────────────
  // Regroupe les cartes purement identifiantes (Canvas, Audio, Intl, CSS…) : elles
  // pistent mais ne tranchent pas bot/humain. On les relocalise ici, en fin de
  // page et repliées, pour ne pas noyer les dimensions de décision. Fait avant
  // d'ajouter le bloc Comportement pour que « Behavioral » reste dans son groupe.
  const fpCards = content.querySelectorAll('details.card[data-fp="1"]');
  if (fpCards.length > 0) {
    content.appendChild(groupTitle('Empreinte — identification (ne tranche pas bot / humain)'));
    for (const fp of fpCards) content.appendChild(fp);
  }

  // ─── Comportement ──────────────────────────────────────────────────────────
  content.appendChild(groupTitle('Comportement — rythme uniquement, jamais le texte'));

  const b = full.client.behavioral;
  content.appendChild(
    section(
      'Behavioral',
      [
        row('Events totaux', b.totalEvents),
        row('Durée collecte (ms)', b.durationMs.toFixed(0)),
        row('Mouse', b.mouse),
        row('Keyboard', b.keyboard),
        row('Scroll', b.scroll),
        row('Touch', b.touch),
      ],
      "Statistiques de rythme (vitesse/courbure souris, dwell/flight clavier, linéarité du scroll). Le contenu tapé n'est jamais enregistré ; seules ces moyennes le sont, pour distinguer un humain d'un script.",
      'behavioral',
    ),
  );
}

render().catch((err) => {
  console.error(err);
  const c = document.getElementById('content');
  if (c) c.replaceChildren(errorPanel('Erreur de rendu — voir la console pour le détail.'));
});
