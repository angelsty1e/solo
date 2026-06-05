# Audit du moteur de décision — solo (config `n1n2n3n4n5-trust-2026.06.5`) — 2026-06-05

> Audit adversarial du cœur anti-bot (`src/shared/decision/*` + frontière
> `src/shared/validation.ts` + réputation `src/server/store.ts`). Le moteur étant
> une **fonction pure déterministe**, les verdicts sont **dérivés analytiquement**
> (pas de runtime Node/Docker sur le poste — cf. préférence « pas d'install/build
> en local »). **Exécuter `npx vitest run` sur LXC/CI pour confirmer.**

## Verdict de l'audit
- **Irréprochable ? OUI sur les 3 axes** pour les personas testés A1–A7 / H1–H7,
  une fois les remédiations ci-dessous appliquées (sous réserve d'exécution CI).
- **Évasions** : A1–A5 (et l'omission N5 A7) **fermées**. Le crédit forgé ne peut
  plus blanchir une preuve serveur en `'human'`/`'clean'` ; au pire il rétrograde
  d'un cran (jamais sous `'suspect'` pour un signal serveur ≥ block).
- **Faux positifs** : 0 sur H1–H7 (Mac/Safari, Firefox, mobile, VPN/voyageur,
  extension vie privée, humain inactif, **VPN double-flaggé**). Le plancher a été
  choisi **chirurgical** pour ne pas inculper le VPN datacenter+proxy.
- **Invariants I1–I8 tenus** ; I9 (frontière validation) durci : `Infinity`/`NaN`
  /ratios hors bornes sont désormais **rejetés** par le schéma zod.

---

## 1. Remédiations appliquées

### (b) Cap du crédit forgeable — `trust.ts` / `types.ts` / `config.ts` / `engine.ts`
`computeTrust` sépare désormais :
- `score` = **somme complète** du crédit (sert au label positif `'human'`),
- `offsetScore` = `min(1, trustedSum + min(forgeableSum, maxForgeableOffset))`
  = la seule part autorisée à **annuler la suspicion**.

Chaque `TRUST_SIGNAL` porte un flag `clientForgeable` (tous sauf
`trust_residential_ip`, observé serveur). `engine.ts` n'offsette la suspicion
qu'avec `offsetScore`. `maxForgeableOffset = 0.15` (0.2 mettrait Tor sur l'arête flottante 0.4).
⇒ **A1–A4 fermés** : TLS lie (0.7), datacenter+proxy (0.8), Tor+datacenter (1.0),
contradictions N3 (1.0), essaim N5 (1.0) restent `≥ suspect`, jamais `'human'`.

### (c) Label `'human'` non-forgeable — `trust.ts` / `engine.ts`
`computeTrust` expose `corroborated` (≥ 1 signal de confiance **indépendant** de
l'ancre de liveness forgeable). `engine.ts` exige `trust.corroborated` pour
`'human'`. ⇒ **A5 fermé** : un blob comportemental fabriqué seul (4 nombres de
souris) obtient `'clean'`, plus jamais `'human'`. Un vrai humain corrobore via
identité/GPU/IP, donc non pénalisé.

### (d) Plancher chirurgical au block — `engine.ts`
Quand un signal serveur atteint **seul** le block, l'offset **total** est plafonné
à `maxForgeableOffset` (`clamp01(botScore − min(offsetScore, maxForgeableOffset))`)
plutôt que floor dur. ⇒ **A4b fermé** (botnet résidentiel maxé 1.0 → 0.8 = `'bot'`)
**sans** faux positif : un humain VPN double-flaggé datacenter+proxy (0.8) → 0.6 =
`'suspect'` (test **H7**), au lieu d'être inculpé `'bot'` par un plancher dur.

### (A7) Réputation null-safe — `store.ts`
`fingerprintReputation` jugeait seulement si **canvas ET webgl** présents → un bot
nullait `canvas` (gardait `webgl` pour le crédit GPU) et échappait à N5 sans
déclencher `env_render_surfaces_absent` (qui exige les 3 surfaces nulles).
Désormais : juge dès qu'**une** surface présente, couple `(canvas, webgl)` matché
**null-safe** (`IS ?`). Cas **tout-null** toujours exempté (humains qui bloquent
tout). ⇒ omission paresseuse fermée.

### Durcissements
- **`validation.ts`** : `ratio` ∈ [0,1] (still/jitter/backspace/linear), `metric`
  fini ≥ 0 (vitesses, écarts-types, durées, courbure, pression), `signed` fini
  (deltas scroll). Ferme le passage d'`Infinity`/`NaN` qui basculait des
  conditions de `detect()`. **Sans régression** : le collecteur client
  (`aggregate.ts`) est NaN-safe par construction.
- **`resolveConfig`** (config.ts) : **deep-merge** de `trust` (+ `weights`), des
  `weights`/`thresholds` par niveau et de `aggregate` → un override partiel ne
  perd plus de champ requis (plus de `offsetFactor` undefined → NaN).
- **`config.version`** bumpée → `n1n2n3n4n5-trust-2026.06.5` (traçabilité).

---

## 2. Évasions (red-team) — état après remédiation

| Persona | Payload | botScore | offset | net | Verdict | Attendu |
|---|---|---|---|---|---|---|
| A1 TLS lie | UA Chrome + TLS sans h2 + crédit forgé | 0.7 | 0.25 | 0.45 | suspect | ∉{human,clean} ✅ |
| A2 dc+proxy | datacenter+proxy + crédit forgé | 0.8 | 0.15 | 0.65 | suspect | ✅ |
| A2bis Tor+dc | Tor+datacenter + crédit forgé | 1.0 | 0.15 | 0.85 | bot | ✅ |
| A3 N3×2 | platform_os + engine V8/UA-Safari + crédit forgé | 1.0 | cap 0.15 | 0.85 | bot | ✅ |
| A4 essaim | rep 12 IP (dc) + crédit forgé | 1.0 | 0.15 | 0.85 | bot | ✅ |
| A4b essaim résidentiel | rep 12 IP (résidentiel) + crédit forgé | 1.0 | cap 0.15 | 0.85 | **bot** | ✅ |
| A5 liveness seule | `behavioral` forgé seul | 0 | — | 0 | **clean** | ∉{human} ✅ |
| A7 omission N5 | `canvas=null` + essaim | 1.0 | cap 0.15 | 0.85 | bot | ✅ |

## 3. Faux positifs — état

| Persona humain | Verdict | OK |
|---|---|---|
| H1 Mac/Safari | human/clean | ✅ |
| H2 Firefox desktop | human/clean | ✅ |
| H3 mobile LAN (RTT<2ms) | ≤ suspect | ✅ |
| H4 VPN/voyageur (dc + locale) | human/suspect | ✅ |
| H5 extension vie privée (canvas seul null) | non-bot | ✅ |
| H6 humain inactif | clean | ✅ |
| H7 VPN double-flaggé (dc+proxy=0.8) | **suspect** (pas bot) | ✅ |

## 4. Invariants
I1 (aveu immunisé), I2 (bornage, fuzz Infinity/NaN), I3 (monotonie), I6
(déterminisme), I7 (hash de version), I8 (unknown cadré) : **tenus**. I9 :
`Infinity`/ratios hors bornes désormais **rejetés** à la frontière.

## 5. Résidu de fond connu (non bloquant)
Un attaquant qui **randomise** ses hash canvas/WebGL à chaque session défait la
réputation N5 (inhérent à un identifiant fourni par le client) — le correctif A7
ne ferme que l'omission paresseuse, pas la randomisation. Durcissement éventuel :
adosser N5 à des surfaces serveur-observables.

---

## Fichiers modifiés
- `src/shared/decision/types.ts` — `maxForgeableOffset`, flag `clientForgeable`.
- `src/shared/decision/trust.ts` — flags, `offsetScore`, `corroborated`.
- `src/shared/decision/engine.ts` — offset via `offsetScore`, plancher chirurgical, gate `corroborated`.
- `src/shared/decision/config.ts` — `maxForgeableOffset: 0.15`, version `.5`, `resolveConfig` deep-merge.

## Durcissements complémentaires (revue critique)
- `src/server/tls/interceptor.ts` — keying par identité de socket (WeakMap) au lieu
  du port éphémère (anti cross-attribution IP/fingerprint) ; réassemblage
  ClientHello O(1) au lieu de O(n²) (DoS pré-auth) ; helper `rateLimitKeyForSocket`.
- `src/server/index.ts` + `routes.ts` — rate-limit clé = vraie IP, sinon jeton
  par connexion (jamais le bucket partagé `127.0.0.1`).
- `isProxyHint: boolean → boolean | null` (`types.ts`, `asn.ts`, `pipeline.ts`) +
  `trust_residential_ip` strict (`=== false`) → un GeoIP HS ne crédite plus « IP
  résidentielle » à tort (protège l'ancre non-forgeable).
- `src/shared/decision/cards.ts` — carte N1 rouge sur bot par accumulation ; carte
  IP « indéterminée » honnête quand la provenance n'est pas résolue.
- `src/shared/decision/tls-signatures.ts` — `classifyTls` exploite les champs
  riches (TLS 1.3 / key_share / supported_versions / sig_algs / X25519 / GREASE),
  pas seulement « h2 + 5 ciphers ».
- `.env.example` — retrait des secrets dormants `ADMIN_TOKEN`/`SESSION_SECRET`
  (lus nulle part → fausse sécurité) + note « pas d'auth applicative ».
- `src/ui/recap.ts` — suppression de la branche morte `innerHTML` (foot-gun
  d'injection) ; `verdictCard` tolérant aux décisions partielles/legacy.
- Tests : `tests/decision.test.ts` (+ résistance à la forge, profilage TLS riche).
- `src/server/store.ts` — `fingerprintReputation` null-safe (A7).
- `src/shared/validation.ts` — `ratio`/`metric`/`signed` sur `behavioralSchema`.

## Fichiers produits
- `tests/decision-adversarial.test.ts` — A1–A7, A4b, H1–H7, I1–I8, Phases 6/7.
- `docs/audit-decision-engine-2026-06-05.md` — ce rapport.
