# Audit du moteur de décision — solo (config `n1n2n3n4n5-trust-2026.06.5`) — 2026-06-05

> Audit adversarial **statique** (lecture + raisonnement, sans exécution : projet
> déployé sur LXC, pas de npm/tsc/node en local). Les recettes d'évasion ont été
> vérifiées par arithmétique manuelle sur le code et figées en tests de régression
> dans `tests/decision-adversarial.test.ts` (non exécutés ici).

## Verdict de l'audit

- **Irréprochable ? NON** — défaut sur l'**axe 1 (anti-évasion / label positif `human`)**.
  Les axes 2 (faux positifs) et 3 (scoring sain) tiennent dans l'ensemble.
- **Évasions confirmées : 1 nette (P1)** + 1 limitation structurelle (P2).
  - Pire recette (P1) : un bot hébergé en **datacenter** (AWS/OVH, `isDatacenter=true`,
    seule preuve serveur, à 0.4) **sans** `isProxyHint`, qui forge intégralement sa
    charge cliente (comportement organique + GPU/fonts/voix), décroche le label
    **positif `human`** — la preuve serveur (0.4) est non seulement annulée par
    l'offset forgeable (0.15) mais *retournée* en `human` par le crédit forgé.
- **Faux positifs : 0** trouvé sur H1–H7 (Mac/Safari, Firefox, mobile, VPN,
  extension, peu actif, VPN double-flaggé). Bonne couverture existante.
- **Invariants violés : aucun** des I1–I9 au sens strict (bornage, déterminisme,
  immunité de l'aveu dur, traçabilité tiennent). I4/I5/I9 n'avaient pas de test
  dédié → ajoutés.

Le moteur a déjà été durci par un audit précédent (cap `maxForgeableOffset`,
`offsetScore` vs `score`, flag `corroborated`, plancher chirurgical au block,
réputation null-safe). Les findings ci-dessous sont le **résidu** après ce
durcissement.

---

## 1. Cartographie (signal × niveau × poids × forgeable)

| Niveau | Signal | Poids | Sévérité | Source | Forgeable ? |
|---|---|---|---|---|---|
| N1 | webdriver, pw_globals, cdp_traces, selenium, phantom, nightmare, headless_ua | hard (override) | hard | client `automation` | **Suppressible** par un headless patché (mais présence = preuve) |
| N1 | forged_chrome | 0.15 | soft | client | oui |
| N1 | zero_plugins | 0.5 | soft | client | oui |
| N1 | notif_no_focus | 0.15 | soft | client | oui |
| N2 | tls_ua_mismatch | 0.7 | soft | **serveur (TLS)** | non (hors uTLS clone parfait) |
| N2 | http_inconsistencies | 0.5 | soft | **serveur (HTTP)** | non |
| N2 | ip_tor | 0.6 | soft | **serveur (liste Tor)** | non |
| N2 | ip_datacenter | 0.4 | soft | **serveur (MaxMind)** | non |
| N2 | ip_proxy | 0.4 | soft | **serveur (MaxMind)** | non |
| N2 | rdns_hosting | 0.25 | soft | **serveur (rDNS)** | non |
| N2 | rtt_incoherence | 0.3 | soft | **serveur (RTT)** | non |
| N2 | lang_header_js_mismatch | 0.5 | soft | serveur header ↔ client JS | partiel |
| N2 | client_hints_ua_mismatch | 0.5 | soft | serveur header ↔ client JS | partiel |
| N3 | 16 signaux env_* | 0.1–0.65 | soft | **client** | **oui, entièrement** |
| N4 | 5 signaux beh_* | 0.2–0.45 | soft | **client (agrégats)** | **oui, entièrement** |
| N5 | rep_fp_many_ips (0.6) + rep_fp_swarm (0.4) | — | soft | **serveur (store)** | non (mais omission de surface : voir A7, corrigé) |

**Crédit de confiance (trust)** — somme des poids forgeables vs serveur :

| Trust signal | Poids | Liveness | Serveur ? |
|---|---|---|---|
| trust_behavior_human | 0.5 | **oui (ancre)** | non (client) |
| trust_identity_coherent | 0.2 | — | non (client) |
| trust_hardware_gpu | 0.15 | — | non (client) |
| trust_hw_video_decode | 0.1 | — | non (client) |
| trust_fonts_rich | 0.1 | — | non (client) |
| trust_residential_ip | 0.1 | — | **OUI (serveur)** |
| trust_speech_voices | 0.05 | — | non (client) |
| trust_media_devices | 0.05 | — | non (client) |

- **Σ poids forgeables = 1.15** → `score` (label `human`) plafonné à **1** entièrement
  par du forgeable. `liveness` ET `corroborated` sont satisfiables sans aucun signal
  serveur. Seul `offsetScore` est bridé : sa part forgeable est plafonnée à
  `maxForgeableOffset = 0.15`.
- Seuils : `aggregate.block = 0.8`, `review = 0.4` ; `offsetFactor = 1.0`,
  `humanThreshold = 0.5`, `requireLiveness = true`, `maxForgeableOffset = 0.15`.

**Constat clé** : le cap (0.15) protège bien l'**offset** (annulation de suspicion),
mais **rien ne protège le label positif `human`** : il s'obtient avec `score≥0.5`,
`liveness`, `corroborated` — les trois 100 % forgeables.

---

## 2. Évasions (red-team)

| Persona | Charge (résumé) | Verdict obtenu | Attendu | Sévérité |
|---|---|---|---|---|
| A1 — TLS↔UA lie + trust forgé | toolTls (no h2) + client forgé | suspect | ∉{human,clean} | tenu ✅ |
| A2 — datacenter+proxy (0.8) + trust forgé | DC+proxy + forgé | suspect | ∉{human,clean} | tenu ✅ |
| A2bis — Tor+DC + trust forgé | Tor+DC + forgé | bot/suspect | ∉{human,clean} | tenu ✅ |
| A3 — 2 contradictions N3 (1.0) + trust forgé | platform+engine mismatch | suspect | ∉{human,clean} | tenu ✅ |
| A4 — essaim N5 (≥10 IP) + trust forgé | rep 12 IP | suspect | ∉{human,clean} | tenu ✅ |
| A4b — essaim résidentiel | rep 12 IP, IP rési | bot | bot | tenu ✅ |
| A5 — comportement forgé seul | behavioral forgé | clean | ≠ human | tenu ✅ |
| **A8 — datacenter SEUL (0.4) + trust forgé** | `isDatacenter=true` only + client forgé | **`human`** | **≠ human** | **P1 ❌** |
| **A10 — proxy SEUL (0.4) + trust forgé** | `isProxyHint=true` only + client forgé | **`human`** | **≠ human** | **P1 ❌** |
| A9/A6 — client 100 % forgé, IP propre, uTLS clone | aucun signal serveur | `human` | discutable | P2 ⚠️ |

### Recette P1 (A8) — arithmétique exacte

```
botScore = max niveaux = ip_datacenter (0.4)           # seule preuve serveur
trust forgé : forgeableSum = 0.5+0.2+0.15+0.1+0.1+0.05+0.05 = 1.15
  score      = min(1, 1.15)               = 1.0   → ≥ humanThreshold (0.5) ✅
  liveness   = true (comportement forgé)          ✅
  corroborated = true (GPU/fonts/... forgés)      ✅
  offsetScore = min(1, 0 + min(1.15, 0.15)) = 0.15
botScore (0.4) < block (0.8) → branche rawNet :
  netSuspicion = clamp01(0.4 − 1.0 × 0.15) = 0.25 < review (0.4)
→ verdict = 'human'                                     ❌ ÉVASION
```

Le commentaire de `config.ts:129` assume ce résultat pour un **vrai humain VPN**
(`ip_proxy 0.4 − 0.15 = 0.25 → human`). Mais l'arithmétique est identique pour un
**bot** : tout ce qui mène à `human` (trust score + liveness + corroboration) est
forgeable. Le moteur ne peut pas distinguer le VPN humain du bot datacenter ici, et
tranche en faveur du label positif → un bot cloud décroche `human`.

**Impact** : un opérateur qui se fie au verdict `human` (ex. allow-list, scoring
aval) accorde une confiance maximale à un bot trivial (cloud + payload JS scripté,
sans même un faux ClientHello). C'est l'échec de l'axe 1 sur le label le plus fort.

---

## 3. Faux positifs (axe 2) — aucun trouvé

| Persona humain | Signaux à risque | Verdict | OK ? |
|---|---|---|---|
| H1 Mac/Safari (no Client Hints, JSC≠V8) | env_engine_ua_mismatch, env_uadata_incoherent gardés | ≠ bot | ✅ |
| H2 Firefox desktop | env_webgpu_absent gardé `!chrome/edge`, forged_chrome neutralisé | ≠ bot | ✅ |
| H3 Mobile wifi local (RTT<2ms) | rtt_incoherence | ≠ bot | ✅ |
| H4 Voyageur/VPN (locale≠pays) | env_locale_ip_mismatch (0.2) seul | ≠ bot | ✅ |
| H5 Extension (canvas bloqué seul) | env_render_surfaces_absent exige 3 nuls | ≠ bot | ✅ |
| H6 Humain peu actif (0 interaction) | beh_no_interaction (0.2) seul | ≠ bot | ✅ |
| H7 VPN double-flaggé (DC+proxy=0.8) | plancher chirurgical → suspect | suspect, ≠ bot | ✅ |

Les gardes Mac/Safari/mobile/Chromium-only (`isMobileUa`, `isChromium`,
frontière V8↔non-V8) sont solides et bien commentées. Aucune régression détectée.

---

## 4. Invariants & maths (I1–I9)

| Inv. | Énoncé | Statut | Preuve |
|---|---|---|---|
| I1 | Aveu dur ⇒ bot, score=1, immune au trust | **tenu** | `engine.ts:63` `forced ? 1`; test I1 |
| I2 | Scores ∈ [0,1] même Infinity/NaN | **tenu** | `clamp01` + `Math.min(1,…)` partout + zod `.finite()` ; test I2 |
| I3 | Monotonie (ajout d'un tell ne baisse pas botScore) | **tenu** | `Math.max` inter-niveaux, somme intra ; test I3 |
| I4 | Aveu dur ⇒ verdict='bot' (jamais human/clean/suspect) | tenu (n'avait **pas** de test) | ajouté |
| I5 | 'human' exige liveness | tenu (n'avait **pas** de test dédié) | `engine.ts:78` ; ajouté |
| I6 | Déterminisme/pureté | **tenu** | `computedAt` injectable, pas de `Date.now`/`random` dans le chemin pur ; test I6 |
| I7 | Traçabilité (hash FNV-1a du contenu) | **tenu** | `configFingerprint` exclut le label ; test I7 |
| I8 | 'unknown' bien cadré | **tenu** | `byLevel.length===0 && trust.signals.length===0` ; test I8 |
| I9 | Payload zod-valide ⇒ pas de NaN/crash | tenu (couvert partiellement par I2) | ajouté un cas tout-à-zéro |

**Maths offset** : le passage `rawNet` ↔ branche-block ne crée pas d'inversion de
verdict (la suspicion croît avec botScore). La non-monotonie locale de l'offset
résiduel au block (résidentiel non cumulé au-delà du cap) est **voulue** (A4b) et
sans effet pervers sur le classement.

---

## 5. Intégrité du crédit de confiance — pouvoir d'annulation & remédiation

- **Annulation de suspicion** : bien bornée. Part forgeable plafonnée à 0.15, part
  serveur (résidentiel 0.1) exemptée mais ne s'empile plus au-delà du cap dès le
  block. Un crédit forgé ne peut **plus** blanchir une preuve serveur *forte ou
  empilée* (TLS, Tor, DC+proxy, essaim) — c'est solide.
- **Mint du label `human`** : **NON borné par une corroboration serveur.** C'est le
  trou résiduel (A8/A10). `trust.corroborated` exige un signal hors-liveness, mais
  tous les candidats hors `trust_residential_ip` sont forgeables.

**Remédiation proposée (à valider avant GO — NON implémentée) :**

- **(b′) Ancre serveur pour `human`** *(recommandée)* : n'autoriser le label positif
  `human` que si **au moins un trust signal SERVEUR** corrobore — concrètement
  `trust_residential_ip` (le seul non-forgeable). Sinon, plafonner à `clean`.
  Effet : A8/A10 (datacenter/proxy = NON résidentiel par construction) → ne peuvent
  plus être `human` ; le vrai humain VPN reste `clean` (pas `bot`), ce qui est le
  bon classement (un VPN n'est pas une *preuve* d'humanité). Le vrai humain en IP
  résidentielle garde `human`.
  Implémentation pressentie : dans `engine.ts`, ajouter au gate `human` une
  condition `trust.serverCorroborated` (nouveau flag dans `TrustResult`, vrai si un
  trust signal `!clientForgeable` a fire).
- **(a) alternative plus douce** : laisser `human` mais le dégrader en `clean`
  quand la seule preuve serveur présente est une présomption N2 (DC/proxy) non
  contrebalancée par un crédit serveur. Moins lisible que (b′).
- **(c) alternative structurelle** : recalculer le comportement (liveness) côté
  serveur à partir d'événements bruts plutôt que d'agrégats client. Coûteux ;
  hors périmètre immédiat.

> Le choix (b′) est minimal, ne touche pas aux faux positifs (H1–H7 ne dépendent
> pas du label `human`) et ferme A8/A9/A10. **À discuter avec Johann.**

---

## 6. Config / tuning & validation

- **`resolveConfig`** : merge **profond** par niveau et sur `trust`/`aggregate`. Un
  override partiel ne wipe **pas** les poids/seuils/hardSignals frères (vérifié,
  tests présents). Pas de NaN introduit. ✅
- **Non-atteignabilité d'un override non fiable** : `routes.ts:209` appelle
  `analyze(full, undefined, …)` → `defaultConfig`. **Aucun chemin** ne laisse un
  override client/non fiable atteindre `resolveConfig`. ✅ (P0 écarté.)
- **`validateConfig`** : couvre ids inconnus, signaux inertes, poids>1. **Trous
  connus, acceptés** : ne détecte pas un hard signal retiré par erreur, ni une Σ de
  poids d'un niveau franchissant le block avec un seul signal. À documenter (P3).
- **`warnConfig`** : `console.warn` uniquement, pas de crash. ✅ `versionTag` =
  label + hash FNV-1a du contenu réel (label exclu) → désync visible. ✅
- **Frontière `validation.ts`** : `metric = z.number().finite().min(0)`,
  `ratio ∈ [0,1]`, `signed` fini. Infinity/NaN **rejetés** à la frontière (tests
  présents) → le moteur ne reçoit jamais ces valeurs via `/collect`. Top-level
  `.strict()` (anti-injection de colonnes), clés imbriquées strippées. ✅
  - Limite résiduelle (P3) : un appel **direct** à `runDecision`/`computeTrust`
    avec un `DecisionInput` non passé par zod (tests, futur code interne) n'a pas
    cette garantie ; le moteur s'appuie sur le clamp, pas sur `.finite()` interne.
    Le bornage (I2) tient quand même grâce aux `clamp01`/`Math.min`.

---

## 7. Plan de remédiation priorisé + tests de régression

| ID | Sévérité | Fichier:ligne | Description | Remédiation |
|---|---|---|---|---|
| **A8/A10** | **P1** | `engine.ts:76-88`, `config.ts:135` | Une présomption serveur isolée (datacenter **ou** proxy, 0.4) + crédit 100 % forgeable décroche le label positif `human`. Le label `human` n'exige aucune corroboration **serveur**. | (b′) gate `human` sur `trust.serverCorroborated` (≥1 trust signal non-forgeable). Bump semver + MAJ README. **GO requis.** |
| A9/A6 | P2 | `engine.ts:76-88`, `trust.ts:150` | Plus généralement, `human` est mintable par une charge JS entièrement forgée dès lors qu'aucun signal serveur ne fire (uTLS clone parfait + IP propre). Le label positif repose sur du forgeable. | Couvert par (b′) si on exige le crédit résidentiel ; sinon documenter comme limite assumée. |
| validateConfig | P3 | `config.ts:187-204` | Ne détecte ni hard signal retiré ni Σ de poids franchissant le block avec un seul signal. | Ajouter ces deux contrôles (warn). |
| runDecision direct | P3 | `engine.ts`, `trust.ts` | Pas de `.finite()` interne ; sûreté repose sur le clamp + la frontière zod. | Documenter l'invariant « entrée toujours zod-validée » ; le bornage tient déjà. |

### Tests de régression ajoutés à `tests/decision-adversarial.test.ts`

- `A8 [FINDING P1]` — datacenter seul (0.4) + trust forgé → **doit** ≠ `human`
  (rouge avant fix, vert après (b′)).
- `A10 [FINDING P1]` — proxy/VPN seul (0.4) + trust forgé → **doit** ≠ `human`.
- `A6` — identité cohérente forgée : documente la corroboration forgeable (vert,
  borne le comportement actuel).
- `A9` — client 100 % forgé + IP résidentielle : fige la frontière (vert ;
  deviendra à arbitrer si (b′) durcit l'exigence d'un 2e ancrage serveur).
- `I4` — sous aveu dur, verdict='bot' (manquait).
- `I5` — `human` exige la liveness (manquait, dédié).
- `I9` — payload zod-valide tout-à-zéro → pas de NaN/crash.

> **Rappel process maison** : toute modif du moteur ⇒ **bump semver** (back + front
> si versions alignées), **MAJ README** si comportement observable change, et
> **liste des fichiers modifiés** en fin de session. La remédiation P1 (b′) **n'est
> pas implémentée** : elle attend le GO explicite de Johann.

---

## Couverture & angles non traités (aucun cap muet)

- ✅ I1–I9 ont chacun un test (tenu ou finding+repro).
- ✅ A1–A10 (≥7 personas attaquants) avec verdict asserté.
- ✅ H1–H7 (≥6 personas humains) sans faux positif.
- ✅ Question « crédit forgeable annule-t-il une preuve serveur ? » tranchée :
  l'**annulation** est bornée (sûr), mais le **label `human`** ne l'est pas (A8 P1).
- ✅ NaN/Infinity à la frontière `validation.ts` testés (rejetés).
- ✅ `resolveConfig` (override partiel) et non-atteignabilité d'un override non
  fiable vérifiés.
- ⚠️ **Non exécuté** : aucun test n'a été lancé (contrainte LXC). Les recettes A8/A10
  sont vérifiées par arithmétique manuelle ; à confirmer en CI conteneur jetable
  (`node:20` + vitest) avant tout GO de remédiation.
- ⚠️ **uTLS / clone TLS parfait** : hors périmètre du moteur (dépend du parser
  ClientHello et des signatures opérateur, cf. audit-parsers) ; supposé non-forgeable
  ici, ce qui est l'hypothèse du modèle de menace.
- ⚠️ **`http_inconsistencies` / `automation.inconsistencies`** : tableaux client
  pour les confessions ; un bot les envoie vides (auto-patch). C'est assumé par le
  modèle (les preuves serveur N2/N5 restent). Pas un finding.
