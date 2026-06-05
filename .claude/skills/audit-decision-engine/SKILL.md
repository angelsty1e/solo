---
name: audit-decision-engine
description: >-
  Audit de sécurité ADVERSARIAL et en profondeur du moteur de décision de solo
  (le cœur anti-bot : src/shared/decision/*, runDecision/analyze, niveaux N1–N5,
  crédit de confiance, config/seuils, validation zod en frontière /collect).
  Objectif : prouver que le verdict est IRRÉPROCHABLE sur trois axes — (1) aucun
  bot ne peut forger un verdict 'human'/'clean', (2) aucun humain réel n'est
  classé 'bot' (faux positifs), (3) le scoring est sain, déterministe, traçable
  et non manipulable via les champs contrôlés par le client. Mène une campagne de
  red-team (payloads d'évasion, fabrication des signaux de confiance et des
  agrégats comportementaux, gaming de la réputation), vérifie les invariants
  mathématiques, traque les faux positifs (Mac/Safari/Firefox/mobile/VPN), audite
  la frontière de validation (bornes, NaN/Infinity), la sûreté du tuning
  (resolveConfig/validateConfig/hash de version) et la pureté/déterminisme. Produit
  un rapport priorisé + des tests de régression à ajouter à tests/decision.test.ts.
  TRIGGER : "audite le moteur de décision", "le moteur de décision doit être
  irréprochable", "teste la robustesse du verdict / anti-bot", "peut-on contourner
  la détection ?", "faux positifs du scoring", "red-team du decision engine".
---

# audit-decision-engine — le verdict doit être irréprochable

## 1. Ce qu'on protège (propriété de sécurité)

Le moteur de décision est le **cœur** de solo : il transforme une empreinte en
verdict `'bot' | 'suspect' | 'clean' | 'human' | 'unknown'`. « Irréprochable »
signifie que les **trois** propriétés suivantes tiennent, et l'audit doit
chercher activement à les casser :

1. **Soundness anti-évasion (faux négatifs)** — *aucun* attaquant ne doit pouvoir
   fabriquer un payload classé `'human'` ou `'clean'` alors que c'est un bot.
   C'est la propriété la plus critique : un verdict positif forgé = échec total.
2. **Soundness anti-faux-positif** — un *vrai* humain (Mac/Safari, Firefox, mobile,
   derrière VPN/voyageur, avec extension vie privée, VM utilisée par un humain) ne
   doit pas être classé `'bot'`. Le code porte déjà des régressions Mac/Safari →
   c'est un risque réel et récurrent.
3. **Soundness du scoring** — déterministe (même entrée → même verdict),
   monotone (ajouter un tell ne doit jamais *réduire* la suspicion), borné
   (scores ∈ [0,1]), traçable (version + hash de config persistés), et **non
   manipulable** par les champs que le client contrôle.

> Si une seule des trois tombe, le moteur n'est pas irréprochable. L'audit ne se
> clôt pas tant qu'on n'a pas, pour chacune, soit une preuve de tenue, soit une
> finding documentée + un test de régression.

---

## 2. Threat model du moteur — la surface réelle

`analyze(full)` dérive un `DecisionInput` puis appelle `runDecision`. **Distingue
impérativement deux classes de données**, car c'est là que se joue l'évasion :

| Donnée | Origine | Forgeable par un bot ? |
|---|---|---|
| `automation` (webdriver, playwrightHints, cdpHints, selenium…) | JS client | **Oui** — mais les aveux *durs* sont ce qu'un headless patché supprime justement en premier |
| `client.navigator / screen / locale / canvas / webgl / fonts / speech / mediaDevices / mediaCapabilities / engine / webrtc …` | JS client (payload `/collect`) | **OUI, entièrement** — validé en *type* par zod, pas en *plausibilité* |
| `client.behavioral` (mouse.meanCurvature, jitterRatio, stdSpeed, keyboard.std*…) | **agrégé côté client** puis envoyé | **OUI** — ce sont des nombres dans le payload, pas une mesure serveur |
| `tls` (JA3/JA4, ALPN, ciphers) | **serveur**, capturé au ClientHello | **Non** (hors usurpation de pile TLS) |
| `http` (ordre/incohérences d'en-têtes, Accept-Language, Sec-CH-UA) | **serveur** | **Non** (le serveur observe le vrai) |
| `ip` (ASN, datacenter, proxy, Tor, rDNS, RTT) | **serveur** (MaxMind/Tor list) | **Non** |
| `reputation` (fpDistinctIps) | **serveur** (requête store) | Partiellement (dépend des hashes client) |

### Le risque structurel n°1 à instruire (hypothèse de travail, à confirmer/réfuter)
Le **crédit de confiance** (`computeTrust`, trust.ts) et le **niveau 4
(comportement)** lisent presque exclusivement des données **client-fabricables**.
Or `engine.ts` calcule :

```
netSuspicion = forced ? 1 : clamp01(botScore − offsetFactor * trust.score)
```

avec `offsetFactor: 1.0` et **seul un aveu dur N1 (`forced`) est immunisé**. Donc :

- Un **headless patché** qui supprime les aveux N1 durs (webdriver/CDP/Playwright)
  ne laisse que des présomptions **N2 (TLS/IP, non forgeables) + N3/N5**.
- Mais il peut **fabriquer le crédit de confiance** : envoyer une chaîne GPU
  matérielle (`trust_hardware_gpu`), une liste de polices riche
  (`trust_fonts_rich`), des voix/périphériques (`trust_speech_voices`,
  `trust_media_devices`), une identité « cohérente » (`trust_identity_coherent`),
  et surtout des **agrégats comportementaux organiques fabriqués**
  (`trust_behavior_human` : `mouse.moves≥25, meanCurvature>0, jitterRatio>0,
  stdSpeed>0`) → ce dernier vaut 0.5 = `humanThreshold` ET porte le `liveness`.
- Résultat possible : `trust.score` monte, `netSuspicion` est *réduit* de la même
  quantité, et un bot dont la pile TLS le trahit (N2, `tls_ua_mismatch` = 0.7)
  peut basculer `bot → suspect → clean`, voire décrocher `'human'` si
  `trust ≥ 0.5 ∧ liveness`. **Une donnée non-forgeable (TLS serveur) se fait
  annuler par une donnée forgeable (comportement client).**

**L'audit DOIT trancher cette question par des tests adversariaux concrets** (Phase
2 + Phase 5) et, si elle est confirmée, proposer la remédiation (cf. §5).

---

## 3. Invariants à vérifier (liste de contrôle formelle)

Pour chacun : écrire/exécuter un test qui tente de le violer.

- **I1 — Immunité de l'aveu dur** : un `forced` (hard N1) ⇒ `verdict='bot'` ET
  `score=1`, quel que soit le crédit de confiance (même `trust=1`). *(testé ?)*
- **I2 — Bornage** : tout `score`, `trustScore`, `confidence` ∈ [0,1]. Aucune
  entrée (y compris `Infinity`/valeurs absurdes) ne sort de [0,1].
- **I3 — Monotonie de la suspicion** : ajouter un tell bot (ou augmenter un poids
  qui fire) ne doit JAMAIS faire baisser `botScore`. Ajouter un signal de confiance
  ne doit jamais *augmenter* `netSuspicion`.
- **I4 — Pas de 'human'/'clean' sous aveu** : si un signal *hard* a fire,
  `verdict` ∈ {'bot'} (jamais 'human'/'clean'/'suspect').
- **I5 — 'human' exige liveness** (si `requireLiveness`) : pas de `'human'` sans
  qu'un signal `liveness` ait fire.
- **I6 — Déterminisme/pureté** : `runDecision(input, cfg, computedAt)` est une
  fonction pure — même `(input,cfg,computedAt)` ⇒ résultat identique au champ
  près. Aucun `Date.now()`/`Math.random()` dans le chemin pur (seul `computedAt`
  par défaut touche l'horloge, et il est injectable).
- **I7 — Traçabilité** : `configVersion` = label + hash FNV-1a du contenu réel des
  règles ; retuner un poids sans bumper le label DOIT changer le hash.
- **I8 — 'unknown' bien cadré** : `'unknown'` seulement quand aucun niveau ni
  signal de confiance n'a rien produit.
- **I9 — Frontière de validation** : tout `DecisionInput` issu d'un payload qui
  passe `ClientFingerprintSchema` ne doit pas faire planter `analyze` ni produire
  un `NaN` dans le score (vérifier NaN/Infinity, tableaux vides, `null` partout).

---

## 4. Déroulé de l'audit (phases)

Outillage : le moteur est **JS/TS pur** ⇒ test via **vitest** sur `runDecision` /
`evaluateLevel` / `computeTrust` / `resolveConfig` directement (déjà la structure
de `tests/decision.test.ts`, 723 lignes — l'étendre, pas repartir de zéro).

Pas de Node/npm en local ⇒ exécuter dans un conteneur jetable :
```bash
NODEC='docker run --rm -v "$PWD":/app -w /app node:20'
eval "$NODEC sh -c 'npm install --ignore-scripts && npx vitest run'"
```
Pour les nouveaux tests adversariaux, créer `tests/decision-adversarial.test.ts`
(garder les régressions séparées des tests de comportement nominal).

### Phase 0 — Cartographier le moteur (établir la vérité terrain)
- [ ] Lister tous les signaux par niveau (`ALL_SIGNALS`) avec leur `detect`, leur
      poids (config.ts) et leur sévérité (hard/soft). Repérer **quels signaux lisent
      des champs client-forgeables vs serveur** (cf. tableau §2).
- [ ] Noter les seuils : `aggregate.block=0.8`, `review=0.4` ; `trust.offsetFactor=1.0`,
      `humanThreshold=0.5`, `requireLiveness=true`.
- [ ] Cartographier le poids des signaux de confiance et **calculer la somme des
      poids forgeables** : peut-elle à elle seule atteindre `humanThreshold` (0.5) ?
      atteindre 1.0 (annulation maximale) ? (`trust_behavior_human`=0.5 suffit déjà
      pour le seuil + liveness — à confirmer.)

### Phase 1 — Vérifier les invariants I1–I9 (property-based)
- [ ] Un test par invariant. Pour I2/I3/I9, générer des entrées par mutation/fuzz :
      partir d'un input neutre et faire varier chaque champ numérique (0, négatif,
      `Infinity`, `NaN`, très grand), chaque tableau (vide, énorme), chaque `null`.
- [ ] I3 (monotonie) : prendre un input, fire un signal de plus, asserter
      `botScore' ≥ botScore`. Faire pareil pour le crédit (jamais d'effet pervers).
- [ ] I6 : appeler `runDecision` 2× avec même `(input,cfg,computedAt)` → deep-equal.
      Grep le chemin pur pour tout `Date`/`Math.random` non injecté.
- [ ] I7 : muter un poids via `resolveConfig`, vérifier que `versionTag` change.

### Phase 2 — Red-team : ÉVASION (le cœur du « irréprochable »)
Construire une batterie de **personas attaquants**. Pour chacun, l'assertion est :
**`verdict ∉ {'human','clean'}`** (idéalement `∈ {'bot','suspect'}`).

- [ ] **A1 — Headless patché + comportement fabriqué** : `automation` propre (aucun
      aveu dur), `tls_ua_mismatch` qui fire (pile non-navigateur + UA navigateur),
      MAIS `behavioral.mouse` fabriqué organique (`moves=40, meanCurvature=0.3,
      jitterRatio=0.2, stdSpeed=5`) + GPU matériel + fonts riches. **Le verdict
      bascule-t-il à 'human'/'clean' ?** ⇒ si oui = finding P0 (TLS non-forgeable
      annulé par comportement forgeable).
- [ ] **A2 — Datacenter + trust forgé** : `ip.isDatacenter=true` (N2=0.4) +
      `ip_tor`/`ip_proxy`, contre un crédit de confiance fabriqué. Le bot d'un
      datacenter peut-il décrocher 'clean'/'human' en mentant sur GPU/fonts/voix/
      comportement ?
- [ ] **A3 — N3 max annulé** : empiler plusieurs contradictions N3 (software GPU,
      langues vides, écran headless…) puis fabriquer le crédit. La présomption
      d'environnement se fait-elle effacer ?
- [ ] **A4 — Essaim N5 annulé** : `reputation.fpDistinctIps=12` (swarm, N5→1.0)
      contre trust forgé. Une ferme de bots peut-elle blanchir son essaim ?
- [ ] **A5 — Liveness forgée seule** : input par ailleurs vide, juste
      `behavioral.mouse` organique fabriqué → décroche-t-il 'human' « gratuitement » ?
      (rappel : `clean` ≠ `human`, mais 'human' affirme positivement l'humanité).
- [ ] **A6 — Identité cohérente forgée** : tout aligner (platform↔UA, langues,
      client-hints) pour gagner `trust_identity_coherent` (0.2) ; cumuler avec A5.
- [ ] **A7 — Contournement par omission** : envoyer `canvas=null`/`webgl=null` pour
      **échapper à la réputation N5** (clé null ⇒ `fingerprintReputation` renvoie
      0/0) sans déclencher `env_render_surfaces_absent` (qui exige les *trois* nuls).
- [ ] Pour chaque évasion réussie : **documenter la recette exacte** (payload
      minimal), la classer P0, et écrire le test de régression qui la fige.

### Phase 3 — Faux positifs : ne PAS inculper un humain
Personas **humains légitimes** ; assertion : **`verdict ≠ 'bot'`** (et idéalement
'human'/'clean'). Réutiliser/étendre les régressions Mac/Safari existantes.
- [ ] **H1 — Mac/Safari** : pas de userAgentData (Client Hints = Chromium only),
      stack JS au format `fn@…` (≠ V8) — ne doit pas fire `env_engine_ua_mismatch`
      ni `env_uadata_incoherent` (déjà couvert ; vérifier non-régression).
- [ ] **H2 — Firefox desktop** : pas de chrome.runtime, pas de Client Hints, pas de
      WebGPU → aucun signal Chromium-only ne doit fire.
- [ ] **H3 — Mobile** (Android/iPhone) : `env_speech_no_voices`, `env_no_media_devices`,
      `env_webgpu_absent` sont gardés `!isMobileUa` — vérifier qu'ils ne firent pas ;
      attention au `rtt_incoherence` (RTT<2ms + UA mobile) sur un vrai mobile en wifi
      local.
- [ ] **H4 — Voyageur / VPN** : `env_locale_ip_mismatch` (0.2) seul ne doit jamais
      passer 'suspect'→'bot'. Un humain derrière VPN datacenter (`ip_datacenter`
      0.4) + locale mismatch (0.2) reste sous le seuil bloc.
- [ ] **H5 — Extension vie privée** : canvas bloqué seul, permissions partiellement
      refusées — ne doit pas suffire.
- [ ] **H6 — Humain peu actif** : 0 interaction → `beh_no_interaction` (0.2) ne doit
      pas suffire à 'bot' ; et l'absence de liveness ⇒ au pire 'clean', jamais 'bot'.
- [ ] Pour chaque faux positif trouvé : finding (sévérité selon la fréquence du
      profil) + test de régression.

### Phase 4 — Soundness du scoring (maths)
- [ ] **Frontières de seuils** : tester `score` exactement à 0.4 et 0.8 (≥ vs >) sur
      chaque niveau et à l'agrégat — vérifier que la frontière est celle voulue.
- [ ] **Accumulation & cap** : N3 a 16 signaux, Σpoids ≫ 1 ; vérifier `Math.min(1,…)`
      partout et que le cap n'introduit pas de non-monotonie.
- [ ] **offsetFactor** : valider que `netSuspicion = clamp01(botScore − offset*trust)`
      se comporte comme spécifié aux extrêmes (trust=0, trust=1, botScore=1 non-forced).
- [ ] **Escalade intra-niveau N5** : `rep_fp_many_ips`(0.6)+`rep_fp_swarm`(0.4)=1.0
      → 'bot' niveau, mais à l'agrégat le `max` inter-niveaux + offset trust : un
      swarm seul (botScore=1, non forced) peut-il être ramené sous 0.8 par trust ?

### Phase 5 — Intégrité du crédit de confiance (cœur de la remédiation)
- [ ] **Classer chaque `TRUST_SIGNAL`** : la donnée lue est-elle vérifiée serveur ou
      déclarée client ? (Attendu : seul `trust_residential_ip` est serveur ; tous
      les autres, dont `trust_behavior_human`, sont client-déclarés.)
- [ ] **Quantifier le pouvoir d'annulation forgeable** : somme des poids des trust
      signals forgeables = combien ? ≥ `humanThreshold` ? = jusqu'où peut tomber
      `netSuspicion` d'un bot N2/N3/N5 ?
- [ ] **Statuer** : le crédit de confiance peut-il annuler des présomptions issues
      de données **non-forgeables** (TLS/IP/réputation serveur) ? Si oui → P0.
- [ ] **Proposer la remédiation** (au moins une, à discuter avec Johann avant
      implémentation — ne pas présumer le GO) :
  - (a) **Le crédit ne peut annuler que la suspicion d'origine client** (N3/N4) ;
        protéger N2 (TLS/IP) et N5 (réputation) de l'offset — un mensonge client
        ne doit pas effacer une preuve serveur.
  - (b) **Plafonner `offsetFactor`** et/ou n'autoriser 'human' que si au moins un
        trust signal **serveur** corrobore (résidentiel) en plus de la liveness.
  - (c) **Ne pas créditer le comportement comme liveness** tant qu'il est agrégé
        client : soit recalculer côté serveur à partir d'événements bruts, soit le
        dégrader en signal faible non-liveness.

### Phase 6 — Sûreté du tuning / config
- [ ] `resolveConfig` : merge *shallow* par niveau — un override partiel d'un niveau
      **écrase-t-il `hardSignals`/`weights` non fournis** ? (un `{level:1, enabled:false}`
      garde-t-il les hardSignals ? oui car spread base ; un `{level:1, weights:{…}}`
      remplace TOUT `weights` → des hard signals deviennent inertes ? tester.)
- [ ] `validateConfig` : couvre ids inconnus, signaux inertes, poids>1. **Ne couvre
      PAS** : un hard signal retiré par erreur, Σpoids d'un niveau qui passe le bloc
      avec un seul signal, override qui casse un niveau. Lister les trous.
- [ ] **Source de l'override** : `analyze()` est appelé avec `config=defaultConfig`
      par la route — vérifier qu'aucun chemin ne laisse un override **client/non
      fiable** atteindre `resolveConfig` (sinon un attaquant retune le moteur).
- [ ] Vérifier que `warnConfig` au chargement ne fait que `console.warn` (pas de
      crash) et que le label `version` est cohérent avec le hash.

### Phase 7 — Frontière de validation (validation.ts ↔ moteur)
- [ ] **NaN/Infinity** : les agrégats comportementaux (`meanCurvature`, `stdSpeed`,
      `linearRatio`…) sont `z.number()` **sans `.finite()`** → `Infinity` passe le
      schéma. Tracer l'effet sur les `detect` (`meanCurvature>0` vrai pour Infinity ;
      `linearRatio>=0.99` ; un score peut-il devenir `NaN` ?). Recommander `.finite()`
      + bornes [0,1] sur les ratios.
- [ ] **Cohérence schéma ↔ types** : `ClientFingerprintSchema` doit refléter
      `ClientFingerprint` ; un champ que le moteur lit mais que le schéma autorise
      en valeur absurde = trou. Vérifier `.strict()` au top-level (anti-injection de
      colonnes) et le strip des clés imbriquées.
- [ ] **UA contradictoire** : `userAgent` côté client vs `http.userAgent` serveur —
      `analyze` préfère le client ; un bot peut envoyer un UA JS différent de l'UA
      HTTP pour aiguiller les signaux. Tester l'effet sur N1/N2/N3.

### Phase 8 — Synthèse, scoring, régressions
- [ ] Agréger les findings, prioriser :
  - **P0** : toute évasion confirmée (bot → 'human'/'clean') ; crédit forgeable
    annulant une preuve serveur ; override non fiable atteignant la config.
  - **P1** : faux positif sur un profil humain courant ; `NaN`/Infinity exploitable ;
    trou de `resolveConfig` rendant des hard signals inertes.
  - **P2** : faux positif sur profil rare ; trou de `validateConfig` ; non-monotonie
    bénigne ; traçabilité incomplète.
  - **P3** : hygiène, lisibilité des seuils, commentaires trompeurs.
- [ ] Pour CHAQUE finding : payload/recette de repro, correctif proposé, et **test
      de régression** ajouté à `tests/decision-adversarial.test.ts` (rouge avant fix,
      vert après).
- [ ] Rappeler que toute modif du moteur = **bump semver** (back, et front si version
      alignée) + **MAJ README** si comportement observable change + **liste des
      fichiers modifiés** en fin de session (préférences maison). Ne PAS implémenter
      les remédiations P0 sans GO explicite de Johann.

---

## 5. Format du rapport de sortie

```
# Audit du moteur de décision — solo (config <versionTag>) — <date>

## Verdict de l'audit
- Irréprochable ? OUI / NON — sur quel(s) axe(s) il échoue
- Évasions confirmées : N (P0) — recette de la pire
- Faux positifs : N — profils touchés
- Invariants violés : I? …

## 1. Cartographie (signaux × niveau × poids × forgeable serveur/client)

## 2. Évasions (red-team) — tableau : persona | payload | verdict obtenu | attendu | sévérité

## 3. Faux positifs — persona humain | signaux qui firent à tort | verdict | sévérité

## 4. Invariants & maths — I1..I9 : tenu / violé + preuve

## 5. Intégrité du crédit de confiance — pouvoir d'annulation forgeable, recommandation (a/b/c)

## 6. Config/tuning & validation — trous de resolveConfig/validateConfig, NaN/Infinity

## 7. Plan de remédiation priorisé (P0→P3) + tests de régression ajoutés
```

---

## 6. Checklist de complétude (ne pas clore sans)
- [ ] Les 9 invariants ont un test (tenu OU finding+repro).
- [ ] ≥ 7 personas attaquants exécutés (A1–A7) avec verdict asserté.
- [ ] ≥ 6 personas humains exécutés (H1–H6) sans faux positif, ou findings.
- [ ] La question « le crédit de confiance forgeable peut-il annuler une preuve
      serveur (TLS/IP/réputation) ? » est tranchée par un test, pas par intuition.
- [ ] NaN/Infinity à la frontière validation.ts testés.
- [ ] resolveConfig (override partiel) et la non-atteignabilité d'un override non
      fiable depuis la route vérifiés.
- [ ] Tout ce qui n'a PAS pu être couvert est listé explicitement (aucun cap muet).
- [ ] Chaque finding a un test de régression dans tests/decision-adversarial.test.ts.
- [ ] Remédiations P0 proposées mais NON implémentées sans GO de Johann.
