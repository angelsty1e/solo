---
name: audit-deps
description: >-
  Audit de sécurité EN PROFONDEUR des dépendances de l'application solo
  (Fingerprint Lab — TS/Fastify/Vite, npm, sans lockfile committé). Va bien
  au-delà d'un `npm audit` de surface : inventaire complet de l'arbre (directes +
  transitives), vulnérabilités connues recoupées sur plusieurs sources
  (npm audit + OSV + GitHub Advisory + CVE/NVD), analyse de la chaîne
  d'approvisionnement (scripts d'install, modules natifs, typosquatting,
  fraîcheur/dépréciation des paquets), deep-dive par dépendance avec sa surface
  d'attaque et son usage réel dans le code, durcissement de la configuration
  (helmet, rate-limit, fastify), licences, et supply chain du build/CI/Docker.
  Produit un rapport priorisé et actionnable. TRIGGER : "audite les dépendances",
  "audit sécurité des deps", "vérifier les vulnérabilités des librairies",
  "supply chain audit", "npm audit en profondeur", "sont-elles à jour / sûres ?".
---

# audit-deps — audit de sécurité en profondeur des dépendances (solo)

## 1. Objectif & philosophie

Auditer **chaque dépendance** de solo comme une **surface d'attaque**, pas comme
une ligne de `package.json`. Le but n'est PAS de coller un `npm audit` : c'est de
répondre, dépendance par dépendance, à :

1. **Quelles versions tournent réellement** (directes ET transitives) ?
2. **Sont-elles vulnérables** — et la vuln touche-t-elle un chemin de code qu'on
   utilise vraiment ?
3. **La chaîne d'approvisionnement est-elle saine** (provenance, scripts d'install,
   modules natifs, dépréciation, typosquatting, fraîcheur) ?
4. **Comment la dépendance est configurée et utilisée** dans le code — exécute-t-on
   ses primitives dangereuses sur de l'entrée non fiable ?
5. **Quel est le plan de remédiation priorisé** ?

### Threat model spécifique à solo (à garder en tête tout du long)
solo est un **lab de fingerprinting** : il **parse de l'entrée hostile par
conception** — `ClientHello` TLS brut, ordre/contenu d'en-têtes HTTP arbitraires,
payloads de collecteurs navigateur, fichiers GeoIP `.mmdb`. Les dépendances sur ce
chemin sont **prioritaires** :

| Dépendance | Pourquoi elle est en première ligne |
|---|---|
| `fastify` + `@fastify/*` | Parse le HTTP brut (headers, body), sert le trafic public |
| `zod` | Valide/parse des payloads non fiables — un bypass de validation = RCE-adjacent |
| `maxmind` | **Parse des fichiers `.mmdb` binaires** (désérialisation) |
| `better-sqlite3` | **Module natif compilé** (C++), postinstall, requêtes SQL |
| `@fastify/helmet`, `@fastify/rate-limit` | Contrôles de sécurité — une mauvaise config = protection illusoire |

Une vuln dans un paquet **uniquement utilisé au build** (`vite`, `esbuild`,
`typescript`, `eslint`, `gsap`) reste à signaler mais avec une criticité d'exécution
moindre — sauf si elle permet une compromission de la chaîne de build.

### Règles d'or
- **Aucune affirmation sans preuve.** Toute vuln citée = un identifiant
  (CVE/GHSA/OSV) + la version affectée + la version installée + le chemin dans
  l'arbre + le verdict « exploitable ici ou non, et pourquoi ».
- **Recouper les sources.** `npm audit` rate des choses et en sur-signale d'autres.
  Recouper avec OSV, GitHub Advisory et WebSearch.
- **Pas de cap silencieux.** Si tu ne peux pas analyser une transitive (trop
  profonde, source indispo), dis-le explicitement dans le rapport.

---

## 2. Pré-requis & comment exécuter les commandes

⚠️ **Pas de Node/npm en local** sur cette machine, et **pas de lockfile committé**
(`npm install` peut tirer des minors plus récentes → c'est en soi un point d'audit).

Exécute tous les outils npm dans un **conteneur `node:20` jetable** qui monte le
repo. Définis ce helper au début de l'audit (mentalement / dans le shell) :

```bash
# Depuis la racine du repo solo
NODEC='docker run --rm -v "$PWD":/app -w /app node:20'
# Exemple :
#   eval "$NODEC npm install --ignore-scripts"
#   eval "$NODEC npm audit --json"
```

> **Important — `--ignore-scripts` au premier install.** On audite des paquets dont
> on ne fait pas encore confiance aux scripts. Installe d'abord SANS scripts pour
> figer l'arbre, inspecte les `postinstall` (Phase 3), puis seulement après
> ré-installe normalement si `better-sqlite3` doit compiler.

Outils qu'on installera à la volée dans le conteneur (pas de pollution locale) :
- `npm audit` (intégré)
- `osv-scanner` (Google) — recoupe sur la base OSV, meilleure que `npm audit` sur
  les transitives. À défaut, requêtes à l'API OSV en `curl`.
- `npm-audit` n'a pas besoin de réseau-projet, juste du registre.

Quand un outil n'est pas installable (offline), **rabats-toi sur WebSearch +
WebFetch** des advisories GitHub/OSV/NVD pour chaque `(paquet, version)`.

---

## 3. Déroulé de l'audit (phases)

Traite les phases **dans l'ordre**. Coche au fur et à mesure. Le rapport final
(§4) agrège tout.

### Phase 0 — Cartographie & confirmation du threat model
- [ ] Lire `package.json` : lister directes (deps) vs dev-deps, repérer les
      versions **épinglées exactes** (bien) vs avec `^`/`~` (à flagger).
- [ ] Confirmer l'**absence de lockfile** (`package-lock.json` / `pnpm-lock.yaml`
      non committé). C'est une **constatation P1 supply-chain** : l'arbre installé
      n'est pas reproductible, et le `npm install` du CI / du Dockerfile peut tirer
      des transitives non auditées. Vérifier ce que fait le `Dockerfile` et
      `.github/workflows/ci.yml` (probablement `npm install` sans `--frozen`).
- [ ] Classer chaque dépendance par **zone d'exposition** : runtime-sur-entrée-hostile
      / runtime-interne / build-only (cf. tableau threat model).

### Phase 1 — Inventaire complet de l'arbre
- [ ] Générer l'arbre résolu : `eval "$NODEC npm install --ignore-scripts"` puis
      `eval "$NODEC npm ls --all --json"` (capturer en fichier pour analyse).
- [ ] Compter : nb de paquets directs vs **transitifs total** (la vraie surface).
- [ ] Identifier les **doublons de versions** (`npm ls <pkg>` qui apparaît en
      plusieurs versions) — vecteur de confusion et de bloat.
- [ ] Repérer les paquets **non épinglés** dont la version résolue diffère de ce
      qu'un `package.json` suggérait → conséquence directe du no-lockfile.
- [ ] **Recommandation transversale** à porter dans le rapport : committer un
      `package-lock.json` + passer le CI/Docker en `npm ci`.

### Phase 2 — Vulnérabilités connues (multi-sources, recoupées)
- [ ] `eval "$NODEC npm audit --json"` → parser : sévérité, paquet, plage
      vulnérable, chemin, advisory.
- [ ] **Recouper avec OSV** : `osv-scanner --lockfile=package-lock.json` (générer
      le lock dans le conteneur si besoin), OU pour chaque `(paquet, version)`
      critique, interroger l'API OSV :
      `curl -s -d '{"package":{"name":"<pkg>","ecosystem":"npm"},"version":"<v>"}' https://api.osv.dev/v1/query`.
- [ ] Pour CHAQUE dépendance **directe** (les 6 runtime + dev-deps sensibles),
      faire une **WebSearch ciblée** : `"<pkg> <version> CVE" / "<pkg> security advisory <année>"`
      et WebFetch l'advisory GitHub (`github.com/advisories`) — ne pas se fier au
      seul `npm audit`.
- [ ] Pour chaque vuln trouvée, statuer : **exploitable dans solo ?** Tracer le
      chemin de code (Phase 4). Une vuln dans une fonction jamais appelée →
      « présente mais non exploitable ici » (mais à patcher quand même par hygiène).
- [ ] Attention particulière aux deps **front exposées** au client (`gsap`, et tout
      ce que Vite bundle) vs serveur.

### Phase 3 — Chaîne d'approvisionnement (le cœur du "profondeur")
Pour chaque dépendance directe **et** chaque transitive notable :
- [ ] **Scripts d'installation** : lister tout `preinstall`/`install`/`postinstall`.
      `eval "$NODEC sh -c 'cat node_modules/*/package.json node_modules/*/*/package.json | grep -B2 -A2 \"install\"'"`
      ou plus proprement parser les `package.json` de `node_modules`. Tout script =
      **code arbitraire exécuté à l'install** → l'inspecter. `better-sqlite3` a
      légitimement un build natif (node-gyp/prebuild) ; vérifier qu'il télécharge
      un prebuild signé ou compile localement, et d'où.
- [ ] **Modules natifs** (`.node`, bindings C/C++) : `better-sqlite3` ici. Risques :
      compilation à l'install, prebuilds téléchargés depuis une URL externe,
      surface mémoire. Vérifier la provenance des prebuilds.
- [ ] **Provenance & santé du paquet** : pour chaque direct, `npm view <pkg>` →
      regarder `maintainers`, `time.modified`, `deprecated`, `dist.integrity`,
      nombre de versions, repo lié. Flagger : paquet **déprécié**, **non maintenu**
      (dernière publi > 18 mois sur un paquet sécurité), **maintainer unique**,
      **publié très récemment** (fenêtre typosquat/compromission).
- [ ] **Typosquatting / confusion** : vérifier que chaque nom correspond bien au
      paquet attendu (scope `@fastify/*` officiel, pas un fork). Méfiance sur toute
      transitive au nom proche d'un paquet populaire.
- [ ] **Fraîcheur vs épinglage** : `eval "$NODEC npm outdated --json"` → écart
      entre installé / wanted / latest. Une dep sécurité (`@fastify/helmet`,
      `@fastify/rate-limit`) en retard de major = à traiter.
- [ ] **Intégrité** : sans lockfile, pas de hash d'intégrité vérifié → le redire.

### Phase 4 — Deep-dive par dépendance (usage réel dans le code)
Pour chaque dépendance **runtime directe**, produire une fiche :
- [ ] **Rôle** dans solo + **où** elle est importée : `grep -rn "from '<pkg>'" src/`.
- [ ] **Surface d'attaque** : reçoit-elle de l'entrée non fiable ? (oui pour
      fastify/zod/maxmind/better-sqlite3).
- [ ] **APIs dangereuses utilisées** :
  - `fastify` / `@fastify/static` : path traversal sur le serveur statique,
    limites de body, parsing d'en-têtes ; vérifier `bodyLimit`, `@fastify/static`
    `root`/`prefix`/`allowedPath`.
  - `zod` : tous les payloads externes sont-ils validés AVANT usage ? Y a-t-il des
    `.passthrough()` / `z.any()` / parsing manquant ? (ReDoS sur regex zod ?)
  - `maxmind` : le `.mmdb` vient-il d'une source fiable ? Que se passe-t-il sur un
    fichier corrompu ? (le code gère-t-il l'erreur de parse — cf. README : ASN/Tor
    `null` si absent).
  - `better-sqlite3` : **requêtes paramétrées partout** ? Chercher toute
    concaténation de SQL : `grep -rn "prepare\|exec" src/server`. Pas de SQL
    construit par string interpolation sur de l'entrée user.
  - `@fastify/helmet` : quels en-têtes activés/désactivés ? CSP présente et stricte ?
  - `@fastify/rate-limit` : limites réelles, par route ? (cf. politique maison :
    ne pas relâcher les rate limits).
- [ ] **Verdict** : OK / durcissement requis / vuln exploitable → action.

### Phase 5 — Configuration & durcissement
- [ ] Relire la config Fastify d'instanciation : `trustProxy`, `bodyLimit`,
      `maxParamLength`, logger (ne pas logger de données sensibles / pas de PII —
      cohérent avec « le texte tapé n'est jamais enregistré »).
- [ ] CSP / helmet : vérifier qu'une CSP est posée (front qui exécute du JS de
      collecte). `@fastify/static` : pas de directory listing, root verrouillé.
- [ ] TLS : le serveur sert en HTTPS (cert self-signed) — versions TLS / ciphers ?
      (solo parse le ClientHello — vérifier que le parser maison ne plante pas sur
      entrée malformée, mais ça c'est code maison, hors deps).

### Phase 6 — Licences
- [ ] `eval "$NODEC npx license-checker --json"` (ou parser les champs `license`
      des `package.json` de `node_modules`). Flagger toute licence
      copyleft-forte/inattendue ou `UNLICENSED`/absente sur une transitive.

### Phase 7 — Supply chain du build / CI / Docker
- [ ] `Dockerfile` : image de base **pinnée par digest** ou tag flottant
      (`node:20` = flottant) ? `npm install` vs `npm ci` ? user non-root (l'entrypoint
      drop vers uid 10001 — bien) ? `--ignore-scripts` au build ?
- [ ] `.github/workflows/ci.yml` : actions tierces **pinnées par SHA** ou par tag
      (`actions/checkout@v4` = tag mutable → flagger) ? `npm install` non reproductible.
- [ ] `dependabot.yml` présent (oui) : couvre npm + docker + github-actions —
      le noter comme mitigation existante, mais rappeler qu'il ne remplace pas un
      lockfile.

### Phase 8 — Synthèse, scoring, remédiation
- [ ] Agréger toutes les findings, **dédupliquer**, **prioriser** :
  - **P0/Critique** : vuln exploitable sur le chemin d'entrée hostile (RCE,
    auth bypass, désérialisation, SQLi) OU compromission supply-chain active.
  - **P1/Élevé** : vuln runtime sérieuse mais mitigée/conditionnelle ; absence de
    lockfile ; module natif à provenance non vérifiée.
  - **P2/Moyen** : deps en retard de major, config à durcir, vuln build-only.
  - **P3/Faible** : hygiène, licences, fraîcheur.
- [ ] Pour chaque finding : **action concrète** (version cible, ligne de config,
      `npm install <pkg>@<safe>`), et **comment vérifier le fix**.

---

## 4. Format du rapport de sortie

Produire un rapport Markdown structuré ainsi :

```
# Audit sécurité des dépendances — solo (vX.Y.Z) — <date>

## Résumé exécutif
- Score global : N/10 — phrase de synthèse
- X findings : P0=… P1=… P2=… P3=…
- Top 3 actions immédiates

## 1. Inventaire
- Directes : N | Transitives : M | Doublons de version : …
- Lockfile : ABSENT (impact) | Épinglage : …

## 2. Vulnérabilités connues (recoupées npm audit / OSV / GitHub Advisory)
| Paquet | Ver. installée | ID (CVE/GHSA) | Sévérité | Chemin | Exploitable ici ? | Fix |

## 3. Chaîne d'approvisionnement
- Scripts d'install inspectés : …
- Modules natifs (better-sqlite3) : provenance prebuild = …
- Paquets dépréciés / non maintenus / maintainer unique : …
- Typosquat / anomalies : …

## 4. Fiches par dépendance runtime (fastify, @fastify/*, zod, maxmind, better-sqlite3)
### <pkg> — rôle / surface / APIs dangereuses / usage dans src / verdict

## 5. Configuration & durcissement (helmet, rate-limit, static, fastify, TLS)

## 6. Licences

## 7. Supply chain build/CI/Docker

## 8. Plan de remédiation priorisé (P0→P3) avec commandes et vérif
```

Respecter les préférences maison : **liste des fichiers modifiés à la fin** si le
skill applique des correctifs ; **bumper le semver** (back + front si applicable)
en cas de changement de deps ; **mettre le README à jour** si une instruction
d'install change.

---

## 5. Checklist de complétude (ne pas clore l'audit sans)
- [ ] Toutes les directes runtime ont une fiche §4.
- [ ] Chaque vuln a un ID + un verdict d'exploitabilité tracé dans le code.
- [ ] Les `postinstall`/scripts natifs ont été ouverts et lus, pas juste listés.
- [ ] Sources recoupées (≥ 2) pour chaque vuln P0/P1.
- [ ] Le point « pas de lockfile » est dans la synthèse avec sa remédiation.
- [ ] Tout ce qui n'a PAS pu être audité (transitive profonde, source offline) est
      listé explicitement — aucun cap silencieux.
- [ ] Plan de remédiation priorisé et exécutable.
