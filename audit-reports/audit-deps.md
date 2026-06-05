# Audit sécurité des dépendances — solo (v1.3.0) — 2026-06-05

> Audit en lecture seule. Aucun `npm install`/build exécuté en local (projet déployé
> sur LXC). Versions vérifiées contre le registre npm + OSV API (api.osv.dev) +
> GitHub Advisory + NVD. Aucun lockfile committé : les versions transitives ci-dessous
> sont **résolues au plus haut satisfaisant les plages `^`** des `package.json` amont,
> pas une garantie de ce qui tournera réellement.

## Résumé exécutif

- **Score global : 6.5/10** — Le code applicatif est sain (SQL 100 % paramétré,
  zod `.strict()` sur la seule entrée hostile, helmet/CSP/rate-limit correctement
  posés, static verrouillé, pas de XFF spoofable). La dette est sur **l'arbre de
  dépendances** : `fastify` est sur une **majeure non maintenue (4.x)** qui ne
  reçoit plus les patchs de sécurité, et **aucun lockfile** ne fige l'arbre.
- **11 findings** : **P0 = 0** · **P1 = 3** · **P2 = 4** · **P3 = 4**
- **Top 3 actions immédiates** :
  1. **Migrer Fastify 4.28.1 → 5.8.5** (+ bumper `@fastify/helmet`→13, `rate-limit`→10,
     `static`→9). La 4.x est EOL et **3 CVE 2026 ne sont corrigées que sur la 5.x**.
  2. **Committer un `package-lock.json` et passer Docker en `npm ci`** (Phase 0/7).
  3. **Bumper les dev-deps build** (`vitest`→4.1, `vite`→5.4.20+, `esbuild`≥0.25)
     pour fermer les CVE dev-server (impact build-only, mais hygiène CI).

---

## 1. Inventaire

| | |
|---|---|
| Dépendances directes runtime | **7** (`fastify`, `@fastify/helmet`, `@fastify/rate-limit`, `@fastify/static`, `better-sqlite3`, `maxmind`, `zod`) |
| Dev-deps | **12** (`vite`, `vitest`, `tsx`, `typescript`, `eslint`, `typescript-eslint`, `gsap`, `prettier`, `pino-pretty`, `@types/*`) |
| Transitives | non figées — **pas de lockfile** (voir P1-2) |
| Épinglage `package.json` | **exact partout** (bien — pas de `^`/`~` dans solo) |
| Lockfile committé | **ABSENT** (ni `package-lock.json`, ni `pnpm-lock.yaml`) |
| `node_modules` local | absent (rien à inspecter sur disque) |

**Constat structurant — pas de lockfile (P1).** `package.json` épingle les *directes* à
l'exact, mais les **transitives** sont déclarées en `^` chez les paquets amont. Sans
lock, le `npm install` du Dockerfile (ligne 17, branche `else npm install`) résout à
chaque build les transitives au plus haut compatible → arbre **non reproductible** et
**non audité**. Exemple concret : `fastify@4.28.1` déclare `find-my-way ^8.0.0`,
`@fastify/send ^2`, `secure-json-parse ^2.7.0` → une future 8.x/2.x compromise ou
vulnérable serait tirée silencieusement.

Pas de doublons de version observables (analyse statique de l'arbre amont ; sans
lockfile l'observation réelle est impossible — **cap explicite assumé**).

---

## 2. Vulnérabilités connues (recoupées npm registry / OSV / GitHub Advisory / NVD)

### Runtime — `fastify@4.28.1` (3 advisories, branche 4.x **non patchée**)

| ID | Sévérité | Plage corrigée | Exploitable dans solo ? |
|---|---|---|---|
| **GHSA-jx2c-rxcm-jvmq** / CVE-2026-25223 — bypass de validation de body via tab (`\t`) dans `Content-Type` | HIGH (CVSS 7.5) | **5.7.2** | **Non directement** : solo ne s'appuie PAS sur la validation de schéma *par Content-Type* de Fastify — `/collect` revalide tout via `ClientFingerprintSchema.safeParse(req.body)` (zod `.strict()`). Le bypass Fastify ne contourne donc pas la barrière zod. **À patcher par hygiène** (le body resterait parsé en JSON même avec un Content-Type forgé). |
| **GHSA-444r-cwp2-x5xf** / CVE-2026-3635 — `request.protocol`/`request.host` spoofables via `X-Forwarded-*` | MODERATE (CVSS 6.x) | **5.8.3** | **Non** : solo tourne `trustProxy:false` (index.ts:81) et n'utilise jamais `req.protocol`/`req.host` pour une décision de sécurité ; l'IP réelle vient de la side-map du proxy TLS, pas de XFF (routes.ts:37-47). Vuln **inerte ici**. |
| **GHSA-mrq3-vjjr-p77c** / CVE-2026-25224 — DoS mémoire via `ReadableStream` dans `reply.send()` | LOW | **5.7.3** | **Non** : solo ne renvoie jamais de Web Stream (réponses JSON/HTML/`readFileSync` bufferisées). Inapplicable. |

> **Le point clé n'est pas l'exploitabilité immédiate (faible) mais la maintenance.**
> Les trois correctifs n'existent **que sur la 5.x**. La branche 4.x est en fin de vie
> (dernière 4.x = **4.29.1**, avril 2025) et **ne reçoit plus de backport**. solo est
> en outre sur **4.28.1**, soit un cran derrière même la dernière 4.x. Rester en 4.x
> = accumuler les futures CVE non corrigées → **P1**.

### Transitives runtime — résolues sous les contraintes de fastify 4.28.1 / plugins

Toutes **clean** sur OSV aux versions résolues : `find-my-way@8.2.2`, `@fastify/send@2.1.0`,
`secure-json-parse@2.7.0`, `@fastify/error@3.4.1`, `fast-content-type-parse@1.1.0`,
`fast-json-stringify@5.16.1`, `@fastify/ajv-compiler@3.6.0`, `pino@9.14.0`, `avvio@8.4.0`,
`light-my-request@5.14.0`, `glob@10.5.0`, `content-disposition@0.5.4`, `helmet@7.2.0`,
`mmdb-lib`, `tiny-lru`, `prebuild-install@7.1.x`, `bindings@1.5.0`, `proxy-addr@2.0.7`,
`semver@7.x`. **Aucune CVE connue** sur le chemin runtime hors fastify-core.

### Dev/build-deps — CVE présentes mais **build-only** (P2/P3)

Le Dockerfile **prune les devDeps** (`npm prune --omit=dev`, ligne 25) → **rien de ceci
n'atteint l'image runtime**. Exploitation nécessite d'exécuter l'outil dev (serveur Vite,
API/UI Vitest) ET de visiter un site hostile — scénario poste-dev, pas production.

| Paquet | Ver. | ID notable | Sévérité | Nature |
|---|---|---|---|---|
| `vitest` | 2.0.5 | **GHSA-5xrq-8626-4rwp** (UI server → lecture/exécution de fichier arbitraire) | **CRITICAL** | dev-server `vitest --ui`. Corrigé en **4.1.0**. (NB : la 2e critique GHSA-9crc ne touche que 1.0–1.6.1 → **2.0.5 non concernée**.) |
| `vite` | 5.3.3 | 13 advisories (dont **GHSA-c27g-q93r-2cwf** launch-editor cmd-injection Windows) | HIGH/MOD | `vite dev`. Corrigés sur les 5.4.x patch (≥5.4.20). |
| `esbuild` | 0.21.5 | **GHSA-67mh-4wv8-2f99** (dev-server CORS large) | MODERATE | transitive de vite. Corrigé en **0.25.0**. |

`tsx`, `typescript`, `eslint`, `typescript-eslint`, `gsap`, `prettier`, `pino-pretty`,
`@types/*` : **clean** sur OSV aux versions épinglées.

---

## 3. Chaîne d'approvisionnement

- **Scripts d'install** : un seul paquet runtime a un script — **`better-sqlite3@11.3.0`** :
  `"install": "prebuild-install || node-gyp rebuild --release"`. Comportement : tente de
  télécharger un **prebuild** depuis les **GitHub Releases de WiseLibs/better-sqlite3**
  (publisher `joshuawise`, mainteneur historique), sinon **compile localement** via node-gyp
  (le Dockerfile builder installe `python3/make/g++` à cet effet, lignes 10-12). Provenance
  = repo officiel `git://github.com/WiseLibs/better-sqlite3.git`. **Pas de prebuild depuis
  une URL tierce/obscure.** Risque résiduel : sans lockfile + sans `--ignore-scripts`, le
  script tourne sur la version résolue ; le pin exact de `better-sqlite3` limite ça à la
  11.3.0. *Recommandation* : le builder Docker pourrait passer `--ignore-scripts` puis
  reconstruire explicitement, ou pinner via lockfile + intégrité.
- **Module natif** : `better-sqlite3` (C++/`.node`) — seul binaire natif. Surface mémoire
  réelle, mais **n'est jamais exposé à de l'entrée hostile via SQL** : 100 % requêtes
  paramétrées (voir §4). Les `.mmdb` (entrée binaire) sont parsés par **`mmdb-lib` (JS pur)**,
  pas par un natif.
- **Santé / fraîcheur des paquets** (registre npm, juin 2026) :

  | Paquet | Installé | Latest | Écart | Déprécié ? |
  |---|---|---|---|---|
  | `fastify` | 4.28.1 | **5.8.5** | **majeure EOL** + retard intra-4.x (4.29.1) | non, mais 4.x non maintenue |
  | `@fastify/helmet` | 11.1.1 | **13.0.2** | 2 majeures | non |
  | `@fastify/rate-limit` | 9.1.0 | **10.3.0** | 1 majeure | non |
  | `@fastify/static` | 7.0.4 | **9.1.3** | 2 majeures | non |
  | `better-sqlite3` | 11.3.0 | 12.10.0 | 1 majeure | non |
  | `maxmind` | 4.3.20 | 5.0.6 | 1 majeure | non |
  | `zod` | 3.23.8 | 4.4.3 | 1 majeure | non |
  | `vite` | 5.3.3 | 7.x | 2 majeures + patchs sécu | non |
  | `vitest` | 2.0.5 | 4.x | 2 majeures + critique | non |

- **Typosquatting / confusion** : aucun. Tous les `@fastify/*` sont le scope officiel ;
  noms exacts des paquets attendus. Aucune transitive au nom suspect.
- **Maintainer unique** : `better-sqlite3` est très centré sur `joshuawise` (typique de ce
  paquet, mature et largement audité) — à noter, pas bloquant.
- **Intégrité** : **sans lockfile, aucun hash d'intégrité (`dist.integrity`) n'est vérifié
  à l'install** → redit comme conséquence P1 du no-lockfile.

---

## 4. Fiches par dépendance runtime

### `fastify@4.28.1` — serveur HTTP, parse le trafic public
- **Importé** : `src/server/index.ts` (instanciation), `routes.ts` (types).
- **Surface** : maximale — parse en-têtes/body bruts, sert tout le trafic public sur :8443.
- **Config** (index.ts) : `bodyLimit: 512KiB` (bon, cap /collect), `trustProxy:false`
  (bon — neutralise CVE-2026-3635 et le spoof XFF), error-handler central qui **ne fuit
  jamais de stack** (5xx → `{error:'internal server error'}`), logger `redact` cookie/auth.
- **Verdict** : **config exemplaire**, mais **majeure EOL → migrer en 5.x (P1)**.

### `@fastify/helmet@11.1.1` — en-têtes de sécurité / CSP
- **Importé** : `src/server/index.ts:6,87`.
- **Config** : CSP **stricte et explicite** — `default-src 'self'`, `script-src 'self'`
  (pas de `unsafe-inline` JS), `object-src 'none'`, `frame-ancestors 'none'`, `base-uri
  'self'`, `form-action 'self'`. Seul relâchement : `style-src 'unsafe-inline'` (styles
  inline du recap) — acceptable, n'autorise pas de script. `hsts:false` assumé (cert
  self-signed sur lab). **Verdict : OK**, durcissement non requis. (Bump majeur à 13.x à
  faire avec la migration fastify 5.)

### `@fastify/rate-limit@9.1.0` — anti-abus
- **Importé** : `src/server/index.ts:7,111`.
- **Config** : global **120/min**, `/collect` resserré à **15/min** (routes.ts:172), clé =
  **vraie IP** récupérée via `rateLimitKeyForSocket` (la side-map du proxy, pas `req.ip`
  toujours = 127.0.0.1). Fallback documenté : requête non-clé → token **par-connexion**,
  jamais un bucket partagé. `/healthz` **non exempté** (volontaire). **Verdict : OK, solide.**

### `@fastify/static@7.0.4` — service d'assets
- **Importé** : `src/server/routes.ts:6,96`.
- **Config** : `root = dist/client/assets`, `prefix='/assets/'`, `decorateReply:false`.
  Root verrouillé sur un sous-dossier, pas de directory-listing, `index.html`/`recap.html`
  servis manuellement via `readFileSync` (pas par le static). **Pas de path traversal**
  exposé. **Verdict : OK.**

### `better-sqlite3@11.3.0` — persistance SQLite (natif)
- **Importé** : `src/server/db.ts:3`, usage dans `store.ts`.
- **Surface SQL** : **toutes les requêtes sont paramétrées** (`?` positionnels ou `@named`).
  `grep` confirme : aucune interpolation `${}` dans `store.ts`/`db.ts`, aucun SQL construit
  par concaténation sur de l'entrée user. Les `ALTER`/index sont des constantes statiques.
  PRAGMAs sains (`foreign_keys=ON`, WAL, `busy_timeout`). **Verdict : OK** — pas de SQLi.
  Module natif → cf. §3 provenance.

### `maxmind@4.3.20` — lecture des `.mmdb` GeoIP (entrée binaire)
- **Importé** : `src/server/enrich/geoip.ts:2`, `country.ts`.
- **Surface** : parse des fichiers binaires `.mmdb` (via `mmdb-lib` JS). Le `.mmdb` vient
  du **volume `/data`** (MaxMind GeoLite2), pas du réseau. `initGeoIp` supporte un
  **pinning SHA-256 optionnel** (`GEOIP_DB_SHA256`) → fail-closed sur DB altérée. Lookup
  entouré d'un `try/catch` qui renvoie `{asn:null}` sur erreur de parse, et **court-circuite
  les IP privées**. **Verdict : OK, robuste.** (Bump 4→5 à planifier.)

### `zod@3.23.8` — validation de `/collect` (la seule entrée hostile persistée)
- **Importé** : `src/shared/validation.ts:9`, appliqué dans `routes.ts:185`.
- **Surface** : **valide AVANT tout usage** le body de `/collect` (`safeParse`, 400 si KO).
  Top-level `.strict()` → aucune colonne smugglée. **Aucun `.passthrough()`, `z.any()`,
  `z.unknown()`** (grep négatif). **Aucune regex** dans le schéma → **pas de surface ReDoS**.
  Les agrégats comportementaux qui pilotent les seuils du moteur de décision sont bornés
  `.finite().min/max` (ratio∈[0,1], metric≥0 fini) → pas de NaN/Infinity sur ces champs.
  *Réserve mineure (hors périmètre deps, → moteur de décision)* : quelques champs non
  comportementaux (`toDataURLLength`, `deviceMemory`…) sont des `z.number()` nus acceptant
  NaN/Infinity ; sans impact deps. **Verdict : OK**, usage exemplaire. (Migration zod 4 :
  changement de perfs/API, à faire posément, non urgent.)

---

## 5. Configuration & durcissement

- **Fastify** : `bodyLimit:512KiB`, `trustProxy:false`, error-handler anti-fuite,
  `disableRequestLogging:false` mais logger `redact` cookie/authorization + pas de PII typée
  loggée. **OK.**
- **CSP/helmet** : stricte (cf. §4). `frame-ancestors 'none'`, `object-src 'none'`. **OK.**
- **rate-limit** : global 120 + /collect 15, clé = vraie IP, fallback per-connection. **OK.**
- **Static** : root verrouillé, pas de listing. **OK.**
- **TLS** : `tls.createServer` avec cert/key + ALPN `http/1.1`. **Les `cipherSuites` parsés
  du ClientHello sont seulement stockés dans l'empreinte, PAS réinjectés dans la config TLS**
  → pas de downgrade attaquant-contrôlé ; Node applique ses défauts (TLS min/ciphers sains).
  Caps anti-DoS sur le proxy : `MAX_CONN_PER_IP=64`, plafond global `32MiB` de buffers
  ClientHello en vol. **OK.** (La robustesse du parser ClientHello lui-même = périmètre
  `audit-parsers`, hors deps.)
- **Secrets** : `.env.example` propre, anciens placeholders `SESSION_SECRET`/`ADMIN_TOKEN`
  retirés (ne servaient rien). **Pas d'auth applicative** — assumé et documenté, mitigé par
  URL-capacité UUIDv4 + isolation réseau LXC (périmètre `audit-endpoints`).

---

## 6. Licences

Toutes les directes runtime + dev-deps clés = **MIT** (`fastify`, `@fastify/*`,
`better-sqlite3`, `maxmind`, `zod`). Projet lui-même = MIT.

**Exception à noter (P3)** : **`gsap@3.12.5`** est sous la **« GreenSock Standard ‘No
Charge’ License »** (non-OSI, conditions propres : usage gratuit autorisé hors certains cas
commerciaux, pas de bonus/club plugins). GSAP est bundlé dans le **client** (donc distribué).
Vérifier que l'usage de solo entre dans le périmètre « no charge » de cette licence ; sinon,
licence GreenSock ou retrait de la dépendance.

Aucune licence copyleft-forte (GPL/AGPL), aucun `UNLICENSED` détecté sur le chemin direct.
*Cap* : les licences des transitives profondes n'ont pas été énumérées (pas de lockfile /
`license-checker` non exécutable offline) — **à passer une fois le lockfile committé**.

---

## 7. Supply chain build / CI / Docker

- **`Dockerfile`** :
  - Base **`node:20-bookworm-slim`** = **tag flottant, non pinné par digest** (P2). Un
    `node:20` repoussé change l'arbre OS sous-jacent. Pinner par `@sha256:…`.
  - Install : `if [ -f package-lock.json ]; then npm ci; else npm install; fi` — comme **il
    n'y a pas de lockfile**, c'est la branche **`npm install` (non reproductible)** qui
    s'exécute (P1, lié au no-lockfile).
  - **Pas de `--ignore-scripts`** → le `postinstall`/`install` de `better-sqlite3` tourne au
    build (légitime, mais cf. §3).
  - Bons points : **multi-stage**, `npm prune --omit=dev` (devDeps absents du runtime),
    user **non-root uid 10001** via gosu dans l'entrypoint, runtime slim.
- **CI GitHub Actions** : **ABSENT** — pas de `.github/workflows/`. Donc rien à pinner par
  SHA côté CI, mais aussi **aucun gate `npm audit`/test automatisé** sur les PR (P3 : pas de
  filet de sécurité sur les bumps de deps).
- **Dependabot** : **ABSENT** — pas de `.github/dependabot.yml`. La description du skill le
  supposait présent ; ce n'est pas le cas → **pas de mise à jour automatique des deps** (P2).
- **`.dockerignore`** : correct (exclut `node_modules`, `.env`, `.git`, `tests`…) → build
  from-scratch, pas de fuite de secret/local dans l'image.

---

## 8. Plan de remédiation priorisé

### P1 — Élevé

1. **Migrer Fastify 4.28.1 → 5.x (dernière 5.8.5)**, avec les plugins compatibles :
   ```
   npm i fastify@5 @fastify/helmet@13 @fastify/rate-limit@10 @fastify/static@9
   ```
   Suivre le [guide de migration v5](https://fastify.dev/docs/latest/Guides/Migration-Guide-V5/).
   **Vérif** : `npm ls fastify` = 5.8.5 ; relancer `tests/` ; OSV sur l'arbre = 0 vuln fastify.
   *Bumper le semver de solo (1.3.0 → 1.4.0) — changement de dépendances majeur.*

2. **Committer un lockfile + Docker `npm ci`** :
   - Générer `package-lock.json` (`npm install --package-lock-only` dans le conteneur node:20),
     le **committer**.
   - Le Dockerfile bascule alors automatiquement sur `npm ci` (branche déjà présente l.17).
   - **Vérif** : `git ls-files | grep package-lock.json` non vide ; build Docker reproductible
     (deux builds → mêmes versions).

3. **(Découle de 2)** Une fois le lock présent, **intégrité vérifiée** à chaque install ;
   re-passer §3/§6 (énumération des transitives + `license-checker`).

### P2 — Moyen

4. **Bumper les dev-deps build** pour fermer les CVE dev-server (build-only, mais hygiène) :
   `vitest@^4.1`, `vite@^5.4.20` (ou 7.x), `esbuild`≥0.25 (via vite). **Vérif** : OSV clean.
5. **Pinner l'image Docker par digest** : `FROM node:20-bookworm-slim@sha256:…` (builder ET
   runtime). **Vérif** : `grep sha256 Dockerfile`.
6. **Ajouter `.github/dependabot.yml`** (écosystèmes `npm`, `docker`, `github-actions`) pour
   automatiser les bumps — **après** le lockfile (sinon Dependabot a peu de prise).
7. **Bumps majeurs runtime restants** à planifier : `better-sqlite3`→12, `maxmind`→5,
   `zod`→4 (changement d'API/perfs — tester). Pas urgent (aucune CVE), mais réduit la dette.

### P3 — Faible

8. **Ajouter un workflow CI** minimal (`npm ci` + `npm run typecheck` + `npm test` +
   `npm audit --omit=dev`) avec actions **pinnées par SHA**, pour gater les PR de deps.
9. **Vérifier la licence GSAP** (« no charge ») couvre l'usage de solo, ou retirer/remplacer.
10. **Optionnel** : `--ignore-scripts` au premier `npm ci` du builder puis rebuild explicite
    de `better-sqlite3`, pour réduire la confiance accordée aux scripts d'install.
11. **Énumérer les licences transitives** une fois le lockfile committé (`license-checker`).

---

## Annexe — limites de l'audit (caps assumés, pas de cap silencieux)
- **Pas de lockfile / pas de `node_modules`** : l'arbre transitif réel n'a pas pu être
  observé sur disque. Les versions transitives de §2/§3 sont **inférées** des plages `^`
  amont (plus haut satisfaisant) — c'est précisément le risque dénoncé en P1-2.
- **`license-checker` / `npm audit` non exécutés** (pas de Node local, pas d'install autorisé) :
  recoupement fait via **OSV API + registre npm + GitHub Advisory + NVD/WebSearch**.
- **Licences des transitives profondes** non énumérées (cf. P3-11).
- Robustesse des **parsers d'octets bruts** (ClientHello, headers, mmdb) = périmètre
  `audit-parsers` ; **endpoints/IDOR/rate-limit runtime** = `audit-endpoints` ; non couverts ici.
