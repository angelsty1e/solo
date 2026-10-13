# solo — instructions pour Claude

_Fichier créé automatiquement le 2026-06-18. Complète-le avec le contexte utile à Claude :
stack, conventions, commandes de build/test, pièges connus, etc._

## Contexte

_À compléter._

## Commandes

Gestionnaire de paquets : **pnpm 11** (version figée par `packageManager`, `corepack enable`),
Node ≥ 22.13. `pnpm-workspace.yaml` porte `allowBuilds` (better-sqlite3, esbuild) — sans lui
pnpm 11 saute leurs scripts d'install et le binaire natif manque.

```bash
docker compose up -d --build        # flux nominal (Docker Desktop sur le Mac, ou LXC)
pnpm run typecheck && pnpm test && pnpm run lint && pnpm run build
```

Pas d'install dans l'arbre du Mac : la suite se joue dans un conteneur jetable sur une copie —
`docker run --rm -e CI=true -v "$PWD":/src:ro node:22-bookworm-slim sh -c 'cp -r /src /w && cd /w && rm -rf node_modules && corepack enable && pnpm install --frozen-lockfile && pnpm test'`
(better-sqlite3 a un prébuilt Node 22 : pas besoin de `g++`).

## Conventions

_À compléter._

## Déploiement — items en attente

Checklist vivante. Tenir à jour à chaque résolution.

- **I1 — Pinning de l'image Docker par digest.** ⏳ _en attente du digest._ Le Dockerfile
  expose déjà `ARG NODE_IMAGE` (défaut = tag mutable `node:22-bookworm-slim`, build non cassé).
  Récupérer le digest puis sceller le défaut :
  ```bash
  docker buildx imagetools inspect node:22-bookworm-slim   # lire « Digest: sha256:… » (index multi-arch)
  # → ARG NODE_IMAGE=node:22-bookworm-slim@sha256:<digest>   (dans Dockerfile)
  ```
- **I2 — Lockfile committé.** ✅ _fait en 1.6.0_ : `pnpm-lock.yaml`, consommé en
  `pnpm install --frozen-lockfile` par le Dockerfile.
- **Fastify 5.** ✅ _validé en 1.6.0 sous Docker_ (typecheck + build + boot TLS `serverFactory` +
  smoke-test). Reste à le déployer sur le LXC.
- **2 tests rouges préexistants** (jamais exécutés avant 1.6.0, identiques sous Node 20 et 22) :
  ⏳ `F1ter [D1]` ([decision-adversarial.test.ts](tests/decision-adversarial.test.ts)) →
  `TypeError` sur `uaData.brands` : [environment.ts](src/shared/decision/environment.ts) ne garde
  que `uaData === null`, pas `undefined` ; `list()` ([store.test.ts](tests/store.test.ts)) → le
  test lit à T0+90 min une session créée à T0+30 min (expire à T0+90 min, borne `expires_at > now`
  stricte) : erreur de borne dans le TEST.
- **SHA-256 des bases MaxMind.** ⏳ _opt-in non renseigné._ Remplir `GEOIP_DB_SHA256` /
  `GEOIP_COUNTRY_DB_SHA256` dans `.env` (`sha256sum data/GeoLite2-*.mmdb`) → pinning fail-closed.

> Avant tout déploiement : `pnpm run typecheck && pnpm test && pnpm run lint && pnpm run format`
> (dans un conteneur, cf. Commandes).

## Changelog

- **1.6.1** — **README : mise en place Windows pas à pas.** Sous macOS/Linux, solo se lance en une commande. Sous Windows, il faut WSL2, Docker Desktop et Git, Windows n'a pas d'`openssl`, et PowerShell a ses propres pièges. Le bug de build corrigé en 1.5.4 est d'ailleurs apparu sur Windows. [README.md](README.md) : tableau d'entrée par système ; étape 1 qui dit explicitement de ne **pas** générer de certificat sous Windows (le conteneur en crée un, avec l'openssl de l'image) et ajoute mkcert en option ; section Windows réécrite en pas-à-pas (`wsl --install`, moteur WSL 2 de Docker Desktop, terminal à rouvrir pour le `PATH`, `.gitattributes`, `curl.exe`) ; tableau de dépannage complété (Docker introuvable ou moteur arrêté, openssl absent, build rouge sur `pnpm run build` → `--progress=plain`, port 8443 réservé par Hyper-V/WinNAT, alias `curl`) ; `Get-FileHash` pour l'empreinte MaxMind ; dev local sous Windows à faire dans WSL. Version d'exemple du `/healthz` passée de 1.4.2 à 1.6.1. Aucun changement de code ; le bump de `package.json` ne change que la version affichée par `/healthz`.
- **1.6.0** — **Passage npm → pnpm 11, image Node 22, Fastify 5 validé.** Le projet s'installait avec npm sans lockfile (`npm install` → dépendances transitives différentes à chaque build) alors que le poste est pnpm-only.
  - **pnpm** : `packageManager: pnpm@11.17.0` + scripts `prebuild`/`build` en `pnpm run` ([package.json](package.json)) ; [pnpm-workspace.yaml](pnpm-workspace.yaml) approuve les builds de `better-sqlite3` et `esbuild` ; **lockfile `pnpm-lock.yaml` committé** (ferme I2). [Dockerfile](Dockerfile) : `corepack enable`, store pnpm dans un cache BuildKit (`/pnpm/store`, fixé globalement pour que `prune` le réutilise), `pnpm install --frozen-lockfile`, puis `CI=true pnpm prune --prod` (sans `CI`, pnpm refuse de purger `node_modules` faute de TTY). Image finale : 7 dépendances de prod, 38 Mo de `node_modules`.
  - **Node 20 → 22** (`ARG NODE_IMAGE=node:22-bookworm-slim`, `engines` ≥ 22.13) : pnpm 11 refuse de tourner sous 22.13 ; Node 20 est en fin de vie depuis avril 2026. 22 plutôt que 24 : better-sqlite3 11.3.0 a un prébuilt Node 22, pas Node 24.
  - **Docs** : commandes du [README](README.md) et messages « Client bundle missing » ([routes.ts](src/server/routes.ts)) en pnpm ; section Commandes de ce fichier remplie.
  - **Vérifié** (Docker Desktop, Mac) : build vert, conteneur `healthy` sous Node 22.23.3, `/healthz` 200 `db:true`, `/` 200, JA3 capturé sur `/api/fp/me`. **Première exécution de la suite** : 308/310 verts, lint 0 erreur (1 warning `httpFp` inutilisé) ; les **2 rouges sont préexistants** et identiques sous Node 20 → détail dans « items en attente ». **Déploiement LXC** : rebuild de l'image requis (changement de Node) ; aucun changement de schéma DB.

- **1.5.4** — **Build Docker réparé : le typecheck bloquait `npm run build`.** `docker compose up --build` échouait dans l'étape builder parce que `prebuild` lance `tsc --noEmit` et que le code des correctifs 1.5.2/1.5.3 n'avait jamais été compilé (« non exécutable en local »). Deux causes, corrigées sans changement de comportement :
  - **`noUncheckedIndexedAccess`** : `split('%')[0]` et le groupe de regex IPv4-mapped sont typés `string | undefined` → `?? addr` / `mapped[1]!` dans `canonicalizeIp` ([ip.ts](src/server/enrich/ip.ts)) et `connCapKey` ([interceptor.ts](src/server/tls/interceptor.ts)).
  - **`headersTimeout`** : option de `http.createServer` bien honorée par Node 20 (vérifié dans `node:20-bookworm-slim`, v20.20.2), mais absente des types de `@types/node` 20.14.10 épinglé → posée en propriété `httpServer.headersTimeout = 10_000` après création ([interceptor.ts](src/server/tls/interceptor.ts)).
  - **Vérifié** sur Docker Desktop (Mac, Compose v5.6.0) : build vert, conteneur `healthy` sans redémarrage, `/` 200, bundle `/assets/*.js` 200, `/healthz` `db:true`, `/api/fp/me` renvoie l'empreinte TLS 1.3 (JA3). **Non vérifié** : la suite vitest (bloquée par le hook pnpm-only du poste) — à jouer dans un conteneur `node:20-bookworm-slim` sur une copie du dépôt. Docker est disponible sur ce Mac depuis le 2026-10-13 : la mention « docker indisponible » des items en attente ne vaut plus.

- **1.5.3** — **Durcissements 🟡 d'enrichissement / rétention.** Trois findings d'audit basse-sévérité fermés (aucun ne touche le moteur de décision : config inchangée `2026.06.8`).
  - **Tor IPv6 (F4)** : `isTorExit` faisait un match exact de chaîne, donc un exit IPv6 listé dans une forme (étendue / casse / IPv4-mapped) ratait quand le socket le rapportait dans une autre → `ip_tor` silencieusement annulé **et** clause `isTorExit !== true` du crédit résidentiel satisfaite à tort. Nouveau `canonicalizeIp` (expansion `::` → 8 hextets, casse, IPv4-mapped → IPv4 pointé) appliqué des **deux** côtés (construction du Set + lookup) ([ip.ts](src/server/enrich/ip.ts), [tor.ts](src/server/enrich/tor.ts)). Régression [enrich-ip.test.ts](tests/enrich-ip.test.ts).
  - **Rétention WAL (privacy P1)** : `secure_delete=ON` zéro-ifie les pages libérées du fichier principal, mais en mode WAL les frames d'origine (IP + empreintes) traînaient dans le `-wal` jusqu'au prochain checkpoint (~1000 pages) — bien au-delà du TTL 1h sur une base write-light. Le sweeper fait désormais `wal_checkpoint(TRUNCATE)` après le DELETE (best-effort, retry au tick suivant) ([store.ts](src/server/store.ts)).
  - **rDNS (CWE-350 + hygiène timer)** : documenté pourquoi le PTR n'est **pas** forward-confirmé (signal `rdns_hosting` advisory et strictement unidirectionnel — un PTR forgé ne peut que supprimer sa propre suspicion, déjà possible ; FCrDNS différé jusqu'à ce que le rDNS alimente une décision positive) ; et le timer de timeout est maintenant `clear`/`unref` (ne retient plus la boucle d'événements sur le chemin succès rapide) ([rdns.ts](src/server/enrich/rdns.ts)).
- **1.5.2** — **Re-audit : complétion de N1 (bypass /64 IPv6 résiduel).** Le correctif N1 de 1.5.1 (`rateLimitKeyForSocket` → `connCapKey`) reposait sur un `connCapKey` lui-même bogué : `addr.split(':').slice(0,4)` découpe des *tokens*, pas des *hextets*, donc pour un /64 dont le préfixe se compresse (forme courante `2001:db8::/64`), `2001:db8::1` et `::2` produisaient des clés différentes → le /64 n'était pas regroupé et la rotation d'adresses contournait encore le rate-limit **et** le cap de concurrence (`MAX_CONN_PER_IP`). `connCapKey` **étend désormais `::` à 8 hextets** avant d'extraire le /64 (gère zone-id et IPv4-mapped), fermant les deux. Reproduction avant/après + régression [interceptor-ipkey.test.ts](tests/interceptor-ipkey.test.ts). [interceptor.ts](src/server/tls/interceptor.ts). Vérifié au re-audit : D1/E1/P1 tiennent ; gel de `human` sans régression (branches mortes intentionnelles uniquement).
- **1.5.1** — **Correctifs de re-audit (OWASP 2025 / MITRE ATT&CK).** Quatre findings traités (D1/E1/P1/N1). ⚠️ **Changement de comportement** : le verdict `human` est désormais **gelé** (cf. D1).
  - **Moteur de décision** (config `2026.06.7`→`2026.06.8`) : **D1** (🔴) — la garde F1 ne fermait que la variante *rembourrée* du bot sur proxy résidentiel ; la variante *épurée* (comportement organique forgé + IP résidentielle, **sans aucun signal passif**) décrochait encore `human` — état figé par le test `F1bis`. Le label positif exige maintenant un signal serveur non-forgeable **au-delà** de l'IP résidentielle (`serverCorroboratedBeyondResidentialIp`) ; aucun n'existant aujourd'hui, **`human` est volontairement inatteignable** (tout cas positif → `clean`, jamais `suspect`/`bot`). Se rouvrira automatiquement le jour d'un ancrage serveur fort (device attesté, liveness recalculée serveur). [engine.ts](src/shared/decision/engine.ts), [config.ts](src/shared/decision/config.ts). Régressions : `F1bis`/`F1ter` ([decision-adversarial.test.ts](tests/decision-adversarial.test.ts)), contrat résidentiel ([decision-contract.test.ts](tests/decision-contract.test.ts)).
  - **Enrichissement IP** : **E1** (🟠) — `lookupAsn` court-circuitait **tout** `172.0.0.0/8` via `startsWith('172.')`, masquant les plages datacenter publiques (Cloudflare 172.64/13, Google 172.217/16) → un bot y échappait à `ip_datacenter`/`ip_proxy`. Helper partagé `isPrivateOrReservedIp` (172.16.0.0/12 seul) factorisé entre [geoip.ts](src/server/enrich/geoip.ts) et [rdns.ts](src/server/enrich/rdns.ts) ([ip.ts](src/server/enrich/ip.ts)) — fin de la divergence des trois copies.
  - **Proxy TLS** ([interceptor.ts](src/server/tls/interceptor.ts)) : **P1** (🟠) — le timer de capture (hello fragmenté) était hors de portée de `cleanup()` ; un hello partiel suivi d'un RST laissait `finalize()` s'exécuter sur une connexion détruite (ré-insertion `pendingByUpPort` morte + buffer ~16 KO retenu 1,5 s après libération de la comptabilité → dépassement transitoire de `MAX_TOTAL_CAPTURE_BYTES`). Timer hissé + nettoyé dans `cleanup`, garde `cleaned` dans `finalize`. **N1** (🟠) — le rate-limit clé sur l'IPv6 *complète* laissait un propriétaire de /64 (2⁶⁴ adresses) obtenir un bucket neuf par adresse et contourner les 120/min et 15/min `/collect` ; clé désormais sur le /64 (`connCapKey`), IPv4 inchangé. La réputation conserve l'IP complète (un /64 = vrai essaim).
  - **Prérequis de déploiement** : inchangés (voir 1.5.0) — `npm run typecheck && npm run test && npm run lint && npm run format` sur le serveur avant déploiement (non exécutables en local).

- **1.5.0** — **Audit multi-axes (UI/UX/workflow/décision/cybersécurité) + correctifs.** Suite à l'audit, durcissement transversal. ⚠️ **Changement de comportement** : le verdict `human` est plus restrictif (cf. F1).
  - **Moteur de décision** (config `2026.06.6`→`2026.06.7`) : **F1** — un bot sur **proxy résidentiel** + client forgé ne décroche plus `human` (rétrogradé `clean`, jamais `bot`), via les drapeaux `forgeableCorroborated`/`serverCorroboratedBeyondResidentialIp` ([trust.ts](src/shared/decision/trust.ts), [engine.ts](src/shared/decision/engine.ts)) — un vrai humain sur IP résidentielle **sans autre ancrage serveur** obtient désormais `clean` au lieu de `human` ; **F2** — nouveau signal N3 `env_render_hashes_absent` (poids 0.2) fermant l'évasion de réputation par nullification canvas+webgl ([environment.ts](src/shared/decision/environment.ts), [config.ts](src/shared/decision/config.ts)). Tests de régression : [decision-adversarial.test.ts](tests/decision-adversarial.test.ts), [decision.test.ts](tests/decision.test.ts).
  - **Workflow `/collect`** : nouveau `persistSession` ([store.ts](src/server/store.ts), [routes.ts](src/server/routes.ts)) — réputation lue **avant** écriture (anti auto-comptage), `full` assemblé en mémoire (plus de scoring sur fingerprint vide), **transaction unique** serveur+client+décision (plus de décision orpheline). Anciennes fonctions `upsert*` conservées.
  - **Cybersécurité serveur** : bornes `.max()` chaînes + tableaux ([validation.ts](src/shared/validation.ts)) ; redaction IP dans les logs, limites d'en-têtes/timeouts HTTP, cap connexions /64 IPv6, cap global anti-EMFILE ([interceptor.ts](src/server/tls/interceptor.ts)) ; ALPN vide ignoré + tableau plafonné ([clienthello.ts](src/server/tls/clienthello.ts)) ; `secure_delete=ON` ([db.ts](src/server/db.ts)) + purge immédiate au boot ([store.ts](src/server/store.ts)) ; sourcemaps off ([vite.config.ts](vite.config.ts)).
  - **UI/UX** : modale consentement focus-trap + Échap + `inert` (gate RGPD), cibles 44px, token `--muted-strong` (contraste AA), recap durci ([recap.ts](src/ui/recap.ts), [index.html](src/ui/index.html), [recap.html](src/ui/recap.html), [tokens.css](src/ui/tokens.css)) ; fenêtre 8s animée + compte à rebours, `<noscript>`, anti-double-envoi, erreur actionnable, redirection annulable ([index.ts](src/client/index.ts)).
  - **Prérequis de déploiement** : `npm run typecheck && npm run test && npm run lint && npm run format` à lancer sur le serveur avant déploiement (non exécutables en local). Restent à traiter hors-LXC : lockfile committé (`npm install --package-lock-only`), migration Fastify 5, pinning des images Docker par digest, SHA-256 des bases MaxMind dans `.env`.
