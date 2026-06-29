# solo — instructions pour Claude

_Fichier créé automatiquement le 2026-06-18. Complète-le avec le contexte utile à Claude :
stack, conventions, commandes de build/test, pièges connus, etc._

## Contexte

_À compléter._

## Commandes

```bash
# TODO: build / test / lint / démarrage
```

## Conventions

_À compléter._

## Déploiement — items en attente (hors-LXC)

Checklist vivante des actions qui ne peuvent **pas** se faire en local (npm/docker/réseau
indisponibles, build uniquement sur le serveur). Tenir à jour à chaque résolution.

- **I1 — Pinning de l'image Docker par digest.** ⏳ _en attente du digest._ Le Dockerfile
  expose déjà `ARG NODE_IMAGE` (défaut = tag mutable `node:20-bookworm-slim`, build non cassé).
  Récupérer le digest puis sceller le défaut :
  ```bash
  docker buildx imagetools inspect node:20-bookworm-slim   # lire « Digest: sha256:… » (index multi-arch)
  # → ARG NODE_IMAGE=node:20-bookworm-slim@sha256:<digest>   (dans Dockerfile)
  ```
- **I2 — Lockfile committé.** ⏳ _non fait (npm non exécutable en local)._ Le Dockerfile bascule
  automatiquement sur `npm ci` dès que `package-lock.json` est présent (`.dockerignore` ne l'exclut
  pas). À lancer une fois sur une machine avec npm + réseau :
  ```bash
  npm install --package-lock-only && git add package-lock.json && git commit -m "Add package-lock.json (audit I2)"
  ```
- **Fastify 5.** ⏳ _déps bumpées dans `package.json` (fastify 5.2.1 / helmet 13 / rate-limit 10 /
  static 8), à VALIDER sur LXC avant de figer._ Aucun changement de code applicatif attendu (API
  utilisées stables en v5). Confirmer les majeurs de plugins (`npm info <pkg> peerDependencies` →
  exiger `fastify@5`), puis `npm run typecheck && test && build` + smoke-test du boot TLS
  (`serverFactory`). **Version d'app non bumpée** : passer à **1.6.0** + entrée changelog une fois
  le build vert.
- **SHA-256 des bases MaxMind.** ⏳ _opt-in non renseigné._ Remplir `GEOIP_DB_SHA256` /
  `GEOIP_COUNTRY_DB_SHA256` dans `.env` (`sha256sum data/GeoLite2-*.mmdb`) → pinning fail-closed.

> Avant tout déploiement : `npm run typecheck && npm run test && npm run lint && npm run format`
> sur le serveur (non exécutables en local — cf. [[feedback_no_local_install]]).

## Changelog

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
