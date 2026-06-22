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

## Changelog

- **1.5.0** — **Audit multi-axes (UI/UX/workflow/décision/cybersécurité) + correctifs.** Suite à l'audit, durcissement transversal. ⚠️ **Changement de comportement** : le verdict `human` est plus restrictif (cf. F1).
  - **Moteur de décision** (config `2026.06.6`→`2026.06.7`) : **F1** — un bot sur **proxy résidentiel** + client forgé ne décroche plus `human` (rétrogradé `clean`, jamais `bot`), via les drapeaux `forgeableCorroborated`/`serverCorroboratedBeyondResidentialIp` ([trust.ts](src/shared/decision/trust.ts), [engine.ts](src/shared/decision/engine.ts)) — un vrai humain sur IP résidentielle **sans autre ancrage serveur** obtient désormais `clean` au lieu de `human` ; **F2** — nouveau signal N3 `env_render_hashes_absent` (poids 0.2) fermant l'évasion de réputation par nullification canvas+webgl ([environment.ts](src/shared/decision/environment.ts), [config.ts](src/shared/decision/config.ts)). Tests de régression : [decision-adversarial.test.ts](tests/decision-adversarial.test.ts), [decision.test.ts](tests/decision.test.ts).
  - **Workflow `/collect`** : nouveau `persistSession` ([store.ts](src/server/store.ts), [routes.ts](src/server/routes.ts)) — réputation lue **avant** écriture (anti auto-comptage), `full` assemblé en mémoire (plus de scoring sur fingerprint vide), **transaction unique** serveur+client+décision (plus de décision orpheline). Anciennes fonctions `upsert*` conservées.
  - **Cybersécurité serveur** : bornes `.max()` chaînes + tableaux ([validation.ts](src/shared/validation.ts)) ; redaction IP dans les logs, limites d'en-têtes/timeouts HTTP, cap connexions /64 IPv6, cap global anti-EMFILE ([interceptor.ts](src/server/tls/interceptor.ts)) ; ALPN vide ignoré + tableau plafonné ([clienthello.ts](src/server/tls/clienthello.ts)) ; `secure_delete=ON` ([db.ts](src/server/db.ts)) + purge immédiate au boot ([store.ts](src/server/store.ts)) ; sourcemaps off ([vite.config.ts](vite.config.ts)).
  - **UI/UX** : modale consentement focus-trap + Échap + `inert` (gate RGPD), cibles 44px, token `--muted-strong` (contraste AA), recap durci ([recap.ts](src/ui/recap.ts), [index.html](src/ui/index.html), [recap.html](src/ui/recap.html), [tokens.css](src/ui/tokens.css)) ; fenêtre 8s animée + compte à rebours, `<noscript>`, anti-double-envoi, erreur actionnable, redirection annulable ([index.ts](src/client/index.ts)).
  - **Prérequis de déploiement** : `npm run typecheck && npm run test && npm run lint && npm run format` à lancer sur le serveur avant déploiement (non exécutables en local). Restent à traiter hors-LXC : lockfile committé (`npm install --package-lock-only`), migration Fastify 5, pinning des images Docker par digest, SHA-256 des bases MaxMind dans `.env`.
