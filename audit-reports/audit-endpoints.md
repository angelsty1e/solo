# Audit endpoints — solo (v1.3.0) — 2026-06-05

Audit appsec **statique** de la surface HTTP (`src/server/routes.ts` + `index.ts` et
modules adjacents : `tls/interceptor.ts`, `store.ts`, `enrich/rdns.ts`,
`enrich/pipeline.ts`, `http/headers.ts`). Aucune exécution locale (projet déployé sur LXC) :
relecture de code uniquement, raisonnement validé par grep ciblés.

## Verdict : surface HTTP saine ? **OUI**

La surface HTTP est solide. Le modèle URL-capacité (UUIDv4 122 bits, généré serveur,
jamais accepté du client) est correctement appliqué sur `/api/fp/:id` et `/export/:id`,
la clé de rate-limit échoue *fermé* (token par connexion, jamais bucket partagé), l'IP est
dérivée du socket réel sans confiance dans XFF, l'error handler masque les 5xx, la CSP est
cohérente avec le HTML réel, et aucune route n'énumère les sessions ni ne déclenche de
sortie réseau pilotée par le client. **Aucun finding P0/P1.** Les findings sont des points
d'hygiène (P2/P3) et un durcissement défensif recommandé.

### Findings par sévérité
- **P0 (critique)** : 0
- **P1 (élevé)** : 0
- **P2 (moyen)** : 2 — sourcemaps publiques en prod ; dette morte `store.list()` exportée.
- **P3 (hygiène)** : 4 — HSTS désactivé (à documenter), oracle 400/404, version dans `/healthz`,
  rDNS non-awaité sur `/api/fp/me`, absence de tests d'endpoints.

---

## 1. Capability / IDOR / énumération

**Statut : SAIN.**

- **Inforgeabilité confirmée.** `/api/fp/:id` (`routes.ts:152-163`) et `/export/:id`
  (`routes.ts:222-236`) valident l'id contre `UUID_V4` (`routes.ts:92`,
  regex stricte v4 : `4` en position version, `[89ab]` en variant) **avant** tout accès au
  store ; un id non conforme renvoie 400 et ne touche jamais la DB.
- **Génération serveur, non imposable par le client.** `/collect` ignore explicitement tout
  id fourni dans le body : `const sessionId = randomUUID()` puis `{ ...parsed.data, sessionId }`
  (`routes.ts:191-194`). `randomUUID()` (node:crypto) = CSPRNG. Aucun chemin n'utilise un id
  prévisible (timestamp/séquence).
- **Aucune route n'expose `store.list()`.** La fonction existe et est **exportée**
  (`store.ts:258-269`, renvoie jusqu'à 200 sessions) mais grep confirme **aucun appelant**
  dans tout `src/` (le seul match `.list(` ailleurs est `tlsServer.listen`). Pas d'endpoint
  d'énumération. → voir Finding #2 (dette morte).
- **`/api/fp/me`** (`routes.ts:148-150`) renvoie l'empreinte serveur de **l'appelant**
  (son propre socket via `getFingerprintForSocket`/`extractIp`) — ne lit aucun `:id`, pas une
  fuite tierce.
- **Brute-force impossible.** 122 bits d'entropie : énumération hors de portée même sans
  rate-limit dédié sur ces routes (le global 120/min s'applique). L'oracle d'existence
  (404 not-found vs 400 invalid-id) est observable mais sans valeur exploitable puisque l'UUID
  est imprévisible (voir Finding #5).

## 2. Rate-limit : clé, fallback null, budgets, auto-DoS

**Statut : SAIN — fail-closed correct.**

- **Clé = vraie IP, fallback NON partagé.** `rateLimitKeyForSocket` (`interceptor.ts:346-350`)
  retourne `real.addr` quand connu, sinon **`noip:<remotePort>`** = un token *unique par
  connexion*, **jamais** `req.ip` (= 127.0.0.1 pour tous derrière le proxy interne). C'est le
  bon choix : un lookup socket raté isole le client dans son propre bucket → ni DoS par quota
  partagé, ni esquive par flip-flop dans un bucket commun. Utilisé identiquement par le
  limiteur global (`index.ts:115`) et `/collect` (`routes.ts:176`).
- **Anti-spoof IP/XFF confirmé.** `trustProxy:false` (`index.ts:81`). `extractIp`
  (`routes.ts:43-47`) ne lit que `getRealRemoteForSocket(socket)` (IP du socket TCP réel),
  jamais un en-tête. `http/headers.ts` capture `rawHeaders`/XFF pour le *fingerprint* mais ne
  les utilise **jamais** pour dériver l'IP stockée/géolocalisée/loggée. Aucun en-tête client ne
  peut changer la clé de rate-limit ni l'IP persistée. Commentaire explicite `routes.ts:38-42`.
- **Budgets.** Global 120/min (`index.ts:111-116`) ; `/collect` 15/min (`routes.ts:172-178`) —
  la config route-level d'`@fastify/rate-limit` v9 *remplace* le global sur cette route, donc
  `/collect` est bien plafonné à 15/min (le chemin cher : parse zod + transactions DB + moteur
  de décision + 1 PTR awaité). `/healthz` non exempté (volontaire) : le healthcheck Docker poll
  ~2/min, bien sous 120/min, et ça ferme un endpoint de recon/amplification gratuit.
- **413 / bodyLimit.** `bodyLimit: 512*1024` (`index.ts:65`) cape le body `/collect` ; un body
  trop gros est rejeté 413 par Fastify avant le handler.
- **Réponse 429.** Passe par l'error handler (`index.ts:122-130`) avec status<500 → conserve le
  message générique du limiteur, pas de fuite. Aucun `errorResponseBuilder` custom (grep vide).

## 3. Fuite d'information

**Statut : SAIN.**

- **Stack traces masquées.** L'error handler central (`index.ts:122-130`) transforme tout
  `status>=500` en `{ error: 'internal server error' }` et log `{err}` côté serveur uniquement.
  Aucune route ne `send()` un `err.stack` ni une erreur brute en amont (les handlers renvoient
  des objets `{error: '...'}` génériques : `routes.ts:154,159,188,224,229`).
- **Chemins disque non exposés.** `/healthz` (`routes.ts:103-125`) ne renvoie que des booléens
  `loaded` + `version` + `tor.count`, jamais `/data/*.mmdb`, le chemin DB ni le cert (commentaire
  `routes.ts:111-113`). Les chemins ne sont loggés qu'au boot (`index.ts:159-171`), côté serveur.
- **Messages 400 génériques.** `/collect` renvoie `invalid fingerprint payload` et ne log que
  `parsed.error.issues.length` (le *nombre*, pas le contenu) — `routes.ts:185-189`.
- **Logs.** `redact` retire `cookie`/`authorization` (`index.ts:70`). (L'IP source figure
  cependant dans les logs de requête Fastify standard — relève de l'audit RGPD, pas appsec.)

## 4. CSP / helmet

**Statut : SAIN — CSP cohérente avec le HTML réel.**

- CSP (`index.ts:87-103`) : `defaultSrc/scriptSrc/connectSrc/baseUri/formAction 'self'`,
  `objectSrc/frameAncestors 'none'`, `imgSrc 'self' data:`, `styleSrc 'self' 'unsafe-inline'`.
- **Validée contre le HTML/bundle réel.** Les deux templates n'ont **aucun script inline** :
  `src/ui/index.html:302` et `src/ui/recap.html:370` chargent uniquement des
  `<script type="module" src="...">`. Grep `<script>` (sans `src`) et `on*=` handlers : **0
  résultat**. Vite (multi-page, sans `plugin-legacy`) émet les bundles JS en assets externes —
  aucun script inline injecté. → `scriptSrc 'self'` tient, pas de page cassée ni besoin de nonce.
- `styleSrc 'unsafe-inline'` justifié par 1 bloc `<style>` par page (styles seuls, pas de
  vecteur script). Résidu acceptable, noté.
- **HSTS désactivé** (`index.ts:101-102`) — justifié pour un lab self-signed ; à documenter pour
  réactivation en déploiement « sérieux » (voir Finding #3).
- **En-têtes sur tous les chemins.** helmet est enregistré globalement (`onRequest`) avant les
  routes, donc émis sur le static, les 4xx et le 429. Le seul `reply.header()` custom de tout le
  serveur est le `content-disposition` d'`/export` (`routes.ts:234`) — il n'écrase aucun en-tête
  de sécurité helmet. Pas de footgun.

## 5. Static & traversal ; injection d'en-tête /export

**Statut : SAIN.**

- `@fastify/static` 7.0.4 : `root = clientDir/assets`, `prefix '/assets/'`,
  `decorateReply:false` (`routes.ts:96-100`). Un **seul** register, root étroit (le
  sous-dossier `assets/` uniquement). Protège du `..` traversal nativement. Pas de
  `wildcard:false` mal configuré, pas de second register élargissant le root.
- `/` et `/recap/:id` lisent des fichiers à **chemin fixe** (`index.html`, `recap.html`) via
  `fs.readFileSync` (`routes.ts:128,133,139,144`) — l'`:id` de `/recap/:id` **n'est jamais
  concaténé à un chemin disque** (la page est une coquille statique, les données viennent
  ensuite de `/api/fp/:id`). Aucun `sendFile` custom contournant la garde (grep).
- **`/export/:id` : pas d'injection d'en-tête (CRLF).** Le `content-disposition`
  (`routes.ts:234`) interpole `req.params.id`, mais la **validation `UUID_V4` précède l'usage**
  (`routes.ts:223`) : la regex n'autorise que `[0-9a-f-]` → impossible d'injecter `\r\n` ou des
  guillemets dans le nom de fichier.

## 6. rDNS / DNS : SSRF ? amplification ?

**Statut : SAIN — pas de SSRF, amplification bornée.**

- `reverseDns(ip)` (`rdns.ts:40-52`) fait `dns.reverse` sur l'**IP source de la connexion**
  (extraite du socket, jamais d'une valeur fournie par le client) → **pas de SSRF** : l'attaquant
  ne choisit pas la cible du lookup. C'est la seule sortie réseau côté serveur déclenchée par une
  requête ; grep `fetch/http.get/https.get/axios/undici` ne trouve **aucun** appel serveur (les 3
  `fetch` sont du code navigateur dans `src/ui` / `src/client`). MaxMind = lookup local mmdb.
- **Amplification mitigée et bornée** : `isPrivate()` court-circuite les IP locales
  (`rdns.ts:25-38`) ; timeout 250 ms (`rdns.ts:40,48`) ; cache LRU `CACHE_MAX=100_000` +
  TTL 1 h (`rdns.ts:11-23`). Un flood d'IP distinctes est en outre plafonné en amont par le
  rate-limit global 120/min et le cap de connexions par IP (`MAX_CONN_PER_IP=64`,
  `interceptor.ts:58`). Un attaquant contrôlant le PTR de sa propre IP n'affecte que son propre
  scoring — pas une fuite.

## 7. Auth dormante & secrets

**Statut : SAIN — pas de demi-câblage.**

- **`ADMIN_TOKEN` / `SESSION_SECRET` totalement absents du code.** Grep sur tout `src/` : 0
  résultat. Le `.env.example` documente explicitement leur **retrait** (« nothing in the code
  read them, so setting one gave a false sense of protection »). Pas de route admin oubliée, pas
  de check d'auth présent-mais-contournable. La fonctionnalité dormante est *absente*, pas
  *entre les deux* — état correct.
- Aucun `process.env` ne lit un secret applicatif (`index.ts` ne lit que PORT/HOST/chemins/
  LOG_LEVEL/NODE_ENV/`*_SHA256` d'intégrité). Rien de critique n'est signé aujourd'hui.

---

## 8. Remédiation priorisée

### Finding #1 — [P2] Sourcemaps publiques en production
- **Fichier** : `vite.config.ts:13` (`sourcemap: true`).
- **Impact** : `dist/client/assets/*.map` est servi par `@fastify/static` → expose le code source
  TS/JS dé-minifié du client (logique de fingerprinting, noms de fonctions, structure interne).
  Reconnaissance facilitée pour qui veut comprendre/contourner la collecte. Pas une fuite de
  secret, mais une fuite de propriété intellectuelle / surface d'analyse.
- **Remédiation** : `sourcemap: false` pour les builds de prod (ou conditionner sur
  `process.env.NODE_ENV`), ou ne pas déployer les `.map` (les exclure du `dist/client/assets`
  livré). Vérifier qu'`@fastify/static` ne les sert pas.

### Finding #2 — [P2] `store.list()` exporté mais mort — dette dangereuse
- **Fichier** : `src/server/store.ts:258-269`.
- **Impact** : aucun à ce jour (aucun appelant). Mais une fonction exportée qui **énumère
  jusqu'à 200 sessions** est une amorce : un futur ajout de route « debug »/« admin » la
  câblerait trivialement et casserait tout le modèle URL-capacité (énumération massive de
  sessions tierces). Risque latent, pas actif.
- **Remédiation** : supprimer `list()` tant qu'aucune route ne l'utilise, ou la rendre non
  exportée. Ajouter un test garantissant qu'aucune route n'énumère les sessions (voir tests).

### Finding #3 — [P3] HSTS désactivé non documenté pour la prod
- **Fichier** : `index.ts:101-102` (`hsts: false`).
- **Impact** : justifié en lab self-signed ; mais sans rappel, un déploiement « sérieux »
  (cert valide, exposition réelle) resterait sans HSTS → downgrade/strip TLS possible.
- **Remédiation** : documenter (README/commentaire) la réactivation d'HSTS dès qu'un cert de
  confiance est utilisé ; idéalement le conditionner sur une variable d'env.

### Finding #4 — [P3] Oracle d'existence 400 vs 404
- **Fichier** : `routes.ts:153-160`, `223-230`.
- **Impact** : un id mal formé → 400, un UUID valide inexistant → 404 : différence observable.
  **Non exploitable** (122 bits imprévisibles, brute-force hors de portée), mais c'est un oracle.
- **Remédiation** : optionnel — uniformiser en 404 pour les deux cas. Faible priorité.

### Finding #5 — [P3] `version` exposée par `/healthz`
- **Fichier** : `routes.ts:119`.
- **Impact** : numéro de version applicatif renvoyé sans auth → facilite le ciblage de CVE par
  version. Acceptable mais à noter.
- **Remédiation** : optionnel — retirer `version` de la réponse publique ou la réserver à un
  endpoint authentifié si une auth est ajoutée un jour.

### Finding #6 — [P3] rDNS non-awaité fired-and-forget sur `/api/fp/me`
- **Fichier** : `pipeline.ts:60-63` (`apply` → `void reverseDns(ip)`), via `enrichIpSync`
  (`routes.ts:73,149`).
- **Impact** : sur cache-miss, `/api/fp/me` déclenche un PTR non awaité pour réchauffer le cache.
  Borné (1 lookup par IP réelle, caché, timeout 250 ms, rate-limit 120/min) → pas d'amplification
  réelle, mais c'est un effet de bord réseau sur un GET non-collecte.
- **Remédiation** : acceptable en l'état ; si l'on veut zéro sortie réseau sur `/api/fp/me`,
  ne déclencher le warm-up que sur le chemin awaité (`/collect`).

### Tests à ajouter — `tests/endpoints.test.ts` (Fastify `app.inject()`, sans réseau)
Couvrir, en injection (pas de socket réel → mocker/forcer la clé) :
1. `/api/fp/:id` et `/export/:id` : id non-UUID → 400 ; UUID v4 valide inexistant → 404 ;
   pas de fuite d'`err.stack` dans les corps 4xx/5xx.
2. `/collect` : body invalide → 400 `invalid fingerprint payload` ; id client fourni dans le
   body → ignoré, l'id renvoyé est un UUID v4 ≠ celui fourni.
3. En-têtes de sécurité présents sur `/`, `/assets/*`, `/healthz`, un 404 et un 400
   (CSP `script-src 'self'`, `X-Content-Type-Options`, `frame-ancestors 'none'`).
4. `/export/:id` : `content-disposition` ne contient que l'UUID (pas de CRLF / guillemets).
5. **Garde anti-énumération** : assert qu'aucune route ne renvoie une liste de sessions
   (régression pour Finding #2 si `list()` est conservée).
6. `/healthz` : ne contient aucun chemin disque (`/data`, `/certs`, `.mmdb`).

### Rappels maison
- Semver : findings P2/P3 → correctifs en **patch** (1.3.1) — pas de changement de comportement.
- Mettre à jour README (HSTS prod, sourcemaps), lister les fichiers modifiés, GO avant prod.

---

## Checklist de complétude
- [x] Confirmé : aucune route n'expose `store.list()` / n'énumère les sessions (grep : 0 appelant).
- [x] Comportement rate-limit quand `getRealRemoteForSocket` renvoie null : **tranché** —
      fallback token par connexion (`noip:<port>`), fail-closed, jamais bucket partagé.
- [x] CSP validée contre le HTML/bundle réel : aucun script inline non couvert.
- [x] Aucune sortie réseau déclenchée par entrée client (grep fetch/http.get/https : seul
      `dns.reverse` sur l'IP du socket, pas une valeur client → pas de SSRF).
- [x] ADMIN_TOKEN/SESSION_SECRET : ni route admin contournable ni demi-câblage (absents du code).
- [x] Tout non-couvert listé ; findings avec fichier:ligne + remédiation + tests proposés.
