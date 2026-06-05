---
name: audit-endpoints
description: >-
  Audit appsec en profondeur des endpoints HTTP de solo (src/server/routes.ts +
  index.ts) : les URLs-capacité /api/fp/:id et /export/:id (IDOR / énumération /
  fuite), /collect (rate-limit, bodyLimit, validation), /healthz et le service
  statique. Vérifie l'efficacité réelle du rate-limit (clé = vraie IP via le proxy,
  comportement si le lookup échoue), la robustesse de la CSP/helmet, l'absence de
  fuite d'info (stack traces, chemins disque), l'anti-spoof IP/XFF, le path
  traversal du static, l'abus de résolveur DNS via le rDNS, et les fonctions
  d'auth dormantes (ADMIN_TOKEN/SESSION_SECRET). Objectif : aucune session d'un
  tiers lisible/énumérable, aucun endpoint non authentifié abusable en
  amplification/DoS, aucune fuite d'interne.
  TRIGGER : "audit des endpoints / des routes", "IDOR sur /api/fp ou /export",
  "le rate-limit tient-il", "fuite d'info / stack trace", "path traversal du
  static", "appsec HTTP de solo", "les URLs de recap sont-elles sûres".
---

# audit-endpoints — appsec de la surface HTTP

## 1. Surface & modèle d'autorisation

Routes (routes.ts / index.ts) :

| Route | Méthode | Auth | Donnée exposée |
|---|---|---|---|
| `/healthz` | GET | aucune (rate-limité) | état (db/geoip/tor booléens) |
| `/` , `/recap/:id` | GET | aucune | shell HTML statique |
| `/assets/*` | GET | aucune | bundle client (`@fastify/static`) |
| `/api/fp/me` | GET | aucune | empreinte **serveur de l'appelant** (TLS/IP) |
| `/api/fp/:id` | GET | **capability** (UUIDv4 imprévisible) | empreinte complète d'une session |
| `/export/:id` | GET | **capability** | dump JSON complet (téléchargement) |
| `/collect` | POST | aucune (rate-limité 15/min) | crée une session, renvoie verdict |

**Le modèle d'autorisation = URL-capacité** : connaître l'UUIDv4 (122 bits, généré
serveur, jamais accepté du client) == être autorisé à lire. Tout l'audit tourne
autour de : *cette capacité est-elle réellement inforgeable et non énumérable, et
les endpoints sans auth sont-ils inabusables ?*

---

## 2. Déroulé de l'audit (phases)

Outillage : lancer le serveur (Docker) et tester avec `curl -k`, plus relecture de
code. Conteneur jetable pour les tests automatisés :
```bash
NODEC='docker run --rm -v "$PWD":/app -w /app node:20'
# build + run local, ou docker compose up -d puis curl -k https://localhost:8443/...
```

### Phase 1 — IDOR / capability / énumération
- [ ] **Inforgeabilité** : confirmer que `/api/fp/:id` et `/export/:id` n'acceptent
      qu'un UUIDv4 (`UUID_V4` regex) et renvoient 404 sinon — qu'il n'existe **aucun
      endpoint qui liste** les sessions. ⚠️ `store.list()` existe (renvoie 200
      sessions) et est **exporté** : vérifier qu'**aucune route ne l'expose** ; sinon
      = énumération de toutes les sessions = fuite massive. Flagger l'export mort
      comme dette dangereuse.
- [ ] **Génération de l'UUID** : `randomUUID()` (node:crypto) = CSPRNG → OK.
      Vérifier qu'aucun chemin n'utilise un id prévisible (timestamp, séquence) et
      que le client ne peut pas imposer son id (la route l'écrase — confirmer).
- [ ] **Oracle d'existence** : 404 (not found) vs 400 (invalid id) — différence
      observable ; sans énumération possible (UUID imprévisible) le risque est nul,
      mais noter que `/api/fp/:id` ne rate-limite pas plus que le global 120/min →
      un attaquant ne peut pas brute-forcer 122 bits de toute façon. Confirmer le
      raisonnement.
- [ ] **Fuite via /api/fp/me** : renvoie l'empreinte serveur de **l'appelant**
      (sa propre IP/TLS) → pas une fuite tierce. Confirmer qu'il ne lit pas un id.

### Phase 2 — Rate-limit : efficacité réelle
- [ ] **Clé = vraie IP** : le keyGenerator global et celui de `/collect` utilisent
      `getRealRemoteForSocket(...)?.addr ?? req.ip`. **Cas critique** : si le lookup
      socket échoue (retourne null), le fallback est `req.ip` = **127.0.0.1 pour
      TOUS** (proxy interne) → soit (a) tous les clients partagent un seul bucket →
      **un attaquant bloque tout le monde** (DoS par épuisement de quota partagé),
      soit (b) inverse. **Tester ce qui se passe quand getRealRemoteForSocket renvoie
      null** et statuer. Reco : fail-closed propre (rejet) plutôt que clé partagée.
- [ ] **Spoofing** : XFF n'est PAS trusté (`trustProxy:false`, et `extractIp` ignore
      XFF volontairement — bien). Confirmer qu'aucun en-tête client ne peut changer
      la clé de rate-limit ni l'IP stockée/géolocalisée.
- [ ] **Budgets** : global 120/min, `/collect` 15/min. `/collect` est le chemin cher
      (parse + writes DB + moteur) → vérifier que 15/min suffit à empêcher l'abus
      CPU/DB tout en restant utilisable. `/healthz` non exempté (volontaire) — OK.
- [ ] **Réponse 429** : passe par l'error handler (status<500 → garde message) — pas
      de fuite.

### Phase 3 — Fuite d'information
- [ ] **Stack traces** : l'error handler (index.ts) transforme tout 5xx en
      `{error:'internal server error'}` et log côté serveur — confirmer qu'aucune
      route ne `send()` une erreur brute / un `err.stack` en amont du handler.
- [ ] **Chemins disque** : `/healthz` n'expose que des booléens `loaded` (le code le
      commente explicitement) — confirmer qu'on ne fuit jamais `/data/...mmdb`, le
      chemin DB, le chemin cert. Vérifier aussi les logs (voir phase RGPD).
- [ ] **Versions** : `/healthz` expose `version` (numéro app) — acceptable, mais le
      noter. Pas de bannière de stack (Fastify/Node) renvoyée ?
- [ ] **Messages 400** : `/collect` renvoie `invalid fingerprint payload` (générique,
      bien) et log juste le **nombre** d'issues zod, pas leur contenu (bien).

### Phase 4 — En-têtes de sécurité (helmet/CSP)
- [ ] **CSP** : `scriptSrc 'self'`, `objectSrc 'none'`, `frameAncestors 'none'`,
      `baseUri 'self'`, `defaultSrc 'self'`. **Vérifier** que `index.html`/`recap.html`
      et le bundle Vite **ne contiennent aucun script inline** (sinon violation CSP →
      page cassée ou besoin de nonce). `styleSrc` autorise `'unsafe-inline'` (styles
      seulement) — acceptable, mais noter le résidu.
- [ ] **HSTS désactivé** (lab self-signed) — justifié ; le documenter pour qu'un
      déploiement « sérieux » le réactive.
- [ ] Vérifier les autres en-têtes helmet par défaut (X-Content-Type-Options,
      Referrer-Policy, X-Frame-Options via frameAncestors) sont bien émis sur
      **toutes** les réponses, y compris le static et les 4xx/5xx (footgun classique :
      un handler qui pose ses propres en-têtes peut écraser ceux de helmet).

### Phase 5 — Service statique & traversal
- [ ] `@fastify/static` : `root = clientDir/assets`, `prefix '/assets/'`,
      `decorateReply:false`. Confirmer qu'il n'y a **pas** de `wildcard:false`
      mal configuré ni de second register exposant un root plus large. `@fastify/static`
      protège du `..` traversal — vérifier la version (audit-deps) et qu'aucun
      `sendFile` custom ne contourne la garde.
- [ ] `/` et `/recap/:id` lisent des fichiers **à chemin fixe** (`index.html`,
      `recap.html`) via `fs.readFileSync` — pas d'injection de chemin (l'`:id` n'est
      jamais concaténé à un chemin disque). Confirmer.
- [ ] `/export/:id` : `content-disposition` contient l'`:id` **déjà validé UUID** →
      pas d'injection d'en-tête (CRLF) ni de nom de fichier. Confirmer la validation
      précède l'usage.

### Phase 6 — rDNS / résolveur DNS (abus côté réseau)
- [ ] `reverseDns(ip)` (rdns.ts) fait `dns.reverse` sur l'**IP source de la
      connexion** (pas une valeur fournie par le client) → pas de SSRF classique.
      Risques résiduels : (a) un attaquant déclenchant beaucoup de connexions depuis
      des IP variées force des lookups PTR → amplification vers le résolveur (mitigé :
      cache LRU 100k + TTL 1h + timeout 250ms — confirmer les bornes) ; (b) l'attaquant
      contrôle le PTR de sa propre IP → n'affecte que son propre scoring (pas une
      fuite). Statuer que ce n'est pas un SSRF, documenter les mitigations.
- [ ] Confirmer qu'aucune autre sortie réseau (fetch/http.get) n'est déclenchée par
      une entrée client (grep). MaxMind = lookup local, pas réseau.

### Phase 7 — Auth dormante & secrets
- [ ] `ADMIN_TOKEN` et `SESSION_SECRET` (.env.example) sont **réservés mais inutilisés**.
      Vérifier qu'**aucun endpoint privilégié** n'est à demi-câblé (un check d'auth
      présent mais contournable, ou une route admin oubliée). Une fonctionnalité de
      sécurité dormante doit être soit absente, soit complète — pas entre les deux.
- [ ] Si `SESSION_SECRET` vide → généré aléatoire au boot (invalidé au restart) :
      confirmer qu'il ne signe rien de critique aujourd'hui (le commentaire le dit).

### Phase 8 — Synthèse
- [ ] Prioriser : **P0** lecture/énumération de sessions tierces, route admin
      contournable, fuite de secret/stack. **P1** rate-limit contournable ou
      auto-DoS par clé partagée, CSP cassée laissant passer du script inline.
      **P2** fuite d'info mineure, en-tête manquant sur un sous-chemin. **P3**
      hygiène (HSTS doc, export mort `list()`).
- [ ] Repro `curl` + correctif + test (créer `tests/endpoints.test.ts` avec
      `app.inject()` Fastify pour tester routes/headers/rate-limit sans réseau).
- [ ] Rappels maison : semver, README, liste des fichiers modifiés, GO avant prod.

---

## 3. Format du rapport
```
# Audit endpoints — solo (vX.Y.Z) — <date>
## Verdict : surface HTTP saine ? OUI/NON
## 1. Capability/IDOR/énumération (dont store.list() exposé ?)
## 2. Rate-limit : clé, fallback null, budgets, auto-DoS
## 3. Fuite d'info (stack/chemins/versions)
## 4. CSP/helmet (script inline ? en-têtes sur tous chemins ?)
## 5. Static & traversal ; injection d'en-tête /export
## 6. rDNS/DNS : SSRF ? amplification ? (mitigations)
## 7. Auth dormante & secrets
## 8. Remédiation priorisée + tests ajoutés
```

## 4. Checklist de complétude
- [ ] Confirmé : aucune route n'expose `store.list()` / n'énumère les sessions.
- [ ] Comportement du rate-limit quand `getRealRemoteForSocket` renvoie null : tranché.
- [ ] CSP validée contre le HTML/bundle réel (pas de script inline non couvert).
- [ ] Aucune sortie réseau déclenchée par entrée client (grep fetch/http.get).
- [ ] ADMIN_TOKEN/SESSION_SECRET : ni route admin contournable ni demi-câblage.
- [ ] Tout non-couvert listé (aucun cap muet) ; findings avec repro + test.
