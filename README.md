# solo — Fingerprint Lab

Laboratoire pédagogique de fingerprinting :

- **TLS** : interception du `ClientHello`, parser maison, calcul **JA3** + **JA4**.
- **HTTP** : capture de l'ordre des en-têtes, détection d'incohérences (UA / Sec-CH-UA, etc.).
- **IP** : lookup ASN/organisation via base MaxMind locale, heuristique datacenter/VPN, sortie Tor.
- **Navigateur** : `navigator`, `screen`, locale, `canvas`, `WebGL`, audio offline, fonts, WebRTC, codecs, permissions, marqueurs d'automatisation.
- **Comportemental** : souris, clavier, scroll, touch + agrégats (rythme uniquement — le texte tapé n'est jamais enregistré).

Tout est écrit à la main, sans lib de fingerprinting tierce, sans dépendance réseau au runtime.

---

## Démarrage — clé en main

Pré-requis : **Docker** + **Docker Compose**. Rien d'autre.

```bash
git clone <repo> solo && cd solo
docker compose up -d --build
```

C'est tout. Au premier démarrage l'`entrypoint` :

1. **génère un certificat TLS self-signed** si tu n'en fournis pas (plus besoin de `mkcert`),
2. **corrige les permissions** des volumes `./certs` et `./data` (plus de `chown` manuel),
3. **lâche les privilèges** vers un utilisateur non-root (uid 10001) avant de lancer Node.

Accès : **https://&lt;hôte&gt;:8443** — le certificat est self-signed, ton navigateur affichera un avertissement à accepter une fois.

Vérifier l'état :

```bash
curl -k https://localhost:8443/healthz
# {"status":"ok","version":"1.3.0","db":true,"geoip":{...},...}
```

### Configuration (optionnelle)

Toutes les variables ont un défaut. Pour en surcharger, copie `.env.example` vers `.env` :

```bash
cp .env.example .env   # puis édite (TLS_CN = ton hostname, etc.)
```

### Fournir ton propre certificat

Dépose `cert.pem` + `key.pem` dans `./certs/` avant le `up` : l'entrypoint les utilise tels quels au lieu d'en générer un.

### Activer l'enrichissement IP (GeoIP / Tor)

Sans ces fichiers, le serveur démarre normalement mais l'ASN/pays/Tor renvoient `null`. Pour les activer, dépose dans `./data/` :

- `GeoLite2-ASN.mmdb` et `GeoLite2-Country.mmdb` (compte MaxMind gratuit requis),
- `tor-exit-nodes.txt` (liste des nœuds de sortie Tor, ex. `check.torproject.org/torbulkexitlist`).

Puis `docker compose restart`.

---

## Architecture

```
TCP server (:8443)
   └── proxy transparent → capture + réassemblage du ClientHello → JA3/JA4
       └── forward vers un TLS server loopback (handshake)
           └── secureConnection → handoff au HTTP server (Fastify)
               └── routes (/, /collect, /api/fp/*, /recap, /export, /healthz)
```

La fingerprint TLS est gardée dans une `Map` indexée par le port éphémère loopback au moment du peek, puis retrouvée côté Fastify via `req.raw.socket`. Le ClientHello est réassemblé sur plusieurs segments TCP (les hellos post-quantiques de Chrome dépassent un MSS).

---

## Stack

- **Serveur** : Node ≥ 20, Fastify 4, `@fastify/static`, `@fastify/helmet`, `@fastify/rate-limit`, `maxmind`, `better-sqlite3`. Modules natifs : `net`, `tls`, `http`, `crypto`.
- **Client** : TypeScript, bundle Vite (multi-pages : `index.html`, `recap.html`), animations GSAP **bundlées localement**. Aucune dépendance réseau au runtime.
- **Stockage** : **SQLite** (`better-sqlite3`, WAL) dans `./data/solo.db`. Schéma hybride (colonnes indexables + blobs JSON). TTL 1h + sweeper toutes les 5 min ; checkpoint WAL à l'arrêt.

### Lisibilité du recap (libellés au rendu)

Le recap traduit les identifiants bruts en libellés humains **uniquement à l'affichage** (`src/ui/registry.ts`), la base garde toujours les valeurs brutes (intégrité JA3/JA4) :

- **TLS** : ciphers, extensions, courbes/groupes et algos de signature affichés sous leur **nom IANA** (`TLS_AES_128_GCM_SHA256 (0x1301)`…), GREASE et codes inconnus repérés sans perdre le hex.
- **Storage & `performance.memory`** : octets formatés en **Go / Mo** (avec le quota signalé comme budget navigateur, pas le disque).
- **Plugins & MIME types** : le collecteur capture désormais les **noms** (`navigator.plugins` / `navigator.mimeTypes`), plus seulement le compte.
- **Matériel (déduit)** : section dédiée regroupant CPU (cœurs), RAM (`deviceMemory`) et GPU (`unmasked renderer` WebGL).
- **Pays** : code ISO → **drapeau + nom** (`🇫🇷 France (FR)`) via `Intl.DisplayNames`, plus une ligne de **cohérence locale ↔ IP** (divergence = indice VPN/proxy).
- **Fuseau horaire** : offset brut → `UTC±HH:MM`.
- **Codecs** : chaînes MIME → noms lisibles (`H.264`, `H.265/HEVC`, `VP9`, `AV1`, `AAC-LC`, `Opus`…).
- **Moteur JS** : `v8`/`spidermonkey`/`javascriptcore` → famille navigateur (Chrome/Edge, Firefox, Safari).
- **Voix de synthèse** : code langue BCP-47 → langue lisible (`fr-FR` → Français (France)).
- **Locale** : `calendar` et `numberingSystem` → libellés (`gregory` → Grégorien, `latn` → Latins).
- **devicePixelRatio** : annotation `HiDPI / Retina`.

> Les dictionnaires (TLS, codecs, calendriers, numérotations) vivent dans `src/ui/registry.ts` — c'est le seul fichier à éditer pour enrichir un libellé. Les noms de pays/langues s'appuient sur `Intl.DisplayNames` (natif, rendu dans la langue du navigateur qui consulte).

---

## Moteur de décision (bot vs humain)

Un moteur **déterministe** (`src/shared/decision/`) transforme l'empreinte en un verdict (`bot` / `suspect` / `clean` / `unknown`) + un score, et un feu tricolore par carte dans le recap. La détection (registry) et la pondération (config) sont **séparées** : on retune les poids/seuils dans `config.ts` sans toucher au code de détection. La `version` des règles est persistée avec chaque verdict.

- **Niveau 1 — aveux d'automatisation** : signaux **durs** (un seul force `bot`) — `navigator.webdriver`, globales Playwright/Selenium/CDP, UA HeadlessChrome — et signaux **mous** pondérés (`chrome.runtime` absent sur UA Chrome, 0 plugin…).
- **Niveau 2 — réseau / contexte** (côté serveur, non masquable en JS) : **tous mous**, jamais de `bot` forcé (un humain derrière un VPN reste un humain). Pile **TLS ≠ User-Agent**, en-têtes HTTP incohérents, **sortie Tor**, **IP datacenter**, indice **proxy/VPN**, reverse-DNS hébergeur, RTT incompatible avec un mobile distant.

### Classification réseau — ASN par numéro

`src/server/enrich/asn.ts` classe l'IP en testant d'abord le **numéro d'AS** contre des `Set` curés (`DATACENTER_ASNS`, `VPN_ASNS` — AWS 16509, Google 15169, Azure 8075, OVH 16276, Hetzner 24940, Hostinger 47583…), puis en repli sur le **nom d'ASN** par mots-clés (incluant les services de scraping : Bright Data, Oxylabs, Smartproxy…). Le numéro est plus fiable et stable que le nom ; il classe même les IP où GeoLite renvoie un numéro sans organisation. Ces flags (`isDatacenter`, `isProxyHint`) alimentent les signaux `ip_datacenter` / `ip_proxy` du Niveau 2, dont l'**evidence** affiche l'AS (`AS16509 Amazon…`).

> Limite : les proxies **résidentiels** (Bright Data, Oxylabs) sortent via des IP de vrais FAI sur des ASN ordinaires — leurs IP de sortie échappent à cette couche. La détection ASN ne couvre que les datacenters et les passerelles déclarées.

---

## Endpoints

| Méthode | Route          | Rôle                                                                   |
| ------- | -------------- | ---------------------------------------------------------------------- |
| GET     | `/`            | Page de collecte (consentement → collectors + behavioral)              |
| GET     | `/recap/:id`   | Page de récap par session (coquille HTML)                              |
| GET     | `/api/fp/me`   | Snapshot serveur (TLS + HTTP + IP) pour la connexion en cours          |
| GET     | `/api/fp/:id`  | Fingerprint complet par session (id = UUID v4 non devinable)           |
| POST    | `/collect`     | Reçoit le payload client, génère un sessionId serveur, renvoie l'URL recap |
| GET     | `/export/:id`  | Téléchargement JSON                                                    |
| GET     | `/healthz`     | Liveness/readiness (utilisé par le healthcheck Docker)                 |

> Le `sessionId` est **généré côté serveur** (UUID v4, 122 bits) : l'URL de recap est une capacité non devinable. Il n'existe volontairement **aucun endpoint qui liste les sessions**.

---

## Sécurité & vie privée

- **Consentement explicite** avant toute collecte (catégories de données listées).
- En-têtes de sécurité via Helmet (CSP stricte, `frame-ancestors 'none'`, nosniff…).
- Rate-limiting par IP réelle, limite de taille de corps sur `/collect`.
- Pas de confiance en `X-Forwarded-For` (exposition directe) : l'IP vient du socket TCP réel.
- Données personnelles éphémères (TTL 1h), supprimées automatiquement ; le texte tapé n'est **jamais** collecté (seul le rythme l'est).

---

## Développement local

> Optionnel — le flux nominal est Docker. Nécessite Node ≥ 20.

```bash
npm install
npm run dev:server      # tsx watch
npm run build:client -- --watch   # dans un autre terminal
```

Qualité :

```bash
npm run typecheck
npm test            # vitest : parsers JA3/JA4, ClientHello, incohérences HTTP
npm run lint
npm run format
```

Pour un run local hors Docker, génère un certificat (ex. `mkcert -key-file certs/key.pem -cert-file certs/cert.pem localhost 127.0.0.1 ::1`) puis `npm run build && npm start`.

---

## Vérifications externes

Pour valider tes JA3/JA4, compare ton `/api/fp/me` avec :

- https://tools.scrapfly.io/api/fp/ja3
- https://tlsfingerprint.io
- https://browserleaks.com/tls

Une suite de tests automatisés (`npm test`) couvre désormais le parseur ClientHello, la dérivation JA3/JA4 (filtrage GREASE inclus) et la détection d'incohérences HTTP.

---

## Limites connues

- Pas de support HTTP/2 (ALPN forcé sur `http/1.1`) — volontaire, pour garder le bridge lisible.
- JA4 suit la spec FoxIO simplifiée (TCP/TLS) ; le tag QUIC n'est pas géré.
- La détection de fonts par mesure est approximative ; `queryLocalFonts()` (si autorisé) donne la liste exacte.

---

Voir [CHANGELOG.md](CHANGELOG.md) pour l'historique des versions.
