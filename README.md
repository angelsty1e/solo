# solo — Fingerprint Lab

Laboratoire pédagogique de **fingerprinting**, sans librairie tierce et sans dépendance réseau au runtime. Il capture et explique tout ce qu'un serveur peut apprendre d'un navigateur :

| Couche | Ce qui est mesuré |
| --- | --- |
| **TLS** | interception du `ClientHello`, parser maison, calcul **JA3** + **JA4** |
| **HTTP** | ordre des en-têtes, incohérences (UA / `Sec-CH-UA`…) |
| **IP** | ASN/organisation (MaxMind), heuristique datacenter/VPN, nœud de sortie Tor |
| **Navigateur** | `navigator`, `screen`, locale, `canvas`, WebGL, audio, fonts, WebRTC, codecs, permissions, marqueurs d'automatisation |
| **Comportemental** | souris, clavier, scroll, touch — **rythme uniquement**, jamais le texte tapé |

Le tout alimente un **moteur de décision déterministe** qui rend un verdict `bot` / `suspect` / `clean`.

---

## Sommaire

- [🚀 Démarrage rapide](#-démarrage-rapide)
- [⚙️ Configuration](#️-configuration)
- [🪟 Windows / WSL — à lire](#-windows--wsl--à-lire)
- [🏗️ Architecture](#️-architecture)
- [📁 Structure du projet](#-structure-du-projet)
- [🧠 Moteur de décision (bot vs humain)](#-moteur-de-décision-bot-vs-humain)
- [🔌 Endpoints](#-endpoints)
- [🔒 Sécurité & vie privée](#-sécurité--vie-privée)
- [🧰 Stack](#-stack)
- [👩‍💻 Développement local](#-développement-local)
- [✅ Vérifications externes & tests](#-vérifications-externes--tests)
- [📌 Limites connues](#-limites-connues)

---

## 🚀 Démarrage rapide

**Pré-requis :** Docker + Docker Compose. Rien d'autre.
Sur Windows : **Docker Desktop avec le backend WSL2** (lire la [section Windows](#-windows--wsl--à-lire)).

### 1. (Optionnel) Générer ton certificat TLS

solo génère **automatiquement** un certificat self-signed au premier démarrage : tu peux sauter cette étape. Génère le tien seulement si tu veux contrôler le CN ou réutiliser un certificat existant. Dépose-le dans `./certs/` **avant** le `docker compose up`.

<details open>
<summary><b>macOS / Linux</b> (et Windows via Git Bash)</summary>

```bash
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout certs/key.pem -out certs/cert.pem \
  -days 825 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1"
chmod 600 certs/key.pem
```
</details>

<details>
<summary><b>Windows — PowerShell</b></summary>

```powershell
mkdir certs -Force
openssl req -x509 -newkey rsa:2048 -nodes `
  -keyout certs\key.pem -out certs\cert.pem `
  -days 825 -subj "/CN=localhost" `
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1"
```

> Pas d'`openssl` sous Windows ? Trois options :
> - **Git for Windows** : ouvre **Git Bash** et lance la commande macOS/Linux ci-dessus (openssl est inclus) ;
> - `winget install ShiningLight.OpenSSL.Light` puis rouvre le terminal ;
> - ou ne génère rien : solo crée le certificat tout seul au démarrage.
</details>

### 2. Lancer

```bash
git clone <repo> solo && cd solo
docker compose up -d --build
```

Au premier démarrage, l'`entrypoint` (lancé en root, puis dégradé en uid non-root 10001) :

1. **génère un certificat self-signed** si `./certs/` est vide,
2. **corrige les permissions** des volumes,
3. **lâche les privilèges** avant de lancer Node.

### 3. Ouvrir

➡️ **https://localhost:8443**

Le certificat est self-signed : le navigateur affiche un avertissement à accepter une fois.

### 4. Vérifier l'état

```bash
docker compose ps          # STATUS doit passer "healthy"
curl -k https://localhost:8443/healthz
# {"status":"ok","version":"1.4.2","db":true,"geoip":{...},...}
```

---

## ⚙️ Configuration

Toutes les variables ont un défaut : un `.env` vide (ou absent) suffit. Pour surcharger :

```bash
cp .env.example .env   # puis édite (TLS_CN = ton hostname, etc.)
```

### Fournir ton propre certificat

Dépose `cert.pem` + `key.pem` dans `./certs/` avant le `up` (voir [étape 1](#1-optionnel-générer-ton-certificat-tls)) : l'entrypoint les utilise tels quels au lieu d'en générer un.

### Activer l'enrichissement IP (GeoIP / Tor)

Sans ces fichiers le serveur démarre normalement, mais l'ASN/pays/Tor renvoient `null`. Pour les activer, dépose dans `./data/` (monté en **lecture seule**) :

- `GeoLite2-ASN.mmdb` + `GeoLite2-Country.mmdb` — compte MaxMind gratuit requis,
- `tor-exit-nodes.txt` — ex. `check.torproject.org/torbulkexitlist`,

puis `docker compose restart`.

> **Intégrité (optionnel, fail-closed).** Renseigne `GEOIP_DB_SHA256` / `GEOIP_COUNTRY_DB_SHA256` dans `.env` pour qu'une base `.mmdb` altérée refuse de se charger. Calcul : `sha256sum data/GeoLite2-*.mmdb`.

---

## 🪟 Windows / WSL — à lire

solo tourne dans un conteneur **Linux** ; or les systèmes de fichiers Windows partagés dans WSL (`C:\…` → `/mnt/c/…`, protocole 9p/DrvFs) **n'implémentent pas les permissions Unix ni le `mmap`**. Deux conséquences historiques, **toutes deux corrigées** :

| Symptôme | Cause | Correctif intégré |
| --- | --- | --- |
| `exec /entrypoint.sh: no such file or directory` | shebang converti en CRLF au `git checkout` Windows | `.gitattributes` force LF + le `Dockerfile` neutralise le CR au build |
| `Restarting (1)` en boucle (clé privée non sécurisable en `0600`) | `chmod` ignoré par DrvFs → le garde-fou refusait de démarrer | garde-fou dégradé en **avertissement** pour un cert self-signed localhost |
| `disk I/O error` SQLite (si la base était sur `/mnt/c`) | mode **WAL** (`-shm` + `mmap`) impossible sur 9p | la base vit désormais sur un **volume Docker nommé** (`solo-db`), jamais sur le disque hôte |

➡️ **Résultat : `docker compose up -d` fonctionne depuis n'importe quel dossier Windows.** Pour de **meilleures performances d'I/O**, tu peux quand même cloner le projet dans le système de fichiers natif WSL (`~/solo`) plutôt que sous `C:\`.

---

## 🏗️ Architecture

```
TCP server (:8443)
   └── proxy transparent → capture + réassemblage du ClientHello → JA3/JA4
       └── forward vers un TLS server loopback (handshake)
           └── secureConnection → handoff au HTTP server (Fastify)
               └── routes (/, /collect, /api/fp/*, /recap, /export, /healthz)
```

La fingerprint TLS est gardée dans une `Map` indexée par le port éphémère loopback au moment du *peek*, puis retrouvée côté Fastify via `req.raw.socket`. Le ClientHello est réassemblé sur plusieurs segments TCP (les hellos post-quantiques de Chrome dépassent un MSS).

**Stockage.** SQLite (`better-sqlite3`, **WAL**) sur le volume nommé `solo-db`. Schéma hybride : colonnes scalaires indexables (`GROUP BY ja3_hash`…) + blobs JSON par domaine pour le snapshot complet. TTL 1 h + sweeper toutes les 5 min ; checkpoint WAL à l'arrêt.

---

## 📁 Structure du projet

```
solo/
├── Dockerfile                 # build multi-stage, runtime non-root (gosu uid 10001)
├── docker-compose.yml         # hardening (cap_drop, read_only, tmpfs, limites) + volumes
├── entrypoint.sh              # cert self-signed + perms + drop de privilèges
├── .env.example               # toutes les variables (avec défauts)
│
├── src/
│   ├── server/                # cœur réseau (tout ce qui touche aux octets bruts)
│   │   ├── index.ts           # bootstrap : init DB/GeoIP/Tor, démarrage serveurs
│   │   ├── routes.ts          # routes Fastify
│   │   ├── db.ts  store.ts     # schéma SQLite + accès données (TTL, sweeper)
│   │   ├── tls/               # clienthello.ts · interceptor.ts · ja3.ts · ja4.ts
│   │   ├── http/headers.ts    # parser d'ordre/incohérences des en-têtes
│   │   └── enrich/            # asn · country · geoip · tor · rdns · integrity · pipeline
│   │
│   ├── client/                # collecteurs navigateur (bundle Vite)
│   │   ├── collectors/        # canvas, webgl, audio, fonts, webrtc, navigator…
│   │   └── behavioral/        # mouse, keyboard, scroll, touch + aggregate
│   │
│   ├── shared/
│   │   ├── decision/          # moteur déterministe (detection ⨉ config ⨉ engine)
│   │   ├── types.ts           # types partagés client/serveur
│   │   └── validation.ts      # schémas zod (frontière /collect)
│   │
│   └── ui/                    # index.html, recap.html, registry.ts (libellés), tokens.css
│
└── tests/                     # vitest : parsers JA3/JA4, ClientHello, incohérences HTTP, décision
```

---

## 🧠 Moteur de décision (bot vs humain)

Un moteur **déterministe** (`src/shared/decision/`) transforme l'empreinte en verdict (`bot` / `suspect` / `clean` / `unknown`) + un score, et un feu tricolore par carte dans le recap. La **détection** (registry) et la **pondération** (config) sont séparées : on retune les poids/seuils dans `config.ts` sans toucher au code de détection. La `version` des règles est persistée avec chaque verdict.

- **Niveau 1 — aveux d'automatisation** : signaux **durs** (un seul force `bot`) — `navigator.webdriver`, globales Playwright/Selenium/CDP, UA HeadlessChrome — et signaux **mous** pondérés (`chrome.runtime` absent sur UA Chrome, 0 plugin…).
- **Niveau 2 — réseau / contexte** (côté serveur, non masquable en JS) : **tous mous**, jamais de `bot` forcé (un humain derrière un VPN reste un humain). Pile **TLS ≠ User-Agent**, en-têtes HTTP incohérents, **sortie Tor**, **IP datacenter**, indice **proxy/VPN**, reverse-DNS hébergeur, RTT incompatible avec un mobile distant.

### Classification réseau — ASN par numéro

`src/server/enrich/asn.ts` classe l'IP en testant d'abord le **numéro d'AS** contre des `Set` curés (`DATACENTER_ASNS`, `VPN_ASNS` — AWS 16509, Google 15169, Azure 8075, OVH 16276, Hetzner 24940…), puis en repli sur le **nom d'ASN** par mots-clés (Bright Data, Oxylabs, Smartproxy…). Le numéro est plus fiable que le nom ; il classe même les IP où GeoLite renvoie un numéro sans organisation. Ces flags (`isDatacenter`, `isProxyHint`) alimentent les signaux `ip_datacenter` / `ip_proxy` du Niveau 2.

> **Limite :** les proxies **résidentiels** sortent via des IP de vrais FAI sur des ASN ordinaires — ils échappent à cette couche. La détection ASN ne couvre que les datacenters et passerelles déclarées.

### Lisibilité du recap

Le recap traduit les identifiants bruts en libellés humains **uniquement à l'affichage** (`src/ui/registry.ts`) ; la base garde toujours les valeurs brutes (intégrité JA3/JA4) : noms IANA des ciphers/extensions TLS, octets → Go/Mo, codes pays → drapeau + nom, codecs MIME → noms lisibles, moteur JS → famille navigateur, etc. C'est le seul fichier à éditer pour enrichir un libellé.

---

## 🔌 Endpoints

| Méthode | Route | Rôle |
| --- | --- | --- |
| GET | `/` | Page de collecte (consentement → collectors + behavioral) |
| GET | `/recap/:id` | Page de récap par session (coquille HTML) |
| GET | `/api/fp/me` | Snapshot serveur (TLS + HTTP + IP) pour la connexion en cours |
| GET | `/api/fp/:id` | Fingerprint complet par session (id = UUID v4 non devinable) |
| POST | `/collect` | Reçoit le payload client, génère un `sessionId` serveur, renvoie l'URL recap |
| GET | `/export/:id` | Téléchargement JSON |
| GET | `/healthz` | Liveness/readiness (utilisé par le healthcheck Docker) |

> Le `sessionId` est **généré côté serveur** (UUID v4, 122 bits) : l'URL de recap est une capacité non devinable. Il n'existe volontairement **aucun endpoint qui liste les sessions**.

---

## 🔒 Sécurité & vie privée

- **Consentement explicite** avant toute collecte (catégories de données listées).
- En-têtes de sécurité via Helmet (CSP stricte, `frame-ancestors 'none'`, nosniff…).
- Rate-limiting par IP réelle, limite de taille de corps sur `/collect`.
- Pas de confiance en `X-Forwarded-For` (exposition directe) : l'IP vient du socket TCP réel.
- Données personnelles éphémères (TTL 1 h), supprimées automatiquement ; le texte tapé n'est **jamais** collecté (seul le rythme l'est).
- Conteneur durci : process Node **non-root** (uid 10001 via gosu), `cap_drop: ALL` + caps minimales, `no-new-privileges`, rootfs **read-only**, `/tmp` en tmpfs, limites mémoire/pids.

> ⚠️ **Aucune authentification applicative.** Les endpoints data sont protégés uniquement par l'UUID non devinable dans l'URL ; `/collect` est ouvert et rate-limité. Pour toute exposition, place le lab derrière une isolation réseau (firewall LXC / reverse proxy).

---

## 🧰 Stack

- **Serveur** : Node ≥ 20, **Fastify 4**, `@fastify/static`, `@fastify/helmet`, `@fastify/rate-limit`, `maxmind`, `better-sqlite3`, `zod`. Modules natifs : `net`, `tls`, `http`, `crypto`.
- **Client** : TypeScript, bundle **Vite** (multi-pages : `index.html`, `recap.html`), animations GSAP **bundlées localement**. Aucune dépendance réseau au runtime.
- **Stockage** : **SQLite** (`better-sqlite3`, WAL) sur le volume nommé `solo-db`.

---

## 👩‍💻 Développement local

> Optionnel — le flux nominal est Docker. Nécessite Node ≥ 20.

```bash
npm install
npm run dev:server                 # tsx watch
npm run build:client -- --watch    # dans un autre terminal
```

Qualité :

```bash
npm run typecheck
npm test            # vitest : parsers JA3/JA4, ClientHello, incohérences HTTP, décision
npm run lint
npm run format
```

Pour un run local hors Docker, génère un certificat dans `certs/` (cf. [étape 1](#1-optionnel-générer-ton-certificat-tls) ou `mkcert -key-file certs/key.pem -cert-file certs/cert.pem localhost 127.0.0.1 ::1`) puis `npm run build && npm start`.

---

## ✅ Vérifications externes & tests

Pour valider tes JA3/JA4, compare ton `/api/fp/me` avec :

- https://tools.scrapfly.io/api/fp/ja3
- https://tlsfingerprint.io
- https://browserleaks.com/tls

La suite `npm test` couvre le parseur ClientHello, la dérivation JA3/JA4 (filtrage GREASE inclus), la détection d'incohérences HTTP et le moteur de décision.

---

## 📌 Limites connues

- Pas de support HTTP/2 (ALPN forcé sur `http/1.1`) — volontaire, pour garder le bridge lisible.
- JA4 suit la spec FoxIO simplifiée (TCP/TLS) ; le tag QUIC n'est pas géré.
- La détection de fonts par mesure est approximative ; `queryLocalFonts()` (si autorisé) donne la liste exacte.
- Proxies résidentiels non détectés au niveau ASN (voir [Moteur de décision](#classification-réseau--asn-par-numéro)).
