# Audit durcissement conteneur/runtime — solo (v1.3.0) — 2026-06-05

Audit **statique** (lecture seule, aucun build/docker exécuté — déploiement LXC).
Périmètre : `Dockerfile`, `entrypoint.sh`, `docker-compose.yml`, `.dockerignore`,
`.env.example`, gestion des secrets et intégrité MaxMind.

## Verdict : posture runtime **À DURCIR** (base solide image/entrypoint, orchestration nue)

La couche **image** et la couche **entrypoint** sont soignées et tiennent
(multi-stage, non-root via gosu uid 10001, clé 0600 fail-closed, TLS_CN assaini,
healthcheck TLS vérifié, aucun secret loggué au boot, intégrité MaxMind disponible).

La couche **orchestration (compose)** n'applique **aucun** durcissement de
privilèges ni de surface : pas de `no-new-privileges`, pas de `cap_drop`, rootfs
inscriptible, aucune limite de ressources, exposition sur `0.0.0.0`. C'est là que
se concentrent les findings P1.

### Top 3 critiques
1. **P1 — Aucun durcissement de privilèges/surface dans compose** : ni
   `no-new-privileges:true`, ni `cap_drop: ALL`, ni `read_only: true`. Un RCE via
   le process Node (parsers d'octets bruts pré-auth, cf. audit-parsers) dispose de
   toutes les capabilities Linux par défaut et d'un rootfs inscriptible.
2. **P1 — Aucune limite de ressources** (`mem_limit`/`pids_limit`/`cpus`/`ulimits`)
   : un OOM/fork-bomb/slowloris n'est borné par rien ; le blast radius d'un DoS
   déborde sur tout l'hôte LXC.
3. **P1 — Base image non pinnée par digest + pas de lockfile committé** :
   `node:20-bookworm-slim` est un tag mutable et `npm install` (fallback sans lock)
   n'est pas reproductible → un rebuild peut tirer une base/des deps différentes.

| Sévérité | Nb | Findings |
|----------|----|----------|
| P1 | 4 | no-new-privileges/cap_drop manquants ; read_only/tmpfs manquants ; limites ressources absentes ; base non pinnée + pas de lockfile |
| P2 | 4 | exposition 0.0.0.0 ; MaxMind sans pinning d'intégrité par défaut ; `chown -R` récursif au boot ; image runtime n'utilise pas `USER` (acceptable mais à documenter) |
| P3 | 3 | clé TLS non chiffrée sur bind-mount (inhérent) ; HSTS désactivé (assumé) ; pas de scan trivy CVE OS (non exécuté ici, recommandé en CI) |

---

## 1. Image (Dockerfile)

**Ce qui tient :**
- **Multi-stage correct** : `python3/make/g++` présents **uniquement** dans le
  builder (lignes 10-12). L'étage runtime n'installe que `openssl gosu
  ca-certificates` (ligne 41) → aucun outil de build ne fuit dans le runtime.
- **`npm prune --omit=dev`** (ligne 25) avant la copie → seules les deps prod sont
  copiées dans le runtime (ligne 47).
- **User non-root créé** : `useradd -r -u 10001 -m solo` (ligne 43), ownership
  posé sur `/app /data /certs` (ligne 45).
- **HEALTHCHECK** défini côté compose, en node (pas de curl) → OK.
- **`.dockerignore`** exclut bien `.git`, `data`, `certs`, `node_modules`, `.env`,
  `.env.local`, `tests` → aucune donnée/secret embarqué dans une layer. **Bon.**

**Findings :**

### [P1] Base image non pinnée par digest
`FROM node:20-bookworm-slim` (lignes 4 et 29) est un **tag mutable**. Un rebuild à
6 mois d'intervalle peut produire une image OS différente sans changement de code.
Reco : pinner par digest sur les deux étages, p.ex.
```dockerfile
FROM node:20-bookworm-slim@sha256:<digest> AS builder
...
FROM node:20-bookworm-slim@sha256:<digest> AS runtime
```
(Récupérer le digest courant via `docker buildx imagetools inspect node:20-bookworm-slim`.)
Recoupe audit-deps.

### [P1] Pas de lockfile committé → build non reproductible
Ligne 17 : `if [ -f package-lock.json ]; then npm ci; else npm install; fi`.
`package-lock.json` **n'est pas dans le repo** (vérifié : absent à la racine, et
`COPY package-lock.json*` avec le glob optionnel ligne 15). On tombe donc sur la
branche `npm install` → résolution non déterministe, surface supply-chain ouverte.
Reco : committer `package-lock.json` pour forcer `npm ci`. Recoupe audit-deps.

### [P2] Image runtime n'utilise pas `USER` (par conception)
Le commentaire (lignes 37-39) l'assume : le conteneur démarre **root** pour
chown/cert puis `exec gosu`. C'est **correct et nécessaire** ici (bind-mounts +
génération cert). À conserver, mais c'est précisément pourquoi `cap_drop`/
`no-new-privileges` côté compose sont indispensables (cf. §3) : sans `USER`, le PID
1 root garde toutes les capabilities tant que l'entrypoint n'a pas exec gosu.

### Note — scripts d'install `better-sqlite3`
`npm ci`/`npm install` n'inhibe pas les scripts post-install ; `better-sqlite3`
télécharge/compile un prebuild dans le builder. Confirmé que c'est isolé au
builder (ne fuit pas en runtime), mais un paquet compromis exécuterait du code au
build. Détail couvert par audit-deps phase 3.

---

## 2. Entrypoint (privilèges, cert, perms)

**Ce qui tient (confirmé) :**
- **Drop de privilèges effectif** : `exec gosu "$APP_UID:$APP_GID" node
  dist/server/index.js` (ligne 70). `gosu` ne laisse **aucune** capability
  résiduelle au process Node (contrairement à `su`/`sudo`) ; le process Node ne
  tourne **jamais** en root. Confirmé : rien après le drop ne re-nécessite root.
- **TLS_CN assaini** : le filtre `case … *[!a-zA-Z0-9.-]*` (lignes 22-27) rejette
  tout caractère non hostname → bloque l'injection d'options openssl via `-subj`
  ET `-addext`. **Vérifié** : `$TLS_CN` est le **seul** champ interpolé dans la
  commande openssl (lignes 42-43) ; le SAN (`DNS:localhost,DNS:$TLS_CN,
  IP:127.0.0.1,IP:::1`) réutilise la même variable déjà assainie → pas d'autre
  vecteur d'injection. **Bon.**
- **Clé créée 0600 atomiquement** : `umask 0077` dans un sous-shell (lignes 38-44)
  **avant** l'écriture openssl → la clé privée n'est jamais exposée sous l'umask
  par défaut, même fugacement. Le sous-shell empêche l'umask restrictif de fuir.
- **Fail-closed sur perms clé** : lignes 58-66, on lit les **vraies** perms via
  `stat` (pas confiance au `chmod` qui peut être un no-op si `./certs` monté ro) et
  on `exit 1` si ce n'est pas 600/400. **Excellent** — une clé group/other-readable
  n'atteint jamais le réseau.
- **Cert** : RSA 2048, 825 jours, `-nodes` (clé non chiffrée — normal pour boot
  auto), SAN corrects. Idempotent (régénère seulement si cert OU clé absent).

**Findings :**

### [P2] `chown -R "$APP_UID:$APP_GID" "$DATA_DIR"` récursif à chaque boot
Ligne 52. Sur un gros volume `/data`, coût I/O à chaque démarrage ; et un fichier
hostile déposé dans le bind-mount serait chowné vers l'uid app. **Acceptable**
(les fichiers app appartiennent déjà à l'uid app), mais à noter. Atténuation
possible : ne chown que si l'ownership diffère, ou ne pas faire de récursif si le
répertoire est déjà correctement possédé.

### [P3] Clé TLS non chiffrée lisible par root de l'hôte
La clé `-nodes` sur le bind-mount `./certs` est lisible par root de l'hôte LXC
(inhérent aux bind-mounts, pas un défaut de solo). À documenter dans le README ;
pour durcir, monter `./certs` en `:ro` une fois le cert généré, ou utiliser un
volume nommé avec ACL hôte restrictive.

---

## 3. Orchestration (docker-compose.yml) — les vrais manques

**Ce qui tient :** `init: true`, `restart: unless-stopped`, logs cappés (10m×3),
healthcheck TLS **vérifié** (`ca` = cert généré + `servername` forcé → MITM local
échoue), aucun `privileged:true`, aucun montage du socket Docker, pas de
`network_mode: host`. **Bon point de départ.**

> **Analyse de faisabilité du durcissement** (statique) : le seul chemin en
> écriture du process Node est `/data` (SQLite WAL — `db.ts` pose
> `journal_mode=WAL`, écrit `.db`/`.db-wal`/`.db-shm` ; `wal_checkpoint(TRUNCATE)`
> au shutdown). Aucune écriture dans le CWD `/app` ni `/tmp` détectée côté serveur
> (`grep` confirme : seul `fs.mkdirSync` sur le dir de la DB). `/certs` est écrit
> **par l'entrypoint root avant le drop**, pas par Node. **Donc `read_only: true`
> est viable** dès lors que `/data` et `/certs` restent des volumes en écriture, +
> un `tmpfs` sur `/tmp` par prudence (better-sqlite3/openssl peuvent y écrire).

### [P1] Ajouter `no-new-privileges` + `cap_drop`/`cap_add`
Le process non-root n'a besoin d'**aucune** capability. Mais l'**entrypoint root**
a besoin avant le drop de : `CHOWN` (chown /data,/certs), `SETUID`/`SETGID`
(gosu→uid 10001), `DAC_OVERRIDE` (écrire dans des bind-mounts root:root),
`FOWNER`/`CHOWN` (chmod 600 de la clé). Donc **ne pas** faire `cap_drop: ALL` sans
`cap_add`, sinon le chown/gosu de l'entrypoint casse au boot.

```yaml
    security_opt:
      - "no-new-privileges:true"
    cap_drop:
      - ALL
    cap_add:
      - CHOWN          # chown /data /certs /cert.pem /key.pem
      - DAC_OVERRIDE   # écrire/chmod dans des bind-mounts root:root
      - FOWNER         # chmod 600 sur la clé
      - SETUID         # gosu → uid 10001
      - SETGID         # gosu → gid 10001
```
> **Validation « démarre toujours »** (raisonnée, à confirmer au 1er déploiement) :
> avec ces 5 caps, l'entrypoint root peut chown/chmod/gosu ; après `exec gosu`, le
> process Node tourne en uid 10001 et `no-new-privileges` empêche toute
> ré-escalade via setuid. Si au boot le chown échoue malgré tout, élargir
> temporairement à `cap_drop: []` pour isoler la cap manquante, puis resserrer.
> **Ne PAS** mettre `no-new-privileges` **sans** garder SETUID/SETGID : gosu en a
> besoin pour le drop initial (le flag empêche le *gain* de privilèges, pas le
> *drop* root→user effectué par PID1 root avant exec).

### [P1] Rootfs en lecture seule + tmpfs
```yaml
    read_only: true
    tmpfs:
      - /tmp:size=64m,mode=1777
```
Les volumes `./certs:/certs` et `./data:/data` restent inscriptibles (déclarés en
§volumes) → couvrent tous les chemins d'écriture réels. Le reste du rootfs devient
immuable : un attaquant ne peut plus déposer de binaire/persister dans `/app`,
`/usr`, etc.

### [P1] Limites de ressources (blast radius DoS)
```yaml
    mem_limit: 512m
    memswap_limit: 512m      # pas de swap → OOM contenu, pas de thrash hôte
    pids_limit: 256          # borne fork-bomb / threads
    cpus: "1.5"
    ulimits:
      nofile:
        soft: 4096
        hard: 8192           # borne les FD/sockets (slowloris, cf. audit-parsers)
```
Cohérent avec audit-parsers : un OOM parser ClientHello est contenu au conteneur
au lieu d'OOM-killer sur l'hôte LXC. Ajuster `mem_limit` selon la taille des bases
MaxMind chargées en mémoire.

### [P2] Exposition réseau `0.0.0.0`
`ports: "8443:8443"` (ligne 14) bind sur **toutes** les interfaces de l'hôte. Le
ClientHello brut **impose** une exposition directe (pas de reverse-proxy TLS qui
casserait JA3/JA4) — c'est documenté ligne 11-12. Mais si solo n'est pas censé être
public, restreindre :
```yaml
    ports:
      - "127.0.0.1:8443:8443"   # ou l'IP LAN du LXC uniquement
```
À défaut, **documenter explicitement** que la protection repose entièrement sur le
firewall LXC (cf. note de `.env.example` : « NO application-level authentication »).
Décision opérateur — fournir le bloc, laisser le choix.

---

## 4. Secrets & intégrité MaxMind

**Ce qui tient :**
- **Aucun secret en dur** dans le Dockerfile/compose. Vérifié.
- **Aucun secret loggué au boot** : le log de démarrage (`index.ts` lignes 159-171)
  liste `version/port/host/geoip/country/tor/db/cert` — **aucun secret**. Le logger
  Fastify redact `cookie`/`authorization` (ligne 70). **Confirmé bon.**
- **`SESSION_SECRET`/`ADMIN_TOKEN` retirés** : `.env.example` (lignes 30-31)
  documente leur suppression — « nothing in the code read them, so setting one gave
  a false sense of protection ». Vérifié par grep : **aucune** référence à
  `SESSION_SECRET`/`ADMIN_TOKEN` dans `src/`. Donc **pas de défaut faible/prévisible
  type "changeme"** non plus → posture saine (mieux qu'un secret factice ignoré).
  À noter : les endpoints data restent protégés uniquement par l'UUID non
  devinable de l'URL (capability), `/collect` ouvert et rate-limité (cf.
  audit-endpoints).
- `env_file` `required: false` (compose lignes 17-19) → `.env` optionnel, secrets
  hors image.

**Findings :**

### [P2] Intégrité MaxMind disponible mais non pinnée par défaut
`index.ts` (lignes 54-57) supporte `GEOIP_DB_SHA256` / `GEOIP_COUNTRY_DB_SHA256`,
et `verifyFileSha256` (`enrich/integrity.ts`) **fail-closed correctement** : il
hash en streaming et `throw` sur mismatch — mais **opt-in** (`if (!want) return
true`, ligne 21). Ces variables ne sont **renseignées ni dans `.env.example` ni
dans compose** → par défaut une base `.mmdb` altérée est chargée sans contrôle (le
parser .mmdb traite un binaire attaquant-influençable, cf. audit-parsers phase 4).
Reco : documenter + renseigner les digests dans `.env` après téléchargement
officiel MaxMind :
```bash
# Calculer une fois après téléchargement :
sha256sum data/GeoLite2-ASN.mmdb data/GeoLite2-Country.mmdb
```
```dotenv
GEOIP_DB_SHA256=<digest_asn>
GEOIP_COUNTRY_DB_SHA256=<digest_country>
```
La logique est déjà correcte (streaming, lowercase, trim, comparaison exacte) — il
ne manque que le **renseignement** des valeurs.

### [P3] Rappel maison — sauvegarde Dashlane
Aucun secret réellement critique aujourd'hui (SESSION_SECRET/ADMIN_TOKEN retirés).
Si un secret applicatif est réintroduit, sauvegarde Dashlane obligatoire à chaque
touch du `.env` (convention maison, cf. VAULT_MASTER_KEY ailleurs).

---

## 5. Vulnérabilités image (trivy)

**Non exécuté** — audit statique, aucun build/docker en local (contrainte LXC).
À lancer en CI ou sur le LXC :
```bash
docker build -t solo:audit .
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy:latest image --severity HIGH,CRITICAL solo:audit
```
Confirmé par lecture : `NODE_ENV=production` bien posé (Dockerfile ligne 32 +
compose ligne 25) ; Node 20 (non EOL au 2026-06, support jusqu'à ~2026-04 en
maintenance — **vérifier la fin de support et planifier Node 22 LTS**). Le pinning
par digest (§1) figera aussi la base scannée.

---

## 6. Remédiation priorisée + validation « démarre toujours »

| Prio | Action | Fichier | Risque si conservé |
|------|--------|---------|--------------------|
| **P1** | `security_opt: no-new-privileges` + `cap_drop: ALL` + `cap_add` minimal (CHOWN, DAC_OVERRIDE, FOWNER, SETUID, SETGID) | compose | Escalade post-RCE, toutes caps dispo |
| **P1** | `read_only: true` + `tmpfs: /tmp` | compose | Persistance/dépôt binaire sur rootfs après RCE |
| **P1** | `mem_limit`/`memswap_limit`/`pids_limit`/`cpus`/`ulimits.nofile` | compose | DoS/OOM/fork-bomb débordant sur l'hôte |
| **P1** | Pinner base par `@sha256` + committer `package-lock.json` (→ `npm ci`) | Dockerfile + repo | Build non reproductible / dérive supply-chain |
| **P2** | `127.0.0.1:8443:8443` (ou documenter le firewall LXC comme seule défense) | compose | Exposition publique non voulue |
| **P2** | Renseigner `GEOIP_DB_SHA256`/`GEOIP_COUNTRY_DB_SHA256` | .env | Base MaxMind altérée chargée sans contrôle |
| **P2** | chown conditionnel (éviter `-R` systématique) | entrypoint.sh | Coût I/O boot / chown de fichier hostile |
| **P3** | Doc clé non chiffrée + `./certs:ro` post-génération ; planifier Node 22 LTS ; trivy en CI | README/CI | — |

**Bloc compose consolidé à insérer** (sous `init: true`, avant `ports:`) — **GO
opérateur requis avant application en prod** :
```yaml
    security_opt:
      - "no-new-privileges:true"
    cap_drop:
      - ALL
    cap_add:
      - CHOWN
      - DAC_OVERRIDE
      - FOWNER
      - SETUID
      - SETGID
    read_only: true
    tmpfs:
      - /tmp:size=64m,mode=1777
    mem_limit: 512m
    memswap_limit: 512m
    pids_limit: 256
    cpus: "1.5"
    ulimits:
      nofile:
        soft: 4096
        hard: 8192
```

**Validation « le conteneur démarre toujours » (raisonnée — à confirmer au 1er
boot sur LXC) :**
1. PID1 root exécute l'entrypoint → chown `/data`/`/certs` (CHOWN+DAC_OVERRIDE),
   génération cert + chmod 600 (FOWNER), puis `exec gosu` (SETUID+SETGID). ✅ avec
   les 5 caps.
2. `read_only: true` : écritures uniquement vers volumes `/data` (SQLite WAL) et
   `/certs` (cert) + tmpfs `/tmp`. Aucune écriture serveur ailleurs (vérifié par
   grep). ✅
3. `no-new-privileges` : n'empêche pas le drop root→uid 10001 (réalisé par PID1
   root avant exec), empêche seulement le *gain* ultérieur via setuid. ✅
4. Healthcheck node inchangé (lit cert, GET /healthz). ✅

**Rappels maison :** bump semver à la prochaine modif compose/Dockerfile ; MAJ
README (toute commande de déploiement qui change, dont les digests MaxMind et le
pinning) ; **GO explicite avant** d'appliquer en prod ; lister les fichiers
modifiés en fin de session.

---

### Checklist de complétude
- [x] Confirmé : process Node non-root, drop gosu effectif, clé 0600 fail-closed.
- [x] Blocs compose de durcissement proposés + validation « démarre toujours » raisonnée (build/docker non exécutés — contrainte LXC).
- [x] `cap_drop: ALL` vs besoin root entrypoint : tranché → `cap_add` minimal (CHOWN, DAC_OVERRIDE, FOWNER, SETUID, SETGID).
- [x] Aucun secret en dur ni loggué ; intégrité MaxMind recommandée (logique OK, valeurs à renseigner).
- [ ] trivy : **non exécuté** (audit statique) — commande fournie pour CI/LXC.
- [x] Tout non-couvert listé (aucun cap muet) ; recos avec YAML exact + repro.
