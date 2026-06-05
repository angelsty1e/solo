---
name: audit-hardening
description: >-
  Audit de durcissement conteneur & runtime de solo : Dockerfile (multi-stage,
  base, non-root via gosu uid 10001), entrypoint.sh (génération de cert
  self-signed, perms clé, drop de privilèges), docker-compose.yml et la gestion
  des secrets (.env / SESSION_SECRET / ADMIN_TOKEN / TLS_CN). Vérifie ce qui tient
  déjà (clé 0600 fail-closed, TLS_CN assaini, process non-root, healthcheck TLS
  vérifié) et traque les durcissements manquants au niveau orchestration :
  cap_drop, no-new-privileges, rootfs read-only, tmpfs, limites mémoire/pids,
  pinning de la base image par digest, intégrité des bases MaxMind, surface du
  conteneur, exposition réseau. Objectif : un conteneur qui, même compromis via le
  process Node, offre le minimum de privilèges et de surface à l'attaquant.
  TRIGGER : "durcir le conteneur / le Docker", "hardening runtime", "le conteneur
  tourne-t-il non-root", "cap_drop / read-only / no-new-privileges", "pinning de
  l'image", "gestion des secrets / cert", "sécurité du déploiement de solo".
---

# audit-hardening — durcissement conteneur & runtime

## 1. Posture actuelle (à confirmer, déjà solide)

Le déploiement est turnkey et déjà soigné. L'audit **vérifie** que ces défenses
tiennent et **comble** ce qui manque au niveau orchestration :

Déjà en place (à confirmer, pas à refaire) :
- Multi-stage : build tools (python/make/g++) **uniquement** dans le builder ;
  `npm prune --omit=dev` avant copie runtime.
- **Non-root** : user `solo` uid 10001 ; l'entrypoint démarre root (chown/cert) puis
  `exec gosu` → le **process Node ne tourne jamais en root**.
- Entrypoint : **TLS_CN assaini** (charset hostname, sinon fallback) ; clé écrite
  sous `umask 0077` ; **fail-closed** si la clé n'est pas 600/400 ; chown idempotent.
- Compose : `init:true`, `restart:unless-stopped`, logs cappés (10m×3), **healthcheck
  TLS vérifié** (CA = cert généré, servername forcé → MITM local échoue).
- index.ts : `bodyLimit 512k`, error handler sans fuite, shutdown gracieux SIGTERM/INT.

---

## 2. Déroulé de l'audit (phases)

Outillage : relecture + `docker` (scan d'image, inspection runtime). Conteneur
jetable pour scanner :
```bash
# Construire et scanner l'image (trivy via image officielle, pas d'install locale)
docker build -t solo:audit .
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy:latest image --severity HIGH,CRITICAL solo:audit
docker inspect solo:audit   # user, env, exposed ports, layers
```

### Phase 1 — Image (Dockerfile)
- [ ] **Base non pinnée par digest** : `node:20-bookworm-slim` est un tag **mutable**
      → un rebuild peut tirer une base différente (cf. aussi audit-deps). Reco :
      pinner par `@sha256:…` (ou au moins documenter le risque de dérive).
- [ ] **Pas de lockfile committé** : le Dockerfile fait `npm ci` *si* `package-lock.json`
      existe, sinon `npm install` (non reproductible). Reco : committer le lock →
      `npm ci` déterministe (recoupe audit-deps).
- [ ] **Scripts d'install** : `better-sqlite3` compile/télécharge un prebuild à
      l'install dans le builder. Vérifier la provenance ; `npm ci` ne désactive pas
      les scripts → un paquet compromis exécute du code au build (audit-deps phase 3).
- [ ] **Surface runtime** : l'image runtime garde `openssl`, `gosu`, `ca-certificates`
      — nécessaires (cert + drop priv). Confirmer qu'aucun outil de build ne fuit dans
      l'étage runtime. Pas de shell superflu ? (slim en garde un — acceptable).
- [ ] **.dockerignore** : vérifier qu'il exclut `.git`, `data/`, `certs/`, `node_modules`,
      `.env` → ne pas embarquer de secret/donnée dans une layer.
- [ ] **HEALTHCHECK** : défini côté compose (pas Dockerfile) — OK ; confirmer qu'il
      ne nécessite pas curl (il utilise node — bien).

### Phase 2 — Entrypoint (privilèges, cert, perms)
- [ ] Confirmer le **drop de privilèges** effectif : `gosu "$APP_UID:$APP_GID"` et
      que rien après le drop ne re-nécessite root. Le process Node hérite-t-il de
      capabilities root résiduelles ? (non avec gosu+user, mais à confirmer avec
      `cap_drop` phase 3).
- [ ] **Génération cert** : RSA 2048, 825 jours, `-nodes` (clé non chiffrée — normal
      pour démarrage auto), SAN corrects. La clé 0600 owner-only est **vérifiée**
      (fail-closed) — bien. Noter : la clé non chiffrée sur le volume `./certs` est
      lisible par root de l'hôte (inhérent aux bind-mounts).
- [ ] **TLS_CN injection** : le filtre `*[!a-zA-Z0-9.-]*` bloque l'injection d'options
      openssl → confirmer qu'aucun autre champ interpolé (SAN) n'échappe au filtre.
- [ ] **chown récursif** sur `/data` à chaque boot : coût si gros volume + un fichier
      hostile dans le bind-mount serait chowné — acceptable, le noter.

### Phase 3 — Orchestration (compose) — les vrais manques
Le `docker-compose.yml` **n'applique aucun durcissement de privilèges/surface**.
Recommander (defense-in-depth si le process Node est compromis) :
- [ ] `security_opt: ["no-new-privileges:true"]` — empêche l'escalade via setuid.
- [ ] `cap_drop: ["ALL"]` (le process non-root n'a besoin d'aucune capability ;
      l'entrypoint root a besoin de CHOWN/SETUID/SETGID **avant** le drop → tester :
      si `cap_drop: ALL` casse le chown root de l'entrypoint, ajouter seulement
      `cap_add: [CHOWN, SETUID, SETGID, DAC_OVERRIDE]` au strict besoin).
- [ ] `read_only: true` (rootfs en lecture seule) + `tmpfs: [/tmp]` ; les seuls
      chemins en écriture doivent être les volumes `/data` et `/certs`.
- [ ] **Limites de ressources** : `mem_limit` / `pids_limit` / `cpus` → borne le
      blast radius d'un DoS (cohérent avec audit-parsers : un OOM parser est contenu).
- [ ] `ulimits: nofile` raisonnable (FD) pour borner les sockets (slowloris).
- [ ] **Exposition réseau** : `ports: "8443:8443"` bind sur **0.0.0.0** (toutes les
      interfaces de l'hôte). Si solo n'est pas censé être public, recommander
      `127.0.0.1:8443:8443` ou un réseau dédié. (Mais le ClientHello brut impose une
      exposition directe — documenter le choix.)
- [ ] Confirmer l'absence de `privileged:true`, de montage du socket Docker, de
      `network_mode: host`.

### Phase 4 — Secrets & config
- [ ] `.env` chargé via `env_file required:false` ; secrets (`SESSION_SECRET`,
      `ADMIN_TOKEN`) hors image. Confirmer qu'aucun secret n'est en dur dans le
      Dockerfile/compose ni loggué au boot (le log de démarrage liste version/ports/
      chemins — **pas** de secret : confirmer).
- [ ] `SESSION_SECRET` vide → aléatoire au boot (invalidé au restart) ; `ADMIN_TOKEN`
      vide → endpoints privilégiés futurs verrouillés. Vérifier qu'aucun défaut
      faible/prévisible n'est utilisé si la var manque (pas de secret « changeme »).
- [ ] **Intégrité MaxMind** : `GEOIP_DB_SHA256` / `GEOIP_COUNTRY_DB_SHA256` supportés
      (index.ts) mais **non renseignés** par défaut → recommander de les fixer pour
      fail-closed sur une base altérée (le parser .mmdb traite un fichier binaire —
      recoupe audit-parsers phase 4).
- [ ] Préférence maison : si un secret devient réellement critique, **sauvegarde
      Dashlane** obligatoire à chaque touch du `.env` (comme VAULT_MASTER_KEY ailleurs).

### Phase 5 — Image vulnérabilités & taille
- [ ] `trivy image` sur `solo:audit` : CVE HIGH/CRITICAL de la base Debian slim +
      node_modules (recoupe audit-deps mais ici au niveau OS/layer).
- [ ] Vérifier qu'on ne tourne pas une version Node EOL et que `NODE_ENV=production`
      est bien posé (l'est, Dockerfile + compose).

### Phase 6 — Synthèse
- [ ] Prioriser : **P1** manque de `no-new-privileges`/`cap_drop`/`read_only`/limites
      (durcissement standard absent) ; base/lock non pinnés. **P2** exposition
      0.0.0.0 si non voulue ; MaxMind sans pinning d'intégrité. **P3** doc HSTS/clé
      non chiffrée/chown récursif.
- [ ] Pour chaque reco compose : fournir le **bloc YAML exact** à ajouter, et
      **tester que le conteneur démarre toujours** après durcissement (le chown root
      de l'entrypoint survit-il à `cap_drop: ALL` ? sinon ajuster `cap_add`).
- [ ] Rappels maison : semver, MAJ README (toute commande/instruction de déploiement
      qui change), **liste des fichiers modifiés** en fin de session, et **GO explicite
      avant** d'appliquer des changements compose/Dockerfile en prod (ne pas présumer).

---

## 3. Format du rapport
```
# Audit durcissement conteneur/runtime — solo (vX.Y.Z) — <date>
## Verdict : posture runtime ? OK/À durcir — top manques
## 1. Image (base/lock pinnés, surface, .dockerignore, scripts d'install)
## 2. Entrypoint (drop priv effectif, cert/clé, TLS_CN)
## 3. Orchestration : no-new-privileges/cap_drop/read_only/limites/exposition — blocs YAML
## 4. Secrets & intégrité MaxMind
## 5. Vulnérabilités image (trivy)
## 6. Remédiation priorisée + validation « démarre toujours »
```

## 4. Checklist de complétude
- [ ] Confirmé : process Node non-root, drop gosu effectif, clé 0600 fail-closed.
- [ ] Blocs compose de durcissement proposés ET testés (le conteneur démarre encore).
- [ ] `cap_drop: ALL` vs besoin root de l'entrypoint : tranché (cap_add minimal).
- [ ] Aucun secret en dur ni loggué ; intégrité MaxMind recommandée.
- [ ] trivy exécuté (CVE OS/layer).
- [ ] Tout non-couvert listé (aucun cap muet) ; recos avec YAML exact + repro.
