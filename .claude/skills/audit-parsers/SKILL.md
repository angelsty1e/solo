---
name: audit-parsers
description: >-
  Audit de robustesse + fuzzing des parsers d'entrée RÉSEAU BRUTE de solo, écrits
  à la main : le parser ClientHello TLS (src/server/tls/clienthello.ts), le proxy
  d'interception TLS (interceptor.ts), JA3/JA4 (ja3.ts/ja4.ts), le parser d'en-têtes
  HTTP (src/server/http/headers.ts) et le parsing des bases MaxMind .mmdb. Ces
  parsers désérialisent des octets ENTIÈREMENT contrôlés par l'attaquant, AVANT
  toute authentification — quiconque atteint :8443 pilote ces bytes. Objectif :
  prouver qu'aucun ClientHello / en-tête / paquet malformé ne peut faire planter le
  process, partir en boucle infinie, lire hors-bornes, exploser la mémoire, ou
  bloquer le serveur (DoS pré-auth). Construit un corpus de payloads malformés +
  un harnais de fuzzing par mutation, vérifie les invariants de terminaison/bornage,
  audite le buffering du proxy (cap, timeout) et durcit les boucles à offset manuel.
  TRIGGER : "fuzzer les parsers", "robustesse du ClientHello / parser TLS", "DoS
  pré-auth", "le serveur peut-il crasher sur une entrée malformée", "tester le
  parsing d'octets bruts", "hardening du parser HTTP/mmdb".
---

# audit-parsers — durcir les parsers d'entrée brute (DoS pré-auth)

## 1. Pourquoi c'est la surface la plus critique

solo expose `:8443` et **conserve le ClientHello brut** (c'est sa raison d'être :
JA3/JA4). L'interception se fait avant TLS, donc le code lit des **octets
arbitraires d'un attaquant non authentifié**. Un parser maison qui se trompe d'une
borne, c'est :

- **Crash du process** — un `throw` non rattrapé dans le handler de socket, ou pire
  une exception qui remonte jusqu'à `uncaughtException` → `process.exit` → **DoS
  total** d'un coup de paquet.
- **Boucle infinie / CPU 100 %** — une boucle à offset manuel qui n'avance pas →
  un seul paquet gèle un worker.
- **Mémoire** — un proxy qui bufferise sans cap en attendant « la suite » d'un
  record dont la longueur annoncée est énorme → OOM.
- **Lecture hors-bornes / fuite** — lire au-delà du buffer et renvoyer/stocker des
  octets voisins.

Le verdict du moteur de décision peut être irréprochable : **inutile si on crashe
le serveur avant qu'il ne s'exécute.** Cet audit garantit la couche d'entrée.

### Cibles (par ordre de criticité)
| Fichier | Entrée | Risque principal |
|---|---|---|
| `src/server/tls/interceptor.ts` (326 l) | flux TCP brut, buffering | **buffering non borné / pas de timeout** → OOM/slowloris ; crash du handler |
| `src/server/tls/clienthello.ts` (259 l) | `Buffer` ClientHello | boucles d'extensions à offset manuel ; `throw` non rattrapé ; hors-bornes |
| `src/server/http/headers.ts` (97 l) | `req.rawHeaders` | en-têtes dupliqués/géants, ordre, tableaux |
| `src/server/tls/ja3.ts` / `ja4.ts` | sortie du parser | overflow d'agrégation, hash sur entrée vide |
| parsing `.mmdb` (via `maxmind`) | fichier opérateur | fichier corrompu/malveillant (couvert aussi par audit-deps) |

---

## 2. Invariants de robustesse à prouver

Pour CHAQUE parser, sur **toute** entrée (y compris la pire) :

- **T1 — Terminaison** : le parsing se termine toujours en temps borné. Aucune
  boucle ne peut tourner sans progresser. *(cible : les `while (off …)` à offset
  manuel de clienthello.ts — SNI, ALPN, supported_versions, curves, sig_algs.)*
- **T2 — Pas de throw non maîtrisé hors du parser** : un input malformé produit
  soit un résultat partiel valide, soit une `Error` **rattrapée par l'appelant**
  (l'interceptor / le handler), jamais une exception qui tue le process.
- **T3 — Bornage mémoire** : aucune entrée ne fait allouer plus de O(taille reçue).
  Le proxy ne bufferise pas au-delà d'un cap dur, et abandonne après un timeout.
- **T4 — Pas de hors-bornes** : toute lecture est gardée (le `Reader` jette sur
  EOF — vérifier que TOUTES les lectures passent par lui, pas de `readUInt*` direct
  sur `data` sans garde dans les `case` d'extensions).
- **T5 — Idempotence/déterminisme** : même octets → même sortie (pas d'état global
  partagé entre connexions dans le parser).
- **T6 — Pas d'amplification CPU** : le coût de parsing est linéaire en la taille du
  paquet (pas de quadratique sur des listes répétées géantes).

---

## 3. Outillage

Parsers = TS pur côté serveur. Pas de Node/npm local ⇒ conteneur jetable :
```bash
NODEC='docker run --rm -v "$PWD":/app -w /app node:20'
eval "$NODEC sh -c 'npm install --ignore-scripts && npx vitest run'"
```
Créer `tests/parsers-fuzz.test.ts`. Deux approches combinées :
1. **Corpus dirigé** — payloads malformés écrits à la main (cas limites connus).
2. **Fuzzing par mutation** — partir d'un ClientHello Chrome **valide** (le capturer
   une fois, le figer en hex dans le test), puis muter : flip d'octets, troncatures
   à chaque offset, longueurs gonflées/à zéro, extensions répétées en masse.
   Propriété asserte : `parseClientHello(mutant)` **retourne OU jette une Error**,
   et ne dépasse jamais un budget temps (mesurer ; un test qui « hang » = bug T1).

> Pour le timing/CPU, exécuter le parser dans une boucle bornée et asserter une
> durée plafond par itération ; un dépassement révèle une boucle non-progressive
> ou une amplification. (Pas de `Date.now()` dans le code testé — mesurer côté test.)

---

## 4. Déroulé de l'audit (phases)

### Phase 0 — Lecture ligne à ligne des bornes
- [ ] `clienthello.ts` : vérifier que **chaque** `case` d'extension lit via des
      gardes (`data.length >= …`, `off + n <= …`). Les `case` SNI/ALPN/0x002b/
      0x000a/0x000b/0x000d utilisent `data.readUInt*` **directement** (pas le
      `Reader`) → confirmer qu'aucune lecture n'échappe à une borne et qu'aucune
      boucle ne peut stagner (ex. un `off += protoLen` avec `protoLen=0` doit quand
      même progresser via le `off += 1` qui précède — le tracer pour chaque boucle).
- [ ] `interceptor.ts` (à lire en entier) : **où sont bufferisés les octets** en
      attendant un ClientHello complet ? Y a-t-il (a) un **cap dur** sur la taille
      accumulée, (b) un **timeout** si le client n'envoie jamais la suite
      (slowloris), (c) une **limite du nombre de connexions** ? Le `throw` du parser
      est-il **rattrapé** (try/catch) autour de l'appel, ou peut-il remonter et tuer
      le serveur ? La map socket→fingerprint a-t-elle une **fuite** (entrées jamais
      supprimées à la fermeture de socket) ?
- [ ] `headers.ts` : `rawHeaders` peut contenir des doublons et des valeurs énormes ;
      la boucle est bornée par la longueur du tableau (OK), mais vérifier le coût sur
      un client envoyant des milliers d'en-têtes (cap côté Node/Fastify ? `bodyLimit`
      ne couvre pas les headers — Node a `maxHeaderSize` par défaut 16ko : le confirmer
      et le rendre explicite).

### Phase 1 — Corpus dirigé (cas limites connus)
Construire et tester ces ClientHello malformés (assertion T1–T4) :
- [ ] Record tronqué à chaque frontière (après recordType, après length, au milieu
      du random, du sessionId, des ciphers).
- [ ] `recordLength`/`handshake length` **mensongers** (annoncent 64 ko, paquet de
      10 octets) — le parser doit jeter proprement, le proxy ne doit pas bufferiser
      64 ko en attente.
- [ ] `sessionIdLen`/`cipherLen`/`compLen` = 255/65535 avec buffer court → `slice`
      doit jeter `eof slice`, pas lire au-delà.
- [ ] `cipherLen` impair (déjà gardé : `odd cipher length`) — confirmer.
- [ ] `extTotalLen` > remaining, et extensions avec `len` > data restante.
- [ ] SNI : `listLen` incohérent, `nameLen=0`, `nameType≠0` en boucle, nom de 256+
      octets (cap présent : `nameLen <= 256` + charset — confirmer qu'un nom hors
      charset est **ignoré** sans casser le reste).
- [ ] ALPN : `protoLen=0` répété, protoLen dépassant `end`.
- [ ] Extensions **dupliquées en masse** (10 000 × la même) → coût linéaire (T6),
      pas de croissance mémoire non bornée des tableaux de sortie.
- [ ] GREASE partout (vérifier `isGrease` ne fausse pas la terminaison).
- [ ] Octets non-handshake (recordType≠0x16, hsType≠0x01) → throw immédiat propre.

### Phase 2 — Fuzzing par mutation
- [ ] Figer un ClientHello réel valide (hex) ; générer N mutants par byte-flip /
      troncature / insertion. Pour chacun : `expect(() => parseClientHello(m)).not.toThrow(/RangeError|out of range/)`
      — on tolère les `Error('eof …')` maison, on **rejette** les `RangeError`
      natifs (= lecture hors-bornes non gardée) et les hangs (budget temps).
- [ ] Faire passer chaque sortie de parser dans `ja3`/`ja4` pour vérifier qu'elles
      ne plantent pas sur des listes vides / valeurs extrêmes.
- [ ] Brancher le mutant sur le **chemin réel** de l'interceptor (parse appelé
      depuis le handler) pour valider T2/T3 de bout en bout, pas juste la fonction
      pure.

### Phase 3 — DoS du proxy (buffering / slowloris / connexions)
- [ ] **Slowloris TLS** : ouvrir une connexion, envoyer 1 octet puis rien.
      L'interceptor libère-t-il la socket après timeout, ou garde-t-il le buffer et
      la map indéfiniment ? (sinon : épuisement mémoire/FD par accumulation de
      connexions semi-ouvertes.)
- [ ] **Record géant annoncé** : envoyer un header annonçant un énorme ClientHello
      en dribblant les octets → mesurer la mémoire accumulée. Doit être capée.
- [ ] **Flood de connexions** : la map socket→state grandit-elle sans nettoyage à
      `close`/`error` ? (fuite mémoire = DoS lent.)
- [ ] Confirmer que `maxHeaderSize` Node et `bodyLimit` Fastify (512 ko, index.ts)
      bornent bien les chemins HTTP, et qu'il existe un équivalent pour la phase TLS.

### Phase 4 — Parsing .mmdb (entrée fichier semi-fiable)
- [ ] `maxmind` parse un fichier binaire ; en cas de `.mmdb` corrompu/tronqué, le
      démarrage doit **échouer proprement** (pas de crash opaque) ou dégrader vers
      ASN/pays `null` (comportement documenté README). Tester un `.mmdb` tronqué.
- [ ] Recommander d'**activer le pinning d'intégrité** (`GEOIP_DB_SHA256` /
      `GEOIP_COUNTRY_DB_SHA256`, déjà supporté dans index.ts) pour fail-closed sur un
      fichier altéré — défense en profondeur contre un parser tiers nourri d'un
      fichier malveillant.

### Phase 5 — Synthèse & remédiation
- [ ] Prioriser :
  - **P0** : crash du process / hors-bornes natif / OOM atteignable par un seul
    paquet non authentifié ; boucle infinie.
  - **P1** : slowloris/fuite mémoire par connexion ; throw non rattrapé dégradant
    le service ; buffering non capé.
  - **P2** : amplification CPU sous-quadratique mais coûteuse ; nom/valeur non
    bornés stockés.
  - **P3** : durcissement défensif (gardes redondantes, messages d'erreur).
- [ ] Pour chaque finding : payload de repro (hex), correctif (garde/cap/timeout/
      try-catch), test de régression dans `tests/parsers-fuzz.test.ts`.
- [ ] Rappels maison : bump semver, MAJ README si comportement change, **liste des
      fichiers modifiés** en fin de session, **GO explicite avant** de toucher au
      proxy en prod (chemin critique).

---

## 5. Format du rapport
```
# Audit parsers d'entrée brute — solo (vX.Y.Z) — <date>
## Verdict : couche d'entrée robuste ? OUI/NON — pire cas atteignable
## 1. Bornes & terminaison (T1–T6) par parser : tenu/violé + preuve
## 2. Corpus dirigé : payload | parser | comportement | attendu | sévérité
## 3. Fuzzing mutation : N mutants, crashes/hangs trouvés
## 4. DoS proxy : slowloris / buffering / fuite map — résultats
## 5. .mmdb : comportement sur fichier corrompu + reco pinning
## 6. Remédiation priorisée (P0→P3) + tests ajoutés
```

## 6. Checklist de complétude
- [ ] interceptor.ts lu en entier ; buffering capé + timeout + nettoyage map vérifiés.
- [ ] Chaque boucle à offset manuel de clienthello.ts prouvée progressive (T1).
- [ ] Aucune lecture hors `Reader`/garde ne subsiste (T4).
- [ ] Fuzzing exécuté ; 0 RangeError natif, 0 hang, sinon findings.
- [ ] Slowloris + flood connexions testés.
- [ ] Tout non-couvert listé explicitement (aucun cap muet).
- [ ] Findings P0/P1 avec repro + test de régression.
