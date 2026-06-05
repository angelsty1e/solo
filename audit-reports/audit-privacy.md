# Audit confidentialité / RGPD — solo (v1.3.0) — 2026-06-05

> Audit statique (lecture de code uniquement, aucun build/exécution local — projet déployé sur LXC).
> Périmètre : `src/server/store.ts`, `src/server/db.ts`, `src/server/routes.ts` (`/collect`, `/export`, `/api/fp`),
> `src/server/index.ts` (logs), `src/server/tls/interceptor.ts`, `src/client/behavioral/*`, `src/shared/validation.ts`, `README.md`.

## Verdict : conforme aux principes ? OUI, avec réserves

Les deux points durs du RGPD pour ce traitement sont **traités correctement** :

1. **Effacement réel au TTL** — les 5 tables enfant ont `ON DELETE CASCADE` ET `PRAGMA foreign_keys = ON` est activé. Le sweeper purge donc bien les blobs JSON, pas seulement la ligne `sessions`. **Pas d'orphelins.**
2. **Texte tapé jamais enregistré** — prouvé dans le code : seul `e.code` (position physique de touche) est capté, jamais `e.key`. Seuls des agrégats numériques (rythme) transitent et sont stockés. Promesse README tenue.

Les manquements restants sont de niveau **P2/P3** : minimisation (IP en clair, blob redondant, WebRTC `localIps`), un log qui contient l'IP réelle, et l'absence de bandeau de transparence + de mini-DPIA formalisée. Aucun P0/P1.

---

## 1. Cartographie DCP × table × finalité × utilisé

| Donnée | Emplacement | Finalité | Utilisé ? |
|---|---|---|---|
| IP complète (en clair) | `sessions.ip` + blob `server_ip` | réputation (COUNT DISTINCT ip), géoloc, verdict | Oui |
| ASN / org / pays / rDNS / datacenter / proxy / Tor | colonnes `sessions.*` + blob `server_ip` | verdict réseau (N2) | Oui |
| JA3/JA4/TLS/SNI/ALPN | colonnes + blob `server_tls` | cohérence TLS↔UA | Oui |
| User-Agent, Accept-Language, Sec-Fetch | colonnes + blob `server_http` | cohérence en-têtes | Oui |
| Empreintes canvas/WebGL/audio (hash) | colonnes `*_hash` | réputation cross-session, verdict | Oui |
| **Blob client complet** (payload intégral) | `client_full.data` | récap `/api/fp/:id` + export | Oui (récap/export) mais **duplique** les colonnes |
| WebRTC `localIps` / `candidates` | dans blob `client_full` | détection incohérence réseau | **Partiel** (voir P2-3) |
| Agrégats comportementaux (rythme souris/clavier/scroll/touch) | blob `client_full` | verdict comportemental | Oui |
| Verdict + scores | `decisions.data` + colonnes `sessions` | profilage anti-bot (finalité) | Oui |

**Double stockage** : la quasi-totalité des colonnes plates de `sessions` est aussi présente dans les blobs JSON (`server_*`, `client_full`). C'est un choix assumé (colonnes indexables vs snapshot brut) mais c'est de la DCP dupliquée → à justifier au titre de la minimisation (cf. P2-1).

---

## 2. Effacement réel au TTL — CONFORME (point critique tranché)

- `TTL_MS = 1h` (`store.ts:6`). `startSweeper()` (`store.ts:271`) exécute toutes les 5 min : `DELETE FROM sessions WHERE expires_at < now`.
- **Le DELETE purge-t-il les tables enfant ?** OUI :
  - Schéma `db.ts:75-101` : `server_tls`, `server_http`, `server_ip`, `client_full`, `decisions` déclarent toutes `REFERENCES sessions(id) ON DELETE CASCADE`.
  - `db.ts:152` : `db.pragma('foreign_keys = ON')` — la cascade est donc **active** (sans ce pragma, SQLite ignore silencieusement les FK). 
  - => La suppression d'une ligne `sessions` supprime atomiquement les 5 blobs JSON associés. **Pas d'orphelins.**
- **Lecture filtrée sur l'expiration** : `selectFull` (`store.ts:24` `expires_at > ?`), `list` (`store.ts:263`), `fingerprintReputation` (`store.ts:248` `created_at >= since`). Une session expirée mais pas encore sweepée n'est **jamais** servie ni comptée dans la réputation. Conforme.
- **Réserve (P3) — réutilisation des pages / secure_delete** : après DELETE, les octets restent dans les pages SQLite jusqu'à réécriture (et le WAL conserve des copies jusqu'au checkpoint ; `closeDb` checkpoint TRUNCATE seulement à l'arrêt). Acceptable pour un lab, mais à noter. `PRAGMA secure_delete = ON` (et éventuellement un `VACUUM` périodique) effacerait physiquement le contenu des pages libérées.
- **Réserve (P3) — pas de purge au boot** : si le process reste arrêté >5 min puis redémarre, le premier sweep n'a lieu qu'après le premier intervalle de 5 min ; entre-temps des sessions expirées existent sur disque (invisibles en lecture, car filtrées). Mineur. Un sweep immédiat au démarrage le couvrirait.

**Test de non-régression à ajouter** (insérer → forcer expiration → sweep → asserter les 5 tables enfant vides) :
```ts
// tests/privacy-retention.test.ts (esquisse)
// 1. upsertServer + upsertClient + upsertDecision sur un sessionId
// 2. db.prepare('UPDATE sessions SET expires_at = 0 WHERE id = ?').run(id)
// 3. db.prepare('DELETE FROM sessions WHERE expires_at < ?').run(Date.now())
// 4. pour t of ['server_tls','server_http','server_ip','client_full','decisions']:
//      expect(db.prepare(`SELECT COUNT(*) c FROM ${t} WHERE session_id = ?`).get(id).c).toBe(0)
// 5. test de garde : PRAGMA foreign_keys doit valoir 1
```

---

## 3. Minimisation

### P2-1 — Blob `client_full` redondant avec les colonnes
`upsertClient` (`store.ts:160-191`) écrit à la fois les colonnes plates extraites ET le payload client intégral (`JSON.stringify(client)`). Le blob sert le récap et l'export. Recommandation : conserver le blob (nécessaire à `/api/fp` et `/export`) mais documenter explicitement que la duplication colonnes↔blob est un choix d'indexation, ou élaguer du blob les champs jamais affichés/exportés.

### P2-2 — IP stockée en clair vs hash
`sessions.ip` et le blob `server_ip` contiennent l'IP **complète en clair**. Or la réputation ne fait que `COUNT(DISTINCT ip)` (`store.ts:246`) : un **hash salé** de l'IP suffirait pour cette fonction de comptage, tout en réduisant la sensibilité de la donnée. La géoloc (ASN/pays/rDNS) est dérivée côté serveur **avant** stockage et pourrait n'enregistrer que le résultat dérivé, pas l'IP source. Proposition : hasher l'IP pour la colonne de réputation et n'exposer l'IP en clair que dans le blob d'export si nécessaire (ou pas du tout).

### P2-3 — WebRTC `localIps` (adresses IP locales / privées)
`validation.ts:125` accepte `localIps: z.array(z.string())` et `candidates`, stockés dans `client_full`. Ce sont des **adresses réseau internes** du poste de l'utilisateur (DCP, et historiquement un vecteur de fuite WebRTC). À confirmer côté moteur : si ces champs ne contribuent pas réellement au verdict, c'est de la collecte « au cas où » → candidat à la suppression (violation de minimisation). S'ils servent, les conserver mais les mentionner dans la note de transparence.

### P3 — Strings non bornées
Les champs `z.string()` de `validation.ts` (UA, candidates, renderer, etc.) n'ont pas de `.max()`. La seule borne est le `bodyLimit: 512 KB` (`index.ts:66`). Suffisant contre le DoS/bloat global, mais des `.max()` par champ durciraient et éviteraient de stocker des chaînes anormalement longues.

---

## 4. Contenu sensible — CONFORME (prouvé)

- **Texte tapé jamais capté** : `keyboard.ts:1-39` n'enregistre que `{ t, type, code }` où `code = e.code` (position physique : "KeyA", "Backspace"), avec le commentaire explicite « we never record `e.key`, so the actual characters typed are never captured or sent ». Aucune lecture de `e.key`/`e.data`/valeur de champ.
- **Seuls des agrégats sortent** : `aggregate.ts:62-97` ne produit que des compteurs/moyennes/écarts-types de dwell/flight + `backspaceRatio`. `aggregateBehavioral` ne renvoie que les 4 agrégats (mouse/keyboard/scroll/touch), jamais la liste d'événements brute.
- **Schéma verrouillé** : `behavioralSchema` (`validation.ts:275-312`) ne contient **que des champs numériques** ; aucun tableau de codes/caractères. L'enveloppe `ClientFingerprintSchema` est `.strict()` (`validation.ts:344`) → tout champ inconnu (ex. un tableau de touches injecté par un client modifié) est **rejeté en 400**, jamais persisté.
- Pas de capture de presse-papier, de saisie de formulaire ni d'URL visitées dans `src/client/behavioral/*` ni dans les collecteurs.

**Conclusion** : la promesse publique « le texte tapé n'est jamais enregistré — seulement le rythme » (README:9, README:139) est **vérifiée dans le code**, pas seulement supposée.

---

## 5. Logs — une fuite mineure d'IP

- Logger Fastify (`index.ts:67-75`) : `redact` retire `cookie` + `authorization` (`remove: true`). `req.ip` vaut toujours 127.0.0.1 (proxy interne, `trustProxy: false`) → la vraie IP **n'apparaît pas** dans le log de requête par défaut. Bon.
- `/collect` ne logge en cas de rejet que **le nombre** d'issues (`routes.ts:187` `{ issues: parsed.error.issues.length }`), **jamais le payload**. Bon.
- Le log final de démarrage (`index.ts:159-171`) sort `db`/`cert` (chemins disque) — pas de DCP, OK pour un log de boot.

### P2-4 — L'IP réelle est loggée par l'interceptor
`interceptor.ts:149` : `logger?.warn?.('per-ip connection cap reached, dropping', realAddr)` écrit l'**IP réelle en clair** dans les logs (via `console.warn`, `index.ts:79`) quand le cap de connexions par IP est atteint. C'est précisément ce que le commentaire `index.ts:70` (« avoid persisting client IPs in the request logs ») cherche à éviter, contourné ici. À fortiori sous un comportement abusif (le cas où ce log se déclenche), une IP atterrit dans les logs json-file (rotation 10m×3 → conservation transitoire). Recommandation : logger un hash/tronqué d'IP, ou un compteur agrégé, plutôt que `realAddr` en clair. Vérifier aussi `interceptor.ts:122/264/283` (n'exposent pas d'IP, OK — bytes hex du ClientHello, pas de DCP).

---

## 6. Export / droits / base légale / transparence / DPIA

- **Export** (`routes.ts:222-236`) : `/export/:id` renvoie le JSON complet de la session (toutes les DCP). Protégé par capability UUIDv4 (122 bits, `routes.ts:92`, validé par regex `routes.ts:223`). C'est le détenteur de l'URL de récap — l'utilisateur lui-même — qui exporte ses propres données → sert le **droit d'accès / portabilité**. Pas de partage tiers, pas d'analytics externe, pas de cookie de tracking (CSP `connectSrc: 'self'`, `index.ts:94` ; aucun appel sortant). Conforme.
- **Droit à l'effacement** : pas de route de suppression explicite, mais mitigé par le **TTL 1h** (effacement automatique rapide et complet, cf. §2). À documenter comme choix de conception.
- **Base légale / finalité** : finalité unique et documentée (démonstration de fingerprinting / anti-bot, pédagogie — README). Pas de réutilisation détournée. Pour un lab non commercial, l'intérêt légitime pédagogique est défendable, **à condition** d'informer l'utilisateur.

### P3-1 — Information / transparence (manquant en tant que feature)
Le README documente la rétention 1h et le « jamais le texte tapé », mais **rien n'est affiché à l'utilisateur qui scanne**. Recommandation : ajouter un court bandeau sur la page de scan : « Ce lab collecte votre empreinte navigateur (canvas/WebGL/audio), votre IP et sa géoloc, et le *rythme* de vos interactions — jamais le texte tapé. Données conservées 1h puis effacées, aucun partage. » C'est une feature livrable → MAJ README en conséquence (rappel maison).

### P3-2 — Mini-DPIA à formaliser
Traitement de **suivi/identification systématique** → cas où une analyse d'impact est recommandée, même en lab. Mini-DPIA proposée :

| Axe | Contenu |
|---|---|
| Finalité | Démonstration pédagogique du fingerprinting + scoring anti-bot. Unique. |
| Données | IP + géoloc/ASN/rDNS, empreintes canvas/WebGL/audio, UA/écran/locale, agrégats comportementaux (rythme), verdict. |
| Personnes | Visiteurs volontaires du lab. |
| Durée | 1h (TTL), effacement automatique en cascade. |
| Destinataires | Aucun tiers ; export = self-service par capability URL. |
| Risques | Ré-identification via empreinte stable ; fuite IP locale (WebRTC) ; IP en clair en base et dans un log. |
| Mitigations | TTL court + cascade prouvée ; pas de texte tapé ; capability URL non énumérable ; (à faire) hash IP, suppression `localIps` si inutile, bandeau transparence, IP non loggée en clair. |

### P3-3 — Géoloc = inférence
La géoloc/ASN par IP est une **inférence faillible** (VPN, Tor, voyageurs). Le récap ne doit pas la présenter comme un fait sur la personne. À noter dans la note de transparence.

---

## 7. Remédiation priorisée + tests

| ID | Sév. | Finding | Correctif | Fichier |
|---|---|---|---|---|
| P2-1 | P2 | Blob `client_full` duplique les colonnes | Documenter le choix, ou élaguer les champs non exportés | `store.ts:187` |
| P2-2 | P2 | IP en clair pour la réputation | Hasher l'IP (salé) pour la colonne de comptage | `store.ts:115,246`, `db.ts:20` |
| P2-3 | P2 | WebRTC `localIps`/`candidates` (IP locales) | Confirmer l'usage moteur ; supprimer si non utilisé | `validation.ts:123-130` |
| P2-4 | P2 | IP réelle loggée en clair (cap connexions) | Logger hash/tronqué ou compteur, pas `realAddr` | `interceptor.ts:149` |
| P3 | P3 | Strings non bornées | Ajouter `.max()` par champ | `validation.ts` |
| P3 | P3 | Pages libérées non écrasées | `PRAGMA secure_delete = ON` (+ VACUUM périodique) | `db.ts:150-154` |
| P3 | P3 | Pas de sweep au boot | Lancer un sweep immédiat au démarrage | `index.ts:133` |
| P3-1 | P3 | Pas de bandeau transparence | Ajouter une note in-page + MAJ README | front + `README.md` |
| P3-2 | P3 | DPIA non formalisée | Intégrer la mini-DPIA ci-dessus à la doc | doc |

**Tests à ajouter** (`tests/`) :
1. **Rétention/cascade** : insérer une session complète → `UPDATE expires_at = 0` → exécuter le DELETE du sweeper → asserter `COUNT(*) = 0` sur les 5 tables enfant ; plus une garde `PRAGMA foreign_keys` == 1.
2. **Pas de texte tapé** : asserter que `behavioralSchema.safeParse` rejette tout payload contenant un champ de contenu (ex. `keys: ['a','b']`), et que `aggregateBehavioral` ne renvoie aucune chaîne.
3. **Strict envelope** : `ClientFingerprintSchema.safeParse` d'un payload avec clé inconnue → `success === false`.

**Rappels maison** : aucun changement de schéma appliqué (audit statique) ; tout correctif touchant le schéma DB → GO + `.schema` sur la base réelle LXC d'abord ; la note de transparence = feature livrée → MAJ README ; bump semver à la livraison des correctifs.
