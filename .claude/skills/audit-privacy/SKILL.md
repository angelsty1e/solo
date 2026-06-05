---
name: audit-privacy
description: >-
  Audit confidentialité / RGPD du traitement de données personnelles par solo —
  un lab de fingerprinting qui collecte et stocke des données à caractère personnel
  (adresse IP, ASN/géoloc, empreintes canvas/WebGL/audio, agrégats comportementaux)
  via /collect et la base SQLite (src/server/store.ts, db.ts). Vérifie : la
  minimisation (ne stocker que le nécessaire), l'effacement RÉEL à l'expiration
  (la rétention TTL ~1h purge-t-elle aussi les tables enfant et les blobs JSON, ou
  laisse-t-elle des orphelins ?), ce qui finit dans les logs, l'absence de contenu
  sensible (le texte tapé ne doit jamais être enregistré — seulement le rythme),
  le périmètre d'export, la base légale / l'information de l'utilisateur, et le
  besoin d'une analyse d'impact (DPIA) pour un traitement de suivi par nature à
  risque. Objectif : aucune donnée perso conservée au-delà du TTL, aucune donnée de
  trop, traçabilité de la finalité.
  TRIGGER : "audit RGPD / confidentialité", "données personnelles de solo",
  "rétention / purge des sessions", "le texte tapé est-il enregistré", "minimisation
  des données", "faut-il une DPIA", "que met-on dans les logs".
---

# audit-privacy — confidentialité & RGPD du fingerprint lab

## 1. Cadre

solo est un **laboratoire de fingerprinting** : par nature il traite des **données
à caractère personnel** au sens RGPD. Même en lab/démo, c'est un traitement de
**suivi/identification** — la catégorie que le RGPD considère comme à risque élevé.
L'audit vérifie les principes : **minimisation, limitation de la conservation,
sécurité, finalité, information**, et le besoin d'une **DPIA**.

### Données personnelles manipulées (à cartographier précisément)
| Donnée | Où | Sensibilité |
|---|---|---|
| Adresse IP | `sessions.ip`, blob `server_ip` | DCP directe |
| ASN / org / pays / rDNS | `sessions.*`, `server_ip` | localisation/identification |
| Empreintes canvas/WebGL/audio (hash + blob complet) | `sessions.*_hash`, `client_full` | quasi-identifiant stable |
| Agrégats comportementaux (souris/clavier/scroll, rythme) | `client_full` | comportemental |
| User-Agent, langues, écran, timezone, polices… | `client_full` + colonnes | fingerprint |
| Verdict + score | `decisions`, `sessions` | profilage |

---

## 2. Déroulé de l'audit (phases)

Lecture de code + inspection DB. Conteneur jetable / `docker compose` pour
inspecter la base réelle :
```bash
NODEC='docker run --rm -v "$PWD":/app -w /app node:20'
# ouvrir data/solo.db : sqlite3 (dans l'image), ou un script node better-sqlite3.
```

### Phase 0 — Cartographie + schéma
- [ ] Lire `db.ts` : **schéma complet** des tables (`sessions`, `server_tls`,
      `server_http`, `server_ip`, `client_full`, `decisions`) et leurs relations.
      Noter les colonnes vs les blobs JSON (double stockage : colonnes plates +
      JSON complet → de la donnée perso est dupliquée).
- [ ] Confirmer la finalité de chaque champ stocké : est-il **utilisé** (par le
      moteur, le récap, la réputation) ou stocké « au cas où » ? Tout champ non
      utilisé = violation de minimisation.

### Phase 1 — Effacement RÉEL à l'expiration (le point dur)
- [ ] **TTL** : `TTL_MS = 1h` ; `startSweeper()` exécute toutes les 5 min
      `DELETE FROM sessions WHERE expires_at < now`. **VÉRIFIER LE POINT CRITIQUE** :
      ce DELETE purge-t-il aussi `server_tls / server_http / server_ip / client_full
      / decisions` ? Si ces tables enfant **n'ont pas `ON DELETE CASCADE`** (et que
      `PRAGMA foreign_keys=ON` est activé), alors **les blobs JSON contenant IP +
      empreinte complète survivent indéfiniment** comme orphelins — la lecture est
      filtrée par `expires_at` (donc invisible) mais la **donnée n'est pas effacée**
      → **violation de la limitation de conservation**. Inspecter le schéma + tester :
      insérer une session, forcer l'expiration, lancer le sweep, vérifier que les 5
      tables enfant sont vides.
- [ ] Si pas de cascade : finding P0/P1 + correctif (FK `ON DELETE CASCADE` + 
      `PRAGMA foreign_keys=ON`, ou DELETE explicite multi-tables dans le sweeper).
- [ ] **VACUUM / réutilisation** : après DELETE, les pages SQLite contiennent encore
      les octets jusqu'à réécriture. Pour un lab c'est acceptable, mais le noter
      (et `PRAGMA secure_delete` envisageable).
- [ ] Confirmer que `selectFull`/`list`/`fingerprintReputation` filtrent **tous** sur
      `expires_at`/`created_at >= since` → une donnée « expirée mais pas encore
      sweepée » n'est jamais servie ni comptée.

### Phase 2 — Minimisation
- [ ] **Blob complet `client_full`** : on stocke l'intégralité du payload client +
      des colonnes extraites. Le blob est-il nécessaire (récap/export) ou peut-on ne
      garder que les colonnes utiles ? Au minimum justifier la double conservation.
- [ ] **IP en clair** : `sessions.ip` stocke l'IP complète. Pour la réputation on
      compte des IP **distinctes** — un **hash d'IP** suffirait-il au lieu de l'IP en
      clair ? (réduit la sensibilité tout en gardant la fonction). À proposer.
- [ ] **rDNS / ASN / pays** : nécessaires au verdict — OK, mais conservés au même
      TTL.
- [ ] Champs collectés mais **jamais lus** par le moteur ni affichés : candidats à
      la suppression.

### Phase 3 — Contenu sensible : le texte tapé
- [ ] **Promesse README** : « le texte tapé n'est jamais enregistré — rythme
      uniquement ». **Le vérifier dans le code** : le collecteur comportemental
      (`src/client/behavioral/*`) n'enregistre que des **agrégats** (counts, moyennes,
      écarts-types de dwell/flight) et **jamais les touches/caractères**. Le schéma
      `behavioralSchema` (validation.ts) ne contient aucun champ de contenu — confirmer
      qu'aucun champ libre (ex. un tableau de codes touches) ne transite. C'est une
      promesse publique : elle doit être prouvée, pas supposée.
- [ ] Idem : pas de capture de presse-papier, de saisie de formulaire, d'URL visitées.

### Phase 4 — Journaux (logs)
- [ ] Logger Fastify (index.ts) : `redact` retire `cookie`/`authorization`, commentaire
      « avoid persisting client IPs in request logs ». **Vérifier** : `req.ip` est
      127.0.0.1 (proxy) donc la vraie IP n'apparaît pas dans le log de requête par
      défaut — mais aucun `log.info/warn` ne logge-t-il `getRealRemoteForSocket`,
      le SNI, l'UA, ou un fingerprint ? Grep les appels de log dans server/. Le log
      `/collect` ne sort que le **nombre** d'issues (bien) — confirmer qu'on ne logge
      jamais le payload.
- [ ] Rotation : compose limite json-file à 10m×3 — OK, mais les logs peuvent
      contenir des DCP transitoires : confirmer leur contenu.

### Phase 5 — Export & droits
- [ ] `/export/:id` dump le **JSON complet** d'une session (toutes les DCP). Protégé
      par capability UUID (cf. audit-endpoints). Confirmer que c'est l'utilisateur
      lui-même (détenteur de l'URL de recap) qui exporte ses propres données →
      sert le **droit d'accès/portabilité**. Pas de partage tiers, pas d'analytics
      externe, pas de cookie de tracking (à confirmer).
- [ ] **Droit à l'effacement** : aucune route de suppression ; mitigé par le TTL 1h
      (effacement automatique rapide). Le documenter comme choix.

### Phase 6 — Base légale, finalité, information, DPIA
- [ ] **Finalité** documentée et unique (démontrer le fingerprinting/anti-bot ;
      pédagogie). Pas de réutilisation détournée.
- [ ] **Information** : l'utilisateur qui scanne sait-il ce qui est collecté ? Pour
      un lab pédago, une note de transparence sur la page suffit généralement —
      recommander un court bandeau « ce lab collecte X, conservé 1h, jamais le texte
      tapé, pas de partage ».
- [ ] **DPIA** : un traitement de suivi/identification systématique relève des
      cas où une analyse d'impact est recommandée. Même pour un lab non déployé,
      proposer une **mini-DPIA** (finalité, données, durée, risques, mitigations) —
      cohérent avec ton réflexe DPIA sur d'autres projets.
- [ ] **Tor/VPN/voyageurs** : noter que la géoloc IP est une **inférence** (faillible)
      et ne doit pas être présentée comme un fait sur la personne.

### Phase 7 — Synthèse
- [ ] Prioriser : **P0/P1** données perso conservées au-delà du TTL (orphelins sans
      cascade) ; contenu sensible enregistré contrairement à la promesse ; IP/payload
      dans les logs. **P2** minimisation (IP en clair vs hash, blob redondant). **P3**
      transparence/DPIA/doc.
- [ ] Pour chaque finding : preuve (requête SQL d'inspection regroupée en **une seule
      commande psql/sqlite** selon ta préférence), correctif, test (insérer→expirer→
      sweep→asserter vide).
- [ ] Rappels maison : semver, README (la note de transparence = feature livrée →
      MAJ README), liste des fichiers modifiés, GO avant tout changement de schéma
      en prod (`\d`/`.schema` sur la base réelle d'abord).

---

## 3. Format du rapport
```
# Audit confidentialité / RGPD — solo (vX.Y.Z) — <date>
## Verdict : conforme aux principes ? OUI/NON — manquements
## 1. Cartographie DCP × table × finalité × utilisé(o/n)
## 2. Effacement réel au TTL (cascade ? orphelins ? preuve test)
## 3. Minimisation (champs de trop, IP en clair vs hash)
## 4. Contenu sensible (preuve : pas de texte tapé/clipboard)
## 5. Logs (DCP loggées ?)
## 6. Export / droits / base légale / transparence / DPIA
## 7. Remédiation priorisée + tests ajoutés
```

## 4. Checklist de complétude
- [ ] Schéma DB lu ; cascade/orphelins tranchés par un test insérer→expirer→sweep.
- [ ] Promesse « pas de texte tapé » prouvée dans collecteur + schéma.
- [ ] Tous les `log.*` de server/ inspectés pour DCP.
- [ ] Chaque champ stocké justifié par une finalité (sinon finding minimisation).
- [ ] Mini-DPIA + note de transparence proposées.
- [ ] Tout non-couvert listé (aucun cap muet) ; findings avec preuve + test.
