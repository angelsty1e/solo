# Audit parsers d'entrée brute — solo (v1.3.0) — 2026-06-05

Audit **statique** (lecture + raisonnement, aucune exécution locale conformément aux
contraintes LXC). Cible : les parsers qui désérialisent des octets **entièrement
contrôlés par un attaquant non authentifié** dès qu'il atteint `:8443`.

Fichiers audités :
- `src/server/tls/clienthello.ts` (parser ClientHello, offsets manuels)
- `src/server/tls/interceptor.ts` (proxy TCP, buffering, slowloris, maps)
- `src/server/tls/ja3.ts`, `src/server/tls/ja4.ts` (agrégation/hash)
- `src/server/http/headers.ts` (capture `rawHeaders`)
- `src/server/enrich/geoip.ts`, `country.ts`, `integrity.ts` (parsing `.mmdb` via `maxmind`)
- `src/server/index.ts` (bornes Fastify/Node, error handler, intégrité)

---

## Verdict : couche d'entrée robuste ? **OUI (avec réserves P2/P3)**

**Pire cas atteignable par un seul paquet non authentifié : aucun crash, aucun
hors-bornes natif, aucune boucle infinie, aucun OOM.**

Le code a manifestement déjà été durci (commit `8dbeb7a` « durcissement anti-bot du
moteur de décision + interception TLS ») : `Reader` à bornes systématiques, `try/catch`
englobant dans `buildFingerprint`, cap mémoire global + cap par IP + timeouts + cleanup
idempotent dans l'interceptor, pinning d'intégrité `.mmdb` optionnel. Les invariants
**T1–T6 sont tenus**. Les findings restants sont du durcissement défensif et de la
robustesse de cap, pas des P0/P1 exploitables.

| Sévérité | Nombre |
|---|---|
| P0 (crash/OOB/OOM/boucle infinie par 1 paquet) | **0** |
| P1 (slowloris/fuite mémoire/throw non rattrapé/buffer non capé) | **0** |
| P2 (amplification CPU bornée mais coûteuse ; cap implicite/muet) | **3** |
| P3 (durcissement défensif, gardes/tests redondants) | **4** |

---

## 1. Bornes & terminaison (T1–T6) par parser : tenu/violé + preuve

### `clienthello.ts`

**T4 (hors-bornes) — TENU.** Le `Reader` garde chaque lecture (`u8/u16/u24/slice`)
et jette `Error('eof …')` maison avant tout `readUInt*` natif (lignes 41, 47, 53, 62).
Les lectures **directes** sur `data` dans les `case` d'extension sont toutes
pré-gardées par une comparaison à `data.length` :

- **SNI** (l.131-158) : garde `data.length >= 5`, puis `listLen + 2 <= data.length`
  (l.135) ⇒ `2 + listLen <= data.length`. La boucle teste `off + 3 <= 2 + listLen`
  ⇒ `off + 3 <= data.length`, donc `readUInt8(off)` et `readUInt16BE(off+1)` (qui lit
  `off+1..off+2`) sont **dans les bornes**. Le `subarray(off, off+nameLen)` est gardé
  par `off + nameLen > data.length → break` (l.141). **OK.**
- **ALPN** (l.159-173) : `end = Math.min(2 + listLen, data.length)`, boucle `off < end`,
  `off + protoLen > end → break`. **OK.**
- **supported_versions / curves / sig_algs / ec_point_formats** : chaque boucle a une
  **double borne** `off+2 <= 1/2+listLen && off+2 <= data.length` (l.179, 189, 209) ou
  `off < data.length` (l.199). **OK.**

**T1 (terminaison) — TENU. Preuve par boucle :**

| Boucle | Pas garanti | Cas pathologique | Termine ? |
|---|---|---|---|
| extensions (l.123) | `slice(len)` consomme `4+len` octets, `extReader` borné | `len` énorme → `slice` jette `eof slice` (rattrapé) | **Oui** |
| ciphers (l.102) | `i += 2` sur `cipherLen` fixe (déjà sliced) | — | **Oui** |
| comp (l.109) | `i++` sur `compLen` fixe | — | **Oui** |
| SNI (l.137) | `off += 3` **inconditionnel** (l.140) avant tout `break`/`off+=nameLen` | `nameType≠0, nameLen=0` répété → off avance de 3/itér | **Oui** |
| ALPN (l.165) | `off += 1` **inconditionnel** (l.166) | `protoLen=0` répété → off avance de 1/itér | **Oui** |
| supVers (l.179) | `off += 2` | listLen menteur → 2e borne `data.length` coupe | **Oui** |
| curves (l.189) | `off += 2` | idem | **Oui** |
| ecPoint (l.199) | `off++` | — | **Oui** |
| sigAlgs (l.209) | `off += 2` | idem | **Oui** |

Aucune boucle ne peut stagner : chaque corps a une progression **inconditionnelle**
du compteur. **T1 prouvé.**

**T2 (pas de throw non maîtrisé) — TENU.** `parseClientHello` jette des `Error`
maison ; l'unique appelant productif (`buildFingerprint`, interceptor l.64-86) est dans
un `try { … } catch { return null }`. Aucun chemin où l'exception remonte au handler de
socket. **OK.**

**T5 (déterminisme) — TENU.** `parseClientHello` est une fonction pure ; aucun état
global, pas de `Date.now()`. Mêmes octets → même sortie.

**T6 (linéarité CPU) — TENU avec réserve (voir F1).** Coût O(taille du paquet) pour
le parsing. Pas de quadratique dans le parser lui-même. La réserve concerne
l'agrégation aval (ja3/ja4) et la taille des tableaux de sortie — voir F1/F2.

### `interceptor.ts`

**T3 (bornage mémoire) — TENU.** Triple cap explicite :
- `FIRST_RECORD_CAP = 16389` octets par capture (l.226), finalize forcé dès dépassement
  (l.294) ⇒ un record annoncé à 64 Ko ne bufferise jamais 64 Ko.
- `MAX_TOTAL_CAPTURE_BYTES = 32 Mo` global (l.59, vérifié l.282) ⇒ shed-load sous flood.
- `MAX_CONN_PER_IP = 64` (l.58, vérifié l.147-152) ⇒ anti-slowloris par source.
- `setTimeout(15_000)` socket (l.158) + `setTimeout(finalize, 1500)` capture (l.292)
  ⇒ une connexion muette est libérée, pas de buffer ni de FD orphelin.
- `cleanup()` idempotent (`cleaned` flag) attaché à error/close/timeout des **deux**
  sockets ⇒ décompte `connCountByIp` et `totalCaptureBytes`, supprime l'entrée
  `pendingByUpPort`. `ctxBySocket` est une **WeakMap** ⇒ pas de fuite à la fermeture.

**T2 — TENU.** `buildFingerprint` ne jette jamais (catch interne). Aucun `throw` dans
le handler `net.createServer`. **OK.**

### `headers.ts`

**T1/T6 — TENU.** Boucle `i += 2` bornée par `rawHeaders.length`. `Node maxHeaderSize`
(16 Ko par défaut, non surchargé — voir F3) borne la taille totale en amont. Coût
linéaire. **OK** (réserve F3 : cap implicite, à rendre explicite).

### `ja3.ts` / `ja4.ts`

**TENU.** `filterGrease` + `join` + `createHash` ne jettent pas sur listes vides
(`[].join('-')` = `''`, hash d'une chaîne vide est valide). `pad2Dec` plafonne à `'99'`.
`alpnCode` gère `alpn.length===0` et `first.length===0`. Aucun `readUInt*`. **OK.**

### `.mmdb` (`geoip.ts` / `country.ts`)

**TENU pour l'entrée réseau** (le `.mmdb` est un fichier **opérateur**, pas piloté par
l'attaquant réseau). `reader.get(ip)` est en `try/catch → null` (l.37-46 geoip).
`open()` au démarrage : sur fichier corrompu, `maxmind` jette → remonte à `main().catch`
→ `process.exit(1)` **au démarrage** (fail-closed, pas un DoS runtime). Pinning
SHA-256 optionnel disponible (`GEOIP_DB_SHA256`). Voir F6.

---

## 2. Corpus dirigé : payload | parser | comportement | attendu | sévérité

Tous ces cas ont été **raisonnés statiquement** (pas exécutés). Comportement attendu
vérifié contre le code. À ajouter en tests (section 6).

| # | Payload (hex / description) | Parser | Comportement (tracé) | Attendu | Sév |
|---|---|---|---|---|---|
| 1 | `16` seul (record tronqué après type) | clienthello | `r.u16()` version → `eof u16` jeté → catch → `null` | throw maison | OK |
| 2 | record annoncé 64 Ko, paquet 10 o | clienthello + proxy | parser jette `eof slice` ; proxy plafonne à 16389 o, n'attend pas 64 Ko | pas d'OOM | OK |
| 3 | `sessionIdLen=255`, buffer court | clienthello | `r.slice(255)` → `eof slice` | throw maison | OK |
| 4 | `cipherLen` impair | clienthello | `odd cipher length` jeté (l.99) | throw maison | OK |
| 5 | `cipherLen=0xFFFF`, buffer court | clienthello | `r.slice(65535)` → `eof slice` | throw maison | OK |
| 6 | `extTotalLen` > remaining | clienthello | `r.slice(extTotalLen)` → `eof slice` | throw maison | OK |
| 7 | ext `len` > data restante de extReader | clienthello | `extReader.slice(len)` → `eof slice` | throw maison | OK |
| 8 | SNI `nameLen=0`, `nameType≠0` ×N | clienthello | `off += 3`/itér, termine ; `sni=null` | termine, pas de hang | OK |
| 9 | SNI nom 300 o (>256) | clienthello | `nameLen <= 256` faux → ignoré, `sni=null` | pas de blob géant gardé | OK |
| 10 | SNI nom hors charset (`a b`) | clienthello | regex échoue → `sni` reste `null`, reste du parse intact | ignoré proprement | OK |
| 11 | ALPN `protoLen=0` ×N | clienthello | `off += 1`/itér, termine ; entrées `''` poussées | termine | **F2** |
| 12 | ALPN `protoLen` > end | clienthello | `off+protoLen>end → break` | pas d'OOB | OK |
| 13 | extensions dupliquées ×10 000 (même type, len=0) | clienthello + ja4 | extReader avance de 4 o/ext → linéaire ; tableaux `extensions`/`extensionTypes` poussent 10 000 entrées | linéaire **mais voir F1/F2** | **F1** |
| 14 | GREASE partout | clienthello + ja3/ja4 | `isGrease` filtre à l'agrégation, pas à la terminaison | pas de fausse boucle | OK |
| 15 | recordType=0x17 | clienthello | `not a handshake record` jeté immédiatement | throw immédiat | OK |
| 16 | hsType≠0x01 | clienthello | `not a ClientHello handshake` jeté | throw immédiat | OK |
| 17 | `recordLength < 4` | clienthello | `truncated record` jeté (l.82) | throw immédiat | OK |
| 18 | curves `listLen` impair | clienthello | boucle `off+2` saute le dernier octet → pas d'OOB | pas d'OOB | OK |
| 19 | en-têtes HTTP ×10 000 | headers | borné par `maxHeaderSize` 16 Ko Node | refus 431 avant parse | **F3** |

**Aucun cas ne produit de `RangeError` natif, de hang, ni d'OOM.** Le corpus dirigé
passe.

---

## 3. Fuzzing par mutation (proposé — NON exécuté)

Harnais à créer dans `tests/parsers-fuzz.test.ts` (cf. section 6). Propriété centrale :

```
parseClientHello(mutant) retourne un objet OU jette une Error('eof …'/maison),
JAMAIS un RangeError natif, JAMAIS un hang (budget temps/itération mesuré côté test).
```

Stratégie : figer un ClientHello Chrome valide en hex, puis pour N mutants appliquer
byte-flip / troncature à chaque offset / longueurs gonflées (0xFFFF) / longueurs à zéro /
extensions répétées en masse. Chaque sortie passe ensuite dans `computeJa3`/`computeJa4`
(doivent ne pas jeter) puis dans `buildFingerprint` (chemin réel interceptor).

**Prédiction de l'audit statique** : 0 RangeError, 0 hang. Le seul risque résiduel est
le **coût mémoire des tableaux de sortie** sur extensions/ciphers répétés en masse (F1),
borné en pratique par `FIRST_RECORD_CAP` (16389 o ⇒ au plus ~4096 extensions de 4 o, ou
~8190 ciphers) — donc **borné, mais non plafonné explicitement** au niveau parser.

---

## 4. DoS proxy : slowloris / buffering / fuite map — résultats

| Vecteur | Défense présente | Verdict |
|---|---|---|
| **Slowloris TLS** (1 octet puis rien) | `setTimeout(15_000)` socket → `cleanup` ; `setTimeout(finalize,1500)` capture | **Couvert** — socket libérée, buffer relâché |
| **Record géant dribblé** | `FIRST_RECORD_CAP=16389` (par conn) + `MAX_TOTAL_CAPTURE_BYTES=32 Mo` (global) | **Couvert** — capé |
| **Flood de connexions** | `MAX_CONN_PER_IP=64` + `cleanup` décompte sur close/error/timeout | **Couvert** par IP source |
| **Fuite map socket→fp** | `ctxBySocket` = WeakMap ; `pendingByUpPort` supprimée à `secureConnection` ou `cleanup` | **Pas de fuite** |
| **Connexion semi-ouverte loopback** | `allowHalfOpen: false` + `upstream.on('error'/'close', cleanup)` | **Couvert** |

**Réserves (P2)** :
- **F4 — `MAX_CONN_PER_IP` contournable derrière NAT/IPv6** : la clé est `remoteAddress`.
  Un attaquant sur un /64 IPv6 dispose de 2⁶⁴ adresses sources ⇒ 64 conns × N adresses.
  Le cap global 32 Mo reste le vrai garde-fou (≈ 2000 captures pleines simultanées),
  mais le per-IP est facilement neutralisé en IPv6. **Bornage par /64** recommandé.
- **F5 — Pas de cap sur le nombre total de connexions concurrentes** : seuls per-IP et
  octets-bufferisés sont capés. Un flood IPv6 distribué peut atteindre le plafond FD du
  process (EMFILE) avant le cap mémoire. Le timeout 15 s limite la durée de vie, mais un
  cap dur `MAX_TOTAL_CONN` serait une ceinture+bretelles.

---

## 5. `.mmdb` : comportement sur fichier corrompu + reco pinning

- **Fichier tronqué/corrompu** : `open()` (maxmind) jette au démarrage → `initGeoIp`/
  `initCountryDb` propage → `main().catch → process.exit(1)`. **Fail-closed au boot**,
  pas un DoS runtime. Acceptable. *(Réserve F6 : message d'erreur brut de la lib remonte
  en console au boot — pas une fuite réseau, log opérateur uniquement.)*
- **Runtime `reader.get(ip)`** : entouré de `try/catch → null` (geoip l.37, country l.29).
  Un IP malformé ou un nœud d'arbre corrompu dégrade vers `asn/country = null`, conforme
  au comportement documenté. **OK.**
- **Pinning d'intégrité** : déjà supporté (`GEOIP_DB_SHA256`, `GEOIP_COUNTRY_DB_SHA256`,
  `verifyFileSha256`). **Recommandation P3 : le RENDRE OBLIGATOIRE en prod** (documenter
  dans le README / refuser le démarrage prod sans pin) — défense en profondeur contre un
  `.mmdb` substitué nourrissant le parser tiers `maxmind`.

---

## 6. Remédiation priorisée (P0→P3) + tests à ajouter

### P0 — aucun.
### P1 — aucun.

### P2 (amplification bornée / cap implicite)

**F1 — Tableaux de sortie du parser non plafondés explicitement (amplification mémoire bornée).**
`extensions`, `extensionTypes`, `cipherSuites` croissent avec l'entrée. Borne **implicite**
par `FIRST_RECORD_CAP` (16389 o) côté proxy, mais le parser pur appelé hors proxy (tests,
réutilisation future) n'a aucun cap. Risque : ~4096 entrées max via le chemin réseau —
non dangereux aujourd'hui, mais le cap est muet.
*Correctif* : plafonner explicitement le nombre d'extensions/ciphers gardés (ex. break si
`extensions.length > 512`) — défensif, documente l'invariant.

**F2 — ALPN/SNI : entrées vides/non significatives gardées.**
ALPN `protoLen=0` pousse des `''` dans `alpn[]` (l.169) ; ces entrées bruitent `ja4`
(`alpnCode` lit `alpn[0]`). Pas un crash, mais pollue le fingerprint et grossit le tableau.
*Correctif* : ignorer `protoLen===0` (`if (protoLen===0) continue;` après `off+=1`).

**F4 — `MAX_CONN_PER_IP` contournable en IPv6 (cf. §4).**
*Correctif* : dériver la clé per-IP du **/64** pour IPv6 (`addr.split(':',4).join(':')`)
au lieu de l'adresse complète.

**F5 — Pas de cap global de connexions concurrentes (cf. §4).**
*Correctif* : compteur `totalConns` + `MAX_TOTAL_CONN` (ex. 4096), `destroy()` au-delà.

### P3 (durcissement défensif)

**F3 — `maxHeaderSize` Node implicite.**
`http.createServer({}, handler)` (interceptor l.99) hérite du défaut Node (16 Ko,
`headersTimeout` 60 s, `requestTimeout` 5 min). Ça **borne** bien l'attaque « milliers
d'en-têtes » (réponse 431 avant le parser `captureHttpFingerprint`), mais le cap est muet.
*Correctif* : passer explicitement `http.createServer({ maxHeaderSize: 16384,
requestTimeout: 30000, headersTimeout: 10000, insecureHTTPParser: false }, handler)` —
rend l'invariant explicite et resserre les timeouts.

**F6 — Pinning `.mmdb` non obligatoire + message d'erreur brut au boot.**
*Correctif* : documenter `GEOIP_*_SHA256` comme requis en prod ; envelopper l'erreur
`open()` dans un message contrôlé.

**F7 — Cross-check absent entre `handshake body length` (u24) et `extTotalLen`.**
Le parser lit `r.u24()` (l.89, jeté) sans vérifier la cohérence avec le reste du record.
Inoffensif (toutes les lectures restent gardées par `Reader`), mais un cross-check
détecterait des records mensongers plus tôt. *Purement défensif.*

**F8 — `parseClientHello` n'a pas de garde de taille minimale globale.**
Un buffer de 5 o passe le record header puis jette en chaîne. Inoffensif (catch), mais un
`if (raw.length < N) throw` en tête clarifierait. *Défensif.*

---

### Tests de régression à ajouter — `tests/parsers-fuzz.test.ts`

```ts
import { describe, it, expect } from 'vitest';
import { parseClientHello } from '../src/server/tls/clienthello.js';
import { computeJa3 } from '../src/server/tls/ja3.js';
import { computeJa4 } from '../src/server/tls/ja4.js';

// Builder minimal (réutiliser buildClientHello() de fingerprint.test.ts).
function rec(body: Buffer): Buffer {
  const hs = Buffer.concat([Buffer.from([0x01]), u24(body.length), body]);
  return Buffer.concat([Buffer.from([0x16, 0x03, 0x01]), u16(hs.length), hs]);
}
function u16(n: number){const b=Buffer.alloc(2);b.writeUInt16BE(n&0xffff);return b;}
function u24(n: number){return Buffer.from([(n>>16)&0xff,(n>>8)&0xff,n&0xff]);}

describe('parsers-fuzz — terminaison & bornage (T1–T6)', () => {
  // T1/T4 : corpus dirigé
  const malformed: [string, Buffer][] = [
    ['record tronqué', Buffer.from([0x16])],
    ['record < 4', Buffer.from([0x16,0x03,0x03,0x00,0x02,0x01,0x00])],
    ['sessionIdLen géant', rec(Buffer.concat([u16(0x0303), Buffer.alloc(32), Buffer.from([0xff])]))],
    ['cipherLen impair', rec(Buffer.concat([u16(0x0303), Buffer.alloc(32), Buffer.from([0x00]), u16(3), Buffer.from([0x13,0x01,0x02])]))],
    ['cipherLen 0xFFFF court', rec(Buffer.concat([u16(0x0303), Buffer.alloc(32), Buffer.from([0x00]), u16(0xfffe)]))],
  ];
  for (const [name, buf] of malformed) {
    it(`ne jette qu'une Error maison (jamais RangeError) — ${name}`, () => {
      try { parseClientHello(buf); }
      catch (e: any) {
        expect(e).toBeInstanceOf(Error);
        expect(e.name).not.toBe('RangeError');           // pas de hors-bornes natif
        expect(String(e.message)).not.toMatch(/out of range/i);
      }
    });
  }

  // T1 : terminaison des boucles à offset manuel (budget temps)
  it('SNI nameType≠0 / nameLen=0 répété : termine en temps borné', () => {
    // ext 0x0000 : listLen, puis [nameType=1, nameLen=0] répété → off+=3/itér
    const entries = Buffer.concat(Array.from({length: 200}, () => Buffer.from([0x01,0x00,0x00])));
    const sniData = Buffer.concat([u16(entries.length), entries]);
    const sniExt = Buffer.concat([u16(0x0000), u16(sniData.length), sniData]);
    const body = Buffer.concat([u16(0x0303), Buffer.alloc(32), Buffer.from([0x00]), u16(0), Buffer.from([0x01,0x00]), u16(sniExt.length), sniExt]);
    const t0 = performance.now();
    parseClientHello(rec(body));            // ne doit pas hang
    expect(performance.now() - t0).toBeLessThan(50);
  });

  it('ALPN protoLen=0 répété : termine', () => {
    const protos = Buffer.alloc(200, 0x00); // 200 protoLen=0
    const alpnData = Buffer.concat([u16(protos.length), protos]);
    const alpnExt = Buffer.concat([u16(0x0010), u16(alpnData.length), alpnData]);
    const body = Buffer.concat([u16(0x0303), Buffer.alloc(32), Buffer.from([0x00]), u16(0), Buffer.from([0x01,0x00]), u16(alpnExt.length), alpnExt]);
    const t0 = performance.now();
    const out = parseClientHello(rec(body));
    expect(performance.now() - t0).toBeLessThan(50);
    expect(Array.isArray(out.alpn)).toBe(true);
  });

  // T6 : ja3/ja4 ne jettent jamais (listes vides / extrêmes)
  it('ja3/ja4 sur parser à listes vides', () => {
    const empty = { legacyVersion:0x0303, random:Buffer.alloc(32), sessionId:Buffer.alloc(0),
      cipherSuites:[], compressionMethods:[], extensions:[], extensionTypes:[], sni:null,
      alpn:[], supportedVersions:[], ellipticCurves:[], ecPointFormats:[], signatureAlgorithms:[] };
    expect(() => computeJa3(empty as any)).not.toThrow();
    expect(() => computeJa4(empty as any)).not.toThrow();
  });

  // Fuzzing par mutation (squelette) : figer un hello valide et muter.
  it('mutation : aucun RangeError, aucun hang', () => {
    const base = /* hex d'un ClientHello Chrome valide, à capturer une fois */ Buffer.from([]);
    if (base.length === 0) return; // placeholder tant que le seed n'est pas figé
    for (let n = 0; n < 5000; n++) {
      const m = Buffer.from(base);
      const i = Math.floor(Math.random()*m.length);
      m[i] = (m[i] + 1 + Math.floor(Math.random()*255)) & 0xff;
      const t0 = performance.now();
      try { const p = parseClientHello(m); computeJa3(p); computeJa4(p); }
      catch (e: any) { expect(e.name).not.toBe('RangeError'); }
      expect(performance.now() - t0).toBeLessThan(50);
    }
  });
});
```

---

## Rappels maison
- **Aucun fichier source modifié** par cet audit (lecture seule, conformément aux
  contraintes). Les correctifs F1–F8 et le test sont **proposés**, pas appliqués.
- Avant tout correctif touchant `interceptor.ts` (chemin critique en prod) : **GO
  explicite requis**, bump semver, MAJ README si le comportement de cap change.
- Non couvert explicitement : exécution réelle du fuzzer (interdite en local), capture
  d'un seed ClientHello Chrome réel (à faire côté LXC), parsing interne de `maxmind`
  (lib tierce — voir audit-deps).
