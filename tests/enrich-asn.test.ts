import { describe, it, expect } from 'vitest';
import { classifyAsn } from '../src/server/enrich/asn.js';

// ─── classifyAsn — classification réseau (datacenter / VPN) ──────────────────
// Signal central de N2 (réseau). Deux couches : ASN par NUMÉRO (fiable, stable)
// puis mot-clé sur l'org-name (fallback). Invariant de sécurité : sans preuve
// POSITIVE, le résultat est null (inconnu), JAMAIS false — un false handerait le
// trust credit résidentiel à un bot quand GeoIP est down (cf. trust.ts:120).

describe('classifyAsn — ASN par numéro (chemin fiable)', () => {
  it('ASN datacenter connu (16509 AWS) → isDatacenter, même sans org-name', () => {
    expect(classifyAsn(null, 16509)).toEqual({ isDatacenter: true, isProxyHint: null });
  });

  it('ASN VPN connu (9009 M247) → datacenter ET proxy (il est dans les deux sets)', () => {
    // 9009 figure à la fois dans DATACENTER_ASNS et VPN_ASNS (M247 héberge des
    // exit VPN sur de l'infra hosting) → les deux drapeaux positifs.
    expect(classifyAsn(null, 9009)).toEqual({ isDatacenter: true, isProxyHint: true });
  });

  it('le numéro prime : org-name résidentiel mais ASN datacenter → isDatacenter', () => {
    expect(classifyAsn('Some Residential ISP', 14618).isDatacenter).toBe(true); // Amazon
  });
});

describe('classifyAsn — invariant null (GeoIP down / ASN non résolu)', () => {
  it('🔴 org-name absent ET ASN inconnu → {null, null}, jamais {false, false}', () => {
    const r = classifyAsn(null, 64500); // ASN privé, hors sets
    expect(r.isDatacenter).toBeNull();
    expect(r.isProxyHint).toBeNull();
    // Le cœur de l'invariant : surtout PAS false (qui vaudrait "résidentiel confirmé").
    expect(r.isDatacenter).not.toBe(false);
    expect(r.isProxyHint).not.toBe(false);
  });

  it('org-name absent, aucun ASN du tout → {null, null}', () => {
    expect(classifyAsn(null)).toEqual({ isDatacenter: null, isProxyHint: null });
  });

  it('asymétrie : ASN datacenter connu mais proxy inconnu → {true, null}', () => {
    // dc positif par numéro, mais rien ne prouve le proxy → null (pas false).
    expect(classifyAsn(null, 24940)).toEqual({ isDatacenter: true, isProxyHint: null }); // Hetzner
  });
});

describe('classifyAsn — mots-clés org-name (fallback)', () => {
  it('hosting connu → isDatacenter ("OVH Hosting")', () => {
    expect(classifyAsn('OVH Hosting', 99999).isDatacenter).toBe(true);
  });

  it('VPN connu → isProxyHint ("NordVPN" / "Mullvad VPN")', () => {
    expect(classifyAsn('NordVPN S.A.', 99999).isProxyHint).toBe(true);
    expect(classifyAsn('Mullvad VPN AB', 99999).isProxyHint).toBe(true);
  });

  it('org-name présent mais sans mot-clé → {false, false} (lookup réussi = résidentiel)', () => {
    // Distinction clé avec le cas null : ICI le lookup a RÉUSSI (org-name connu) et
    // ne matche aucun mot-clé → résidentiel POSITIVEMENT confirmé → false légitime.
    expect(classifyAsn('Orange S.A.', 3215)).toEqual({ isDatacenter: false, isProxyHint: false });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// ⚠️ FAUX POSITIFS sur HUMAINS RÉELS — mots-clés en SOUS-CHAÎNE (asn.ts:76,79)
// `lower.includes(k)` matche n'importe quelle sous-chaîne. 'cloud' et 'host' sont
// si génériques qu'ils attrapent des services grand public. Ces tests ÉPINGLENT
// le comportement actuel : à décider si on resserre (word-boundary / liste) ou si
// on l'accepte. Axe « faux positif sur humain réel » du projet.
// ─────────────────────────────────────────────────────────────────────────────
describe('⚠️ classifyAsn — sur-match des mots-clés génériques (à trancher)', () => {
  it('iCloud Private Relay (humain réel) est classé datacenter via la sous-chaîne "cloud"', () => {
    // 'icloud private relay'.includes('cloud') → true. Un humain Apple derrière le
    // Private Relay est donc marqué isDatacenter — faux positif réseau.
    const r = classifyAsn('iCloud Private Relay', 99999);
    expect(r.isDatacenter).toBe(true); // comportement ACTUEL épinglé
  });

  it('un nom résidentiel contenant "host" est classé datacenter (sur-match)', () => {
    // Illustratif : toute org contenant la sous-chaîne "host" matche, y compris des
    // intitulés qu'un humain lirait comme résidentiels.
    expect(classifyAsn('CityHost Home Broadband', 99999).isDatacenter).toBe(true);
  });
});
