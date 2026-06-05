import type { SignalDef } from './types.js';

// ─── Level 4 — comportement (souris / clavier / scroll) ──────────────────────
// Source : BehavioralSnapshot, agrégé côté client sur la fenêtre de collecte.
// Principe : on ne cherche PAS « pas assez d'activité » (un humain peut lire
// sans bouger) mais des **motifs synthétiques** — des régularités qu'un humain
// ne produit jamais avec assez d'échantillons (courbure rigoureusement nulle,
// variance de frappe nulle, scroll parfaitement linéaire, vitesse constante).
//
// Tous soft (présomption, jamais un aveu). Seuils conservateurs : chaque signal
// exige une taille d'échantillon minimale ET une régularité exacte, pour éviter
// le faux positif sur un humain peu actif (le reproche n°1 du test Mac). La
// lecture *positive* du comportement (entropie souris = humain) est réservée au
// futur score de confiance, pas ici.

export const LEVEL4: SignalDef[] = [
  {
    id: 'beh_no_interaction',
    label: 'Aucune interaction durant la collecte',
    level: 4,
    detect: (i) => {
      const b = i.client?.behavioral;
      if (!b) return null;
      // Faible : un humain peut rester immobile à lire. Ne pèse qu'empilé.
      return b.totalEvents === 0 && b.durationMs >= 5000
        ? [`0 événement souris/clavier/scroll en ${Math.round(b.durationMs / 1000)} s`]
        : null;
    },
  },
  {
    id: 'beh_mouse_synthetic',
    label: 'Trajectoire souris synthétique',
    level: 4,
    detect: (i) => {
      const m = i.client?.behavioral?.mouse;
      if (!m || m.moves < 25) return null;
      // Une vraie main produit toujours de la courbure et du micro-jitter ;
      // exactement 0 sur 25+ déplacements = trajectoire générée.
      if (m.meanCurvature === 0) return [`${m.moves} déplacements souris en ligne parfaitement droite (courbure = 0)`];
      if (m.jitterRatio === 0) return [`${m.moves} déplacements souris sans aucun micro-jitter`];
      return null;
    },
  },
  {
    id: 'beh_mouse_constant_speed',
    label: 'Vitesse de souris constante',
    level: 4,
    detect: (i) => {
      const m = i.client?.behavioral?.mouse;
      if (!m || m.moves < 25) return null;
      return m.meanSpeed > 0 && m.stdSpeed === 0
        ? [`vitesse souris rigoureusement constante (écart-type = 0) sur ${m.moves} déplacements`]
        : null;
    },
  },
  {
    id: 'beh_scroll_linear',
    label: 'Scroll parfaitement linéaire',
    level: 4,
    detect: (i) => {
      const s = i.client?.behavioral?.scroll;
      if (!s || s.events < 10) return null;
      return s.linearRatio >= 0.99
        ? [`scroll linéaire à ${(s.linearRatio * 100).toFixed(0)} % sur ${s.events} événements (programmatique)`]
        : null;
    },
  },
  {
    id: 'beh_keystroke_robotic',
    label: 'Frappe clavier sans variance',
    level: 4,
    detect: (i) => {
      const k = i.client?.behavioral?.keyboard;
      if (!k || k.keydowns < 10) return null;
      // dwell = durée d'appui, flight = inter-touches. Variance nulle sur 10+
      // frappes = saisie injectée, pas tapée.
      return k.stdDwellMs === 0 && k.stdFlightMs === 0
        ? [`${k.keydowns} frappes sans aucune variance de rythme (dwell/flight)`]
        : null;
    },
  },
];

// Tous les signaux comportementaux pointent vers la carte « Behavioral » du récap.
export const BEHAVIOR_CARD: Record<string, string> = {
  beh_no_interaction: 'behavioral',
  beh_mouse_synthetic: 'behavioral',
  beh_mouse_constant_speed: 'behavioral',
  beh_scroll_linear: 'behavioral',
  beh_keystroke_robotic: 'behavioral',
};
