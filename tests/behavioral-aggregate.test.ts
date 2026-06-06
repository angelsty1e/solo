import { describe, it, expect } from 'vitest';
import type { MouseSample } from '../src/client/behavioral/mouse.js';
import type { KeyEvent } from '../src/client/behavioral/keyboard.js';
import type { ScrollSample } from '../src/client/behavioral/scroll.js';
import type { TouchSample } from '../src/client/behavioral/touch.js';
import {
  meanStd,
  mouseAggregate,
  keyboardAggregate,
  scrollAggregate,
  touchAggregate,
} from '../src/client/behavioral/aggregate.js';

// ─── Math pure des agrégats comportementaux — source du signal N4 ────────────
// N4 (decision.test.ts) part d'agrégats FAITS MAIN ; il ne vérifie jamais qu'une
// vraie trajectoire PRODUIT ces agrégats. Ces tests verrouillent la chaîne
// « échantillons bruts → métrique » : une ligne droite a une courbure nulle, un
// rythme constant a un écart-type nul — exactement ce que le moteur lit comme
// « motif synthétique ». (import type = pas de chargement DOM des modules sample.)

const move = (x: number, y: number, t: number): MouseSample => ({ type: 'move', x, y, t });
const click = (t: number): MouseSample => ({ type: 'click', x: 0, y: 0, t });
const kdown = (code: string, t: number): KeyEvent => ({ type: 'keydown', code, t });
const kup = (code: string, t: number): KeyEvent => ({ type: 'keyup', code, t });
const wheel = (deltaY: number, t: number): ScrollSample => ({ deltaY, deltaX: 0, y: 0, t });

describe('meanStd', () => {
  it('liste vide → {0, 0}', () => {
    expect(meanStd([])).toEqual({ mean: 0, std: 0 });
  });

  it('valeurs constantes → écart-type 0', () => {
    expect(meanStd([5, 5, 5, 5])).toEqual({ mean: 5, std: 0 });
  });

  it('moyenne et écart-type (population) corrects', () => {
    const r = meanStd([2, 4, 6]); // mean 4, var (4+0+4)/3 = 8/3
    expect(r.mean).toBe(4);
    expect(r.std).toBeCloseTo(Math.sqrt(8 / 3));
  });
});

describe('mouseAggregate — courbure & vitesse', () => {
  it('🎯 ligne parfaitement droite → meanCurvature = 0', () => {
    // Le signal-clé de N4 : un script qui déplace le curseur en ligne droite a une
    // courbure nulle là où un humain en a toujours un peu.
    const r = mouseAggregate([move(0, 0, 0), move(10, 0, 10), move(20, 0, 20), move(30, 0, 30)]);
    expect(r.moves).toBe(4);
    expect(r.meanCurvature).toBe(0);
  });

  it('virage à angle droit → courbure maximale (1)', () => {
    const r = mouseAggregate([move(0, 0, 0), move(10, 0, 10), move(10, 10, 20)]);
    expect(r.meanCurvature).toBeCloseTo(1); // |v1×v2| / (|v1||v2|) pour un angle de 90°
  });

  it('vitesse constante → stdSpeed 0 ; vitesse variable → stdSpeed > 0', () => {
    const constant = mouseAggregate([move(0, 0, 0), move(10, 0, 10), move(20, 0, 20), move(30, 0, 30)]);
    expect(constant.meanSpeed).toBeCloseTo(1);
    expect(constant.stdSpeed).toBe(0);

    const variable = mouseAggregate([move(0, 0, 0), move(10, 0, 10), move(40, 0, 20), move(45, 0, 30)]);
    expect(variable.stdSpeed).toBeGreaterThan(0);
  });

  it('clicks comptés séparément des moves ; stillRatio sur déplacements ~nuls', () => {
    const r = mouseAggregate([move(0, 0, 0), move(0, 0, 10), move(0, 0, 20), click(25)]);
    expect(r.clicks).toBe(1);
    expect(r.moves).toBe(3);
    expect(r.stillRatio).toBeGreaterThan(0); // déplacements < 1px
  });

  it('jitterRatio > 0 quand des micro-mouvements arrivent à très court intervalle (<8ms)', () => {
    const r = mouseAggregate([move(0, 0, 0), move(3, 1, 2), move(6, 2, 4)]); // dt 2,2 < 8, dist > 0
    expect(r.jitterRatio).toBeGreaterThan(0);
  });

  it('aucun move → métriques à 0 (pas de NaN)', () => {
    const r = mouseAggregate([click(0), click(10)]);
    expect(r.moves).toBe(0);
    expect(r.meanCurvature).toBe(0);
    expect(r.stillRatio).toBe(0);
    expect(r.jitterRatio).toBe(0);
  });
});

describe('keyboardAggregate — dwell & flight', () => {
  it('🎯 rythme robotique (dwell/flight constants) → écarts-types nuls', () => {
    // Frappe parfaitement régulière : la signature d'un script de saisie.
    const events: KeyEvent[] = [
      kdown('KeyA', 0), kup('KeyA', 50),
      kdown('KeyB', 100), kup('KeyB', 150),
      kdown('KeyC', 200), kup('KeyC', 250),
    ];
    const r = keyboardAggregate(events);
    expect(r.keydowns).toBe(3);
    expect(r.keyups).toBe(3);
    expect(r.meanDwellMs).toBeCloseTo(50);
    expect(r.stdDwellMs).toBe(0); // dwell constant
    expect(r.meanFlightMs).toBeCloseTo(50);
    expect(r.stdFlightMs).toBe(0); // flight constant
  });

  it('dwell variable → stdDwellMs > 0', () => {
    const events: KeyEvent[] = [kdown('KeyA', 0), kup('KeyA', 30), kdown('KeyB', 100), kup('KeyB', 220)];
    const r = keyboardAggregate(events);
    expect(r.stdDwellMs).toBeGreaterThan(0);
  });

  it('backspaceRatio = backspaces / keydowns', () => {
    const events: KeyEvent[] = [
      kdown('KeyA', 0), kup('KeyA', 40),
      kdown('Backspace', 80), kup('Backspace', 120),
      kdown('KeyB', 160), kup('KeyB', 200),
      kdown('Backspace', 240), kup('Backspace', 280),
    ];
    const r = keyboardAggregate(events); // 4 keydowns, 2 Backspace
    expect(r.backspaceRatio).toBeCloseTo(0.5);
  });

  it('aucune frappe → 0 partout, pas de NaN', () => {
    const r = keyboardAggregate([]);
    expect(r).toMatchObject({ keydowns: 0, keyups: 0, meanDwellMs: 0, stdDwellMs: 0, backspaceRatio: 0 });
  });
});

describe('scrollAggregate — linéarité', () => {
  it('🎯 deltas constants → linearRatio = 1 (scroll mécanique)', () => {
    const r = scrollAggregate([wheel(100, 0), wheel(100, 10), wheel(100, 20), wheel(100, 30)]);
    expect(r.linearRatio).toBe(1);
    expect(r.totalDeltaPx).toBe(400);
    expect(r.meanDeltaPx).toBeCloseTo(100);
  });

  it('deltas erratiques → linearRatio < 1', () => {
    const r = scrollAggregate([wheel(10, 0), wheel(90, 10), wheel(5, 20), wheel(120, 30), wheel(15, 40)]);
    expect(r.linearRatio).toBeLessThan(1);
  });

  it('deltaY nuls ignorés ; aucun delta → ratios à 0', () => {
    const r = scrollAggregate([wheel(0, 0), wheel(0, 10)]);
    expect(r.totalDeltaPx).toBe(0);
    expect(r.meanDeltaPx).toBe(0);
    expect(r.linearRatio).toBe(0);
  });
});

describe('touchAggregate — pression & multi-touch', () => {
  const touch = (type: TouchSample['type'], forces: number[], t: number): TouchSample => ({
    type,
    t,
    points: forces.map((force, id) => ({ x: 0, y: 0, force, id })),
  });

  it('compte starts/moves/ends, pression moyenne, multi-touch max', () => {
    const r = touchAggregate([
      touch('start', [0.5], 0),
      touch('move', [0.5, 0.7], 10), // 2 doigts
      touch('end', [0.3], 20),
    ]);
    expect(r.starts).toBe(1);
    expect(r.moves).toBe(1);
    expect(r.ends).toBe(1);
    expect(r.multiTouchMax).toBe(2);
    expect(r.meanPressure).toBeCloseTo((0.5 + 0.5 + 0.7 + 0.3) / 4);
  });

  it('forces nulles ignorées dans la moyenne ; aucun point → 0', () => {
    const r = touchAggregate([touch('start', [0], 0)]);
    expect(r.meanPressure).toBe(0); // force 0 non comptée
    expect(r.multiTouchMax).toBe(1);
  });
});
