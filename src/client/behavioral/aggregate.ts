import type {
  BehavioralSnapshot,
  KeyboardAggregate,
  MouseAggregate,
  ScrollAggregate,
  TouchAggregate,
} from '../../shared/types.js';
import { getKeyEvents, type KeyEvent } from './keyboard.js';
import { getMouseSamples, type MouseSample } from './mouse.js';
import { getScrollSamples, type ScrollSample } from './scroll.js';
import { getTouchSamples, type TouchSample } from './touch.js';

// Exportés pour les tests unitaires de la math pure (courbure, std de rythme…).
// Ce sont les fonctions qui PRODUISENT les agrégats que le niveau N4 consomme :
// les tester verrouille la chaîne « échantillons bruts → signal comportemental ».
export function meanStd(values: number[]): { mean: number; std: number } {
  if (values.length === 0) return { mean: 0, std: 0 };
  const mean = values.reduce((a, b) => a + b, 0) / values.length;
  const variance = values.reduce((acc, v) => acc + (v - mean) ** 2, 0) / values.length;
  return { mean, std: Math.sqrt(variance) };
}

export function mouseAggregate(samples: MouseSample[]): MouseAggregate {
  const moves = samples.filter((s) => s.type === 'move');
  const clicks = samples.filter((s) => s.type === 'click').length;
  const speeds: number[] = [];
  const curvatures: number[] = [];
  let still = 0;
  let jitter = 0;
  for (let i = 1; i < moves.length; i++) {
    const a = moves[i - 1]!;
    const b = moves[i]!;
    const dt = Math.max(1, b.t - a.t);
    const dx = b.x - a.x;
    const dy = b.y - a.y;
    const dist = Math.sqrt(dx * dx + dy * dy);
    const speed = dist / dt;
    speeds.push(speed);
    if (dist < 1) still++;
    if (dist > 0 && dt < 8) jitter++;
    if (i >= 2) {
      const z = moves[i - 2]!;
      const v1x = a.x - z.x;
      const v1y = a.y - z.y;
      const v2x = b.x - a.x;
      const v2y = b.y - a.y;
      const cross = Math.abs(v1x * v2y - v1y * v2x);
      const norm = Math.hypot(v1x, v1y) * Math.hypot(v2x, v2y);
      if (norm > 0) curvatures.push(cross / norm);
    }
  }
  const speed = meanStd(speeds);
  const curv = meanStd(curvatures);
  return {
    moves: moves.length,
    clicks,
    meanSpeed: speed.mean,
    stdSpeed: speed.std,
    meanCurvature: curv.mean,
    stillRatio: moves.length > 0 ? still / moves.length : 0,
    jitterRatio: moves.length > 0 ? jitter / moves.length : 0,
  };
}

export function keyboardAggregate(events: KeyEvent[]): KeyboardAggregate {
  let downs = 0;
  let ups = 0;
  let backspaces = 0;
  const dwellByCode = new Map<string, number>();
  const dwellTimes: number[] = [];
  const flightTimes: number[] = [];
  let lastUpT: number | null = null;
  for (const e of events) {
    if (e.type === 'keydown') {
      downs++;
      if (e.code === 'Backspace') backspaces++;
      dwellByCode.set(e.code, e.t);
      if (lastUpT !== null) flightTimes.push(e.t - lastUpT);
    } else {
      ups++;
      const down = dwellByCode.get(e.code);
      if (typeof down === 'number') {
        dwellTimes.push(e.t - down);
        dwellByCode.delete(e.code);
      }
      lastUpT = e.t;
    }
  }
  const dwell = meanStd(dwellTimes);
  const flight = meanStd(flightTimes);
  return {
    keydowns: downs,
    keyups: ups,
    meanDwellMs: dwell.mean,
    stdDwellMs: dwell.std,
    meanFlightMs: flight.mean,
    stdFlightMs: flight.std,
    backspaceRatio: downs > 0 ? backspaces / downs : 0,
  };
}

export function scrollAggregate(samples: ScrollSample[]): ScrollAggregate {
  const deltas = samples.filter((s) => s.deltaY !== 0).map((s) => Math.abs(s.deltaY));
  const total = deltas.reduce((a, b) => a + b, 0);
  let linear = 0;
  let nonLinear = 0;
  for (let i = 2; i < deltas.length; i++) {
    const a = deltas[i - 2]!;
    const b = deltas[i - 1]!;
    const c = deltas[i]!;
    if (Math.abs(c - b) <= 1 && Math.abs(b - a) <= 1) linear++;
    else nonLinear++;
  }
  const totalCompared = linear + nonLinear;
  return {
    events: samples.length,
    totalDeltaPx: total,
    meanDeltaPx: deltas.length > 0 ? total / deltas.length : 0,
    linearRatio: totalCompared > 0 ? linear / totalCompared : 0,
  };
}

export function touchAggregate(samples: TouchSample[]): TouchAggregate {
  let starts = 0;
  let moves = 0;
  let ends = 0;
  const pressures: number[] = [];
  let multiMax = 0;
  for (const s of samples) {
    if (s.type === 'start') starts++;
    else if (s.type === 'move') moves++;
    else ends++;
    for (const p of s.points) {
      if (p.force > 0) pressures.push(p.force);
    }
    if (s.points.length > multiMax) multiMax = s.points.length;
  }
  const meanPressure = pressures.length > 0 ? pressures.reduce((a, b) => a + b, 0) / pressures.length : 0;
  return { starts, moves, ends, meanPressure, multiTouchMax: multiMax };
}

export function aggregateBehavioral(startedAt: number): BehavioralSnapshot {
  const mouse = mouseAggregate(getMouseSamples());
  const keyboard = keyboardAggregate(getKeyEvents());
  const scroll = scrollAggregate(getScrollSamples());
  const touch = touchAggregate(getTouchSamples());
  const total =
    getMouseSamples().length +
    getKeyEvents().length +
    getScrollSamples().length +
    getTouchSamples().length;
  return {
    totalEvents: total,
    durationMs: performance.now() - startedAt,
    mouse,
    keyboard,
    scroll,
    touch,
  };
}
