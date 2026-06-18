/*
 * Copyright 2026 angelsty1e
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

export interface TouchSample {
  t: number;
  type: 'start' | 'move' | 'end';
  points: Array<{ x: number; y: number; force: number; id: number }>;
}

const samples: TouchSample[] = [];
let attached = false;
const MAX = 3000;

function snap(e: TouchEvent, type: TouchSample['type']) {
  if (samples.length >= MAX) return;
  const list = e.touches.length > 0 ? e.touches : e.changedTouches;
  const points: TouchSample['points'] = [];
  for (let i = 0; i < list.length; i++) {
    const t = list.item(i);
    if (!t) continue;
    points.push({ x: t.clientX, y: t.clientY, force: t.force ?? 0, id: t.identifier });
  }
  samples.push({ t: performance.now(), type, points });
}

const onStart = (e: TouchEvent) => snap(e, 'start');
const onMove = (e: TouchEvent) => snap(e, 'move');
const onEnd = (e: TouchEvent) => snap(e, 'end');

export function startTouch(): void {
  if (attached) return;
  attached = true;
  window.addEventListener('touchstart', onStart, { passive: true });
  window.addEventListener('touchmove', onMove, { passive: true });
  window.addEventListener('touchend', onEnd, { passive: true });
}

export function stopTouch(): void {
  if (!attached) return;
  attached = false;
  window.removeEventListener('touchstart', onStart);
  window.removeEventListener('touchmove', onMove);
  window.removeEventListener('touchend', onEnd);
}

export function getTouchSamples(): TouchSample[] {
  return samples;
}