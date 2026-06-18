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

export interface MouseSample {
  t: number;
  x: number;
  y: number;
  type: 'move' | 'click';
  button?: number;
}

const samples: MouseSample[] = [];
let attached = false;
const MAX = 5000;

function onMove(e: MouseEvent) {
  if (samples.length >= MAX) return;
  samples.push({ t: performance.now(), x: e.clientX, y: e.clientY, type: 'move' });
}

function onClick(e: MouseEvent) {
  if (samples.length >= MAX) return;
  samples.push({ t: performance.now(), x: e.clientX, y: e.clientY, type: 'click', button: e.button });
}

export function startMouse(): void {
  if (attached) return;
  attached = true;
  window.addEventListener('mousemove', onMove, { passive: true });
  window.addEventListener('click', onClick, { passive: true, capture: true });
}

export function stopMouse(): void {
  if (!attached) return;
  attached = false;
  window.removeEventListener('mousemove', onMove);
  window.removeEventListener('click', onClick, { capture: true } as EventListenerOptions);
}

export function getMouseSamples(): MouseSample[] {
  return samples;
}