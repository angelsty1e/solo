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

export interface ScrollSample {
  t: number;
  deltaY: number;
  deltaX: number;
  y: number;
}

const samples: ScrollSample[] = [];
let attached = false;
const MAX = 2000;

function onWheel(e: WheelEvent) {
  if (samples.length >= MAX) return;
  samples.push({ t: performance.now(), deltaY: e.deltaY, deltaX: e.deltaX, y: window.scrollY });
}

function onScroll() {
  if (samples.length >= MAX) return;
  samples.push({ t: performance.now(), deltaY: 0, deltaX: 0, y: window.scrollY });
}

export function startScroll(): void {
  if (attached) return;
  attached = true;
  window.addEventListener('wheel', onWheel, { passive: true });
  window.addEventListener('scroll', onScroll, { passive: true });
}

export function stopScroll(): void {
  if (!attached) return;
  attached = false;
  window.removeEventListener('wheel', onWheel);
  window.removeEventListener('scroll', onScroll);
}

export function getScrollSamples(): ScrollSample[] {
  return samples;
}