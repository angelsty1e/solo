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

export interface KeyEvent {
  t: number;
  type: 'keydown' | 'keyup';
  // Physical key position (e.g. "KeyA", "Backspace") and timing only — we never
  // record `e.key`, so the actual characters typed are never captured or sent.
  code: string;
}

const events: KeyEvent[] = [];
let attached = false;
const MAX = 2000;

function onDown(e: KeyboardEvent) {
  if (events.length >= MAX) return;
  events.push({ t: performance.now(), type: 'keydown', code: e.code });
}

function onUp(e: KeyboardEvent) {
  if (events.length >= MAX) return;
  events.push({ t: performance.now(), type: 'keyup', code: e.code });
}

export function startKeyboard(): void {
  if (attached) return;
  attached = true;
  window.addEventListener('keydown', onDown, { passive: true });
  window.addEventListener('keyup', onUp, { passive: true });
}

export function stopKeyboard(): void {
  if (!attached) return;
  attached = false;
  window.removeEventListener('keydown', onDown);
  window.removeEventListener('keyup', onUp);
}

export function getKeyEvents(): KeyEvent[] {
  return events;
}