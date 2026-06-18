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

import type { ClientFingerprint } from '../../shared/types.js';
import { collectNavigator } from './navigator.js';
import { collectScreen } from './screen.js';
import { collectLocale } from './locale.js';
import { collectCanvas } from './canvas.js';
import { collectWebgl } from './webgl.js';
import { collectAudio } from './audio.js';
import { collectFonts } from './fonts.js';
import { collectWebrtc } from './webrtc.js';
import { collectCodecs } from './codecs.js';
import { collectPermissions } from './permissions.js';
import { collectAutomation } from './automation.js';
import { collectSpeech } from './speech.js';
import { collectMediaDevices } from './mediaDevices.js';
import { collectMediaCapabilities } from './mediaCapabilities.js';
import { collectWebgpu } from './webgpu.js';
import { collectCssMedia } from './cssMedia.js';
import { collectIntl } from './intl.js';
import { collectEngine } from './engine.js';
import { collectNetwork } from './network.js';
import { collectStorage } from './storage.js';
import { collectPerfMemory } from './perfMemory.js';

export type StaticSnapshot = Omit<ClientFingerprint, 'sessionId' | 'collectedAt' | 'durationMs' | 'behavioral'>;

const COLLECTOR_TIMEOUT_MS = 5000;

// Bound every collector individually: a single one that hangs (or rejects)
// can no longer freeze the whole snapshot — it resolves to its fallback instead.
function withTimeout<T>(p: Promise<T>, fallback: T, ms = COLLECTOR_TIMEOUT_MS): Promise<T> {
  return new Promise<T>((resolve) => {
    let done = false;
    const settle = (v: T): void => {
      if (done) return;
      done = true;
      clearTimeout(timer);
      resolve(v);
    };
    const timer = setTimeout(() => settle(fallback), ms);
    p.then((v) => settle(v), () => settle(fallback));
  });
}

export async function collectAllStatic(): Promise<StaticSnapshot> {
  const [
    navigatorSnap,
    canvas,
    webgl,
    audio,
    fonts,
    webrtc,
    permissions,
    speech,
    mediaDevices,
    mediaCapabilities,
    webgpu,
    intl,
    engine,
    storage,
  ] = await Promise.all([
    collectNavigator(),
    withTimeout(collectCanvas(), null),
    withTimeout(collectWebgl(), null),
    withTimeout(collectAudio(), null),
    withTimeout(collectFonts(), null),
    withTimeout(collectWebrtc(), null),
    withTimeout(collectPermissions(), { states: {} }),
    withTimeout(collectSpeech(), null),
    withTimeout(collectMediaDevices(), null),
    withTimeout(collectMediaCapabilities(), null),
    withTimeout(collectWebgpu(), null),
    withTimeout(collectIntl(), null),
    withTimeout(collectEngine(), null),
    withTimeout(collectStorage(), null),
  ]);
  return {
    navigator: navigatorSnap,
    screen: collectScreen(),
    locale: collectLocale(),
    canvas,
    webgl,
    audio,
    fonts,
    webrtc,
    codecs: collectCodecs(),
    permissions,
    automation: collectAutomation(),
    speech,
    mediaDevices,
    mediaCapabilities,
    webgpu,
    cssMedia: collectCssMedia(),
    intl,
    engine,
    network: collectNetwork(),
    storage,
    perfMemory: collectPerfMemory(),
  };
}