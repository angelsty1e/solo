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

import type { SpeechSnapshot } from '../../shared/types.js';

async function sha256Hex(input: string): Promise<string> {
  const enc = new TextEncoder().encode(input);
  const buf = await crypto.subtle.digest('SHA-256', enc);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// On Chrome the voice list is populated asynchronously; we wait for the
// `voiceschanged` event but never more than `timeoutMs`.
function getVoices(timeoutMs = 1500): Promise<SpeechSynthesisVoice[]> {
  if (typeof speechSynthesis === 'undefined') return Promise.resolve([]);
  const immediate = speechSynthesis.getVoices();
  if (immediate.length > 0) return Promise.resolve(immediate);
  return new Promise((resolve) => {
    let done = false;
    const onChange = (): void => {
      if (done) return;
      done = true;
      resolve(speechSynthesis.getVoices());
    };
    speechSynthesis.addEventListener('voiceschanged', onChange, { once: true });
    setTimeout(() => {
      if (done) return;
      done = true;
      resolve(speechSynthesis.getVoices());
    }, timeoutMs);
  });
}

export async function collectSpeech(): Promise<SpeechSnapshot> {
  if (typeof speechSynthesis === 'undefined') {
    return { available: false, voiceCount: 0, voices: [], voicesHash: '' };
  }
  try {
    const list = await getVoices();
    const voices = list.map((v) => ({
      name: v.name,
      lang: v.lang,
      localService: v.localService,
      default: v.default,
    }));
    const canonical = voices
      .map((v) => `${v.name}|${v.lang}|${v.localService ? 1 : 0}`)
      .sort()
      .join('\n');
    return {
      available: true,
      voiceCount: voices.length,
      voices,
      voicesHash: await sha256Hex(canonical),
    };
  } catch {
    return { available: false, voiceCount: 0, voices: [], voicesHash: '' };
  }
}