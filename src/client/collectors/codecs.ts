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

import type { CodecsSnapshot } from '../../shared/types.js';

const VIDEO_CODECS = [
  'video/mp4; codecs="avc1.42E01E"',          // H.264 baseline
  'video/mp4; codecs="avc1.640028"',          // H.264 high
  'video/mp4; codecs="hev1.1.6.L93.B0"',      // HEVC/H.265
  'video/webm; codecs="vp8"',
  'video/webm; codecs="vp9"',
  'video/webm; codecs="vp09.00.10.08"',
  'video/mp4; codecs="av01.0.05M.08"',        // AV1
  'video/ogg; codecs="theora"',
];

const AUDIO_CODECS = [
  'audio/mp4; codecs="mp4a.40.2"',  // AAC LC
  'audio/mp4; codecs="mp4a.40.5"',  // HE-AAC
  'audio/ogg; codecs="vorbis"',
  'audio/ogg; codecs="opus"',
  'audio/webm; codecs="opus"',
  'audio/flac',
  'audio/wav; codecs="1"',
  'audio/aac',
];

const MSE_TYPES = [
  'video/mp4; codecs="avc1.42E01E"',
  'video/webm; codecs="vp9"',
  'audio/mp4; codecs="mp4a.40.2"',
  'audio/webm; codecs="opus"',
];

export function collectCodecs(): CodecsSnapshot {
  const video: Record<string, string> = {};
  const audio: Record<string, string> = {};
  const mediaSourceTypes: Record<string, boolean> = {};

  const v = document.createElement('video');
  for (const codec of VIDEO_CODECS) {
    video[codec] = v.canPlayType(codec) || 'no';
  }
  const a = document.createElement('audio');
  for (const codec of AUDIO_CODECS) {
    audio[codec] = a.canPlayType(codec) || 'no';
  }
  const MS = (window as Window & { MediaSource?: { isTypeSupported?: (t: string) => boolean } }).MediaSource;
  if (MS && typeof MS.isTypeSupported === 'function') {
    for (const t of MSE_TYPES) {
      try {
        mediaSourceTypes[t] = MS.isTypeSupported(t);
      } catch {
        mediaSourceTypes[t] = false;
      }
    }
  }
  return { video, audio, mediaSourceTypes };
}