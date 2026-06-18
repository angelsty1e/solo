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

import type { MediaDevicesSnapshot } from '../../shared/types.js';

async function sha256Hex(input: string): Promise<string> {
  const enc = new TextEncoder().encode(input);
  const buf = await crypto.subtle.digest('SHA-256', enc);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export async function collectMediaDevices(): Promise<MediaDevicesSnapshot> {
  const empty: MediaDevicesSnapshot = {
    available: false,
    audioInputCount: 0,
    audioOutputCount: 0,
    videoInputCount: 0,
    kinds: [],
    groupIdsHash: '',
  };
  if (!navigator.mediaDevices?.enumerateDevices) return empty;
  try {
    const devices = await navigator.mediaDevices.enumerateDevices();
    const kinds = devices.map((d) => d.kind);
    // Without `getUserMedia` permission, labels are blank but groupIds carry
    // signal — identical hardware groups appear under the same opaque id.
    const groups = devices.map((d) => d.groupId).filter(Boolean).sort();
    return {
      available: true,
      audioInputCount: kinds.filter((k) => k === 'audioinput').length,
      audioOutputCount: kinds.filter((k) => k === 'audiooutput').length,
      videoInputCount: kinds.filter((k) => k === 'videoinput').length,
      kinds,
      groupIdsHash: groups.length > 0 ? await sha256Hex(groups.join('|')) : '',
    };
  } catch {
    return empty;
  }
}