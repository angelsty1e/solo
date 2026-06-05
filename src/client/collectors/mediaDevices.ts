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
