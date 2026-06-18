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

import type { WebgpuSnapshot } from '../../shared/types.js';

async function sha256Hex(input: string): Promise<string> {
  const enc = new TextEncoder().encode(input);
  const buf = await crypto.subtle.digest('SHA-256', enc);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

interface GpuAdapterInfo {
  vendor: string;
  architecture: string;
  device: string;
  description: string;
}
interface GpuAdapter {
  features: { values(): IterableIterator<string> };
  limits: Record<string, number>;
  requestAdapterInfo?: () => Promise<GpuAdapterInfo>;
  info?: GpuAdapterInfo;
}
interface NavigatorGpu {
  requestAdapter: (opts?: { powerPreference?: string }) => Promise<GpuAdapter | null>;
}

export async function collectWebgpu(): Promise<WebgpuSnapshot> {
  const empty: WebgpuSnapshot = {
    available: false,
    adapter: null,
    features: [],
    limits: {},
    limitsHash: '',
  };
  const gpu = (navigator as Navigator & { gpu?: NavigatorGpu }).gpu;
  if (!gpu?.requestAdapter) return empty;
  try {
    const adapter = await gpu.requestAdapter();
    if (!adapter) return empty;

    let info: GpuAdapterInfo | null = null;
    if (adapter.info) {
      info = adapter.info;
    } else if (adapter.requestAdapterInfo) {
      info = await adapter.requestAdapterInfo();
    }

    const features = Array.from(adapter.features.values()).sort();
    const limits: Record<string, number> = {};
    for (const k in adapter.limits) {
      const v = adapter.limits[k];
      if (typeof v === 'number') limits[k] = v;
    }
    const canonical = JSON.stringify({ features, limits });
    return {
      available: true,
      adapter: info
        ? {
            vendor: info.vendor ?? '',
            architecture: info.architecture ?? '',
            device: info.device ?? '',
            description: info.description ?? '',
          }
        : null,
      features,
      limits,
      limitsHash: await sha256Hex(canonical),
    };
  } catch {
    return empty;
  }
}