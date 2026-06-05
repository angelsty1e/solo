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
