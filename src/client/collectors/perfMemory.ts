import type { PerfMemorySnapshot } from '../../shared/types.js';

interface PerfMemory {
  jsHeapSizeLimit?: number;
  totalJSHeapSize?: number;
  usedJSHeapSize?: number;
}

export function collectPerfMemory(): PerfMemorySnapshot {
  const m = (performance as Performance & { memory?: PerfMemory }).memory;
  if (!m) {
    return {
      available: false,
      jsHeapSizeLimit: null,
      totalJSHeapSize: null,
      usedJSHeapSize: null,
    };
  }
  return {
    available: true,
    jsHeapSizeLimit: typeof m.jsHeapSizeLimit === 'number' ? m.jsHeapSizeLimit : null,
    totalJSHeapSize: typeof m.totalJSHeapSize === 'number' ? m.totalJSHeapSize : null,
    usedJSHeapSize: typeof m.usedJSHeapSize === 'number' ? m.usedJSHeapSize : null,
  };
}
