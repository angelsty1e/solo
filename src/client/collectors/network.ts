import type { NetworkInfoSnapshot } from '../../shared/types.js';

interface NetworkInformation {
  effectiveType?: string;
  downlink?: number;
  rtt?: number;
  saveData?: boolean;
  type?: string;
}

export function collectNetwork(): NetworkInfoSnapshot {
  const c = (navigator as Navigator & { connection?: NetworkInformation }).connection;
  if (!c) {
    return {
      available: false,
      effectiveType: null,
      downlink: null,
      rtt: null,
      saveData: null,
      type: null,
    };
  }
  return {
    available: true,
    effectiveType: c.effectiveType ?? null,
    downlink: c.downlink ?? null,
    rtt: c.rtt ?? null,
    saveData: c.saveData ?? null,
    type: c.type ?? null,
  };
}
