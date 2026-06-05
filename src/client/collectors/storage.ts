import type { StorageSnapshot } from '../../shared/types.js';

export async function collectStorage(): Promise<StorageSnapshot> {
  const empty: StorageSnapshot = {
    available: false,
    quota: null,
    usage: null,
    persisted: null,
  };
  if (!navigator.storage?.estimate) return empty;
  try {
    const est = await navigator.storage.estimate();
    let persisted: boolean | null = null;
    if (navigator.storage.persisted) {
      try {
        persisted = await navigator.storage.persisted();
      } catch {
        persisted = null;
      }
    }
    return {
      available: true,
      quota: typeof est.quota === 'number' ? est.quota : null,
      usage: typeof est.usage === 'number' ? est.usage : null,
      persisted,
    };
  } catch {
    return empty;
  }
}
