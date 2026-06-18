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