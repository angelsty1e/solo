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