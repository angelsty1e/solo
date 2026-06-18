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