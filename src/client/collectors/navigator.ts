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

import type { NavigatorSnapshot } from '../../shared/types.js';

interface NavigatorUaData {
  brands?: Array<{ brand: string; version: string }>;
  mobile?: boolean;
  platform?: string;
  getHighEntropyValues?: (hints: string[]) => Promise<Record<string, unknown>>;
}

export async function collectNavigator(): Promise<NavigatorSnapshot> {
  const n = navigator as unknown as Navigator & {
    deviceMemory?: number;
    userAgentData?: NavigatorUaData;
    pdfViewerEnabled?: boolean;
  };

  let uaData: NavigatorSnapshot['uaData'] = null;
  if (n.userAgentData) {
    const base = n.userAgentData;
    let extra: Record<string, unknown> = {};
    if (typeof base.getHighEntropyValues === 'function') {
      try {
        extra = await base.getHighEntropyValues([
          'architecture',
          'bitness',
          'model',
          'platformVersion',
          'fullVersionList',
          'wow64',
        ]);
      } catch {
        extra = {};
      }
    }
    uaData = {
      brands: base.brands ?? [],
      mobile: Boolean(base.mobile),
      platform: base.platform ?? '',
      fullVersionList: (extra.fullVersionList as Array<{ brand: string; version: string }>) ?? undefined,
      architecture: (extra.architecture as string) ?? undefined,
      bitness: (extra.bitness as string) ?? undefined,
      model: (extra.model as string) ?? undefined,
      platformVersion: (extra.platformVersion as string) ?? undefined,
      wow64: (extra.wow64 as boolean) ?? undefined,
    };
  }

  return {
    userAgent: n.userAgent,
    appVersion: n.appVersion,
    platform: n.platform,
    vendor: n.vendor,
    product: n.product,
    language: n.language,
    languages: Array.isArray(n.languages) ? [...n.languages] : [],
    hardwareConcurrency: n.hardwareConcurrency ?? 0,
    deviceMemory: typeof n.deviceMemory === 'number' ? n.deviceMemory : null,
    doNotTrack: n.doNotTrack ?? null,
    maxTouchPoints: n.maxTouchPoints ?? 0,
    cookieEnabled: n.cookieEnabled,
    pdfViewerEnabled: typeof n.pdfViewerEnabled === 'boolean' ? n.pdfViewerEnabled : null,
    uaData,
  };
}