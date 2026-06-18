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

import type { IntlSnapshot } from '../../shared/types.js';

async function sha256Hex(input: string): Promise<string> {
  const enc = new TextEncoder().encode(input);
  const buf = await crypto.subtle.digest('SHA-256', enc);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

interface IntlWithSupported {
  supportedValuesOf?: (key: string) => string[];
}

export async function collectIntl(): Promise<IntlSnapshot> {
  const I = (Intl as unknown) as IntlWithSupported;
  if (!I.supportedValuesOf) {
    return {
      timeZones: 0,
      calendars: 0,
      currencies: 0,
      numberingSystems: 0,
      collations: 0,
      supportedHash: '',
    };
  }
  const safe = (k: string): string[] => {
    try {
      return I.supportedValuesOf!(k);
    } catch {
      return [];
    }
  };
  const timeZones = safe('timeZone');
  const calendars = safe('calendar');
  const currencies = safe('currency');
  const numberingSystems = safe('numberingSystem');
  const collations = safe('collation');
  const canonical = [
    `tz:${timeZones.length}`,
    `cal:${calendars.join(',')}`,
    `cur:${currencies.length}`,
    `nu:${numberingSystems.join(',')}`,
    `co:${collations.join(',')}`,
  ].join('\n');
  return {
    timeZones: timeZones.length,
    calendars: calendars.length,
    currencies: currencies.length,
    numberingSystems: numberingSystems.length,
    collations: collations.length,
    supportedHash: await sha256Hex(canonical),
  };
}