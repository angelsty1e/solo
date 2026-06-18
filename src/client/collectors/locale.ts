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

import type { LocaleSnapshot } from '../../shared/types.js';

export function collectLocale(): LocaleSnapshot {
  const dtf = new Intl.DateTimeFormat();
  const nf = new Intl.NumberFormat();
  const opts = dtf.resolvedOptions();
  return {
    timezone: opts.timeZone,
    timezoneOffset: new Date().getTimezoneOffset(),
    dateFormat: dtf.format(new Date(2025, 0, 31, 14, 5)),
    numberFormat: nf.format(1234567.89),
    resolvedOptionsLocale: opts.locale,
    calendar: opts.calendar,
    numberingSystem: opts.numberingSystem,
  };
}