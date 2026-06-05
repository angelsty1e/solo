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
