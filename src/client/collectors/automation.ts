import type { AutomationSnapshot } from '../../shared/types.js';

// Heuristics: each marker on its own is weak; the combination is the signal.
export function collectAutomation(): AutomationSnapshot {
  const n = navigator as Navigator & { webdriver?: boolean };
  // Bridge through `unknown`: `Window & typeof globalThis` has no string index
  // signature, so a direct assertion to `Record<string, unknown>` is rejected as
  // a non-overlapping cast (TS2352). We only use `w` to probe injected globals.
  const w = window as unknown as Window & Record<string, unknown>;
  const inconsistencies: string[] = [];
  const playwrightHints: string[] = [];
  const cdpHints: string[] = [];

  const webdriver = typeof n.webdriver === 'boolean' ? n.webdriver : null;

  const pluginsLength = n.plugins ? n.plugins.length : 0;
  const mimeTypesLength = n.mimeTypes ? n.mimeTypes.length : 0;
  // Names (not just the count): modern browsers freeze this to a fixed set of
  // PDF-viewer plugins, so the *list itself* is a signal — an empty list on a
  // Chrome UA, or an exotic name, stands out.
  const pluginNames = n.plugins ? Array.from(n.plugins, (p) => p.name).filter(Boolean) : [];
  const mimeTypeNames = n.mimeTypes ? Array.from(n.mimeTypes, (m) => m.type).filter(Boolean) : [];
  const chromeRuntime = typeof (w as { chrome?: { runtime?: unknown } }).chrome?.runtime !== 'undefined';
  const hasNotificationPermission =
    typeof Notification !== 'undefined' && Notification.permission === 'granted';

  // Headless Chrome historically has 0 plugins and 0 mime types AND no Notification.
  if (pluginsLength === 0 && mimeTypesLength === 0 && /Chrome/i.test(n.userAgent)) {
    inconsistencies.push('chrome-ua-zero-plugins');
  }
  if (n.userAgent.includes('HeadlessChrome')) {
    inconsistencies.push('headless-chrome-ua');
  }

  for (const key of Object.keys(w)) {
    if (/^(__playwright|playwright|__pw_|__webdriver_evaluate|__selenium_evaluate|__webdriver_script_function|__driver_unwrapped|__fxdriver_unwrapped|__driver_evaluate)/i.test(key)) {
      playwrightHints.push(key);
    }
    if (/^(cdc_|__nightmare|__phantomas|__phantom)/i.test(key)) {
      cdpHints.push(key);
    }
  }

  const callPhantom = typeof (w as { callPhantom?: unknown }).callPhantom !== 'undefined';
  const nightmare = typeof (w as { __nightmare?: unknown }).__nightmare !== 'undefined';
  const selenium =
    typeof (w as { _selenium?: unknown })._selenium !== 'undefined' ||
    typeof (document as Document & { __selenium_unwrapped?: unknown }).__selenium_unwrapped !== 'undefined';

  // CDP smell: error stack trace contains DevTools URL when getter is forced
  try {
    const err = new Error();
    const stack = err.stack ?? '';
    if (stack.includes('devtools://')) cdpHints.push('error-stack-devtools');
  } catch {
    // ignore
  }

  // Permission anomaly: notifications "denied" while document.hasFocus() is false
  // — typical of headless. We only note it, the user can correlate offline.
  if (typeof Notification !== 'undefined' && Notification.permission === 'denied' && !document.hasFocus()) {
    inconsistencies.push('notif-denied-no-focus');
  }

  return {
    webdriver,
    pluginsLength,
    mimeTypesLength,
    pluginNames,
    mimeTypeNames,
    chromeRuntime,
    hasNotificationPermission,
    inconsistencies,
    callPhantom,
    nightmare,
    selenium,
    playwrightHints,
    cdpHints,
  };
}
