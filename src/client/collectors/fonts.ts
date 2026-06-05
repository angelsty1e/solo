import type { FontsSnapshot } from '../../shared/types.js';

const PROBE_FONTS = [
  'Arial', 'Arial Black', 'Arial Narrow', 'Arial Rounded MT Bold',
  'Bookman Old Style', 'Bradley Hand ITC', 'Calibri', 'Cambria',
  'Candara', 'Century', 'Century Gothic', 'Comic Sans MS',
  'Consolas', 'Courier', 'Courier New', 'Garamond', 'Geneva',
  'Georgia', 'Helvetica', 'Helvetica Neue', 'Impact', 'Lucida Console',
  'Lucida Sans Unicode', 'Microsoft Sans Serif', 'Monaco', 'Monotype Corsiva',
  'MS Gothic', 'MS PGothic', 'MS Reference Sans Serif', 'MS Sans Serif',
  'MS Serif', 'Palatino', 'Palatino Linotype', 'Segoe Print', 'Segoe Script',
  'Segoe UI', 'Segoe UI Light', 'Segoe UI Semibold', 'Symbol',
  'Tahoma', 'Times', 'Times New Roman', 'Trebuchet MS', 'Verdana',
  'Wingdings', 'Wingdings 2', 'Wingdings 3', 'SF Pro Text', 'SF Pro Display',
  'San Francisco', 'Menlo', 'Andale Mono', 'Apple Chancery', 'Big Caslon',
  'Brush Script MT', 'Chalkboard', 'Cochin', 'Copperplate', 'Didot',
  'Futura', 'Gill Sans', 'Herculanum', 'Hoefler Text', 'Optima',
  'Papyrus', 'Roboto', 'Roboto Mono', 'Ubuntu', 'Cantarell',
  'DejaVu Sans', 'Liberation Sans', 'Noto Sans', 'Noto Sans CJK',
  'PingFang SC', 'Hiragino Sans', 'Yu Gothic',
];

const BASELINE_FONTS = ['monospace', 'sans-serif', 'serif'] as const;
const TEST_STRING = 'mmmmmmmmmmlli';
const TEST_SIZE = '72px';

// queryLocalFonts can return thousands of families on a workstation, which would
// blow past the server's bodyLimit (→ confusing 413). Cap the list client-side:
// the first N sorted families are more than enough entropy for fingerprinting.
const MAX_FONTS = 400;

interface QueryLocalFontsApi {
  queryLocalFonts?: () => Promise<Array<{ family: string }>>;
}

export async function collectFonts(): Promise<FontsSnapshot> {
  const w = window as Window & QueryLocalFontsApi;
  if (typeof w.queryLocalFonts === 'function') {
    try {
      const list = await w.queryLocalFonts();
      const families = Array.from(new Set(list.map((f) => f.family)))
        .sort()
        .slice(0, MAX_FONTS);
      return { detectedFonts: families, detectionMethod: 'queryLocalFonts' };
    } catch {
      // permission denied, fall through
    }
  }

  const body = document.body;
  if (!body) return { detectedFonts: [], detectionMethod: 'unavailable' };

  const span = document.createElement('span');
  span.style.fontSize = TEST_SIZE;
  span.style.position = 'absolute';
  span.style.left = '-9999px';
  span.style.top = '-9999px';
  span.style.lineHeight = 'normal';
  span.textContent = TEST_STRING;

  const baselineSize: Record<string, { w: number; h: number }> = {};
  for (const base of BASELINE_FONTS) {
    span.style.fontFamily = base;
    body.appendChild(span);
    baselineSize[base] = { w: span.offsetWidth, h: span.offsetHeight };
    body.removeChild(span);
  }

  const detected: string[] = [];
  for (const font of PROBE_FONTS) {
    let isDifferent = false;
    for (const base of BASELINE_FONTS) {
      span.style.fontFamily = `"${font}", ${base}`;
      body.appendChild(span);
      const b = baselineSize[base];
      if (b && (span.offsetWidth !== b.w || span.offsetHeight !== b.h)) {
        isDifferent = true;
      }
      body.removeChild(span);
      if (isDifferent) break;
    }
    if (isDifferent) detected.push(font);
  }

  return { detectedFonts: detected, detectionMethod: 'measurement' };
}
