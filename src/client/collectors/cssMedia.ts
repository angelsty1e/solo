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

import type { CssMediaSnapshot } from '../../shared/types.js';

function mq(query: string): boolean {
  try {
    return window.matchMedia(query).matches;
  } catch {
    return false;
  }
}

function probe(values: string[], group: string): string {
  for (const v of values) {
    if (mq(`(${group}: ${v})`)) return v;
  }
  return 'unknown';
}

const SUPPORTS_PROBES = [
  'display: grid',
  'display: flex',
  'aspect-ratio: 1',
  'gap: 1rem',
  'container-type: inline-size',
  'has(*)',
  'color: color(display-p3 1 0 0)',
  'backdrop-filter: blur(1px)',
  'scrollbar-gutter: stable',
  'text-wrap: balance',
  'view-transition-name: x',
  'anchor-name: --x',
  'field-sizing: content',
];

export function collectCssMedia(): CssMediaSnapshot {
  const supports: Record<string, boolean> = {};
  for (const s of SUPPORTS_PROBES) {
    try {
      supports[s] = CSS.supports(s);
    } catch {
      supports[s] = false;
    }
  }
  return {
    prefersColorScheme: probe(['dark', 'light', 'no-preference'], 'prefers-color-scheme'),
    prefersReducedMotion: probe(['reduce', 'no-preference'], 'prefers-reduced-motion'),
    prefersContrast: probe(['more', 'less', 'custom', 'no-preference'], 'prefers-contrast'),
    prefersReducedTransparency: probe(['reduce', 'no-preference'], 'prefers-reduced-transparency'),
    forcedColors: probe(['active', 'none'], 'forced-colors'),
    invertedColors: probe(['inverted', 'none'], 'inverted-colors'),
    pointer: probe(['fine', 'coarse', 'none'], 'pointer'),
    hover: probe(['hover', 'none'], 'hover'),
    anyPointer: probe(['fine', 'coarse', 'none'], 'any-pointer'),
    anyHover: probe(['hover', 'none'], 'any-hover'),
    colorGamut: probe(['rec2020', 'p3', 'srgb'], 'color-gamut'),
    dynamicRange: probe(['high', 'standard'], 'dynamic-range'),
    supports,
  };
}