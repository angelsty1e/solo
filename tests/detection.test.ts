import { describe, it, expect } from 'vitest';
import {
  SOFTWARE_GPU,
  uaOs,
  uaBrowser,
  isMobileUa,
  isChromium,
  isChromiumUa,
  expectedEngine,
  platformMatchesOs,
  platformMatchesUa,
  isRealBrowserUa,
  isGenuineChromeUa,
  baseLang,
  parseSecChUaBrands,
  isGreaseBrand,
  normalizedBrandSet,
} from '../src/shared/decision/detection.js';

// ─── Helpers de détection — source de vérité unique (UA / plateforme / brands) ─
// Fonctions pures, déjà exercées indirectement par N1–N3. Ces tests les figent en
// ISOLATION et verrouillent les cas d'ordre piégeux (Android avant Linux, iOS
// avant Mac, Edge/Opera avant Chrome) et le filtrage GREASE des brands.

const UA = {
  chrome: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
  edge: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0',
  opera: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 OPR/110.0.0.0',
  firefox: 'Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0',
  safariMac: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
  android: 'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36',
  ios: 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
  headless: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/124.0.0.0 Safari/537.36',
  curl: 'curl/8.4.0',
};

describe('uaOs — Android avant Linux, iOS avant Mac', () => {
  it.each([
    [UA.chrome, 'windows'],
    [UA.android, 'android'], // contient "Linux" mais Android prime
    [UA.ios, 'ios'], // contient "Mac OS X" mais iPhone prime
    [UA.safariMac, 'mac'],
    [UA.firefox, 'linux'],
  ])('%s → %s', (ua, os) => {
    expect(uaOs(ua)).toBe(os);
  });

  it('UA inconnu → null', () => {
    expect(uaOs('SomeRandomBot/1.0')).toBeNull();
  });
});

describe('uaBrowser — Edge/Opera avant Chrome, Safari exige Version/', () => {
  it.each([
    [UA.edge, 'edge'], // porte le token "Chrome" mais Edg/ prime
    [UA.opera, 'opera'], // idem via OPR/
    [UA.firefox, 'firefox'],
    [UA.chrome, 'chrome'],
    [UA.safariMac, 'safari'],
    [UA.ios, 'safari'],
  ])('%s → %s', (ua, b) => {
    expect(uaBrowser(ua)).toBe(b);
  });

  it('UA non navigateur → null', () => {
    expect(uaBrowser(UA.curl)).toBeNull();
  });
});

describe('isMobileUa / isChromium / expectedEngine', () => {
  it('isMobileUa', () => {
    expect(isMobileUa(UA.android)).toBe(true);
    expect(isMobileUa(UA.ios)).toBe(true);
    expect(isMobileUa(UA.chrome)).toBe(false);
  });

  it('isChromium : chrome/edge/opera oui, firefox/safari non', () => {
    expect(isChromium('chrome')).toBe(true);
    expect(isChromium('edge')).toBe(true);
    expect(isChromium('opera')).toBe(true);
    expect(isChromium('firefox')).toBe(false);
    expect(isChromium('safari')).toBe(false);
    expect(isChromium(null)).toBe(false);
  });

  it('isChromiumUa via le UA', () => {
    expect(isChromiumUa(UA.edge)).toBe(true);
    expect(isChromiumUa(UA.firefox)).toBe(false);
  });

  it('expectedEngine : moteur attendu par famille', () => {
    expect(expectedEngine('chrome')).toBe('v8');
    expect(expectedEngine('edge')).toBe('v8');
    expect(expectedEngine('opera')).toBe('v8');
    expect(expectedEngine('firefox')).toBe('spidermonkey');
    expect(expectedEngine('safari')).toBe('javascriptcore');
    expect(expectedEngine(null)).toBeNull();
  });
});

describe('platformMatchesOs / platformMatchesUa', () => {
  it.each([
    ['Win32', 'windows', true],
    ['MacIntel', 'mac', true],
    ['Linux x86_64', 'linux', true],
    ['iPhone', 'ios', true],
    ['Linux armv8l', 'android', true],
    ['Win32', 'mac', false],
    ['MacIntel', 'windows', false],
  ] as const)('platformMatchesOs(%s, %s) → %s', (p, os, ok) => {
    expect(platformMatchesOs(p, os)).toBe(ok);
  });

  it('platformMatchesUa croise plateforme et OS du UA', () => {
    expect(platformMatchesUa('Win32', UA.chrome)).toBe(true);
    expect(platformMatchesUa('MacIntel', UA.chrome)).toBe(false); // UA windows
    expect(platformMatchesUa('MacIntel', UA.safariMac)).toBe(true);
  });
});

describe('isRealBrowserUa — navigateur revendiqué, ni outil ni headless', () => {
  it('vrai navigateur → true', () => {
    expect(isRealBrowserUa(UA.chrome)).toBe(true);
    expect(isRealBrowserUa(UA.safariMac)).toBe(true);
  });

  it('outil / headless / vide → false', () => {
    expect(isRealBrowserUa(UA.headless)).toBe(false); // token Headless
    expect(isRealBrowserUa(UA.curl)).toBe(false);
    expect(isRealBrowserUa('python-requests/2.31')).toBe(false);
    expect(isRealBrowserUa('')).toBe(false);
  });
});

describe('isGenuineChromeUa — exclut Edge/Opera/HeadlessChrome', () => {
  it.each([
    [UA.chrome, true],
    [UA.edge, false],
    [UA.opera, false],
    [UA.headless, false],
    [UA.firefox, false],
  ])('%s → %s', (ua, ok) => {
    expect(isGenuineChromeUa(ua)).toBe(ok);
  });
});

describe('baseLang', () => {
  it.each([
    ['fr-FR', 'fr'],
    ['EN-us', 'en'],
    ['  de-DE  ', 'de'],
    ['pt', 'pt'],
    ['', ''],
  ])('%s → %s', (tag, base) => {
    expect(baseLang(tag)).toBe(base);
  });
});

describe('parseSecChUaBrands / isGreaseBrand / normalizedBrandSet', () => {
  it('parseSecChUaBrands extrait les noms de marque dans l’ordre wire', () => {
    expect(parseSecChUaBrands('"Chromium";v="124", "Google Chrome";v="124", "Not A;Brand";v="99"')).toEqual([
      'Chromium',
      'Google Chrome',
      'Not A;Brand',
    ]);
  });

  it('parseSecChUaBrands sur un header vide → []', () => {
    expect(parseSecChUaBrands('')).toEqual([]);
  });

  it('isGreaseBrand reconnaît les placeholders GREASE', () => {
    expect(isGreaseBrand('Not A;Brand')).toBe(true);
    expect(isGreaseBrand('Not.A/Brand')).toBe(true);
    expect(isGreaseBrand('Chromium')).toBe(false);
    expect(isGreaseBrand('Google Chrome')).toBe(false);
  });

  it('normalizedBrandSet : minuscule, filtre GREASE, trié', () => {
    expect(normalizedBrandSet(['Google Chrome', 'Chromium', 'Not A;Brand'])).toEqual(['chromium', 'google chrome']);
  });

  it('normalizedBrandSet ne garde que les marques réelles même tout en GREASE', () => {
    expect(normalizedBrandSet(['Not A;Brand', 'Not.A/Brand'])).toEqual([]);
  });
});

describe('SOFTWARE_GPU — renderers émulés / VM', () => {
  it.each(['SwiftShader', 'llvmpipe', 'Mesa OffScreen', 'Microsoft Basic Render Driver', 'VMware SVGA 3D', 'QEMU'])(
    '%s → détecté logiciel',
    (r) => {
      expect(SOFTWARE_GPU.test(r)).toBe(true);
    },
  );

  it.each(['ANGLE (NVIDIA GeForce RTX 3060 Direct3D11)', 'Apple M2', 'AMD Radeon Pro 5500M'])(
    '%s → GPU matériel (non détecté)',
    (r) => {
      expect(SOFTWARE_GPU.test(r)).toBe(false);
    },
  );
});
