// Runtime validation for the only attacker-controlled input the server trusts:
// the `/collect` body. The TypeScript `ClientFingerprint` type is erased at
// runtime, so without this a client could send wrong types, missing fields or
// absurd numbers — skewing the decision engine, polluting the DB, or tripping
// `analyze()`. This schema mirrors `ClientFingerprint` in ./types.ts; keep the
// two in sync. Unknown *nested* keys are stripped (forward-compatible with new
// collector fields), but the top-level envelope is `.strict()` so a hostile
// client can't smuggle extra columns past us.
import { z } from 'zod';

// Generous bounds: wide enough for any real browser, tight enough to reject the
// absurd values a hostile client would use to skew scoring or bloat the DB.
const dim = z.number().min(0).max(100_000);
const count = z.number().min(0).max(1_000_000);
// Behavioural aggregates feed the decision engine's detect() thresholds. A bare
// z.number() accepts Infinity/NaN, which slip through and silently flip those
// conditions (e.g. meanCurvature=Infinity > 0 grants the liveness credit;
// linearRatio=Infinity >= 0.99 fires the synthetic-scroll signal). Bound them:
//   ratio  → a proportion, must be finite and within [0,1].
//   metric → a non-negative magnitude (speed, std, time…), must be finite.
//   signed → may be negative (scroll delta direction), must be finite.
const ratio = z.number().min(0).max(1);
const metric = z.number().finite().min(0);
const signed = z.number().finite();

const uaDataSchema = z
  .object({
    brands: z.array(z.object({ brand: z.string(), version: z.string() })),
    mobile: z.boolean(),
    platform: z.string(),
    fullVersionList: z.array(z.object({ brand: z.string(), version: z.string() })).optional(),
    architecture: z.string().optional(),
    bitness: z.string().optional(),
    model: z.string().optional(),
    platformVersion: z.string().optional(),
    wow64: z.boolean().optional(),
  })
  .nullable();

const navigatorSchema = z.object({
  userAgent: z.string(),
  appVersion: z.string(),
  platform: z.string(),
  vendor: z.string(),
  product: z.string(),
  language: z.string(),
  languages: z.array(z.string()),
  hardwareConcurrency: count,
  deviceMemory: z.number().min(0).max(1_048_576).nullable(),
  doNotTrack: z.string().nullable(),
  maxTouchPoints: count,
  cookieEnabled: z.boolean(),
  pdfViewerEnabled: z.boolean().nullable(),
  uaData: uaDataSchema,
});

const screenSchema = z.object({
  width: dim,
  height: dim,
  availWidth: dim,
  availHeight: dim,
  colorDepth: z.number().min(0).max(64),
  pixelDepth: z.number().min(0).max(64),
  devicePixelRatio: z.number().min(0).max(1000),
  orientation: z.string().nullable(),
  windowInnerWidth: dim,
  windowInnerHeight: dim,
  windowOuterWidth: dim,
  windowOuterHeight: dim,
});

const localeSchema = z.object({
  timezone: z.string(),
  timezoneOffset: z.number(),
  dateFormat: z.string(),
  numberFormat: z.string(),
  resolvedOptionsLocale: z.string(),
  calendar: z.string(),
  numberingSystem: z.string(),
});

const canvasSchema = z
  .object({
    dataUrlHash: z.string(),
    textMetricsHash: z.string(),
    winding: z.boolean(),
    fillTextSupported: z.boolean(),
    toDataURLLength: z.number(),
  })
  .nullable();

const webglSchema = z
  .object({
    vendor: z.string().nullable(),
    renderer: z.string().nullable(),
    unmaskedVendor: z.string().nullable(),
    unmaskedRenderer: z.string().nullable(),
    version: z.string().nullable(),
    shadingLanguageVersion: z.string().nullable(),
    extensions: z.array(z.string()),
    maxTextureSize: z.number().nullable(),
    parametersHash: z.string(),
  })
  .nullable();

const audioSchema = z
  .object({
    oscillatorHash: z.string(),
    baseLatency: z.number().nullable(),
    sampleRate: z.number().nullable(),
    outputLatency: z.number().nullable(),
    state: z.string().nullable(),
  })
  .nullable();

const fontsSchema = z
  .object({
    detectedFonts: z.array(z.string()),
    detectionMethod: z.enum(['measurement', 'queryLocalFonts', 'unavailable']),
  })
  .nullable();

const webrtcSchema = z
  .object({
    localIps: z.array(z.string()),
    publicIp: z.string().nullable(),
    candidates: z.array(z.string()),
    error: z.string().nullable(),
  })
  .nullable();

const codecsSchema = z.object({
  video: z.record(z.string()),
  audio: z.record(z.string()),
  mediaSourceTypes: z.record(z.boolean()),
});

const permissionsSchema = z.object({ states: z.record(z.string()) });

const automationSchema = z.object({
  webdriver: z.boolean().nullable(),
  pluginsLength: count,
  mimeTypesLength: count,
  pluginNames: z.array(z.string()),
  mimeTypeNames: z.array(z.string()),
  chromeRuntime: z.boolean(),
  hasNotificationPermission: z.boolean(),
  inconsistencies: z.array(z.string()),
  callPhantom: z.boolean(),
  nightmare: z.boolean(),
  selenium: z.boolean(),
  playwrightHints: z.array(z.string()),
  cdpHints: z.array(z.string()),
});

const speechSchema = z
  .object({
    available: z.boolean(),
    voiceCount: count,
    voices: z.array(
      z.object({
        name: z.string(),
        lang: z.string(),
        localService: z.boolean(),
        default: z.boolean(),
      }),
    ),
    voicesHash: z.string(),
  })
  .nullable();

const mediaDevicesSchema = z
  .object({
    available: z.boolean(),
    audioInputCount: count,
    audioOutputCount: count,
    videoInputCount: count,
    kinds: z.array(z.string()),
    groupIdsHash: z.string(),
  })
  .nullable();

const mediaCapabilitiesSchema = z
  .object({
    available: z.boolean(),
    video: z.record(
      z.object({ supported: z.boolean(), smooth: z.boolean(), powerEfficient: z.boolean() }),
    ),
  })
  .nullable();

const webgpuSchema = z
  .object({
    available: z.boolean(),
    adapter: z
      .object({
        vendor: z.string(),
        architecture: z.string(),
        device: z.string(),
        description: z.string(),
      })
      .nullable(),
    features: z.array(z.string()),
    limits: z.record(z.number()),
    limitsHash: z.string(),
  })
  .nullable();

const cssMediaSchema = z
  .object({
    prefersColorScheme: z.string(),
    prefersReducedMotion: z.string(),
    prefersContrast: z.string(),
    prefersReducedTransparency: z.string(),
    forcedColors: z.string(),
    invertedColors: z.string(),
    pointer: z.string(),
    hover: z.string(),
    anyPointer: z.string(),
    anyHover: z.string(),
    colorGamut: z.string(),
    dynamicRange: z.string(),
    supports: z.record(z.boolean()),
  })
  .nullable();

const intlSchema = z
  .object({
    timeZones: count,
    calendars: count,
    currencies: count,
    numberingSystems: count,
    collations: count,
    supportedHash: z.string(),
  })
  .nullable();

const engineSchema = z
  .object({
    mathFingerprint: z.string(),
    errorStackFormat: z.string(),
    detectedEngine: z.enum(['v8', 'spidermonkey', 'javascriptcore', 'unknown']),
  })
  .nullable();

const networkSchema = z
  .object({
    available: z.boolean(),
    effectiveType: z.string().nullable(),
    downlink: z.number().nullable(),
    rtt: z.number().nullable(),
    saveData: z.boolean().nullable(),
    type: z.string().nullable(),
  })
  .nullable();

const storageSchema = z
  .object({
    available: z.boolean(),
    quota: z.number().nullable(),
    usage: z.number().nullable(),
    persisted: z.boolean().nullable(),
  })
  .nullable();

const perfMemorySchema = z
  .object({
    available: z.boolean(),
    jsHeapSizeLimit: z.number().nullable(),
    totalJSHeapSize: z.number().nullable(),
    usedJSHeapSize: z.number().nullable(),
  })
  .nullable();

const behavioralSchema = z.object({
  totalEvents: count,
  // Background-tab throttling can legitimately inflate wall-clock elapsed well
  // past the 8s collection window, so bound generously (10 min) while still
  // rejecting negative / absurd values.
  durationMs: z.number().min(0).max(600_000),
  mouse: z.object({
    moves: count,
    clicks: count,
    meanSpeed: metric,
    stdSpeed: metric,
    meanCurvature: metric,
    stillRatio: ratio,
    jitterRatio: ratio,
  }),
  keyboard: z.object({
    keydowns: count,
    keyups: count,
    meanDwellMs: metric,
    stdDwellMs: metric,
    meanFlightMs: metric,
    stdFlightMs: metric,
    backspaceRatio: ratio,
  }),
  scroll: z.object({
    events: count,
    totalDeltaPx: signed,
    meanDeltaPx: signed,
    linearRatio: ratio,
  }),
  touch: z.object({
    starts: count,
    moves: count,
    ends: count,
    meanPressure: metric,
    multiTouchMax: count,
  }),
});

export const ClientFingerprintSchema = z
  .object({
    // Accepted but ignored: the route always overwrites it with a server-side
    // UUID, so we don't constrain its format here.
    sessionId: z.string(),
    collectedAt: z.string(),
    durationMs: z.number().min(0).max(600_000),
    navigator: navigatorSchema,
    screen: screenSchema,
    locale: localeSchema,
    canvas: canvasSchema,
    webgl: webglSchema,
    audio: audioSchema,
    fonts: fontsSchema,
    webrtc: webrtcSchema,
    codecs: codecsSchema,
    permissions: permissionsSchema,
    automation: automationSchema,
    speech: speechSchema,
    mediaDevices: mediaDevicesSchema,
    mediaCapabilities: mediaCapabilitiesSchema,
    webgpu: webgpuSchema,
    cssMedia: cssMediaSchema,
    intl: intlSchema,
    engine: engineSchema,
    network: networkSchema,
    storage: storageSchema,
    perfMemory: perfMemorySchema,
    behavioral: behavioralSchema,
  })
  .strict();

// The schema mirrors `ClientFingerprint` (./types.ts). The compile-time link is
// the `/collect` handler itself: it feeds `parse`d output into `upsertClient` /
// `analyze`, both typed `ClientFingerprint`, so any drift breaks `tsc` there.
export type ValidatedClientFingerprint = z.infer<typeof ClientFingerprintSchema>;
