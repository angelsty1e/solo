// Shared types between client and server.

// Type-only import — erased at compile time, so the circular reference with
// decision/types.ts (which imports AutomationSnapshot from here) is harmless.
import type { DecisionResult } from './decision/types.js';

export interface TlsFingerprint {
  version: number;
  versionName: string;
  ciphers: number[];
  extensions: number[];
  ellipticCurves: number[];
  ecPointFormats: number[];
  signatureAlgorithms: number[];
  alpn: string[];
  sni: string | null;
  supportedVersions: number[];
  ja3: string;
  ja3Hash: string;
  ja4: string;
}

export interface SecFetchHeaders {
  site: string | null;
  mode: string | null;
  dest: string | null;
  user: string | null;
}

export interface HttpFingerprint {
  method: string;
  path: string;
  httpVersion: string;
  rawHeaders: string[];
  headerOrder: string[];
  userAgent: string | null;
  clientHints: Record<string, string>;
  accept: string | null;
  acceptLanguage: string | null;
  acceptEncoding: string | null;
  secFetch: SecFetchHeaders;
  inconsistencies: string[];
}

export interface IpFingerprint {
  ip: string;
  asn: number | null;
  asnOrganization: string | null;
  country: string | null;
  isDatacenter: boolean | null;
  // null = unknown (GeoIP down / ASN unresolved), NOT "definitely not a proxy".
  // trust_residential_ip only credits a *positively* residential IP (datacenter
  // and proxy both === false), never an unresolved one — see trust.ts.
  isProxyHint: boolean | null;
  reverseDns: string | null;
  isTorExit: boolean | null;
  tcpRttMs: number | null;
}

export interface ServerFingerprint {
  capturedAt: string;
  tls: TlsFingerprint | null;
  http: HttpFingerprint | null;
  ip: IpFingerprint | null;
}

export interface NavigatorSnapshot {
  userAgent: string;
  appVersion: string;
  platform: string;
  vendor: string;
  product: string;
  language: string;
  languages: string[];
  hardwareConcurrency: number;
  deviceMemory: number | null;
  doNotTrack: string | null;
  maxTouchPoints: number;
  cookieEnabled: boolean;
  pdfViewerEnabled: boolean | null;
  uaData: {
    brands: Array<{ brand: string; version: string }>;
    mobile: boolean;
    platform: string;
    fullVersionList?: Array<{ brand: string; version: string }>;
    architecture?: string;
    bitness?: string;
    model?: string;
    platformVersion?: string;
    wow64?: boolean;
  } | null;
}

export interface ScreenSnapshot {
  width: number;
  height: number;
  availWidth: number;
  availHeight: number;
  colorDepth: number;
  pixelDepth: number;
  devicePixelRatio: number;
  orientation: string | null;
  windowInnerWidth: number;
  windowInnerHeight: number;
  windowOuterWidth: number;
  windowOuterHeight: number;
}

export interface LocaleSnapshot {
  timezone: string;
  timezoneOffset: number;
  dateFormat: string;
  numberFormat: string;
  resolvedOptionsLocale: string;
  calendar: string;
  numberingSystem: string;
}

export interface CanvasSnapshot {
  dataUrlHash: string;
  textMetricsHash: string;
  winding: boolean;
  fillTextSupported: boolean;
  toDataURLLength: number;
}

export interface WebglSnapshot {
  vendor: string | null;
  renderer: string | null;
  unmaskedVendor: string | null;
  unmaskedRenderer: string | null;
  version: string | null;
  shadingLanguageVersion: string | null;
  extensions: string[];
  maxTextureSize: number | null;
  parametersHash: string;
}

export interface AudioSnapshot {
  oscillatorHash: string;
  baseLatency: number | null;
  sampleRate: number | null;
  outputLatency: number | null;
  state: string | null;
}

export interface FontsSnapshot {
  detectedFonts: string[];
  detectionMethod: 'measurement' | 'queryLocalFonts' | 'unavailable';
}

export interface WebRtcSnapshot {
  localIps: string[];
  publicIp: string | null;
  candidates: string[];
  error: string | null;
}

export interface CodecsSnapshot {
  video: Record<string, string>;
  audio: Record<string, string>;
  mediaSourceTypes: Record<string, boolean>;
}

export interface PermissionsSnapshot {
  states: Record<string, string>;
}

export interface AutomationSnapshot {
  webdriver: boolean | null;
  pluginsLength: number;
  mimeTypesLength: number;
  pluginNames: string[];
  mimeTypeNames: string[];
  chromeRuntime: boolean;
  hasNotificationPermission: boolean;
  inconsistencies: string[];
  callPhantom: boolean;
  nightmare: boolean;
  selenium: boolean;
  playwrightHints: string[];
  cdpHints: string[];
}

// ─── Sprint 2 additions ────────────────────────────────────────────────────

export interface SpeechSnapshot {
  available: boolean;
  voiceCount: number;
  voices: Array<{ name: string; lang: string; localService: boolean; default: boolean }>;
  voicesHash: string;
}

export interface MediaDevicesSnapshot {
  available: boolean;
  audioInputCount: number;
  audioOutputCount: number;
  videoInputCount: number;
  // Without `getUserMedia` permission, labels are empty strings. We keep the
  // shape (kind + non-empty deviceId/groupId) for fingerprinting.
  kinds: string[];
  groupIdsHash: string;
}

export interface MediaCapabilitiesSnapshot {
  available: boolean;
  // For each codec config, whether it's smooth + powerEfficient (HW accel).
  video: Record<string, { supported: boolean; smooth: boolean; powerEfficient: boolean }>;
}

export interface WebgpuSnapshot {
  available: boolean;
  adapter: {
    vendor: string;
    architecture: string;
    device: string;
    description: string;
  } | null;
  features: string[];
  limits: Record<string, number>;
  limitsHash: string;
}

export interface CssMediaSnapshot {
  prefersColorScheme: string;
  prefersReducedMotion: string;
  prefersContrast: string;
  prefersReducedTransparency: string;
  forcedColors: string;
  invertedColors: string;
  pointer: string;
  hover: string;
  anyPointer: string;
  anyHover: string;
  colorGamut: string;
  dynamicRange: string;
  // Set of `@supports` features (subset of common modern CSS).
  supports: Record<string, boolean>;
}

export interface IntlSnapshot {
  timeZones: number;
  calendars: number;
  currencies: number;
  numberingSystems: number;
  collations: number;
  supportedHash: string;
}

export interface EngineSnapshot {
  // Quirks that vary by JS engine / version.
  mathFingerprint: string;
  errorStackFormat: string;
  // V8 has Math.sin(1) precision differences across major versions.
  // We just record the hash so we can diff across browsers.
  detectedEngine: 'v8' | 'spidermonkey' | 'javascriptcore' | 'unknown';
}

export interface NetworkInfoSnapshot {
  available: boolean;
  effectiveType: string | null;
  downlink: number | null;
  rtt: number | null;
  saveData: boolean | null;
  type: string | null;
}

export interface StorageSnapshot {
  available: boolean;
  quota: number | null;
  usage: number | null;
  persisted: boolean | null;
}

export interface PerfMemorySnapshot {
  available: boolean;
  jsHeapSizeLimit: number | null;
  totalJSHeapSize: number | null;
  usedJSHeapSize: number | null;
}

// ─── End sprint 2 additions ────────────────────────────────────────────────

export interface ClientFingerprint {
  sessionId: string;
  collectedAt: string;
  durationMs: number;
  navigator: NavigatorSnapshot;
  screen: ScreenSnapshot;
  locale: LocaleSnapshot;
  canvas: CanvasSnapshot | null;
  webgl: WebglSnapshot | null;
  audio: AudioSnapshot | null;
  fonts: FontsSnapshot | null;
  webrtc: WebRtcSnapshot | null;
  codecs: CodecsSnapshot;
  permissions: PermissionsSnapshot;
  automation: AutomationSnapshot;
  speech: SpeechSnapshot | null;
  mediaDevices: MediaDevicesSnapshot | null;
  mediaCapabilities: MediaCapabilitiesSnapshot | null;
  webgpu: WebgpuSnapshot | null;
  cssMedia: CssMediaSnapshot | null;
  intl: IntlSnapshot | null;
  engine: EngineSnapshot | null;
  network: NetworkInfoSnapshot | null;
  storage: StorageSnapshot | null;
  perfMemory: PerfMemorySnapshot | null;
  behavioral: BehavioralSnapshot;
}

export interface BehavioralSnapshot {
  totalEvents: number;
  durationMs: number;
  mouse: MouseAggregate;
  keyboard: KeyboardAggregate;
  scroll: ScrollAggregate;
  touch: TouchAggregate;
}

export interface MouseAggregate {
  moves: number;
  clicks: number;
  meanSpeed: number;
  stdSpeed: number;
  meanCurvature: number;
  stillRatio: number;
  jitterRatio: number;
}

export interface KeyboardAggregate {
  keydowns: number;
  keyups: number;
  meanDwellMs: number;
  stdDwellMs: number;
  meanFlightMs: number;
  stdFlightMs: number;
  backspaceRatio: number;
}

export interface ScrollAggregate {
  events: number;
  totalDeltaPx: number;
  meanDeltaPx: number;
  linearRatio: number;
}

export interface TouchAggregate {
  starts: number;
  moves: number;
  ends: number;
  meanPressure: number;
  multiTouchMax: number;
}

export interface FullFingerprint {
  sessionId: string;
  server: ServerFingerprint;
  client: ClientFingerprint;
  // Verdict of the decision engine, computed server-side at /collect time.
  // Optional: absent for sessions stored before the engine existed.
  decision?: DecisionResult | null;
}
