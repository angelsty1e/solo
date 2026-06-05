import type { EngineSnapshot } from '../../shared/types.js';

async function sha256Hex(input: string): Promise<string> {
  const enc = new TextEncoder().encode(input);
  const buf = await crypto.subtle.digest('SHA-256', enc);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// Math operations whose low-order bits diverge between V8 / SpiderMonkey /
// JavaScriptCore. The hash collapses many tiny ULP differences into one
// stable fingerprint per (engine, major version, OS) tuple.
function mathFingerprintString(): string {
  const samples = [
    Math.sin(1),
    Math.cos(1),
    Math.tan(1),
    Math.asin(0.5),
    Math.acos(0.5),
    Math.atan(0.5),
    Math.sinh(1),
    Math.cosh(1),
    Math.tanh(1),
    Math.exp(1),
    Math.log(2),
    Math.log1p(0.5),
    Math.expm1(1),
    Math.pow(Math.E, Math.PI),
    Math.atan2(1, 1),
    Math.hypot(3, 4),
    parseFloat('0.1') + parseFloat('0.2'),
  ];
  return samples.map((n) => n.toString()).join('|');
}

function detectEngine(stack: string): EngineSnapshot['detectedEngine'] {
  // V8: "Error\n    at <anonymous>:1:1"
  // SpiderMonkey: "@debugger eval code:1:1"
  // JSC: "global code@[native code]"
  if (/^\s*at\s/m.test(stack)) return 'v8';
  if (/@\S+:\d+:\d+/.test(stack)) return 'spidermonkey';
  if (/global code@/.test(stack) || /\[native code\]/.test(stack)) return 'javascriptcore';
  return 'unknown';
}

export async function collectEngine(): Promise<EngineSnapshot> {
  let stack = '';
  try {
    throw new Error('probe');
  } catch (e) {
    stack = (e as Error).stack ?? '';
  }
  // Keep the first 3 frames only — enough to identify the engine, short
  // enough to be stable across call sites.
  const errorStackFormat = stack.split('\n').slice(0, 3).join('\n');
  return {
    mathFingerprint: await sha256Hex(mathFingerprintString()),
    errorStackFormat,
    detectedEngine: detectEngine(stack),
  };
}
