import type { SpeechSnapshot } from '../../shared/types.js';

async function sha256Hex(input: string): Promise<string> {
  const enc = new TextEncoder().encode(input);
  const buf = await crypto.subtle.digest('SHA-256', enc);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

// On Chrome the voice list is populated asynchronously; we wait for the
// `voiceschanged` event but never more than `timeoutMs`.
function getVoices(timeoutMs = 1500): Promise<SpeechSynthesisVoice[]> {
  if (typeof speechSynthesis === 'undefined') return Promise.resolve([]);
  const immediate = speechSynthesis.getVoices();
  if (immediate.length > 0) return Promise.resolve(immediate);
  return new Promise((resolve) => {
    let done = false;
    const onChange = (): void => {
      if (done) return;
      done = true;
      resolve(speechSynthesis.getVoices());
    };
    speechSynthesis.addEventListener('voiceschanged', onChange, { once: true });
    setTimeout(() => {
      if (done) return;
      done = true;
      resolve(speechSynthesis.getVoices());
    }, timeoutMs);
  });
}

export async function collectSpeech(): Promise<SpeechSnapshot> {
  if (typeof speechSynthesis === 'undefined') {
    return { available: false, voiceCount: 0, voices: [], voicesHash: '' };
  }
  try {
    const list = await getVoices();
    const voices = list.map((v) => ({
      name: v.name,
      lang: v.lang,
      localService: v.localService,
      default: v.default,
    }));
    const canonical = voices
      .map((v) => `${v.name}|${v.lang}|${v.localService ? 1 : 0}`)
      .sort()
      .join('\n');
    return {
      available: true,
      voiceCount: voices.length,
      voices,
      voicesHash: await sha256Hex(canonical),
    };
  } catch {
    return { available: false, voiceCount: 0, voices: [], voicesHash: '' };
  }
}
