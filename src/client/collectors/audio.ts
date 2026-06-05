import type { AudioSnapshot } from '../../shared/types.js';
import { sha256Hex } from '../session.js';

// Offline-render a known DSP graph and hash the resulting waveform.
// Different audio stacks (browser, OS) produce slightly different float values.
export async function collectAudio(): Promise<AudioSnapshot | null> {
  try {
    const OfflineCtx =
      (window as unknown as { OfflineAudioContext?: typeof OfflineAudioContext }).OfflineAudioContext ??
      (window as unknown as { webkitOfflineAudioContext?: typeof OfflineAudioContext }).webkitOfflineAudioContext;
    if (!OfflineCtx) return null;

    const sampleRate = 44100;
    const length = 5000;
    const ctx = new OfflineCtx(1, length, sampleRate);
    const osc = ctx.createOscillator();
    osc.type = 'triangle';
    osc.frequency.setValueAtTime(10000, ctx.currentTime);

    const compressor = ctx.createDynamicsCompressor();
    compressor.threshold.setValueAtTime(-50, ctx.currentTime);
    compressor.knee.setValueAtTime(40, ctx.currentTime);
    compressor.ratio.setValueAtTime(12, ctx.currentTime);
    compressor.attack.setValueAtTime(0, ctx.currentTime);
    compressor.release.setValueAtTime(0.25, ctx.currentTime);

    osc.connect(compressor);
    compressor.connect(ctx.destination);
    osc.start(0);
    const buffer = await ctx.startRendering();
    const data = buffer.getChannelData(0);

    let sum = 0;
    let parts = '';
    for (let i = 4500; i < 5000; i++) {
      const v = data[i] ?? 0;
      sum += Math.abs(v);
      parts += v.toFixed(7);
    }
    const oscillatorHash = await sha256Hex(parts + '|' + sum.toFixed(7));

    let baseLatency: number | null = null;
    let outputLatency: number | null = null;
    let state: string | null = null;
    let onlineSampleRate: number | null = null;
    try {
      const AudioCtx =
        (window as unknown as { AudioContext?: typeof AudioContext }).AudioContext ??
        (window as unknown as { webkitAudioContext?: typeof AudioContext }).webkitAudioContext;
      if (AudioCtx) {
        const live = new AudioCtx();
        baseLatency = (live as AudioContext & { baseLatency?: number }).baseLatency ?? null;
        outputLatency = (live as AudioContext & { outputLatency?: number }).outputLatency ?? null;
        onlineSampleRate = live.sampleRate;
        state = live.state;
        live.close().catch(() => {});
      }
    } catch {
      // ignore
    }

    return {
      oscillatorHash,
      baseLatency,
      sampleRate: onlineSampleRate,
      outputLatency,
      state,
    };
  } catch {
    return null;
  }
}
