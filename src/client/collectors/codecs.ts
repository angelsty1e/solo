import type { CodecsSnapshot } from '../../shared/types.js';

const VIDEO_CODECS = [
  'video/mp4; codecs="avc1.42E01E"',          // H.264 baseline
  'video/mp4; codecs="avc1.640028"',          // H.264 high
  'video/mp4; codecs="hev1.1.6.L93.B0"',      // HEVC/H.265
  'video/webm; codecs="vp8"',
  'video/webm; codecs="vp9"',
  'video/webm; codecs="vp09.00.10.08"',
  'video/mp4; codecs="av01.0.05M.08"',        // AV1
  'video/ogg; codecs="theora"',
];

const AUDIO_CODECS = [
  'audio/mp4; codecs="mp4a.40.2"',  // AAC LC
  'audio/mp4; codecs="mp4a.40.5"',  // HE-AAC
  'audio/ogg; codecs="vorbis"',
  'audio/ogg; codecs="opus"',
  'audio/webm; codecs="opus"',
  'audio/flac',
  'audio/wav; codecs="1"',
  'audio/aac',
];

const MSE_TYPES = [
  'video/mp4; codecs="avc1.42E01E"',
  'video/webm; codecs="vp9"',
  'audio/mp4; codecs="mp4a.40.2"',
  'audio/webm; codecs="opus"',
];

export function collectCodecs(): CodecsSnapshot {
  const video: Record<string, string> = {};
  const audio: Record<string, string> = {};
  const mediaSourceTypes: Record<string, boolean> = {};

  const v = document.createElement('video');
  for (const codec of VIDEO_CODECS) {
    video[codec] = v.canPlayType(codec) || 'no';
  }
  const a = document.createElement('audio');
  for (const codec of AUDIO_CODECS) {
    audio[codec] = a.canPlayType(codec) || 'no';
  }
  const MS = (window as Window & { MediaSource?: { isTypeSupported?: (t: string) => boolean } }).MediaSource;
  if (MS && typeof MS.isTypeSupported === 'function') {
    for (const t of MSE_TYPES) {
      try {
        mediaSourceTypes[t] = MS.isTypeSupported(t);
      } catch {
        mediaSourceTypes[t] = false;
      }
    }
  }
  return { video, audio, mediaSourceTypes };
}
