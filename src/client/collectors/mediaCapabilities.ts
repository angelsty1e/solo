import type { MediaCapabilitiesSnapshot } from '../../shared/types.js';

// Probe a small matrix of common video configs. The interesting signal isn't
// `supported` (most browsers say yes) but `powerEfficient` — that flips when
// the codec hits hardware decode, which is a function of GPU + OS + drivers.
const PROBES: Array<{ key: string; contentType: string; width: number; height: number; bitrate: number; framerate: number }> = [
  { key: 'h264-1080p',  contentType: 'video/mp4; codecs="avc1.640028"',  width: 1920, height: 1080, bitrate: 5_000_000, framerate: 30 },
  { key: 'h264-4k',     contentType: 'video/mp4; codecs="avc1.640033"',  width: 3840, height: 2160, bitrate: 20_000_000, framerate: 30 },
  { key: 'hevc-1080p',  contentType: 'video/mp4; codecs="hev1.1.6.L120.B0"', width: 1920, height: 1080, bitrate: 5_000_000, framerate: 30 },
  { key: 'hevc-4k',     contentType: 'video/mp4; codecs="hev1.1.6.L150.B0"', width: 3840, height: 2160, bitrate: 20_000_000, framerate: 30 },
  { key: 'vp9-1080p',   contentType: 'video/webm; codecs="vp09.00.40.08"', width: 1920, height: 1080, bitrate: 5_000_000, framerate: 30 },
  { key: 'av1-1080p',   contentType: 'video/mp4; codecs="av01.0.08M.08"', width: 1920, height: 1080, bitrate: 5_000_000, framerate: 30 },
  { key: 'av1-4k',      contentType: 'video/mp4; codecs="av01.0.12M.08"', width: 3840, height: 2160, bitrate: 20_000_000, framerate: 30 },
];

export async function collectMediaCapabilities(): Promise<MediaCapabilitiesSnapshot> {
  const mc = (navigator as Navigator & { mediaCapabilities?: MediaCapabilities }).mediaCapabilities;
  if (!mc?.decodingInfo) {
    return { available: false, video: {} };
  }
  const video: MediaCapabilitiesSnapshot['video'] = {};
  await Promise.all(
    PROBES.map(async (p) => {
      try {
        const r = await mc.decodingInfo({
          type: 'file',
          video: {
            contentType: p.contentType,
            width: p.width,
            height: p.height,
            bitrate: p.bitrate,
            framerate: p.framerate,
          },
        });
        video[p.key] = {
          supported: r.supported,
          smooth: r.smooth,
          powerEfficient: r.powerEfficient,
        };
      } catch {
        video[p.key] = { supported: false, smooth: false, powerEfficient: false };
      }
    }),
  );
  return { available: true, video };
}
