import type { WebRtcSnapshot } from '../../shared/types.js';

// Collect ICE candidates from a no-op PeerConnection. The host candidates
// reveal local IPs (or mDNS hostnames in privacy-protected browsers).
// Server-reflexive candidates would expose the public IP if STUN was configured.
export function collectWebrtc(): Promise<WebRtcSnapshot | null> {
  return new Promise((resolve) => {
    const RTCPC =
      (window as Window & { RTCPeerConnection?: typeof RTCPeerConnection }).RTCPeerConnection ??
      (window as Window & { webkitRTCPeerConnection?: typeof RTCPeerConnection }).webkitRTCPeerConnection;
    if (!RTCPC) {
      resolve(null);
      return;
    }

    let pc: RTCPeerConnection | null = null;
    const candidates: string[] = [];
    const localIps = new Set<string>();
    let publicIp: string | null = null;
    let error: string | null = null;

    try {
      pc = new RTCPC({ iceServers: [] });
    } catch (e) {
      resolve({ localIps: [], publicIp: null, candidates: [], error: (e as Error).message });
      return;
    }

    pc.createDataChannel('probe');

    pc.onicecandidate = (ev) => {
      if (!ev.candidate) return;
      const c = ev.candidate.candidate;
      candidates.push(c);
      const ipMatch = c.match(/(\d{1,3}(?:\.\d{1,3}){3}|[a-f0-9:]+:[a-f0-9:]+)/i);
      if (ipMatch) {
        if (c.includes('typ host')) {
          localIps.add(ipMatch[0]);
        } else if (c.includes('typ srflx')) {
          publicIp = ipMatch[0];
        }
      }
    };

    pc.createOffer()
      .then((offer) => pc!.setLocalDescription(offer))
      .catch((e) => {
        error = (e as Error).message;
      });

    setTimeout(() => {
      try {
        pc?.close();
      } catch {
        // ignore
      }
      resolve({
        localIps: Array.from(localIps),
        publicIp,
        candidates,
        error,
      });
    }, 2500);
  });
}
