export interface ScrollSample {
  t: number;
  deltaY: number;
  deltaX: number;
  y: number;
}

const samples: ScrollSample[] = [];
let attached = false;
const MAX = 2000;

function onWheel(e: WheelEvent) {
  if (samples.length >= MAX) return;
  samples.push({ t: performance.now(), deltaY: e.deltaY, deltaX: e.deltaX, y: window.scrollY });
}

function onScroll() {
  if (samples.length >= MAX) return;
  samples.push({ t: performance.now(), deltaY: 0, deltaX: 0, y: window.scrollY });
}

export function startScroll(): void {
  if (attached) return;
  attached = true;
  window.addEventListener('wheel', onWheel, { passive: true });
  window.addEventListener('scroll', onScroll, { passive: true });
}

export function stopScroll(): void {
  if (!attached) return;
  attached = false;
  window.removeEventListener('wheel', onWheel);
  window.removeEventListener('scroll', onScroll);
}

export function getScrollSamples(): ScrollSample[] {
  return samples;
}
