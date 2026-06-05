export interface MouseSample {
  t: number;
  x: number;
  y: number;
  type: 'move' | 'click';
  button?: number;
}

const samples: MouseSample[] = [];
let attached = false;
const MAX = 5000;

function onMove(e: MouseEvent) {
  if (samples.length >= MAX) return;
  samples.push({ t: performance.now(), x: e.clientX, y: e.clientY, type: 'move' });
}

function onClick(e: MouseEvent) {
  if (samples.length >= MAX) return;
  samples.push({ t: performance.now(), x: e.clientX, y: e.clientY, type: 'click', button: e.button });
}

export function startMouse(): void {
  if (attached) return;
  attached = true;
  window.addEventListener('mousemove', onMove, { passive: true });
  window.addEventListener('click', onClick, { passive: true, capture: true });
}

export function stopMouse(): void {
  if (!attached) return;
  attached = false;
  window.removeEventListener('mousemove', onMove);
  window.removeEventListener('click', onClick, { capture: true } as EventListenerOptions);
}

export function getMouseSamples(): MouseSample[] {
  return samples;
}
