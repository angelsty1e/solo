import type { CanvasSnapshot } from '../../shared/types.js';
import { sha256Hex } from '../session.js';

// Canvas fingerprinting: paint a known scene, hash the pixels.
// Same scene yields different bytes per GPU/driver/font stack.
export async function collectCanvas(): Promise<CanvasSnapshot | null> {
  try {
    const canvas = document.createElement('canvas');
    canvas.width = 320;
    canvas.height = 80;
    const ctx = canvas.getContext('2d');
    if (!ctx) return null;

    ctx.textBaseline = 'top';
    ctx.font = "14px 'Arial'";
    ctx.fillStyle = '#f60';
    ctx.fillRect(125, 1, 62, 20);
    ctx.fillStyle = '#069';
    ctx.fillText('Sphinx of black quartz, judge my vow.', 2, 15);
    ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
    ctx.fillText('Sphinx of black quartz, judge my vow.', 4, 17);

    // Winding rule test (Chrome/Firefox/Safari differ here).
    ctx.globalCompositeOperation = 'multiply';
    ctx.fillStyle = 'rgb(255,0,255)';
    ctx.beginPath();
    ctx.arc(50, 50, 50, 0, Math.PI * 2, true);
    ctx.closePath();
    ctx.fill();
    ctx.fillStyle = 'rgb(0,255,255)';
    ctx.beginPath();
    ctx.arc(100, 50, 50, 0, Math.PI * 2, true);
    ctx.closePath();
    ctx.fill();

    const dataUrl = canvas.toDataURL();
    const dataUrlHash = await sha256Hex(dataUrl);

    const metrics = ctx.measureText('Solo fingerprint lab — 2025');
    const metricsStr = [
      metrics.width,
      metrics.actualBoundingBoxLeft,
      metrics.actualBoundingBoxRight,
      metrics.actualBoundingBoxAscent,
      metrics.actualBoundingBoxDescent,
      metrics.fontBoundingBoxAscent ?? '',
      metrics.fontBoundingBoxDescent ?? '',
    ].join('|');
    const textMetricsHash = await sha256Hex(metricsStr);

    // Winding detection (filling a square subpath both ways).
    ctx.fillStyle = '#000';
    ctx.beginPath();
    ctx.rect(0, 0, 10, 10);
    ctx.rect(2, 2, 6, 6);
    ctx.fill();
    const winding = ctx.isPointInPath(5, 5, 'evenodd') === false;

    return {
      dataUrlHash,
      textMetricsHash,
      winding,
      fillTextSupported: typeof ctx.fillText === 'function',
      toDataURLLength: dataUrl.length,
    };
  } catch {
    return null;
  }
}
