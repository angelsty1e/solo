import type { ScreenSnapshot } from '../../shared/types.js';

export function collectScreen(): ScreenSnapshot {
  const s = window.screen;
  return {
    width: s.width,
    height: s.height,
    availWidth: s.availWidth,
    availHeight: s.availHeight,
    colorDepth: s.colorDepth,
    pixelDepth: s.pixelDepth,
    devicePixelRatio: window.devicePixelRatio,
    orientation: s.orientation ? s.orientation.type : null,
    windowInnerWidth: window.innerWidth,
    windowInnerHeight: window.innerHeight,
    windowOuterWidth: window.outerWidth,
    windowOuterHeight: window.outerHeight,
  };
}
