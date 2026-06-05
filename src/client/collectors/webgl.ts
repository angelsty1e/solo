import type { WebglSnapshot } from '../../shared/types.js';
import { sha256Hex } from '../session.js';

const PARAMS_TO_QUERY: Array<keyof WebGLRenderingContext | number> = [
  0x1f00, // VENDOR
  0x1f01, // RENDERER
  0x1f02, // VERSION
  0x8b8c, // SHADING_LANGUAGE_VERSION
  0x0d33, // MAX_TEXTURE_SIZE
  0x851c, // MAX_RENDERBUFFER_SIZE
  0x8869, // MAX_VERTEX_ATTRIBS
  0x8dfb, // MAX_FRAGMENT_UNIFORM_VECTORS
  0x8dfc, // MAX_VARYING_VECTORS
  0x8dfa, // MAX_VERTEX_UNIFORM_VECTORS
  0x84e2, // MAX_TEXTURE_IMAGE_UNITS
  0x8b4d, // MAX_VERTEX_TEXTURE_IMAGE_UNITS
  0x8b4c, // MAX_COMBINED_TEXTURE_IMAGE_UNITS
];

export async function collectWebgl(): Promise<WebglSnapshot | null> {
  try {
    const canvas = document.createElement('canvas');
    const gl = (canvas.getContext('webgl') ?? canvas.getContext('experimental-webgl')) as WebGLRenderingContext | null;
    if (!gl) return null;

    const vendor = String(gl.getParameter(gl.VENDOR));
    const renderer = String(gl.getParameter(gl.RENDERER));
    const version = String(gl.getParameter(gl.VERSION));
    const shadingLanguageVersion = String(gl.getParameter(gl.SHADING_LANGUAGE_VERSION));

    let unmaskedVendor: string | null = null;
    let unmaskedRenderer: string | null = null;
    const debug = gl.getExtension('WEBGL_debug_renderer_info');
    if (debug) {
      unmaskedVendor = String(gl.getParameter(debug.UNMASKED_VENDOR_WEBGL));
      unmaskedRenderer = String(gl.getParameter(debug.UNMASKED_RENDERER_WEBGL));
    }

    const extensions = gl.getSupportedExtensions() ?? [];

    const paramValues: string[] = [];
    for (const p of PARAMS_TO_QUERY) {
      try {
        const v = gl.getParameter(p as number);
        paramValues.push(String(v));
      } catch {
        paramValues.push('');
      }
    }
    const parametersHash = await sha256Hex(paramValues.join('|') + '||' + extensions.slice().sort().join(','));

    const maxTextureSize = Number(gl.getParameter(gl.MAX_TEXTURE_SIZE)) || null;

    return {
      vendor,
      renderer,
      unmaskedVendor,
      unmaskedRenderer,
      version,
      shadingLanguageVersion,
      extensions,
      maxTextureSize,
      parametersHash,
    };
  } catch {
    return null;
  }
}
