/*
 * Copyright 2026 angelsty1e
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { createHash } from 'node:crypto';
import { isGrease, type ParsedClientHello } from './clienthello.js';

// JA3 = MD5(version,ciphers,extensions,curves,ec_point_formats)
// Each field uses decimal numbers, comma-separated for the field,
// dash-separated inside the field. GREASE values are stripped.

function filterGrease(values: number[]): number[] {
  return values.filter((v) => !isGrease(v));
}

export interface Ja3Result {
  ja3: string;
  ja3Hash: string;
}

export function computeJa3(parsed: ParsedClientHello): Ja3Result {
  const version = parsed.legacyVersion;
  const ciphers = filterGrease(parsed.cipherSuites).join('-');
  const extensions = filterGrease(parsed.extensionTypes).join('-');
  const curves = filterGrease(parsed.ellipticCurves).join('-');
  const points = parsed.ecPointFormats.join('-');

  const ja3 = `${version},${ciphers},${extensions},${curves},${points}`;
  const ja3Hash = createHash('md5').update(ja3).digest('hex');
  return { ja3, ja3Hash };
}