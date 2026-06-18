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
import { createReadStream } from 'node:fs';

// Stream-hash a file (SHA-256, hex). Streaming avoids loading a multi-MB .mmdb
// fully into a JS Buffer just to checksum it.
export function sha256File(path: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const h = createHash('sha256');
    createReadStream(path)
      .on('data', (chunk) => h.update(chunk))
      .on('error', reject)
      .on('end', () => resolve(h.digest('hex')));
  });
}

// Verify a file against an expected SHA-256. Opt-in: when no expected hash is
// configured we return true (skip). When one is given and doesn't match, we
// fail closed so a tampered/corrupt DB is never loaded.
export async function verifyFileSha256(path: string, expected: string | undefined): Promise<boolean> {
  const want = expected?.trim().toLowerCase();
  if (!want) return true;
  const got = (await sha256File(path)).toLowerCase();
  return got === want;
}