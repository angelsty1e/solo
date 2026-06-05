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
