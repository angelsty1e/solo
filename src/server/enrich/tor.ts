import fs from 'node:fs';
import net from 'node:net';
import readline from 'node:readline';

// Tor exit list: one IPv4/IPv6 per line. The user is expected to refresh
// this from https://check.torproject.org/torbulkexitlist on a schedule
// (cron / systemd timer). We stream it line-by-line at startup so a huge (or
// malicious) file never has to be loaded into memory all at once, and only
// well-formed IP literals are kept.
const exits = new Set<string>();
let loadAttempted = false;
let listPath = '';
let count = 0;
let mtime: string | null = null;

export async function initTorList(path: string): Promise<boolean> {
  listPath = path;
  loadAttempted = true;
  exits.clear();
  if (!fs.existsSync(path)) {
    count = 0;
    mtime = null;
    return false;
  }
  const rl = readline.createInterface({
    input: fs.createReadStream(path, { encoding: 'utf8' }),
    crlfDelay: Infinity,
  });
  for await (const line of rl) {
    const ip = line.trim();
    if (!ip || ip.startsWith('#')) continue;
    // Reject anything that isn't a valid IPv4/IPv6 literal — keeps junk /
    // hostile lines out of the lookup set.
    if (net.isIP(ip) !== 0) exits.add(ip);
  }
  count = exits.size;
  mtime = fs.statSync(path).mtime.toISOString();
  return true;
}

export function isTorExit(ip: string): boolean | null {
  if (!loadAttempted) return null;
  if (exits.size === 0) return null;
  if (!ip) return null;
  return exits.has(ip);
}

export function torListStatus(): { loaded: boolean; attempted: boolean; path: string; count: number; mtime: string | null } {
  return { loaded: exits.size > 0, attempted: loadAttempted, path: listPath, count, mtime };
}
